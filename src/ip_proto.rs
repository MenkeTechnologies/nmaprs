//! IP protocol scan (`-sO`): raw IPv4 / IPv6 headers + ICMP classification.
//!
//! **IPv4** (privileged): ICMPv4 **destination unreachable / protocol unreachable** (type 3 code 2)
//! ⇒ `closed`; timeout ⇒ `filtered`.
//!
//! **IPv6** (privileged, Unix): raw IPv6 (`IPPROTO_RAW` + `IPV6_HDRINCL`) probes; ICMPv6 **Parameter
//! Problem** type 4 code 1 (unrecognized Next Header) with embedded IPv6 ⇒ `closed`; timeout ⇒
//! `filtered`. Same sharded pipeline pattern as [`crate::syn`].

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
#[cfg(unix)]
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{
    checksum as ipv4_header_checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet,
};
#[cfg(unix)]
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::Packet;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
};
use pnet_sys;
use rand::Rng;

#[cfg(unix)]
use crate::ipv6_l4;
use crate::scan::{
    host_over_deadline, sleep_inter_probe_delay_sync, PortLine, PortReason, ProbeRatePacer,
};

const RECV_SLICE: Duration = Duration::from_millis(50);
const RX_BUF: usize = 65536;

/// Upper bound on concurrent raw IP pipelines (each shard = raw send + ICMP recv thread).
pub const MAX_IP_PROTO_PARALLEL_SHARDS: usize = 16;

#[derive(Clone, Copy)]
enum ProtoOutcome {
    Closed,
    HostTimeout,
}

fn local_ipv4_for_checksum() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source for IP header")),
    }
}

#[cfg(unix)]
fn local_ipv6_for_checksum() -> io::Result<Ipv6Addr> {
    let s = UdpSocket::bind("[::]:0")?;
    s.connect("2001:4860:4860::8888:443")?;
    match s.local_addr()? {
        SocketAddr::V6(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv6 source for IP protocol scan")),
    }
}

/// Raw ICMP sockets may deliver an IPv4 header + ICMP payload; accept ICMP-only buffers too.
fn icmp_packet_from_recv_buffer(buf: &[u8]) -> Option<IcmpPacket<'_>> {
    if let Some(ip) = Ipv4Packet::new(buf) {
        let offset = ip.get_header_length() as usize * 4;
        if offset < buf.len() {
            return IcmpPacket::new(&buf[offset..]);
        }
    }
    IcmpPacket::new(buf)
}

fn recv_icmp_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<(IcmpPacket<'_>, IpAddr)>> {
    let fd = tr.socket.fd;
    let old_timeout = pnet_sys::get_socket_receive_timeout(fd)?;
    pnet_sys::set_socket_receive_timeout(fd, t)?;
    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
    let r = pnet_sys::recv_from(fd, &mut tr.buffer[..], &mut caddr);
    let _ = pnet_sys::set_socket_receive_timeout(fd, old_timeout);
    match r {
        Ok(len) => {
            let ip =
                pnet_sys::sockaddr_to_addr(&caddr, mem::size_of::<pnet_sys::SockAddrStorage>())?
                    .ip();
            let buf = &tr.buffer[..len];
            let Some(pkt) = icmp_packet_from_recv_buffer(buf) else {
                return Ok(None);
            };
            Ok(Some((pkt, ip)))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Extract embedded IPv4 from ICMP destination unreachable (RFC 792: 4-byte unused + original IP).
fn embedded_ipv4_from_dest_unreach<'a>(icmp: &'a IcmpPacket<'a>) -> Option<Ipv4Packet<'a>> {
    if icmp.get_icmp_type() != IcmpTypes::DestinationUnreachable {
        return None;
    }
    if icmp.get_icmp_code().0 != 2 {
        return None;
    }
    let p = icmp.payload();
    if p.len() < 4 + 20 {
        return None;
    }
    Ipv4Packet::new(&p[4..])
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct ProtoKey {
    dst: Ipv4Addr,
    proto: u16,
}

#[allow(clippy::too_many_arguments)]
fn ip_proto_ipv4_one_round(
    subset: &[(usize, Ipv4Addr, u16)],
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    apply_probe_delays: bool,
    global_results: Arc<Mutex<Vec<Option<ProtoOutcome>>>>,
    mut tx: pnet::transport::TransportSender,
    src_ip: Ipv4Addr,
) -> io::Result<()> {
    if subset.is_empty() {
        return Ok(());
    }

    let mut rx_tr = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(
            pnet::packet::ip::IpNextHeaderProtocols::Icmp,
        )),
    )?
    .1;

    let pending: Arc<DashMap<ProtoKey, (Instant, usize)>> = Arc::new(DashMap::new());
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&global_results);
    let global_end_r = Arc::clone(&global_end);

    let recv_handle = thread::spawn(move || -> io::Result<()> {
        loop {
            let now = Instant::now();
            let ge = *global_end_r.lock().expect("global_end");
            if pending_r.is_empty() && ge.is_some() {
                break;
            }
            if ge.is_some_and(|g| now >= g) {
                break;
            }
            let remain = ge
                .map(|g| g.saturating_duration_since(now))
                .unwrap_or(RECV_SLICE);
            let slice = remain.min(RECV_SLICE);
            match recv_icmp_with_timeout(&mut rx_tr, slice) {
                Ok(Some((icmp, _addr))) => {
                    let Some(emb) = embedded_ipv4_from_dest_unreach(&icmp) else {
                        continue;
                    };
                    let dst = emb.get_destination();
                    let proto = u16::from(emb.get_next_level_protocol().0);
                    let key = ProtoKey { dst, proto };
                    let Some((_, gidx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    results_r.lock().expect("results")[gidx] = Some(ProtoOutcome::Closed);
                    pending_r.remove(&key);
                }
                Ok(None) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });

    let pnet_src = src_ip;
    let mut rng = rand::thread_rng();
    let mut pkt_buf = vec![0u8; MutableIpv4Packet::minimum_packet_size()];
    let mut ge_max = Instant::now();

    for &(gidx, dst_ip, proto_u16) in subset {
        let proto = proto_u16.min(255) as u8;
        if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
            let ip = IpAddr::V4(dst_ip);
            if host_over_deadline(hs.as_ref(), ip, limit) {
                global_results.lock().expect("results")[gidx] = Some(ProtoOutcome::HostTimeout);
                continue;
            }
        }
        if apply_probe_delays {
            sleep_inter_probe_delay_sync(scan_delay, max_scan_delay);
            if let Some(p) = pacer.as_ref() {
                p.wait_turn_sync();
            }
        }
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        let key = ProtoKey {
            dst: dst_ip,
            proto: proto_u16,
        };
        pending.insert(key, (deadline, gidx));

        {
            let buf = &mut pkt_buf[..];
            let mut ip = MutableIpv4Packet::new(buf).expect("ipv4 buffer");
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_dscp(0);
            ip.set_ecn(0);
            ip.set_total_length(20);
            ip.set_identification(rng.gen());
            ip.set_flags(Ipv4Flags::DontFragment);
            ip.set_fragment_offset(0);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocol::new(proto));
            ip.set_checksum(0);
            ip.set_source(pnet_src);
            ip.set_destination(dst_ip);
            let cks = ipv4_header_checksum(&ip.to_immutable());
            ip.set_checksum(cks);
            tx.send_to(ip.to_immutable(), IpAddr::V4(dst_ip))?;
        }
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle
        .join()
        .map_err(|e| io::Error::other(format!("ICMP recv: {e:?}")))?;
    recv_res?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ip_proto_scan_ipv4_inner(
    order: Vec<(Ipv4Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    let total = order.len();
    if total == 0 {
        return Ok(vec![]);
    }

    let global_results = Arc::new(Mutex::new(vec![None; total]));

    for pass in 0..=connect_retries {
        let mut subset: Vec<(usize, Ipv4Addr, u16)> = Vec::new();
        for (idx, &(dst, proto)) in order.iter().enumerate() {
            if global_results.lock().expect("global_results")[idx].is_some() {
                continue;
            }
            if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
                let ip = IpAddr::V4(dst);
                if host_over_deadline(hs.as_ref(), ip, limit) {
                    global_results.lock().expect("global_results")[idx] =
                        Some(ProtoOutcome::HostTimeout);
                    continue;
                }
            }
            subset.push((idx, dst, proto));
        }
        if subset.is_empty() {
            break;
        }

        let (tx, _rx) = transport_channel(
            RX_BUF,
            TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Reserved),
        )?;
        let src_ip = local_ipv4_for_checksum()?;

        ip_proto_ipv4_one_round(
            &subset,
            per_probe_timeout,
            pacer.clone(),
            host_timeout,
            host_start.clone(),
            scan_delay,
            max_scan_delay,
            pass == 0,
            Arc::clone(&global_results),
            tx,
            src_ip,
        )?;
    }

    let results = global_results.lock().expect("global_results");
    let mut out = Vec::with_capacity(total);
    for (i, (host, port)) in order.into_iter().enumerate() {
        let (state, reason) = match results[i] {
            Some(ProtoOutcome::Closed) => ("closed", PortReason::IcmpProtoUnreachable),
            Some(ProtoOutcome::HostTimeout) => ("filtered", PortReason::HostTimeout),
            None => ("filtered", PortReason::Timeout),
        };
        out.push(PortLine::new(
            IpAddr::V4(host),
            port,
            "ip",
            state,
            reason,
            None,
        ));
    }

    Ok(out)
}

/// Raw IPv4 IP protocol scan with optional multi-shard parallelism.
#[allow(clippy::too_many_arguments)]
pub fn parallel_ip_proto_scan_ipv4(
    order: Vec<(Ipv4Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
    max_shards: usize,
) -> io::Result<Vec<PortLine>> {
    let total = order.len();
    if total == 0 {
        return Ok(vec![]);
    }
    let shards = max_shards.clamp(1, MAX_IP_PROTO_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return ip_proto_scan_ipv4_inner(
            order,
            per_probe_timeout,
            pacer,
            host_timeout,
            host_start,
            scan_delay,
            max_scan_delay,
            connect_retries,
        );
    }
    let chunks = crate::syn::split_into_syn_chunks(order, shards);
    let mut merged: Vec<PortLine> = Vec::with_capacity(total);
    let mut shard_results = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let pacer = pacer.clone();
            let host_start = host_start.clone();
            handles.push(s.spawn(move || {
                ip_proto_scan_ipv4_inner(
                    chunk,
                    per_probe_timeout,
                    pacer,
                    host_timeout,
                    host_start,
                    scan_delay,
                    max_scan_delay,
                    connect_retries,
                )
            }));
        }
        for h in handles {
            shard_results.push(h.join());
        }
    });
    for r in shard_results {
        match r {
            Ok(Ok(lines)) => merged.extend(lines),
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(io::Error::other(format!(
                    "IP protocol scan shard join: {e:?}"
                )))
            }
        }
    }
    Ok(merged)
}

#[cfg(unix)]
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct ProtoKeyV6 {
    dst: Ipv6Addr,
    proto: u16,
}

#[cfg(unix)]
fn recv_icmpv6_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<(Icmpv6Packet<'_>, IpAddr)>> {
    let fd = tr.socket.fd;
    let old_timeout = pnet_sys::get_socket_receive_timeout(fd)?;
    pnet_sys::set_socket_receive_timeout(fd, t)?;
    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
    let r = pnet_sys::recv_from(fd, &mut tr.buffer[..], &mut caddr);
    let _ = pnet_sys::set_socket_receive_timeout(fd, old_timeout);
    match r {
        Ok(len) => {
            let ip =
                pnet_sys::sockaddr_to_addr(&caddr, mem::size_of::<pnet_sys::SockAddrStorage>())?
                    .ip();
            let buf = &tr.buffer[..len];
            let icmp_slice = ipv6_l4::icmpv6_slice_after_ipv6(buf).unwrap_or(buf);
            let Some(pkt) = Icmpv6Packet::new(icmp_slice) else {
                return Ok(None);
            };
            Ok(Some((pkt, ip)))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// ICMPv6 Parameter Problem code 1 — unrecognized Next Header (RFC 4443).
#[cfg(unix)]
fn embedded_ipv6_from_icmpv6_param_problem<'a>(
    icmp: &'a Icmpv6Packet<'a>,
) -> Option<Ipv6Packet<'a>> {
    if icmp.get_icmpv6_type() != Icmpv6Types::ParameterProblem {
        return None;
    }
    if icmp.get_icmpv6_code().0 != 1 {
        return None;
    }
    let p = icmp.payload();
    if p.len() < 4 + 40 {
        return None;
    }
    Ipv6Packet::new(&p[4..])
}

#[cfg(unix)]
fn ipv6_raw_socket_hdrincl() -> io::Result<std::os::fd::OwnedFd> {
    use libc::{c_int, c_void, setsockopt, socket, AF_INET6, IPPROTO_IPV6, IPPROTO_RAW, SOCK_RAW};
    use std::os::fd::FromRawFd;

    let hdrincl: c_int = if cfg!(any(target_os = "linux", target_os = "android")) {
        36
    } else {
        2
    };

    let fd = unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let on: c_int = 1;
    let r = unsafe {
        setsockopt(
            fd,
            IPPROTO_IPV6,
            hdrincl,
            &on as *const c_int as *const c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if r != 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn send_ipv6_proto_header_probe(
    sock: &std::os::fd::OwnedFd,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
    rng: &mut impl Rng,
) -> io::Result<()> {
    use libc::{c_void, sendto, sockaddr_in6, AF_INET6};
    use std::os::fd::AsRawFd;

    let mut buf = vec![0u8; 40];
    {
        let mut ip = MutableIpv6Packet::new(&mut buf).expect("ipv6 40");
        ip.set_version(6);
        ip.set_traffic_class(0);
        ip.set_flow_label(rng.gen::<u32>() & 0xfffff);
        ip.set_payload_length(0);
        ip.set_next_header(IpNextHeaderProtocol::new(proto));
        ip.set_hop_limit(64);
        ip.set_source(src);
        ip.set_destination(dst);
    }

    let mut sin6: sockaddr_in6 = unsafe { mem::zeroed() };
    sin6.sin6_family = AF_INET6 as libc::sa_family_t;
    sin6.sin6_addr = libc::in6_addr {
        s6_addr: dst.octets(),
    };
    #[cfg(target_vendor = "apple")]
    {
        sin6.sin6_len = mem::size_of::<sockaddr_in6>() as u8;
    }
    let n = unsafe {
        sendto(
            sock.as_raw_fd(),
            buf.as_ptr() as *const c_void,
            buf.len(),
            0,
            &sin6 as *const _ as *const libc::sockaddr,
            mem::size_of::<sockaddr_in6>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::other("short IPv6 raw send"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
fn ip_proto_ipv6_one_round(
    subset: &[(usize, Ipv6Addr, u16)],
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    apply_probe_delays: bool,
    global_results: Arc<Mutex<Vec<Option<ProtoOutcome>>>>,
    src_ip: Ipv6Addr,
    tx: std::os::fd::OwnedFd,
) -> io::Result<()> {
    if subset.is_empty() {
        return Ok(());
    }

    let mut rx_tr = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(
            pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
        )),
    )?
    .1;

    let pending: Arc<DashMap<ProtoKeyV6, (Instant, usize)>> = Arc::new(DashMap::new());
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&global_results);
    let global_end_r = Arc::clone(&global_end);

    let recv_handle = thread::spawn(move || -> io::Result<()> {
        loop {
            let now = Instant::now();
            let ge = *global_end_r.lock().expect("global_end");
            if pending_r.is_empty() && ge.is_some() {
                break;
            }
            if ge.is_some_and(|g| now >= g) {
                break;
            }
            let remain = ge
                .map(|g| g.saturating_duration_since(now))
                .unwrap_or(RECV_SLICE);
            let slice = remain.min(RECV_SLICE);
            match recv_icmpv6_with_timeout(&mut rx_tr, slice) {
                Ok(Some((icmp, _addr))) => {
                    let Some(emb) = embedded_ipv6_from_icmpv6_param_problem(&icmp) else {
                        continue;
                    };
                    let dst = emb.get_destination();
                    let proto = u16::from(emb.get_next_header().0);
                    let key = ProtoKeyV6 { dst, proto };
                    let Some((_, gidx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    results_r.lock().expect("results")[gidx] = Some(ProtoOutcome::Closed);
                    pending_r.remove(&key);
                }
                Ok(None) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });

    let mut rng = rand::thread_rng();
    let mut ge_max = Instant::now();

    for &(gidx, dst_ip, proto_u16) in subset {
        let proto = proto_u16.min(255) as u8;
        if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
            let ip = IpAddr::V6(dst_ip);
            if host_over_deadline(hs.as_ref(), ip, limit) {
                global_results.lock().expect("results")[gidx] = Some(ProtoOutcome::HostTimeout);
                continue;
            }
        }
        if apply_probe_delays {
            sleep_inter_probe_delay_sync(scan_delay, max_scan_delay);
            if let Some(p) = pacer.as_ref() {
                p.wait_turn_sync();
            }
        }
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        let key = ProtoKeyV6 {
            dst: dst_ip,
            proto: proto_u16,
        };
        pending.insert(key, (deadline, gidx));

        send_ipv6_proto_header_probe(&tx, src_ip, dst_ip, proto, &mut rng)?;
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle
        .join()
        .map_err(|e| io::Error::other(format!("ICMPv6 recv: {e:?}")))?;
    recv_res?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
fn ip_proto_scan_ipv6_inner(
    order: Vec<(Ipv6Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    let total = order.len();
    if total == 0 {
        return Ok(vec![]);
    }

    let global_results = Arc::new(Mutex::new(vec![None; total]));

    for pass in 0..=connect_retries {
        let mut subset: Vec<(usize, Ipv6Addr, u16)> = Vec::new();
        for (idx, &(dst, proto)) in order.iter().enumerate() {
            if global_results.lock().expect("global_results")[idx].is_some() {
                continue;
            }
            if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
                let ip = IpAddr::V6(dst);
                if host_over_deadline(hs.as_ref(), ip, limit) {
                    global_results.lock().expect("global_results")[idx] =
                        Some(ProtoOutcome::HostTimeout);
                    continue;
                }
            }
            subset.push((idx, dst, proto));
        }
        if subset.is_empty() {
            break;
        }

        let tx = ipv6_raw_socket_hdrincl()?;
        let src_ip = local_ipv6_for_checksum()?;

        ip_proto_ipv6_one_round(
            &subset,
            per_probe_timeout,
            pacer.clone(),
            host_timeout,
            host_start.clone(),
            scan_delay,
            max_scan_delay,
            pass == 0,
            Arc::clone(&global_results),
            src_ip,
            tx,
        )?;
    }

    let results = global_results.lock().expect("global_results");
    let mut out = Vec::with_capacity(total);
    for (i, (host, port)) in order.into_iter().enumerate() {
        let (state, reason) = match results[i] {
            Some(ProtoOutcome::Closed) => ("closed", PortReason::IcmpProtoUnreachable),
            Some(ProtoOutcome::HostTimeout) => ("filtered", PortReason::HostTimeout),
            None => ("filtered", PortReason::Timeout),
        };
        out.push(PortLine::new(
            IpAddr::V6(host),
            port,
            "ip",
            state,
            reason,
            None,
        ));
    }

    Ok(out)
}

/// Raw IPv6 IP protocol scan with optional multi-shard parallelism (Unix only).
#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
pub fn parallel_ip_proto_scan_ipv6(
    order: Vec<(Ipv6Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
    max_shards: usize,
) -> io::Result<Vec<PortLine>> {
    let total = order.len();
    if total == 0 {
        return Ok(vec![]);
    }
    let shards = max_shards.clamp(1, MAX_IP_PROTO_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return ip_proto_scan_ipv6_inner(
            order,
            per_probe_timeout,
            pacer,
            host_timeout,
            host_start,
            scan_delay,
            max_scan_delay,
            connect_retries,
        );
    }
    let chunks = crate::syn::split_into_syn_chunks(order, shards);
    let mut merged: Vec<PortLine> = Vec::with_capacity(total);
    let mut shard_results = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let pacer = pacer.clone();
            let host_start = host_start.clone();
            handles.push(s.spawn(move || {
                ip_proto_scan_ipv6_inner(
                    chunk,
                    per_probe_timeout,
                    pacer,
                    host_timeout,
                    host_start,
                    scan_delay,
                    max_scan_delay,
                    connect_retries,
                )
            }));
        }
        for h in handles {
            shard_results.push(h.join());
        }
    });
    for r in shard_results {
        match r {
            Ok(Ok(lines)) => merged.extend(lines),
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(io::Error::other(format!(
                    "IPv6 IP protocol scan shard join: {e:?}"
                )))
            }
        }
    }
    Ok(merged)
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(unix))]
pub fn parallel_ip_proto_scan_ipv6(
    order: Vec<(Ipv6Addr, u16)>,
    _per_probe_timeout: Duration,
    _pacer: Option<Arc<ProbeRatePacer>>,
    _host_timeout: Option<Duration>,
    _host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    _scan_delay: Option<Duration>,
    _max_scan_delay: Option<Duration>,
    _connect_retries: u32,
    _max_shards: usize,
) -> io::Result<Vec<PortLine>> {
    if order.is_empty() {
        return Ok(vec![]);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPv6 IP protocol scan (-sO) requires Unix with raw sockets",
    ))
}

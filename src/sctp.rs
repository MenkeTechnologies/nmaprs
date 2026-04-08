//! Raw SCTP scans (`-sY` INIT, `-sZ` COOKIE_ECHO) — CRC32c + pipelined recv like [`crate::syn`].
//!
//! **IPv4** uses Layer3 raw IPv4; **IPv6** uses Layer4 raw SCTP (protocol **132**) like IPv6 TCP.
//! No `pnet` SCTP packet type: we build SCTP manually (RFC 4960). **Privileged** raw sockets.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crc32c::crc32c as crc32c_fn;
use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{
    checksum as ipv4_header_checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet,
};
use pnet::packet::Packet;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
};
use pnet_sys;
use rand::Rng;

use crate::ipv6_l4;
use crate::scan::{
    host_over_deadline, sleep_inter_probe_delay_sync, PortLine, PortReason, ProbeRatePacer,
};

/// SCTP segment for [`TransportSender::send_to`] (Layer4 IPv6 SCTP).
struct RawSctp<'a>(&'a [u8]);

impl Packet for RawSctp<'_> {
    fn packet(&self) -> &[u8] {
        self.0
    }

    fn payload(&self) -> &[u8] {
        &[]
    }
}

const RECV_SLICE: Duration = Duration::from_millis(50);
const RX_BUF: usize = 65536;

pub const MAX_SCTP_PARALLEL_SHARDS: usize = 16;

const CHUNK_INIT: u8 = 1;
const CHUNK_INIT_ACK: u8 = 2;
const CHUNK_ABORT: u8 = 6;
const CHUNK_COOKIE_ECHO: u8 = 10;
const CHUNK_COOKIE_ACK: u8 = 11;

#[derive(Clone, Copy)]
pub enum SctpProbeKind {
    Init,
    CookieEcho,
}

#[derive(Clone, Copy)]
enum SctpOutcome {
    Open,
    Closed,
    HostTimeout,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SctpKeyV4 {
    dst: Ipv4Addr,
    dport: u16,
    sport: u16,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SctpKeyV6 {
    dst: Ipv6Addr,
    dport: u16,
    sport: u16,
}

fn local_ipv4_for_checksum() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source")),
    }
}

fn recv_ipv4_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<(Ipv4Packet<'_>, IpAddr)>> {
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
            let Some(ipkt) = Ipv4Packet::new(buf) else {
                return Ok(None);
            };
            Ok(Some((ipkt, ip)))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

fn recv_ipv6_sctp_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<(&[u8], IpAddr)>> {
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
            let sctp_slice = match ipv6_l4::ipv6_l4_slice(buf, IpNextHeaderProtocols::Sctp.0) {
                Some(s) => s,
                None => return Ok(None),
            };
            if sctp_slice.len() < 12 {
                return Ok(None);
            }
            Ok(Some((sctp_slice, ip)))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// First SCTP chunk type after the 12-byte common header.
fn sctp_first_chunk_type(sctp_payload: &[u8]) -> Option<u8> {
    if sctp_payload.len() < 13 {
        return None;
    }
    Some(sctp_payload[12])
}

fn set_sctp_checksum(sctp: &mut [u8]) {
    if sctp.len() < 12 {
        return;
    }
    sctp[8..12].fill(0);
    let c = crc32c_fn(sctp);
    sctp[8..12].copy_from_slice(&c.to_be_bytes());
}

/// SCTP INIT or COOKIE_ECHO segment (CRC32c).
fn build_sctp_segment(kind: SctpProbeKind, sport: u16, dport: u16, rng: &mut impl Rng) -> Vec<u8> {
    let mut sctp: Vec<u8> = match kind {
        SctpProbeKind::Init => {
            // Common 12 + INIT chunk length 20 (fixed params only).
            let mut v = vec![0u8; 32];
            v[0..2].copy_from_slice(&sport.to_be_bytes());
            v[2..4].copy_from_slice(&dport.to_be_bytes());
            // verification tag 0 for first INIT
            v[4..8].fill(0);
            // checksum filled later
            // INIT chunk at 12
            v[12] = CHUNK_INIT;
            v[13] = 0;
            v[14..16].copy_from_slice(&20u16.to_be_bytes()); // chunk length
            v[16..20].copy_from_slice(&rng.gen::<u32>().to_be_bytes()); // initiate tag
            v[20..24].copy_from_slice(&65535u32.to_be_bytes()); // a_rwnd
            v[24..26].copy_from_slice(&10u16.to_be_bytes());
            v[26..28].copy_from_slice(&10u16.to_be_bytes());
            v[28..32].copy_from_slice(&rng.gen::<u32>().to_be_bytes()); // initial TSN
            v
        }
        SctpProbeKind::CookieEcho => {
            // COOKIE_ECHO: 12 common + chunk 16 (4 hdr + 8 cookie)
            let mut v = vec![0u8; 28];
            v[0..2].copy_from_slice(&sport.to_be_bytes());
            v[2..4].copy_from_slice(&dport.to_be_bytes());
            v[4..8].fill(0);
            v[12] = CHUNK_COOKIE_ECHO;
            v[13] = 0;
            v[14..16].copy_from_slice(&16u16.to_be_bytes());
            v[16..24].copy_from_slice(&rng.gen::<u64>().to_be_bytes());
            v
        }
    };
    set_sctp_checksum(&mut sctp);
    sctp
}

/// Build IPv4 + SCTP (INIT or COOKIE_ECHO) for `Layer3` send.
fn build_ipv4_sctp_probe(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    kind: SctpProbeKind,
    rng: &mut impl Rng,
) -> Vec<u8> {
    let sctp = build_sctp_segment(kind, sport, dport, rng);

    let mut ip_buf = vec![0u8; 20 + sctp.len()];
    let mut ip = MutableIpv4Packet::new(&mut ip_buf[..20]).expect("ipv4");
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length((20 + sctp.len()) as u16);
    ip.set_identification(rng.gen());
    ip.set_flags(Ipv4Flags::DontFragment);
    ip.set_fragment_offset(0);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Sctp);
    ip.set_checksum(0);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);
    let cks = ipv4_header_checksum(&ip.to_immutable());
    ip.set_checksum(cks);
    ip_buf[20..].copy_from_slice(&sctp);
    ip_buf
}

#[allow(clippy::too_many_arguments)]
fn sctp_ipv4_one_round(
    subset: &[(usize, Ipv4Addr, u16)],
    probe: SctpProbeKind,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    apply_probe_delays: bool,
    global_results: Arc<Mutex<Vec<Option<SctpOutcome>>>>,
    mut tx: pnet::transport::TransportSender,
    src_ip: Ipv4Addr,
) -> io::Result<()> {
    if subset.is_empty() {
        return Ok(());
    }

    let mut rx_tr = transport_channel(
        RX_BUF,
        TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Reserved),
    )?
    .1;

    let pending: Arc<DashMap<SctpKeyV4, (Instant, usize)>> = Arc::new(DashMap::new());
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&global_results);
    let global_end_r = Arc::clone(&global_end);
    let probe_kind = probe;

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
            match recv_ipv4_with_timeout(&mut rx_tr, slice) {
                Ok(Some((ip, _addr))) => {
                    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Sctp {
                        continue;
                    }
                    let dst = ip.get_source();
                    let ihl = ip.get_header_length() as usize * 4;
                    let buf = ip.packet();
                    if buf.len() < ihl + 12 {
                        continue;
                    }
                    let sctp = &buf[ihl..];
                    if sctp.len() < 12 {
                        continue;
                    }
                    let sport = u16::from_be_bytes([sctp[0], sctp[1]]);
                    let dport = u16::from_be_bytes([sctp[2], sctp[3]]);
                    let key = SctpKeyV4 {
                        dst,
                        dport: sport,
                        sport: dport,
                    };
                    let Some((_, gidx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    let Some(ct) = sctp_first_chunk_type(sctp) else {
                        continue;
                    };
                    let o = match probe_kind {
                        SctpProbeKind::Init => {
                            if ct == CHUNK_INIT_ACK {
                                SctpOutcome::Open
                            } else if ct == CHUNK_ABORT {
                                SctpOutcome::Closed
                            } else {
                                continue;
                            }
                        }
                        SctpProbeKind::CookieEcho => {
                            if ct == CHUNK_COOKIE_ACK {
                                SctpOutcome::Open
                            } else if ct == CHUNK_ABORT {
                                SctpOutcome::Closed
                            } else {
                                continue;
                            }
                        }
                    };
                    results_r.lock().expect("results")[gidx] = Some(o);
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

    for &(gidx, dst_ip, port) in subset {
        if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
            let ip = IpAddr::V4(dst_ip);
            if host_over_deadline(hs.as_ref(), ip, limit) {
                global_results.lock().expect("results")[gidx] = Some(SctpOutcome::HostTimeout);
                continue;
            }
        }
        if apply_probe_delays {
            sleep_inter_probe_delay_sync(scan_delay, max_scan_delay);
            if let Some(p) = pacer.as_ref() {
                p.wait_turn_sync();
            }
        }
        let sport = loop {
            let s: u16 = rng.gen_range(32768..65535);
            let k = SctpKeyV4 {
                dst: dst_ip,
                dport: port,
                sport: s,
            };
            if !pending.contains_key(&k) {
                break s;
            }
        };
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        pending.insert(
            SctpKeyV4 {
                dst: dst_ip,
                dport: port,
                sport,
            },
            (deadline, gidx),
        );
        let pkt = build_ipv4_sctp_probe(src_ip, dst_ip, sport, port, probe, &mut rng);
        let ip = Ipv4Packet::new(&pkt).expect("packet");
        tx.send_to(ip, IpAddr::V4(dst_ip))?;
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle
        .join()
        .map_err(|e| io::Error::other(format!("SCTP recv: {e:?}")))?;
    recv_res?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sctp_ipv6_one_round(
    subset: &[(usize, Ipv6Addr, u16)],
    probe: SctpProbeKind,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    apply_probe_delays: bool,
    global_results: Arc<Mutex<Vec<Option<SctpOutcome>>>>,
) -> io::Result<()> {
    if subset.is_empty() {
        return Ok(());
    }

    let (mut tx, mut rx) = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Sctp)),
    )?;

    let pending: Arc<DashMap<SctpKeyV6, (Instant, usize)>> = Arc::new(DashMap::new());
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&global_results);
    let global_end_r = Arc::clone(&global_end);
    let probe_kind = probe;

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
            match recv_ipv6_sctp_with_timeout(&mut rx, slice) {
                Ok(Some((sctp, addr))) => {
                    let IpAddr::V6(dst) = addr else {
                        continue;
                    };
                    let sport = u16::from_be_bytes([sctp[0], sctp[1]]);
                    let dport = u16::from_be_bytes([sctp[2], sctp[3]]);
                    let key = SctpKeyV6 {
                        dst,
                        dport: sport,
                        sport: dport,
                    };
                    let Some((_, gidx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    let Some(ct) = sctp_first_chunk_type(sctp) else {
                        continue;
                    };
                    let o = match probe_kind {
                        SctpProbeKind::Init => {
                            if ct == CHUNK_INIT_ACK {
                                SctpOutcome::Open
                            } else if ct == CHUNK_ABORT {
                                SctpOutcome::Closed
                            } else {
                                continue;
                            }
                        }
                        SctpProbeKind::CookieEcho => {
                            if ct == CHUNK_COOKIE_ACK {
                                SctpOutcome::Open
                            } else if ct == CHUNK_ABORT {
                                SctpOutcome::Closed
                            } else {
                                continue;
                            }
                        }
                    };
                    results_r.lock().expect("results")[gidx] = Some(o);
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

    for &(gidx, dst_ip, port) in subset {
        if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
            let ip = IpAddr::V6(dst_ip);
            if host_over_deadline(hs.as_ref(), ip, limit) {
                global_results.lock().expect("results")[gidx] = Some(SctpOutcome::HostTimeout);
                continue;
            }
        }
        if apply_probe_delays {
            sleep_inter_probe_delay_sync(scan_delay, max_scan_delay);
            if let Some(p) = pacer.as_ref() {
                p.wait_turn_sync();
            }
        }
        let sport = loop {
            let s: u16 = rng.gen_range(32768..65535);
            let k = SctpKeyV6 {
                dst: dst_ip,
                dport: port,
                sport: s,
            };
            if !pending.contains_key(&k) {
                break s;
            }
        };
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        pending.insert(
            SctpKeyV6 {
                dst: dst_ip,
                dport: port,
                sport,
            },
            (deadline, gidx),
        );
        let seg = build_sctp_segment(probe, sport, port, &mut rng);
        tx.send_to(RawSctp(&seg), IpAddr::V6(dst_ip)).map(|_| ())?;
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle
        .join()
        .map_err(|e| io::Error::other(format!("SCTP IPv6 recv: {e:?}")))?;
    recv_res?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sctp_scan_ipv6_inner(
    order: Vec<(Ipv6Addr, u16)>,
    probe: SctpProbeKind,
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
        for (idx, &(dst, port)) in order.iter().enumerate() {
            if global_results.lock().expect("global_results")[idx].is_some() {
                continue;
            }
            if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
                let ip = IpAddr::V6(dst);
                if host_over_deadline(hs.as_ref(), ip, limit) {
                    global_results.lock().expect("global_results")[idx] =
                        Some(SctpOutcome::HostTimeout);
                    continue;
                }
            }
            subset.push((idx, dst, port));
        }
        if subset.is_empty() {
            break;
        }

        sctp_ipv6_one_round(
            &subset,
            probe,
            per_probe_timeout,
            pacer.clone(),
            host_timeout,
            host_start.clone(),
            scan_delay,
            max_scan_delay,
            pass == 0,
            Arc::clone(&global_results),
        )?;
    }

    let results = global_results.lock().expect("global_results");
    let mut out = Vec::with_capacity(total);
    for (i, (host, port)) in order.into_iter().enumerate() {
        let (state, reason) = match results[i] {
            Some(SctpOutcome::Open) => match probe {
                SctpProbeKind::Init => ("open", PortReason::SctpInitAck),
                SctpProbeKind::CookieEcho => ("open", PortReason::SctpCookieAck),
            },
            Some(SctpOutcome::Closed) => ("closed", PortReason::SctpAbort),
            Some(SctpOutcome::HostTimeout) => ("filtered", PortReason::HostTimeout),
            None => ("filtered", PortReason::Timeout),
        };
        out.push(PortLine::new(
            IpAddr::V6(host),
            port,
            "sctp",
            state,
            reason,
            None,
        ));
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn sctp_scan_ipv4_inner(
    order: Vec<(Ipv4Addr, u16)>,
    probe: SctpProbeKind,
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
        for (idx, &(dst, port)) in order.iter().enumerate() {
            if global_results.lock().expect("global_results")[idx].is_some() {
                continue;
            }
            if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
                let ip = IpAddr::V4(dst);
                if host_over_deadline(hs.as_ref(), ip, limit) {
                    global_results.lock().expect("global_results")[idx] =
                        Some(SctpOutcome::HostTimeout);
                    continue;
                }
            }
            subset.push((idx, dst, port));
        }
        if subset.is_empty() {
            break;
        }

        let (tx, _rx) = transport_channel(
            RX_BUF,
            TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Reserved),
        )?;
        let src_ip = local_ipv4_for_checksum()?;

        sctp_ipv4_one_round(
            &subset,
            probe,
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
            Some(SctpOutcome::Open) => match probe {
                SctpProbeKind::Init => ("open", PortReason::SctpInitAck),
                SctpProbeKind::CookieEcho => ("open", PortReason::SctpCookieAck),
            },
            Some(SctpOutcome::Closed) => ("closed", PortReason::SctpAbort),
            Some(SctpOutcome::HostTimeout) => ("filtered", PortReason::HostTimeout),
            None => ("filtered", PortReason::Timeout),
        };
        out.push(PortLine::new(
            IpAddr::V4(host),
            port,
            "sctp",
            state,
            reason,
            None,
        ));
    }

    Ok(out)
}

/// Raw SCTP scan with optional multi-shard parallelism.
#[allow(clippy::too_many_arguments)]
pub fn parallel_sctp_scan_ipv4(
    order: Vec<(Ipv4Addr, u16)>,
    probe: SctpProbeKind,
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
    let shards = max_shards.clamp(1, MAX_SCTP_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return sctp_scan_ipv4_inner(
            order,
            probe,
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
                sctp_scan_ipv4_inner(
                    chunk,
                    probe,
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
            Err(e) => return Err(io::Error::other(format!("SCTP shard join: {e:?}"))),
        }
    }
    Ok(merged)
}

/// Raw SCTP scan (IPv6) with optional multi-shard parallelism.
#[allow(clippy::too_many_arguments)]
pub fn parallel_sctp_scan_ipv6(
    order: Vec<(Ipv6Addr, u16)>,
    probe: SctpProbeKind,
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
    let shards = max_shards.clamp(1, MAX_SCTP_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return sctp_scan_ipv6_inner(
            order,
            probe,
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
                sctp_scan_ipv6_inner(
                    chunk,
                    probe,
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
            Err(e) => return Err(io::Error::other(format!("SCTP IPv6 shard join: {e:?}"))),
        }
    }
    Ok(merged)
}

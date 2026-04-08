//! Raw half-open TCP scans (SYN / NULL / FIN / Xmas) via `pnet` (requires elevated privileges on most OSes).
//!
//! **Batched + pipelined**: a receiver thread drains TCP replies while the main thread sends probes,
//! overlapping RTT with the send phase. Large scans **shard** work across multiple independent
//! pipelines (see [`MAX_SYN_PARALLEL_SHARDS`]). `--max-retries` runs additional full rounds (new raw
//! socket each round) for probes still unresolved, omitting scan-delay / rate pacing on later rounds
//! (TCP connect parity).

use std::fmt;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver,
};
use pnet_sys;
use rand::Rng;

use crate::ipv6_l4;
use crate::scan::{
    host_over_deadline, sleep_inter_probe_delay_sync, PortLine, PortReason, ProbeRatePacer,
};

const RECV_SLICE: Duration = Duration::from_millis(50);
const RX_BUF: usize = 65536;

/// Upper bound on concurrent raw SYN pipelines per address family (each has its own recv thread).
pub const MAX_SYN_PARALLEL_SHARDS: usize = 16;

/// Split `order` into `shards` contiguous chunks (balanced lengths).
fn split_into_syn_chunks<T>(order: Vec<T>, shards: usize) -> Vec<Vec<T>> {
    let n = order.len();
    if n == 0 {
        return vec![];
    }
    let shards = shards.max(1).min(n);
    if shards == 1 {
        return vec![order];
    }
    let base = n / shards;
    let rem = n % shards;
    let mut out = Vec::with_capacity(shards);
    let mut iter = order.into_iter();
    for i in 0..shards {
        let take = base + usize::from(i < rem);
        let mut chunk = Vec::with_capacity(take);
        for _ in 0..take {
            chunk.push(iter.next().expect("split_into_syn_chunks: length mismatch"));
        }
        out.push(chunk);
    }
    debug_assert!(iter.next().is_none());
    out
}

fn local_ipv4_for_checksum() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source for checksum")),
    }
}

fn local_ipv6_for_checksum() -> io::Result<Ipv6Addr> {
    let s = UdpSocket::bind("[::]:0")?;
    s.connect("2001:4860:4860::8888:443")?;
    match s.local_addr()? {
        SocketAddr::V6(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv6 source for checksum")),
    }
}

fn recv_ipv6_tcp_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<(TcpPacket<'_>, IpAddr)>> {
    let fd = tr.socket.fd;
    let old_timeout = pnet_sys::get_socket_receive_timeout(fd)?;
    pnet_sys::set_socket_receive_timeout(fd, t)?;
    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
    let r = pnet_sys::recv_from(fd, &mut tr.buffer[..], &mut caddr);
    let _ = pnet_sys::set_socket_receive_timeout(fd, old_timeout);
    match r {
        Ok(len) => {
            let ip = pnet_sys::sockaddr_to_addr(&caddr, mem::size_of::<pnet_sys::SockAddrStorage>())?
                .ip();
            let buf = &tr.buffer[..len];
            let tcp_slice = ipv6_l4::ipv6_l4_slice(buf, IpNextHeaderProtocols::Tcp.0).unwrap_or(buf);
            let Some(pkt) = TcpPacket::new(tcp_slice) else {
                return Ok(None);
            };
            Ok(Some((pkt, ip)))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(Clone, Copy)]
enum SynOutcome {
    Open,
    Closed,
    /// RST on TCP ACK port scan (`-sA`) — Nmap `unfiltered`.
    Unfiltered,
    HostTimeout,
}

/// Map raw recv outcomes to [`PortLine`] (SYN-style vs ACK scan semantics).
fn port_line_from_syn_outcome(
    kind: RawTcpProbeKind,
    outcome: Option<SynOutcome>,
    host: IpAddr,
    port: u16,
) -> PortLine {
    let (state, reason) = match (kind, outcome) {
        (_, Some(SynOutcome::Open)) => ("open", PortReason::SynAck),
        (_, Some(SynOutcome::Unfiltered)) => ("unfiltered", PortReason::TcpRst),
        (_, Some(SynOutcome::Closed)) => ("closed", PortReason::ConnRefused),
        (_, Some(SynOutcome::HostTimeout)) => ("filtered", PortReason::HostTimeout),
        (_, None) => ("filtered", PortReason::Timeout),
    };
    PortLine {
        host,
        port,
        proto: "tcp",
        state,
        reason,
        latency_ms: None,
    }
}

/// Raw TCP packet for port scans (`Syn`, `Null`, `Fin`, `Xmas`, `AckPortScan`) vs Nmap-style **TCP ACK ping**
/// (`AckPing`) for `-PA` discovery.
#[derive(Clone, Copy)]
enum RawTcpProbeKind {
    Syn,
    /// `-sN`: no flags.
    Null,
    /// `-sF`: FIN only.
    Fin,
    /// `-sX`: FIN \| PSH \| URG (Christmas tree).
    Xmas,
    /// `-sA`: ACK scan — RST ⇒ `unfiltered`, no reply ⇒ `filtered` (not TCP `closed`/`open`).
    AckPortScan,
    AckPing,
}

/// User-facing TCP scan using the raw half-open pipeline (same recv classification as SYN).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpPortScanKind {
    Syn,
    Null,
    Fin,
    Xmas,
    /// TCP ACK scan (`-sA`); no TCP connect fallback on raw failure (semantics differ).
    Ack,
}

impl TcpPortScanKind {
    /// Whether a failed raw socket setup should fall back to TCP connect (same as Nmap for half-open scans).
    #[must_use]
    pub fn tcp_connect_fallback_on_raw_error(self) -> bool {
        !matches!(self, Self::Ack)
    }
}

impl From<TcpPortScanKind> for RawTcpProbeKind {
    fn from(k: TcpPortScanKind) -> Self {
        match k {
            TcpPortScanKind::Syn => RawTcpProbeKind::Syn,
            TcpPortScanKind::Null => RawTcpProbeKind::Null,
            TcpPortScanKind::Fin => RawTcpProbeKind::Fin,
            TcpPortScanKind::Xmas => RawTcpProbeKind::Xmas,
            TcpPortScanKind::Ack => RawTcpProbeKind::AckPortScan,
        }
    }
}

impl fmt::Display for TcpPortScanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcpPortScanKind::Syn => "SYN",
            TcpPortScanKind::Null => "NULL",
            TcpPortScanKind::Fin => "FIN",
            TcpPortScanKind::Xmas => "Xmas",
            TcpPortScanKind::Ack => "ACK",
        })
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SynKeyV4 {
    dst: Ipv4Addr,
    dport: u16,
    sport: u16,
}

/// One pipelined IPv4 round: recv thread + main-thread sends for `subset` (global indices).
#[allow(clippy::too_many_arguments)]
fn tcp_ipv4_one_round(
    subset: &[(usize, Ipv4Addr, u16)],
    probe_kind: RawTcpProbeKind,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    apply_probe_delays: bool,
    global_results: Arc<Mutex<Vec<Option<SynOutcome>>>>,
) -> io::Result<()> {
    if subset.is_empty() {
        return Ok(());
    }

    let (mut tx, mut rx) = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )?;
    let src_ip = local_ipv4_for_checksum()?;
    let mut rng = rand::thread_rng();

    let pending: Arc<DashMap<SynKeyV4, (Instant, usize)>> = Arc::new(DashMap::new());
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&global_results);
    let global_end_r = Arc::clone(&global_end);
    let recv_pk = probe_kind;

    let recv_handle = thread::spawn(move || -> io::Result<()> {
        let mut iter = tcp_packet_iter(&mut rx);
        loop {
            let now = Instant::now();
            let ge = *global_end_r.lock().expect("global_end");
            if pending_r.is_empty() && ge.is_some() {
                break;
            }
            if ge.is_some_and(|g| now >= g) {
                break;
            }
            let remain = ge.map(|g| g.saturating_duration_since(now)).unwrap_or(RECV_SLICE);
            let slice = remain.min(RECV_SLICE);
            match iter.next_with_timeout(slice) {
                Ok(Some((pkt, addr))) => {
                    let IpAddr::V4(dst) = addr else {
                        continue;
                    };
                    let sport = pkt.get_destination();
                    let dport = pkt.get_source();
                    let key = SynKeyV4 {
                        dst,
                        dport,
                        sport,
                    };
                    let Some((_, gidx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    let f = pkt.get_flags();
                    if f & TcpFlags::RST != 0 {
                        let o = if matches!(recv_pk, RawTcpProbeKind::AckPortScan) {
                            SynOutcome::Unfiltered
                        } else {
                            SynOutcome::Closed
                        };
                        results_r.lock().expect("results")[gidx] = Some(o);
                        pending_r.remove(&key);
                    } else if f & TcpFlags::SYN != 0 && f & TcpFlags::ACK != 0 {
                        results_r.lock().expect("results")[gidx] = Some(SynOutcome::Open);
                        pending_r.remove(&key);
                    }
                }
                Ok(None) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });

    let tcp_len = MutableTcpPacket::minimum_packet_size();
    let mut pkt_buf = vec![0u8; tcp_len];
    let mut ge_max = Instant::now();
    for &(gidx, dst_ip, port) in subset {
        if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
            let ip = IpAddr::V4(dst_ip);
            if host_over_deadline(hs.as_ref(), ip, limit) {
                global_results.lock().expect("results")[gidx] = Some(SynOutcome::HostTimeout);
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
            let k = SynKeyV4 {
                dst: dst_ip,
                dport: port,
                sport: s,
            };
            if !pending.contains_key(&k) {
                break s;
            }
        };
        let seq: u32 = rng.gen();
        let (ack_num, flags) = match probe_kind {
            RawTcpProbeKind::Syn => (0u32, TcpFlags::SYN),
            RawTcpProbeKind::Null => (0u32, 0),
            RawTcpProbeKind::Fin => (0u32, TcpFlags::FIN),
            RawTcpProbeKind::Xmas => (0u32, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG),
            RawTcpProbeKind::AckPortScan | RawTcpProbeKind::AckPing => {
                let a = rng.gen::<u32>() | 1;
                (a, TcpFlags::ACK)
            }
        };
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        pending.insert(
            SynKeyV4 {
                dst: dst_ip,
                dport: port,
                sport,
            },
            (deadline, gidx),
        );
        {
            let buf = &mut pkt_buf[..];
            let mut tcp = MutableTcpPacket::new(buf).expect("tcp buffer");
            tcp.set_source(sport);
            tcp.set_destination(port);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(ack_num);
            tcp.set_data_offset(5);
            tcp.set_reserved(0);
            tcp.set_flags(flags);
            tcp.set_window(64240);
            tcp.set_checksum(0);
            tcp.set_urgent_ptr(0);
            let cks = ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
            tcp.set_checksum(cks);
            tx.send_to(tcp.to_immutable(), IpAddr::V4(dst_ip))?;
        }
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle.join().map_err(|e| io::Error::other(format!("recv thread: {e:?}")))?;
    recv_res?;
    Ok(())
}

/// Half-open SYN scan for IPv4: receiver thread + main-thread send pipeline; optional `--max-retries` rounds.
#[allow(clippy::too_many_arguments)]
fn tcp_scan_ipv4_with_kind(
    order: Vec<(Ipv4Addr, u16)>,
    kind: RawTcpProbeKind,
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
                    global_results.lock().expect("global_results")[idx] = Some(SynOutcome::HostTimeout);
                    continue;
                }
            }
            subset.push((idx, dst, port));
        }
        if subset.is_empty() {
            break;
        }
        tcp_ipv4_one_round(
            &subset,
            kind,
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
        out.push(port_line_from_syn_outcome(
            kind,
            results[i],
            IpAddr::V4(host),
            port,
        ));
    }

    Ok(out)
}

/// Raw TCP port scan (SYN / NULL / FIN / Xmas / ACK): same pipeline as [`syn_scan_ipv4`].
#[allow(clippy::too_many_arguments)]
pub fn tcp_port_scan_ipv4(
    kind: TcpPortScanKind,
    order: Vec<(Ipv4Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    tcp_scan_ipv4_with_kind(
        order,
        kind.into(),
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
    )
}

/// Half-open SYN scan for IPv4: receiver thread + main-thread send pipeline; optional `--max-retries` rounds.
#[allow(clippy::too_many_arguments)]
pub fn syn_scan_ipv4(
    order: Vec<(Ipv4Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    tcp_port_scan_ipv4(
        TcpPortScanKind::Syn,
        order,
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
    )
}

/// Raw TCP ACK probes for `-PA` host discovery (RST / SYN-ACK response classification same as SYN scan).
#[allow(clippy::too_many_arguments)]
pub fn ack_ping_scan_ipv4(
    order: Vec<(Ipv4Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    tcp_scan_ipv4_with_kind(
        order,
        RawTcpProbeKind::AckPing,
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
    )
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct SynKeyV6 {
    dst: Ipv6Addr,
    dport: u16,
    sport: u16,
}

#[allow(clippy::too_many_arguments)]
fn tcp_ipv6_one_round(
    subset: &[(usize, Ipv6Addr, u16)],
    probe_kind: RawTcpProbeKind,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    apply_probe_delays: bool,
    global_results: Arc<Mutex<Vec<Option<SynOutcome>>>>,
) -> io::Result<()> {
    if subset.is_empty() {
        return Ok(());
    }

    let (mut tx, mut rx) = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
    )?;
    let src_ip = local_ipv6_for_checksum()?;
    let mut rng = rand::thread_rng();

    let pending: Arc<DashMap<SynKeyV6, (Instant, usize)>> = Arc::new(DashMap::new());
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&global_results);
    let global_end_r = Arc::clone(&global_end);
    let recv_pk = probe_kind;

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
            let remain = ge.map(|g| g.saturating_duration_since(now)).unwrap_or(RECV_SLICE);
            let slice = remain.min(RECV_SLICE);
            match recv_ipv6_tcp_with_timeout(&mut rx, slice) {
                Ok(Some((pkt, addr))) => {
                    let IpAddr::V6(dst) = addr else {
                        continue;
                    };
                    let sport = pkt.get_destination();
                    let dport = pkt.get_source();
                    let key = SynKeyV6 {
                        dst,
                        dport,
                        sport,
                    };
                    let Some((_, gidx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    let f = pkt.get_flags();
                    if f & TcpFlags::RST != 0 {
                        let o = if matches!(recv_pk, RawTcpProbeKind::AckPortScan) {
                            SynOutcome::Unfiltered
                        } else {
                            SynOutcome::Closed
                        };
                        results_r.lock().expect("results")[gidx] = Some(o);
                        pending_r.remove(&key);
                    } else if f & TcpFlags::SYN != 0 && f & TcpFlags::ACK != 0 {
                        results_r.lock().expect("results")[gidx] = Some(SynOutcome::Open);
                        pending_r.remove(&key);
                    }
                }
                Ok(None) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });

    let tcp_len = MutableTcpPacket::minimum_packet_size();
    let mut pkt_buf = vec![0u8; tcp_len];
    let mut ge_max = Instant::now();
    for &(gidx, dst_ip, port) in subset {
        if let (Some(limit), Some(ref hs)) = (host_timeout, host_start.as_ref()) {
            let ip = IpAddr::V6(dst_ip);
            if host_over_deadline(hs.as_ref(), ip, limit) {
                global_results.lock().expect("results")[gidx] = Some(SynOutcome::HostTimeout);
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
            let k = SynKeyV6 {
                dst: dst_ip,
                dport: port,
                sport: s,
            };
            if !pending.contains_key(&k) {
                break s;
            }
        };
        let seq: u32 = rng.gen();
        let (ack_num, flags) = match probe_kind {
            RawTcpProbeKind::Syn => (0u32, TcpFlags::SYN),
            RawTcpProbeKind::Null => (0u32, 0),
            RawTcpProbeKind::Fin => (0u32, TcpFlags::FIN),
            RawTcpProbeKind::Xmas => (0u32, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG),
            RawTcpProbeKind::AckPortScan | RawTcpProbeKind::AckPing => {
                let a = rng.gen::<u32>() | 1;
                (a, TcpFlags::ACK)
            }
        };
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        pending.insert(
            SynKeyV6 {
                dst: dst_ip,
                dport: port,
                sport,
            },
            (deadline, gidx),
        );
        {
            let buf = &mut pkt_buf[..];
            let mut tcp = MutableTcpPacket::new(buf).expect("tcp buffer");
            tcp.set_source(sport);
            tcp.set_destination(port);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(ack_num);
            tcp.set_data_offset(5);
            tcp.set_reserved(0);
            tcp.set_flags(flags);
            tcp.set_window(64240);
            tcp.set_checksum(0);
            tcp.set_urgent_ptr(0);
            let cks = ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
            tcp.set_checksum(cks);
            tx.send_to(tcp.to_immutable(), IpAddr::V6(dst_ip))?;
        }
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle.join().map_err(|e| io::Error::other(format!("recv thread: {e:?}")))?;
    recv_res?;
    Ok(())
}

/// Half-open SYN scan for IPv6 (separate raw path from IPv4); optional `--max-retries` rounds.
#[allow(clippy::too_many_arguments)]
fn tcp_scan_ipv6_with_kind(
    order: Vec<(Ipv6Addr, u16)>,
    kind: RawTcpProbeKind,
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
                    global_results.lock().expect("global_results")[idx] = Some(SynOutcome::HostTimeout);
                    continue;
                }
            }
            subset.push((idx, dst, port));
        }
        if subset.is_empty() {
            break;
        }
        tcp_ipv6_one_round(
            &subset,
            kind,
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
        out.push(port_line_from_syn_outcome(
            kind,
            results[i],
            IpAddr::V6(host),
            port,
        ));
    }

    Ok(out)
}

/// Raw TCP port scan (SYN / NULL / FIN / Xmas / ACK), IPv6.
#[allow(clippy::too_many_arguments)]
pub fn tcp_port_scan_ipv6(
    kind: TcpPortScanKind,
    order: Vec<(Ipv6Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    tcp_scan_ipv6_with_kind(
        order,
        kind.into(),
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
    )
}

/// Half-open SYN scan for IPv6 (separate raw path from IPv4); optional `--max-retries` rounds.
#[allow(clippy::too_many_arguments)]
pub fn syn_scan_ipv6(
    order: Vec<(Ipv6Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    tcp_port_scan_ipv6(
        TcpPortScanKind::Syn,
        order,
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
    )
}

/// Raw TCP ACK probes for `-PA` host discovery (IPv6).
#[allow(clippy::too_many_arguments)]
pub fn ack_ping_scan_ipv6(
    order: Vec<(Ipv6Addr, u16)>,
    per_probe_timeout: Duration,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_timeout: Option<Duration>,
    host_start: Option<Arc<DashMap<IpAddr, Instant>>>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    connect_retries: u32,
) -> io::Result<Vec<PortLine>> {
    tcp_scan_ipv6_with_kind(
        order,
        RawTcpProbeKind::AckPing,
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
    )
}

/// Run several independent IPv4 raw TCP port pipelines in parallel (one raw socket + recv thread per shard).
#[allow(clippy::too_many_arguments)]
pub fn parallel_tcp_port_scan_ipv4(
    kind: TcpPortScanKind,
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
    let shards = max_shards.clamp(1, MAX_SYN_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return tcp_port_scan_ipv4(
            kind,
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
    let chunks = split_into_syn_chunks(order, shards);
    let mut merged: Vec<PortLine> = Vec::with_capacity(total);
    let mut shard_results = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let pacer = pacer.clone();
            let host_start = host_start.clone();
            handles.push(s.spawn(move || {
                tcp_port_scan_ipv4(
                    kind,
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
            Err(e) => return Err(io::Error::other(format!("raw TCP port scan shard join: {e:?}"))),
        }
    }
    Ok(merged)
}

/// Run several independent IPv4 SYN pipelines in parallel (one raw socket + recv thread per shard).
#[allow(clippy::too_many_arguments)]
pub fn parallel_syn_scan_ipv4(
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
    parallel_tcp_port_scan_ipv4(
        TcpPortScanKind::Syn,
        order,
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
        max_shards,
    )
}

/// Run several independent IPv6 raw TCP port pipelines in parallel.
#[allow(clippy::too_many_arguments)]
pub fn parallel_tcp_port_scan_ipv6(
    kind: TcpPortScanKind,
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
    let shards = max_shards.clamp(1, MAX_SYN_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return tcp_port_scan_ipv6(
            kind,
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
    let chunks = split_into_syn_chunks(order, shards);
    let mut merged: Vec<PortLine> = Vec::with_capacity(total);
    let mut shard_results = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let pacer = pacer.clone();
            let host_start = host_start.clone();
            handles.push(s.spawn(move || {
                tcp_port_scan_ipv6(
                    kind,
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
            Err(e) => return Err(io::Error::other(format!("raw TCP port scan shard join: {e:?}"))),
        }
    }
    Ok(merged)
}

/// Run several independent IPv6 SYN pipelines in parallel.
#[allow(clippy::too_many_arguments)]
pub fn parallel_syn_scan_ipv6(
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
    parallel_tcp_port_scan_ipv6(
        TcpPortScanKind::Syn,
        order,
        per_probe_timeout,
        pacer,
        host_timeout,
        host_start,
        scan_delay,
        max_scan_delay,
        connect_retries,
        max_shards,
    )
}

/// Parallel raw TCP ACK ping (`-PA` discovery), IPv4.
#[allow(clippy::too_many_arguments)]
pub fn parallel_ack_ping_scan_ipv4(
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
    let shards = max_shards.clamp(1, MAX_SYN_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return ack_ping_scan_ipv4(
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
    let chunks = split_into_syn_chunks(order, shards);
    let mut merged: Vec<PortLine> = Vec::with_capacity(total);
    let mut shard_results = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let pacer = pacer.clone();
            let host_start = host_start.clone();
            handles.push(s.spawn(move || {
                ack_ping_scan_ipv4(
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
            Err(e) => return Err(io::Error::other(format!("ACK ping shard join: {e:?}"))),
        }
    }
    Ok(merged)
}

/// Parallel raw TCP ACK ping (`-PA` discovery), IPv6.
#[allow(clippy::too_many_arguments)]
pub fn parallel_ack_ping_scan_ipv6(
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
    let shards = max_shards.clamp(1, MAX_SYN_PARALLEL_SHARDS).min(total);
    if shards <= 1 {
        return ack_ping_scan_ipv6(
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
    let chunks = split_into_syn_chunks(order, shards);
    let mut merged: Vec<PortLine> = Vec::with_capacity(total);
    let mut shard_results = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let pacer = pacer.clone();
            let host_start = host_start.clone();
            handles.push(s.spawn(move || {
                ack_ping_scan_ipv6(
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
            Err(e) => return Err(io::Error::other(format!("ACK ping shard join: {e:?}"))),
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod syn_shard_tests {
    use super::split_into_syn_chunks;

    #[test]
    fn split_chunks_balanced() {
        let v: Vec<u8> = (0..10).collect();
        let c = split_into_syn_chunks(v, 4);
        assert_eq!(c.len(), 4);
        let sum: usize = c.iter().map(|x| x.len()).sum();
        assert_eq!(sum, 10);
        assert_eq!(c[0].len(), 3);
        assert_eq!(c[1].len(), 3);
        assert_eq!(c[2].len(), 2);
        assert_eq!(c[3].len(), 2);
    }

    #[test]
    fn split_single_chunk() {
        let v = vec![1, 2, 3];
        let c = split_into_syn_chunks(v, 1);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], vec![1, 2, 3]);
    }
}

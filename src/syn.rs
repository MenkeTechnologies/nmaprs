//! Raw TCP SYN scan via `pnet` (requires elevated privileges on most OSes).
//!
//! **Batched + pipelined**: a receiver thread drains TCP replies while the main thread sends SYNs,
//! overlapping RTT with the send phase.

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
use crate::scan::{PortLine, PortReason};

const RECV_SLICE: Duration = Duration::from_millis(50);
const RX_BUF: usize = 65536;

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
}

/// Half-open SYN scan for IPv4: receiver thread + main-thread send pipeline.
pub fn syn_scan_ipv4(
    order: Vec<(Ipv4Addr, u16)>,
    per_probe_timeout: Duration,
) -> io::Result<Vec<PortLine>> {
    let (mut tx, mut rx) = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )?;
    let src_ip = local_ipv4_for_checksum()?;
    let mut rng = rand::thread_rng();

    #[derive(Hash, Eq, PartialEq, Clone, Copy)]
    struct Key {
        dst: Ipv4Addr,
        dport: u16,
        sport: u16,
    }

    let total = order.len();
    if total == 0 {
        return Ok(vec![]);
    }

    let pending: Arc<DashMap<Key, (Instant, usize)>> = Arc::new(DashMap::new());
    let results: Arc<Mutex<Vec<Option<SynOutcome>>>> = Arc::new(Mutex::new(vec![None; total]));
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&results);
    let global_end_r = Arc::clone(&global_end);

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
                    let key = Key {
                        dst,
                        dport,
                        sport,
                    };
                    let Some((_, idx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    let f = pkt.get_flags();
                    if f & TcpFlags::RST != 0 {
                        results_r.lock().expect("results")[idx] = Some(SynOutcome::Closed);
                        pending_r.remove(&key);
                    } else if f & TcpFlags::SYN != 0 && f & TcpFlags::ACK != 0 {
                        results_r.lock().expect("results")[idx] = Some(SynOutcome::Open);
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
    for (idx, (dst_ip, port)) in order.iter().enumerate() {
        let sport = loop {
            let s: u16 = rng.gen_range(32768..65535);
            let k = Key {
                dst: *dst_ip,
                dport: *port,
                sport: s,
            };
            if !pending.contains_key(&k) {
                break s;
            }
        };
        let seq: u32 = rng.gen();
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        pending.insert(
            Key {
                dst: *dst_ip,
                dport: *port,
                sport,
            },
            (deadline, idx),
        );
        {
            let buf = &mut pkt_buf[..];
            let mut tcp = MutableTcpPacket::new(buf).expect("tcp buffer");
            tcp.set_source(sport);
            tcp.set_destination(*port);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_reserved(0);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(64240);
            tcp.set_checksum(0);
            tcp.set_urgent_ptr(0);
            let cks = ipv4_checksum(&tcp.to_immutable(), &src_ip, dst_ip);
            tcp.set_checksum(cks);
            tx.send_to(tcp.to_immutable(), IpAddr::V4(*dst_ip))?;
        }
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle.join().map_err(|e| io::Error::other(format!("recv thread: {e:?}")))?;
    recv_res?;

    let results = results.lock().expect("results");
    let mut out = Vec::with_capacity(total);
    for (i, (host, port)) in order.into_iter().enumerate() {
        let (state, reason) = match results[i] {
            Some(SynOutcome::Open) => ("open", PortReason::SynAck),
            Some(SynOutcome::Closed) => ("closed", PortReason::ConnRefused),
            None => ("filtered", PortReason::Timeout),
        };
        out.push(PortLine {
            host: IpAddr::V4(host),
            port,
            proto: "tcp",
            state,
            reason,
            latency_ms: None,
        });
    }

    Ok(out)
}

/// Half-open SYN scan for IPv6 (separate raw path from IPv4).
pub fn syn_scan_ipv6(
    order: Vec<(Ipv6Addr, u16)>,
    per_probe_timeout: Duration,
) -> io::Result<Vec<PortLine>> {
    let (mut tx, mut rx) = transport_channel(
        RX_BUF,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
    )?;
    let src_ip = local_ipv6_for_checksum()?;
    let mut rng = rand::thread_rng();

    #[derive(Hash, Eq, PartialEq, Clone, Copy)]
    struct Key {
        dst: Ipv6Addr,
        dport: u16,
        sport: u16,
    }

    let total = order.len();
    if total == 0 {
        return Ok(vec![]);
    }

    let pending: Arc<DashMap<Key, (Instant, usize)>> = Arc::new(DashMap::new());
    let results: Arc<Mutex<Vec<Option<SynOutcome>>>> = Arc::new(Mutex::new(vec![None; total]));
    let global_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let pending_r = Arc::clone(&pending);
    let results_r = Arc::clone(&results);
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
            let remain = ge.map(|g| g.saturating_duration_since(now)).unwrap_or(RECV_SLICE);
            let slice = remain.min(RECV_SLICE);
            match recv_ipv6_tcp_with_timeout(&mut rx, slice) {
                Ok(Some((pkt, addr))) => {
                    let IpAddr::V6(dst) = addr else {
                        continue;
                    };
                    let sport = pkt.get_destination();
                    let dport = pkt.get_source();
                    let key = Key {
                        dst,
                        dport,
                        sport,
                    };
                    let Some((_, idx)) = pending_r.get(&key).map(|e| *e.value()) else {
                        continue;
                    };
                    let f = pkt.get_flags();
                    if f & TcpFlags::RST != 0 {
                        results_r.lock().expect("results")[idx] = Some(SynOutcome::Closed);
                        pending_r.remove(&key);
                    } else if f & TcpFlags::SYN != 0 && f & TcpFlags::ACK != 0 {
                        results_r.lock().expect("results")[idx] = Some(SynOutcome::Open);
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
    for (idx, (dst_ip, port)) in order.iter().enumerate() {
        let sport = loop {
            let s: u16 = rng.gen_range(32768..65535);
            let k = Key {
                dst: *dst_ip,
                dport: *port,
                sport: s,
            };
            if !pending.contains_key(&k) {
                break s;
            }
        };
        let seq: u32 = rng.gen();
        let deadline = Instant::now() + per_probe_timeout;
        ge_max = ge_max.max(deadline);
        pending.insert(
            Key {
                dst: *dst_ip,
                dport: *port,
                sport,
            },
            (deadline, idx),
        );
        {
            let buf = &mut pkt_buf[..];
            let mut tcp = MutableTcpPacket::new(buf).expect("tcp buffer");
            tcp.set_source(sport);
            tcp.set_destination(*port);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_reserved(0);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(64240);
            tcp.set_checksum(0);
            tcp.set_urgent_ptr(0);
            let cks = ipv6_checksum(&tcp.to_immutable(), &src_ip, dst_ip);
            tcp.set_checksum(cks);
            tx.send_to(tcp.to_immutable(), IpAddr::V6(*dst_ip))?;
        }
    }

    *global_end.lock().expect("global_end") = Some(ge_max);

    let recv_res = recv_handle.join().map_err(|e| io::Error::other(format!("recv thread: {e:?}")))?;
    recv_res?;

    let results = results.lock().expect("results");
    let mut out = Vec::with_capacity(total);
    for (i, (host, port)) in order.into_iter().enumerate() {
        let (state, reason) = match results[i] {
            Some(SynOutcome::Open) => ("open", PortReason::SynAck),
            Some(SynOutcome::Closed) => ("closed", PortReason::ConnRefused),
            None => ("filtered", PortReason::Timeout),
        };
        out.push(PortLine {
            host: IpAddr::V6(host),
            port,
            proto: "tcp",
            state,
            reason,
            latency_ms: None,
        });
    }

    Ok(out)
}

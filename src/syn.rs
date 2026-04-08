//! Raw TCP SYN scan via `pnet` (requires elevated privileges on most OSes).

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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

/// Half-open SYN scan for IPv4 targets. Uses one raw transport channel; best-effort packet match.
pub fn syn_scan_ipv4(
    hosts: Vec<Ipv4Addr>,
    ports: &[u16],
    per_probe_timeout: Duration,
) -> io::Result<Vec<PortLine>> {
    let (mut tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )?;
    let mut iter = tcp_packet_iter(&mut rx);
    let src_ip = local_ipv4_for_checksum()?;
    let mut rng = rand::thread_rng();
    let mut out = Vec::new();

    for dst_ip in hosts {
        for &port in ports {
            let sport: u16 = rng.gen_range(32768..65535);
            let seq: u32 = rng.gen();
            let tcp_len = MutableTcpPacket::minimum_packet_size();
            let mut buf = vec![0u8; tcp_len];
            {
                let mut tcp = MutableTcpPacket::new(&mut buf).expect("tcp buffer");
                tcp.set_source(sport);
                tcp.set_destination(port);
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(0);
                tcp.set_data_offset(5);
                tcp.set_reserved(0);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(64240);
                tcp.set_checksum(0);
                tcp.set_urgent_ptr(0);
                let cks = ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
                tcp.set_checksum(cks);
                tx.send_to(tcp.to_immutable(), IpAddr::V4(dst_ip))?;
            }

            let deadline = Instant::now() + per_probe_timeout;
            let mut got: Option<&'static str> = None;
            while Instant::now() < deadline {
                let remain = deadline.saturating_duration_since(Instant::now());
                if remain.is_zero() {
                    break;
                }
                match iter.next_with_timeout(remain) {
                    Ok(Some((pkt, addr))) => {
                        if addr != IpAddr::V4(dst_ip) {
                            continue;
                        }
                        if pkt.get_source() != port || pkt.get_destination() != sport {
                            continue;
                        }
                        let f = pkt.get_flags();
                        if f & TcpFlags::RST != 0 {
                            got = Some("closed");
                            break;
                        }
                        if f & TcpFlags::SYN != 0 && f & TcpFlags::ACK != 0 {
                            got = Some("open");
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            let (state, reason): (&'static str, PortReason) = match got {
                Some("open") => ("open", PortReason::SynAck),
                Some("closed") => ("closed", PortReason::ConnRefused),
                _ => ("filtered", PortReason::Timeout),
            };
            out.push(PortLine {
                host: IpAddr::V4(dst_ip),
                port,
                proto: "tcp",
                state,
                reason,
                latency_ms: None,
            });
        }
    }

    Ok(out)
}

/// Half-open SYN scan for IPv6 targets (separate raw socket path from IPv4).
pub fn syn_scan_ipv6(
    hosts: Vec<Ipv6Addr>,
    ports: &[u16],
    per_probe_timeout: Duration,
) -> io::Result<Vec<PortLine>> {
    let (mut tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
    )?;
    let src_ip = local_ipv6_for_checksum()?;
    let mut rng = rand::thread_rng();
    let mut out = Vec::new();

    for dst_ip in hosts {
        for &port in ports {
            let sport: u16 = rng.gen_range(32768..65535);
            let seq: u32 = rng.gen();
            let tcp_len = MutableTcpPacket::minimum_packet_size();
            let mut buf = vec![0u8; tcp_len];
            {
                let mut tcp = MutableTcpPacket::new(&mut buf).expect("tcp buffer");
                tcp.set_source(sport);
                tcp.set_destination(port);
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(0);
                tcp.set_data_offset(5);
                tcp.set_reserved(0);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(64240);
                tcp.set_checksum(0);
                tcp.set_urgent_ptr(0);
                let cks = ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
                tcp.set_checksum(cks);
                tx.send_to(tcp.to_immutable(), IpAddr::V6(dst_ip))?;
            }

            let deadline = Instant::now() + per_probe_timeout;
            let mut got: Option<&'static str> = None;
            'wait: while Instant::now() < deadline {
                let remain = deadline.saturating_duration_since(Instant::now());
                if remain.is_zero() {
                    break;
                }
                match recv_ipv6_tcp_with_timeout(&mut rx, remain) {
                    Ok(Some((pkt, addr))) => {
                        if addr != IpAddr::V6(dst_ip) {
                            continue 'wait;
                        }
                        if pkt.get_source() != port || pkt.get_destination() != sport {
                            continue 'wait;
                        }
                        let f = pkt.get_flags();
                        if f & TcpFlags::RST != 0 {
                            got = Some("closed");
                            break;
                        }
                        if f & TcpFlags::SYN != 0 && f & TcpFlags::ACK != 0 {
                            got = Some("open");
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            let (state, reason): (&'static str, PortReason) = match got {
                Some("open") => ("open", PortReason::SynAck),
                Some("closed") => ("closed", PortReason::ConnRefused),
                _ => ("filtered", PortReason::Timeout),
            };
            out.push(PortLine {
                host: IpAddr::V6(dst_ip),
                port,
                proto: "tcp",
                state,
                reason,
                latency_ms: None,
            });
        }
    }

    Ok(out)
}

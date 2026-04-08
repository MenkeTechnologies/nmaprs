//! Raw IPv4 TCP SYN scan via `pnet` (requires elevated privileges on most OSes).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use rand::Rng;

use crate::scan::{PortLine, PortReason};

fn local_ipv4_for_checksum() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source for checksum")),
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

//! ICMP / ICMPv6 “port unreachable” listeners to refine UDP scan (`closed` vs `open|filtered`).

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
};
use pnet_sys;

use crate::ipv6_l4;
use crate::scan::UdpIcmpClosedSet;

/// Background loop: ICMP type 3 code 3 (IPv4 port unreachable).
pub fn run_ipv4_port_unreachable_listener(
    closed: UdpIcmpClosedSet,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let (mut _tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let mut iter = icmp_packet_iter(&mut rx);
    while !stop.load(Ordering::Relaxed) {
        match iter.next_with_timeout(Duration::from_millis(150)) {
            Ok(Some((pkt, _))) => {
                if pkt.get_icmp_type() != IcmpTypes::DestinationUnreachable {
                    continue;
                }
                if pkt.get_icmp_code().0 != 3 {
                    continue;
                }
                if let Some((dst, dport)) = parse_embedded_udp_ipv4(pkt.payload()) {
                    closed
                        .lock()
                        .insert((IpAddr::V4(dst), dport));
                }
            }
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Background loop: ICMPv6 type 1 code 4 (port unreachable) [RFC 4443].
pub fn run_ipv6_port_unreachable_listener(
    closed: UdpIcmpClosedSet,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let (mut _tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )?;
    while !stop.load(Ordering::Relaxed) {
        match recv_icmpv6_with_timeout(&mut rx, Duration::from_millis(150)) {
            Ok(Some(pkt)) => {
                if pkt.get_icmpv6_type() != Icmpv6Types::DestinationUnreachable {
                    continue;
                }
                if pkt.get_icmpv6_code().0 != 4 {
                    continue;
                }
                if let Some((dst, dport)) = parse_embedded_udp_ipv6(pkt.payload()) {
                    closed.lock().insert((IpAddr::V6(dst), dport));
                }
            }
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn recv_icmpv6_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<Icmpv6Packet<'_>>> {
    let fd = tr.socket.fd;
    let old_timeout = pnet_sys::get_socket_receive_timeout(fd)?;
    pnet_sys::set_socket_receive_timeout(fd, t)?;
    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
    let r = pnet_sys::recv_from(fd, &mut tr.buffer[..], &mut caddr);
    let _ = pnet_sys::set_socket_receive_timeout(fd, old_timeout);
    match r {
        Ok(len) => {
            let buf = &tr.buffer[..len];
            let icmp_slice = ipv6_l4::icmpv6_slice_after_ipv6(buf).unwrap_or(buf);
            Ok(Icmpv6Packet::new(icmp_slice))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// `icmp_payload` = bytes after ICMP type/code/checksum: 4-byte unused + embedded IPv4 (RFC 792).
fn parse_embedded_udp_ipv4(icmp_payload: &[u8]) -> Option<(std::net::Ipv4Addr, u16)> {
    use pnet::packet::ipv4::Ipv4Packet;
    let payload = icmp_payload.get(4..)?;
    let ip = Ipv4Packet::new(payload)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }
    let hlen = ip.get_header_length() as usize * 4;
    if payload.len() < hlen + 8 {
        return None;
    }
    let udp = &payload[hlen..hlen + 8];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    Some((ip.get_destination(), dst_port))
}

/// `icmp_payload` = bytes after ICMPv6 type/code/checksum: 4-byte unused + embedded IPv6 (RFC 4443).
fn parse_embedded_udp_ipv6(icmp_payload: &[u8]) -> Option<(Ipv6Addr, u16)> {
    let ip_buf = icmp_payload.get(4..)?;
    let ip = Ipv6Packet::new(ip_buf)?;
    let dst = ip.get_destination();
    let udp_slice = ipv6_l4::ipv6_l4_slice(ip_buf, IpNextHeaderProtocols::Udp.0)?;
    let udp_hdr = udp_slice.get(..8)?;
    let dst_port = u16::from_be_bytes([udp_hdr[2], udp_hdr[3]]);
    Some((dst, dst_port))
}

#[cfg(test)]
mod tests {
    use super::parse_embedded_udp_ipv4;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn port_unreachable_embedded_udp_dest_port_v4() {
        let mut buf = vec![0u8; 28];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf[..20]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_dscp(0);
            ip.set_ecn(0);
            ip.set_total_length(28);
            ip.set_identification(0);
            ip.set_flags(0);
            ip.set_fragment_offset(0);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(Ipv4Addr::new(192, 0, 2, 100));
            ip.set_destination(Ipv4Addr::new(192, 0, 2, 1));
            ip.set_checksum(0);
            ip.set_checksum(checksum(&ip.to_immutable()));
        }
        {
            let mut udp = MutableUdpPacket::new(&mut buf[20..]).unwrap();
            udp.set_source(50000);
            udp.set_destination(53);
            udp.set_length(8);
            udp.set_checksum(0);
        }
        let mut icmp_payload = vec![0u8; 4];
        icmp_payload.extend_from_slice(&buf);
        let (dst, dport) = parse_embedded_udp_ipv4(&icmp_payload).unwrap();
        assert_eq!(dst, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(dport, 53);
    }

    #[test]
    fn port_unreachable_embedded_udp_dest_port_v6() {
        use super::parse_embedded_udp_ipv6;
        let mut buf = vec![0u8; 48];
        {
            let mut ip = MutableIpv6Packet::new(&mut buf[..40]).unwrap();
            ip.set_version(6);
            ip.set_traffic_class(0);
            ip.set_flow_label(0);
            ip.set_payload_length(8);
            ip.set_next_header(IpNextHeaderProtocols::Udp);
            ip.set_hop_limit(64);
            ip.set_source(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100));
            ip.set_destination(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));
        }
        {
            let mut udp = MutableUdpPacket::new(&mut buf[40..]).unwrap();
            udp.set_source(50000);
            udp.set_destination(5353);
            udp.set_length(8);
            udp.set_checksum(0);
        }
        let mut icmp_payload = vec![0u8; 4];
        icmp_payload.extend_from_slice(&buf);
        let (dst, dport) = parse_embedded_udp_ipv6(&icmp_payload).unwrap();
        assert_eq!(dst, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));
        assert_eq!(dport, 5353);
    }
}

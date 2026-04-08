//! ICMP / ICMPv6 destination-unreachable listeners to refine UDP scan (`closed` / `filtered` / `open|filtered`).

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use libc;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
};
use pnet_sys;

use crate::ipv6_l4;
use crate::scan::{merge_udp_icmp_note, UdpIcmpNotes, UdpIcmpOutcome};

fn apply_icmpv4_packet(pkt: &IcmpPacket<'_>, notes: &UdpIcmpNotes) {
    if pkt.get_icmp_type() != IcmpTypes::DestinationUnreachable {
        return;
    }
    let code = pkt.get_icmp_code().0;
    let Some((dst, dport)) = parse_embedded_udp_ipv4(pkt.payload()) else {
        return;
    };
    let outcome = match code {
        3 => UdpIcmpOutcome::Closed,
        _ => UdpIcmpOutcome::Filtered,
    };
    merge_udp_icmp_note(notes, (IpAddr::V4(dst), dport), outcome);
}

fn apply_icmpv4_from_ip_buffer(buf: &[u8], len: usize, notes: &UdpIcmpNotes) {
    if len < 20 {
        return;
    }
    let slice = &buf[..len];
    let Some(ip) = Ipv4Packet::new(slice) else {
        return;
    };
    let offset = ip.get_header_length() as usize * 4;
    if offset >= len {
        return;
    }
    let Some(icmp) = IcmpPacket::new(&slice[offset..len]) else {
        return;
    };
    apply_icmpv4_packet(&icmp, notes);
}

fn apply_icmpv6_packet(pkt: &Icmpv6Packet<'_>, notes: &UdpIcmpNotes) {
    if pkt.get_icmpv6_type() != Icmpv6Types::DestinationUnreachable {
        return;
    }
    let code = pkt.get_icmpv6_code().0;
    let Some((dst, dport)) = parse_embedded_udp_ipv6(pkt.payload()) else {
        return;
    };
    let outcome = match code {
        4 => UdpIcmpOutcome::Closed,
        _ => UdpIcmpOutcome::Filtered,
    };
    merge_udp_icmp_note(notes, (IpAddr::V6(dst), dport), outcome);
}

fn apply_icmpv6_from_buffer(buf: &[u8], len: usize, notes: &UdpIcmpNotes) {
    let buf = &buf[..len];
    let icmp_slice = ipv6_l4::icmpv6_slice_after_ipv6(buf).unwrap_or(buf);
    let Some(pkt) = Icmpv6Packet::new(icmp_slice) else {
        return;
    };
    apply_icmpv6_packet(&pkt, notes);
}

/// Single thread: `poll(2)` on IPv4 + IPv6 ICMP sockets, non-blocking `recv` burst per wakeup (Unix).
#[cfg(unix)]
pub fn run_udp_icmp_dual_stack(notes: UdpIcmpNotes, stop: Arc<AtomicBool>) -> io::Result<()> {
    let (mut _tx4, mut rx4) = transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let (mut _tx6, mut rx6) = transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )?;

    set_socket_nonblocking(rx4.socket.fd)?;
    set_socket_nonblocking(rx6.socket.fd)?;

    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };

    let mut fds = [
        libc::pollfd {
            fd: rx4.socket.fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: rx6.socket.fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    while !stop.load(Ordering::Relaxed) {
        let pr = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                150,
            )
        };
        if pr < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if pr == 0 {
            continue;
        }

        if fds[0].revents & libc::POLLIN != 0 {
            drain_icmpv4(&mut rx4, &notes, &mut caddr)?;
        }
        if fds[1].revents & libc::POLLIN != 0 {
            drain_icmpv6(&mut rx6, &notes, &mut caddr)?;
        }

        fds[0].revents = 0;
        fds[1].revents = 0;
    }
    Ok(())
}

#[cfg(unix)]
fn set_socket_nonblocking(fd: pnet_sys::CSocket) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn drain_icmpv4(
    rx: &mut TransportReceiver,
    notes: &UdpIcmpNotes,
    caddr: &mut pnet_sys::SockAddrStorage,
) -> io::Result<()> {
    loop {
        match pnet_sys::recv_from(rx.socket.fd, &mut rx.buffer[..], caddr) {
            Ok(len) => apply_icmpv4_from_ip_buffer(&rx.buffer, len, notes),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
fn drain_icmpv6(
    rx: &mut TransportReceiver,
    notes: &UdpIcmpNotes,
    caddr: &mut pnet_sys::SockAddrStorage,
) -> io::Result<()> {
    loop {
        match pnet_sys::recv_from(rx.socket.fd, &mut rx.buffer[..], caddr) {
            Ok(len) => apply_icmpv6_from_buffer(&rx.buffer, len, notes),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// ICMPv4 type 3: code 3 → `closed`; any other code with a parsable embedded UDP probe → `filtered`.
pub fn run_ipv4_port_unreachable_listener(notes: UdpIcmpNotes, stop: Arc<AtomicBool>) -> io::Result<()> {
    let (mut _tx, mut rx) = transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let mut iter = icmp_packet_iter(&mut rx);
    while !stop.load(Ordering::Relaxed) {
        match iter.next_with_timeout(Duration::from_millis(150)) {
            Ok(Some((pkt, _))) => apply_icmpv4_packet(&pkt, &notes),
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// ICMPv6 type 1: code 4 → `closed`; other codes with parsable embedded UDP → `filtered` [RFC 4443].
pub fn run_ipv6_port_unreachable_listener(notes: UdpIcmpNotes, stop: Arc<AtomicBool>) -> io::Result<()> {
    let (mut _tx, mut rx) = transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )?;
    while !stop.load(Ordering::Relaxed) {
        match recv_icmpv6_with_timeout(&mut rx, Duration::from_millis(150)) {
            Ok(Some(pkt)) => apply_icmpv6_packet(&pkt, &notes),
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

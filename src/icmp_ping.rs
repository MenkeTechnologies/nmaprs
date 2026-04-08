//! ICMP **timestamp** (`-PP`) and **address mask** (`-PM`) host discovery (IPv4 only).
//!
//! Uses raw ICMP sockets (`pnet` transport channel). ICMPv6 has no direct equivalents for these
//! legacy IPv4 message types; IPv6 targets are skipped with a warning in [`crate::discovery`].

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

#[cfg(unix)]
use pnet::packet::icmp::{self, IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
#[cfg(unix)]
use pnet::packet::ip::IpNextHeaderProtocols;
#[cfg(unix)]
use pnet::packet::Packet;
#[cfg(unix)]
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
#[cfg(unix)]
use rand::Rng;

/// Build an ICMP Timestamp Request (type 13) with originate/receive/transmit set to zero.
#[cfg(unix)]
fn build_icmp_timestamp_request(id: u16, seq: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 20];
    {
        let mut m = MutableIcmpPacket::new(&mut buf).expect("buffer length 20");
        m.set_icmp_type(IcmpTypes::Timestamp);
        m.set_icmp_code(IcmpCode::new(0));
        m.set_checksum(0);
        let pl = vec![
            (id >> 8) as u8,
            id as u8,
            (seq >> 8) as u8,
            seq as u8,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        m.set_payload(&pl);
    }
    let icmp = IcmpPacket::new(&buf).expect("icmp");
    let cs = icmp::checksum(&icmp);
    MutableIcmpPacket::new(&mut buf)
        .expect("icmp mut")
        .set_checksum(cs);
    buf
}

/// Build an ICMP Address Mask Request (type 17) with mask field zero.
#[cfg(unix)]
fn build_icmp_address_mask_request(id: u16, seq: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    {
        let mut m = MutableIcmpPacket::new(&mut buf).expect("buffer length 12");
        m.set_icmp_type(IcmpTypes::AddressMaskRequest);
        m.set_icmp_code(IcmpCode::new(0));
        m.set_checksum(0);
        let pl = vec![
            (id >> 8) as u8,
            id as u8,
            (seq >> 8) as u8,
            seq as u8,
            0,
            0,
            0,
            0,
        ];
        m.set_payload(&pl);
    }
    let icmp = IcmpPacket::new(&buf).expect("icmp");
    let cs = icmp::checksum(&icmp);
    MutableIcmpPacket::new(&mut buf)
        .expect("icmp mut")
        .set_checksum(cs);
    buf
}

#[cfg(unix)]
fn icmp_id_seq_from_payload(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from_be_bytes([payload[2], payload[3]]),
    ))
}

/// Returns `true` if the host sent ICMP Timestamp Reply (14) matching `id` / `seq`.
#[cfg(unix)]
fn icmp_timestamp_probe_v4_inner(dst: Ipv4Addr, timeout: Duration) -> io::Result<bool> {
    let (mut tx, mut rx) = transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let mut rng = rand::thread_rng();
    let id: u16 = rng.gen();
    let seq: u16 = rng.gen();
    let buf = build_icmp_timestamp_request(id, seq);
    let pkt = IcmpPacket::new(&buf).expect("built icmp");
    tx.send_to(pkt, IpAddr::V4(dst))?;

    let deadline = Instant::now() + timeout;
    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let slice = (deadline - now).min(Duration::from_millis(500));
        let got = iter.next_with_timeout(slice)?;
        let Some((icmp, src)) = got else {
            continue;
        };
        if src != IpAddr::V4(dst) {
            continue;
        }
        if icmp.get_icmp_type() != IcmpTypes::TimestampReply {
            continue;
        }
        let Some((rid, rseq)) = icmp_id_seq_from_payload(icmp.payload()) else {
            continue;
        };
        if rid == id && rseq == seq {
            return Ok(true);
        }
    }
}

/// Returns `true` if the host sent ICMP Address Mask Reply (18) matching `id` / `seq`.
#[cfg(unix)]
fn icmp_address_mask_probe_v4_inner(dst: Ipv4Addr, timeout: Duration) -> io::Result<bool> {
    let (mut tx, mut rx) = transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let mut rng = rand::thread_rng();
    let id: u16 = rng.gen();
    let seq: u16 = rng.gen();
    let buf = build_icmp_address_mask_request(id, seq);
    let pkt = IcmpPacket::new(&buf).expect("built icmp");
    tx.send_to(pkt, IpAddr::V4(dst))?;

    let deadline = Instant::now() + timeout;
    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let slice = (deadline - now).min(Duration::from_millis(500));
        let got = iter.next_with_timeout(slice)?;
        let Some((icmp, src)) = got else {
            continue;
        };
        if src != IpAddr::V4(dst) {
            continue;
        }
        if icmp.get_icmp_type() != IcmpTypes::AddressMaskReply {
            continue;
        }
        let Some((rid, rseq)) = icmp_id_seq_from_payload(icmp.payload()) else {
            continue;
        };
        if rid == id && rseq == seq {
            return Ok(true);
        }
    }
}

/// `-PP`: ICMP timestamp request → timestamp reply means host responded.
#[must_use]
pub fn icmp_timestamp_probe_v4(dst: Ipv4Addr, timeout: Duration) -> bool {
    #[cfg(unix)]
    {
        match icmp_timestamp_probe_v4_inner(dst, timeout) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, dst = %dst, "ICMP timestamp probe failed");
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dst, timeout);
        false
    }
}

/// `-PM`: ICMP address mask request → mask reply means host responded.
#[must_use]
pub fn icmp_address_mask_probe_v4(dst: Ipv4Addr, timeout: Duration) -> bool {
    #[cfg(unix)]
    {
        match icmp_address_mask_probe_v4_inner(dst, timeout) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, dst = %dst, "ICMP address mask probe failed");
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dst, timeout);
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use pnet::packet::icmp::IcmpPacket;

    #[test]
    fn timestamp_request_well_formed() {
        let buf = build_icmp_timestamp_request(0x1234, 0xabcd);
        assert_eq!(buf.len(), 20);
        let p = IcmpPacket::new(&buf).unwrap();
        assert_eq!(p.get_icmp_type(), IcmpTypes::Timestamp);
        assert_eq!(p.payload().len(), 16);
    }

    #[test]
    fn address_mask_request_well_formed() {
        let buf = build_icmp_address_mask_request(1, 2);
        assert_eq!(buf.len(), 12);
        let p = IcmpPacket::new(&buf).unwrap();
        assert_eq!(p.get_icmp_type(), IcmpTypes::AddressMaskRequest);
        assert_eq!(p.payload().len(), 8);
    }
}

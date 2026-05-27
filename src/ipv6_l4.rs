//! Locate the layer-4 header inside an IPv6 frame (fixed header + common extension headers).

use pnet::packet::ip::IpNextHeaderProtocols;

/// Returns a slice starting at the L4 header (`nh == l4_protocol`), or `None` if not found / malformed.
pub fn ipv6_l4_slice(buf: &[u8], l4_protocol: u8) -> Option<&[u8]> {
    if buf.len() < 40 || (buf[0] >> 4) != 6 {
        return None;
    }
    let mut off = 40usize;
    let mut nh = buf[6];
    while nh != l4_protocol {
        if off + 2 > buf.len() {
            return None;
        }
        let next_after_ext = buf[off];
        match nh {
            0 | 43 | 50 | 51 | 60 => {
                let elen = buf[off + 1] as usize * 8 + 8;
                if off + elen > buf.len() {
                    return None;
                }
                off += elen;
                nh = next_after_ext;
            }
            44 => {
                if off + 8 > buf.len() {
                    return None;
                }
                off += 8;
                nh = next_after_ext;
            }
            _ => return None,
        }
    }
    buf.get(off..)
}

/// Slice beginning at ICMPv6 (protocol 58) inside an IPv6 frame.
pub fn icmpv6_slice_after_ipv6(buf: &[u8]) -> Option<&[u8]> {
    ipv6_l4_slice(buf, IpNextHeaderProtocols::Icmpv6.0)
}

#[cfg(test)]
mod tests {
    use pnet::packet::ip::IpNextHeaderProtocols;

    use super::{icmpv6_slice_after_ipv6, ipv6_l4_slice};

    fn v6_frame(next_header: u8, payload_len: u16) -> Vec<u8> {
        let total = 40usize + payload_len as usize;
        let mut buf = vec![0u8; total];
        buf[0] = 0x60;
        buf[4] = (payload_len >> 8) as u8;
        buf[5] = payload_len as u8;
        buf[6] = next_header;
        buf[7] = 64;
        buf
    }

    fn v6_with_ext(next_ext: u8, ext_body_len: u8, after_ext: u8, tail: &[u8]) -> Vec<u8> {
        let ext_total = 8usize + ext_body_len as usize * 8;
        let payload_len = ext_total + tail.len();
        let mut buf = vec![0u8; 40 + payload_len];
        buf[0] = 0x60;
        buf[4] = (payload_len >> 8) as u8;
        buf[5] = payload_len as u8;
        buf[6] = next_ext;
        buf[7] = 64;
        buf[40] = after_ext;
        buf[41] = ext_body_len;
        buf[40 + ext_total..].copy_from_slice(tail);
        buf
    }

    #[test]
    fn rejects_buffer_shorter_than_ipv6_header() {
        assert!(ipv6_l4_slice(&[0x60; 20], IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn rejects_non_ipv6_version_nibble() {
        let mut buf = v6_frame(IpNextHeaderProtocols::Tcp.0, 20);
        buf[0] = 0x40;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn direct_tcp_returns_slice_at_offset_40() {
        let tail = [0xAA; 20];
        let mut buf = v6_frame(IpNextHeaderProtocols::Tcp.0, tail.len() as u16);
        buf[40..40 + tail.len()].copy_from_slice(&tail);
        let got = ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap();
        assert_eq!(got, &tail);
    }

    #[test]
    fn direct_udp_returns_slice_at_offset_40() {
        let tail = [0xBB; 8];
        let mut buf = v6_frame(IpNextHeaderProtocols::Udp.0, tail.len() as u16);
        buf[40..40 + tail.len()].copy_from_slice(&tail);
        let got = ipv6_l4_slice(&buf, IpNextHeaderProtocols::Udp.0).unwrap();
        assert_eq!(got, &tail);
    }

    #[test]
    fn direct_icmpv6_via_helper() {
        let tail = [0x01, 0x00, 0xAB, 0xCD];
        let mut buf = v6_frame(IpNextHeaderProtocols::Icmpv6.0, tail.len() as u16);
        buf[40..40 + tail.len()].copy_from_slice(&tail);
        assert_eq!(icmpv6_slice_after_ipv6(&buf).unwrap(), &tail);
    }

    #[test]
    fn hop_by_hop_then_tcp() {
        let tcp = [0x11; 20];
        let buf = v6_with_ext(0, 0, IpNextHeaderProtocols::Tcp.0, &tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn routing_header_then_udp() {
        let udp = [0x22; 8];
        let buf = v6_with_ext(43, 0, IpNextHeaderProtocols::Udp.0, &udp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Udp.0).unwrap(),
            &udp
        );
    }

    #[test]
    fn destination_options_then_icmpv6() {
        let icmp = [0x03, 0x03, 0x00, 0x00];
        let buf = v6_with_ext(60, 0, IpNextHeaderProtocols::Icmpv6.0, &icmp);
        assert_eq!(icmpv6_slice_after_ipv6(&buf).unwrap(), &icmp);
    }

    #[test]
    fn fragment_header_then_tcp() {
        let tcp = [0x33; 20];
        let mut buf = v6_frame(44, (8 + tcp.len()) as u16);
        buf[40] = IpNextHeaderProtocols::Tcp.0;
        buf[48..48 + tcp.len()].copy_from_slice(&tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn ah_extension_then_udp() {
        let udp = [0x44; 8];
        let buf = v6_with_ext(51, 0, IpNextHeaderProtocols::Udp.0, &udp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Udp.0).unwrap(),
            &udp
        );
    }

    #[test]
    fn esp_extension_then_tcp() {
        let tcp = [0x55; 20];
        let buf = v6_with_ext(50, 0, IpNextHeaderProtocols::Tcp.0, &tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn truncated_extension_header_returns_none() {
        let mut buf = v6_frame(0, 4);
        buf[6] = 0;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn extension_length_overflow_returns_none() {
        let mut buf = v6_frame(0, 16);
        buf[6] = 0;
        buf[41] = 200;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn unknown_next_header_in_chain_returns_none() {
        let mut buf = v6_frame(99, 8);
        buf[6] = 0;
        buf[40] = 99;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn wrong_l4_protocol_requested_returns_none() {
        let tail = [0x66; 8];
        let buf = v6_frame(IpNextHeaderProtocols::Udp.0, tail.len() as u16);
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn chained_hop_by_hop_and_routing_to_tcp() {
        let tcp = [0x77; 20];
        let hop = 8usize;
        let route = 8usize;
        let payload_len = hop + route + tcp.len();
        let mut buf = vec![0u8; 40 + payload_len];
        buf[0] = 0x60;
        buf[4] = (payload_len >> 8) as u8;
        buf[5] = payload_len as u8;
        buf[6] = 0;
        buf[40] = 43;
        buf[41] = 0;
        buf[48] = IpNextHeaderProtocols::Tcp.0;
        buf[49] = 0;
        buf[56..56 + tcp.len()].copy_from_slice(&tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn empty_l4_payload_is_valid_zero_len_slice() {
        let buf = v6_frame(IpNextHeaderProtocols::Tcp.0, 0);
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn icmpv6_helper_none_when_tcp_only() {
        let tail = [0x88; 20];
        let buf = v6_frame(IpNextHeaderProtocols::Tcp.0, tail.len() as u16);
        assert!(icmpv6_slice_after_ipv6(&buf).is_none());
    }

    #[test]
    fn ipv6_version_nibble_must_be_six() {
        let mut buf = v6_frame(IpNextHeaderProtocols::Tcp.0, 4);
        buf[0] = 0x40;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn routing_header_with_body_len_one() {
        let tcp = [0x99; 4];
        let buf = v6_with_ext(43, 1, IpNextHeaderProtocols::Tcp.0, &tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn icmpv6_slice_after_ipv6_for_icmpv6_next_header() {
        let icmp = [0x01, 0x00, 0x00, 0x00];
        let mut buf = v6_frame(IpNextHeaderProtocols::Icmpv6.0, icmp.len() as u16);
        buf[40..44].copy_from_slice(&icmp);
        let slice = icmpv6_slice_after_ipv6(&buf).expect("icmpv6");
        assert_eq!(slice, &icmp);
    }

    #[test]
    fn ipv6_l4_udp_payload_extracted() {
        let udp = [0x01, 0x02, 0x03, 0x04, 0x00, 0x08, 0x00, 0x00];
        let mut buf = v6_frame(IpNextHeaderProtocols::Udp.0, udp.len() as u16);
        buf[40..48].copy_from_slice(&udp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Udp.0).unwrap(),
            &udp
        );
    }

    #[test]
    fn ipv6_buffer_shorter_than_header_returns_none() {
        assert!(ipv6_l4_slice(&[0x60, 0, 0, 0], IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn dest_header_then_udp() {
        let udp = [0xAA; 8];
        let buf = v6_with_ext(60, 0, IpNextHeaderProtocols::Udp.0, &udp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Udp.0).unwrap(),
            &udp
        );
    }

    #[test]
    fn hop_byhop_then_tcp() {
        let tcp = [0x11, 0x22, 0x33, 0x44];
        let buf = v6_with_ext(0, 0, IpNextHeaderProtocols::Tcp.0, &tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn unknown_next_header_stops_walk() {
        let buf = v6_frame(99, 4);
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn extension_header_truncated_returns_none() {
        let mut buf = v6_frame(43, 16);
        buf[6] = 43;
        buf[40] = IpNextHeaderProtocols::Tcp.0;
        buf[41] = 10;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn fragment_header_skips_eight_bytes() {
        let tcp = [0x55; 4];
        let mut buf = vec![0u8; 40 + 8 + tcp.len()];
        buf[0] = 0x60;
        buf[6] = 44;
        buf[7] = 64;
        buf[4] = 0;
        buf[5] = (8 + tcp.len()) as u8;
        buf[40] = IpNextHeaderProtocols::Tcp.0;
        buf[48..].copy_from_slice(&tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn icmpv6_slice_empty_buffer_none() {
        assert!(icmpv6_slice_after_ipv6(&[]).is_none());
    }

    #[test]
    fn rejects_ipv4_version_nibble_six() {
        let mut buf = v6_frame(IpNextHeaderProtocols::Tcp.0, 4);
        buf[0] = 0x46;
        assert!(ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).is_none());
    }

    #[test]
    fn payload_length_zero_direct_tcp_empty_slice() {
        let buf = v6_frame(IpNextHeaderProtocols::Tcp.0, 0);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &[] as &[u8]
        );
    }

    #[test]
    fn destination_options_then_udp() {
        let udp = [0xCC; 8];
        let buf = v6_with_ext(60, 0, IpNextHeaderProtocols::Udp.0, &udp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Udp.0).unwrap(),
            &udp
        );
    }

    #[test]
    fn routing_header_then_tcp() {
        let tcp = [0xDD; 12];
        let buf = v6_with_ext(43, 0, IpNextHeaderProtocols::Tcp.0, &tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn icmpv6_helper_matches_direct_icmpv6_slice() {
        let tail = [0x01, 0x03, 0x00, 0x00];
        let mut buf = v6_frame(IpNextHeaderProtocols::Icmpv6.0, tail.len() as u16);
        buf[40..].copy_from_slice(&tail);
        assert_eq!(
            icmpv6_slice_after_ipv6(&buf).unwrap(),
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Icmpv6.0).unwrap()
        );
    }

    #[test]
    fn hop_by_hop_chained_to_destination_options_then_tcp() {
        let tcp = [0x11; 4];
        let mut buf = vec![0u8; 40 + 8 + 8 + tcp.len()];
        buf[0] = 0x60;
        let payload_len = 8 + 8 + tcp.len();
        buf[4] = (payload_len >> 8) as u8;
        buf[5] = payload_len as u8;
        buf[6] = 0;
        buf[7] = 64;
        buf[40] = 60;
        buf[41] = 0;
        buf[48] = IpNextHeaderProtocols::Tcp.0;
        buf[49] = 0;
        buf[56..].copy_from_slice(&tcp);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap(),
            &tcp
        );
    }

    #[test]
    fn buffer_exactly_40_bytes_no_payload_none_for_tcp() {
        let buf = v6_frame(IpNextHeaderProtocols::Tcp.0, 0);
        assert_eq!(
            ipv6_l4_slice(&buf, IpNextHeaderProtocols::Tcp.0).unwrap().len(),
            0
        );
    }
}

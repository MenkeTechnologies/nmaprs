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

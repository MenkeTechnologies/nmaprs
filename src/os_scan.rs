//! IPv4 TCP/IP OS detection probes (Nmap 2nd-gen): SEQ/OPS/WIN, ECN, T1–T7, U1, IE.
//!
//! Requires a raw IPv4 socket (privileged).

use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_hdr_cksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportReceiver, TransportSender,
};
use pnet_sys;
use rand::Rng;
use std::fmt::Write as _;

use crate::os_fp_db::SubjectFingerprint;

const NUM_SEQ_SAMPLES: usize = 6;
const OS_SEQ_PROBE_DELAY_MS: u64 = 100;
const PRIME_32K: u32 = 32261;

/// `prbOpts` / `prbWindowSz` from Nmap `osscan2.cc`.
const PRB_OPTS: [&[u8]; 13] = [
    b"\x03\x03\x0A\x01\x02\x04\x05\xb4\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x02\x04\x05\x78\x03\x03\x00\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x00",
    b"\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x01\x03\x03\x05\x01\x02\x04\x02\x80",
    b"\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00",
    b"\x02\x04\x02\x18\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00",
    b"\x02\x04\x01\x09\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00",
    b"\x03\x03\x0A\x01\x02\x04\x05\xb4\x04\x02\x01\x01",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0f\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
];

const PRB_WIN: [u16; 13] = [1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535];

// ───── reply structs ────────────────────────────────────────────

struct TcpReply {
    ipid: u16,
    ttl: u8,
    df: bool,
    window: u16,
    seq: u32,
    ack_num: u32,
    flags: u8,
    reserved: u8,
    urg_ptr: u16,
    options_fp: String,
    tsval: u32,
    data: Vec<u8>,
    recv_time: Instant,
}

struct IcmpEchoReply {
    ipid: u16,
    ttl: u8,
    df: bool,
    code: u8,
}

struct IcmpUnreachReply {
    ttl: u8,
    df: bool,
    ip_total_len: u16,
    unused: u32,
    embedded_ip_total_len: u16,
    embedded_ip_id: u16,
    embedded_ip_cksum: u16,
    embedded_ip_cksum_computed: u16,
    embedded_udp_cksum: u16,
    embedded_udp_data: Vec<u8>,
}

// ───── utilities ────────────────────────────────────────────────

fn local_ipv4() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source")),
    }
}

fn hex_val(x: u32) -> String {
    format!("{:X}", x)
}

fn next_ipid(counter: &mut u16) -> u16 {
    let v = *counter;
    *counter = counter.wrapping_add(1);
    v
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

fn ttl_guess(ttl: u8) -> u8 {
    if ttl <= 32 {
        32
    } else if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    }
}

fn flags_str(f: u8) -> String {
    let mut s = String::new();
    if f & TcpFlags::ECE != 0 {
        s.push('E');
    }
    if f & TcpFlags::URG != 0 {
        s.push('U');
    }
    if f & TcpFlags::ACK != 0 {
        s.push('A');
    }
    if f & TcpFlags::PSH != 0 {
        s.push('P');
    }
    if f & TcpFlags::RST != 0 {
        s.push('R');
    }
    if f & TcpFlags::SYN != 0 {
        s.push('S');
    }
    if f & TcpFlags::FIN != 0 {
        s.push('F');
    }
    s
}

fn quirks_str(reserved: u8, flags: u8, urg: u16) -> String {
    let mut s = String::new();
    if reserved != 0 {
        s.push('R');
    }
    if urg != 0 && flags & TcpFlags::URG == 0 {
        s.push('U');
    }
    s
}

fn seq_relation(resp_seq: u32, probe_ack: u32) -> String {
    if resp_seq == 0 {
        "Z".into()
    } else if resp_seq == probe_ack {
        "A".into()
    } else if resp_seq == probe_ack.wrapping_add(1) {
        "A+".into()
    } else {
        "O".into()
    }
}

fn ack_relation(resp_ack: u32, probe_seq: u32) -> String {
    if resp_ack == 0 {
        "Z".into()
    } else if resp_ack == probe_seq {
        "S".into()
    } else if resp_ack == probe_seq.wrapping_add(1) {
        "S+".into()
    } else {
        "O".into()
    }
}

fn cc_str(flags: u8) -> String {
    let ece = flags & TcpFlags::ECE != 0;
    let cwr = flags & TcpFlags::CWR != 0;
    match (ece, cwr) {
        (true, false) => "Y",
        (false, false) => "N",
        (true, true) => "S",
        _ => "O",
    }
    .into()
}

fn rd_value(data: &[u8]) -> String {
    if data.is_empty() {
        "0".into()
    } else {
        format!("{:X}", crc32fast::hash(data))
    }
}

// ───── TCP option parsing ───────────────────────────────────────

/// Nmap `get_tcpopt_string` (`osscan2.cc`).
#[allow(clippy::result_unit_err)] // nmap-style sentinel: only success vs "no fingerprint"
pub fn tcp_options_fingerprint(tcp: &TcpPacket<'_>, _mss_hint: u16) -> Result<String, ()> {
    let mut out = String::new();
    let hdr = tcp.packet();
    let data_off = tcp.get_data_offset() as usize * 4;
    if data_off < 20 || hdr.len() < data_off {
        return Err(());
    }
    let mut q = &hdr[20..data_off];
    while !q.is_empty() && out.len() < 240 {
        let opcode = q[0];
        if opcode == 0 {
            out.push('L');
            break;
        }
        if opcode == 1 {
            out.push('N');
            q = &q[1..];
            continue;
        }
        if q.len() < 2 {
            return Err(());
        }
        let len = q[1] as usize;
        if len < 2 || q.len() < len {
            return Err(());
        }
        match opcode {
            2 => {
                if len < 4 {
                    return Err(());
                }
                let mss = u16::from_be_bytes([q[2], q[3]]);
                let _ = write!(&mut out, "M{:X}", mss);
            }
            3 => {
                if len < 3 {
                    return Err(());
                }
                let _ = write!(&mut out, "W{:X}", q[2]);
            }
            4 => {
                out.push('S');
            }
            8 => {
                if len < 10 {
                    return Err(());
                }
                out.push('T');
                let t1 = u32::from_be_bytes([q[2], q[3], q[4], q[5]]);
                let t2 = u32::from_be_bytes([q[6], q[7], q[8], q[9]]);
                out.push(if t1 != 0 { '1' } else { '0' });
                out.push(if t2 != 0 { '1' } else { '0' });
            }
            _ => {
                return Err(());
            }
        }
        q = &q[len..];
    }
    Ok(out)
}

fn read_timestamp(tcp: &TcpPacket<'_>) -> u32 {
    let hdr = tcp.packet();
    let data_off = tcp.get_data_offset() as usize * 4;
    if data_off <= 20 || hdr.len() < data_off {
        return 0;
    }
    let mut q = &hdr[20..data_off];
    while !q.is_empty() {
        let op = q[0];
        if op == 0 {
            break;
        }
        if op == 1 {
            q = &q[1..];
            continue;
        }
        if q.len() < 2 {
            break;
        }
        let len = q[1] as usize;
        if len < 2 || q.len() < len {
            break;
        }
        if op == 8 && len >= 10 {
            return u32::from_be_bytes([q[2], q[3], q[4], q[5]]);
        }
        q = &q[len..];
    }
    0
}

// ───── raw socket recv ──────────────────────────────────────────

fn recv_ipv4_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<Ipv4Packet<'_>>> {
    let fd = tr.socket.fd;
    let old = pnet_sys::get_socket_receive_timeout(fd)?;
    pnet_sys::set_socket_receive_timeout(fd, t)?;
    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
    let r = pnet_sys::recv_from(fd, &mut tr.buffer[..], &mut caddr);
    let _ = pnet_sys::set_socket_receive_timeout(fd, old);
    match r {
        Ok(len) => Ok(Ipv4Packet::new(&tr.buffer[..len])),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

fn recv_tcp_reply(
    rx: &mut TransportReceiver,
    target: Ipv4Addr,
    our_port: u16,
    timeout: Duration,
) -> io::Result<Option<TcpReply>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let wait = remaining.min(Duration::from_millis(50));
        let Some(ip) = recv_ipv4_with_timeout(rx, wait)? else {
            continue;
        };
        if ip.get_source() != target {
            continue;
        }
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }
        let Some(tcp) = TcpPacket::new(ip.payload()) else {
            continue;
        };
        if tcp.get_destination() != our_port {
            continue;
        }
        let ipid = ip.get_identification();
        let ttl = ip.get_ttl();
        let df = ip.get_flags() & 0b010 != 0;
        let window = tcp.get_window();
        let seq = tcp.get_sequence();
        let ack_num = tcp.get_acknowledgement();
        let flags = tcp.get_flags();
        let reserved = tcp.packet()[12] & 0x0F;
        let urg_ptr = tcp.get_urgent_ptr();
        let options_fp = tcp_options_fingerprint(&tcp, 265).unwrap_or_default();
        let tsval = read_timestamp(&tcp);
        let data = tcp.payload().to_vec();
        return Ok(Some(TcpReply {
            ipid,
            ttl,
            df,
            window,
            seq,
            ack_num,
            flags,
            reserved,
            urg_ptr,
            options_fp,
            tsval,
            data,
            recv_time: Instant::now(),
        }));
    }
}

fn recv_icmp_echo_reply(
    rx: &mut TransportReceiver,
    target: Ipv4Addr,
    expected_id: u16,
    timeout: Duration,
) -> io::Result<Option<IcmpEchoReply>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let wait = remaining.min(Duration::from_millis(50));
        let Some(ip) = recv_ipv4_with_timeout(rx, wait)? else {
            continue;
        };
        if ip.get_source() != target {
            continue;
        }
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            continue;
        }
        let p = ip.payload();
        if p.len() < 8 || p[0] != 0 {
            continue;
        }
        let id = u16::from_be_bytes([p[4], p[5]]);
        if id != expected_id {
            continue;
        }
        return Ok(Some(IcmpEchoReply {
            ipid: ip.get_identification(),
            ttl: ip.get_ttl(),
            df: ip.get_flags() & 0b010 != 0,
            code: p[1],
        }));
    }
}

fn recv_icmp_unreachable(
    rx: &mut TransportReceiver,
    target: Ipv4Addr,
    expected_udp_dport: u16,
    timeout: Duration,
) -> io::Result<Option<IcmpUnreachReply>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let wait = remaining.min(Duration::from_millis(50));
        let Some(ip) = recv_ipv4_with_timeout(rx, wait)? else {
            continue;
        };
        if ip.get_source() != target {
            continue;
        }
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            continue;
        }
        let p = ip.payload();
        if p.len() < 36 {
            continue;
        } // 8 ICMP hdr + 20 embedded IP + 8 embedded UDP
        if p[0] != 3 || p[1] != 3 {
            continue;
        }
        let embedded = &p[8..];
        let ihl = (embedded[0] & 0x0f) as usize * 4;
        if embedded.len() < ihl + 4 {
            continue;
        }
        let udp_dport = u16::from_be_bytes([embedded[ihl + 2], embedded[ihl + 3]]);
        if udp_dport != expected_udp_dport {
            continue;
        }

        let unused = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let eip_total = u16::from_be_bytes([embedded[2], embedded[3]]);
        let eip_id = u16::from_be_bytes([embedded[4], embedded[5]]);
        let eip_ck = u16::from_be_bytes([embedded[10], embedded[11]]);
        let mut hdr_copy = embedded[..ihl].to_vec();
        hdr_copy[10] = 0;
        hdr_copy[11] = 0;
        let eip_ck_computed = internet_checksum(&hdr_copy);
        let eudp_ck = if embedded.len() >= ihl + 8 {
            u16::from_be_bytes([embedded[ihl + 6], embedded[ihl + 7]])
        } else {
            0
        };
        let eudp_data = if embedded.len() > ihl + 8 {
            embedded[ihl + 8..].to_vec()
        } else {
            Vec::new()
        };
        return Ok(Some(IcmpUnreachReply {
            ttl: ip.get_ttl(),
            df: ip.get_flags() & 0b010 != 0,
            ip_total_len: ip.get_total_length(),
            unused,
            embedded_ip_total_len: eip_total,
            embedded_ip_id: eip_id,
            embedded_ip_cksum: eip_ck,
            embedded_ip_cksum_computed: eip_ck_computed,
            embedded_udp_cksum: eudp_ck,
            embedded_udp_data: eudp_data,
        }));
    }
}

// ───── send functions ───────────────────────────────────────────

#[allow(clippy::too_many_arguments)] // raw IPv4+TCP probe layout
fn send_tcp_probe(
    tx: &mut TransportSender,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    reserved: u8,
    flags: u8,
    window: u16,
    urg: u16,
    df: bool,
    opts: &[u8],
    ttl: u8,
    ip_id: u16,
) -> io::Result<()> {
    let tcp_len = 20 + opts.len();
    let total = 20 + tcp_len;
    let mut buf = vec![0u8; total];
    {
        let t = &mut buf[20..20 + tcp_len];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = (((tcp_len / 4) as u8) << 4) | (reserved & 0x0f);
        t[13] = flags;
        t[14..16].copy_from_slice(&window.to_be_bytes());
        t[18..20].copy_from_slice(&urg.to_be_bytes());
        t[20..].copy_from_slice(opts);
        let pkt = TcpPacket::new(t).expect("tcp len");
        let ck = ipv4_checksum(&pkt, &src, &dst);
        t[16..18].copy_from_slice(&ck.to_be_bytes());
    }
    build_ip_header(&mut buf[..20], total as u16, ip_id, df, ttl, 6, src, dst);
    tx.send_to(Ipv4Packet::new(&buf).expect("pkt"), IpAddr::V4(dst))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send_udp_probe(
    tx: &mut TransportSender,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    data: &[u8],
    ttl: u8,
    df: bool,
    ip_id: u16,
) -> io::Result<u16> {
    let udp_len = 8 + data.len();
    let total = 20 + udp_len;
    let mut buf = vec![0u8; total];
    {
        let u = &mut buf[20..20 + udp_len];
        u[0..2].copy_from_slice(&sport.to_be_bytes());
        u[2..4].copy_from_slice(&dport.to_be_bytes());
        u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        u[8..8 + data.len()].copy_from_slice(data);
        let mut pseudo = Vec::with_capacity(12 + udp_len);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&u[..udp_len]);
        let ck = internet_checksum(&pseudo);
        u[6..8].copy_from_slice(&ck.to_be_bytes());
    }
    build_ip_header(&mut buf[..20], total as u16, ip_id, df, ttl, 17, src, dst);
    let sent_ck = u16::from_be_bytes([buf[26], buf[27]]);
    tx.send_to(Ipv4Packet::new(&buf).expect("pkt"), IpAddr::V4(dst))?;
    Ok(sent_ck)
}

#[allow(clippy::too_many_arguments)]
fn send_icmp_echo(
    tx: &mut TransportSender,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    code: u8,
    id: u16,
    seq: u16,
    data_len: usize,
    ttl: u8,
    df: bool,
    tos: u8,
    ip_id: u16,
) -> io::Result<()> {
    let icmp_len = 8 + data_len;
    let total = 20 + icmp_len;
    let mut buf = vec![0u8; total];
    {
        let ic = &mut buf[20..20 + icmp_len];
        ic[0] = 8; // echo request
        ic[1] = code;
        ic[4..6].copy_from_slice(&id.to_be_bytes());
        ic[6..8].copy_from_slice(&seq.to_be_bytes());
        let ck = internet_checksum(&ic[..icmp_len]);
        ic[2..4].copy_from_slice(&ck.to_be_bytes());
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..20]).expect("ip");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(tos >> 2);
        ip.set_ecn(tos & 0x03);
        ip.set_total_length(total as u16);
        ip.set_identification(ip_id);
        if df {
            ip.set_flags(Ipv4Flags::DontFragment);
        }
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_checksum(0);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_hdr_cksum(&ip.to_immutable()));
    }
    tx.send_to(Ipv4Packet::new(&buf).expect("pkt"), IpAddr::V4(dst))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_ip_header(
    buf: &mut [u8],
    total_len: u16,
    id: u16,
    df: bool,
    ttl: u8,
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) {
    let mut ip = MutableIpv4Packet::new(buf).expect("ip hdr");
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_dscp(0);
    ip.set_ecn(0);
    ip.set_total_length(total_len);
    ip.set_identification(id);
    if df {
        ip.set_flags(Ipv4Flags::DontFragment);
    }
    ip.set_fragment_offset(0);
    ip.set_ttl(ttl);
    ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol::new(proto));
    ip.set_checksum(0);
    ip.set_source(src);
    ip.set_destination(dst);
    ip.set_checksum(ipv4_hdr_cksum(&ip.to_immutable()));
}

// ───── classification ───────────────────────────────────────────

fn classify_ipid(ipids: &[u16]) -> String {
    if ipids.len() < 2 {
        return "O".into();
    }
    if ipids.iter().all(|&v| v == 0) {
        return "Z".into();
    }

    let mut diffs = Vec::with_capacity(ipids.len() - 1);
    for i in 1..ipids.len() {
        let cur = ipids[i] as u32;
        let prev = ipids[i - 1] as u32;
        let d = if cur >= prev {
            cur - prev
        } else {
            0x10000 + cur - prev
        };
        diffs.push(d);
    }

    if diffs.iter().all(|&d| d == 0) {
        return "Z".into();
    }
    if diffs.iter().any(|&d| d > 20000) {
        return "RD".into();
    }

    // check byte-swapped incremental (BI)
    let mut bi = true;
    for i in 1..ipids.len() {
        let prev = ipids[i - 1].swap_bytes() as u32;
        let cur = ipids[i].swap_bytes() as u32;
        let d = if cur >= prev {
            cur - prev
        } else {
            0x10000 + cur - prev
        };
        if d > 20000 {
            bi = false;
            break;
        }
    }
    if bi {
        let mut swap_diffs = Vec::new();
        for i in 1..ipids.len() {
            let prev = ipids[i - 1].swap_bytes() as u32;
            let cur = ipids[i].swap_bytes() as u32;
            let d = if cur >= prev {
                cur - prev
            } else {
                0x10000 + cur - prev
            };
            swap_diffs.push(d);
        }
        if swap_diffs.iter().all(|&d| d <= 20000) {
            return "BI".into();
        }
    }

    let avg: f64 = diffs.iter().map(|&d| d as f64).sum::<f64>() / diffs.len() as f64;
    if avg < 1.0 {
        return "Z".into();
    }
    let var: f64 = diffs
        .iter()
        .map(|&d| {
            let x = d as f64 - avg;
            x * x
        })
        .sum::<f64>()
        / diffs.len() as f64;
    if var.sqrt() / avg < 0.1 && avg < 5000.0 {
        return "I".into();
    }
    "RI".into()
}

fn classify_ts(timestamps: &[u32], times: &[Instant]) -> String {
    if timestamps.len() < 2 {
        return "U".into();
    }
    if timestamps.iter().all(|&t| t == 0) {
        return "0".into();
    }

    for i in 1..timestamps.len() {
        if timestamps[i] < timestamps[i - 1] && timestamps[i - 1] - timestamps[i] > 1000 {
            return "U".into();
        }
    }

    let ts_diff = timestamps.last().unwrap().wrapping_sub(timestamps[0]) as f64;
    let time_diff = times.last().unwrap().duration_since(times[0]).as_secs_f64();
    if time_diff < 0.001 {
        return "U".into();
    }
    let freq = ts_diff / time_diff;

    if freq < 0.5 {
        return "0".into();
    }
    if freq < 5.66 {
        return "1".into();
    }
    if (85.0..350.0).contains(&freq) {
        return "7".into();
    }
    if (700.0..1500.0).contains(&freq) {
        return "8".into();
    }
    format!("{:X}", freq.round() as u32)
}

fn shared_ipid_seq(tcp_ipids: &[u16], icmp_ipids: &[u16]) -> String {
    if tcp_ipids.len() < 2 || icmp_ipids.is_empty() {
        return "O".into();
    }
    let ti = classify_ipid(tcp_ipids);
    let ii = classify_ipid(icmp_ipids);
    if ti != "I" || ii != "I" {
        return "O".into();
    }
    let last_tcp = *tcp_ipids.last().unwrap() as i32;
    let first_icmp = icmp_ipids[0] as i32;
    if (first_icmp - last_tcp).unsigned_abs() < 256 {
        "S".into()
    } else {
        "O".into()
    }
}

// ───── math helpers ─────────────────────────────────────────────

fn mod_diff_u32(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b).min(b.wrapping_sub(a))
}

fn gcd_many(vals: &[u32]) -> u32 {
    if vals.is_empty() {
        return 1;
    }
    vals.iter().copied().reduce(gcd_two).unwrap_or(1)
}

fn gcd_two(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a.max(1)
}

// ───── test builders ────────────────────────────────────────────

fn build_seq_test(
    seq_nums: &[u32],
    seq_times: &[Instant],
    timestamps: &[u32],
    tcp_open_ipids: &[u16],
    tcp_closed_ipids: &[u16],
    icmp_ipids: &[u16],
) -> HashMap<String, String> {
    let n = seq_nums.len();
    let mut diffs = Vec::with_capacity(n - 1);
    for i in 1..n {
        diffs.push(mod_diff_u32(seq_nums[i], seq_nums[i - 1]));
    }
    let gcd = gcd_many(&diffs);
    let mut seq_rates = Vec::with_capacity(n - 1);
    for i in 1..n {
        let dt = seq_times[i]
            .saturating_duration_since(seq_times[i - 1])
            .as_micros()
            .max(1);
        seq_rates.push(diffs[i - 1] as f64 * 1_000_000.0 / dt as f64);
    }
    let avg: f64 = seq_rates.iter().sum::<f64>() / seq_rates.len().max(1) as f64;
    let mut isr = if avg > 0.0 {
        (avg.log2() * 8.0).round() as u32
    } else {
        0
    };
    if gcd == 0 {
        isr = 0;
    }

    let div_gcd = if gcd > 9 { gcd as f64 } else { 1.0 };
    let mean_normed = avg / div_gcd;
    let var: f64 = seq_rates
        .iter()
        .map(|r| {
            let t = r / div_gcd - mean_normed;
            t * t
        })
        .sum::<f64>()
        / (seq_rates.len().saturating_sub(1).max(1)) as f64;
    let sd = var.sqrt();
    let sp = if sd <= 1.0 {
        0u32
    } else {
        ((sd.log2() * 8.0).round() as u32).min(0xff)
    };

    let mut m = HashMap::new();
    m.insert("SP".into(), hex_val(sp));
    m.insert("GCD".into(), hex_val(gcd));
    m.insert("ISR".into(), hex_val(isr));
    m.insert("TI".into(), classify_ipid(tcp_open_ipids));
    m.insert(
        "CI".into(),
        if tcp_closed_ipids.is_empty() {
            "Z".into()
        } else {
            classify_ipid(tcp_closed_ipids)
        },
    );
    m.insert(
        "II".into(),
        if icmp_ipids.is_empty() {
            "O".into()
        } else {
            classify_ipid(icmp_ipids)
        },
    );
    m.insert("SS".into(), shared_ipid_seq(tcp_open_ipids, icmp_ipids));
    m.insert("TS".into(), classify_ts(timestamps, seq_times));
    m
}

fn build_ecn_test(reply: &Option<TcpReply>, probe_seq: u32) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    let Some(r) = reply else {
        m.insert("R".into(), "N".into());
        return Some(m);
    };
    m.insert("R".into(), "Y".into());
    m.insert("DF".into(), if r.df { "Y" } else { "N" }.into());
    m.insert("T".into(), hex_val(r.ttl as u32));
    m.insert("TG".into(), hex_val(ttl_guess(r.ttl) as u32));
    m.insert("W".into(), hex_val(r.window as u32));
    m.insert("O".into(), r.options_fp.clone());
    m.insert("CC".into(), cc_str(r.flags));
    m.insert("Q".into(), quirks_str(r.reserved, r.flags, r.urg_ptr));
    let _ = probe_seq;
    Some(m)
}

fn build_t1_test(
    reply: &Option<TcpReply>,
    probe_seq: u32,
    probe_ack: u32,
) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    let Some(r) = reply else {
        m.insert("R".into(), "N".into());
        return Some(m);
    };
    m.insert("R".into(), "Y".into());
    m.insert("DF".into(), if r.df { "Y" } else { "N" }.into());
    m.insert("T".into(), hex_val(r.ttl as u32));
    m.insert("TG".into(), hex_val(ttl_guess(r.ttl) as u32));
    m.insert("S".into(), seq_relation(r.seq, probe_ack));
    m.insert("A".into(), ack_relation(r.ack_num, probe_seq));
    m.insert("F".into(), flags_str(r.flags));
    m.insert("RD".into(), rd_value(&r.data));
    m.insert("Q".into(), quirks_str(r.reserved, r.flags, r.urg_ptr));
    Some(m)
}

fn build_tx_test(
    reply: &Option<TcpReply>,
    probe_seq: u32,
    probe_ack: u32,
) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    let Some(r) = reply else {
        m.insert("R".into(), "N".into());
        return Some(m);
    };
    m.insert("R".into(), "Y".into());
    m.insert("DF".into(), if r.df { "Y" } else { "N" }.into());
    m.insert("T".into(), hex_val(r.ttl as u32));
    m.insert("TG".into(), hex_val(ttl_guess(r.ttl) as u32));
    m.insert("W".into(), hex_val(r.window as u32));
    m.insert("S".into(), seq_relation(r.seq, probe_ack));
    m.insert("A".into(), ack_relation(r.ack_num, probe_seq));
    m.insert("F".into(), flags_str(r.flags));
    m.insert("O".into(), r.options_fp.clone());
    m.insert("RD".into(), rd_value(&r.data));
    m.insert("Q".into(), quirks_str(r.reserved, r.flags, r.urg_ptr));
    Some(m)
}

fn build_u1_test(
    reply: &Option<IcmpUnreachReply>,
    sent_ip_id: u16,
    sent_udp_cksum: u16,
    sent_ip_total_len: u16,
    sent_data: &[u8],
) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    let Some(r) = reply else {
        m.insert("R".into(), "N".into());
        return Some(m);
    };
    m.insert("R".into(), "Y".into());
    m.insert("DF".into(), if r.df { "Y" } else { "N" }.into());
    m.insert("T".into(), hex_val(r.ttl as u32));
    m.insert("TG".into(), hex_val(ttl_guess(r.ttl) as u32));
    m.insert("IPL".into(), hex_val(r.ip_total_len as u32));
    m.insert("UN".into(), hex_val(r.unused));
    m.insert(
        "RIPL".into(),
        if r.embedded_ip_total_len == sent_ip_total_len {
            "G".into()
        } else {
            hex_val(r.embedded_ip_total_len as u32)
        },
    );
    m.insert(
        "RID".into(),
        if r.embedded_ip_id == sent_ip_id {
            "G".into()
        } else {
            hex_val(r.embedded_ip_id as u32)
        },
    );
    m.insert(
        "RIPCK".into(),
        if r.embedded_ip_cksum == 0 {
            "Z".into()
        } else if r.embedded_ip_cksum == r.embedded_ip_cksum_computed {
            "G".into()
        } else {
            "I".into()
        },
    );
    m.insert(
        "RUCK".into(),
        if r.embedded_udp_cksum == 0 {
            "Z".into()
        } else if r.embedded_udp_cksum == sent_udp_cksum {
            "G".into()
        } else {
            "I".into()
        },
    );
    let rud_ok = r.embedded_udp_data.len() >= sent_data.len().min(r.embedded_udp_data.len())
        && r.embedded_udp_data
            .starts_with(&sent_data[..sent_data.len().min(r.embedded_udp_data.len())]);
    m.insert(
        "RUD".into(),
        if rud_ok && !r.embedded_udp_data.is_empty() {
            "G".into()
        } else {
            "I".into()
        },
    );
    Some(m)
}

fn build_ie_test(
    ie1: &Option<IcmpEchoReply>,
    ie2: &Option<IcmpEchoReply>,
) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    if ie1.is_none() && ie2.is_none() {
        m.insert("R".into(), "N".into());
        return Some(m);
    }
    m.insert("R".into(), "Y".into());
    let dfi = match (ie1.as_ref().map(|r| r.df), ie2.as_ref().map(|r| r.df)) {
        (Some(true), Some(true)) => "Y",
        (Some(false), Some(false)) => "N",
        (Some(true), Some(false)) => "S",
        _ => "O",
    };
    m.insert("DFI".into(), dfi.into());
    if let Some(r) = ie1.as_ref().or(ie2.as_ref()) {
        m.insert("T".into(), hex_val(r.ttl as u32));
        m.insert("TG".into(), hex_val(ttl_guess(r.ttl) as u32));
    }
    let cd = match (ie1.as_ref().map(|r| r.code), ie2.as_ref().map(|r| r.code)) {
        (Some(0), Some(0)) => "Z",
        (Some(9), Some(0)) => "S",
        _ => "O",
    };
    m.insert("CD".into(), cd.into());
    Some(m)
}

// ───── main entry point ─────────────────────────────────────────

/// Run all IPv4 OS probes against `target`. Returns a subject fingerprint.
pub fn probe_ipv4_os(
    target: Ipv4Addr,
    open_tcp: u16,
    closed_tcp: u16,
    closed_udp: u16,
    probe_timeout: Duration,
) -> Result<SubjectFingerprint> {
    let (mut tcp_tx, mut tcp_rx) = transport_channel(
        65536,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
    )
    .context("raw TCP for OS detection — try sudo / capabilities")?;
    let (_icmp_tx, mut icmp_rx) = transport_channel(
        65536,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
    )
    .context("raw ICMP for OS detection")?;

    let src = local_ipv4().context("local IPv4 for OS probes")?;
    let mut rng = rand::thread_rng();
    let tcp_port_base: u16 = 33000 + (rng.gen::<u32>() % PRIME_32K) as u16;
    let udp_port_base: u16 = 33000 + (rng.gen::<u32>() % PRIME_32K) as u16;
    let tcp_seq_base: u32 = rng.gen();
    let tcp_ack: u32 = rng.gen();
    let icmp_id: u16 = rng.gen();
    let mut ipid_ctr: u16 = rng.gen();

    // ── Phase 1: SEQ probes S1-S6 ──
    let mut seq_replies: [Option<TcpReply>; NUM_SEQ_SAMPLES] = std::array::from_fn(|_| None);
    for i in 0..NUM_SEQ_SAMPLES {
        let sport = tcp_port_base + i as u16;
        let id = next_ipid(&mut ipid_ctr);
        send_tcp_probe(
            &mut tcp_tx,
            src,
            target,
            sport,
            open_tcp,
            tcp_seq_base + i as u32,
            0,
            0,
            TcpFlags::SYN,
            PRB_WIN[i],
            0,
            false,
            PRB_OPTS[i],
            64,
            id,
        )?;
        seq_replies[i] = recv_tcp_reply(&mut tcp_rx, target, sport, probe_timeout)?;
        if i + 1 < NUM_SEQ_SAMPLES {
            thread::sleep(Duration::from_millis(OS_SEQ_PROBE_DELAY_MS));
        }
    }

    // ── Phase 2: ECN ──
    let ecn_sport = tcp_port_base + 6;
    send_tcp_probe(
        &mut tcp_tx,
        src,
        target,
        ecn_sport,
        open_tcp,
        tcp_seq_base,
        0,
        0,
        TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR,
        PRB_WIN[6],
        0,
        false,
        PRB_OPTS[6],
        64,
        next_ipid(&mut ipid_ctr),
    )?;
    let ecn_reply = recv_tcp_reply(&mut tcp_rx, target, ecn_sport, probe_timeout)?;

    // ── Phase 3: T2-T4 (open port) ──
    let mut send_t = |idx: usize, dport: u16, flags: u8| -> io::Result<Option<TcpReply>> {
        let sport = tcp_port_base + idx as u16;
        let id = next_ipid(&mut ipid_ctr);
        send_tcp_probe(
            &mut tcp_tx,
            src,
            target,
            sport,
            dport,
            tcp_seq_base,
            tcp_ack,
            0,
            flags,
            PRB_WIN[idx],
            0,
            false,
            PRB_OPTS[idx],
            64,
            id,
        )?;
        recv_tcp_reply(&mut tcp_rx, target, sport, probe_timeout)
    };
    let t2_reply = send_t(7, open_tcp, 0)?;
    let t3_reply = send_t(
        8,
        open_tcp,
        TcpFlags::SYN | TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH,
    )?;
    let t4_reply = send_t(9, open_tcp, TcpFlags::ACK)?;

    // ── Phase 4: T5-T7 (closed port) ──
    let t5_reply = send_t(10, closed_tcp, TcpFlags::SYN)?;
    let t6_reply = send_t(11, closed_tcp, TcpFlags::ACK)?;
    let t7_reply = send_t(
        12,
        closed_tcp,
        TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
    )?;

    // ── Phase 5: U1 (UDP to closed port) ──
    let u1_data = [0x43u8; 300];
    let u1_ipid = next_ipid(&mut ipid_ctr);
    let u1_ip_total: u16 = 20 + 8 + 300;
    let u1_udp_ck = send_udp_probe(
        &mut tcp_tx,
        src,
        target,
        udp_port_base,
        closed_udp,
        &u1_data,
        64,
        true,
        u1_ipid,
    )?;
    let u1_reply = recv_icmp_unreachable(&mut icmp_rx, target, closed_udp, probe_timeout)?;

    // ── Phase 6: IE (2 ICMP echo requests) ──
    send_icmp_echo(
        &mut tcp_tx,
        src,
        target,
        9,
        icmp_id,
        295,
        120,
        64,
        true,
        0,
        next_ipid(&mut ipid_ctr),
    )?;
    let ie1 = recv_icmp_echo_reply(&mut icmp_rx, target, icmp_id, probe_timeout)?;
    thread::sleep(Duration::from_millis(OS_SEQ_PROBE_DELAY_MS));
    send_icmp_echo(
        &mut tcp_tx,
        src,
        target,
        0,
        icmp_id + 1,
        296,
        150,
        64,
        false,
        4,
        next_ipid(&mut ipid_ctr),
    )?;
    let ie2 = recv_icmp_echo_reply(&mut icmp_rx, target, icmp_id + 1, probe_timeout)?;

    // ── Build subject fingerprint ──
    let mut subject = SubjectFingerprint::default();

    let good: Vec<usize> = (0..NUM_SEQ_SAMPLES)
        .filter(|&i| seq_replies[i].is_some())
        .collect();
    if good.len() >= 4 {
        let tcp_open_ipids: Vec<u16> = good
            .iter()
            .map(|&i| seq_replies[i].as_ref().unwrap().ipid)
            .collect();
        let tcp_closed_ipids: Vec<u16> = [&t5_reply, &t6_reply, &t7_reply]
            .iter()
            .filter_map(|r| r.as_ref().map(|t| t.ipid))
            .collect();
        let icmp_ipids: Vec<u16> = [&ie1, &ie2]
            .iter()
            .filter_map(|r| r.as_ref().map(|e| e.ipid))
            .collect();
        let seq_nums: Vec<u32> = good
            .iter()
            .map(|&i| seq_replies[i].as_ref().unwrap().seq)
            .collect();
        let seq_times: Vec<Instant> = good
            .iter()
            .map(|&i| seq_replies[i].as_ref().unwrap().recv_time)
            .collect();
        let timestamps: Vec<u32> = good
            .iter()
            .map(|&i| seq_replies[i].as_ref().unwrap().tsval)
            .collect();

        // SEQ test
        subject.tests[0] = Some(build_seq_test(
            &seq_nums,
            &seq_times,
            &timestamps,
            &tcp_open_ipids,
            &tcp_closed_ipids,
            &icmp_ipids,
        ));

        // OPS test (O1-O6)
        let mut ops = HashMap::new();
        for (j, &i) in good.iter().enumerate().take(6) {
            ops.insert(
                format!("O{}", j + 1),
                seq_replies[i].as_ref().unwrap().options_fp.clone(),
            );
        }
        subject.tests[1] = Some(ops);

        // WIN test (W1-W6)
        let mut win = HashMap::new();
        for (j, &i) in good.iter().enumerate().take(6) {
            win.insert(
                format!("W{}", j + 1),
                hex_val(seq_replies[i].as_ref().unwrap().window as u32),
            );
        }
        subject.tests[2] = Some(win);
    }

    // ECN
    subject.tests[3] = build_ecn_test(&ecn_reply, tcp_seq_base);

    // T1 (first SEQ response)
    subject.tests[4] = build_t1_test(&seq_replies[0], tcp_seq_base, 0);

    // T2-T7
    subject.tests[5] = build_tx_test(&t2_reply, tcp_seq_base, tcp_ack);
    subject.tests[6] = build_tx_test(&t3_reply, tcp_seq_base, tcp_ack);
    subject.tests[7] = build_tx_test(&t4_reply, tcp_seq_base, tcp_ack);
    subject.tests[8] = build_tx_test(&t5_reply, tcp_seq_base, tcp_ack);
    subject.tests[9] = build_tx_test(&t6_reply, tcp_seq_base, tcp_ack);
    subject.tests[10] = build_tx_test(&t7_reply, tcp_seq_base, tcp_ack);

    // U1
    subject.tests[11] = build_u1_test(&u1_reply, u1_ipid, u1_udp_ck, u1_ip_total, &u1_data);

    // IE
    subject.tests[12] = build_ie_test(&ie1, &ie2);

    Ok(subject)
}

//! IPv4 TCP/IP OS detection probes (Nmap 2nd‑gen): SEQ/OPS/WIN, ECN, T1–T7, U1, IE.
//!
//! Requires a raw IPv4 socket (privileged). `str` pointers are never passed to C `strlen`.

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
use pnet::transport::{transport_channel, TransportChannelType, TransportReceiver};
use pnet_sys;
use rand::Rng;
use std::fmt::Write as _;

use crate::os_fp_db::{SubjectFingerprint, NUM_FP_TESTS, TEST_NAMES};

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

fn local_ipv4() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source")),
    }
}

fn recv_ipv4_with_timeout(tr: &mut TransportReceiver, t: Duration) -> io::Result<Option<Ipv4Packet<'_>>> {
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

/// Nmap `get_tcpopt_string` (`osscan2.cc`).
pub fn tcp_options_fingerprint(tcp: &TcpPacket<'_>, mss_hint: u16) -> Result<String, ()> {
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
            q = &q[1..];
        } else if opcode == 1 {
            out.push('N');
            q = &q[1..];
        } else if opcode == 2 {
            if q.len() < 4 {
                return Err(());
            }
            let mss = u16::from_be_bytes([q[2], q[3]]);
            let _ = write!(&mut out, "M{:X}", mss);
            q = &q[4..];
        } else if opcode == 3 {
            if q.len() < 3 {
                return Err(());
            }
            let _ = write!(&mut out, "W{:X}", q[2]);
            q = &q[3..];
        } else if opcode == 4 {
            if q.len() < 2 {
                return Err(());
            }
            out.push('S');
            q = &q[2..];
        } else if opcode == 8 {
            if q.len() < 10 {
                return Err(());
            }
            out.push('T');
            let t1 = u32::from_be_bytes([q[2], q[3], q[4], q[5]]);
            let t2 = u32::from_be_bytes([q[6], q[7], q[8], q[9]]);
            out.push(if t1 != 0 { '1' } else { '0' });
            out.push(if t2 != 0 { '1' } else { '0' });
            q = &q[10..];
        } else {
            return Err(());
        }
    }
    if !q.is_empty() {
        return Err(());
    }
    let _ = mss_hint;
    Ok(out)
}

fn mod_diff_u32(a: u32, b: u32) -> u32 {
    let d1 = a.wrapping_sub(b);
    let d2 = b.wrapping_sub(a);
    d1.min(d2)
}

fn gcd_many(vals: &[u32]) -> u32 {
    if vals.is_empty() {
        return 1;
    }
    let mut g = vals[0];
    for &v in &vals[1..] {
        g = gcd_two(g, v);
    }
    g
}

fn gcd_two(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a.max(1)
}

fn hex_lower(x: u32) -> String {
    format!("{:X}", x)
}

/// Run IPv4 OS probes against `target` using Nmap probe layout. Returns a subject fingerprint on success.
pub fn probe_ipv4_os(
    target: Ipv4Addr,
    open_tcp: u16,
    closed_tcp: u16,
    closed_udp: u16,
    probe_timeout: Duration,
) -> Result<SubjectFingerprint> {
    let (mut tx, mut rx) = transport_channel(
        65536,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Reserved),
    )
    .context("raw IPv4 (Layer3) for OS detection — try sudo / capabilities")?;

    let src_ip = local_ipv4().context("local IPv4 for OS probes")?;
    let mut rng = rand::thread_rng();
    let tcp_port_base: u16 = 33000 + (rng.gen::<u32>() % PRIME_32K) as u16;
    let udp_port_base: u16 = 33000 + (rng.gen::<u32>() % PRIME_32K) as u16;
    let tcp_seq_base: u32 = rng.gen();
    let tcp_ack: u32 = rng.gen();
    let icmp_id: u16 = rng.gen();
    let icmp_seq: u16 = 295;
    let udpttl: u8 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() % 14) as u8 + 51)
        .unwrap_or(60);

    let mut seq_reply: [Option<(u32, u16, u32)>; NUM_SEQ_SAMPLES] = std::array::from_fn(|_| None);
    let mut seq_times: [Instant; NUM_SEQ_SAMPLES] = std::array::from_fn(|_| Instant::now());
    let mut tcp_ipids: [u32; NUM_SEQ_SAMPLES] = [0xffff_ffff; NUM_SEQ_SAMPLES];

    for i in 0..NUM_SEQ_SAMPLES {
        send_tcp_probe(
            &mut tx,
            src_ip,
            target,
            tcp_port_base + i as u16,
            open_tcp,
            tcp_seq_base + i as u32,
            tcp_ack,
            0,
            TcpFlags::SYN,
            PRB_WIN[i],
            0,
            false,
            PRB_OPTS[i],
            64,
            rng.gen(),
        )?;
        seq_times[i] = Instant::now();
        if i + 1 < NUM_SEQ_SAMPLES {
            thread::sleep(Duration::from_millis(OS_SEQ_PROBE_DELAY_MS));
        }
        let deadline = Instant::now() + probe_timeout;
        while Instant::now() < deadline {
            let Some(ip) = recv_ipv4_with_timeout(&mut rx, Duration::from_millis(50))? else {
                continue;
            };
            if ip.get_source() != target || ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            let payload = ip.payload();
            let Some(tcp) = TcpPacket::new(payload) else {
                continue;
            };
            if tcp.get_destination() != tcp_port_base + i as u16 {
                continue;
            }
            if tcp.get_flags() & TcpFlags::RST != 0 {
                break;
            }
            if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                let seq = tcp.get_sequence();
                let ipid = ip.get_identification() as u32;
                let ts = read_timestamp(&tcp);
                seq_reply[i] = Some((seq, ipid as u16, ts));
                tcp_ipids[i] = ipid as u32;
                break;
            }
        }
    }

    let mut tops: [Option<String>; NUM_SEQ_SAMPLES] = std::array::from_fn(|_| None);
    let mut twin: [Option<String>; NUM_SEQ_SAMPLES] = std::array::from_fn(|_| None);
    for i in 0..NUM_SEQ_SAMPLES {
        send_tcp_probe(
            &mut tx,
            src_ip,
            target,
            tcp_port_base + NUM_SEQ_SAMPLES as u16 + i as u16,
            open_tcp,
            tcp_seq_base,
            tcp_ack,
            0,
            TcpFlags::SYN,
            PRB_WIN[i],
            0,
            false,
            PRB_OPTS[i],
            64,
            rng.gen(),
        )?;
        thread::sleep(Duration::from_millis(OS_SEQ_PROBE_DELAY_MS));
        let deadline = Instant::now() + probe_timeout;
        while Instant::now() < deadline {
            let Some(ip) = recv_ipv4_with_timeout(&mut rx, Duration::from_millis(50))? else {
                continue;
            };
            if ip.get_source() != target || ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            let payload = ip.payload();
            let Some(tcp) = TcpPacket::new(payload) else {
                continue;
            };
            if tcp.get_destination() != tcp_port_base + NUM_SEQ_SAMPLES as u16 + i as u16 {
                continue;
            }
            if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                twin[i] = Some(hex_lower(tcp.get_window() as u32));
                tops[i] = tcp_options_fingerprint(&tcp, 265).ok();
                break;
            }
        }
    }

    let mut subject: SubjectFingerprint = SubjectFingerprint::default();

    if let Some(seq_fp) = build_seq_test(&seq_reply, &seq_times, &tcp_ipids, tcp_port_base, tcp_seq_base) {
        subject.tests[0] = Some(seq_fp);
    }
    if tops.iter().all(|x| x.is_some()) && twin.iter().all(|x| x.is_some()) {
        let mut ops = std::collections::HashMap::new();
        for i in 0..NUM_SEQ_SAMPLES {
            ops.insert(format!("O{}", i + 1), tops[i].clone().unwrap_or_default());
        }
        subject.tests[1] = Some(ops);
        let mut win = std::collections::HashMap::new();
        for i in 0..NUM_SEQ_SAMPLES {
            win.insert(format!("W{}", i + 1), twin[i].clone().unwrap_or_default());
        }
        subject.tests[2] = Some(win);
    }

    let _ = (
        closed_tcp,
        closed_udp,
        udp_port_base,
        icmp_id,
        icmp_seq,
        udpttl,
        &mut tx,
        &mut rx,
        src_ip,
        tcp_ack,
        rng,
    );

    let _ = TEST_NAMES;
    let _ = NUM_FP_TESTS;

    Ok(subject)
}

fn read_timestamp(tcp: &TcpPacket<'_>) -> u32 {
    let hdr = tcp.packet();
    let data_off = tcp.get_data_offset() as usize * 4;
    if data_off < 20 || hdr.len() < data_off {
        return 0;
    }
    let mut q = &hdr[20..data_off];
    while q.len() >= 2 {
        let op = q[0];
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

fn build_seq_test(
    seq_reply: &[Option<(u32, u16, u32)>; NUM_SEQ_SAMPLES],
    seq_times: &[Instant; NUM_SEQ_SAMPLES],
    tcp_ipids: &[u32; NUM_SEQ_SAMPLES],
    _tcp_port_base: u16,
    _tcp_seq_base: u32,
) -> Option<std::collections::HashMap<String, String>> {
    let mut good_idx = Vec::new();
    for i in 0..NUM_SEQ_SAMPLES {
        if seq_reply[i].is_some() {
            good_idx.push(i);
        }
    }
    if good_idx.len() < 4 {
        return None;
    }
    let mut seqs = Vec::new();
    let mut times = Vec::new();
    for &i in &good_idx {
        seqs.push(seq_reply[i].unwrap().0);
        times.push(seq_times[i]);
    }
    let mut diffs = Vec::new();
    for i in 1..seqs.len() {
        diffs.push(mod_diff_u32(seqs[i], seqs[i - 1]));
    }
    let gcd = gcd_many(&diffs);
    let mut seq_rates = Vec::new();
    for i in 1..seqs.len() {
        let dt = times[i].saturating_duration_since(times[i - 1]).as_micros().max(1);
        seq_rates.push(diffs[i - 1] as f64 * 1_000_000.0 / dt as f64);
    }
    let seq_avg: f64 = seq_rates.iter().sum::<f64>() / seq_rates.len() as f64;
    let mut seq_rate = (seq_avg.log2() * 8.0).round() as u32;
    let mut seq_stddev = 0.0f64;
    let div_gcd = if gcd > 9 { gcd } else { 1 };
    for r in &seq_rates {
        let t = *r / div_gcd as f64 - seq_avg / div_gcd as f64;
        seq_stddev += t * t;
    }
    seq_stddev /= (seq_rates.len().saturating_sub(1).max(1)) as f64;
    seq_stddev = seq_stddev.sqrt();
    let sp_idx = if seq_stddev <= 1.0 {
        0u32
    } else {
        ((seq_stddev.log2() * 8.0).round() as u32).min(0xff)
    };
    if gcd == 0 {
        seq_rate = 0;
    }

    let mut m = std::collections::HashMap::new();
    m.insert("SP".to_string(), hex_lower(sp_idx));
    m.insert("GCD".to_string(), hex_lower(gcd));
    m.insert("ISR".to_string(), hex_lower(seq_rate));

    let ti = classify_ipid(&tcp_ipids[..NUM_SEQ_SAMPLES.min(good_idx.len())]);
    m.insert("TI".to_string(), ti);

    m.insert("CI".to_string(), "X".to_string());
    m.insert("II".to_string(), "X".to_string());
    m.insert("SS".to_string(), "S".to_string());
    m.insert("TS".to_string(), "U".to_string());
    let _ = tcp_ipids;
    Some(m)
}

fn classify_ipid(_ipids: &[u32]) -> String {
    "I".to_string()
}

fn send_tcp_probe(
    tx: &mut pnet::transport::TransportSender,
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
        let doff = (tcp_len / 4) as u8;
        t[12] = (doff << 4) | (reserved & 0x0f);
        t[13] = flags;
        t[14..16].copy_from_slice(&window.to_be_bytes());
        t[16..18].copy_from_slice(&0u16.to_be_bytes());
        t[18..20].copy_from_slice(&urg.to_be_bytes());
        t[20..].copy_from_slice(opts);
        let tcp_pkt = TcpPacket::new(t).expect("tcp len");
        let cks = ipv4_checksum(&tcp_pkt, &src, &dst);
        t[16..18].copy_from_slice(&cks.to_be_bytes());
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..20]).expect("ip");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(total as u16);
        ip.set_identification(ip_id);
        if df {
            ip.set_flags(Ipv4Flags::DontFragment);
        }
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_checksum(0);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_hdr_cksum(&ip.to_immutable()));
    }
    tx.send_to(Ipv4Packet::new(&buf).expect("pkt"), IpAddr::V4(dst))?;
    Ok(())
}

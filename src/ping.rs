//! ICMP host discovery (`-sn`) via raw ICMP echo request/reply (pnet).
//! Falls back to system `ping` when raw sockets are unavailable (non-root).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};

/// Outcome of probing a single host with ICMP echo.
#[derive(Debug, Clone)]
pub struct PingOutcome {
    pub host: IpAddr,
    pub up: bool,
    pub ttl: Option<u8>,
    pub latency_ms: Option<u128>,
}

pub async fn ping_hosts(hosts: &[IpAddr], concurrency: usize) -> Vec<PingOutcome> {
    let c = concurrency.max(1);
    stream::iter(hosts.iter().copied())
        .map(ping_one)
        .buffer_unordered(c)
        .collect()
        .await
}

async fn ping_one(host: IpAddr) -> PingOutcome {
    // Try raw ICMP first; fall back to system ping on failure.
    match tokio::task::spawn_blocking(move || raw_icmp_ping(host, Duration::from_secs(2))).await {
        Ok(Some(outcome)) => outcome,
        _ => system_ping_one(host).await,
    }
}

/// Raw ICMP echo request/reply using pnet transport channels.
fn raw_icmp_ping(host: IpAddr, timeout: Duration) -> Option<PingOutcome> {
    match host {
        IpAddr::V4(addr) => raw_icmp_ping_v4(addr, timeout),
        IpAddr::V6(addr) => raw_icmp_ping_v6(addr, timeout),
    }
}

fn raw_icmp_ping_v4(addr: std::net::Ipv4Addr, timeout: Duration) -> Option<PingOutcome> {
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::Packet;
    use pnet::transport::{
        icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    };

    let (mut tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .ok()?;

    let mut buf = vec![0u8; 64]; // 8 byte ICMP header + 56 byte payload
    let mut pkt = MutableEchoRequestPacket::new(&mut buf)?;
    pkt.set_icmp_type(IcmpTypes::EchoRequest);
    pkt.set_icmp_code(pnet::packet::icmp::echo_request::IcmpCodes::NoCode);
    pkt.set_identifier(std::process::id() as u16);
    pkt.set_sequence_number(1);
    // Compute ICMP checksum over the entire packet.
    let ck = {
        let data = pkt.packet();
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    };
    pkt.set_checksum(ck);

    let start = Instant::now();
    tx.send_to(pkt, IpAddr::V4(addr)).ok()?;

    let mut iter = icmp_packet_iter(&mut rx);
    let deadline = start + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Some(PingOutcome {
                host: IpAddr::V4(addr),
                up: false,
                ttl: None,
                latency_ms: None,
            });
        }
        match iter.next_with_timeout(remaining) {
            Ok(Some((pkt, src))) => {
                use pnet::packet::icmp::IcmpPacket;
                if let Some(icmp) = IcmpPacket::new(pkt.packet()) {
                    if icmp.get_icmp_type() == IcmpTypes::EchoReply {
                        if let IpAddr::V4(src_v4) = src {
                            if src_v4 == addr {
                                let elapsed = start.elapsed().as_millis();
                                return Some(PingOutcome {
                                    host: IpAddr::V4(addr),
                                    up: true,
                                    ttl: None, // pnet transport doesn't expose TTL directly
                                    latency_ms: Some(elapsed),
                                });
                            }
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
    Some(PingOutcome {
        host: IpAddr::V4(addr),
        up: false,
        ttl: None,
        latency_ms: None,
    })
}

fn raw_icmp_ping_v6(addr: std::net::Ipv6Addr, timeout: Duration) -> Option<PingOutcome> {
    use pnet::packet::icmpv6::Icmpv6Types;
    use pnet::packet::icmpv6::MutableIcmpv6Packet;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::transport::{
        icmpv6_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    };

    let (mut tx, mut rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .ok()?;

    let mut buf = vec![0u8; 64];
    let mut pkt = MutableIcmpv6Packet::new(&mut buf)?;
    pkt.set_icmpv6_type(Icmpv6Types::EchoRequest);
    pkt.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code::new(0));
    // ICMPv6 checksum is computed by the kernel.
    pkt.set_checksum(0);

    let start = Instant::now();
    tx.send_to(pkt, IpAddr::V6(addr)).ok()?;

    let mut iter = icmpv6_packet_iter(&mut rx);
    let deadline = start + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Some(PingOutcome {
                host: IpAddr::V6(addr),
                up: false,
                ttl: None,
                latency_ms: None,
            });
        }
        match iter.next_with_timeout(remaining) {
            Ok(Some((pkt, src))) => {
                if pkt.get_icmpv6_type() == Icmpv6Types::EchoReply {
                    if let IpAddr::V6(src_v6) = src {
                        if src_v6 == addr {
                            let elapsed = start.elapsed().as_millis();
                            return Some(PingOutcome {
                                host: IpAddr::V6(addr),
                                up: true,
                                ttl: None,
                                latency_ms: Some(elapsed),
                            });
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
    Some(PingOutcome {
        host: IpAddr::V6(addr),
        up: false,
        ttl: None,
        latency_ms: None,
    })
}

/// Fallback: system `ping` / `ping6` command.
async fn system_ping_one(host: IpAddr) -> PingOutcome {
    use tokio::process::Command;

    let start = Instant::now();
    let (prog, args) = ping_cmd(host);
    let mut cmd = Command::new(prog);
    cmd.args(&args);
    cmd.arg(host.to_string());
    cmd.kill_on_drop(true);
    match cmd.output().await {
        Ok(out) => {
            let ok = out.status.success();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ttl = parse_ttl(&stdout);
            let latency_ms = parse_time_ms(&stdout).or_else(|| {
                if ok {
                    Some(start.elapsed().as_millis())
                } else {
                    None
                }
            });
            PingOutcome {
                host,
                up: ok,
                ttl,
                latency_ms,
            }
        }
        Err(_) => PingOutcome {
            host,
            up: false,
            ttl: None,
            latency_ms: None,
        },
    }
}

fn ping_cmd(host: IpAddr) -> (&'static str, Vec<&'static str>) {
    #[cfg(windows)]
    {
        match host {
            IpAddr::V4(_) => ("ping", vec!["-n", "1", "-w", "1000"]),
            IpAddr::V6(_) => ("ping", vec!["-6", "-n", "1", "-w", "1000"]),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match host {
            IpAddr::V4(_) => ("ping", vec!["-c", "1", "-W", "1000"]),
            IpAddr::V6(_) => ("ping6", vec!["-c", "1", "-W", "1000"]),
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        match host {
            IpAddr::V4(_) => ("ping", vec!["-c", "1", "-W", "1"]),
            IpAddr::V6(_) => ("ping6", vec!["-c", "1", "-W", "1"]),
        }
    }
}

fn parse_ttl(s: &str) -> Option<u8> {
    for part in s.split_whitespace() {
        let p = part.to_ascii_lowercase();
        if let Some(rest) = p.strip_prefix("ttl=") {
            return rest.trim_end_matches(',').parse().ok();
        }
        if let Some(rest) = p.strip_prefix("ttl") {
            let rest = rest.trim_start_matches('=');
            return rest.trim_end_matches(',').parse().ok();
        }
    }
    None
}

fn parse_time_ms(s: &str) -> Option<u128> {
    for line in s.lines() {
        let l = line.to_ascii_lowercase();
        if let Some(idx) = l.find("time=") {
            let tail = &line[idx + 5..];
            let num = tail
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .next()
                .unwrap_or("");
            if let Ok(ms) = num.parse::<f64>() {
                return Some(ms as u128);
            }
        }
    }
    None
}

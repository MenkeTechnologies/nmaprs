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

#[cfg(test)]
mod tests {
    use super::{parse_time_ms, parse_ttl, ping_cmd};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ─── parse_ttl: covers BSD/macOS, Linux iputils, Windows formats ──

    #[test]
    fn macos_ping_ttl_line_extracts_64() {
        // macOS: "64 bytes from 8.8.8.8: icmp_seq=0 ttl=128 time=10.523 ms"
        let s = "64 bytes from 8.8.8.8: icmp_seq=0 ttl=128 time=10.523 ms";
        assert_eq!(parse_ttl(s), Some(128));
    }

    #[test]
    fn linux_iputils_ttl_line_extracts() {
        let s = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms";
        assert_eq!(parse_ttl(s), Some(57));
    }

    #[test]
    fn windows_ttl_uppercase_extracts() {
        // Windows: "Reply from 8.8.8.8: bytes=32 time=15ms TTL=128"
        let s = "Reply from 8.8.8.8: bytes=32 time=15ms TTL=128";
        assert_eq!(parse_ttl(s), Some(128));
    }

    #[test]
    fn ttl_with_trailing_comma_strips_comma() {
        // Some flavors print "ttl=64,".
        let s = "ttl=64,";
        assert_eq!(parse_ttl(s), Some(64));
    }

    #[test]
    fn ttl_max_u8_is_255() {
        let s = "ttl=255";
        assert_eq!(parse_ttl(s), Some(255));
    }

    #[test]
    fn ttl_overflow_returns_none() {
        // 256 exceeds u8::MAX.
        let s = "ttl=256";
        assert_eq!(parse_ttl(s), None);
    }

    #[test]
    fn no_ttl_in_string_returns_none() {
        assert_eq!(parse_ttl("nothing relevant here"), None);
        assert_eq!(parse_ttl(""), None);
    }

    #[test]
    fn ttl_mixed_case_matches() {
        assert_eq!(parse_ttl("TtL=42"), Some(42));
        assert_eq!(parse_ttl("Ttl=42"), Some(42));
    }

    // ─── parse_time_ms: covers BSD/macOS/Linux/Windows formats ────────

    #[test]
    fn macos_time_line_extracts_milliseconds() {
        // "time=10.523 ms"
        let s = "64 bytes from 8.8.8.8: icmp_seq=0 ttl=128 time=10.523 ms";
        // Truncated to u128 → 10.
        assert_eq!(parse_time_ms(s), Some(10));
    }

    #[test]
    fn windows_time_no_decimal_extracts_integer_ms() {
        // "time=15ms"
        let s = "Reply from 8.8.8.8: bytes=32 time=15ms TTL=128";
        assert_eq!(parse_time_ms(s), Some(15));
    }

    #[test]
    fn time_less_than_one_ms_truncates_to_zero() {
        let s = "time=0.5 ms";
        assert_eq!(parse_time_ms(s), Some(0));
    }

    #[test]
    fn time_searched_in_each_line() {
        // First line has no time, second does.
        let s = "PING google.com\n64 bytes from 8.8.8.8: time=5.5 ms\n";
        assert_eq!(parse_time_ms(s), Some(5));
    }

    #[test]
    fn no_time_returns_none() {
        assert_eq!(parse_time_ms("nothing here"), None);
        assert_eq!(parse_time_ms(""), None);
    }

    #[test]
    fn invalid_time_value_returns_none() {
        // "time=abc" has no numeric segment.
        let s = "time=abc";
        assert_eq!(parse_time_ms(s), None);
    }

    // ─── ping_cmd: platform dispatch ──────────────────────────────────

    #[test]
    fn ping_cmd_v4_uses_ping_binary() {
        let (prog, _args) = ping_cmd(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(prog, "ping");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn ping_cmd_v6_uses_ping6_on_macos() {
        let (prog, _args) = ping_cmd(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(prog, "ping6");
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn ping_cmd_v6_uses_ping6_on_linux() {
        let (prog, _args) = ping_cmd(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(prog, "ping6");
    }

    #[test]
    #[cfg(unix)]
    fn ping_cmd_count_one_arg_present() {
        // All unix variants pass `-c 1` to send exactly one echo.
        let (_prog, args) = ping_cmd(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let joined: Vec<&str> = args.iter().copied().collect();
        assert!(joined.contains(&"-c"));
        assert!(joined.contains(&"1"));
    }

    #[test]
    fn ttl_zero_is_valid() {
        assert_eq!(parse_ttl("ttl=0"), Some(0));
    }

    #[test]
    fn ttl_non_numeric_suffix_returns_none() {
        assert_eq!(parse_ttl("ttl=abc"), None);
    }

    #[test]
    fn parse_time_ms_integer_without_decimal() {
        assert_eq!(parse_time_ms("time=42 ms"), Some(42));
    }

    #[test]
    fn parse_time_ms_picks_first_match_in_multiline() {
        let s = "time=9 ms\ntime=99 ms\n";
        assert_eq!(parse_time_ms(s), Some(9));
    }

    #[test]
    fn parse_ttl_before_time_in_same_line() {
        let s = "ttl=32 time=7.2 ms";
        assert_eq!(parse_ttl(s), Some(32));
        assert_eq!(parse_time_ms(s), Some(7));
    }

    #[test]
    #[cfg(unix)]
    fn ping_cmd_v6_uses_ping6_binary() {
        let host = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let (prog, _args) = ping_cmd(host);
        assert_eq!(prog, "ping6");
    }
}

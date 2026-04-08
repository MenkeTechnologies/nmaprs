//! Host discovery before port scan. Skipped with `-Pn` / `--no-ping`.
//!
//! Default probes: **ICMP echo** (parallel with TCP) plus **TCP 443 and 80** using **raw SYN** when
//! privileged ([`crate::syn::parallel_syn_scan_ipv4`] / `ipv6`), otherwise TCP connect fallback.
//!
//! **`-PS`**: raw half-open SYN; **`-PA`**: raw TCP ACK (same `syn` stack as `-PS`); both fall back to
//! TCP connect if raw sockets fail.
//!
//! **UDP `-PU`**: UDP datagram; reply or ICMP-unreachable-style socket errors → “up”.

use std::collections::HashSet;
use std::io::ErrorKind as IoErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use futures::stream::{self, StreamExt};
use tokio::io::ErrorKind as TokioErrorKind;
use tokio::net::{TcpStream, UdpSocket};

use crate::cli::Args;
use crate::ping::ping_hosts;
use crate::ports::parse_port_spec;
use crate::scan::PortLine;
use crate::syn::MAX_SYN_PARALLEL_SHARDS;

/// TCP ports for default discovery (Nmap: SYN 443, ACK 80).
const DEFAULT_TCP_DISCOVERY_PORTS: &[u16] = &[443, 80];

const TCP_SYN_DEFAULT: u16 = 80;
const TCP_ACK_DEFAULT: u16 = 80;
const UDP_PING_DEFAULT: u16 = 40_125;

fn has_explicit_discovery_flags(args: &Args) -> bool {
    args.ping_echo
        || args.ping_syn.is_some()
        || args.ping_ack.is_some()
        || args.ping_udp.is_some()
        || args.ping_sctp.is_some()
        || args.ping_timestamp
        || args.ping_mask
        || args.ping_ip_proto.is_some()
}

fn has_implemented_explicit_probes(args: &Args) -> bool {
    args.ping_echo
        || args.ping_syn.is_some()
        || args.ping_ack.is_some()
        || args.ping_udp.is_some()
}

fn ports_from_ping_tcp(opt: &Option<Option<String>>, default: u16) -> Result<Vec<u16>> {
    match opt {
        None => Ok(vec![]),
        Some(None) => Ok(vec![default]),
        Some(Some(s)) => parse_port_spec(s.trim()).map_err(|e| anyhow!("{e}")),
    }
}

fn ports_from_ping_udp(opt: &Option<Option<String>>) -> Result<Vec<u16>> {
    match opt {
        None => Ok(vec![]),
        Some(None) => Ok(vec![UDP_PING_DEFAULT]),
        Some(Some(s)) => parse_port_spec(s.trim()).map_err(|e| anyhow!("{e}")),
    }
}

fn port_lines_to_alive_hosts(lines: Vec<PortLine>) -> HashSet<IpAddr> {
    lines
        .into_iter()
        .filter(|l| l.state == "open" || l.state == "closed")
        .map(|l| l.host)
        .collect()
}

/// Raw SYN discovery: RST or SYN-ACK ⇒ host responded (up).
async fn syn_raw_discovery_collect(
    hosts: &[IpAddr],
    ports: &[u16],
    skip: Option<&HashSet<IpAddr>>,
    timeout: Duration,
    max_shards: usize,
) -> std::io::Result<HashSet<IpAddr>> {
    let mut v4: Vec<(Ipv4Addr, u16)> = Vec::new();
    let mut v6: Vec<(Ipv6Addr, u16)> = Vec::new();
    for &h in hosts {
        if skip.map(|s| s.contains(&h)).unwrap_or(false) {
            continue;
        }
        for &p in ports {
            match h {
                IpAddr::V4(a) => v4.push((a, p)),
                IpAddr::V6(a) => v6.push((a, p)),
            }
        }
    }

    let v4_fut = async {
        if v4.is_empty() {
            return Ok::<HashSet<IpAddr>, std::io::Error>(HashSet::new());
        }
        tokio::task::spawn_blocking(move || {
            let lines = crate::syn::parallel_syn_scan_ipv4(
                v4,
                timeout,
                None,
                None,
                None,
                None,
                None,
                0,
                max_shards,
            )?;
            Ok(port_lines_to_alive_hosts(lines))
        })
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))?
    };

    let v6_fut = async {
        if v6.is_empty() {
            return Ok::<HashSet<IpAddr>, std::io::Error>(HashSet::new());
        }
        tokio::task::spawn_blocking(move || {
            let lines = crate::syn::parallel_syn_scan_ipv6(
                v6,
                timeout,
                None,
                None,
                None,
                None,
                None,
                0,
                max_shards,
            )?;
            Ok(port_lines_to_alive_hosts(lines))
        })
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))?
    };

    let (r4, r6) = tokio::join!(v4_fut, v6_fut);
    let mut out = r4?;
    out.extend(r6?);
    Ok(out)
}

/// Raw ACK discovery (`-PA`): RST or SYN-ACK ⇒ host responded.
async fn ack_raw_discovery_collect(
    hosts: &[IpAddr],
    ports: &[u16],
    skip: Option<&HashSet<IpAddr>>,
    timeout: Duration,
    max_shards: usize,
) -> std::io::Result<HashSet<IpAddr>> {
    let mut v4: Vec<(Ipv4Addr, u16)> = Vec::new();
    let mut v6: Vec<(Ipv6Addr, u16)> = Vec::new();
    for &h in hosts {
        if skip.map(|s| s.contains(&h)).unwrap_or(false) {
            continue;
        }
        for &p in ports {
            match h {
                IpAddr::V4(a) => v4.push((a, p)),
                IpAddr::V6(a) => v6.push((a, p)),
            }
        }
    }

    let v4_fut = async {
        if v4.is_empty() {
            return Ok::<HashSet<IpAddr>, std::io::Error>(HashSet::new());
        }
        tokio::task::spawn_blocking(move || {
            let lines = crate::syn::parallel_ack_ping_scan_ipv4(
                v4,
                timeout,
                None,
                None,
                None,
                None,
                None,
                0,
                max_shards,
            )?;
            Ok(port_lines_to_alive_hosts(lines))
        })
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))?
    };

    let v6_fut = async {
        if v6.is_empty() {
            return Ok::<HashSet<IpAddr>, std::io::Error>(HashSet::new());
        }
        tokio::task::spawn_blocking(move || {
            let lines = crate::syn::parallel_ack_ping_scan_ipv6(
                v6,
                timeout,
                None,
                None,
                None,
                None,
                None,
                0,
                max_shards,
            )?;
            Ok(port_lines_to_alive_hosts(lines))
        })
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))?
    };

    let (r4, r6) = tokio::join!(v4_fut, v6_fut);
    let mut out = r4?;
    out.extend(r6?);
    Ok(out)
}

/// `-PS` / default TCP ports: raw SYN when possible, else TCP connect.
async fn tcp_ps_discovery_or_connect(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    skip: Option<&HashSet<IpAddr>>,
    connect_timeout: Duration,
    max_shards: usize,
) -> HashSet<IpAddr> {
    match syn_raw_discovery_collect(hosts, ports, skip, connect_timeout, max_shards).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "raw TCP SYN discovery failed; using TCP connect");
            tcp_connect_discovery_collect(hosts, ports, concurrency, skip, connect_timeout).await
        }
    }
}

async fn tcp_ps_discovery_merge(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    alive: &mut HashSet<IpAddr>,
    connect_timeout: Duration,
    max_shards: usize,
) {
    let skip = alive.clone();
    let new_up = tcp_ps_discovery_or_connect(
        hosts,
        ports,
        concurrency,
        Some(&skip),
        connect_timeout,
        max_shards,
    )
    .await;
    alive.extend(new_up);
}

/// `-PA`: raw ACK when possible, else TCP connect.
async fn tcp_pa_discovery_or_connect(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    skip: Option<&HashSet<IpAddr>>,
    connect_timeout: Duration,
    max_shards: usize,
) -> HashSet<IpAddr> {
    match ack_raw_discovery_collect(hosts, ports, skip, connect_timeout, max_shards).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "raw TCP ACK discovery failed; using TCP connect");
            tcp_connect_discovery_collect(hosts, ports, concurrency, skip, connect_timeout).await
        }
    }
}

async fn tcp_pa_discovery_merge(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    alive: &mut HashSet<IpAddr>,
    connect_timeout: Duration,
    max_shards: usize,
) {
    let skip = alive.clone();
    let new_up = tcp_pa_discovery_or_connect(
        hosts,
        ports,
        concurrency,
        Some(&skip),
        connect_timeout,
        max_shards,
    )
    .await;
    alive.extend(new_up);
}

async fn tcp_probe(host: IpAddr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(host, port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => e.kind() == TokioErrorKind::ConnectionRefused,
        Err(_) => false,
    }
}

async fn tcp_connect_discovery_collect(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    skip: Option<&HashSet<IpAddr>>,
    connect_timeout: Duration,
) -> HashSet<IpAddr> {
    let pairs: Vec<(IpAddr, u16)> = hosts
        .iter()
        .copied()
        .filter(|h| !skip.map(|s| s.contains(h)).unwrap_or(false))
        .flat_map(|h| ports.iter().map(move |&p| (h, p)))
        .collect();

    let results: Vec<(IpAddr, bool)> = stream::iter(pairs.into_iter())
        .map(|(host, port)| {
            let t = connect_timeout;
            async move { (host, tcp_probe(host, port, t).await) }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(h, _)| h)
        .collect()
}

async fn udp_ping_probe(host: IpAddr, port: u16, wait: Duration) -> bool {
    let bind_addr: SocketAddr = match host {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let Ok(socket) = UdpSocket::bind(bind_addr).await else {
        return false;
    };
    let dst = SocketAddr::new(host, port);
    if socket.send_to(&[0u8], dst).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => n > 0,
        Ok(Err(e)) => matches!(
            e.kind(),
            IoErrorKind::ConnectionRefused
                | IoErrorKind::NetworkUnreachable
                | IoErrorKind::HostUnreachable
        ),
        Err(_) => false,
    }
}

async fn udp_discovery_collect(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    skip: Option<&HashSet<IpAddr>>,
    icmp_wait: Duration,
) -> HashSet<IpAddr> {
    let pairs: Vec<(IpAddr, u16)> = hosts
        .iter()
        .copied()
        .filter(|h| !skip.map(|s| s.contains(h)).unwrap_or(false))
        .flat_map(|h| ports.iter().map(move |&p| (h, p)))
        .collect();

    let results: Vec<(IpAddr, bool)> = stream::iter(pairs.into_iter())
        .map(|(host, port)| {
            let w = icmp_wait;
            async move { (host, udp_ping_probe(host, port, w).await) }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(h, _)| h)
        .collect()
}

async fn udp_discovery(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    alive: &mut HashSet<IpAddr>,
    icmp_wait: Duration,
) {
    let skip = alive.clone();
    let new_up = udp_discovery_collect(hosts, ports, concurrency, Some(&skip), icmp_wait).await;
    alive.extend(new_up);
}

/// Filter `hosts` to targets that respond to at least one discovery probe.
pub async fn hosts_after_discovery(
    hosts: Vec<IpAddr>,
    args: &Args,
    concurrency: usize,
    connect_timeout: Duration,
) -> Result<Vec<IpAddr>> {
    if args.no_ping {
        return Ok(hosts);
    }
    if hosts.is_empty() {
        return Ok(hosts);
    }

    let c = concurrency.max(1);
    let max_shards = c.clamp(1, MAX_SYN_PARALLEL_SHARDS);

    if args.ping_timestamp {
        tracing::warn!("-PP (ICMP timestamp) host discovery is not implemented; ignoring");
    }
    if args.ping_mask {
        tracing::warn!("-PM (ICMP netmask) host discovery is not implemented; ignoring");
    }
    if args.ping_ip_proto.is_some() {
        tracing::warn!("-PO (IP protocol ping) is not implemented; ignoring");
    }
    if args.ping_sctp.is_some() {
        tracing::warn!("-PY (SCTP ping) is not implemented; ignoring");
    }

    let explicit = has_explicit_discovery_flags(args);
    let implemented = has_implemented_explicit_probes(args);

    if explicit && !implemented {
        tracing::warn!(
            "only unimplemented -P* discovery probes were given; using default discovery (ICMP + TCP {})",
            DEFAULT_TCP_DISCOVERY_PORTS
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    let mut alive: HashSet<IpAddr> = HashSet::new();

    let use_default = !(explicit && implemented);

    if use_default {
        let hosts_icmp = hosts.clone();
        let hosts_tcp = hosts.clone();
        let ct = connect_timeout;
        let (icmp_alive, tcp_alive) = tokio::join!(
            async move {
                let mut s = HashSet::new();
                for o in ping_hosts(&hosts_icmp, c).await {
                    if o.up {
                        s.insert(o.host);
                    }
                }
                s
            },
            async move {
                tcp_ps_discovery_or_connect(
                    &hosts_tcp,
                    DEFAULT_TCP_DISCOVERY_PORTS,
                    c,
                    None,
                    ct,
                    max_shards,
                )
                .await
            }
        );
        alive.extend(icmp_alive);
        alive.extend(tcp_alive);
    } else {
        if args.ping_echo {
            for o in ping_hosts(&hosts, c).await {
                if o.up {
                    alive.insert(o.host);
                }
            }
        }
        if args.ping_syn.is_some() {
            let ports = ports_from_ping_tcp(&args.ping_syn, TCP_SYN_DEFAULT)?;
            tcp_ps_discovery_merge(&hosts, &ports, c, &mut alive, connect_timeout, max_shards).await;
        }
        if args.ping_ack.is_some() {
            let ports = ports_from_ping_tcp(&args.ping_ack, TCP_ACK_DEFAULT)?;
            tcp_pa_discovery_merge(&hosts, &ports, c, &mut alive, connect_timeout, max_shards).await;
        }
        if args.ping_udp.is_some() {
            let ports = ports_from_ping_udp(&args.ping_udp)?;
            udp_discovery(&hosts, &ports, c, &mut alive, connect_timeout).await;
        }
    }

    let out: Vec<IpAddr> = hosts.into_iter().filter(|h| alive.contains(h)).collect();
    if out.is_empty() {
        bail!("no hosts responded to discovery (try -Pn to skip host discovery, or adjust -P* probes)");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_from_ping_tcp_variants() {
        assert_eq!(
            ports_from_ping_tcp(&Some(None), 80).unwrap(),
            vec![80]
        );
        assert_eq!(
            ports_from_ping_tcp(&Some(Some("443".into())), 80).unwrap(),
            vec![443]
        );
        assert_eq!(
            ports_from_ping_tcp(&Some(Some("80,443".into())), 80).unwrap(),
            vec![80, 443]
        );
        assert!(ports_from_ping_tcp(&None, 80).unwrap().is_empty());
    }

    #[test]
    fn ports_from_ping_udp_variants() {
        assert_eq!(ports_from_ping_udp(&Some(None)).unwrap(), vec![40_125]);
        assert_eq!(
            ports_from_ping_udp(&Some(Some("53".into()))).unwrap(),
            vec![53]
        );
        assert!(ports_from_ping_udp(&None).unwrap().is_empty());
    }

    #[test]
    fn port_lines_to_alive_filters_timeouts() {
        let lines = vec![
            PortLine {
                host: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                port: 80,
                proto: "tcp",
                state: "closed",
                reason: crate::scan::PortReason::ConnRefused,
                latency_ms: None,
            },
            PortLine {
                host: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                port: 80,
                proto: "tcp",
                state: "filtered",
                reason: crate::scan::PortReason::Timeout,
                latency_ms: None,
            },
        ];
        let a = port_lines_to_alive_hosts(lines);
        assert_eq!(a.len(), 1);
        assert!(a.contains(&IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))));
    }
}

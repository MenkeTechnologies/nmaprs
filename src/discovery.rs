//! Host discovery before port scan. Skipped with `-Pn` / `--no-ping`.
//!
//! Default probes: **ICMP echo** (parallel with TCP) plus **TCP 443 and 80** using **raw SYN** when
//! privileged ([`crate::syn::parallel_syn_scan_ipv4`] / `ipv6`), otherwise TCP connect fallback.
//!
//! **`-PS`**: raw half-open SYN; **`-PA`**: raw TCP ACK (same `syn` stack as `-PS`); both fall back to
//! TCP connect if raw sockets fail.
//!
//! **UDP `-PU`**: UDP datagram; reply or ICMP-unreachable-style socket errors → “up”.
//!
//! **`-PY`**: SCTP **INIT** (same engines as `-sY`); INIT-ACK / ABORT ⇒ host responded (up).
//!
//! **`-PO`**: IP protocol probes (same engines as `-sO`); ICMP **protocol unreachable** or IPv6
//! Parameter Problem ⇒ “closed”; any **open**/**closed** result ⇒ host up.
//!
//! **`-PP`** / **`-PM`**: legacy ICMP **timestamp** and **address mask** (IPv4 only; Unix raw ICMP).

use std::collections::HashSet;
use std::io::ErrorKind as IoErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use futures::stream::{self, StreamExt};
use tokio::io::ErrorKind as TokioErrorKind;
use tokio::net::{TcpStream, UdpSocket};

use crate::cli::Args;
use crate::ip_proto::MAX_IP_PROTO_PARALLEL_SHARDS;
use crate::ping::ping_hosts;
use crate::ports::parse_port_spec;
use crate::scan::PortLine;
use crate::sctp::MAX_SCTP_PARALLEL_SHARDS;
use crate::syn::MAX_SYN_PARALLEL_SHARDS;

/// TCP ports for default discovery (Nmap: SYN 443, ACK 80).
const DEFAULT_TCP_DISCOVERY_PORTS: &[u16] = &[443, 80];

const TCP_SYN_DEFAULT: u16 = 80;
const TCP_ACK_DEFAULT: u16 = 80;
const UDP_PING_DEFAULT: u16 = 40_125;
/// Nmap default SCTP ping port (`-PY` with no port list).
const SCTP_PING_DEFAULT: u16 = 80;

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
        || args.ping_sctp.is_some()
        || args.ping_ip_proto.is_some()
        || args.ping_timestamp
        || args.ping_mask
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

fn ports_from_ping_sctp(opt: &Option<Option<String>>) -> Result<Vec<u16>> {
    match opt {
        None => Ok(vec![]),
        Some(None) => Ok(vec![SCTP_PING_DEFAULT]),
        Some(Some(s)) => parse_port_spec(s.trim()).map_err(|e| anyhow!("{e}")),
    }
}

/// Parse `-PO` / `--ping-ip-proto` protocol list (comma-separated 0–255). Empty or omitted list uses
/// Nmap’s default **1,2,4** (ICMP, IGMP, IP-in-IP).
fn parse_ping_ip_proto_list(s: &str) -> Result<Vec<u16>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(vec![1, 2, 4]);
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let n: u16 = p
            .parse()
            .map_err(|_| anyhow!("invalid protocol number in -PO: {p}"))?;
        if n > 255 {
            bail!("protocol number in -PO must be 0..=255, got {n}");
        }
        out.push(n);
    }
    if out.is_empty() {
        bail!("-PO protocol list is empty");
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
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
                v4, timeout, None, None, None, None, None, 0, max_shards,
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
                v6, timeout, None, None, None, None, None, 0, max_shards,
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
                v4, timeout, None, None, None, None, None, 0, max_shards,
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
                v6, timeout, None, None, None, None, None, 0, max_shards,
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

/// Raw SCTP INIT discovery (`-PY`): INIT-ACK or ABORT ⇒ host responded.
/// IPv4 / IPv6 are merged independently; one family may warn and yield empty while the other succeeds.
async fn sctp_raw_discovery_collect(
    hosts: &[IpAddr],
    ports: &[u16],
    skip: Option<&HashSet<IpAddr>>,
    timeout: Duration,
    max_shards: usize,
) -> HashSet<IpAddr> {
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
            return Ok(HashSet::new());
        }
        let r = tokio::task::spawn_blocking(move || {
            crate::sctp::parallel_sctp_scan_ipv4(
                v4,
                crate::sctp::SctpProbeKind::Init,
                timeout,
                None,
                None,
                None,
                None,
                None,
                0,
                max_shards,
            )
            .map(port_lines_to_alive_hosts)
        })
        .await;
        match r {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(std::io::Error::other(format!("{e}"))),
        }
    };

    let v6_fut = async {
        if v6.is_empty() {
            return Ok(HashSet::new());
        }
        let r = tokio::task::spawn_blocking(move || {
            crate::sctp::parallel_sctp_scan_ipv6(
                v6,
                crate::sctp::SctpProbeKind::Init,
                timeout,
                None,
                None,
                None,
                None,
                None,
                0,
                max_shards,
            )
            .map(port_lines_to_alive_hosts)
        })
        .await;
        match r {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(std::io::Error::other(format!("{e}"))),
        }
    };

    let (r4, r6) = tokio::join!(v4_fut, v6_fut);
    let mut out = HashSet::new();
    match r4 {
        Ok(s) => out.extend(s),
        Err(e) => tracing::warn!(error = %e, "SCTP discovery IPv4 (-PY) failed"),
    }
    match r6 {
        Ok(s) => out.extend(s),
        Err(e) => tracing::warn!(error = %e, "SCTP discovery IPv6 (-PY) failed"),
    }
    out
}

/// Raw IP-protocol discovery (`-PO`): ICMP unreachable / IPv6 Parameter Problem ⇒ “closed”; same
/// engines as `-sO`. IPv4 / IPv6 merged independently on partial failure.
async fn ip_proto_ping_discovery_collect(
    hosts: &[IpAddr],
    protos: &[u16],
    skip: Option<&HashSet<IpAddr>>,
    timeout: Duration,
    max_shards: usize,
) -> HashSet<IpAddr> {
    let mut v4: Vec<(Ipv4Addr, u16)> = Vec::new();
    let mut v6: Vec<(Ipv6Addr, u16)> = Vec::new();
    for &h in hosts {
        if skip.map(|s| s.contains(&h)).unwrap_or(false) {
            continue;
        }
        for &p in protos {
            match h {
                IpAddr::V4(a) => v4.push((a, p)),
                IpAddr::V6(a) => v6.push((a, p)),
            }
        }
    }

    let v4_fut = async {
        if v4.is_empty() {
            return Ok(HashSet::new());
        }
        let r = tokio::task::spawn_blocking(move || {
            crate::ip_proto::parallel_ip_proto_scan_ipv4(
                v4, timeout, None, None, None, None, None, 0, max_shards,
            )
            .map(port_lines_to_alive_hosts)
        })
        .await;
        match r {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(std::io::Error::other(format!("{e}"))),
        }
    };

    let v6_fut = async {
        if v6.is_empty() {
            return Ok(HashSet::new());
        }
        let r = tokio::task::spawn_blocking(move || {
            crate::ip_proto::parallel_ip_proto_scan_ipv6(
                v6, timeout, None, None, None, None, None, 0, max_shards,
            )
            .map(port_lines_to_alive_hosts)
        })
        .await;
        match r {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(std::io::Error::other(format!("{e}"))),
        }
    };

    let (r4, r6) = tokio::join!(v4_fut, v6_fut);
    let mut out = HashSet::new();
    match r4 {
        Ok(s) => out.extend(s),
        Err(e) => tracing::warn!(error = %e, "IP protocol discovery IPv4 (-PO) failed"),
    }
    match r6 {
        Ok(s) => out.extend(s),
        Err(e) => tracing::warn!(error = %e, "IP protocol discovery IPv6 (-PO) failed"),
    }
    out
}

async fn ip_proto_ping_discovery_merge(
    hosts: &[IpAddr],
    protos: &[u16],
    alive: &mut HashSet<IpAddr>,
    connect_timeout: Duration,
    max_shards: usize,
) {
    let skip = alive.clone();
    let s =
        ip_proto_ping_discovery_collect(hosts, protos, Some(&skip), connect_timeout, max_shards)
            .await;
    alive.extend(s);
}

async fn sctp_discovery_merge(
    hosts: &[IpAddr],
    ports: &[u16],
    alive: &mut HashSet<IpAddr>,
    connect_timeout: Duration,
    max_shards: usize,
) {
    let skip = alive.clone();
    let s =
        sctp_raw_discovery_collect(hosts, ports, Some(&skip), connect_timeout, max_shards).await;
    alive.extend(s);
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

#[cfg(unix)]
async fn icmp_timestamp_discovery_merge(
    hosts: &[IpAddr],
    alive: &mut HashSet<IpAddr>,
    timeout: Duration,
    concurrency: usize,
) {
    let skip = alive.clone();
    let v4: Vec<Ipv4Addr> = hosts
        .iter()
        .copied()
        .filter(|h| !skip.contains(h))
        .filter_map(|h| match h {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        })
        .collect();
    if v4.is_empty() {
        return;
    }
    let results: Vec<(IpAddr, bool)> = stream::iter(v4.into_iter())
        .map(|dst| async move {
            let ok = tokio::task::spawn_blocking(move || {
                crate::icmp_ping::icmp_timestamp_probe_v4(dst, timeout)
            })
            .await
            .unwrap_or(false);
            (IpAddr::V4(dst), ok)
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    for (ip, ok) in results {
        if ok {
            alive.insert(ip);
        }
    }
}

#[cfg(unix)]
async fn icmp_mask_discovery_merge(
    hosts: &[IpAddr],
    alive: &mut HashSet<IpAddr>,
    timeout: Duration,
    concurrency: usize,
) {
    let skip = alive.clone();
    let v4: Vec<Ipv4Addr> = hosts
        .iter()
        .copied()
        .filter(|h| !skip.contains(h))
        .filter_map(|h| match h {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        })
        .collect();
    if v4.is_empty() {
        return;
    }
    let results: Vec<(IpAddr, bool)> = stream::iter(v4.into_iter())
        .map(|dst| async move {
            let ok = tokio::task::spawn_blocking(move || {
                crate::icmp_ping::icmp_address_mask_probe_v4(dst, timeout)
            })
            .await
            .unwrap_or(false);
            (IpAddr::V4(dst), ok)
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    for (ip, ok) in results {
        if ok {
            alive.insert(ip);
        }
    }
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
    let max_sctp_shards = c.clamp(1, MAX_SCTP_PARALLEL_SHARDS);
    let max_ip_proto_shards = c.clamp(1, MAX_IP_PROTO_PARALLEL_SHARDS);

    if (args.ping_timestamp || args.ping_mask) && hosts.iter().any(|h| matches!(h, IpAddr::V6(_))) {
        let n = hosts.iter().filter(|h| matches!(h, IpAddr::V6(_))).count();
        tracing::warn!(
            count = n,
            "ICMP timestamp (-PP) and netmask (-PM) are IPv4-only; skipping IPv6 targets"
        );
    }
    if args.ping_timestamp && cfg!(not(unix)) {
        tracing::warn!("-PP (ICMP timestamp) requires Unix raw ICMP; skipping");
    }
    if args.ping_mask && cfg!(not(unix)) {
        tracing::warn!("-PM (ICMP netmask) requires Unix raw ICMP; skipping");
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
            tcp_ps_discovery_merge(&hosts, &ports, c, &mut alive, connect_timeout, max_shards)
                .await;
        }
        if args.ping_ack.is_some() {
            let ports = ports_from_ping_tcp(&args.ping_ack, TCP_ACK_DEFAULT)?;
            tcp_pa_discovery_merge(&hosts, &ports, c, &mut alive, connect_timeout, max_shards)
                .await;
        }
        if args.ping_udp.is_some() {
            let ports = ports_from_ping_udp(&args.ping_udp)?;
            udp_discovery(&hosts, &ports, c, &mut alive, connect_timeout).await;
        }
        if args.ping_sctp.is_some() {
            let ports = ports_from_ping_sctp(&args.ping_sctp)?;
            sctp_discovery_merge(&hosts, &ports, &mut alive, connect_timeout, max_sctp_shards)
                .await;
        }
        if let Some(opt) = &args.ping_ip_proto {
            let protos = parse_ping_ip_proto_list(opt.as_deref().unwrap_or(""))?;
            ip_proto_ping_discovery_merge(
                &hosts,
                &protos,
                &mut alive,
                connect_timeout,
                max_ip_proto_shards,
            )
            .await;
        }
        if args.ping_timestamp {
            #[cfg(unix)]
            icmp_timestamp_discovery_merge(&hosts, &mut alive, connect_timeout, c).await;
        }
        if args.ping_mask {
            #[cfg(unix)]
            icmp_mask_discovery_merge(&hosts, &mut alive, connect_timeout, c).await;
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
        assert_eq!(ports_from_ping_tcp(&Some(None), 80).unwrap(), vec![80]);
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
    fn ports_from_ping_sctp_variants() {
        assert_eq!(ports_from_ping_sctp(&Some(None)).unwrap(), vec![80]);
        assert_eq!(
            ports_from_ping_sctp(&Some(Some("38412".into()))).unwrap(),
            vec![38412]
        );
        assert!(ports_from_ping_sctp(&None).unwrap().is_empty());
    }

    #[test]
    fn parse_ping_ip_proto_list_variants() {
        assert_eq!(parse_ping_ip_proto_list("").unwrap(), vec![1, 2, 4]);
        assert_eq!(parse_ping_ip_proto_list("  ").unwrap(), vec![1, 2, 4]);
        assert_eq!(parse_ping_ip_proto_list("6").unwrap(), vec![6]);
        assert_eq!(parse_ping_ip_proto_list("17,6").unwrap(), vec![6, 17]);
        assert!(parse_ping_ip_proto_list("256").is_err());
        assert!(parse_ping_ip_proto_list(",,").is_err());
    }

    #[test]
    fn port_lines_to_alive_filters_timeouts() {
        let lines = vec![
            PortLine::new(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                80,
                "tcp",
                "closed",
                crate::scan::PortReason::ConnRefused,
                None,
            ),
            PortLine::new(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                80,
                "tcp",
                "filtered",
                crate::scan::PortReason::Timeout,
                None,
            ),
        ];
        let a = port_lines_to_alive_hosts(lines);
        assert_eq!(a.len(), 1);
        assert!(a.contains(&IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))));
    }
}

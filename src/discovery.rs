//! Host discovery before port scan. Skipped with `-Pn` / `--no-ping`.
//!
//! When no `-P*` probes are specified, Nmap sends several default probes; here we use ICMP echo
//! plus TCP connects to **443** and **80** (approximating Nmap’s TCP SYN to 443 and TCP ACK to 80).
//! Explicit `-PE`, `-PS`, `-PA`, `-PU` narrow or combine probes. Raw half-open SYN/ACK is not required for
//! “host is up”: a completed connect or `ECONNREFUSED` (RST) implies the target stack responded.
//!
//! **UDP `-PU`**: we send a UDP datagram and treat a non-empty UDP reply or a socket error that
//! typically follows ICMP destination-unreachable (`ECONNREFUSED` / unreachable) as “up”. A pure
//! receive timeout is treated as not up (conservative; OSes differ on ICMP→socket mapping).

use std::collections::HashSet;
use std::io::ErrorKind as IoErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use futures::stream::{self, StreamExt};
use tokio::io::ErrorKind as TokioErrorKind;
use tokio::net::{TcpStream, UdpSocket};

use crate::cli::Args;
use crate::ping::ping_hosts;
use crate::ports::parse_port_spec;

/// TCP ports for default discovery (Nmap: SYN 443, ACK 80 — both approximated via connect).
const DEFAULT_TCP_DISCOVERY_PORTS: &[u16] = &[443, 80];

const TCP_SYN_DEFAULT: u16 = 80;
const TCP_ACK_DEFAULT: u16 = 80;
/// Nmap default UDP ping port when `-PU` is given without a list.
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

async fn tcp_probe(host: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(host, port);
    let timeout = Duration::from_secs(1);
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
) -> HashSet<IpAddr> {
    let pairs: Vec<(IpAddr, u16)> = hosts
        .iter()
        .copied()
        .filter(|h| !skip.map(|s| s.contains(h)).unwrap_or(false))
        .flat_map(|h| ports.iter().map(move |&p| (h, p)))
        .collect();

    let results: Vec<(IpAddr, bool)> = stream::iter(pairs.into_iter())
        .map(|(host, port)| async move { (host, tcp_probe(host, port).await) })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(h, _)| h)
        .collect()
}

async fn tcp_connect_discovery(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    alive: &mut HashSet<IpAddr>,
) {
    let skip = alive.clone();
    let new_up = tcp_connect_discovery_collect(hosts, ports, concurrency, Some(&skip)).await;
    alive.extend(new_up);
}

/// UDP ping: ICMP port-unreachable often surfaces as `ECONNREFUSED` on `recv_from` (Linux/macOS).
async fn udp_ping_probe(host: IpAddr, port: u16) -> bool {
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
    let wait = Duration::from_secs(1);
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
) -> HashSet<IpAddr> {
    let pairs: Vec<(IpAddr, u16)> = hosts
        .iter()
        .copied()
        .filter(|h| !skip.map(|s| s.contains(h)).unwrap_or(false))
        .flat_map(|h| ports.iter().map(move |&p| (h, p)))
        .collect();

    let results: Vec<(IpAddr, bool)> = stream::iter(pairs.into_iter())
        .map(|(host, port)| async move { (host, udp_ping_probe(host, port).await) })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(h, _)| h)
        .collect()
}

async fn udp_discovery(hosts: &[IpAddr], ports: &[u16], concurrency: usize, alive: &mut HashSet<IpAddr>) {
    let skip = alive.clone();
    let new_up = udp_discovery_collect(hosts, ports, concurrency, Some(&skip)).await;
    alive.extend(new_up);
}

/// Filter `hosts` to targets that respond to at least one discovery probe.
pub async fn hosts_after_discovery(
    hosts: Vec<IpAddr>,
    args: &Args,
    concurrency: usize,
) -> Result<Vec<IpAddr>> {
    if args.no_ping {
        return Ok(hosts);
    }
    if hosts.is_empty() {
        return Ok(hosts);
    }

    let c = concurrency.max(1);

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
                tcp_connect_discovery_collect(&hosts_tcp, DEFAULT_TCP_DISCOVERY_PORTS, c, None).await
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
            tcp_connect_discovery(&hosts, &ports, c, &mut alive).await;
        }
        if args.ping_ack.is_some() {
            let ports = ports_from_ping_tcp(&args.ping_ack, TCP_ACK_DEFAULT)?;
            tcp_connect_discovery(&hosts, &ports, c, &mut alive).await;
        }
        if args.ping_udp.is_some() {
            let ports = ports_from_ping_udp(&args.ping_udp)?;
            udp_discovery(&hosts, &ports, c, &mut alive).await;
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
}

//! Parallel TCP connect and UDP probes (`tokio` + bounded concurrency).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::config::ScanPlan;

/// Outcome of an ICMP error that references our UDP probe (embedded IP header + UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpIcmpOutcome {
    /// ICMPv4 type 3 code 3 / ICMPv6 type 1 code 4 — port explicitly closed.
    Closed,
    /// Other destination-unreachable codes (host/net unreachable, admin prohibited, etc.) — path/filtered.
    Filtered,
}

/// Concurrent map filled by ICMP / ICMPv6 listeners. `Closed` wins over `Filtered` if both appear.
pub type UdpIcmpNotes = Arc<DashMap<(IpAddr, u16), UdpIcmpOutcome>>;

pub(crate) fn merge_udp_icmp_note(notes: &UdpIcmpNotes, k: (IpAddr, u16), new: UdpIcmpOutcome) {
    notes
        .entry(k)
        .and_modify(|cur| {
            if new == UdpIcmpOutcome::Closed {
                *cur = UdpIcmpOutcome::Closed;
            }
        })
        .or_insert(new);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReason {
    SynAck,
    ConnRefused,
    Timeout,
    Error,
    UdpResponse,
    IcmpPortUnreachable,
    IcmpUnreachableFiltered,
}

#[derive(Debug, Clone)]
pub struct PortLine {
    pub host: IpAddr,
    pub port: u16,
    pub proto: &'static str,
    pub state: &'static str,
    pub reason: PortReason,
    pub latency_ms: Option<u128>,
}

/// TCP connect scan with `buffer_unordered(concurrency)`.
pub async fn tcp_connect_scan(work: Vec<(IpAddr, u16)>, plan: Arc<ScanPlan>) -> Vec<PortLine> {
    let sem = Arc::new(Semaphore::new(plan.concurrency.max(1)));
    let timeout = plan.connect_timeout;
    let no_ping = plan.no_ping;

    stream::iter(work)
        .map(|(host, port)| {
            let sem = sem.clone();
            async move {
                let _p = sem.acquire().await.ok()?;
                let addr = SocketAddr::new(host, port);
                let start = Instant::now();
                let fut = TcpStream::connect(addr);
                let res = tokio::time::timeout(timeout, fut).await;
                let elapsed = start.elapsed().as_millis();
                Some(match res {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        PortLine {
                            host,
                            port,
                            proto: "tcp",
                            state: "open",
                            reason: PortReason::SynAck,
                            latency_ms: Some(elapsed),
                        }
                    }
                    Ok(Err(e)) => {
                        let kind = e.kind();
                        let (state, reason): (&'static str, PortReason) =
                            if kind == io::ErrorKind::ConnectionRefused {
                                ("closed", PortReason::ConnRefused)
                            } else {
                                ("filtered", PortReason::Error)
                            };
                        PortLine {
                            host,
                            port,
                            proto: "tcp",
                            state,
                            reason,
                            latency_ms: Some(elapsed),
                        }
                    }
                    Err(_) => PortLine {
                        host,
                        port,
                        proto: "tcp",
                        state: if no_ping { "open|filtered" } else { "filtered" },
                        reason: PortReason::Timeout,
                        latency_ms: None,
                    },
                })
            }
        })
        .buffer_unordered(plan.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

/// UDP scan: send a minimal datagram and treat any UDP reply as `open`; timeout → `open|filtered`.
///
/// When `icmp_notes` is set, ICMP destination-unreachable messages after the UDP timeout refine
/// `open|filtered` to `closed` (port unreachable) or `filtered` (other unreachable codes).
pub async fn udp_scan(
    work: Vec<(IpAddr, u16)>,
    plan: Arc<ScanPlan>,
    icmp_notes: Option<UdpIcmpNotes>,
) -> Vec<PortLine> {
    let sem = Arc::new(Semaphore::new(plan.concurrency.max(1)));
    let timeout = plan.connect_timeout;

    stream::iter(work)
        .map(|(host, port)| {
            let sem = sem.clone();
            let icmp_notes = icmp_notes.clone();
            async move {
                let _p = sem.acquire().await.ok()?;
                let bind_addr: SocketAddr = match host {
                    IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    IpAddr::V6(_) => "[::]:0".parse().unwrap(),
                };
                let socket = UdpSocket::bind(bind_addr).await.ok()?;
                let dst = SocketAddr::new(host, port);
                let start = Instant::now();
                let payload = [0x00u8];
                if socket.send_to(&payload, dst).await.is_err() {
                    return Some(PortLine {
                        host,
                        port,
                        proto: "udp",
                        state: "filtered",
                        reason: PortReason::Error,
                        latency_ms: Some(start.elapsed().as_millis()),
                    });
                }
                let mut buf = [0u8; 512];
                let recv = socket.recv_from(&mut buf);
                let res = tokio::time::timeout(timeout, recv).await;
                let elapsed = start.elapsed().as_millis();
                Some(match res {
                    Ok(Ok((n, _))) if n > 0 => PortLine {
                        host,
                        port,
                        proto: "udp",
                        state: "open",
                        reason: PortReason::UdpResponse,
                        latency_ms: Some(elapsed),
                    },
                    Ok(_) => PortLine {
                        host,
                        port,
                        proto: "udp",
                        state: "open|filtered",
                        reason: PortReason::Error,
                        latency_ms: Some(elapsed),
                    },
                    Err(_) => {
                        if let Some(ref notes) = icmp_notes {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            if let Some(out) = notes.get(&(host, port)).as_deref().copied() {
                                return Some(match out {
                                    UdpIcmpOutcome::Closed => PortLine {
                                        host,
                                        port,
                                        proto: "udp",
                                        state: "closed",
                                        reason: PortReason::IcmpPortUnreachable,
                                        latency_ms: None,
                                    },
                                    UdpIcmpOutcome::Filtered => PortLine {
                                        host,
                                        port,
                                        proto: "udp",
                                        state: "filtered",
                                        reason: PortReason::IcmpUnreachableFiltered,
                                        latency_ms: None,
                                    },
                                });
                            }
                        }
                        PortLine {
                            host,
                            port,
                            proto: "udp",
                            state: "open|filtered",
                            reason: PortReason::Timeout,
                            latency_ms: None,
                        }
                    }
                })
            }
        })
        .buffer_unordered(plan.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

#[cfg(test)]
mod merge_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use dashmap::DashMap;

    use super::{merge_udp_icmp_note, UdpIcmpNotes, UdpIcmpOutcome};

    #[test]
    fn merge_prefers_closed_over_filtered() {
        let notes: UdpIcmpNotes = Arc::new(DashMap::new());
        let k = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Filtered);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Closed);
        assert_eq!(*notes.get(&k).unwrap(), UdpIcmpOutcome::Closed);
    }

    #[test]
    fn merge_keeps_closed_when_later_filtered() {
        let notes: UdpIcmpNotes = Arc::new(DashMap::new());
        let k = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 9);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Closed);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Filtered);
        assert_eq!(*notes.get(&k).unwrap(), UdpIcmpOutcome::Closed);
    }
}

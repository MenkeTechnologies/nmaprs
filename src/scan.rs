//! Parallel TCP connect and UDP probes (`tokio` + bounded concurrency).

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::config::ScanPlan;

/// Filled by ICMP / ICMPv6 listeners when a UDP port-unreachable is observed (IPv4: type 3 code 3; IPv6: type 1 code 4).
pub type UdpIcmpClosedSet = Arc<Mutex<HashSet<(IpAddr, u16)>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReason {
    SynAck,
    ConnRefused,
    Timeout,
    Error,
    UdpResponse,
    IcmpPortUnreachable,
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
/// When `icmp_closed` is set (ICMP / ICMPv6 listeners), a port-unreachable after the UDP timeout
/// marks the port `closed` instead of `open|filtered`.
pub async fn udp_scan(
    work: Vec<(IpAddr, u16)>,
    plan: Arc<ScanPlan>,
    icmp_closed: Option<UdpIcmpClosedSet>,
) -> Vec<PortLine> {
    let sem = Arc::new(Semaphore::new(plan.concurrency.max(1)));
    let timeout = plan.connect_timeout;

    stream::iter(work)
        .map(|(host, port)| {
            let sem = sem.clone();
            let icmp_closed = icmp_closed.clone();
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
                        if let Some(ref set) = icmp_closed {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            if set.lock().contains(&(host, port)) {
                                return Some(PortLine {
                                    host,
                                    port,
                                    proto: "udp",
                                    state: "closed",
                                    reason: PortReason::IcmpPortUnreachable,
                                    latency_ms: None,
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

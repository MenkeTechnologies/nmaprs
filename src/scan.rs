//! Parallel TCP connect and UDP probes (`tokio` + bounded concurrency).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use futures::stream::{self, StreamExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::config::ScanPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReason {
    SynAck,
    ConnRefused,
    Timeout,
    Error,
    UdpResponse,
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
pub async fn udp_scan(work: Vec<(IpAddr, u16)>, plan: Arc<ScanPlan>) -> Vec<PortLine> {
    let sem = Arc::new(Semaphore::new(plan.concurrency.max(1)));
    let timeout = plan.connect_timeout;

    stream::iter(work)
        .map(|(host, port)| {
            let sem = sem.clone();
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
                    Err(_) => PortLine {
                        host,
                        port,
                        proto: "udp",
                        state: "open|filtered",
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

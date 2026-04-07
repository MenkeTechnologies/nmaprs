//! Highly parallel TCP connect scanning (tokio + bounded concurrency).

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReason {
    SynAck,
    ConnRefused,
    Timeout,
    Error,
}

#[derive(Debug, Clone)]
pub struct PortLine {
    pub host: Ipv4Addr,
    pub port: u16,
    pub state: &'static str,
    pub reason: PortReason,
    pub latency_ms: Option<u128>,
}

/// TCP connect scan with `buffer_unordered(concurrency)` for parallelism across all host:port pairs.
pub async fn tcp_connect_scan(hosts: Vec<Ipv4Addr>, plan: Arc<ScanPlan>) -> Vec<PortLine> {
    let sem = Arc::new(Semaphore::new(plan.concurrency.max(1)));
    let timeout = plan.connect_timeout;
    let no_ping = plan.no_ping;

    let work: Vec<(Ipv4Addr, u16)> = hosts
        .into_iter()
        .flat_map(|h| plan.ports.iter().copied().map(move |p| (h, p)))
        .collect();

    stream::iter(work)
        .map(|(host, port)| {
            let sem = sem.clone();
            async move {
                let _p = sem.acquire().await.ok()?;
                let addr = SocketAddr::from((host, port));
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
                            state,
                            reason,
                            latency_ms: Some(elapsed),
                        }
                    }
                    Err(_) => PortLine {
                        host,
                        port,
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

//! ICMP host discovery (`-sn`) via system `ping` / `ping6` (portable; no raw ICMP in userspace here).

use std::net::IpAddr;
use std::time::Instant;

use futures::stream::{self, StreamExt};
use tokio::process::Command;

/// Outcome of probing a single host with ICMP echo.
#[derive(Debug, Clone)]
pub struct PingOutcome {
    pub host: IpAddr,
    pub up: bool,
    pub ttl: Option<u8>,
    pub latency_ms: Option<u128>,
}

pub async fn ping_hosts(hosts: &[IpAddr], concurrency: usize) -> Vec<PingOutcome> {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    stream::iter(hosts.iter().copied())
        .map(|h| {
            let sem = sem.clone();
            async move {
                let _p = sem.acquire().await.ok()?;
                Some(ping_one(h).await)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

async fn ping_one(host: IpAddr) -> PingOutcome {
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

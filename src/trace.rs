//! `--traceroute` using system `traceroute` / `tracert`.
//!
//! Hosts are probed **concurrently** up to `min(max_parallel, 32)` to avoid spawning hundreds of
//! subprocesses at once; output is printed in **input order**.

use std::net::IpAddr;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use tokio::process::Command;

/// Upper bound on simultaneous `traceroute` / `tracert` processes (each is a heavy subprocess).
const MAX_TRACEROUTE_PARALLEL: usize = 32;

async fn traceroute_one(host: IpAddr) -> (String, String) {
    #[cfg(unix)]
    {
        let mut c = Command::new("traceroute");
        c.arg("-n").arg("-q").arg("1");
        #[cfg(target_os = "linux")]
        c.arg("-w").arg("1");
        c.arg(host.to_string());
        match c.output().await {
            Ok(out) => (
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ),
            Err(e) => {
                tracing::warn!(error = %e, %host, "traceroute failed");
                (String::new(), String::new())
            }
        }
    }
    #[cfg(windows)]
    {
        let mut c = Command::new("tracert");
        c.arg("-d").arg("-h").arg("15").arg(host.to_string());
        match c.output().await {
            Ok(out) => (
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ),
            Err(e) => {
                tracing::warn!(error = %e, %host, "tracert failed");
                (String::new(), String::new())
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = host;
        (String::new(), String::new())
    }
}

/// Run system traceroute for each host, **bounded parallel** (`max_parallel` clamped to
/// [`MAX_TRACEROUTE_PARALLEL`]), preserving scan output order.
pub async fn run_traceroute(hosts: &[IpAddr], max_parallel: usize) -> Result<()> {
    if hosts.is_empty() {
        return Ok(());
    }
    let cap = max_parallel.clamp(1, MAX_TRACEROUTE_PARALLEL);
    let chunks: Vec<(usize, IpAddr)> = hosts.iter().copied().enumerate().collect();
    let mut out: Vec<(usize, String, String)> = stream::iter(chunks.into_iter())
        .map(|(idx, host)| async move {
            let (stdout, stderr) = traceroute_one(host).await;
            (idx, stdout, stderr)
        })
        .buffer_unordered(cap)
        .collect()
        .await;
    out.sort_by_key(|(i, _, _)| *i);
    for (_, stdout, stderr) in out {
        print!("{stdout}");
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn traceroute_empty_is_ok() {
        run_traceroute(&[], 8).await.unwrap();
    }
}

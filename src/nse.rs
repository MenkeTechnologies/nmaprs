//! Built-in “script” probes (not full NSE/Lua). Parses `--script` / `-sC` and runs Rust builtins.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::warn;

use crate::cli::Args;

/// Run banner / default-style probes on open TCP `(host, port)` pairs.
pub async fn run_scripts(args: &Args, open_tcp: &[(IpAddr, u16)]) -> Result<()> {
    let mut names: Vec<String> = Vec::new();
    if args.script_default {
        names.push("default".into());
    }
    if let Some(s) = &args.script {
        names.extend(
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(String::from),
        );
    }
    if names.is_empty() {
        return Ok(());
    }

    for name in names {
        match name.as_str() {
            "default" | "banner" => {
                for &(host, port) in open_tcp {
                    match grab_tcp_banner(host, port).await {
                        Ok(Some(b)) => {
                            println!("NSE[{name}] {host}:{port} banner: {}", b.trim());
                        }
                        Ok(None) => {}
                        Err(e) => tracing::debug!("banner {host}:{port}: {e}"),
                    }
                }
            }
            other => {
                warn!("script {other} has no built-in implementation in nmaprs (Lua NSE not embedded)");
            }
        }
    }
    Ok(())
}

async fn grab_tcp_banner(host: IpAddr, port: u16) -> Result<Option<String>> {
    let addr = SocketAddr::new(host, port);
    let mut s = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };
    let mut buf = vec![0u8; 512];
    let n = match tokio::time::timeout(Duration::from_millis(800), s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) | Err(_) => 0,
    };
    if n == 0 {
        return Ok(None);
    }
    buf.truncate(n);
    Ok(String::from_utf8(buf).ok())
}

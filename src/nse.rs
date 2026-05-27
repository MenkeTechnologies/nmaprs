//! Built-in “script” probes (not full NSE/Lua). Parses `--script` / `-sC` and runs Rust builtins.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::warn;

use crate::cli::Args;

/// Run banner / default-style probes on open TCP `(host, port)` pairs.
pub async fn run_scripts(
    args: &Args,
    open_tcp: &[(IpAddr, u16)],
    script_timeout: Option<Duration>,
) -> Result<()> {
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

    let connect_to = script_timeout.unwrap_or(Duration::from_secs(3));

    for name in names {
        match name.as_str() {
            "default" | "banner" => {
                for &(host, port) in open_tcp {
                    match grab_tcp_banner(host, port, connect_to).await {
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

async fn grab_tcp_banner(host: IpAddr, port: u16, connect_to: Duration) -> Result<Option<String>> {
    let addr = SocketAddr::new(host, port);
    let mut s = match tokio::time::timeout(connect_to, TcpStream::connect(addr)).await {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use crate::cli::Args;

    use super::run_scripts;

    #[tokio::test]
    async fn run_scripts_no_names_is_noop() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "127.0.0.1"]).expect("parse");
        run_scripts(&args, &[], None).await.expect("run");
    }

    #[tokio::test]
    async fn run_scripts_trims_and_skips_empty_csv_tokens() {
        let args = Args::try_parse_from([
            "nmaprs",
            "-p",
            "80",
            "--script",
            "  , banner ,  , ",
            "127.0.0.1",
        ])
        .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_unknown_builtin_warns_but_ok() {
        let args = Args::try_parse_from([
            "nmaprs",
            "-p",
            "80",
            "--script",
            "nonexistent-nse-name",
            "127.0.0.1",
        ])
        .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_default_alias_runs_without_error() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script-default", "127.0.0.1"])
            .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_banner_on_empty_open_list_is_noop() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script", "banner", "127.0.0.1"])
            .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_default_and_banner_both_run() {
        let args = Args::try_parse_from([
            "nmaprs",
            "-p",
            "80",
            "--script-default",
            "--script",
            "banner",
            "127.0.0.1",
        ])
        .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_banner_alias_same_as_default_for_empty_list() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script", "banner", "127.0.0.1"])
            .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_multiple_unknown_names_still_ok() {
        let args =
            Args::try_parse_from(["nmaprs", "-p", "80", "--script", "foo,bar,baz", "127.0.0.1"])
                .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_with_unreachable_port_does_not_panic() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script", "banner", "127.0.0.1"])
            .expect("parse");
        let host: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        run_scripts(&args, &[(host, 65519)], Some(Duration::from_millis(50)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_duplicate_banner_token_runs_twice() {
        let args = Args::try_parse_from([
            "nmaprs",
            "-p",
            "80",
            "--script",
            "banner,banner",
            "127.0.0.1",
        ])
        .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_default_plus_unknown_name_still_ok() {
        let args = Args::try_parse_from([
            "nmaprs",
            "-p",
            "80",
            "--script-default",
            "--script",
            "no-such-script",
            "127.0.0.1",
        ])
        .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_whitespace_only_script_name_is_noop() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script", "   ", "127.0.0.1"])
            .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_banner_alias_on_unreachable_port() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script", "banner", "127.0.0.1"])
            .expect("parse");
        let host: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        run_scripts(&args, &[(host, 65518)], Some(Duration::from_millis(20)))
            .await
            .expect("run");
    }

    #[tokio::test]
    async fn run_scripts_three_unknown_names() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "--script", "a,b,c", "127.0.0.1"])
            .expect("parse");
        run_scripts(&args, &[], Some(Duration::from_millis(1)))
            .await
            .expect("run");
    }
}

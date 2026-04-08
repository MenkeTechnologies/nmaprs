//! `--traceroute` using system `traceroute` / `tracert`.

use std::net::IpAddr;

use anyhow::Result;
use tokio::process::Command;

pub async fn run_traceroute(hosts: &[IpAddr]) -> Result<()> {
    for h in hosts {
        #[cfg(unix)]
        {
            let mut c = Command::new("traceroute");
            c.arg("-n").arg("-q").arg("1");
            #[cfg(target_os = "linux")]
            c.arg("-w").arg("1");
            c.arg(h.to_string());
            match c.output().await {
                Ok(out) => {
                    print!("{}", String::from_utf8_lossy(&out.stdout));
                    if !out.stderr.is_empty() {
                        eprint!("{}", String::from_utf8_lossy(&out.stderr));
                    }
                }
                Err(e) => tracing::warn!("traceroute failed for {h}: {e}"),
            }
        }
        #[cfg(windows)]
        {
            let mut c = Command::new("tracert");
            c.arg("-d").arg("-h").arg("15").arg(h.to_string());
            if let Ok(out) = c.output().await {
                print!("{}", String::from_utf8_lossy(&out.stdout));
            }
        }
    }
    Ok(())
}

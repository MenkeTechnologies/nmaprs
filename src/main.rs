//! `nmaprs` binary entry — nmap-style argv expansion then [`nmaprs::run`].

use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .compact()
        .init();

    let args = nmaprs::cli::Args::parse_from_env();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let code = rt.block_on(nmaprs::run(args))?;
    std::process::exit(code);
}

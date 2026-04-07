//! `nmaprs` — parallel TCP connect scanner with nmap-style CLI parsing.

pub mod argv_expand;
pub mod cli;
pub mod config;
pub mod output;
pub mod ports;
pub mod scan;
pub mod target;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{info, warn};

use crate::cli::Args;
use crate::config::ScanPlan;
use crate::output::{print_stdout, OutputSet};
use crate::scan::{tcp_connect_scan, PortLine};
use crate::target::{apply_exclude, expand_target};

/// Run the full pipeline: parse → plan → expand targets → scan → emit output.
pub async fn run(args: Args) -> Result<i32> {
    if args.iflist {
        bail!("--iflist is not implemented (use `ifconfig` / `ip addr`)");
    }
    if args.ping_only {
        bail!("-sn (ping scan) is not implemented; ICMP / ARP discovery requires OS hooks");
    }
    if args.output_script_kiddie.is_some() {
        warn!("-oS (script kiddie) output is not implemented; ignoring");
    }

    let plan = ScanPlan::from_args(&args)?;
    let plan = Arc::new(plan);

    if args.targets.is_empty() && !args.list_scan {
        bail!("no targets specified (see -h)");
    }

    if args.list_scan {
        for t in &args.targets {
            let ips = expand_target(t, args.no_dns)
                .await
                .with_context(|| format!("expand target {t}"))?;
            for ip in ips {
                println!("{ip}");
            }
        }
        return Ok(0);
    }

    let mut hosts = Vec::new();
    for t in &args.targets {
        let ips = expand_target(t, args.no_dns)
            .await
            .with_context(|| format!("expand target {t}"))?;
        hosts.extend(ips);
    }

    hosts = apply_exclude(hosts, args.exclude.as_deref(), args.exclude_file.as_deref())
        .map_err(|e| anyhow!("{e}"))?;

    if hosts.is_empty() {
        bail!("no hosts to scan after exclusions");
    }

    if plan.verbosity >= 1 {
        info!(
            hosts = hosts.len(),
            ports = plan.ports.len(),
            concurrency = plan.concurrency,
            "starting scan"
        );
    }

    let lines = tcp_connect_scan(hosts.clone(), plan.clone()).await;

    let mut by_host: HashMap<std::net::Ipv4Addr, Vec<PortLine>> = HashMap::new();
    for l in lines {
        by_host.entry(l.host).or_default().push(l);
    }

    let cmdline = std::env::args().collect::<Vec<_>>().join(" ");
    let mut outs = OutputSet::open(
        plan.output_normal.as_deref(),
        plan.output_grepable.as_deref(),
        plan.output_xml.as_deref(),
        plan.append_output,
    )?;
    outs.write_headers(&cmdline)?;

    for host in &hosts {
        let hl = by_host.get(host).cloned().unwrap_or_default();
        println!("Nmap scan report for {host}");
        print_stdout(&hl, plan.open_only, plan.show_reason, plan.verbosity);
        if let Some(f) = &mut outs.normal {
            crate::output::write_normal(f, *host, &hl)?;
        }
        if let Some(f) = &mut outs.grep {
            crate::output::write_grep(f, *host, &hl)?;
        }
        if let Some(f) = &mut outs.xml {
            crate::output::write_xml_host(f, *host, &hl)?;
        }
    }

    outs.write_footer()?;

    Ok(0)
}

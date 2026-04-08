//! `nmaprs` — parallel network scanner with nmap-style CLI parsing.

pub mod argv_expand;
pub mod cli;
pub mod config;
pub mod icmp_listen;
pub mod ipv6_l4;
pub mod nse;
pub mod os_detect;
pub mod output;
pub mod ping;
pub mod ports;
pub mod resume;
pub mod scan;
pub mod syn;
pub mod target;
pub mod trace;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{info, warn};

use crate::cli::Args;
use crate::config::{ScanKind, ScanPlan};
use crate::output::{print_stdout, OutputSet};
use crate::scan::{tcp_connect_scan, udp_scan, PortLine, UdpIcmpClosedSet};
use crate::target::{apply_exclude, expand_target, random_addresses, read_input_list, ExpandOpts};

fn build_work(hosts: &[IpAddr], ports: &[u16]) -> Vec<(IpAddr, u16)> {
    hosts
        .iter()
        .flat_map(|h| ports.iter().map(|p| (*h, *p)))
        .collect()
}

async fn collect_hosts(args: &Args) -> Result<Vec<IpAddr>> {
    let opts = ExpandOpts {
        ipv6: args.ipv6,
        no_dns: args.no_dns,
    };
    let mut hosts = Vec::new();
    if let Some(path) = &args.input_list {
        for line in read_input_list(path)? {
            hosts.extend(expand_target(&line, &opts).await?);
        }
    }
    if let Some(n) = args.random_targets {
        hosts.extend(random_addresses(n, args.ipv6));
    }
    for t in &args.targets {
        hosts.extend(expand_target(t, &opts).await?);
    }
    Ok(hosts)
}

/// Run the full pipeline: parse → plan → expand targets → scan → emit output.
pub async fn run(args: Args) -> Result<i32> {
    if args.output_script_kiddie.is_some() {
        warn!("-oS (script kiddie) output is not implemented; ignoring");
    }

    if args.iflist {
        for iface in if_addrs::get_if_addrs()? {
            println!("{}: {:?}", iface.name, iface.addr);
        }
        return Ok(0);
    }

    let plan = ScanPlan::from_args(&args)?;
    let plan = Arc::new(plan);

    if args.targets.is_empty()
        && args.input_list.is_none()
        && args.random_targets.is_none()
        && !args.list_scan
    {
        bail!("no targets specified (see -h)");
    }

    if args.list_scan {
        let opts = ExpandOpts {
            ipv6: args.ipv6,
            no_dns: args.no_dns,
        };
        let mut tokens: Vec<String> = args.targets.clone();
        if let Some(path) = &args.input_list {
            for line in read_input_list(path)? {
                tokens.push(line);
            }
        }
        for t in tokens {
            let ips = expand_target(&t, &opts)
                .await
                .with_context(|| format!("expand target {t}"))?;
            for ip in ips {
                println!("{ip}");
            }
        }
        return Ok(0);
    }

    let mut hosts = collect_hosts(&args).await.context("collect targets")?;

    hosts = apply_exclude(
        hosts,
        args.exclude.as_deref(),
        args.exclude_file.as_deref(),
        &ExpandOpts {
            ipv6: args.ipv6,
            no_dns: args.no_dns,
        },
    )
    .map_err(|e| anyhow!("{e}"))?;

    if hosts.is_empty() {
        bail!("no hosts to scan after exclusions");
    }

    if plan.ping_only {
        let outs = crate::ping::ping_hosts(&hosts, plan.concurrency).await;
        for o in &outs {
            if o.up {
                println!("Nmap scan report for {} - Host is up", o.host);
                if plan.os_detect_requested {
                    println!("OS guess: {}", crate::os_detect::guess_from_ttl(o.ttl));
                }
            }
        }
        if plan.traceroute {
            crate::trace::run_traceroute(&hosts).await?;
        }
        return Ok(0);
    }

    if plan.verbosity >= 1 {
        info!(
            hosts = hosts.len(),
            ports = plan.ports.len(),
            concurrency = plan.concurrency,
            "starting scan"
        );
    }

    let mut work = build_work(&hosts, &plan.ports);
    if let Some(path) = &plan.resume_path {
        let st = crate::resume::ResumeState::load(path).unwrap_or_default();
        work.retain(|(h, p)| !st.is_done(*h, *p));
    }

    let lines: Vec<PortLine> = match plan.scan_kind {
        ScanKind::Udp => {
            let has_v4 = work.iter().any(|(h, _)| h.is_ipv4());
            let has_v6 = work.iter().any(|(h, _)| h.is_ipv6());
            if has_v4 || has_v6 {
                let closed: UdpIcmpClosedSet = Arc::new(Mutex::new(HashSet::new()));
                let stop = Arc::new(AtomicBool::new(false));
                let mut listeners = Vec::new();
                if has_v4 {
                    let closed_bg = closed.clone();
                    let stop_bg = stop.clone();
                    listeners.push(std::thread::spawn(move || {
                        if let Err(e) =
                            crate::icmp_listen::run_ipv4_port_unreachable_listener(closed_bg, stop_bg)
                        {
                            warn!(error = %e, "IPv4 ICMP port-unreachable listener exited");
                        }
                    }));
                }
                if has_v6 {
                    let closed_bg = closed.clone();
                    let stop_bg = stop.clone();
                    listeners.push(std::thread::spawn(move || {
                        if let Err(e) =
                            crate::icmp_listen::run_ipv6_port_unreachable_listener(closed_bg, stop_bg)
                        {
                            warn!(error = %e, "ICMPv6 port-unreachable listener exited");
                        }
                    }));
                }
                let lines = udp_scan(work, plan.clone(), Some(closed)).await;
                stop.store(true, Ordering::SeqCst);
                for h in listeners {
                    let _ = h.join();
                }
                lines
            } else {
                udp_scan(work, plan.clone(), None).await
            }
        }
        ScanKind::TcpSyn => {
            let mut collected = Vec::new();
            let v4: Vec<Ipv4Addr> = hosts
                .iter()
                .filter_map(|h| match h {
                    IpAddr::V4(a) => Some(*a),
                    _ => None,
                })
                .collect();
            let v6: Vec<Ipv6Addr> = hosts
                .iter()
                .filter_map(|h| match h {
                    IpAddr::V6(a) => Some(*a),
                    _ => None,
                })
                .collect();
            let v6_hosts: Vec<IpAddr> = hosts.iter().filter(|h| h.is_ipv6()).copied().collect();
            if !v4.is_empty() {
                let ports = plan.ports.clone();
                let to = plan.connect_timeout;
                match tokio::task::spawn_blocking(move || crate::syn::syn_scan_ipv4(v4, &ports, to))
                    .await
                {
                    Ok(Ok(mut s)) => collected.append(&mut s),
                    Ok(Err(e)) => {
                        warn!("SYN scan failed ({e}); falling back to TCP connect for IPv4");
                        let w: Vec<_> = build_work(
                            &hosts
                                .iter()
                                .copied()
                                .filter(|h| h.is_ipv4())
                                .collect::<Vec<_>>(),
                            &plan.ports,
                        );
                        collected.extend(tcp_connect_scan(w, plan.clone()).await);
                    }
                    Err(e) => bail!("SYN join: {e}"),
                }
            }
            if !v6.is_empty() {
                let ports = plan.ports.clone();
                let to = plan.connect_timeout;
                let plan_clone = plan.clone();
                match tokio::task::spawn_blocking(move || crate::syn::syn_scan_ipv6(v6, &ports, to))
                    .await
                {
                    Ok(Ok(mut s)) => collected.append(&mut s),
                    Ok(Err(e)) => {
                        warn!("IPv6 SYN scan failed ({e}); falling back to TCP connect for IPv6");
                        let w = build_work(&v6_hosts, &plan.ports);
                        collected.extend(tcp_connect_scan(w, plan_clone).await);
                    }
                    Err(e) => bail!("IPv6 SYN join: {e}"),
                }
            }
            collected
        }
        ScanKind::TcpConnect | ScanKind::Other(_) => tcp_connect_scan(work, plan.clone()).await,
    };

    if let Some(path) = &plan.resume_path {
        let mut st = crate::resume::ResumeState::load(path).unwrap_or_default();
        let pairs: Vec<_> = lines.iter().map(|l| (l.host, l.port)).collect();
        st.merge_from_scan(&pairs);
        st.save(path)?;
    }

    let mut by_host: HashMap<IpAddr, Vec<PortLine>> = HashMap::new();
    for l in lines.iter().cloned() {
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

    if plan.os_detect_requested && !plan.ping_only {
        let ping_out = crate::ping::ping_hosts(&hosts, plan.concurrency).await;
        for o in ping_out {
            if o.up {
                println!(
                    "OS guess for {}: {}",
                    o.host,
                    crate::os_detect::guess_from_ttl(o.ttl)
                );
            }
        }
    }

    if plan.script_requested {
        let open_tcp: Vec<_> = lines
            .iter()
            .filter(|l| l.proto == "tcp" && l.state == "open")
            .map(|l| (l.host, l.port))
            .collect();
        crate::nse::run_scripts(&args, &open_tcp).await?;
    }

    if plan.traceroute && !plan.ping_only {
        crate::trace::run_traceroute(&hosts).await?;
    }

    Ok(0)
}

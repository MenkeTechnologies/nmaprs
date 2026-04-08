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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use tracing::{info, warn};

use crate::cli::Args;
use crate::config::{ScanKind, ScanPlan};
use crate::output::{print_stdout, OutputSet};
use crate::scan::{tcp_connect_scan, udp_scan, PortLine, ProbeRatePacer, UdpIcmpNotes};
use crate::target::{apply_exclude, expand_target, random_addresses, read_input_list, ExpandOpts};

fn build_work(hosts: &[IpAddr], ports: &[u16]) -> Vec<(IpAddr, u16)> {
    hosts
        .iter()
        .flat_map(|h| ports.iter().map(|p| (*h, *p)))
        .collect()
}

type SynProbeV4 = (Ipv4Addr, u16);
type SynProbeV6 = (Ipv6Addr, u16);

/// Split `(host, port)` work for raw SYN: same ordering as TCP connect / UDP (`--resume` applies).
fn split_syn_work(work: &[(IpAddr, u16)]) -> (Vec<SynProbeV4>, Vec<SynProbeV6>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for &(h, p) in work {
        match h {
            IpAddr::V4(a) => v4.push((a, p)),
            IpAddr::V6(a) => v6.push((a, p)),
        }
    }
    (v4, v6)
}

/// Expand many target tokens (hostnames, CIDRs, …) **in parallel** while preserving input order.
async fn expand_specs_ordered(
    specs: Vec<String>,
    opts: ExpandOpts,
    concurrency: usize,
) -> Result<Vec<IpAddr>> {
    if specs.is_empty() {
        return Ok(vec![]);
    }
    let c = concurrency.max(1);
    let results: Vec<Result<(usize, Vec<IpAddr>), anyhow::Error>> = stream::iter(specs.into_iter().enumerate())
        .map(|(i, token)| async move {
                let ips = expand_target(&token, &opts)
                    .await
                    .map_err(|e| anyhow!("expand target {token}: {e}"))?;
                Ok((i, ips))
        })
        .buffer_unordered(c)
        .collect()
        .await;
    let mut indexed: Vec<(usize, Vec<IpAddr>)> = Vec::with_capacity(results.len());
    for r in results {
        indexed.push(r?);
    }
    indexed.sort_by_key(|(i, _)| *i);
    Ok(indexed.into_iter().flat_map(|(_, ips)| ips).collect())
}

async fn collect_hosts(args: &Args, concurrency: usize) -> Result<Vec<IpAddr>> {
    let opts = ExpandOpts {
        ipv6: args.ipv6,
        no_dns: args.no_dns,
    };
    let mut hosts = Vec::new();
    if let Some(path) = &args.input_list {
        let lines = read_input_list(path)?;
        hosts.extend(expand_specs_ordered(lines, opts, concurrency).await?);
    }
    if let Some(n) = args.random_targets {
        hosts.extend(random_addresses(n, args.ipv6));
    }
    if !args.targets.is_empty() {
        hosts.extend(
            expand_specs_ordered(args.targets.clone(), opts, concurrency).await?,
        );
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
        let ips = expand_specs_ordered(tokens, opts, plan.effective_probe_concurrency())
            .await
            .context("expand targets for list scan")?;
        for ip in ips {
            println!("{ip}");
        }
        return Ok(0);
    }

    let mut hosts = collect_hosts(&args, plan.effective_probe_concurrency())
        .await
        .context("collect targets")?;

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
        let outs = crate::ping::ping_hosts(&hosts, plan.effective_probe_concurrency()).await;
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
            concurrency = plan.effective_probe_concurrency(),
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
                let notes: UdpIcmpNotes = Arc::new(DashMap::new());
                let stop = Arc::new(AtomicBool::new(false));
                let mut listeners = Vec::new();
                #[cfg(unix)]
                let icmp_dual_stack = has_v4 && has_v6;
                #[cfg(not(unix))]
                let icmp_dual_stack = false;

                if icmp_dual_stack {
                    let notes_bg = notes.clone();
                    let stop_bg = stop.clone();
                    listeners.push(std::thread::spawn(move || {
                        if let Err(e) = crate::icmp_listen::run_udp_icmp_dual_stack(notes_bg, stop_bg) {
                            warn!(error = %e, "ICMP dual-stack listener exited");
                        }
                    }));
                } else {
                    if has_v4 {
                        let notes_bg = notes.clone();
                        let stop_bg = stop.clone();
                        listeners.push(std::thread::spawn(move || {
                            if let Err(e) =
                                crate::icmp_listen::run_ipv4_port_unreachable_listener(notes_bg, stop_bg)
                            {
                                warn!(error = %e, "IPv4 ICMP listener exited");
                            }
                        }));
                    }
                    if has_v6 {
                        let notes_bg = notes.clone();
                        let stop_bg = stop.clone();
                        listeners.push(std::thread::spawn(move || {
                            if let Err(e) =
                                crate::icmp_listen::run_ipv6_port_unreachable_listener(notes_bg, stop_bg)
                            {
                                warn!(error = %e, "ICMPv6 listener exited");
                            }
                        }));
                    }
                }
                let lines = udp_scan(work, plan.clone(), Some(notes)).await;
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
            let (work_v4, work_v6) = split_syn_work(&work);
            let to = plan.connect_timeout;
            let syn_pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
            let syn_host_start = plan
                .host_timeout
                .map(|_| Arc::new(DashMap::<IpAddr, Instant>::new()));
            let syn_host_limit = plan.host_timeout;
            let syn_scan_delay = plan.scan_delay;
            let syn_max_scan_delay = plan.max_scan_delay;

            let v4_fut = async {
                if work_v4.is_empty() {
                    return Ok(Ok(vec![]));
                }
                let pacer = syn_pacer.clone();
                let host_start = syn_host_start.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::syn::syn_scan_ipv4(
                        work_v4,
                        to,
                        pacer,
                        syn_host_limit,
                        host_start,
                        syn_scan_delay,
                        syn_max_scan_delay,
                    )
                })
                .await
                {
                    Ok(r) => Ok(r),
                    Err(e) => Err(anyhow!("SYN join v4: {e}")),
                }
            };
            let v6_fut = async {
                if work_v6.is_empty() {
                    return Ok(Ok(vec![]));
                }
                let pacer = syn_pacer.clone();
                let host_start = syn_host_start.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::syn::syn_scan_ipv6(
                        work_v6,
                        to,
                        pacer,
                        syn_host_limit,
                        host_start,
                        syn_scan_delay,
                        syn_max_scan_delay,
                    )
                })
                .await
                {
                    Ok(r) => Ok(r),
                    Err(e) => Err(anyhow!("SYN join v6: {e}")),
                }
            };

            let (v4_out, v6_out) = tokio::join!(v4_fut, v6_fut);

            let mut collected = Vec::new();

            let work_tcp_fallback_v4: Vec<(IpAddr, u16)> =
                work.iter().filter(|(h, _)| h.is_ipv4()).copied().collect();
            let work_tcp_fallback_v6: Vec<(IpAddr, u16)> =
                work.iter().filter(|(h, _)| h.is_ipv6()).copied().collect();

            match v4_out? {
                Ok(mut lines) => collected.append(&mut lines),
                Err(e) => {
                    warn!("SYN scan failed ({e}); falling back to TCP connect for IPv4");
                    collected.extend(tcp_connect_scan(work_tcp_fallback_v4, plan.clone()).await);
                }
            }
            match v6_out? {
                Ok(mut lines) => collected.append(&mut lines),
                Err(e) => {
                    warn!("IPv6 SYN scan failed ({e}); falling back to TCP connect for IPv6");
                    collected.extend(tcp_connect_scan(work_tcp_fallback_v6, plan.clone()).await);
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
        let ping_out = crate::ping::ping_hosts(&hosts, plan.effective_probe_concurrency()).await;
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

#[cfg(test)]
mod expand_specs_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::target::ExpandOpts;

    use super::expand_specs_ordered;

    #[tokio::test]
    async fn expand_specs_ordered_empty() {
        let opts = ExpandOpts {
            ipv6: false,
            no_dns: true,
        };
        let v = expand_specs_ordered(vec![], opts, 4).await.unwrap();
        assert!(v.is_empty());
    }

    #[tokio::test]
    async fn expand_specs_ordered_preserves_spec_order() {
        let opts = ExpandOpts {
            ipv6: false,
            no_dns: true,
        };
        let specs = vec!["127.0.0.2".to_string(), "127.0.0.1".to_string()];
        let v = expand_specs_ordered(specs, opts, 8).await.unwrap();
        assert_eq!(
            v,
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ]
        );
    }
}

#[cfg(test)]
mod syn_work_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::split_syn_work;

    #[test]
    fn split_syn_work_partitions_by_family() {
        let work = vec![
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        ];
        let (v4, v6) = split_syn_work(&work);
        assert_eq!(
            v4,
            vec![
                (Ipv4Addr::new(10, 0, 0, 1), 22),
                (Ipv4Addr::new(10, 0, 0, 2), 80),
            ]
        );
        assert_eq!(v6, vec![(Ipv6Addr::LOCALHOST, 443)]);
    }
}

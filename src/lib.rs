//! `nmaprs` — parallel network scanner with nmap-style CLI parsing.

pub mod argv_expand;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod ftp_bounce;
pub mod fp_match;
pub mod help_tp;
pub mod icmp_listen;
pub mod icmp_ping;
pub mod idle;
pub mod ip_proto;
pub mod ipv6_l4;
pub mod nse;
pub mod os_db;
pub mod os_detect;
pub mod os_fp_db;
pub mod os_scan;
pub mod output;
pub mod ping;
pub mod ports;
pub mod resume;
pub mod scan;
pub mod scanflags;
pub mod sctp;
pub mod skiddie;
pub mod syn;
pub mod target;
pub mod trace;
pub mod vscan;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use rand::seq::SliceRandom;
use rand::Rng;
use tracing::{info, warn};

use crate::cli::Args;
use crate::config::{ScanKind, ScanPlan};
use crate::output::{print_stdout, OutputSet};
use crate::scan::{tcp_connect_scan, udp_scan, PortLine, ProbeRatePacer, UdpIcmpNotes};
use crate::target::{apply_exclude, expand_target, random_addresses, read_input_list, ExpandOpts};

fn expand_opts(args: &Args) -> ExpandOpts {
    ExpandOpts {
        ipv6: args.ipv6,
        no_dns: args.no_dns,
        resolve_all: args.resolve_all,
    }
}

fn trace_nmap_compat(args: &Args) {
    if !(args.fragment
        || args.mtu.is_some()
        || args.decoys.is_some()
        || args.spoof_source.is_some()
        || args.interface.is_some()
        || args.source_port.is_some()
        || args.proxies.is_some()
        || args.data_hex.is_some()
        || args.data_string.is_some()
        || args.data_length.is_some()
        || args.ip_options.is_some()
        || args.ttl.is_some()
        || args.spoof_mac.is_some()
        || args.badsum
        || args.packet_trace
        || args.send_eth
        || args.send_ip
        || args.dns_servers.is_some()
        || args.system_dns
        || args.always_resolve
        || args.noninteractive
        || args.privileged
        || args.route_dst.is_some()
        || args.nsock_engine.is_some()
        || args.servicedb.is_some()
        || args.release_memory
        || args.nogcc
        || args.adler32
        || args.log_errors
        || args.deprecated_xml_osclass
        || args.thc
        || args.stats_every.is_some())
    {
        return;
    }
    tracing::debug!(
        "nmaprs: one or more packet-level / resolver / nsock options are set; not all are fully implemented (flags accepted for CLI parity)"
    );
}

async fn try_load_fp_db(plan: &ScanPlan) -> Option<Arc<crate::os_fp_db::FingerprintDb>> {
    let path = plan.data_file("nmap-os-db");
    if !path.exists() {
        return None;
    }
    match tokio::task::spawn_blocking(move || crate::os_fp_db::FingerprintDb::load(&path)).await {
        Ok(Ok(db)) => Some(Arc::new(db)),
        Ok(Err(e)) => {
            warn!("nmap-os-db: {e}");
            None
        }
        Err(e) => {
            warn!("nmap-os-db load: {e}");
            None
        }
    }
}

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

/// Default upper bound when only `--min-hostgroup` is set (Nmap-style).
const DEFAULT_HOSTGROUP_MAX: u32 = 1024;

fn host_batches(hosts: &[IpAddr], plan: &ScanPlan) -> Vec<Vec<IpAddr>> {
    if plan.hostgroup_min.is_none() && plan.hostgroup_max.is_none() {
        return vec![hosts.to_vec()];
    }
    let min_g = plan.hostgroup_min.unwrap_or(1);
    let max_g = plan.hostgroup_max.unwrap_or(DEFAULT_HOSTGROUP_MAX);
    batch_hosts_slice(hosts, min_g, max_g)
}

fn batch_hosts_slice(hosts: &[IpAddr], min_g: u32, max_g: u32) -> Vec<Vec<IpAddr>> {
    batch_hosts_slice_with_rng(hosts, min_g, max_g, &mut rand::thread_rng())
}

fn batch_hosts_slice_with_rng<R: Rng + ?Sized>(
    hosts: &[IpAddr],
    min_g: u32,
    max_g: u32,
    rng: &mut R,
) -> Vec<Vec<IpAddr>> {
    if hosts.is_empty() {
        return vec![];
    }
    let min_g = min_g.max(1);
    let max_g = max_g.max(min_g);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < hosts.len() {
        let remaining = hosts.len() - i;
        let chunk_upper = remaining.min(max_g as usize);
        let chunk_lower = (min_g as usize).min(chunk_upper);
        let chunk_size = if min_g == max_g {
            chunk_upper.min(min_g as usize)
        } else {
            rng.gen_range(chunk_lower..=chunk_upper)
        };
        let end = i + chunk_size;
        out.push(hosts[i..end].to_vec());
        i = end;
    }
    out
}

/// Raw ICMP listeners for UDP `closed`/`filtered` classification; shared across host batches.
fn spawn_udp_icmp_listeners(
    has_v4: bool,
    has_v6: bool,
    notes: UdpIcmpNotes,
    stop: Arc<AtomicBool>,
) -> Vec<std::thread::JoinHandle<()>> {
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
    listeners
}

async fn port_scan(work: Vec<(IpAddr, u16)>, plan: Arc<ScanPlan>) -> Result<Vec<PortLine>> {
    let out = match plan.scan_kind {
        ScanKind::Udp => {
            unreachable!("UDP scans use shared ICMP listeners in run(); do not call port_scan")
        }
        ScanKind::IpProto => {
            let (work_v4, work_v6) = split_syn_work(&work);
            if work_v4.is_empty() && work_v6.is_empty() {
                return Ok(vec![]);
            }
            let to = plan.connect_timeout;
            let pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
            let host_start = plan
                .host_timeout
                .map(|_| Arc::new(DashMap::<IpAddr, Instant>::new()));
            let host_limit = plan.host_timeout;
            let scan_delay = plan.scan_delay;
            let max_scan_delay = plan.max_scan_delay;
            let connect_retries = plan.connect_retries;
            let shard_cap = plan
                .effective_probe_concurrency()
                .clamp(1, crate::ip_proto::MAX_IP_PROTO_PARALLEL_SHARDS);

            let v4_fut = async {
                if work_v4.is_empty() {
                    return Ok::<Vec<PortLine>, anyhow::Error>(vec![]);
                }
                let work = work_v4;
                let pacer = pacer.clone();
                let host_start = host_start.clone();
                let out = tokio::task::spawn_blocking(move || {
                    crate::ip_proto::parallel_ip_proto_scan_ipv4(
                        work,
                        to,
                        pacer,
                        host_limit,
                        host_start,
                        scan_delay,
                        max_scan_delay,
                        connect_retries,
                        shard_cap,
                    )
                })
                .await
                .map_err(|e| anyhow!("IP protocol scan IPv4 join: {e}"))?;
                out.map_err(|e| anyhow!("IP protocol scan IPv4: {e}"))
            };

            let v6_fut = async {
                if work_v6.is_empty() {
                    return Ok::<Vec<PortLine>, anyhow::Error>(vec![]);
                }
                let work = work_v6;
                let pacer = pacer.clone();
                let host_start = host_start.clone();
                let out = tokio::task::spawn_blocking(move || {
                    crate::ip_proto::parallel_ip_proto_scan_ipv6(
                        work,
                        to,
                        pacer,
                        host_limit,
                        host_start,
                        scan_delay,
                        max_scan_delay,
                        connect_retries,
                        shard_cap,
                    )
                })
                .await
                .map_err(|e| anyhow!("IP protocol scan IPv6 join: {e}"))?;
                out.map_err(|e| anyhow!("IP protocol scan IPv6: {e}"))
            };

            let (v4_lines, v6_lines) = tokio::join!(v4_fut, v6_fut);
            let mut collected = Vec::new();
            collected.extend(v4_lines?);
            collected.extend(v6_lines?);
            collected
        }
        ScanKind::TcpSyn
        | ScanKind::TcpNull
        | ScanKind::TcpFin
        | ScanKind::TcpXmas
        | ScanKind::TcpMaimon
        | ScanKind::TcpAck
        | ScanKind::TcpWindow => {
            let kind = plan
                .scan_kind
                .tcp_port_raw_kind()
                .expect("raw TCP scan kinds only");
            let (work_v4, work_v6) = split_syn_work(&work);
            let to = plan.connect_timeout;
            let syn_pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
            let syn_host_start = plan
                .host_timeout
                .map(|_| Arc::new(DashMap::<IpAddr, Instant>::new()));
            let syn_host_limit = plan.host_timeout;
            let syn_scan_delay = plan.scan_delay;
            let syn_max_scan_delay = plan.max_scan_delay;
            let syn_connect_retries = plan.connect_retries;
            let syn_shard_cap = plan
                .effective_probe_concurrency()
                .clamp(1, crate::syn::MAX_SYN_PARALLEL_SHARDS);
            let tcp_scan_flags = plan.tcp_scan_flags;

            let v4_fut = async {
                if work_v4.is_empty() {
                    return Ok(Ok(vec![]));
                }
                let pacer = syn_pacer.clone();
                let host_start = syn_host_start.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::syn::parallel_tcp_port_scan_ipv4(
                        kind,
                        tcp_scan_flags,
                        work_v4,
                        to,
                        pacer,
                        syn_host_limit,
                        host_start,
                        syn_scan_delay,
                        syn_max_scan_delay,
                        syn_connect_retries,
                        syn_shard_cap,
                    )
                })
                .await
                {
                    Ok(r) => Ok(r),
                    Err(e) => Err(anyhow!("raw TCP ({kind}) join v4: {e}")),
                }
            };
            let v6_fut = async {
                if work_v6.is_empty() {
                    return Ok(Ok(vec![]));
                }
                let pacer = syn_pacer.clone();
                let host_start = syn_host_start.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::syn::parallel_tcp_port_scan_ipv6(
                        kind,
                        tcp_scan_flags,
                        work_v6,
                        to,
                        pacer,
                        syn_host_limit,
                        host_start,
                        syn_scan_delay,
                        syn_max_scan_delay,
                        syn_connect_retries,
                        syn_shard_cap,
                    )
                })
                .await
                {
                    Ok(r) => Ok(r),
                    Err(e) => Err(anyhow!("raw TCP ({kind}) join v6: {e}")),
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
                    if kind.tcp_connect_fallback_on_raw_error() {
                        warn!("{kind} scan failed ({e}); falling back to TCP connect for IPv4");
                        collected
                            .extend(tcp_connect_scan(work_tcp_fallback_v4, plan.clone()).await);
                    } else {
                        warn!(
                            "{kind} scan failed ({e}); skipping TCP connect fallback (raw scan semantics differ from connect)"
                        );
                    }
                }
            }
            match v6_out? {
                Ok(mut lines) => collected.append(&mut lines),
                Err(e) => {
                    if kind.tcp_connect_fallback_on_raw_error() {
                        warn!(
                            "IPv6 {kind} scan failed ({e}); falling back to TCP connect for IPv6"
                        );
                        collected
                            .extend(tcp_connect_scan(work_tcp_fallback_v6, plan.clone()).await);
                    } else {
                        warn!(
                            "IPv6 {kind} scan failed ({e}); skipping TCP connect fallback (raw scan semantics differ from connect)"
                        );
                    }
                }
            }

            collected
        }
        ScanKind::Idle => {
            let (work_v4, work_v6) = split_syn_work(&work);
            if !work_v6.is_empty() {
                warn!(
                    "Idle scan (-sI): skipping {} IPv6 target(s) (IPv4 only)",
                    work_v6.len()
                );
            }
            if work_v4.is_empty() {
                return Ok(vec![]);
            }
            let idle = plan
                .idle_scan
                .clone()
                .expect("idle scan requires idle_scan target");
            let plan_bg = plan.clone();
            let res = tokio::task::spawn_blocking(move || {
                crate::idle::idle_scan_ipv4(work_v4, idle, plan_bg)
            })
            .await
            .map_err(|e| anyhow!("idle scan join: {e}"))?;
            res.map_err(|e| anyhow!("idle scan: {e}"))?
        }
        ScanKind::SctpInit | ScanKind::SctpCookieEcho => {
            let probe = match plan.scan_kind {
                ScanKind::SctpInit => crate::sctp::SctpProbeKind::Init,
                ScanKind::SctpCookieEcho => crate::sctp::SctpProbeKind::CookieEcho,
                _ => unreachable!(),
            };
            let (work_v4, work_v6) = split_syn_work(&work);
            if work_v4.is_empty() && work_v6.is_empty() {
                return Ok(vec![]);
            }
            let to = plan.connect_timeout;
            let pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
            let host_start = plan
                .host_timeout
                .map(|_| Arc::new(DashMap::<IpAddr, Instant>::new()));
            let host_limit = plan.host_timeout;
            let scan_delay = plan.scan_delay;
            let max_scan_delay = plan.max_scan_delay;
            let connect_retries = plan.connect_retries;
            let shard_cap = plan
                .effective_probe_concurrency()
                .clamp(1, crate::sctp::MAX_SCTP_PARALLEL_SHARDS);

            let v4_fut = async {
                if work_v4.is_empty() {
                    return Ok::<Vec<PortLine>, anyhow::Error>(vec![]);
                }
                let work = work_v4;
                let pacer = pacer.clone();
                let host_start = host_start.clone();
                let out = tokio::task::spawn_blocking(move || {
                    crate::sctp::parallel_sctp_scan_ipv4(
                        work,
                        probe,
                        to,
                        pacer,
                        host_limit,
                        host_start,
                        scan_delay,
                        max_scan_delay,
                        connect_retries,
                        shard_cap,
                    )
                })
                .await
                .map_err(|e| anyhow!("SCTP IPv4 join: {e}"))?;
                out.map_err(|e| anyhow!("SCTP IPv4: {e}"))
            };

            let v6_fut = async {
                if work_v6.is_empty() {
                    return Ok::<Vec<PortLine>, anyhow::Error>(vec![]);
                }
                let work = work_v6;
                let pacer = pacer.clone();
                let host_start = host_start.clone();
                let out = tokio::task::spawn_blocking(move || {
                    crate::sctp::parallel_sctp_scan_ipv6(
                        work,
                        probe,
                        to,
                        pacer,
                        host_limit,
                        host_start,
                        scan_delay,
                        max_scan_delay,
                        connect_retries,
                        shard_cap,
                    )
                })
                .await
                .map_err(|e| anyhow!("SCTP IPv6 join: {e}"))?;
                out.map_err(|e| anyhow!("SCTP IPv6: {e}"))
            };

            let (v4_lines, v6_lines) = tokio::join!(v4_fut, v6_fut);
            let mut collected = Vec::new();
            collected.extend(v4_lines?);
            collected.extend(v6_lines?);
            collected
        }
        ScanKind::TcpConnect => {
            if let Some(fb) = plan.ftp_bounce.clone() {
                crate::ftp_bounce::ftp_bounce_scan(work, plan.clone(), fb).await
            } else {
                tcp_connect_scan(work, plan.clone()).await
            }
        }
    };
    Ok(out)
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
    let results: Vec<Result<(usize, Vec<IpAddr>), anyhow::Error>> =
        stream::iter(specs.into_iter().enumerate())
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
    let opts = expand_opts(args);
    let mut hosts = Vec::new();
    if let Some(path) = &args.input_list {
        let lines = read_input_list(path)?;
        hosts.extend(expand_specs_ordered(lines, opts, concurrency).await?);
    }
    if let Some(n) = args.random_targets {
        hosts.extend(random_addresses(n, args.ipv6));
    }
    if !args.targets.is_empty() {
        hosts.extend(expand_specs_ordered(args.targets.clone(), opts, concurrency).await?);
    }
    Ok(hosts)
}

/// Run the full pipeline: parse → plan → expand targets → scan → emit output.
pub async fn run(args: Args) -> Result<i32> {
    if let Some(expr) = &args.script_help {
        println!("nmaprs --script-help: {expr}");
        println!("Built-in scripts only (Lua NSE is not embedded). Use --script / -sC.");
        return Ok(0);
    }
    if args.script_updatedb {
        println!("nmaprs: --script-updatedb acknowledged (no bundled NSE database).");
        return Ok(0);
    }

    if args.iflist {
        for iface in if_addrs::get_if_addrs()? {
            println!("{}: {:?}", iface.name, iface.addr);
        }
        return Ok(0);
    }

    let plan = ScanPlan::from_args(&args)?;
    let plan = Arc::new(plan);

    let fp_db = if plan.os_detect_requested {
        try_load_fp_db(&plan).await
    } else {
        None
    };

    trace_nmap_compat(&args);
    if args.servicedb.is_some() {
        warn!("--servicedb: custom nmap-services path accepted; embedded top-ports list still used until full parser is wired");
    }
    if args.script_trace {
        tracing::info!("--script-trace: script I/O tracing not implemented for builtins");
    }

    if args.targets.is_empty()
        && args.input_list.is_none()
        && args.random_targets.is_none()
        && !args.list_scan
    {
        bail!("no targets specified (see -h)");
    }

    if args.list_scan {
        let opts = expand_opts(&args);
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
        &expand_opts(&args),
    )
    .map_err(|e| anyhow!("{e}"))?;

    if plan.unique {
        let mut seen = HashSet::new();
        hosts.retain(|h| seen.insert(*h));
    }
    if plan.randomize_hosts {
        hosts.shuffle(&mut rand::thread_rng());
    }

    if hosts.is_empty() {
        bail!("no hosts to scan after exclusions");
    }

    if !plan.ping_only && !plan.no_ping {
        hosts = crate::discovery::hosts_after_discovery(
            hosts,
            &args,
            plan.effective_probe_concurrency(),
            plan.connect_timeout,
        )
        .await
        .context("host discovery")?;
    }

    if plan.ping_only {
        let cmdline = std::env::args().collect::<Vec<_>>().join(" ");
        let mut outs = OutputSet::open(
            plan.output_normal.as_deref(),
            plan.output_grepable.as_deref(),
            plan.output_xml.as_deref(),
            plan.output_script_kiddie.as_deref(),
            plan.output_machine.as_deref(),
            plan.output_hex.as_deref(),
            plan.append_output,
        )?;
        outs.write_headers(
            &cmdline,
            args.stylesheet.as_deref(),
            args.webxml,
            args.no_stylesheet,
        )?;
        if let Some(hf) = &mut outs.hex {
            use std::io::Write;
            writeln!(
                hf,
                "# nmaprs -oH: full hex packet capture not implemented; placeholder header"
            )?;
        }

        let ex_cap = (plan.max_os_tries as usize).min(10);
        let ping_out = crate::ping::ping_hosts(&hosts, plan.effective_probe_concurrency()).await;
        for o in &ping_out {
            if !o.up {
                continue;
            }
            println!("Nmap scan report for {} - Host is up", o.host);
            let os_line = if plan.os_detect_requested {
                let base_guess = match fp_db.as_deref() {
                    Some(db) => db.format_os_guess(o.ttl, ex_cap),
                    None => crate::os_detect::guess_from_ttl(o.ttl).to_string(),
                };
                let s = format!("OS guess: {}", base_guess);
                println!("{}", s);
                Some(s)
            } else {
                None
            };
            crate::output::write_sn_host_files(
                outs.normal.as_mut(),
                outs.skiddie.as_mut(),
                outs.grep.as_mut(),
                outs.xml.as_mut(),
                o.host,
                os_line.as_deref(),
            )?;
            if let Some(mf) = &mut outs.machine {
                use std::io::Write;
                writeln!(mf, "Host: {} ()\tStatus: Up", o.host)?;
            }
        }
        outs.write_footer()?;
        if plan.traceroute {
            crate::trace::run_traceroute(&hosts, plan.effective_probe_concurrency()).await?;
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

    let mut resume_st = plan
        .resume_path
        .as_ref()
        .map(|p| crate::resume::ResumeState::load(p).unwrap_or_default());

    let mut lines: Vec<PortLine> = Vec::new();

    if plan.scan_kind == ScanKind::Udp {
        let has_v4 = hosts.iter().any(|h| h.is_ipv4());
        let has_v6 = hosts.iter().any(|h| h.is_ipv6());
        let mut icmp_session: Option<(
            UdpIcmpNotes,
            Arc<AtomicBool>,
            Vec<std::thread::JoinHandle<()>>,
        )> = None;

        for batch_hosts in host_batches(&hosts, &plan) {
            let mut work = build_work(&batch_hosts, &plan.ports);
            if let Some(ref st) = resume_st {
                work.retain(|(h, p)| !st.is_done(*h, *p));
            }
            if work.is_empty() {
                continue;
            }
            if icmp_session.is_none() && (has_v4 || has_v6) {
                let notes: UdpIcmpNotes = Arc::new(DashMap::new());
                let stop = Arc::new(AtomicBool::new(false));
                let handles = spawn_udp_icmp_listeners(has_v4, has_v6, notes.clone(), stop.clone());
                icmp_session = Some((notes, stop, handles));
            }
            let icmp_notes = icmp_session.as_ref().map(|(n, _, _)| n.clone());
            lines.extend(udp_scan(work, plan.clone(), icmp_notes).await);
        }

        if let Some((_, stop, handles)) = icmp_session {
            stop.store(true, Ordering::SeqCst);
            for h in handles {
                let _ = h.join();
            }
        }
    } else {
        for batch_hosts in host_batches(&hosts, &plan) {
            let mut work = build_work(&batch_hosts, &plan.ports);
            if let Some(ref st) = resume_st {
                work.retain(|(h, p)| !st.is_done(*h, *p));
            }
            if work.is_empty() {
                continue;
            }
            lines.extend(port_scan(work, plan.clone()).await?);
        }
    }

    if let Some(path) = &plan.resume_path {
        let pairs: Vec<_> = lines.iter().map(|l| (l.host, l.port)).collect();
        if let Some(ref mut st) = resume_st {
            st.merge_from_scan(&pairs);
            st.save(path)?;
        }
    }

    if plan.version_scan_requested {
        let path = plan.service_probes_path();
        if args.version_trace {
            tracing::info!("--version-trace: loading {}", path.display());
        }
        if path.exists() {
            let intensity = plan.version_intensity;
            let connect_timeout = plan.connect_timeout;
            let conc = plan.effective_probe_concurrency();
            let bundle =
                match tokio::task::spawn_blocking(move || crate::vscan::load_service_probes(&path))
                    .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        warn!("-sV: {e}");
                        crate::vscan::ServiceProbes::default()
                    }
                    Err(e) => {
                        warn!("-sV: load task: {e}");
                        crate::vscan::ServiceProbes::default()
                    }
                };
            let tcp_probes = Arc::new(bundle.tcp);
            let udp_probes = Arc::new(bundle.udp);
            if !tcp_probes.is_empty() {
                let open_tcp: Vec<_> = lines
                    .iter()
                    .filter(|l| l.proto == "tcp" && l.state == "open")
                    .map(|l| (l.host, l.port))
                    .collect();
                let vmap = crate::vscan::run_tcp_version_scan(
                    open_tcp,
                    tcp_probes,
                    intensity,
                    connect_timeout,
                    conc,
                )
                .await;
                for l in &mut lines {
                    if l.proto == "tcp" && l.state == "open" {
                        if let Some(v) = vmap.get(&(l.host, l.port)) {
                            l.version_info = Some(v.clone());
                        }
                    }
                }
            }
            if !udp_probes.is_empty() {
                let open_udp: Vec<_> = lines
                    .iter()
                    .filter(|l| l.proto == "udp" && l.state == "open")
                    .map(|l| (l.host, l.port))
                    .collect();
                let vmap_u = crate::vscan::run_udp_version_scan(
                    open_udp,
                    udp_probes,
                    intensity,
                    connect_timeout,
                    conc,
                )
                .await;
                for l in &mut lines {
                    if l.proto == "udp" && l.state == "open" {
                        if let Some(v) = vmap_u.get(&(l.host, l.port)) {
                            l.version_info = Some(v.clone());
                        }
                    }
                }
            }
        } else {
            warn!(
                "-sV: {} not found; install Nmap's nmap-service-probes under data/ or run scripts/fetch_nmap_data.sh",
                path.display()
            );
        }
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
        plan.output_script_kiddie.as_deref(),
        plan.output_machine.as_deref(),
        plan.output_hex.as_deref(),
        plan.append_output,
    )?;
    outs.write_headers(
        &cmdline,
        args.stylesheet.as_deref(),
        args.webxml,
        args.no_stylesheet,
    )?;
    if let Some(hf) = &mut outs.hex {
        use std::io::Write;
        writeln!(
            hf,
            "# nmaprs -oH: full hex packet capture not implemented; placeholder header"
        )?;
    }

    let ex_cap = (plan.max_os_tries as usize).min(10);
    for host in &hosts {
        let hl = by_host.get(host).cloned().unwrap_or_default();
        println!("Nmap scan report for {host}");
        print_stdout(&hl, plan.open_only, plan.show_reason, plan.verbosity);
        crate::output::write_normal_files(
            outs.normal.as_mut(),
            outs.skiddie.as_mut(),
            *host,
            &hl,
            plan.show_reason,
        )?;
        if let Some(f) = &mut outs.grep {
            crate::output::write_grep(f, *host, &hl)?;
        }
        if let Some(f) = &mut outs.machine {
            crate::output::write_grep(f, *host, &hl)?;
        }
        if let Some(f) = &mut outs.xml {
            crate::output::write_xml_host(f, *host, &hl)?;
        }
    }

    outs.write_footer()?;

    if plan.os_detect_requested && !plan.ping_only {
        let any_open_tcp = lines.iter().any(|l| l.proto == "tcp" && l.state == "open");
        if plan.osscan_limit && !any_open_tcp {
            if plan.verbosity >= 1 {
                info!("--osscan-limit: skipping OS detection (no open TCP ports)");
            }
        } else {
            let ping_out =
                crate::ping::ping_hosts(&hosts, plan.effective_probe_concurrency()).await;
            let to = plan.connect_timeout;
            for o in ping_out {
                if !o.up {
                    continue;
                }
                let mut os_line = match fp_db.as_deref() {
                    Some(db) => db.format_os_guess(o.ttl, ex_cap),
                    None => crate::os_detect::guess_from_ttl(o.ttl).to_string(),
                };
                if let (Some(db), std::net::IpAddr::V4(ip)) = (fp_db.as_deref(), o.host) {
                    let open = lines
                        .iter()
                        .find(|l| l.host == o.host && l.proto == "tcp" && l.state == "open")
                        .map(|l| l.port);
                    let closed = lines
                        .iter()
                        .find(|l| l.host == o.host && l.proto == "tcp" && l.state == "closed")
                        .map(|l| l.port);
                    let closed_udp = lines
                        .iter()
                        .find(|l| l.host == o.host && l.proto == "udp" && l.state == "closed")
                        .map(|l| l.port)
                        .unwrap_or(40125);
                    if let (Some(op), Some(cl)) = (open, closed) {
                        let r = tokio::task::spawn_blocking(move || {
                            crate::os_scan::probe_ipv4_os(ip, op, cl, closed_udp, to)
                        })
                        .await;
                        if let Ok(Ok(subj)) = r {
                            if let Some((idx, acc)) = db.best_match(&subj, 0.85) {
                                os_line = format!(
                                    "{} ({:.0}% match)",
                                    db.references[idx].name,
                                    acc * 100.0
                                );
                            }
                        }
                    }
                }
                println!("OS guess for {}: {}", o.host, os_line);
            }
        }
    }

    if plan.script_requested {
        let open_tcp: Vec<_> = lines
            .iter()
            .filter(|l| l.proto == "tcp" && l.state == "open")
            .map(|l| (l.host, l.port))
            .collect();
        crate::nse::run_scripts(&args, &open_tcp, plan.script_timeout).await?;
    }

    if plan.traceroute && !plan.ping_only {
        crate::trace::run_traceroute(&hosts, plan.effective_probe_concurrency()).await?;
    }

    Ok(0)
}

/// Initialize tracing, parse CLI args from the environment, and block on [`run`].
///
/// Shared by the `nmaprs` and `nms` binaries (identical behavior).
pub fn run_from_cli_env() -> Result<()> {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .compact()
        .init();

    let args = crate::cli::Args::parse_from_env();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let code = rt.block_on(crate::run(args))?;
    std::process::exit(code);
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
            resolve_all: false,
        };
        let v = expand_specs_ordered(vec![], opts, 4).await.unwrap();
        assert!(v.is_empty());
    }

    #[tokio::test]
    async fn expand_specs_ordered_preserves_spec_order() {
        let opts = ExpandOpts {
            ipv6: false,
            no_dns: true,
            resolve_all: false,
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

#[cfg(test)]
mod host_batch_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use clap::Parser;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::cli::Args;
    use crate::config::ScanPlan;

    use super::{batch_hosts_slice_with_rng, host_batches};

    fn ipv4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn batch_hosts_fixed_width_splits_and_preserves_order() {
        let hosts: Vec<_> = (1..=5).map(ipv4).collect();
        let mut rng = StdRng::seed_from_u64(0);
        let b = batch_hosts_slice_with_rng(&hosts, 2, 2, &mut rng);
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].len(), 2);
        assert_eq!(b[1].len(), 2);
        assert_eq!(b[2].len(), 1);
        let flat: Vec<_> = b.iter().flatten().copied().collect();
        assert_eq!(flat, hosts);
    }

    #[test]
    fn batch_hosts_empty_yields_empty() {
        let hosts: Vec<IpAddr> = vec![];
        let mut rng = StdRng::seed_from_u64(1);
        let b = batch_hosts_slice_with_rng(&hosts, 1, 10, &mut rng);
        assert!(b.is_empty());
    }

    #[test]
    fn host_batches_unset_is_single_pass() {
        let args = Args::try_parse_from(["nmaprs", "-p", "80", "127.0.0.1", "127.0.0.2"]).unwrap();
        let plan = ScanPlan::from_args(&args).expect("plan");
        let hosts = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let b = host_batches(&hosts, &plan);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0], hosts);
    }

    #[test]
    fn host_batches_min_max_one_splits_each_host() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--min-hostgroup",
            "1",
            "--max-hostgroup",
            "1",
            "-p",
            "80",
            "127.0.0.1",
            "127.0.0.2",
            "127.0.0.3",
        ])
        .unwrap();
        let plan = ScanPlan::from_args(&args).expect("plan");
        let hosts = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
        ];
        let b = host_batches(&hosts, &plan);
        assert_eq!(b.len(), 3);
        for chunk in &b {
            assert_eq!(chunk.len(), 1);
        }
    }
}

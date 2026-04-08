//! Resolve [`crate::cli::Args`] into an executable [`ScanPlan`].

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rand::seq::SliceRandom;
use tracing::{info, warn};

use crate::cli::Args;
use crate::ports::{
    default_tcp_ports, fast_tcp_ports, parse_exclude_ports, parse_port_spec, top_ports,
    top_ports_len,
};

/// Resolved scan configuration after validating nmap-style flags.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    pub ports: Vec<u16>,
    /// Resolved parallelism (timing template + `--min-parallelism` / `--max-parallelism`).
    pub concurrency: usize,
    /// `true` when the user set `--max-parallelism` (caps probe concurrency even with `--min-rate`).
    pub max_parallelism_explicit: bool,
    pub connect_timeout: Duration,
    pub no_ping: bool,
    pub scan_kind: ScanKind,
    pub verbosity: u8,
    pub debug: u8,
    pub sequential_ports: bool,
    pub list_scan: bool,
    pub ping_only: bool,
    pub output_normal: Option<PathBuf>,
    pub output_grepable: Option<PathBuf>,
    pub output_xml: Option<PathBuf>,
    pub output_all_base: Option<PathBuf>,
    pub append_output: bool,
    pub show_reason: bool,
    pub open_only: bool,
    pub randomize_ports: bool,
    pub aggressive: bool,
    pub version_scan_requested: bool,
    pub os_detect_requested: bool,
    pub script_requested: bool,
    pub traceroute: bool,
    pub resume_path: Option<PathBuf>,
    /// Cap on probe **starts** per second (`--max-rate`). `None` = no limit.
    pub max_probe_rate: Option<u64>,
    /// Minimum desired probe **starts** per second (`--min-rate`). Validated against `--max-rate`
    /// when both are set; does not install a pacer by itself (see [`crate::scan::ProbeRatePacer`]).
    pub min_probe_rate: Option<u64>,
    /// Max wall-clock time per host for the port scan phase (`--host-timeout`).
    pub host_timeout: Option<Duration>,
    /// Extra probe attempts after timeout (`--max-retries`); total tries = `1 + connect_retries`
    /// (TCP connect, UDP, raw SYN).
    pub connect_retries: u32,
    /// Minimum delay before each probe (`--scan-delay`); with `--max-scan-delay`, delay is uniform in `[min, max]`.
    pub scan_delay: Option<Duration>,
    pub max_scan_delay: Option<Duration>,
    /// `--min-hostgroup` / `--max-hostgroup` (Nmap-style host batches). `None` for both = scan all hosts in one batch.
    pub hostgroup_min: Option<u32>,
    pub hostgroup_max: Option<u32>,
    pub unimplemented: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    TcpConnect,
    TcpSyn,
    Udp,
    Other(char),
}

impl ScanPlan {
    /// Parallel slots for TCP connect, UDP, ping, and target expansion (`buffer_unordered` / semaphores).
    ///
    /// When `--min-rate` is set and `--max-parallelism` was **not** used, raises the floor toward
    /// `min(min_rate, 65_535)` so Nmap-style minimum probe throughput is not capped by default `-T`
    /// limits alone.
    pub fn effective_probe_concurrency(&self) -> usize {
        let base = self.concurrency.max(1);
        let Some(mr) = self.min_probe_rate else {
            return base;
        };
        if self.max_parallelism_explicit {
            return base;
        }
        let floor = (mr as usize).clamp(1, 65_535);
        base.max(floor)
    }

    pub fn from_args(args: &Args) -> Result<Self> {
        let mut unimplemented: Vec<String> = Vec::new();

        if args.aggressive {
            unimplemented.push(
                "-A: full Nmap OS fingerprint DB and full version DB not embedded; TTL/heuristic OS + banner scripts run instead where applicable".into(),
            );
        }

        if args.version_scan {
            unimplemented.push(
                "-sV: service/version DB not embedded; use nmap for full version detection".into(),
            );
        }

        if args.ping_only && args.list_scan {
            bail!("-sn and -sL together are ambiguous");
        }

        if args.ip_proto_scan {
            bail!("-sO IP protocol scan is not implemented");
        }
        if args.idle_scan.is_some() {
            bail!("-sI idle scan is not implemented");
        }
        if args.ftp_bounce.is_some() {
            bail!("-b FTP bounce scan is not implemented");
        }

        if let Some(n) = args.max_rate {
            if n == 0 {
                bail!("--max-rate must be > 0");
            }
        }
        if let Some(n) = args.min_rate {
            if n == 0 {
                bail!("--min-rate must be > 0");
            }
        }
        if let (Some(mx), Some(mn)) = (args.max_rate, args.min_rate) {
            if mx < mn {
                bail!("--max-rate must be >= --min-rate (both are probe starts per second)");
            }
        }

        if let (Some(lo), Some(hi)) = (args.min_hostgroup, args.max_hostgroup) {
            if hi < lo {
                bail!("--max-hostgroup must be >= --min-hostgroup");
            }
        }

        // --- Scan kind ---
        let mut scan_kind = ScanKind::TcpConnect;
        if let Some(ch) = args.scan_type {
            match ch {
                'T' | 't' => scan_kind = ScanKind::TcpConnect,
                'S' | 's' => scan_kind = ScanKind::TcpSyn,
                'U' | 'u' => scan_kind = ScanKind::Udp,
                'N' | 'F' | 'X' | 'A' | 'W' | 'M' | 'Y' | 'Z' | 'O' | 'I' => {
                    scan_kind = ScanKind::Other(ch);
                    unimplemented.push(format!(
                        "scan type -s{ch} is not implemented in nmaprs (use nmap for exotic TCP flags)"
                    ));
                }
                _ => bail!("unknown --scan-type {ch}"),
            }
        }

        // --- Ports (skipped for host-discovery-only) ---
        let mut ports: Vec<u16> = if args.ping_only {
            if args.ports.is_some() {
                warn!("-sn ignores explicit -p port list");
            }
            vec![]
        } else if let Some(p) = &args.ports {
            parse_port_spec(p).map_err(|e| anyhow!(e))?
        } else if args.fast {
            fast_tcp_ports()
        } else if let Some(n) = args.top_ports {
            top_ports(n as usize)
        } else if let Some(r) = args.port_ratio {
            if r <= 0.0 || r > 1.0 {
                bail!("--port-ratio must be in (0,1]");
            }
            let n = ((top_ports_len() as f64) * r).round() as usize;
            top_ports(n.max(1))
        } else {
            default_tcp_ports()
        };

        if !args.ping_only {
            if let Some(ex) = &args.exclude_ports {
                let banned = parse_exclude_ports(ex).map_err(|e| anyhow!(e))?;
                ports.retain(|p| !banned.contains(p));
            }

            if ports.is_empty() {
                bail!("no ports to scan after exclusions");
            }

            if !args.sequential_ports && !args.list_scan {
                ports.shuffle(&mut rand::thread_rng());
            }
        }

        // --- Timing / concurrency ---
        let timing = args.timing.unwrap_or(3);
        let (base_conc, base_timeout_ms) = match timing {
            0 => (32, 10_000u64),
            1 => (64, 5_000),
            2 => (128, 2_000),
            3 => (256, 1_500),
            4 => (512, 750),
            5 => (1024, 300),
            _ => bail!("timing template must be 0..=5"),
        };

        let mut concurrency = base_conc as usize;
        let max_parallelism_explicit = args.max_parallelism.is_some();
        if let Some(n) = args.max_parallelism {
            concurrency = n.min(65_535) as usize;
        }
        if let Some(n) = args.min_parallelism {
            concurrency = concurrency.max(n as usize);
        }

        let mut connect_timeout = Duration::from_millis(base_timeout_ms);
        if let Some(s) = &args.max_rtt_timeout {
            connect_timeout = parse_duration(s).with_context(|| "max-rtt-timeout")?;
        } else if let Some(s) = &args.initial_rtt_timeout {
            connect_timeout = parse_duration(s).with_context(|| "initial-rtt-timeout")?;
        }

        if let Some(s) = &args.min_rtt_timeout {
            let min = parse_duration(s).with_context(|| "min-rtt-timeout")?;
            connect_timeout = connect_timeout.max(min);
        }

        let scan_delay = if let Some(s) = &args.scan_delay {
            Some(parse_duration(s).with_context(|| "scan-delay")?)
        } else {
            None
        };
        let max_scan_delay = if let Some(s) = &args.max_scan_delay {
            Some(parse_duration(s).with_context(|| "max-scan-delay")?)
        } else {
            None
        };
        if let (Some(lo), Some(hi)) = (scan_delay, max_scan_delay) {
            if hi < lo {
                bail!("--max-scan-delay must be >= --scan-delay");
            }
        }

        let host_timeout = if let Some(s) = &args.host_timeout {
            Some(parse_duration(s).with_context(|| "host-timeout")?)
        } else {
            None
        };

        let mut output_normal = args.output_normal.clone();
        let mut output_grepable = args.output_grepable.clone();
        let mut output_xml = args.output_xml.clone();
        if let Some(base) = &args.output_all {
            output_normal = Some(base.with_extension("nmap"));
            output_grepable = Some(base.with_extension("gnmap"));
            output_xml = Some(base.with_extension("xml"));
        }

        let plan = ScanPlan {
            ports,
            concurrency,
            max_parallelism_explicit,
            connect_timeout,
            no_ping: args.no_ping,
            scan_kind,
            verbosity: args.verbosity,
            debug: args.debug,
            sequential_ports: args.sequential_ports,
            list_scan: args.list_scan,
            ping_only: args.ping_only,
            output_normal,
            output_grepable,
            output_xml,
            output_all_base: args.output_all.clone(),
            append_output: args.append_output,
            show_reason: args.reason,
            open_only: args.open_only,
            randomize_ports: !args.sequential_ports,
            aggressive: args.aggressive,
            version_scan_requested: args.version_scan || args.aggressive,
            os_detect_requested: args.os_detect || args.aggressive,
            script_requested: args.script_default || args.script.is_some() || args.aggressive,
            traceroute: args.traceroute,
            resume_path: args.resume.clone(),
            max_probe_rate: args.max_rate,
            min_probe_rate: args.min_rate,
            host_timeout,
            connect_retries: args.max_retries.unwrap_or(0),
            scan_delay,
            max_scan_delay,
            hostgroup_min: args.min_hostgroup,
            hostgroup_max: args.max_hostgroup,
            unimplemented,
        };

        for msg in &plan.unimplemented {
            warn!("{msg}");
        }

        if let Some(mr) = plan.min_probe_rate {
            let base = plan.concurrency.max(1);
            if plan.max_parallelism_explicit {
                if (mr as usize) > base {
                    warn!(
                        "--min-rate ({mr}) is higher than --max-parallelism ({base}); min-rate may not be achievable"
                    );
                }
            } else {
                let eff = plan.effective_probe_concurrency();
                if eff > base {
                    info!(
                        "--min-rate ({mr}) raised probe parallelism from {base} to {eff} (omit --max-parallelism to allow this automatic floor)"
                    );
                }
            }
        }

        Ok(plan)
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        let v: u64 = ms.trim().parse().context("parse ms")?;
        return Ok(Duration::from_millis(v));
    }
    if let Some(sec) = s.strip_suffix('s') {
        let v: f64 = sec.trim().parse().context("parse seconds")?;
        return Ok(Duration::from_secs_f64(v));
    }
    if let Some(m) = s.strip_suffix('m') {
        let v: f64 = m.trim().parse().context("parse minutes")?;
        return Ok(Duration::from_secs_f64(v * 60.0));
    }
    if let Some(h) = s.strip_suffix('h') {
        let v: f64 = h.trim().parse().context("parse hours")?;
        return Ok(Duration::from_secs_f64(v * 3600.0));
    }
    let v: f64 = s.parse().context("parse duration")?;
    Ok(Duration::from_secs_f64(v))
}

#[cfg(test)]
mod rate_validation_tests {
    use clap::Parser;

    use crate::cli::Args;

    use super::ScanPlan;

    #[test]
    fn max_rate_below_min_rate_errors() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--max-rate",
            "50",
            "--min-rate",
            "100",
            "127.0.0.1",
        ])
        .expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        assert!(
            err.to_string().contains("max-rate") && err.to_string().contains("min-rate"),
            "{err}"
        );
    }

    #[test]
    fn min_rate_raises_effective_probe_concurrency_without_explicit_cap() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--min-rate",
            "1000",
            "-p",
            "80",
            "127.0.0.1",
        ])
        .expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.concurrency, 256);
        assert!(!plan.max_parallelism_explicit);
        assert_eq!(plan.effective_probe_concurrency(), 1000);
    }

    #[test]
    fn effective_probe_concurrency_respects_explicit_max_parallelism() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--min-rate",
            "1000",
            "--max-parallelism",
            "64",
            "-p",
            "80",
            "127.0.0.1",
        ])
        .expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.concurrency, 64);
        assert!(plan.max_parallelism_explicit);
        assert_eq!(plan.effective_probe_concurrency(), 64);
    }

    #[test]
    fn max_hostgroup_below_min_errors() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--min-hostgroup",
            "10",
            "--max-hostgroup",
            "5",
            "-p",
            "80",
            "127.0.0.1",
        ])
        .expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("max-hostgroup") && s.contains("min-hostgroup"),
            "{err}"
        );
    }

    #[test]
    fn hostgroup_flags_round_trip() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--min-hostgroup",
            "8",
            "--max-hostgroup",
            "32",
            "-p",
            "443",
            "127.0.0.1",
        ])
        .expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.hostgroup_min, Some(8));
        assert_eq!(plan.hostgroup_max, Some(32));
    }
}

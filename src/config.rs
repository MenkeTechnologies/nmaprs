//! Resolve [`crate::cli::Args`] into an executable [`ScanPlan`].

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rand::seq::SliceRandom;
use tracing::{info, warn};

use crate::cli::Args;
use crate::ports::{
    default_tcp_ports, fast_ip_protocols_nmap, fast_tcp_ports, parse_exclude_ports,
    parse_port_spec, top_ports, top_ports_len,
};

/// Parsed `-b user:pass@host:port` FTP relay (classic `PORT` is IPv4-only on the target side).
#[derive(Debug, Clone)]
pub struct FtpBounceTarget {
    pub user: String,
    pub pass: String,
    pub server: SocketAddr,
}

/// Parse Nmap-style `username:password@host:port` (password may be empty: `user:@host:21`).
pub fn parse_ftp_bounce(spec: &str) -> Result<FtpBounceTarget> {
    let spec = spec.trim();
    let at = spec
        .find('@')
        .ok_or_else(|| anyhow!("FTP bounce (-b): expected user:pass@host:port"))?;
    let (user_part, host_part) = spec.split_at(at);
    let host_part = host_part.trim_start_matches('@');
    if host_part.is_empty() {
        bail!("FTP bounce (-b): missing host after @");
    }
    let (user, pass) = match user_part.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (user_part.to_string(), String::new()),
    };
    let (host, port) = parse_host_colon_port(host_part, 21)?;
    let server = (host.as_str(), port)
        .to_socket_addrs()
        .with_context(|| format!("FTP bounce: resolve {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("FTP bounce: no addresses for {host}:{port}"))?;
    Ok(FtpBounceTarget { user, pass, server })
}

/// `host`, `host:port`, or `[ipv6]:port` — `default_port` when omitted.
fn parse_host_colon_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let inner = &s[1..end];
            let rest = &s[end + 1..];
            let port = if let Some(p) = rest.strip_prefix(':') {
                p.parse().with_context(|| "bad port after ]")?
            } else {
                default_port
            };
            return Ok((format!("[{inner}]"), port));
        }
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Ok((host.to_string(), port.parse().with_context(|| "port")?));
        }
    }
    Ok((s.to_string(), default_port))
}

/// `-sI zombie[:probeport]` — IPv4 zombie only; `probeport` should be **closed** on the zombie (default **65535**).
#[derive(Debug, Clone)]
pub struct IdleScanTarget {
    pub zombie: Ipv4Addr,
    pub probe_port: u16,
}

/// Resolve zombie host to IPv4 for idle scan.
pub fn parse_idle_scan(spec: &str) -> Result<IdleScanTarget> {
    let (host, probe_port) = parse_host_colon_port(spec.trim(), 65535)?;
    let server = format!("{}:{}", host, probe_port);
    let zombie = server
        .to_socket_addrs()
        .with_context(|| format!("idle (-sI): resolve {host}"))?
        .find_map(|a| match a {
            SocketAddr::V4(v) => Some(*v.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("idle (-sI): no IPv4 address for {host}"))?;
    Ok(IdleScanTarget { zombie, probe_port })
}

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
    /// TCP flag byte from `--scanflags` (only with raw `-s*` TCP scans).
    pub tcp_scan_flags: Option<u8>,
    pub verbosity: u8,
    pub debug: u8,
    pub sequential_ports: bool,
    pub list_scan: bool,
    pub ping_only: bool,
    pub output_normal: Option<PathBuf>,
    pub output_grepable: Option<PathBuf>,
    pub output_xml: Option<PathBuf>,
    /// Script-kiddie (`-oS`) — same content as normal output, transformed (mirrors `-oN` style lines).
    pub output_script_kiddie: Option<PathBuf>,
    pub output_all_base: Option<PathBuf>,
    /// Nmap data directory (`--datadir`); defaults to `./data` when resolving `nmap-service-probes` / `nmap-os-db`.
    pub datadir: Option<PathBuf>,
    pub append_output: bool,
    pub show_reason: bool,
    pub open_only: bool,
    pub randomize_ports: bool,
    pub aggressive: bool,
    pub version_scan_requested: bool,
    /// Nmap `--version-intensity` (0–9), after `--version-light` / `--version-all` overrides.
    pub version_intensity: u8,
    pub os_detect_requested: bool,
    pub script_requested: bool,
    /// `--traceroute` or implied by **`-A`** (Nmap aggressive scan).
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
    /// `-b user:pass@host:port` — FTP bounce TCP scan (IPv4 targets only).
    pub ftp_bounce: Option<FtpBounceTarget>,
    /// `-sI zombie[:probeport]` — idle (IP ID) scan (IPv4 only).
    pub idle_scan: Option<IdleScanTarget>,
    /// Nmap `--resolve-all` (see [`crate::target::ExpandOpts::resolve_all`]).
    pub resolve_all: bool,
    /// Nmap `--randomize-hosts` / `--rH`.
    pub randomize_hosts: bool,
    /// Nmap `--unique` — deduplicate target list.
    pub unique: bool,
    /// Nmap `--max-os-tries` (1–50; probe rounds — full TCP/IP OS scan not implemented).
    pub max_os_tries: u8,
    pub osscan_limit: bool,
    pub osscan_guess: bool,
    pub defeat_rst_ratelimit: bool,
    pub defeat_icmp_ratelimit: bool,
    pub discovery_ignore_rst: bool,
    pub disable_arp_ping: bool,
    pub stats_every: Option<Duration>,
    pub script_timeout: Option<Duration>,
    /// Override path for `nmap-service-probes` (Nmap `--versiondb`).
    pub versiondb: Option<PathBuf>,
    /// Override path for `nmap-services` (reserved; custom top-ports list not yet loaded).
    pub servicedb: Option<PathBuf>,
    /// Nmap `-oM` machine-parseable output.
    pub output_machine: Option<PathBuf>,
    /// Nmap `-oH` hex output (placeholder file when set).
    pub output_hex: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    TcpConnect,
    /// IPv4 IP protocol scan (`-sO` / `--sO`).
    IpProto,
    TcpSyn,
    TcpNull,
    TcpFin,
    TcpXmas,
    TcpAck,
    TcpWindow,
    TcpMaimon,
    /// SCTP INIT / COOKIE-ECHO (`-sY` / `-sZ`) — IPv4 raw only in nmaprs.
    SctpInit,
    SctpCookieEcho,
    /// TCP idle scan (`-sI zombie`) — spoofed SYN, IP-ID delta on zombie (IPv4 only).
    Idle,
    Udp,
}

impl ScanKind {
    /// Raw half-open TCP scan (`-sS` / `-sN` / `-sF` / `-sX` / `-sA` / `-sW` / `-sM`), if applicable.
    pub fn tcp_port_raw_kind(self) -> Option<crate::syn::TcpPortScanKind> {
        match self {
            ScanKind::TcpSyn => Some(crate::syn::TcpPortScanKind::Syn),
            ScanKind::TcpNull => Some(crate::syn::TcpPortScanKind::Null),
            ScanKind::TcpFin => Some(crate::syn::TcpPortScanKind::Fin),
            ScanKind::TcpXmas => Some(crate::syn::TcpPortScanKind::Xmas),
            ScanKind::TcpAck => Some(crate::syn::TcpPortScanKind::Ack),
            ScanKind::TcpWindow => Some(crate::syn::TcpPortScanKind::Window),
            ScanKind::TcpMaimon => Some(crate::syn::TcpPortScanKind::Maimon),
            _ => None,
        }
    }
}

impl ScanPlan {
    /// Resolve `name` (e.g. `nmap-service-probes`) under `--datadir` or `./data`.
    pub fn data_file(&self, name: &str) -> PathBuf {
        self.datadir
            .clone()
            .unwrap_or_else(|| PathBuf::from("data"))
            .join(name)
    }

    /// Path to `nmap-service-probes` (`--versiondb` or `--datadir`).
    pub fn service_probes_path(&self) -> PathBuf {
        self.versiondb
            .clone()
            .unwrap_or_else(|| self.data_file("nmap-service-probes"))
    }

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
        let unimplemented: Vec<String> = Vec::new();

        if args.privileged && args.unprivileged {
            bail!("--privileged and --unprivileged are mutually exclusive");
        }

        if args.ping_only && args.list_scan {
            bail!("-sn and -sL together are ambiguous");
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

        if let (Some(smax), Some(smin)) = (&args.max_rtt_timeout, &args.min_rtt_timeout) {
            let max_d = parse_duration(smax).with_context(|| "max-rtt-timeout")?;
            let min_d = parse_duration(smin).with_context(|| "min-rtt-timeout")?;
            if max_d < min_d {
                bail!("--max-rtt-timeout must be >= --min-rtt-timeout");
            }
        }

        // --- Scan kind ---
        let mut scan_kind = ScanKind::TcpConnect;
        if let Some(ch) = args.scan_type {
            match ch {
                'T' | 't' => scan_kind = ScanKind::TcpConnect,
                'S' | 's' => scan_kind = ScanKind::TcpSyn,
                'U' | 'u' => scan_kind = ScanKind::Udp,
                'N' | 'n' => scan_kind = ScanKind::TcpNull,
                'F' | 'f' => scan_kind = ScanKind::TcpFin,
                'X' | 'x' => scan_kind = ScanKind::TcpXmas,
                'A' | 'a' => scan_kind = ScanKind::TcpAck,
                'W' | 'w' => scan_kind = ScanKind::TcpWindow,
                'M' | 'm' => scan_kind = ScanKind::TcpMaimon,
                'Y' | 'y' => scan_kind = ScanKind::SctpInit,
                'Z' | 'z' => scan_kind = ScanKind::SctpCookieEcho,
                'O' | 'o' => {
                    bail!(
                        "IP protocol scan uses `-sO` / `--sO`, not `--scan-type O` (that flag selects TCP/UDP/SCTP/raw-TCP scan letters)"
                    );
                }
                'I' | 'i' => {
                    bail!(
                        "Idle scan uses `-sI <zombie[:probeport]>` / `--sI`, not `--scan-type I`"
                    );
                }
                _ => bail!("unknown --scan-type {ch}"),
            }
        }

        if args.ip_proto_scan {
            if args.scan_type.is_some() {
                bail!("-sO (--sO) cannot be combined with --scan-type or other -sS/-sT/-sU scan flags");
            }
            scan_kind = ScanKind::IpProto;
        }

        let mut idle_scan = None;
        if let Some(ref s) = args.idle_scan {
            if args.scan_type.is_some() {
                bail!("-sI idle scan cannot be combined with --scan-type");
            }
            if args.ip_proto_scan {
                bail!("-sI cannot be combined with -sO");
            }
            if args.ftp_bounce.is_some() {
                bail!("-sI cannot be combined with -b");
            }
            idle_scan = Some(parse_idle_scan(s)?);
            scan_kind = ScanKind::Idle;
        }

        let mut ftp_bounce = None;
        if let Some(ref s) = args.ftp_bounce {
            if args.idle_scan.is_some() {
                bail!("-b cannot be combined with -sI");
            }
            if args.ip_proto_scan {
                bail!("-b (FTP bounce) cannot be combined with -sO");
            }
            if !matches!(scan_kind, ScanKind::TcpConnect) {
                bail!(
                    "FTP bounce (-b) only works with TCP connect (-sT); omit -sS/-sU and other scan types"
                );
            }
            ftp_bounce = Some(parse_ftp_bounce(s)?);
        }

        let mut tcp_scan_flags = None;
        if let Some(ref s) = args.scanflags {
            tcp_scan_flags = Some(crate::scanflags::parse_scanflags(s)?);
        }
        if tcp_scan_flags.is_some() && scan_kind.tcp_port_raw_kind().is_none() {
            warn!(
                "--scanflags requires a raw TCP scan type (-sS, -sN, -sF, -sX, -sM, -sA, -sW); ignoring"
            );
            tcp_scan_flags = None;
        }

        if args.unprivileged {
            if matches!(
                scan_kind,
                ScanKind::IpProto | ScanKind::Idle | ScanKind::SctpInit | ScanKind::SctpCookieEcho
            ) {
                bail!(
                    "--unprivileged: this scan type requires raw sockets (omit or use TCP connect)"
                );
            }
            if scan_kind.tcp_port_raw_kind().is_some() {
                warn!("--unprivileged: using TCP connect scan instead of raw half-open");
                scan_kind = ScanKind::TcpConnect;
            }
        }

        // --- Ports (skipped for host-discovery-only) ---
        let mut ports: Vec<u16> = if args.ping_only {
            if args.ports.is_some() {
                warn!("-sn ignores explicit -p port list");
            }
            vec![]
        } else if args.ip_proto_scan {
            if args.top_ports.is_some() && args.ports.is_none() {
                warn!("-sO: --top-ports is a TCP list in nmap; omit -p to scan all IP protocols 0..255");
            }
            if args.port_ratio.is_some() && args.ports.is_none() {
                warn!("-sO: --port-ratio applies to TCP in nmap; omit -p to scan all IP protocols 0..255");
            }
            let v = if let Some(p) = &args.ports {
                parse_port_spec(p).map_err(|e| anyhow!(e))?
            } else if args.fast {
                fast_ip_protocols_nmap()
            } else {
                (0u16..=255).collect()
            };
            for &p in &v {
                if p > 255 {
                    bail!("IP protocol scan (-sO): protocol numbers must be in 0..=255 (got {p})");
                }
            }
            v
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
                if !args.allports {
                    let banned = parse_exclude_ports(ex).map_err(|e| anyhow!(e))?;
                    ports.retain(|p| !banned.contains(p));
                }
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

        let max_os_tries = args.max_os_tries.unwrap_or(5);
        if !(1..=50).contains(&max_os_tries) {
            bail!("--max-os-tries must be between 1 and 50");
        }

        let stats_every = if let Some(s) = &args.stats_every {
            Some(parse_duration(s).with_context(|| "stats-every")?)
        } else {
            None
        };

        let script_timeout = if let Some(s) = &args.script_timeout {
            Some(parse_duration(s).with_context(|| "script-timeout")?)
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

        let output_machine = args.output_machine.clone();
        let output_hex = args.output_hex.clone();

        let mut version_intensity = args.version_intensity.unwrap_or(7).min(9);
        if args.version_light {
            version_intensity = version_intensity.min(2);
        }
        if args.version_all {
            version_intensity = 9;
        }

        let plan = ScanPlan {
            ports,
            concurrency,
            max_parallelism_explicit,
            connect_timeout,
            no_ping: args.no_ping,
            scan_kind,
            tcp_scan_flags,
            verbosity: args.effective_verbosity(),
            debug: args.effective_debug(),
            sequential_ports: args.sequential_ports,
            list_scan: args.list_scan,
            ping_only: args.ping_only,
            output_normal,
            output_grepable,
            output_xml,
            output_script_kiddie: args.output_script_kiddie.clone(),
            output_all_base: args.output_all.clone(),
            datadir: args.datadir.clone(),
            append_output: args.append_output,
            show_reason: args.reason,
            open_only: args.open_only,
            randomize_ports: !args.sequential_ports,
            aggressive: args.aggressive,
            version_scan_requested: args.version_scan || args.aggressive,
            version_intensity,
            os_detect_requested: args.os_detect || args.aggressive,
            script_requested: args.script_default || args.script.is_some() || args.aggressive,
            traceroute: args.traceroute || args.aggressive,
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
            ftp_bounce,
            idle_scan,
            resolve_all: args.resolve_all,
            randomize_hosts: args.effective_randomize_hosts(),
            unique: args.unique,
            max_os_tries,
            osscan_limit: args.osscan_limit,
            osscan_guess: args.effective_osscan_guess(),
            defeat_rst_ratelimit: args.defeat_rst_ratelimit || args.open_only,
            defeat_icmp_ratelimit: args.defeat_icmp_ratelimit,
            discovery_ignore_rst: args.discovery_ignore_rst,
            disable_arp_ping: args.disable_arp_ping,
            stats_every,
            script_timeout,
            versiondb: args.versiondb.clone(),
            servicedb: args.servicedb.clone(),
            output_machine,
            output_hex,
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

    use super::{parse_ftp_bounce, parse_idle_scan, ScanPlan};

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
    fn privileged_and_unprivileged_conflict() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--privileged",
            "--unprivileged",
            "-p",
            "80",
            "127.0.0.1",
        ])
        .expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn min_rate_raises_effective_probe_concurrency_without_explicit_cap() {
        let args = Args::try_parse_from(["nmaprs", "--min-rate", "1000", "-p", "80", "127.0.0.1"])
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

    #[test]
    fn aggressive_enables_os_version_scripts_traceroute() {
        let args = Args::try_parse_from(["nmaprs", "-A", "-p", "80", "127.0.0.1"]).expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert!(plan.aggressive);
        assert!(plan.os_detect_requested);
        assert!(plan.version_scan_requested);
        assert!(plan.script_requested);
        assert!(plan.traceroute);
    }

    #[test]
    fn dash_o_enables_os_detection_only() {
        let args = Args::try_parse_from(["nmaprs", "-O", "-p", "22", "127.0.0.1"]).expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert!(plan.os_detect_requested);
        assert!(!plan.version_scan_requested);
        assert!(!plan.traceroute);
        assert!(!plan.aggressive);
    }

    #[test]
    fn max_rtt_below_min_rtt_errors() {
        let args = Args::try_parse_from([
            "nmaprs",
            "--max-rtt-timeout",
            "50ms",
            "--min-rtt-timeout",
            "200ms",
            "-p",
            "80",
            "127.0.0.1",
        ])
        .expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("max-rtt-timeout") && s.contains("min-rtt-timeout"),
            "{s}"
        );
    }

    #[test]
    fn scan_type_raw_tcp_scan_kinds_round_trip() {
        use crate::syn::TcpPortScanKind;

        use super::ScanKind;
        let cases = [
            ("--scan-type", "N", ScanKind::TcpNull, TcpPortScanKind::Null),
            ("--scan-type", "F", ScanKind::TcpFin, TcpPortScanKind::Fin),
            ("--scan-type", "X", ScanKind::TcpXmas, TcpPortScanKind::Xmas),
            ("--scan-type", "A", ScanKind::TcpAck, TcpPortScanKind::Ack),
            (
                "--scan-type",
                "W",
                ScanKind::TcpWindow,
                TcpPortScanKind::Window,
            ),
            (
                "--scan-type",
                "M",
                ScanKind::TcpMaimon,
                TcpPortScanKind::Maimon,
            ),
        ];
        for (opt, ch, kind, raw) in cases {
            let args =
                Args::try_parse_from(["nmaprs", opt, ch, "-p", "22", "127.0.0.1"]).expect("parse");
            let plan = ScanPlan::from_args(&args).expect("plan");
            assert_eq!(plan.scan_kind, kind, "{opt} {ch}");
            assert_eq!(plan.scan_kind.tcp_port_raw_kind(), Some(raw));
        }
    }

    #[test]
    fn ip_proto_scan_defaults_all_protocols() {
        use super::ScanKind;

        let args = Args::try_parse_from(["nmaprs", "--sO", "127.0.0.1"]).expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.scan_kind, ScanKind::IpProto);
        assert_eq!(plan.ports.len(), 256);
        let mut seen = [false; 256];
        for &p in &plan.ports {
            seen[p as usize] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }

    #[test]
    fn ip_proto_scan_fast_matches_embedded_nmap_protocols_list() {
        use super::ScanKind;

        let args = Args::try_parse_from(["nmaprs", "--sO", "-F", "127.0.0.1"]).expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.scan_kind, ScanKind::IpProto);
        let mut got = plan.ports.clone();
        let mut want = crate::ports::fast_ip_protocols_nmap();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn parses_ftp_bounce_target() {
        let t = parse_ftp_bounce("anonymous:pw@127.0.0.1:2121").expect("parse");
        assert_eq!(t.user, "anonymous");
        assert_eq!(t.pass, "pw");
        assert_eq!(t.server.port(), 2121);
    }

    #[test]
    fn parses_ftp_bounce_empty_password() {
        let t = parse_ftp_bounce("user:@example.com:21").expect("parse");
        assert_eq!(t.user, "user");
        assert_eq!(t.pass, "");
    }

    #[test]
    fn parses_idle_scan_target() {
        use std::net::Ipv4Addr;

        let t = parse_idle_scan("192.0.2.1").expect("parse");
        assert_eq!(t.zombie, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(t.probe_port, 65535);
        let t2 = parse_idle_scan("192.0.2.1:1234").expect("parse");
        assert_eq!(t2.zombie, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(t2.probe_port, 1234);
    }

    #[test]
    fn idle_scan_sets_kind_and_probe_port() {
        use super::ScanKind;

        let args =
            Args::try_parse_from(["nmaprs", "--sI", "192.0.2.1:443", "-p", "80", "10.0.0.1"])
                .expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.scan_kind, ScanKind::Idle);
        assert_eq!(plan.idle_scan.expect("idle").probe_port, 443);
    }

    #[test]
    fn scan_type_sctp_y_and_z() {
        use super::ScanKind;

        let y = Args::try_parse_from(["nmaprs", "--scan-type", "Y", "-p", "38412", "127.0.0.1"])
            .expect("parse");
        assert_eq!(
            ScanPlan::from_args(&y).expect("plan").scan_kind,
            ScanKind::SctpInit
        );
        let z = Args::try_parse_from(["nmaprs", "--scan-type", "z", "-p", "38412", "127.0.0.1"])
            .expect("parse");
        assert_eq!(
            ScanPlan::from_args(&z).expect("plan").scan_kind,
            ScanKind::SctpCookieEcho
        );
    }

    #[test]
    fn scan_type_letter_o_points_to_so_flag() {
        let args =
            Args::try_parse_from(["nmaprs", "--scan-type", "O", "127.0.0.1"]).expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("sO") || s.contains("-sO"), "{s}");
    }

    #[test]
    fn scan_type_letter_i_points_to_si_flag() {
        let args =
            Args::try_parse_from(["nmaprs", "--scan-type", "i", "127.0.0.1"]).expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("sI") || s.contains("-sI"), "{s}");
    }

    #[test]
    fn ip_proto_with_scan_type_errors() {
        let args =
            Args::try_parse_from(["nmaprs", "--sO", "--scan-type", "S", "-p", "1", "127.0.0.1"])
                .expect("parse");
        let err = ScanPlan::from_args(&args).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("sO") || s.contains("scan-type"), "{s}");
    }

    #[test]
    fn scanflags_sets_tcp_scan_flags_with_raw_syn() {
        use pnet::packet::tcp::TcpFlags;

        use super::ScanKind;
        let args = Args::try_parse_from([
            "nmaprs",
            "--scan-type",
            "S",
            "--scanflags",
            "FIN|ACK",
            "-p",
            "22",
            "127.0.0.1",
        ])
        .expect("parse");
        let plan = ScanPlan::from_args(&args).expect("plan");
        assert_eq!(plan.scan_kind, ScanKind::TcpSyn);
        assert_eq!(plan.tcp_scan_flags, Some(TcpFlags::FIN | TcpFlags::ACK));
    }
}

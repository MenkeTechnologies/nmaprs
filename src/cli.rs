//! nmap-compatible CLI surface. Parsing accepts the union of `nmap --help` and Nmap’s `long_options`
//! table (`nmap.cc`); behavior parity is documented in README.

use clap::CommandFactory;
use clap::FromArgMatches;
use clap::Parser;
use std::path::PathBuf;

/// Parallel network scanner — nmap-compatible CLI (see README for parity).
#[derive(Parser, Debug)]
#[command(
    name = "nmaprs",
    version,
    author = "MenkeTechnologies",
    about = "NMAPRS // GRID SCANNER — rust-native parallel port probe",
    long_about = "TCP connect, UDP probes, ICMP ping scan (-sn), IPv6 (-6), -iL/-iR, resume, SYN (-sS) via raw IPv4 (privileged), `-A` (like Nmap: -O, -sV, default scripts, --traceroute), `-O` / `-sV` with optional `nmap-os-db` / `nmap-service-probes` under `--datadir`, and built-in scripts (not full Nmap NSE/Lua).",
    disable_help_flag = true,
    disable_version_flag = true,
    next_line_help = false
)]
/// `Args` — see fields for layout.
pub struct Args {
    /// Print help (-h / --help).
    #[arg(short = 'h', long, global = true, action = clap::ArgAction::Help)]
    pub help: Option<bool>,

    /// Print version (-V).
    #[arg(short = 'V', long = "version", action = clap::ArgAction::Version)]
    pub version_req: Option<bool>,

    // --- Target specification ---
    /// `input_list` field.
    #[arg(long = "iL", value_name = "FILE")]
    pub input_list: Option<PathBuf>,
    /// `random_targets` field.
    #[arg(long = "iR", value_name = "NUM")]
    pub random_targets: Option<u64>,
    /// `exclude` field.
    #[arg(long = "exclude", value_name = "TARGETS")]
    pub exclude: Option<String>,
    /// `exclude_file` field.
    #[arg(long = "excludefile", value_name = "FILE")]
    pub exclude_file: Option<PathBuf>,

    // --- Host discovery ---
    /// `list_scan` field.
    #[arg(long = "sL")]
    pub list_scan: bool,
    /// `ping_only` field.
    #[arg(long = "sn")]
    pub ping_only: bool,
    /// `no_ping` field.
    #[arg(long = "no-ping")]
    pub no_ping: bool,
    /// `ping_syn` field.
    #[arg(long = "ping-S", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_syn: Option<Option<String>>,
    /// `ping_ack` field.
    #[arg(long = "ping-A", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_ack: Option<Option<String>>,
    /// `ping_udp` field.
    #[arg(long = "ping-U", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_udp: Option<Option<String>>,
    /// `ping_sctp` field.
    #[arg(long = "ping-Y", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_sctp: Option<Option<String>>,
    /// `ping_echo` field.
    #[arg(long = "ping-E", action = clap::ArgAction::SetTrue)]
    pub ping_echo: bool,
    /// `ping_timestamp` field.
    #[arg(long = "ping-P", action = clap::ArgAction::SetTrue)]
    pub ping_timestamp: bool,
    /// `ping_mask` field.
    #[arg(long = "ping-M", action = clap::ArgAction::SetTrue)]
    pub ping_mask: bool,
    /// `ping_ip_proto` field.
    #[arg(long = "ping-ip-proto", num_args = 0..=1, value_name = "PROTOS")]
    pub ping_ip_proto: Option<Option<String>>,
    /// `no_dns` field.
    #[arg(short = 'n')]
    pub no_dns: bool,
    /// `always_resolve` field.
    #[arg(short = 'R')]
    pub always_resolve: bool,
    /// `dns_servers` field.
    #[arg(long = "dns-servers", value_name = "SERVERS")]
    pub dns_servers: Option<String>,
    /// `system_dns` field.
    #[arg(long = "system-dns")]
    pub system_dns: bool,
    /// `traceroute` field.
    #[arg(long = "traceroute")]
    pub traceroute: bool,

    // --- Scan techniques ---
    /// `scan_type` field.
    #[arg(long = "scan-type", value_name = "CHAR")]
    pub scan_type: Vec<char>,
    /// `scanflags` field.
    #[arg(long = "scanflags", value_name = "FLAGS")]
    pub scanflags: Option<String>,
    /// `idle_scan` field.
    #[arg(long = "sI", value_name = "ZOMBIE")]
    pub idle_scan: Option<String>,
    /// `ip_proto_scan` field.
    #[arg(long = "sO")]
    pub ip_proto_scan: bool,
    /// `ftp_bounce` field.
    #[arg(short = 'b', value_name = "FTP")]
    pub ftp_bounce: Option<String>,

    // --- Version / script / OS ---
    /// `version_scan` field.
    #[arg(long = "version-scan")]
    pub version_scan: bool,
    /// `script_default` field.
    #[arg(long = "script-default")]
    pub script_default: bool,
    /// `script` field.
    #[arg(long = "script", value_name = "EXPR")]
    pub script: Option<String>,
    /// `script_args` field.
    #[arg(long = "script-args", value_name = "ARGS")]
    pub script_args: Option<String>,
    /// `script_args_file` field.
    #[arg(long = "script-args-file", value_name = "FILE")]
    pub script_args_file: Option<PathBuf>,
    /// `script_trace` field.
    #[arg(long = "script-trace")]
    pub script_trace: bool,
    /// `script_updatedb` field.
    #[arg(long = "script-updatedb")]
    pub script_updatedb: bool,
    /// `script_help` field.
    #[arg(long = "script-help", value_name = "EXPR")]
    pub script_help: Option<String>,
    /// `version_intensity` field.
    #[arg(long = "version-intensity", value_name = "0-9")]
    pub version_intensity: Option<u8>,
    /// `version_light` field.
    #[arg(long = "version-light")]
    pub version_light: bool,
    /// `version_all` field.
    #[arg(long = "version-all")]
    pub version_all: bool,
    /// `version_trace` field.
    #[arg(long = "version-trace")]
    pub version_trace: bool,
    /// `os_detect` field.
    #[arg(short = 'O')]
    pub os_detect: bool,
    /// `osscan_limit` field.
    #[arg(long = "osscan-limit")]
    pub osscan_limit: bool,
    /// `osscan_guess` field.
    #[arg(long = "osscan-guess")]
    pub osscan_guess: bool,

    // --- Ports ---
    /// `ports` field.
    #[arg(short = 'p', value_name = "PORTS")]
    pub ports: Option<String>,
    /// `exclude_ports` field.
    #[arg(long = "exclude-ports", value_name = "PORTS")]
    pub exclude_ports: Option<String>,
    /// `fast` field.
    #[arg(short = 'F')]
    pub fast: bool,
    /// `sequential_ports` field.
    #[arg(short = 'r')]
    pub sequential_ports: bool,
    /// `top_ports` field.
    #[arg(long = "top-ports", value_name = "N")]
    pub top_ports: Option<u16>,
    /// `port_ratio` field.
    #[arg(long = "port-ratio", value_name = "RATIO")]
    pub port_ratio: Option<f64>,

    // --- Timing ---
    /// `timing` field.
    #[arg(long = "timing", value_name = "0-5")]
    pub timing: Option<u8>,
    /// `min_hostgroup` field.
    #[arg(long = "min-hostgroup", value_name = "N")]
    pub min_hostgroup: Option<u32>,
    /// `max_hostgroup` field.
    #[arg(long = "max-hostgroup", value_name = "N")]
    pub max_hostgroup: Option<u32>,
    /// `min_parallelism` field.
    #[arg(long = "min-parallelism", value_name = "N")]
    pub min_parallelism: Option<u32>,
    /// `max_parallelism` field.
    #[arg(short = 'M', long = "max-parallelism", value_name = "N")]
    pub max_parallelism: Option<u32>,
    /// `min_rtt_timeout` field.
    #[arg(long = "min-rtt-timeout", value_name = "TIME")]
    pub min_rtt_timeout: Option<String>,
    /// `max_rtt_timeout` field.
    #[arg(long = "max-rtt-timeout", value_name = "TIME")]
    pub max_rtt_timeout: Option<String>,
    /// `initial_rtt_timeout` field.
    #[arg(long = "initial-rtt-timeout", value_name = "TIME")]
    pub initial_rtt_timeout: Option<String>,
    /// `max_retries` field.
    #[arg(long = "max-retries", value_name = "N")]
    pub max_retries: Option<u32>,
    /// `host_timeout` field.
    #[arg(long = "host-timeout", value_name = "TIME")]
    pub host_timeout: Option<String>,
    /// `scan_delay` field.
    #[arg(long = "scan-delay", value_name = "TIME")]
    pub scan_delay: Option<String>,
    /// `max_scan_delay` field.
    #[arg(long = "max-scan-delay", value_name = "TIME")]
    pub max_scan_delay: Option<String>,
    /// `min_rate` field.
    #[arg(long = "min-rate", value_name = "RATE")]
    pub min_rate: Option<u64>,
    /// `max_rate` field.
    #[arg(long = "max-rate", value_name = "RATE")]
    pub max_rate: Option<u64>,

    // --- Evasion / spoofing ---
    /// `fragment` field.
    #[arg(short = 'f')]
    pub fragment: bool,
    /// `mtu` field.
    #[arg(long = "mtu", value_name = "VAL")]
    pub mtu: Option<u16>,
    /// `decoys` field.
    #[arg(short = 'D', value_name = "DECOYS")]
    pub decoys: Option<String>,
    /// `spoof_source` field.
    #[arg(short = 'S', value_name = "ADDR")]
    pub spoof_source: Option<String>,
    /// `interface` field.
    #[arg(short = 'e', value_name = "IFACE")]
    pub interface: Option<String>,
    /// `source_port` field.
    #[arg(short = 'g', long = "source-port", value_name = "PORT")]
    pub source_port: Option<u16>,
    /// `proxies` field.
    #[arg(long = "proxies", visible_alias = "proxy", value_name = "URLS")]
    pub proxies: Option<String>,
    /// `data_hex` field.
    #[arg(long = "data", value_name = "HEX")]
    pub data_hex: Option<String>,
    /// `data_string` field.
    #[arg(long = "data-string", value_name = "STR")]
    pub data_string: Option<String>,
    /// `data_length` field.
    #[arg(long = "data-length", value_name = "NUM")]
    pub data_length: Option<u32>,
    /// `ip_options` field.
    #[arg(long = "ip-options", value_name = "OPTS")]
    pub ip_options: Option<String>,
    /// `ttl` field.
    #[arg(long = "ttl", value_name = "VAL")]
    pub ttl: Option<u8>,
    /// `spoof_mac` field.
    #[arg(long = "spoof-mac", value_name = "MAC")]
    pub spoof_mac: Option<String>,
    /// `badsum` field.
    #[arg(long = "badsum")]
    pub badsum: bool,

    // --- Output ---
    /// `output_normal` field.
    #[arg(long = "oN", value_name = "FILE")]
    pub output_normal: Option<PathBuf>,
    /// `output_xml` field.
    #[arg(long = "oX", value_name = "FILE")]
    pub output_xml: Option<PathBuf>,
    /// `output_script_kiddie` field.
    #[arg(long = "oS", value_name = "FILE")]
    pub output_script_kiddie: Option<PathBuf>,
    /// `output_grepable` field.
    #[arg(long = "oG", value_name = "FILE")]
    pub output_grepable: Option<PathBuf>,
    /// `output_all` field.
    #[arg(long = "oA", value_name = "BASE")]
    pub output_all: Option<PathBuf>,

    /// Machine-parseable output (Nmap `-oM`; same line family as `-oG` in nmaprs).
    #[arg(long = "oM", value_name = "FILE")]
    pub output_machine: Option<PathBuf>,

    /// Hex dump output (Nmap `-oH`; reserved — file opened when set, minimal placeholder).
    #[arg(long = "oH", value_name = "FILE")]
    pub output_hex: Option<PathBuf>,
    /// `verbosity` field.
    #[arg(long = "verbosity", value_name = "N", default_value = "0")]
    pub verbosity: u8,
    /// `debug` field.
    #[arg(long = "debug", value_name = "N", default_value = "0")]
    pub debug: u8,
    /// `reason` field.
    #[arg(long = "reason")]
    pub reason: bool,
    /// `open_only` field.
    #[arg(long = "open")]
    pub open_only: bool,
    /// `packet_trace` field.
    #[arg(long = "packet-trace")]
    pub packet_trace: bool,
    /// `iflist` field.
    #[arg(long = "iflist")]
    pub iflist: bool,
    /// `append_output` field.
    #[arg(long = "append-output")]
    pub append_output: bool,
    /// `resume` field.
    #[arg(long = "resume", value_name = "FILE")]
    pub resume: Option<PathBuf>,
    /// `noninteractive` field.
    #[arg(long = "noninteractive")]
    pub noninteractive: bool,
    /// `stylesheet` field.
    #[arg(long = "stylesheet", value_name = "PATH")]
    pub stylesheet: Option<String>,
    /// `webxml` field.
    #[arg(long = "webxml")]
    pub webxml: bool,
    /// `no_stylesheet` field.
    #[arg(long = "no-stylesheet")]
    pub no_stylesheet: bool,

    // --- Misc ---
    /// `ipv6` field.
    #[arg(short = '6')]
    pub ipv6: bool,

    /// Aggressive scan (Nmap `-A`): enables `-O`, `-sV`, default scripts (`-sC`), and `--traceroute`.
    #[arg(short = 'A')]
    pub aggressive: bool,
    /// `datadir` field.
    #[arg(long = "datadir", value_name = "DIR")]
    pub datadir: Option<PathBuf>,
    /// `send_eth` field.
    #[arg(long = "send-eth")]
    pub send_eth: bool,
    /// `send_ip` field.
    #[arg(long = "send-ip")]
    pub send_ip: bool,
    /// `privileged` field.
    #[arg(long = "privileged")]
    pub privileged: bool,
    /// `unprivileged` field.
    #[arg(long = "unprivileged")]
    pub unprivileged: bool,

    // --- Extended options (see Nmap `nmap.cc` / man page; not all in `nmap --help`) ---
    /// `resolve_all` field.
    #[arg(long = "resolve-all")]
    pub resolve_all: bool,
    /// `max_os_tries` field.
    #[arg(long = "max-os-tries", value_name = "N")]
    pub max_os_tries: Option<u8>,
    /// `defeat_rst_ratelimit` field.
    #[arg(long = "defeat-rst-ratelimit")]
    pub defeat_rst_ratelimit: bool,
    /// `defeat_icmp_ratelimit` field.
    #[arg(long = "defeat-icmp-ratelimit")]
    pub defeat_icmp_ratelimit: bool,
    /// `randomize_hosts` field.
    #[arg(long = "randomize-hosts")]
    pub randomize_hosts: bool,

    /// Alias for `--randomize-hosts` (Nmap compatibility).
    #[arg(long = "rH")]
    pub r_h: bool,
    /// `stats_every` field.
    #[arg(long = "stats-every", value_name = "TIME")]
    pub stats_every: Option<String>,
    /// `nsock_engine` field.
    #[arg(long = "nsock-engine", value_name = "NAME")]
    pub nsock_engine: Option<String>,
    /// `discovery_ignore_rst` field.
    #[arg(long = "discovery-ignore-rst")]
    pub discovery_ignore_rst: bool,

    /// Same as `--osscan-guess` (Nmap `--fuzzy`).
    #[arg(long = "fuzzy")]
    pub fuzzy: bool,
    /// `unique` field.
    #[arg(long = "unique")]
    pub unique: bool,
    /// `log_errors` field.
    #[arg(long = "log-errors")]
    pub log_errors: bool,
    /// `deprecated_xml_osclass` field.
    #[arg(long = "deprecated-xml-osclass")]
    pub deprecated_xml_osclass: bool,
    /// `adler32` field.
    #[arg(long = "adler32")]
    pub adler32: bool,
    /// `disable_arp_ping` field.
    #[arg(long = "disable-arp-ping")]
    pub disable_arp_ping: bool,
    /// `route_dst` field.
    #[arg(long = "route-dst", value_name = "HOST")]
    pub route_dst: Option<String>,
    /// `servicedb` field.
    #[arg(long = "servicedb", value_name = "FILE")]
    pub servicedb: Option<PathBuf>,
    /// `versiondb` field.
    #[arg(long = "versiondb", value_name = "FILE")]
    pub versiondb: Option<PathBuf>,
    /// `release_memory` field.
    #[arg(long = "release-memory")]
    pub release_memory: bool,
    /// `nogcc` field.
    #[arg(long = "nogcc")]
    pub nogcc: bool,
    /// `allports` field.
    #[arg(long = "allports")]
    pub allports: bool,
    /// `script_timeout` field.
    #[arg(long = "script-timeout", value_name = "TIME")]
    pub script_timeout: Option<String>,
    /// `thc` field.
    #[arg(long = "thc")]
    pub thc: bool,

    /// Nmap hidden alias: extra verbosity (equivalent to `-vv` increment).
    #[arg(long = "vv")]
    pub vv: bool,

    /// Nmap hidden alias: extra debug (equivalent to `-dd` increment).
    #[arg(long = "ff")]
    pub ff: bool,

    /// Trailing targets (hostnames, IPs, CIDR, nmap-style ranges).
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
}

impl Args {
    /// `parse_from_env` — see implementation.
    pub fn parse_from_env() -> Self {
        let raw: Vec<String> = std::env::args().collect();
        let expanded = crate::argv_expand::expand_nmap_style_argv(raw);
        let bin = expanded
            .first()
            .map(|p| {
                std::path::Path::new(p)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("nmaprs")
            })
            .unwrap_or("nmaprs")
            .to_string();

        let mut cmd = Self::command();
        cmd = cmd.bin_name(&bin).name(&bin);

        match cmd.try_get_matches_from(expanded) {
            Ok(matches) => Self::from_arg_matches(&matches).expect("nmaprs CLI parse"),
            Err(err) => {
                use clap::error::ErrorKind;
                match err.kind() {
                    ErrorKind::DisplayHelp
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                        crate::help_tp::print_help(&bin);
                        std::process::exit(0);
                    }
                    ErrorKind::DisplayVersion => {
                        crate::help_tp::print_version(&bin);
                        std::process::exit(0);
                    }
                    _ => err.exit(),
                }
            }
        }
    }
    /// `effective_verbosity` — see implementation.
    pub fn effective_verbosity(&self) -> u8 {
        self.verbosity.saturating_add(if self.vv { 2 } else { 0 })
    }
    /// `effective_debug` — see implementation.
    pub fn effective_debug(&self) -> u8 {
        self.debug.saturating_add(if self.ff { 2 } else { 0 })
    }
    /// `effective_randomize_hosts` — see implementation.
    pub fn effective_randomize_hosts(&self) -> bool {
        self.randomize_hosts || self.r_h
    }
    /// `effective_osscan_guess` — see implementation.
    pub fn effective_osscan_guess(&self) -> bool {
        self.osscan_guess || self.fuzzy
    }
}

#[cfg(test)]
mod effective_opts_tests {
    use clap::Parser;

    use super::Args;

    #[test]
    fn effective_verbosity_adds_hidden_vv() {
        let a = Args::try_parse_from([
            "nmaprs",
            "-p",
            "80",
            "--verbosity",
            "1",
            "--vv",
            "127.0.0.1",
        ])
        .unwrap();
        assert_eq!(a.effective_verbosity(), 3);
    }

    #[test]
    fn effective_debug_adds_hidden_ff() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--debug", "1", "--ff", "127.0.0.1"])
            .unwrap();
        assert_eq!(a.effective_debug(), 3);
    }

    #[test]
    fn effective_randomize_hosts_includes_r_h_alias() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--rH", "127.0.0.1"]).unwrap();
        assert!(a.effective_randomize_hosts());
    }

    #[test]
    fn effective_osscan_guess_includes_fuzzy_alias() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--fuzzy", "127.0.0.1"]).unwrap();
        assert!(a.effective_osscan_guess());
    }

    #[test]
    fn effective_verbosity_high_value_passthrough() {
        let a =
            Args::try_parse_from(["nmaprs", "-p", "80", "--verbosity", "4", "127.0.0.1"]).unwrap();
        assert_eq!(a.effective_verbosity(), 4);
    }

    #[test]
    fn effective_debug_with_ff_adds_two() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--debug", "1", "--ff", "127.0.0.1"])
            .unwrap();
        assert_eq!(a.effective_debug(), 3);
    }

    #[test]
    fn effective_randomize_hosts_from_long_flag() {
        let a =
            Args::try_parse_from(["nmaprs", "-p", "80", "--randomize-hosts", "127.0.0.1"]).unwrap();
        assert!(a.effective_randomize_hosts());
    }

    #[test]
    fn ping_only_and_list_scan_flags_parse() {
        let a = Args::try_parse_from(["nmaprs", "--sL", "127.0.0.1"]).unwrap();
        assert!(a.list_scan);
        let b = Args::try_parse_from(["nmaprs", "--sn", "127.0.0.1"]).unwrap();
        assert!(b.ping_only);
    }

    #[test]
    fn no_ping_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "--no-ping", "-p", "80", "127.0.0.1"]).unwrap();
        assert!(a.no_ping);
    }

    #[test]
    fn ipv6_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "-6", "-p", "80", "::1"]).unwrap();
        assert!(a.ipv6);
    }

    #[test]
    fn top_ports_and_fast_flags_parse() {
        let a = Args::try_parse_from(["nmaprs", "-F", "127.0.0.1"]).unwrap();
        assert!(a.fast);
        let b = Args::try_parse_from(["nmaprs", "--top-ports", "50", "127.0.0.1"]).unwrap();
        assert_eq!(b.top_ports, Some(50));
    }

    #[test]
    fn traceroute_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--traceroute", "127.0.0.1"]).unwrap();
        assert!(a.traceroute);
    }

    #[test]
    fn version_scan_flag_parses() {
        let a =
            Args::try_parse_from(["nmaprs", "-p", "80", "--version-scan", "127.0.0.1"]).unwrap();
        assert!(a.version_scan);
    }

    #[test]
    fn script_default_flag_parses() {
        let a =
            Args::try_parse_from(["nmaprs", "-p", "80", "--script-default", "127.0.0.1"]).unwrap();
        assert!(a.script_default);
    }

    #[test]
    fn aggressive_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "-A", "-p", "80", "127.0.0.1"]).unwrap();
        assert!(a.aggressive);
    }

    #[test]
    fn os_detect_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "-O", "-p", "80", "127.0.0.1"]).unwrap();
        assert!(a.os_detect);
    }

    #[test]
    fn exclude_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--exclude", "10.0.0.1", "127.0.0.1"])
            .unwrap();
        assert_eq!(a.exclude.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn input_list_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "--iL", "/tmp/hosts.txt", "-p", "80"]).unwrap();
        assert_eq!(
            a.input_list
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            Some("/tmp/hosts.txt".to_string())
        );
    }

    #[test]
    fn random_targets_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "--iR", "5", "-p", "80"]).unwrap();
        assert_eq!(a.random_targets, Some(5));
    }

    #[test]
    fn defeat_icmp_ratelimit_flag_parses() {
        let a =
            Args::try_parse_from(["nmaprs", "-p", "80", "--defeat-icmp-ratelimit", "127.0.0.1"])
                .unwrap();
        assert!(a.defeat_icmp_ratelimit);
    }

    #[test]
    fn discovery_ignore_rst_flag_parses() {
        let a = Args::try_parse_from(["nmaprs", "-p", "80", "--discovery-ignore-rst", "127.0.0.1"])
            .unwrap();
        assert!(a.discovery_ignore_rst);
    }
}

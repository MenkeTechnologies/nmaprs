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
pub struct Args {
    /// Print help (-h / --help).
    #[arg(short = 'h', long, global = true, action = clap::ArgAction::Help)]
    pub help: Option<bool>,

    /// Print version (-V).
    #[arg(short = 'V', long = "version", action = clap::ArgAction::Version)]
    pub version_req: Option<bool>,

    // --- Target specification ---
    #[arg(long = "iL", value_name = "FILE")]
    pub input_list: Option<PathBuf>,

    #[arg(long = "iR", value_name = "NUM")]
    pub random_targets: Option<u64>,

    #[arg(long = "exclude", value_name = "TARGETS")]
    pub exclude: Option<String>,

    #[arg(long = "excludefile", value_name = "FILE")]
    pub exclude_file: Option<PathBuf>,

    // --- Host discovery ---
    #[arg(long = "sL")]
    pub list_scan: bool,

    #[arg(long = "sn")]
    pub ping_only: bool,

    #[arg(long = "no-ping")]
    pub no_ping: bool,

    #[arg(long = "ping-S", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_syn: Option<Option<String>>,

    #[arg(long = "ping-A", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_ack: Option<Option<String>>,

    #[arg(long = "ping-U", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_udp: Option<Option<String>>,

    #[arg(long = "ping-Y", num_args = 0..=1, value_name = "PORTLIST")]
    pub ping_sctp: Option<Option<String>>,

    #[arg(long = "ping-E", action = clap::ArgAction::SetTrue)]
    pub ping_echo: bool,

    #[arg(long = "ping-P", action = clap::ArgAction::SetTrue)]
    pub ping_timestamp: bool,

    #[arg(long = "ping-M", action = clap::ArgAction::SetTrue)]
    pub ping_mask: bool,

    #[arg(long = "ping-ip-proto", num_args = 0..=1, value_name = "PROTOS")]
    pub ping_ip_proto: Option<Option<String>>,

    #[arg(short = 'n')]
    pub no_dns: bool,

    #[arg(short = 'R')]
    pub always_resolve: bool,

    #[arg(long = "dns-servers", value_name = "SERVERS")]
    pub dns_servers: Option<String>,

    #[arg(long = "system-dns")]
    pub system_dns: bool,

    #[arg(long = "traceroute")]
    pub traceroute: bool,

    // --- Scan techniques ---
    #[arg(long = "scan-type", value_name = "CHAR")]
    pub scan_type: Option<char>,

    #[arg(long = "scanflags", value_name = "FLAGS")]
    pub scanflags: Option<String>,

    #[arg(long = "sI", value_name = "ZOMBIE")]
    pub idle_scan: Option<String>,

    #[arg(long = "sO")]
    pub ip_proto_scan: bool,

    #[arg(short = 'b', value_name = "FTP")]
    pub ftp_bounce: Option<String>,

    // --- Version / script / OS ---
    #[arg(long = "version-scan")]
    pub version_scan: bool,

    #[arg(long = "script-default")]
    pub script_default: bool,

    #[arg(long = "script", value_name = "EXPR")]
    pub script: Option<String>,

    #[arg(long = "script-args", value_name = "ARGS")]
    pub script_args: Option<String>,

    #[arg(long = "script-args-file", value_name = "FILE")]
    pub script_args_file: Option<PathBuf>,

    #[arg(long = "script-trace")]
    pub script_trace: bool,

    #[arg(long = "script-updatedb")]
    pub script_updatedb: bool,

    #[arg(long = "script-help", value_name = "EXPR")]
    pub script_help: Option<String>,

    #[arg(long = "version-intensity", value_name = "0-9")]
    pub version_intensity: Option<u8>,

    #[arg(long = "version-light")]
    pub version_light: bool,

    #[arg(long = "version-all")]
    pub version_all: bool,

    #[arg(long = "version-trace")]
    pub version_trace: bool,

    #[arg(short = 'O')]
    pub os_detect: bool,

    #[arg(long = "osscan-limit")]
    pub osscan_limit: bool,

    #[arg(long = "osscan-guess")]
    pub osscan_guess: bool,

    // --- Ports ---
    #[arg(short = 'p', value_name = "PORTS")]
    pub ports: Option<String>,

    #[arg(long = "exclude-ports", value_name = "PORTS")]
    pub exclude_ports: Option<String>,

    #[arg(short = 'F')]
    pub fast: bool,

    #[arg(short = 'r')]
    pub sequential_ports: bool,

    #[arg(long = "top-ports", value_name = "N")]
    pub top_ports: Option<u16>,

    #[arg(long = "port-ratio", value_name = "RATIO")]
    pub port_ratio: Option<f64>,

    // --- Timing ---
    #[arg(long = "timing", value_name = "0-5")]
    pub timing: Option<u8>,

    #[arg(long = "min-hostgroup", value_name = "N")]
    pub min_hostgroup: Option<u32>,

    #[arg(long = "max-hostgroup", value_name = "N")]
    pub max_hostgroup: Option<u32>,

    #[arg(long = "min-parallelism", value_name = "N")]
    pub min_parallelism: Option<u32>,

    #[arg(short = 'M', long = "max-parallelism", value_name = "N")]
    pub max_parallelism: Option<u32>,

    #[arg(long = "min-rtt-timeout", value_name = "TIME")]
    pub min_rtt_timeout: Option<String>,

    #[arg(long = "max-rtt-timeout", value_name = "TIME")]
    pub max_rtt_timeout: Option<String>,

    #[arg(long = "initial-rtt-timeout", value_name = "TIME")]
    pub initial_rtt_timeout: Option<String>,

    #[arg(long = "max-retries", value_name = "N")]
    pub max_retries: Option<u32>,

    #[arg(long = "host-timeout", value_name = "TIME")]
    pub host_timeout: Option<String>,

    #[arg(long = "scan-delay", value_name = "TIME")]
    pub scan_delay: Option<String>,

    #[arg(long = "max-scan-delay", value_name = "TIME")]
    pub max_scan_delay: Option<String>,

    #[arg(long = "min-rate", value_name = "RATE")]
    pub min_rate: Option<u64>,

    #[arg(long = "max-rate", value_name = "RATE")]
    pub max_rate: Option<u64>,

    // --- Evasion / spoofing ---
    #[arg(short = 'f')]
    pub fragment: bool,

    #[arg(long = "mtu", value_name = "VAL")]
    pub mtu: Option<u16>,

    #[arg(short = 'D', value_name = "DECOYS")]
    pub decoys: Option<String>,

    #[arg(short = 'S', value_name = "ADDR")]
    pub spoof_source: Option<String>,

    #[arg(short = 'e', value_name = "IFACE")]
    pub interface: Option<String>,

    #[arg(short = 'g', long = "source-port", value_name = "PORT")]
    pub source_port: Option<u16>,

    #[arg(long = "proxies", visible_alias = "proxy", value_name = "URLS")]
    pub proxies: Option<String>,

    #[arg(long = "data", value_name = "HEX")]
    pub data_hex: Option<String>,

    #[arg(long = "data-string", value_name = "STR")]
    pub data_string: Option<String>,

    #[arg(long = "data-length", value_name = "NUM")]
    pub data_length: Option<u32>,

    #[arg(long = "ip-options", value_name = "OPTS")]
    pub ip_options: Option<String>,

    #[arg(long = "ttl", value_name = "VAL")]
    pub ttl: Option<u8>,

    #[arg(long = "spoof-mac", value_name = "MAC")]
    pub spoof_mac: Option<String>,

    #[arg(long = "badsum")]
    pub badsum: bool,

    // --- Output ---
    #[arg(long = "oN", value_name = "FILE")]
    pub output_normal: Option<PathBuf>,

    #[arg(long = "oX", value_name = "FILE")]
    pub output_xml: Option<PathBuf>,

    #[arg(long = "oS", value_name = "FILE")]
    pub output_script_kiddie: Option<PathBuf>,

    #[arg(long = "oG", value_name = "FILE")]
    pub output_grepable: Option<PathBuf>,

    #[arg(long = "oA", value_name = "BASE")]
    pub output_all: Option<PathBuf>,

    /// Machine-parseable output (Nmap `-oM`; same line family as `-oG` in nmaprs).
    #[arg(long = "oM", value_name = "FILE")]
    pub output_machine: Option<PathBuf>,

    /// Hex dump output (Nmap `-oH`; reserved — file opened when set, minimal placeholder).
    #[arg(long = "oH", value_name = "FILE")]
    pub output_hex: Option<PathBuf>,

    #[arg(long = "verbosity", value_name = "N", default_value = "0")]
    pub verbosity: u8,

    #[arg(long = "debug", value_name = "N", default_value = "0")]
    pub debug: u8,

    #[arg(long = "reason")]
    pub reason: bool,

    #[arg(long = "open")]
    pub open_only: bool,

    #[arg(long = "packet-trace")]
    pub packet_trace: bool,

    #[arg(long = "iflist")]
    pub iflist: bool,

    #[arg(long = "append-output")]
    pub append_output: bool,

    #[arg(long = "resume", value_name = "FILE")]
    pub resume: Option<PathBuf>,

    #[arg(long = "noninteractive")]
    pub noninteractive: bool,

    #[arg(long = "stylesheet", value_name = "PATH")]
    pub stylesheet: Option<String>,

    #[arg(long = "webxml")]
    pub webxml: bool,

    #[arg(long = "no-stylesheet")]
    pub no_stylesheet: bool,

    // --- Misc ---
    #[arg(short = '6')]
    pub ipv6: bool,

    /// Aggressive scan (Nmap `-A`): enables `-O`, `-sV`, default scripts (`-sC`), and `--traceroute`.
    #[arg(short = 'A')]
    pub aggressive: bool,

    #[arg(long = "datadir", value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    #[arg(long = "send-eth")]
    pub send_eth: bool,

    #[arg(long = "send-ip")]
    pub send_ip: bool,

    #[arg(long = "privileged")]
    pub privileged: bool,

    #[arg(long = "unprivileged")]
    pub unprivileged: bool,

    // --- Extended options (see Nmap `nmap.cc` / man page; not all in `nmap --help`) ---
    #[arg(long = "resolve-all")]
    pub resolve_all: bool,

    #[arg(long = "max-os-tries", value_name = "N")]
    pub max_os_tries: Option<u8>,

    #[arg(long = "defeat-rst-ratelimit")]
    pub defeat_rst_ratelimit: bool,

    #[arg(long = "defeat-icmp-ratelimit")]
    pub defeat_icmp_ratelimit: bool,

    #[arg(long = "randomize-hosts")]
    pub randomize_hosts: bool,

    /// Alias for `--randomize-hosts` (Nmap compatibility).
    #[arg(long = "rH")]
    pub r_h: bool,

    #[arg(long = "stats-every", value_name = "TIME")]
    pub stats_every: Option<String>,

    #[arg(long = "nsock-engine", value_name = "NAME")]
    pub nsock_engine: Option<String>,

    #[arg(long = "discovery-ignore-rst")]
    pub discovery_ignore_rst: bool,

    /// Same as `--osscan-guess` (Nmap `--fuzzy`).
    #[arg(long = "fuzzy")]
    pub fuzzy: bool,

    #[arg(long = "unique")]
    pub unique: bool,

    #[arg(long = "log-errors")]
    pub log_errors: bool,

    #[arg(long = "deprecated-xml-osclass")]
    pub deprecated_xml_osclass: bool,

    #[arg(long = "adler32")]
    pub adler32: bool,

    #[arg(long = "disable-arp-ping")]
    pub disable_arp_ping: bool,

    #[arg(long = "route-dst", value_name = "HOST")]
    pub route_dst: Option<String>,

    #[arg(long = "servicedb", value_name = "FILE")]
    pub servicedb: Option<PathBuf>,

    #[arg(long = "versiondb", value_name = "FILE")]
    pub versiondb: Option<PathBuf>,

    #[arg(long = "release-memory")]
    pub release_memory: bool,

    #[arg(long = "nogcc")]
    pub nogcc: bool,

    #[arg(long = "allports")]
    pub allports: bool,

    #[arg(long = "script-timeout", value_name = "TIME")]
    pub script_timeout: Option<String>,

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

    pub fn effective_verbosity(&self) -> u8 {
        self.verbosity.saturating_add(if self.vv { 2 } else { 0 })
    }

    pub fn effective_debug(&self) -> u8 {
        self.debug.saturating_add(if self.ff { 2 } else { 0 })
    }

    pub fn effective_randomize_hosts(&self) -> bool {
        self.randomize_hosts || self.r_h
    }

    pub fn effective_osscan_guess(&self) -> bool {
        self.osscan_guess || self.fuzzy
    }
}

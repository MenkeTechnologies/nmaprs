//! `tp`-style help output (MenkeTechnologies/temprs: banner, `//` columns, section rules).
//! ANSI colors match `temprs` `src/model/opts.rs` (`CYBERPUNK_TEMPLATE`, `BANNER`, `AFTER`).

use std::io::IsTerminal;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Banner art lines 1–2 cyan, 3–4 magenta, 5–6 red — same pattern as `tp` `BANNER`.
const BANNER_COLOR: &str = concat!(
    "\x1b[36m ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗\x1b[0m\n",
    "\x1b[36m ██╔██╗ ██║████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝\x1b[0m\n",
    "\x1b[35m ██║╚██╗██║██╔████╔██║███████║██████╔╝██████╔╝███████╗\x1b[0m\n",
    "\x1b[35m ██║ ╚████║██║╚██╔╝██║██╔══██║██╔══██╗██╔══██╗╚════██║\x1b[0m\n",
    "\x1b[31m ╚██╗ ╚██╔╝██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██║███████║\x1b[0m\n",
    "\x1b[31m  ╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝\x1b[0m\n",
);

const BANNER_PLAIN: &str = concat!(
    " ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗\n",
    " ██╔██╗ ██║████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝\n",
    " ██║╚██╗██║██╔████╔██║███████║██████╔╝██████╔╝███████╗\n",
    " ██║ ╚████║██║╚██╔╝██║██╔══██║██╔══██╗██╔══██╗╚════██║\n",
    " ╚██╗ ╚██╔╝██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██║███████║\n",
    "  ╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝\n",
);

fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn section_line(title: &str, total_width: usize, color: bool) -> String {
    let prefix = format!(" ── {} ", title);
    let dashes = total_width.saturating_sub(prefix.chars().count());
    let body = format!("{}{}", prefix, "─".repeat(dashes));
    if color {
        format!("\x1b[36m{}\x1b[0m", body)
    } else {
        body
    }
}

fn tp_line(flags: &str, comment: &str, color: bool) -> String {
    const COL: usize = 48;
    let mut line = String::new();
    line.push_str("  ");
    line.push_str(flags);
    let len = line.chars().count();
    if len < COL {
        line.push_str(&" ".repeat(COL - len));
    } else {
        line.push_str("  ");
    }
    if color {
        line.push_str(" \x1b[32m//\x1b[0m ");
    } else {
        line.push_str("// ");
    }
    line.push_str(comment);
    line
}

fn print_section(title: &str, rows: &[(&str, &str)], color: bool) {
    println!("{}", section_line(title, 56, color));
    for &(flags, desc) in rows {
        println!("{}", tp_line(flags, desc, color));
    }
    println!();
}

fn print_banner_and_status(color: bool) {
    if color {
        print!("{}", BANNER_COLOR);
        println!("\x1b[36m ┌──────────────────────────────────────────────────────┐\x1b[0m");
        println!(
            "\x1b[36m │ STATUS: ONLINE // SIGNAL: ████████░░ // v{}\x1b[36m │\x1b[0m",
            VERSION
        );
        println!("\x1b[36m └──────────────────────────────────────────────────────┘\x1b[0m");
        println!("\x1b[35m >> NMAPRS // GRID SCANNER // FULL SPECTRUM <<\x1b[0m");
    } else {
        print!("{}", BANNER_PLAIN);
        println!(" ┌──────────────────────────────────────────────────────┐");
        println!(
            " │ STATUS: ONLINE // SIGNAL: ████████░░ // v{} │",
            VERSION
        );
        println!(" └──────────────────────────────────────────────────────┘");
        println!("  >> NMAPRS // GRID SCANNER // FULL SPECTRUM <<");
    }
}

fn print_footer(color: bool) {
    println!("{}", section_line("SYSTEM", 52, color));
    if color {
        println!(
            concat!(
                "\x1b[35m v",
                env!("CARGO_PKG_VERSION"),
                " \x1b[0m// \x1b[33m(c) MenkeTechnologies\x1b[0m"
            )
        );
        println!("\x1b[35m The grid is wide and infinite.\x1b[0m");
        println!("\x1b[33m >>> JACK IN. MAP THE GRID. OWN YOUR PORTS. <<<\x1b[0m");
        println!("\x1b[36m ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░\x1b[0m");
    } else {
        println!("  v{VERSION} // (c) MenkeTechnologies");
        println!("  The grid is wide and infinite.");
        println!("  >>> JACK IN. MAP THE GRID. OWN YOUR PORTS. <<<");
        println!(" ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░");
    }
}

/// Full-screen help matching `tp -h` layout (banner, USAGE, sections, footer).
pub fn print_help(bin: &str) {
    let color = use_color();

    print_banner_and_status(color);

    println!();
    println!("Parallel network scanner — nmap-compatible CLI (see README).");
    println!();
    if color {
        println!(
            "\x1b[33m USAGE:\x1b[0m {} [OPTIONS] [TARGET]...",
            bin
        );
    } else {
        println!("  USAGE: {bin} [OPTIONS] [TARGET]...");
    }
    println!();

    print_section(
        "TARGET SPEC",
        &[
            ("--iL <FILE>", "Input host list from FILE"),
            ("--iR <NUM>", "Choose NUM random targets"),
            ("--exclude <TARGETS>", "Exclude hosts or networks"),
            ("--excludefile <FILE>", "Exclude list from FILE"),
        ],
        color,
    );

    print_section(
        "HOST DISCOVERY",
        &[
            ("--sL", "List scan (targets only)"),
            ("--sn", "Ping scan — no port scan"),
            ("-Pn, --no-ping", "Skip host discovery; treat all as up"),
            ("--ping-S [<PORTLIST>]", "TCP SYN discovery (or -PS)"),
            ("--ping-A [<PORTLIST>]", "TCP ACK discovery (or -PA)"),
            ("--ping-U [<PORTLIST>]", "UDP discovery (or -PU)"),
            ("--ping-Y [<PORTLIST>]", "SCTP discovery (or -PY)"),
            ("--ping-E / -PE", "ICMP echo discovery"),
            ("--ping-P / -PP", "ICMP timestamp discovery"),
            ("--ping-M / -PM", "ICMP netmask discovery"),
            ("--ping-ip-proto [<PROTOS>]", "IP protocol ping (or -PO)"),
            ("-n", "Never do DNS resolution"),
            ("-R", "Always resolve"),
            ("--dns-servers <SERVERS>", "Custom resolvers"),
            ("--system-dns", "Use OS resolver"),
            ("--traceroute", "Trace hop path to each host"),
        ],
        color,
    );

    print_section(
        "SCAN TECHNIQUES",
        &[
            ("--scan-type <CHAR>", "Scan letter (-sT / -sS / -sU / …)"),
            ("--scanflags <FLAGS>", "Custom TCP flags (raw TCP scans)"),
            ("--sI <ZOMBIE>", "Idle scan (or -sI)"),
            ("--sO", "IP protocol scan"),
            ("-b <FTP>", "FTP bounce scan"),
            ("-sS -sT -sU …", "Short scan types (-sN -sF -sX -sA -sW -sM -sY -sZ)"),
        ],
        color,
    );

    print_section(
        "SCRIPTS / VERSION / OS",
        &[
            ("--version-scan / -sV", "Service version detection"),
            ("--script-default / -sC", "Default script set"),
            ("--script <EXPR>", "Script expression"),
            ("--script-args <ARGS>", "Script arguments"),
            ("--script-args-file <FILE>", "Script args from file"),
            ("--script-trace", "Trace script I/O"),
            ("--script-updatedb", "Update script DB (stub)"),
            ("--script-help <EXPR>", "Script help (built-ins)"),
            ("--version-intensity <0-9>", "Version probe depth"),
            ("--version-light / --version-all", "Intensity presets"),
            ("--version-trace", "Trace version scan"),
            ("-O", "OS detection (heuristic)"),
            ("--osscan-limit", "Limit OS scan to promising targets"),
            ("--osscan-guess / --fuzzy", "Guess OS more aggressively"),
        ],
        color,
    );

    print_section(
        "PORTS",
        &[
            ("-p <PORTS>", "Port list / ranges"),
            ("--exclude-ports <PORTS>", "Exclude ports from scan"),
            ("-F", "Fast scan (fewer ports)"),
            ("-r", "Sequential port order"),
            ("--top-ports <N>", "Top N TCP ports by frequency"),
            ("--port-ratio <RATIO>", "Ports more common than RATIO"),
            ("--allports", "Ignore --exclude-ports"),
        ],
        color,
    );

    print_section(
        "TIMING",
        &[
            ("-T <0-5>, --timing <0-5>", "Timing template"),
            ("--min-hostgroup / --max-hostgroup <N>", "Host batch sizes"),
            ("--min-parallelism / -M, --max-parallelism <N>", "Probe parallelism"),
            ("--min-rtt-timeout / --max-rtt-timeout / --initial-rtt-timeout", "RTT bounds"),
            ("--max-retries <N>", "Extra probe retries after timeout"),
            ("--host-timeout <TIME>", "Give up on host after TIME"),
            ("--scan-delay / --max-scan-delay <TIME>", "Inter-probe delay"),
            ("--min-rate / --max-rate <RATE>", "Global probe start rate"),
            ("--stats-every <TIME>", "Stats interval (parsed)"),
        ],
        color,
    );

    print_section(
        "EVASION",
        &[
            ("-f, --mtu <VAL>", "Fragment / MTU"),
            ("-D <DECOYS>", "Decoy addresses"),
            ("-S <ADDR>", "Spoof source address"),
            ("-e <IFACE>", "Network interface"),
            ("-g, --source-port <PORT>", "Fixed source port"),
            ("--proxies / --proxy <URLS>", "HTTP/SOCKS proxies"),
            ("--data / --data-string / --data-length", "Append payload"),
            ("--ip-options <OPTS>", "Raw IP options"),
            ("--ttl <VAL>", "IP TTL"),
            ("--spoof-mac <MAC>", "Spoof MAC"),
            ("--badsum", "Bad TCP/UDP checksum"),
        ],
        color,
    );

    print_section(
        "OUTPUT",
        &[
            ("-oN -oX -oS -oG -oA -oM -oH <FILE>", "Output paths"),
            ("--verbosity <N> / --debug <N>", "Log levels"),
            ("--reason", "Show port state reason"),
            ("--open", "Open ports only"),
            ("--packet-trace", "Packet trace"),
            ("--iflist", "List interfaces"),
            ("--append-output", "Append to output files"),
            ("--resume <FILE>", "Resume from checkpoint"),
            ("--noninteractive", "No keyboard interaction"),
            ("--stylesheet / --webxml / --no-stylesheet", "XML styling"),
        ],
        color,
    );

    print_section(
        "MISC",
        &[
            ("-6", "IPv6"),
            ("-A", "Aggressive (-O -sV -sC --traceroute)"),
            ("--datadir <DIR>", "Nmap data files directory"),
            ("--send-eth / --send-ip", "Link-layer send mode"),
            ("--privileged / --unprivileged", "Capability hints"),
            ("-h, --help", "Print help"),
            ("-V, --version", "Print version"),
        ],
        color,
    );

    print_section(
        "EXTENDED",
        &[
            ("--resolve-all", "Scan every resolved address"),
            ("--max-os-tries <N>", "OS detection tries (1–50)"),
            ("--defeat-rst-ratelimit", "Defeat RST rate limit"),
            ("--defeat-icmp-ratelimit", "Defeat ICMP rate limit"),
            ("--randomize-hosts / --rH", "Shuffle host order"),
            ("--nsock-engine <NAME>", "Nsock engine (kqueue/poll/select)"),
            ("--discovery-ignore-rst", "Ignore RST in discovery"),
            ("--unique", "Deduplicate targets"),
            ("--log-errors", "Log errors"),
            ("--deprecated-xml-osclass", "Legacy XML osclass"),
            ("--adler32", "Adler32 checksums"),
            ("--disable-arp-ping", "Disable ARP ping"),
            ("--route-dst <HOST>", "Route debug"),
            ("--servicedb / --versiondb <FILE>", "Override data files"),
            ("--release-memory", "Release memory hint"),
            ("--nogcc", "No GCC optimizations"),
            ("--script-timeout <TIME>", "Built-in script timeout"),
            ("--thc", "THC mode"),
            ("--vv / --ff", "Extra verbosity / debug"),
        ],
        color,
    );

    print_section(
        "POSITIONAL",
        &[
            (
                "[TARGET]...",
                "Hostnames, IPs, CIDR, nmap-style octet ranges",
            ),
        ],
        color,
    );

    print_footer(color);
}

pub fn print_version(bin: &str) {
    if use_color() {
        println!("\x1b[35m{bin} {VERSION}\x1b[0m");
    } else {
        println!("{bin} {VERSION}");
    }
}

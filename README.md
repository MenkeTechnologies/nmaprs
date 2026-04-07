```
╔══════════════════════════════════════════════════════════════════╗
║  N M A P R S   //   R U S T   G R I D   S C A N N E R            ║
║  neon wire · parallel sockets · nmap-shaped CLI                   ║
╚══════════════════════════════════════════════════════════════════╝
```

# nmaprs

**nmaprs** is a Rust-native network scanner that speaks **nmap’s CLI dialect** (see `nmap --help`) and runs a **highly parallel TCP connect** engine (`tokio` + `futures::stream` + bounded concurrency). It is **not** a byte-for-byte reimplementation of Nmap: NSE (Lua), OS fingerprinting, raw SYN/UDP, traceroute, and ICMP discovery are separate lifetimes of work. This tool **accepts the same flag families**, implements **connect scanning and target/port plumbing** for real workloads, and **fails loudly** on features that are not wired yet.

Created by **MenkeTechnologies**.

## Truth table (read this)

| Area | Status |
|------|--------|
| TCP connect scan (`-sT`, default) | **Implemented** — async, parallel, timeout-bound |
| Port specs (`-p`, `-F`, `--top-ports`, `--exclude-ports`, `--port-ratio`) | **Implemented** — default port order from embedded `nmap-services` TCP frequency list |
| Targets (IPv4, CIDR, `192.168.1-3.1-20` ranges, DNS names) | **Implemented** — IPv6 (`-6`) not implemented |
| Output (`-oN`, `-oG`, `-oX`, `-oA`) | **Implemented** — XML is minimal; `-oS` ignored with warning |
| Timing (`-T0`–`-T5`, parallelism / RTT-ish timeout) | **Partial** — maps to concurrency + connect timeout |
| Raw SYN (`-sS`), UDP (`-sU`), NSE (`--script`), OS (`-O`), ping (`-sn`) | **Not implemented** — CLI may parse; execution bails or warns (see runtime) |

If you need **authoritative** Nmap behavior, use **[Nmap](https://nmap.org/)**. Use **nmaprs** when you want a **fast Rust connect scanner** with **familiar flags** and **room to grow**.

## Build

```bash
cargo build --release
```

Binary: `target/release/nmaprs`

## Help (`-h` / `--help`)

Short help and long help match the **nmap-style surface** (combined flags like `-sT`, `-Pn`, `-PS80`, `-T4` are expanded before parsing). Try:

```bash
cargo run -- -h
```

## Examples

```bash
# TCP connect scan — top ports from embedded frequency table
nmaprs scanme.nmap.org

# Explicit ports, treat all hosts up, aggressive timing template
nmaprs -Pn -p 22,80,443 -T4 192.168.0.0/30

# List targets only (no port scan)
nmaprs -sL 10.0.0.0/29

# Grepable output
nmaprs -p 443 -oG - scanme.nmap.org
```

## Tests

```bash
cargo test
```

## Benchmarks

```bash
cargo bench --bench scan
```

Uses Criterion on a tiny localhost workload (closed ports, short timeout). For wall-clock scans, your network RTT and firewall policy dominate.

## Architecture (why it is parallel)

1. **Argv expansion** (`src/argv_expand.rs`) normalizes glued nmap tokens (`-sS`, `-PS443`, `-T3`, …) before `clap`.
2. **Plan** (`src/config.rs`) turns flags into a `ScanPlan` (ports, concurrency, timeout).
3. **Targets** (`src/target.rs`) expand hostnames / CIDR / nmap-style octet ranges (IPv4) with a hard cap on fan-out.
4. **Scan** (`src/scan.rs`) schedules one async task per `(host, port)` pair, **`buffer_unordered(concurrency)`** so work stays CPU + syscall bound instead of one-host-at-a-time.
5. **Output** (`src/output.rs`) streams normal / grepable / minimal XML.

## Data

`data/top_ports.txt` is generated from Nmap’s `nmap-services` TCP frequency ordering. Regenerate with `bash scripts/fetch_top_ports.sh` (requires `curl` and `awk`).

## License

Licensed under either of **Apache License, Version 2.0** or **MIT** at your option.

## Legal / ethics

Only scan networks you own or are authorized to test. This software is provided as-is for legitimate security research and operations.

```
╔══════════════════════════════════════════════════════════════════╗
║  N M A P R S   //   R U S T   G R I D   S C A N N E R            ║
║  neon wire · parallel sockets · nmap-shaped CLI                   ║
╚══════════════════════════════════════════════════════════════════╝
```

# nmaprs

**nmaprs** is a Rust-native network scanner that speaks **nmap’s CLI dialect** (see `nmap --help`) and runs **highly parallel** scan engines (`tokio` + `futures::stream` + bounded concurrency). Multiple `-iL` lines and CLI targets resolve **in parallel** (order preserved) with the same **`--max-parallelism` / `--min-parallelism` / timing template** cap as port probes. It is **not** a byte-for-byte reimplementation of Nmap: the full **NSE Lua runtime**, **Nmap OS fingerprint database**, and **every** obscure probe path are not embedded. This tool implements **real** TCP connect, UDP probes, ICMP ping discovery, raw IPv4/IPv6 SYN (privileged), target list / random hosts, IPv6, resume checkpoints, traceroute, TTL-based OS **heuristics**, and **built-in** Rust “scripts” (banner grab) for `--script` / `-sC`.

Created by **MenkeTechnologies**.

## Truth table (read this)

| Area | Status |
|------|--------|
| TCP connect (`-sT`, default) | **Implemented** — async, parallel, timeout-bound |
| UDP (`-sU`) | **Implemented** — reply → `open`; short post-timeout window for ICMP; raw listeners (privileged) classify **destination unreachable** probes: **port unreachable** → `closed`; **other unreachable codes** → `filtered` (IPv4 type 3 / ICMPv6 type 1); **Unix** uses one `poll(2)`+burst-recv thread when both IPv4 and IPv6 targets; `closed` wins over `filtered` |
| SYN (`-sS`) | **Implemented** — raw IPv4 + **separate** raw IPv6 TCP path via `pnet` — **requires privileges**; **pipelined** per family: dedicated recv thread + main-thread sends (keys registered **before** each send to avoid races); **mixed v4+v6 targets** run both SYN scans **concurrently** (`tokio::join`); falls back to TCP connect per address family on failure |
| Ping scan (`-sn`) | **Implemented** — system `ping` / `ping6` |
| IPv6 (`-6`) | **Implemented** — targets + scans (including raw SYN when privileged) |
| `-iL` / `-iR` | **Implemented** |
| `--resume` | **Implemented** — JSON checkpoint of completed `(host, port)`; applies to TCP connect, UDP, and **raw SYN** (SYN scans only the remaining pairs after the checkpoint) |
| `--traceroute` | **Implemented** — system `traceroute` / `tracert` |
| `-O` / `-A` OS | **Heuristic** — ICMP TTL bucket guess (+ ping after TCP scan when not `-sn`) |
| `--script` / `-sC` | **Partial** — `default` / `banner` builtins; Lua NSE **not** embedded |
| `--iflist` | **Implemented** — lists interfaces via `if-addrs` |
| `--host-timeout` | **Implemented** — per-host wall clock from first probe; remaining ports marked `filtered` with reason `host-timeout` (TCP connect, UDP, raw SYN; mixed v4+v6 SYN share one per-`IpAddr` clock) |
| `--max-rate` | **Implemented** — global cap on probe **starts** per second (TCP connect, UDP, raw SYN; mixed IPv4+IPv6 SYN share one limiter) |
| `--min-rate` | **Not implemented** — ignored with a warning |
| Port specs (`-p`, `-F`, `--top-ports`, …) | **Implemented** — embedded TCP frequency list |
| Output (`-oN`, `-oG`, `-oX`, `-oA`) | **Implemented** — XML minimal; `-oS` ignored with warning |

If you need **authoritative** Nmap NSE/OS DB behavior, use **[Nmap](https://nmap.org/)**.

## Build

```bash
cargo build --release
```

Binary: `target/release/nmaprs`

## Help (`-h` / `--help`)

Combined flags like `-sT`, `-Pn`, `-PS80`, `-T4` are expanded before parsing.

## Examples

```bash
# TCP connect — top ports from embedded frequency table
nmaprs scanme.nmap.org

# Ping scan (no port scan)
nmaprs -sn scanme.nmap.org

# UDP top ports
nmaprs -sU --top-ports 100 target

# Targets from file + resume
nmaprs -iL hosts.txt --resume state.json -oN out.txt

# IPv6
nmaprs -6 -p 80,443 2001:db8::/126
```

## Tests

```bash
cargo test
```

## Benchmarks

```bash
cargo bench --bench scan
```

## Architecture

1. **Argv expansion** (`src/argv_expand.rs`) normalizes glued nmap tokens before `clap`.
2. **Plan** (`src/config.rs`) → `ScanPlan`.
3. **Targets** (`src/target.rs`, `src/lib.rs` `expand_specs_ordered`) — IPv4/IPv6, CIDR, nmap-style IPv4 ranges, DNS, `-iL`, `-iR`; **parallel** `expand_target` with stable ordering.
4. **Scan** (`src/scan.rs`, `src/syn.rs`, `src/icmp_listen.rs`, `src/ipv6_l4.rs`) — TCP connect / UDP (+ parallel ICMP + ICMPv6 listeners for port-unreachable) / raw IPv4 + IPv6 SYN (recv thread pipelined with sends).
5. **Ping** (`src/ping.rs`), **trace** (`src/trace.rs`), **resume** (`src/resume.rs`), **NSE builtins** (`src/nse.rs`), **OS guess** (`src/os_detect.rs`).
6. **Output** (`src/output.rs`).

## Data

`data/top_ports.txt` — regenerate with `bash scripts/fetch_top_ports.sh`.

## License

Licensed under either of **Apache License, Version 2.0** or **MIT** at your option.

## Legal / ethics

Only scan networks you own or are authorized to test.

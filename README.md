```
╔══════════════════════════════════════════════════════════════════╗
║  N M A P R S   //   R U S T   G R I D   S C A N N E R            ║
║  neon wire · parallel sockets · nmap-shaped CLI                   ║
╚══════════════════════════════════════════════════════════════════╝
```

# nmaprs

**nmaprs** is a Rust-native network scanner that speaks **nmap’s CLI dialect** (see `nmap --help`) and runs **highly parallel** scan engines (`tokio` + `futures::stream` + bounded concurrency). Multiple `-iL` lines and CLI targets resolve **in parallel** (order preserved) with the same **`--max-parallelism` / `--min-parallelism` / timing template** cap as port probes. It is **not** a byte-for-byte reimplementation of Nmap: the full **NSE Lua runtime**, **Nmap OS fingerprint database**, and **every** obscure probe path are not embedded. This tool implements **real** TCP connect, UDP probes, ICMP ping discovery, raw IPv4/IPv6 half-open TCP including SYN / NULL / FIN / Xmas / ACK (privileged), target list / random hosts, IPv6, resume checkpoints, traceroute, TTL-based OS **heuristics**, and **built-in** Rust “scripts” (banner grab) for `--script` / `-sC`.

Created by **MenkeTechnologies**.

## Truth table (read this)

| Area | Status |
|------|--------|
| TCP connect (`-sT`, default) | **Implemented** — async, parallel, timeout-bound |
| UDP (`-sU`) | **Implemented** — reply → `open`; short post-timeout window for ICMP; raw listeners (privileged) classify **destination unreachable** probes: **port unreachable** → `closed`; **other unreachable codes** → `filtered` (IPv4 type 3 / ICMPv6 type 1); **Unix** uses one `poll(2)`+burst-recv thread when both IPv4 and IPv6 targets; `closed` wins over `filtered`. With `--min-hostgroup` / `--max-hostgroup`, ICMP listener threads are started **once** for the whole scan (not per batch) |
| Raw half-open TCP (`-sS` SYN, `-sN` NULL, `-sF` FIN, `-sX` Xmas) | **Implemented** — raw IPv4 + **separate** raw IPv6 TCP path via `pnet` — **requires privileges**; RST→`closed`, SYN/ACK→`open`; **pipelined** per family: dedicated recv thread + main-thread sends (keys registered **before** each send to avoid races); work is **sharded** across up to **16** concurrent pipelines per family (bounded by `effective_probe_concurrency()`); **mixed v4+v6 targets** run both families **concurrently** (`tokio::join`); falls back to TCP connect per address family on raw failure |
| TCP ACK scan (`-sA`) | **Implemented** — same raw sharded pipeline; RST→`unfiltered`, no reply→`filtered` (Nmap-style firewall mapping); **no** TCP connect fallback on raw failure (connect would not produce ACK-scan states) |
| Ping scan (`-sn`) | **Implemented** — system `ping` / `ping6` |
| Host discovery (before port scan) | **Implemented** — skipped with `-Pn` / `--no-ping`. **Default** runs **ICMP echo** in parallel with **raw TCP SYN** to **443** and **80** (same engine as `-sS`); **RST/SYN-ACK** ⇒ up; falls back to **TCP connect** if raw fails. **`-PS`**: raw SYN; **`-PA`**: raw TCP **ACK** probes (RST/SYN-ACK), same sharded pipelines + connect fallback. **`-PU`** (default **40125**): UDP / ICMP-style socket errors. **`connect_timeout`** applies to TCP/UDP waits. `-PP`, `-PM`, `-PY`, `-PO` ignored with warning |
| IPv6 (`-6`) | **Implemented** — targets + scans (including raw SYN when privileged) |
| `-iL` / `-iR` | **Implemented** |
| `--resume` | **Implemented** — JSON checkpoint of completed `(host, port)`; applies to TCP connect, UDP, and **raw half-open TCP** (SYN/NULL/FIN/Xmas only the remaining pairs after the checkpoint) |
| `--traceroute` | **Implemented** — system `traceroute` / `tracert` |
| `-O` / `-A` OS | **Heuristic** — ICMP TTL bucket guess (+ ping after TCP scan when not `-sn`) |
| `--script` / `-sC` | **Partial** — `default` / `banner` builtins; Lua NSE **not** embedded |
| `--iflist` | **Implemented** — lists interfaces via `if-addrs` |
| `--host-timeout` | **Implemented** — per-host wall clock from first probe; remaining ports marked `filtered` with reason `host-timeout` (TCP connect, UDP, raw half-open TCP; mixed v4+v6 share one per-`IpAddr` clock) |
| `--max-retries` | **Implemented** — extra attempts after **probe timeout** (total tries = `1 + N`) for TCP connect, UDP, and raw half-open TCP (retry rounds omit scan-delay / rate pacer like TCP retries) |
| `--min-rtt-timeout` | **Implemented** — lower bound on per-probe wait (`connect_timeout = max(..., min)`); applies to TCP connect, UDP, and raw half-open TCP probe timeout. When both `--max-rtt-timeout` and `--min-rtt-timeout` are set, `max` must be `≥` `min` |
| `--scan-delay` / `--max-scan-delay` | **Implemented** — per-probe delay before send/connect: fixed `scan-delay`, or uniform random in `[scan-delay, max-scan-delay]` when both set; TCP (first attempt), UDP, raw half-open TCP; `max` must be `>=` `min` |
| `--max-rate` | **Implemented** — global cap on probe **starts** per second (TCP connect, UDP, raw half-open TCP; mixed IPv4+IPv6 share one limiter) |
| `--min-rate` | **Implemented** — must be ≤ `--max-rate` when both are set (probe starts/sec); `--max-rate` still caps probe starts via the global pacer. Without `--max-parallelism`, TCP/UDP/ping/target expansion parallelism is raised toward `min(min-rate, 65535)` when that exceeds the timing template so the floor is reachable; with `--max-parallelism`, that cap wins and a warning is emitted if min-rate is still higher (raw half-open TCP uses the same pacer) |
| `--min-hostgroup` / `--max-hostgroup` | **Implemented** — splits the resolved host list into batches before port work is built; omitting both scans all hosts in one batch. If only one is set, the other defaults to **1** or **1024** (Nmap-style). When both differ, batch sizes are uniform random in `[min, max]` (last batch may be smaller). `--resume` still filters per batch and merges once at the end |
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
4. **Discovery** (`src/discovery.rs`) — before port scan (unless `-Pn`); default ICMP + raw SYN (`syn.rs`) run concurrently; `-PS` raw SYN, `-PA` connect, `-PU` UDP; `connect_timeout` from `--min-rtt-timeout` / timing template.
5. **Scan** (`src/scan.rs`, `src/syn.rs`, `src/icmp_listen.rs`, `src/ipv6_l4.rs`) — optional `--min-hostgroup` / `--max-hostgroup` batching in `src/lib.rs` (`host_batches`); UDP ICMP listeners are **one session per scan** (shared `DashMap` across batches). TCP connect / UDP / ping use `futures::stream` + `buffer_unordered(effective concurrency)` (single cap; no duplicate semaphores) / raw IPv4 + IPv6 half-open TCP (SYN, NULL, FIN, Xmas: recv thread pipelined with sends; optional multi-shard parallel pipelines per family).
6. **Ping** (`src/ping.rs`), **trace** (`src/trace.rs`), **resume** (`src/resume.rs`), **NSE builtins** (`src/nse.rs`), **OS guess** (`src/os_detect.rs`).
7. **Output** (`src/output.rs`).

## Data

`data/top_ports.txt` — regenerate with `bash scripts/fetch_top_ports.sh`.

## License

Licensed under either of **Apache License, Version 2.0** or **MIT** at your option.

## Legal / ethics

Only scan networks you own or are authorized to test.

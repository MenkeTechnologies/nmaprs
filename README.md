```
╔══════════════════════════════════════════════════════════════════╗
║  N M A P R S   //   R U S T   G R I D   S C A N N E R            ║
║  neon wire · parallel sockets · nmap-shaped CLI                   ║
╚══════════════════════════════════════════════════════════════════╝
```

# nmaprs

**nmaprs** is a Rust-native network scanner that speaks **nmap’s CLI dialect** (`nmap --help` **plus** the long-option set from upstream **`nmap.cc`**, e.g. `--resolve-all`, `--defeat-rst-ratelimit`, `--versiondb`, `--oM` / `--oH`, `--vv`, `--proxy` as an alias of `--proxies`). **Evasion flags** (`-g` source port, `--ttl`, `--badsum`, `-D` decoys, `-S` source spoofing, `--data`/`--data-string`/`--data-length`, `-f`/`--mtu` fragmentation) are **wired at the packet level** for raw TCP scans. **`--proxies`** routes TCP connect scans through SOCKS4 or HTTP CONNECT proxies; **`--dns-servers`** resolves targets via custom DNS servers (**hickory-resolver**); **`--spoof-mac`** spoofs the source MAC on ARP discovery frames; **`--stats-every`** prints periodic scan progress with ETC and probes/sec. Multiple `-iL` lines and CLI targets resolve **in parallel** (order preserved) with the same **`--max-parallelism` / `--min-parallelism` / timing template** cap as port probes. It is **not** a byte-for-byte reimplementation of Nmap: the full **NSE Lua runtime** is **not** embedded. **IPv4 `-O`** runs raw TCP/IP probes (SEQ/OPS/WIN subset plus extras in progress), builds a subject fingerprint, and scores **`nmap-os-db`** reference entries with **MatchPoints** + **expr_match** (not every Nmap probe or field is implemented yet). With Nmap’s **`nmap-service-probes`** and **`nmap-os-db`** files under `--datadir` (default `./data`), **`-sV`** runs TCP and UDP probes with `ports` / `sslports` filtering, `tls` (**rustls**) for probe `sslports`, `rarity` vs `--version-intensity`, and `match` / `softmatch` handling (Rust `regex`; Perl-only patterns skipped). **`-O`** falls back to ICMP TTL heuristics and example DB titles when raw probes or matching are unavailable. This tool implements **real** TCP connect, UDP probes, ICMP ping discovery, raw IPv4/IPv6 half-open TCP including SYN / NULL / FIN / Xmas / ACK / Window / Maimon (privileged), target list / random hosts, IPv6, resume checkpoints, traceroute, and **built-in** Rust “scripts” (banner grab) for `--script` / `-sC`.

Created by **MenkeTechnologies**.

## Truth table (read this)

| Area | Status |
|------|--------|
| TCP connect (`-sT`, default) | **Implemented** — async, parallel, timeout-bound |
| FTP bounce (`-b user:pass@host:port`) | **Implemented** — parallel `buffer_unordered` sessions (one control connection per probe); **IPv4 targets only** (`PORT`); maps typical `150`/`125`/`250` vs `425`/`426`/`421` to open/closed; misconfigured or strict servers may yield `filtered` |
| SCTP (`-sY` INIT, `-sZ` COOKIE_ECHO) | **Implemented (IPv4 + IPv6)** — CRC32c SCTP segments; **IPv4** Layer3 full datagrams; **IPv6** raw SCTP (protocol **132**) like IPv6 TCP; pipelined recv + up to **16** shards per family; **mixed v4+v6** runs both engines **concurrently** (`tokio::join`); INIT-ACK / COOKIE-ACK ⇒ `open`, ABORT ⇒ `closed`; **privileged** raw socket |
| Idle scan (`-sI zombie[:probeport]`) | **Implemented (IPv4)** — spoofed TCP SYN (source = zombie) toward targets; **sequential** IP-ID sampling on the zombie (RST to a **closed** probe port, default **65535**) so global IP-ID deltas stay interpretable; **delta ≥ 2** ⇒ `open`, else `closed`; probe/RST failures ⇒ `filtered` (`idle-probe-failed`). **Privileged** raw send; **IPv6 targets skipped** with warning; **not** a substitute for Nmap’s full idle heuristics on odd stacks |
| UDP (`-sU`) | **Implemented** — reply → `open`; short post-timeout window for ICMP; raw listeners (privileged) classify **destination unreachable** probes: **port unreachable** → `closed`; **other unreachable codes** → `filtered` (IPv4 type 3 / ICMPv6 type 1); **Unix** uses one `poll(2)`+burst-recv thread when both IPv4 and IPv6 targets; `closed` wins over `filtered`. With `--min-hostgroup` / `--max-hostgroup`, ICMP listener threads are started **once** for the whole scan (not per batch) |
| IP protocol (`-sO`) | **Implemented (IPv4 + IPv6 on Unix)** — **IPv4**: raw IPv4 headers; ICMPv4 **protocol unreachable** (type 3 code 2) ⇒ `closed`. **IPv6** (Unix): raw IPv6 (`IPPROTO_RAW` + `IPV6_HDRINCL`) with Next Header = probe; ICMPv6 **Parameter Problem** type 4 code 1 (unrecognized Next Header) with embedded IPv6 ⇒ `closed`; **not** supported on non-Unix (error if IPv6 targets only). Timeout ⇒ `filtered`. **Mixed v4+v6** runs both engines **concurrently** (`tokio::join`); sharded recv + up to **16** pipelines per family. `-p` lists **protocol numbers** `0..=255`; omit `-p` to probe all **256** values. **`-F`** limits protocols to those named in Nmap’s `nmap-protocols` list (embedded as `data/nmap_ip_protocols_fast.txt`), matching Nmap’s `[P:0-]` fast selection. Does not classify rare “open” (non-ICMP) responses |
| `--scan-type` `O` / `I` | **Rejected at plan time** — IP protocol scan is **`-sO` / `--sO`**; idle scan is **`-sI` / `--sI`** with a zombie target. `--scan-type` is only for scan **letters** such as `T` `S` `U` `N` `F` `X` `A` `W` `M` `Y` `Z` |
| Raw half-open TCP (`-sS` SYN, `-sN` NULL, `-sF` FIN, `-sX` Xmas, `-sM` Maimon) | **Implemented** — raw IPv4 + **separate** raw IPv6 TCP path via `pnet` — **requires privileges**; RST→`closed`, SYN/ACK→`open` (Maimon sends FIN+ACK); **pipelined** per family: dedicated recv thread + main-thread sends (keys registered **before** each send to avoid races); work is **sharded** across up to **16** concurrent pipelines per family (bounded by `effective_probe_concurrency()`); **mixed v4+v6 targets** run both families **concurrently** (`tokio::join`); falls back to TCP connect per address family on raw failure |
| TCP ACK scan (`-sA`) | **Implemented** — same raw sharded pipeline; RST→`unfiltered`, no reply→`filtered` (Nmap-style firewall mapping); **no** TCP connect fallback on raw failure (connect would not produce ACK-scan states) |
| TCP window scan (`-sW`) | **Implemented** — same ACK probes as `-sA`; RST with non-zero TCP window→`open`, RST with zero window→`closed` (typical BSD-derived stacks); no reply→`filtered`; **no** TCP connect fallback on raw failure |
| Combined scan types (`-sS -sU`) | **Implemented** — multiple scan types run sequentially in one pass (e.g. SYN + UDP simultaneously) |
| Ping scan (`-sn`) | **Implemented** — raw ICMP echo via `pnet` (privileged), falls back to system `ping`/`ping6`; **`-oN` / `-oG` / `-oX` / `-oS`** write host-up lines (and `-oS` skiddie text) like the port-scan path |
| Host discovery (before port scan) | **Implemented** — skipped with `-Pn` / `--no-ping`. **ARP ping** (`-PR`) auto-runs for **local-subnet IPv4** hosts (disable with `--disable-arp-ping`). **Default** runs **raw ICMP echo** in parallel with **raw TCP SYN** to **443** and **80** (same engine as `-sS`); **RST/SYN-ACK** ⇒ up; falls back to **TCP connect** if raw fails. **`-PS`**: raw SYN; **`-PA`**: raw TCP **ACK** probes (RST/SYN-ACK), same sharded pipelines + connect fallback. **`-PU`** (default **40125**): UDP / ICMP-style socket errors. **`-PY`**: SCTP **INIT** (default port **80**), same raw SCTP engines as `-sY`; INIT-ACK/ABORT ⇒ up; **privileged**; IPv4/IPv6 merged independently on partial failure. **`-PO`**: IP protocol ping (default protocols **1,2,4**), same engines as `-sO`; host **up** if any probe is **open** or **closed**; **privileged**; IPv4/IPv6 merged independently on partial failure. **`-PP`** / **`-PM`**: ICMP **timestamp** and **address mask** requests (IPv4 only, **Unix** raw ICMP); **timestamp reply** / **mask reply** ⇒ up; **`connect_timeout`** applies to TCP/UDP/SCTP/IP-proto waits and to these ICMP probes; non-Unix builds skip `-PP`/`-PM` with a warning |
| IPv6 (`-6`) | **Implemented** — targets + scans (including raw SYN when privileged) |
| `-iL` / `-iR` | **Implemented** |
| `--resume` | **Implemented** — JSON checkpoint of completed `(host, port)`; applies to TCP connect, UDP, **raw half-open TCP**, and **IP protocol (`-sO`)** (remaining pairs only after the checkpoint) |
| `--traceroute` | **Implemented** — system `traceroute` / `tracert`; hosts run **concurrently** up to **`min(effective parallelism, 32)`** subprocesses, stdout/stderr printed in **target order** |
| `-O` | **Partial** — **IPv4** (privileged): raw Layer3 probes + **`nmap-os-db`** MatchPoints scoring when **`--datadir`** has the DB and the scan found **open** and **closed** TCP ports (and not **`--osscan-limit`** with no open TCP). Falls back to ICMP TTL + example **Class** titles from the legacy DB parse. **IPv6**: TTL-style guess only (no raw OS probe engine yet) |
| `-A` | **Implemented** — Nmap-style bundle: **`-O`** + **`-sV`** + default **`-sC`** scripts + **`--traceroute`**; not full Nmap NSE/Lua |
| `-sV` / `--version-scan` | **Partial** — loads `nmap-service-probes`: **TCP** + **UDP** `Probe` blocks, **`ports`** / **`sslports`** (TLS via **rustls** when the port matches the probe’s `sslports`), **`rarity`** vs `--version-intensity`, **`match`** / **`softmatch`** with full template fields: **`p/`** (product), **`v/`** (version), **`i/`** (info), **`o/`** (OS), **`d/`** (device type), **`cpe:/`** (CPE URIs); **Perl-only** regex features omitted; parallel per open port |
| `--script` / `-sC` | **Partial** — `default` / `banner` builtins; Lua NSE **not** embedded |
| `--iflist` | **Implemented** — lists interfaces via `if-addrs` |
| `--host-timeout` | **Implemented** — per-host wall clock from first probe; remaining ports marked `filtered` with reason `host-timeout` (TCP connect, UDP, raw half-open TCP, **IP protocol scan**; mixed v4+v6 share one per-`IpAddr` clock) |
| `--max-retries` | **Implemented** — extra attempts after **probe timeout** (total tries = `1 + N`) for TCP connect, UDP, raw half-open TCP, **IP protocol (`-sO`)**, **FTP bounce**, **SCTP**, and **idle scan** (retry rounds omit scan-delay / rate pacer like TCP retries) |
| `--min-rtt-timeout` | **Implemented** — lower bound on per-probe wait (`connect_timeout = max(..., min)`); applies to TCP connect, UDP, raw half-open TCP, and **IP protocol (`-sO`)** probe timeout. When both `--max-rtt-timeout` and `--min-rtt-timeout` are set, `max` must be `≥` `min` |
| `--scan-delay` / `--max-scan-delay` | **Implemented** — per-probe delay before send/connect: fixed `scan-delay`, or uniform random in `[scan-delay, max-scan-delay]` when both set; TCP (first attempt), UDP, raw half-open TCP, **IP protocol (`-sO`)**; `max` must be `>=` `min` |
| `--max-rate` | **Implemented** — global cap on probe **starts** per second (TCP connect, UDP, raw half-open TCP, **SCTP**, **IP protocol (`-sO`)**; mixed IPv4+IPv6 share one limiter) |
| `--min-rate` | **Implemented** — must be ≤ `--max-rate` when both are set (probe starts/sec); `--max-rate` still caps probe starts via the global pacer. Without `--max-parallelism`, TCP/UDP/ping/target expansion parallelism is raised toward `min(min-rate, 65535)` when that exceeds the timing template so the floor is reachable; with `--max-parallelism`, that cap wins and a warning is emitted if min-rate is still higher (raw half-open TCP, **SCTP**, and **IP protocol (`-sO`)** use the same pacer) |
| `--min-hostgroup` / `--max-hostgroup` | **Implemented** — splits the resolved host list into batches before port work is built; omitting both scans all hosts in one batch. If only one is set, the other defaults to **1** or **1024** (Nmap-style). When both differ, batch sizes are uniform random in `[min, max]` (last batch may be smaller). `--resume` still filters per batch and merges once at the end |
| `--scanflags` | **Implemented** — custom TCP flag set for **raw** TCP scans (`-sS` / `-sN` / `-sF` / `-sX` / `-sM` / `-sA` / `-sW`); names `SYN` `ACK` `FIN` `RST` `PSH` `URG` `ECE` `CWR` (space, comma, pipe, or glued e.g. `SYNACK`); sequence/ack numbers follow Nmap-style rules for SYN vs ACK probes; recv classification still follows the selected scan type; **ignored** (with warning) if the scan type is not raw TCP |
| Port specs (`-p`, `-F`, `--top-ports`, …) | **Implemented** — embedded TCP frequency list; **`-p -`** shorthand for all 65536 ports |
| Evasion (`-g`, `--ttl`, `--badsum`, `-D`, `-S`, `--data*`, `-f`/`--mtu`, `--spoof-mac`) | **Implemented** — source port, TTL, bad checksum, decoys, source IP spoofing, custom data payload, fragmentation MTU are **wired into raw TCP packet construction** (IPv4 SYN/NULL/FIN/Xmas/ACK/Window/Maimon); **`--spoof-mac`** applies to ARP discovery frames |
| `--proxies` / `--proxy` | **Implemented** — SOCKS4 and HTTP CONNECT proxy support for TCP connect scans; comma-separated proxy URLs |
| `--dns-servers` | **Implemented** — custom DNS resolver addresses (comma-separated IPs); uses **hickory-resolver** for target resolution instead of system resolver |
| Auto privilege detection | **Implemented** — auto-detects root/sudo via `geteuid()`; falls back from SYN to TCP connect when unprivileged (use `--privileged` to force) |
| Output (`-oN`, `-oG`, `-oX`, `-oA`, `-oS`) | **Implemented** — XML uses nmap-compatible `<nmaprun>` root with `<scaninfo>`, `<host>`, `<status>`, `<address>`, `<hostnames>`, `<ports>`, `<extraports>`, `<service>`, `<runstats>`; **`-oS`** writes script-kiddie text mirroring `-oN` lines (stdout stays normal); works for **`-sn`** as well as port scans |
| `-oM` / `-oH` | **Partial** — **`-oM`** writes the same grepable-style machine lines as **`-oG`**; **`-oH`** creates a placeholder file (full hex capture not implemented) |
| `--stylesheet` / `--webxml` / `--no-stylesheet` | **Partial** — XML preamble / `xml-stylesheet` PI when `-oX` is used |
| `--resolve-all` | **Implemented** — forward DNS returns **one** address by default (Nmap “first only”); **`--resolve-all`** scans every resolved address |
| `--unprivileged` / `--privileged` | **Implemented** — **auto-detects** privilege level via `geteuid()`; unprivileged mode forces **TCP connect** instead of raw half-open TCP; rejects raw-only modes (`-sO`, `-sI`, SCTP). **`--privileged`** forces raw mode even when not root |
| `--allports` | **Implemented** — ignores **`--exclude-ports`** when set |
| `--max-os-tries`, `--osscan-limit`, `--osscan-guess` / `--fuzzy` | **Partial** — limits OS DB example titles / skips OS pass when **`--osscan-limit`** and no open TCP ports; full multi-round OS retry not implemented |
| `--script-timeout` | **Partial** — applies to built-in script TCP connects |
| `--stats-every` | **Implemented** — periodic scan progress to stderr (% done, ETC, probes/sec); per-probe granularity for TCP connect |

If you need **authoritative** Nmap NSE/OS DB behavior, use **[Nmap](https://nmap.org/)**.

## Build

```bash
cargo build --release
```

Binaries: `target/release/nmaprs` and `target/release/nms` (same CLI and behavior; `nms` is a short alias).

## Zsh completion

`completions/_nmaprs` completes **`nmaprs`** and **`nms`**. Add the repo’s `completions` directory to **`fpath`** before **`compinit`** (e.g. in `~/.zshrc`):

```zsh
fpath+=("$HOME/path/to/nmaprs/completions")
autoload -Uz compinit && compinit
```

Or symlink `_nmaprs` into a directory already on **`fpath`**.

## Help (`-h` / `--help`)

Combined flags like `-sT`, `-Pn`, `-PS80`, `-T4` are expanded before parsing.

`-h` / `--help` prints a custom screen styled like **`tp`** ([temprs](https://github.com/MenkeTechnologies/temprs) `CYBERPUNK_TEMPLATE`): cyan section rules and box, magenta banner accents and tagline, yellow `USAGE` / copyright line, green `//` column, red/magenta/cyan ASCII bands. On a **non-TTY** or when **`NO_COLOR`** is set, escapes are omitted.

## Examples

```bash
# TCP connect — top ports from embedded frequency table
nmaprs scanme.nmap.org
# same as: nms scanme.nmap.org

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

### nmaprs vs nmap (wall clock)

All runs on **127.0.0.1**, TCP connect (`-sT`), `-n -Pn`, `--min-rtt-timeout 50ms`, `--max-retries 0`, output to `/dev/null`. Measured with **[hyperfine](https://github.com/sharkdp/hyperfine)** (warmup + 10–30 runs). macOS arm64, nmap 7.99.

#### By port count (M=256)

| Test | nmap | nmaprs | Speedup |
|------|------|--------|---------|
| 2 ports (`-p 80,443`) | 12.3 ms | 2.4 ms | **5.1× faster** |
| 3 closed high ports (65533–65535) | 12.6 ms | 2.7 ms | **4.6× faster** |
| `-F` (fast, ~100 ports) | 15.4 ms | 5.6 ms | **2.8× faster** |
| `--top-ports 100` | 15.9 ms | 5.4 ms | **2.9× faster** |
| `--top-ports 1000` | 40.3 ms | 23.7 ms | **1.7× faster** |
| `-p-` (all 65535) | 1.81 s | 1.15 s | **1.6× faster** |

#### By parallelism (`--top-ports 1000`)

| Parallelism | nmap | nmaprs | Speedup |
|-------------|------|--------|---------|
| M=64 | 39.1 ms | 19.2 ms | **2.0× faster** |
| M=256 | 40.3 ms | 23.7 ms | **1.7× faster** |

#### By parallelism (`-p-`, all 65535)

| Parallelism | nmap | nmaprs | Speedup |
|-------------|------|--------|---------|
| M=256 | 1.81 s | 1.15 s | **1.6× faster** |
| M=1024 | 1.82 s | 1.21 s | **1.5× faster** |

#### By output format (`--top-ports 100`, M=256)

| Output | nmap | nmaprs | Speedup |
|--------|------|--------|---------|
| `-oN` | 15.9 ms | 5.4 ms | **2.9× faster** |
| `-oG` | 15.8 ms | 6.1 ms | **2.6× faster** |
| `-oX` | 15.8 ms | 6.0 ms | **2.6× faster** |

#### Ping scan (`-sn`, no `-Pn`)

| Test | nmap | nmaprs | Speedup |
|------|------|--------|---------|
| `-sn 127.0.0.1` | 7.2 ms | 4.9 ms | **1.5× faster** |

#### Analysis

nmaprs is **1.5–5.1× faster** across all port counts. Small scans (2–100 ports) see the largest gains (**3–5×**) because nmap's startup overhead (Lua/NSE, libpcap, service databases) dominates. Full 65535-port sweeps show **1.5–1.6×** speedup thanks to a worker-pool architecture with blocking `std::net::TcpStream::connect_timeout` (fewer syscalls than tokio async — no per-socket `ioctl`/`fcntl` non-blocking setup) plus lock-free `UnsafeCell` result slots indexed by atomic work counter. Ping scan shows **1.5×** improvement. Output format has negligible impact on either tool.

### Criterion (Rust internals)

TCP connect scan to three closed localhost ports — measures pure scan-loop overhead:

```
tcp_connect_scan_localhost_3_ports  time: [74.0 µs 77.4 µs 81.7 µs]
```

### Running benchmarks

```bash
# Criterion microbenchmark
cargo bench --bench scan

# vs nmap (requires nmap + hyperfine on PATH)
cargo build --release
./scripts/benchmark_vs_nmap.sh
```

## Architecture

1. **Argv expansion** (`src/argv_expand.rs`) normalizes glued nmap tokens before `clap`.
2. **Plan** (`src/config.rs`, `src/scanflags.rs`) → `ScanPlan` (optional `--scanflags` TCP byte for raw scans).
3. **Targets** (`src/target.rs`, `src/lib.rs` `expand_specs_ordered`) — IPv4/IPv6, CIDR, nmap-style IPv4 ranges, DNS, `-iL`, `-iR`; **parallel** `expand_target` with stable ordering.
4. **Discovery** (`src/discovery.rs`, `src/icmp_ping.rs`) — before port scan (unless `-Pn`); default ICMP + raw SYN (`syn.rs`) run concurrently; `-PS` raw SYN, `-PA` connect, `-PU` UDP, `-PY` SCTP, `-PO` IP protocol (`ip_proto.rs`), `-PP`/`-PM` legacy ICMP on Unix (`icmp_ping.rs`); `connect_timeout` from `--min-rtt-timeout` / timing template.
5. **Scan** (`src/scan.rs`, `src/syn.rs`, `src/sctp.rs`, `src/ip_proto.rs`, `src/ftp_bounce.rs`, `src/icmp_listen.rs`, `src/ipv6_l4.rs`) — optional `--min-hostgroup` / `--max-hostgroup` batching in `src/lib.rs` (`host_batches`); UDP ICMP listeners are **one session per scan** (shared `DashMap` across batches). TCP connect uses a **worker-pool** of `conc` OS threads (blocking `std::net::TcpStream::connect_timeout` — fewer syscalls than async) draining a shared atomic work index into lock-free `UnsafeCell` result slots; falls back to async tokio tasks when `--proxies` are configured. UDP / ping use `tokio::spawn` + `Semaphore` / raw IPv4 + IPv6 half-open TCP + **SCTP** (`-sY`/`-sZ`, CRC32c, IPv4 Layer3 + IPv6 raw SCTP, sharded blocking pool, mixed v4+v6 `tokio::join`) + **IP protocol** (`-sO`: IPv4 ICMP + Unix IPv6 raw + ICMPv6 Parameter Problem, sharded, mixed v4+v6 `tokio::join`) + **FTP bounce** (`-b`, Tokio parallel FTP sessions).
6. **Ping** (`src/ping.rs`), **trace** (`src/trace.rs` — bounded parallel `traceroute` / `tracert`, ordered output), **resume** (`src/resume.rs`), **NSE builtins** (`src/nse.rs`), **OS guess** (`src/os_detect.rs`, `src/os_db.rs`, `src/os_fp_db.rs`, `src/os_scan.rs`, `src/fp_match.rs`), **version scan** (`src/vscan.rs`), **script-kiddie output** (`src/skiddie.rs`).
7. **Output** (`src/output.rs`) — optional **`-oM`** / **`-oH`**, XML stylesheet options.

## Data

`data/top_ports.txt` — regenerate with `bash scripts/fetch_top_ports.sh`.

`data/nmap_ip_protocols_fast.txt` — one IP protocol number per line (from Nmap’s `nmap-protocols`: entries `0..=255` with a registered name, plus `253` and `254`). Regenerate with:

`curl -sL https://raw.githubusercontent.com/nmap/nmap/master/nmap-protocols | awk '!/^#/ && !/^$/ {for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) {print $i+0; break}}' | sort -n -u`

**`-sV`** / **`-O`** (optional, large upstream files): place Nmap’s `nmap-service-probes` and `nmap-os-db` under `./data/` or pass **`--datadir DIR`**. Fetch both in one step:

`bash scripts/fetch_nmap_data.sh`

Those files are **not** committed; without them, **`-sV`** logs a warning and **`-O`** uses TTL-only heuristics (no DB titles, no fingerprint match).

### OS fingerprint probes (partial)

**IPv4** loads a single **`FingerprintDb`** from **`nmap-os-db`** (`MatchPoints`, `Fingerprint`, `Class`), sends Nmap 2nd-gen probes **SEQ×6, ECN, T2–T7, U1, IE×2** from **`src/os_scan.rs`** (raw IPv4 Layer3 + ICMP), builds **SEQ/OPS/WIN/ECN/T1–T7/U1/IE** subject tests, and scores against all reference entries with **`expr_match`** (C++ FFI in **`c/expr_match.cpp`**). Real IPID classification (Z/I/BI/RI/RD) and TS classification (0/1/7/8/U/hex) are implemented; **CI** comes from T5–T7, **II** from IE echo replies, **SS** detects shared IPID sequence. **IPv6** OS detection remains TTL-oriented until a v6 probe path exists.

## License

Licensed under either of **Apache License, Version 2.0** or **MIT** at your option.

## Legal / ethics

Only scan networks you own or are authorized to test.

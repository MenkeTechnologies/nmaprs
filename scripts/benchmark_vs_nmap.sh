#!/usr/bin/env bash
# Compare wall-clock time: nmap vs nmaprs (TCP connect, localhost loopback).
# Requires: nmap, hyperfine (https://github.com/sharkdp/hyperfine), release-built nmaprs.
#
# This is not a feature-parity test — both are asked to do the same *shape* of work:
#   -n -Pn, TCP connect, same port set, ~50ms connect bound, 256-way parallelism,
#   no connect retries, output to /dev/null.
#
# Usage:
#   cargo build --release
#   ./scripts/benchmark_vs_nmap.sh
# Optional:
#   NMAPRS_BIN=path/to/nmaprs NMAP=/path/to/nmap ./scripts/benchmark_vs_nmap.sh

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${NMAPRS_BIN:-$root/target/release/nmaprs}"
nmap_bin="${NMAP:-$(command -v nmap)}"
hf="${HYPERFINE:-$(command -v hyperfine)}"

if [[ ! -x "$bin" ]]; then
  echo "release binary missing: $bin (run: cargo build --release)" >&2
  exit 1
fi
if [[ -z "$nmap_bin" ]]; then
  echo "nmap not found in PATH" >&2
  exit 1
fi
if [[ -z "$hf" ]]; then
  echo "hyperfine not found (brew install hyperfine / cargo install hyperfine)" >&2
  exit 1
fi

echo "=== nmap vs nmaprs (localhost 127.0.0.1, TCP connect) ==="
echo "nmaprs:    $bin"
echo "nmap:      $nmap_bin"
echo "hyperfine: $hf"
echo

cmd_nmap_a="${nmap_bin} -n -Pn -sT -p65533-65535 --min-rtt-timeout 50ms --max-retries 0 --min-parallelism 256 --max-parallelism 256 -T4 -oN /dev/null 127.0.0.1"
cmd_rs_a="${bin} -n -Pn -p 65533-65535 --min-rtt-timeout 50ms --max-retries 0 -M 256 -oN /dev/null 127.0.0.1"

# -N/--shell=none: exec without a shell (stable timings; avoids sub-5ms calibration issues).
echo "--- A: 3 high ports (65533–65535), closed ---"
"$hf" -N --warmup 3 --runs 30 -n nmap "$cmd_nmap_a" -n nmaprs "$cmd_rs_a"
echo

cmd_nmap_b="${nmap_bin} -n -Pn -sT --top-ports 100 --min-rtt-timeout 50ms --max-retries 0 --min-parallelism 256 --max-parallelism 256 -T4 -oN /dev/null 127.0.0.1"
cmd_rs_b="${bin} -n -Pn --top-ports 100 --min-rtt-timeout 50ms --max-retries 0 -M 256 -oN /dev/null 127.0.0.1"

echo "--- B: top 100 TCP ports (embedded frequency list) ---"
"$hf" -N --warmup 2 --runs 25 -n nmap "$cmd_nmap_b" -n nmaprs "$cmd_rs_b"
echo
echo "Done. Results vary by OS, CPU, and Nmap build; compare on your own machine."

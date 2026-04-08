#!/usr/bin/env bash
# Download Nmap upstream nmap-service-probes and nmap-os-db into ./data/ for -sV / -O.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/data"
command mkdir -p "$DATA"
for f in nmap-service-probes nmap-os-db; do
  curl -sL "https://raw.githubusercontent.com/nmap/nmap/master/$f" -o "$DATA/$f"
  echo "Wrote $DATA/$f"
done

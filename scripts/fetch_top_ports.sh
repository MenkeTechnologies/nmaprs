#!/usr/bin/env bash
# Regenerate data/top_ports.txt from upstream nmap-services (TCP, by open-frequency).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/data/top_ports.txt"
command mkdir -p "$root/data"
curl -fsSL "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services" \
  | awk '!/^#/ && NF>=3 && $2 ~ /^[0-9]+\/tcp$/ {
      split($2,a,"/");
      port=a[1];
      freq=$3;
      gsub(/[^0-9.]/,"",freq);
      if (freq=="") next;
      print port, freq
    }' \
  | sort -k2 -nr \
  | head -1000 \
  | awk '{print $1}' \
  > "$out"
wc -l "$out"

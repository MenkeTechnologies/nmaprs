//! Port list resolution: `-p`, `-F`, `--top-ports`, exclusions, and `-sO -F` IP protocol subsets.

use std::collections::HashSet;
use std::sync::OnceLock;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PortParseError {
    #[error("invalid port token: {0}")]
    InvalidToken(String),
    #[error("empty port specification")]
    Empty,
}

static TOP_PORTS: OnceLock<Vec<u16>> = OnceLock::new();
static FAST_IP_PROTOCOLS_NMAP: OnceLock<Vec<u16>> = OnceLock::new();

fn load_top_ports() -> &'static [u16] {
    TOP_PORTS.get_or_init(|| {
        include_str!("../data/top_ports.txt")
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    })
}

/// Top *n* TCP ports by nmap `nmap-services` frequency order (embedded list).
pub fn top_ports(n: usize) -> Vec<u16> {
    load_top_ports().iter().take(n).copied().collect()
}

/// Number of ranked TCP ports available in the embedded frequency table.
pub fn top_ports_len() -> usize {
    load_top_ports().len()
}

/// Default scan set: top 1000 TCP ports (matches common nmap default intent).
pub fn default_tcp_ports() -> Vec<u16> {
    top_ports(1000)
}

/// Fast scan (`-F`): top 100 TCP ports (nmap semantics).
pub fn fast_tcp_ports() -> Vec<u16> {
    top_ports(100)
}

fn load_fast_ip_protocols_nmap() -> &'static [u16] {
    FAST_IP_PROTOCOLS_NMAP.get_or_init(|| {
        include_str!("../data/nmap_ip_protocols_fast.txt")
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| {
                let t = l.trim();
                if t.is_empty() {
                    return None;
                }
                t.parse::<u16>().ok().filter(|&n| n <= 255)
            })
            .collect()
    })
}

/// IP protocol numbers listed in Nmap’s `nmap-protocols` database (embedded copy in
/// `data/nmap_ip_protocols_fast.txt`). Used for **`-sO -F`**, matching Nmap’s nested `[P:0-]`
/// selection (only protocols with a registered name).
pub fn fast_ip_protocols_nmap() -> Vec<u16> {
    load_fast_ip_protocols_nmap().to_vec()
}

fn parse_single_range(token: &str, out: &mut Vec<u16>) -> Result<(), PortParseError> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(());
    }
    if let Some((a, b)) = token.split_once('-') {
        let start: u16 = a
            .parse()
            .map_err(|_| PortParseError::InvalidToken(token.to_string()))?;
        let end: u16 = b
            .parse()
            .map_err(|_| PortParseError::InvalidToken(token.to_string()))?;
        if start > end {
            return Err(PortParseError::InvalidToken(token.to_string()));
        }
        out.extend(start..=end);
        return Ok(());
    }
    let p: u16 = token
        .parse()
        .map_err(|_| PortParseError::InvalidToken(token.to_string()))?;
    out.push(p);
    Ok(())
}

/// Parse `-p` expression for TCP-only scanning (U:T:,S: prefixes are filtered to TCP lanes later).
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, PortParseError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(PortParseError::Empty);
    }
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // nmap-style T:80,U:53 — we only collect TCP side for this scanner
        if let Some(rest) = part.strip_prefix("T:") {
            parse_single_range(rest, &mut out)?;
            continue;
        }
        if let Some(rest) = part.strip_prefix("U:") {
            // UDP requested — still parse numbers but caller may reject if no UDP scan
            parse_single_range(rest, &mut out)?;
            continue;
        }
        if let Some(rest) = part.strip_prefix("S:") {
            parse_single_range(rest, &mut out)?;
            continue;
        }
        parse_single_range(part, &mut out)?;
    }
    if out.is_empty() {
        return Err(PortParseError::Empty);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub fn parse_exclude_ports(spec: &str) -> Result<HashSet<u16>, PortParseError> {
    let v = parse_port_spec(spec)?;
    Ok(v.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_lists() {
        let p = parse_port_spec("22,80-82,443").unwrap();
        assert_eq!(p, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn top_100_non_empty() {
        assert_eq!(fast_tcp_ports().len(), 100);
    }

    #[test]
    fn fast_ip_protocols_sorted_unique_in_range() {
        let v = fast_ip_protocols_nmap();
        assert!(v.len() > 1, "embedded nmap IP protocol list must not be empty");
        for w in v.windows(2) {
            assert!(w[0] < w[1], "expected sorted unique list");
        }
        assert!(v.iter().all(|&p| p <= 255));
    }
}

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
///
/// Returns a sorted, deduplicated static slice (call `.to_vec()` when an owned list is required).
pub fn fast_ip_protocols_nmap() -> &'static [u16] {
    load_fast_ip_protocols_nmap()
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
    // nmap `-p -` shorthand for all 65536 ports (0-65535)
    if spec == "-" {
        return Ok((0u16..=65535).collect());
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
        let v = fast_ip_protocols_nmap().to_vec();
        assert!(
            v.len() > 1,
            "embedded nmap IP protocol list must not be empty"
        );
        for w in v.windows(2) {
            assert!(w[0] < w[1], "expected sorted unique list");
        }
        assert!(v.iter().all(|&p| p <= 255));
    }

    #[test]
    fn parse_port_dash_is_all_ports() {
        let p = parse_port_spec("-").expect("dash");
        assert_eq!(p.len(), 65536);
        assert_eq!(p.first().copied(), Some(0));
        assert_eq!(p.last().copied(), Some(65535));
    }

    #[test]
    fn parse_port_t_u_s_prefixes_sort_dedup() {
        let p = parse_port_spec("U:53,T:80,S:22,443").unwrap();
        assert_eq!(p, vec![22, 53, 80, 443]);
    }

    #[test]
    fn parse_port_reversed_range_errors() {
        let e = parse_port_spec("10-5").unwrap_err();
        assert!(
            matches!(e, PortParseError::InvalidToken(_)),
            "expected InvalidToken, got {e:?}"
        );
    }

    #[test]
    fn parse_port_empty_spec_errors() {
        assert!(matches!(parse_port_spec(""), Err(PortParseError::Empty)));
        assert!(matches!(parse_port_spec("   "), Err(PortParseError::Empty)));
    }

    #[test]
    fn parse_port_only_commas_errors_empty() {
        assert!(matches!(parse_port_spec(",,,"), Err(PortParseError::Empty)));
    }

    #[test]
    fn parse_exclude_ports_same_as_spec_set() {
        let ex = parse_exclude_ports("22,80-81").unwrap();
        assert!(ex.contains(&22));
        assert!(ex.contains(&80));
        assert!(ex.contains(&81));
        assert!(!ex.contains(&443));
    }

    #[test]
    fn default_and_top_ports_subset_relation() {
        let d = default_tcp_ports();
        let t10 = top_ports(10);
        assert_eq!(d.len(), 1000);
        for p in &t10 {
            assert!(
                d.contains(p),
                "top 10 port {p} must appear in default top-1000 set"
            );
        }
    }

    #[test]
    fn parse_port_single_value() {
        assert_eq!(parse_port_spec("443").unwrap(), vec![443]);
    }

    #[test]
    fn parse_port_dedupes_duplicates() {
        let p = parse_port_spec("80,80,443,443").unwrap();
        assert_eq!(p, vec![80, 443]);
    }

    #[test]
    fn parse_port_sorts_ascending() {
        assert_eq!(parse_port_spec("443,22,80").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn parse_port_max_boundary_65535() {
        assert_eq!(parse_port_spec("65535").unwrap(), vec![65535]);
    }

    #[test]
    fn parse_port_zero_is_valid() {
        assert_eq!(parse_port_spec("0").unwrap(), vec![0]);
    }

    #[test]
    fn parse_port_out_of_range_errors() {
        assert!(parse_port_spec("65536").is_err());
    }

    #[test]
    fn parse_port_non_numeric_errors() {
        assert!(matches!(
            parse_port_spec("abc"),
            Err(PortParseError::InvalidToken(_))
        ));
    }

    #[test]
    fn top_ports_zero_is_empty() {
        assert!(top_ports(0).is_empty());
    }

    #[test]
    fn top_ports_one_is_first_default_port() {
        let d = default_tcp_ports();
        assert_eq!(top_ports(1), vec![d[0]]);
    }

    #[test]
    fn parse_port_whitespace_around_commas() {
        assert_eq!(parse_port_spec(" 22 , 80 ").unwrap(), vec![22, 80]);
    }

    #[test]
    fn parse_exclude_ports_empty_errors() {
        assert!(matches!(
            parse_exclude_ports(""),
            Err(PortParseError::Empty)
        ));
    }

    #[test]
    fn fast_tcp_ports_first_port_is_http() {
        assert_eq!(fast_tcp_ports()[0], 80);
    }

    #[test]
    fn default_tcp_ports_are_unique() {
        let d = default_tcp_ports();
        let mut seen = std::collections::HashSet::new();
        for p in d {
            assert!(seen.insert(p), "duplicate port {p} in default set");
        }
    }

    #[test]
    fn parse_port_triple_range_expands() {
        assert_eq!(parse_port_spec("1-3").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn parse_port_duplicate_in_range_deduped() {
        assert_eq!(parse_port_spec("80-82,81").unwrap(), vec![80, 81, 82]);
    }

    #[test]
    fn parse_exclude_ports_rejects_invalid_token() {
        assert!(parse_exclude_ports("abc").is_err());
    }

    #[test]
    fn fast_ip_protocols_contains_icmp() {
        let protos = fast_ip_protocols_nmap();
        assert!(protos.contains(&1), "ICMP (1) must be in fast IP proto set");
    }

    #[test]
    fn fast_ip_protocols_contains_tcp_and_udp() {
        let protos = fast_ip_protocols_nmap();
        assert!(protos.contains(&6));
        assert!(protos.contains(&17));
    }

    #[test]
    fn top_ports_fifty_is_subset_of_default() {
        let d = default_tcp_ports();
        for p in top_ports(50) {
            assert!(d.contains(&p), "top-50 port {p} missing from default-1000");
        }
    }

    #[test]
    fn top_ports_len_matches_embedded_table() {
        let len = top_ports_len();
        assert_eq!(top_ports(len).len(), len);
        assert_eq!(top_ports(len + 500).len(), len);
    }

    #[test]
    fn parse_port_spec_leading_trailing_commas_ignored() {
        assert_eq!(parse_port_spec(",22,").unwrap(), vec![22]);
    }

    #[test]
    fn parse_port_spec_s_prefix_sctp_ports() {
        assert_eq!(parse_port_spec("S:22,443").unwrap(), vec![22, 443]);
    }

    #[test]
    fn parse_port_range_single_port_expands_to_one() {
        assert_eq!(parse_port_spec("8080-8080").unwrap(), vec![8080]);
    }

    #[test]
    fn parse_exclude_ports_from_dash_spec() {
        let ex = parse_exclude_ports("-").unwrap();
        assert_eq!(ex.len(), 65536);
        assert!(ex.contains(&0));
        assert!(ex.contains(&65535));
    }

    #[test]
    fn fast_tcp_ports_len_is_100() {
        assert_eq!(fast_tcp_ports().len(), 100);
    }

    #[test]
    fn top_ports_exceeding_default_caps_at_table_len() {
        let n = default_tcp_ports().len();
        assert_eq!(top_ports(n + 100).len(), n);
    }

    #[test]
    fn parse_port_negative_number_errors() {
        assert!(parse_port_spec("-1").is_err());
    }

    #[test]
    fn parse_port_float_like_token_errors() {
        assert!(matches!(
            parse_port_spec("80.5"),
            Err(PortParseError::InvalidToken(_))
        ));
    }

    #[test]
    fn parse_port_spec_s_prefix_single_sctp() {
        assert_eq!(parse_port_spec("S:3868").unwrap(), vec![3868]);
    }

    #[test]
    fn fast_ip_protocols_len_at_least_three() {
        assert!(fast_ip_protocols_nmap().len() >= 3);
    }

    #[test]
    fn top_ports_len_helper_matches_top_ports_call() {
        assert_eq!(top_ports_len(), top_ports(usize::MAX).len());
    }

    #[test]
    fn parse_port_spec_multiple_ranges() {
        assert_eq!(parse_port_spec("22,80-82").unwrap(), vec![22, 80, 81, 82]);
    }

    #[test]
    fn parse_exclude_ports_single_port() {
        let ex = parse_exclude_ports("22").unwrap();
        assert!(ex.contains(&22));
        assert_eq!(ex.len(), 1);
    }

    #[test]
    fn fast_tcp_ports_contains_https() {
        assert!(fast_tcp_ports().contains(&443));
    }

    #[test]
    fn default_tcp_ports_len_exceeds_top_ports_table() {
        assert!(default_tcp_ports().len() >= top_ports_len());
    }

    #[test]
    fn top_ports_one_returns_single_port() {
        assert_eq!(top_ports(1).len(), 1);
    }

    #[test]
    fn default_tcp_ports_first_matches_top_one() {
        assert_eq!(default_tcp_ports()[0], top_ports(1)[0]);
    }

    #[test]
    fn fast_ip_protocols_are_strictly_increasing() {
        let protos = fast_ip_protocols_nmap();
        for w in protos.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn parse_exclude_ports_range() {
        let ex = parse_exclude_ports("1000-1002").unwrap();
        assert!(ex.contains(&1000));
        assert!(ex.contains(&1001));
        assert!(ex.contains(&1002));
    }

    #[test]
    fn top_ports_two_returns_two_distinct() {
        let t = top_ports(2);
        assert_eq!(t.len(), 2);
        assert_ne!(t[0], t[1]);
    }

    #[test]
    fn default_tcp_ports_contains_port_22() {
        assert!(default_tcp_ports().contains(&22));
    }

    #[test]
    fn parse_port_spec_mixed_t_and_plain_ports() {
        assert_eq!(parse_port_spec("T:22,443,8080").unwrap(), vec![22, 443, 8080]);
    }

    #[test]
    fn parse_port_spec_dash_is_all_ports() {
        assert_eq!(parse_port_spec("-").unwrap().len(), 65536);
    }
}

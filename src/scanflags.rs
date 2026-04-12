//! Parse Nmap-style `--scanflags` (TCP flag names).

use anyhow::{bail, Result};
use pnet::packet::tcp::TcpFlags;

/// Parse `--scanflags` into a TCP flags byte (OR of [`TcpFlags`] constants).
///
/// Accepts whitespace-, comma-, or pipe-separated tokens, and glued names (e.g. `SYNACK`).
pub fn parse_scanflags(s: &str) -> Result<u8> {
    let s = s.trim();
    if s.is_empty() {
        bail!("--scanflags must not be empty");
    }
    /// Longest names first so `SYN` is consumed before a trailing `ACK` in `SYNACK`.
    const KEYWORDS: &[(&str, u8)] = &[
        ("SYN", TcpFlags::SYN),
        ("ACK", TcpFlags::ACK),
        ("FIN", TcpFlags::FIN),
        ("RST", TcpFlags::RST),
        ("PSH", TcpFlags::PSH),
        ("URG", TcpFlags::URG),
        ("ECE", TcpFlags::ECE),
        ("CWR", TcpFlags::CWR),
    ];
    let normalized = s.replace(['|', ','], " ");
    let mut flags = 0u8;
    for word in normalized.split_whitespace() {
        if word.is_empty() {
            continue;
        }
        let word_u = word.to_ascii_uppercase();
        let mut sub = word_u.as_str();
        while !sub.is_empty() {
            let mut matched = false;
            for (name, bit) in KEYWORDS.iter() {
                if sub.starts_with(name) {
                    flags |= bit;
                    sub = &sub[name.len()..];
                    matched = true;
                    break;
                }
            }
            if !matched {
                bail!("unknown --scanflags token in '{word}' (unparsed suffix '{sub}')");
            }
        }
    }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::parse_scanflags;
    use pnet::packet::tcp::TcpFlags;

    #[test]
    fn parses_spaced_and_glued() {
        let a = parse_scanflags("SYN ACK").unwrap();
        let b = parse_scanflags("SYNACK").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, TcpFlags::SYN | TcpFlags::ACK);
    }

    #[test]
    fn parses_pipe() {
        let f = parse_scanflags("URG|PSH").unwrap();
        assert_eq!(f, TcpFlags::URG | TcpFlags::PSH);
    }

    #[test]
    fn empty_errors() {
        assert!(parse_scanflags("").is_err());
        assert!(parse_scanflags("   ").is_err());
    }

    #[test]
    fn unknown_token_errors() {
        let e = parse_scanflags("SYN,QXYZ").unwrap_err();
        let s = e.to_string();
        assert!(
            s.contains("unknown") || s.contains("scanflags"),
            "unexpected error: {s}"
        );
    }

    #[test]
    fn parses_rst_syn_ece_cwr() {
        let f = parse_scanflags("RST,SYN,ECE,CWR").unwrap();
        assert_eq!(
            f,
            TcpFlags::RST | TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR
        );
    }

    #[test]
    fn parses_comma_separated_mixed_case() {
        let f = parse_scanflags("syn,fin").unwrap();
        assert_eq!(f, TcpFlags::SYN | TcpFlags::FIN);
    }
}

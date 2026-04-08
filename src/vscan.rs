//! TCP service/version detection using Nmap `nmap-service-probes` (subset of Nmap behavior).
//!
//! Probes and `match` lines are parsed from the upstream file; Perl-specific regex features that
//! the Rust `regex` crate cannot compile are skipped. Probes are tried in file order until a match.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use regex::bytes::{Captures, Regex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// One compiled `match` / `softmatch` rule attached to a TCP probe.
#[derive(Debug)]
pub struct ServiceMatch {
    pub service_name: String,
    pub regex: Regex,
    pub product_tpl: Option<String>,
    pub version_tpl: Option<String>,
}

#[derive(Debug)]
pub struct TcpProbe {
    pub name: String,
    pub payload: Vec<u8>,
    pub totalwait_ms: u64,
    pub rarity: u8,
    pub matches: Vec<ServiceMatch>,
}

pub fn load_tcp_probes(path: &Path) -> Result<Vec<TcpProbe>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    parse_probes(&text).context("parse nmap-service-probes")
}

fn parse_probes(text: &str) -> Result<Vec<TcpProbe>> {
    let mut probes: Vec<TcpProbe> = Vec::new();
    let mut cur: Option<TcpProbe> = None;

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("Exclude ") {
            continue;
        }

        if let Some(rest) = line.strip_prefix("Probe TCP ") {
            if let Some(p) = cur.take() {
                probes.push(p);
            }
            let (name, payload) = parse_probe_tcp_line(rest)?;
            cur = Some(TcpProbe {
                name,
                payload,
                totalwait_ms: 6000,
                rarity: 5,
                matches: Vec::new(),
            });
            continue;
        }

        let Some(p) = cur.as_mut() else {
            continue;
        };

        if let Some(ms) = line.strip_prefix("totalwaitms ") {
            if let Ok(n) = ms.trim().parse::<u64>() {
                p.totalwait_ms = n;
            }
            continue;
        }
        if let Some(r) = line.strip_prefix("rarity ") {
            if let Ok(n) = r.trim().parse::<u8>() {
                p.rarity = n;
            }
            continue;
        }

        if line.starts_with("match ") || line.starts_with("softmatch ") {
            if let Some(m) = parse_match_line(line)? {
                p.matches.push(m);
            }
        }
    }

    if let Some(p) = cur.take() {
        probes.push(p);
    }

    Ok(probes)
}

fn parse_probe_tcp_line(rest: &str) -> Result<(String, Vec<u8>)> {
    let rest = rest.trim_start();
    let name_end = rest
        .find(char::is_whitespace)
        .ok_or_else(|| anyhow::anyhow!("Probe TCP: missing probe name"))?;
    let name = rest[..name_end].to_string();
    let qpart = rest[name_end..].trim_start();
    let payload = parse_q_field(qpart).unwrap_or_default();
    Ok((name, payload))
}

/// `q|payload|` or `q/payload/` — delimiter is the first byte after `q`.
fn parse_q_field(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_start();
    let rest = s.strip_prefix('q')?;
    let delim = rest.chars().next()?;
    let inner = rest.get(delim.len_utf8()..)?;
    let end = inner.find(delim)?;
    Some(decode_nmap_escape_bytes(&inner[..end]))
}

fn decode_nmap_escape_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c as u8);
            continue;
        }
        match it.next() {
            Some('x') | Some('X') => {
                let mut hex = String::with_capacity(2);
                hex.push(it.next().unwrap_or('0'));
                hex.push(it.next().unwrap_or('0'));
                if let Ok(v) = u8::from_str_radix(&hex, 16) {
                    out.push(v);
                }
            }
            Some('0') => out.push(0),
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('t') => out.push(b'\t'),
            Some('\\') => out.push(b'\\'),
            Some(o) => out.push(o as u8),
            None => {}
        }
    }
    out
}

fn parse_match_line(line: &str) -> Result<Option<ServiceMatch>> {
    let rest = if line.starts_with("softmatch ") {
        line.strip_prefix("softmatch ").unwrap()
    } else {
        line.strip_prefix("match ").unwrap()
    };
    let (service_token, after_svc) = split_first_token(rest);
    if service_token.is_empty() {
        return Ok(None);
    }
    let after_svc = after_svc.trim_start();
    let (pattern_src, tail) = match extract_m_delimited(after_svc) {
        Some(x) => x,
        None => return Ok(None),
    };
    let dotall = tail.split("p/").next().unwrap_or("").contains("|s");
    let mut pat = String::new();
    if dotall {
        pat.push_str("(?s)");
    }
    pat.push_str(pattern_src);

    let regex = match Regex::new(&pat) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    let (product_tpl, version_tpl) = extract_p_v_templates(tail);
    Ok(Some(ServiceMatch {
        service_name: service_token.to_string(),
        regex,
        product_tpl,
        version_tpl,
    }))
}

fn split_first_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s
        .find(char::is_whitespace)
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

/// After `m<delim>regex<delim>`, return `(regex_source, tail)`.
fn extract_m_delimited(rest: &str) -> Option<(&str, &str)> {
    let b = rest.as_bytes();
    if b.first().copied()? != b'm' {
        return None;
    }
    let delim = b.get(1).copied()? as char;
    let mut i = 2usize;
    let mut escaped = false;
    while i < b.len() {
        let c = b[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if c == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if c == delim as u8 {
            let pattern = std::str::from_utf8(&b[2..i]).ok()?;
            let tail = std::str::from_utf8(&b[i + 1..]).ok()?;
            return Some((pattern, tail));
        }
        i += 1;
    }
    None
}

fn extract_p_v_templates(tail: &str) -> (Option<String>, Option<String>) {
    let p = find_slash_field(tail, "p/");
    let v = find_slash_field(tail, "v/");
    (p, v)
}

fn find_slash_field(s: &str, needle: &str) -> Option<String> {
    let i = s.find(needle)?;
    let rest = &s[i + needle.len()..];
    let end = rest.find('/')?;
    Some(rest[..end].to_string())
}

fn apply_template(tpl: &str, caps: &Captures) -> String {
    let mut out = String::with_capacity(tpl.len() + 16);
    let mut chars = tpl.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'$') {
            out.push('$');
            chars.next();
            continue;
        }
        if c == '$' {
            let mut n: usize = 0;
            let mut any = false;
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    any = true;
                    n = n * 10 + (d as u8 - b'0') as usize;
                    chars.next();
                } else {
                    break;
                }
            }
            if any {
                if let Some(m) = caps.get(n) {
                    out.push_str(&String::from_utf8_lossy(m.as_bytes()));
                }
            } else {
                out.push('$');
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn format_match(m: &ServiceMatch, caps: &Captures) -> String {
    let prod = m
        .product_tpl
        .as_ref()
        .map(|t| apply_template(t, caps))
        .unwrap_or_default();
    let ver = m
        .version_tpl
        .as_ref()
        .map(|t| apply_template(t, caps))
        .unwrap_or_default();
    let prod = prod.trim();
    let ver = ver.trim();
    match (prod.is_empty(), ver.is_empty()) {
        (false, false) => format!("{} {}", prod, ver),
        (false, true) => prod.to_string(),
        (true, false) => ver.to_string(),
        (true, true) => m.service_name.clone(),
    }
}

/// Run version detection for open TCP `(host, port)` pairs; returns map to display string.
pub async fn run_tcp_version_scan(
    open_tcp: Vec<(IpAddr, u16)>,
    probes: std::sync::Arc<Vec<TcpProbe>>,
    intensity: u8,
    connect_timeout: Duration,
    concurrency: usize,
) -> std::collections::HashMap<(IpAddr, u16), String> {
    use std::collections::HashMap;

    let mut out: HashMap<(IpAddr, u16), String> = HashMap::new();
    if probes.is_empty() || open_tcp.is_empty() {
        return out;
    }
    let c = concurrency.max(1);
    let results: Vec<_> = stream::iter(open_tcp)
        .map(|(host, port)| {
            let probes = std::sync::Arc::clone(&probes);
            async move {
                let s = probe_one_port(host, port, &probes, intensity, connect_timeout).await;
                ((host, port), s)
            }
        })
        .buffer_unordered(c)
        .collect()
        .await;
    for ((h, p), s) in results {
        if let Some(text) = s {
            out.insert((h, p), text);
        }
    }
    out
}

async fn probe_one_port(
    host: IpAddr,
    port: u16,
    probes: &[TcpProbe],
    intensity: u8,
    connect_timeout: Duration,
) -> Option<String> {
    let addr = SocketAddr::new(host, port);
    for probe in probes {
        if probe.rarity > intensity {
            continue;
        }
        if probe.matches.is_empty() {
            continue;
        }
        let read_to = Duration::from_millis(probe.totalwait_ms.clamp(1, 30_000));
        let stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => continue,
        };
        let mut stream = stream;
        if !probe.payload.is_empty() {
            let _ = stream.write_all(&probe.payload).await;
        }
        let mut buf = vec![0u8; 65_536];
        let n = match timeout(read_to, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        let banner = &buf[..n];
        for m in &probe.matches {
            if let Some(caps) = m.regex.captures(banner) {
                return Some(format_match(m, &caps));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_fixture() {
        let fixture = r#"
Probe TCP NULL q||
rarity 1
match ssh m|^SSH-([\d.]+)-([^\r\n]+)| p/OpenSSH/ v/$1/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
match http m|^HTTP/1\.[01]\s\d\d\d| p/HTTP server/
"#;
        let probes = parse_probes(fixture).expect("parse");
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].name, "NULL");
        assert!(probes[0].payload.is_empty());
    }

    #[test]
    fn q_field_decodes_hex_escape() {
        let p = parse_q_field("q|\\x00\\x01SSH|").expect("q");
        assert_eq!(p, vec![0, 1, b'S', b'S', b'H']);
    }
}

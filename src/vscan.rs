//! TCP/UDP service/version detection using Nmap `nmap-service-probes` (subset of Nmap behavior).
//!
//! Supports `Probe TCP` / `Probe UDP`, `ports` / `sslports`, `rarity`, `totalwaitms`, `match` /
//! `softmatch` (soft matches defer to later probes until a hard match). TLS is used when the
//! target port appears on the probe's `sslports` line. Perl-only regex features that `regex`
//! cannot compile are skipped.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use regex::bytes::{Captures, Regex};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// One compiled `match` / `softmatch` rule attached to a probe.
#[derive(Debug)]
pub struct ServiceMatch {
    pub service_name: String,
    pub regex: Regex,
    pub product_tpl: Option<String>,
    pub version_tpl: Option<String>,
    /// `softmatch` — does not stop the probe sequence; used only if no hard match is found.
    pub soft: bool,
}

/// Inclusive port ranges `(lo, hi)` from Nmap `ports` / `sslports` lines.
pub type PortRanges = Vec<(u16, u16)>;

#[derive(Debug)]
pub struct TcpProbe {
    pub name: String,
    pub payload: Vec<u8>,
    pub totalwait_ms: u64,
    pub rarity: u8,
    /// `None` ⇒ probe may run against any port (Nmap default when `ports` omitted for some probes).
    pub ports: Option<PortRanges>,
    pub sslports: Option<PortRanges>,
    pub matches: Vec<ServiceMatch>,
}

#[derive(Debug)]
pub struct UdpProbe {
    pub name: String,
    pub payload: Vec<u8>,
    pub totalwait_ms: u64,
    pub rarity: u8,
    pub ports: Option<PortRanges>,
    pub matches: Vec<ServiceMatch>,
}

#[derive(Debug, Default)]
pub struct ServiceProbes {
    pub tcp: Vec<TcpProbe>,
    pub udp: Vec<UdpProbe>,
}

fn tls_client_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

fn server_name(host: IpAddr) -> ServerName<'static> {
    match host {
        IpAddr::V4(a) => ServerName::IpAddress(a.into()),
        IpAddr::V6(a) => ServerName::IpAddress(a.into()),
    }
}

pub fn load_service_probes(path: &Path) -> Result<ServiceProbes> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    parse_probes(&text).context("parse nmap-service-probes")
}

/// Backward-compatible: TCP probes only.
pub fn load_tcp_probes(path: &Path) -> Result<Vec<TcpProbe>> {
    Ok(load_service_probes(path)?.tcp)
}

fn parse_probes(text: &str) -> Result<ServiceProbes> {
    let mut out = ServiceProbes::default();
    let mut cur_tcp: Option<TcpProbe> = None;
    let mut cur_udp: Option<UdpProbe> = None;

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("Exclude ") {
            continue;
        }

        if let Some(rest) = line.strip_prefix("Probe TCP ") {
            if let Some(p) = cur_udp.take() {
                out.udp.push(p);
            }
            if let Some(p) = cur_tcp.take() {
                out.tcp.push(p);
            }
            let (name, payload) = parse_probe_tcp_line(rest)?;
            cur_tcp = Some(TcpProbe {
                name,
                payload,
                totalwait_ms: 6000,
                rarity: 5,
                ports: None,
                sslports: None,
                matches: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("Probe UDP ") {
            if let Some(p) = cur_tcp.take() {
                out.tcp.push(p);
            }
            if let Some(p) = cur_udp.take() {
                out.udp.push(p);
            }
            let (name, payload) = parse_probe_udp_line(rest)?;
            cur_udp = Some(UdpProbe {
                name,
                payload,
                totalwait_ms: 6000,
                rarity: 5,
                ports: None,
                matches: Vec::new(),
            });
            continue;
        }

        if let Some(p) = cur_tcp.as_mut() {
            if apply_probe_line_tcp(line, p)? {
                continue;
            }
        }
        if let Some(p) = cur_udp.as_mut() {
            if apply_probe_line_udp(line, p)? {
                continue;
            }
        }
    }

    if let Some(p) = cur_udp.take() {
        out.udp.push(p);
    }
    if let Some(p) = cur_tcp.take() {
        out.tcp.push(p);
    }

    Ok(out)
}

fn apply_probe_line_tcp(line: &str, p: &mut TcpProbe) -> Result<bool> {
    if let Some(ms) = line.strip_prefix("totalwaitms ") {
        if let Ok(n) = ms.trim().parse::<u64>() {
            p.totalwait_ms = n;
        }
        return Ok(true);
    }
    if let Some(r) = line.strip_prefix("rarity ") {
        if let Ok(n) = r.trim().parse::<u8>() {
            p.rarity = n;
        }
        return Ok(true);
    }
    if let Some(rest) = line.strip_prefix("ports ") {
        p.ports = parse_port_ranges_list(rest);
        return Ok(true);
    }
    if let Some(rest) = line.strip_prefix("sslports ") {
        p.sslports = parse_port_ranges_list(rest);
        return Ok(true);
    }
    if line.starts_with("match ") || line.starts_with("softmatch ") {
        if let Some(m) = parse_match_line(line)? {
            p.matches.push(m);
        }
        return Ok(true);
    }
    Ok(false)
}

fn apply_probe_line_udp(line: &str, p: &mut UdpProbe) -> Result<bool> {
    if let Some(ms) = line.strip_prefix("totalwaitms ") {
        if let Ok(n) = ms.trim().parse::<u64>() {
            p.totalwait_ms = n;
        }
        return Ok(true);
    }
    if let Some(r) = line.strip_prefix("rarity ") {
        if let Ok(n) = r.trim().parse::<u8>() {
            p.rarity = n;
        }
        return Ok(true);
    }
    if let Some(rest) = line.strip_prefix("ports ") {
        p.ports = parse_port_ranges_list(rest);
        return Ok(true);
    }
    if line.starts_with("match ") || line.starts_with("softmatch ") {
        if let Some(m) = parse_match_line(line)? {
            p.matches.push(m);
        }
        return Ok(true);
    }
    Ok(false)
}

fn parse_port_ranges_list(s: &str) -> Option<PortRanges> {
    let mut out = PortRanges::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a.trim().parse().ok()?;
            let hi: u16 = b.trim().parse().ok()?;
            out.push((lo.min(hi), lo.max(hi)));
        } else {
            let p: u16 = part.parse().ok()?;
            out.push((p, p));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn port_in_ranges(port: u16, ranges: &PortRanges) -> bool {
    ranges.iter().any(|&(lo, hi)| port >= lo && port <= hi)
}

fn probe_ports_ok(port: u16, spec: &Option<PortRanges>) -> bool {
    spec.as_ref().is_none_or(|r| port_in_ranges(port, r))
}

fn use_tls_for_tcp(port: u16, probe: &TcpProbe) -> bool {
    probe
        .sslports
        .as_ref()
        .is_some_and(|r| port_in_ranges(port, r))
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

fn parse_probe_udp_line(rest: &str) -> Result<(String, Vec<u8>)> {
    let rest = rest.trim_start();
    let name_end = rest
        .find(char::is_whitespace)
        .ok_or_else(|| anyhow::anyhow!("Probe UDP: missing probe name"))?;
    let name = rest[..name_end].to_string();
    let qpart = rest[name_end..].trim_start();
    let payload = parse_q_field(qpart).unwrap_or_default();
    Ok((name, payload))
}

/// `q|payload|` — delimiter is the first byte after `q`.
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
    let soft = line.starts_with("softmatch ");
    let rest = if soft {
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
        soft,
    }))
}

fn split_first_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s
        .find(char::is_whitespace)
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

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

/// Run version detection for open TCP `(host, port)` pairs.
pub async fn run_tcp_version_scan(
    open_tcp: Vec<(IpAddr, u16)>,
    probes: Arc<Vec<TcpProbe>>,
    intensity: u8,
    connect_timeout: Duration,
    concurrency: usize,
) -> HashMap<(IpAddr, u16), String> {
    let mut out = HashMap::new();
    if probes.is_empty() || open_tcp.is_empty() {
        return out;
    }
    let c = concurrency.max(1);
    let results: Vec<_> = stream::iter(open_tcp)
        .map(|(host, port)| {
            let probes = Arc::clone(&probes);
            async move {
                let s = probe_one_tcp_port(host, port, &probes, intensity, connect_timeout).await;
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

/// Run version detection for open UDP `(host, port)` pairs.
pub async fn run_udp_version_scan(
    open_udp: Vec<(IpAddr, u16)>,
    probes: Arc<Vec<UdpProbe>>,
    intensity: u8,
    connect_timeout: Duration,
    concurrency: usize,
) -> HashMap<(IpAddr, u16), String> {
    let mut out = HashMap::new();
    if probes.is_empty() || open_udp.is_empty() {
        return out;
    }
    let c = concurrency.max(1);
    let results: Vec<_> = stream::iter(open_udp)
        .map(|(host, port)| {
            let probes = Arc::clone(&probes);
            async move {
                let s = probe_one_udp_port(host, port, &probes, intensity, connect_timeout).await;
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

async fn read_tcp_banner(
    host: IpAddr,
    port: u16,
    payload: &[u8],
    read_to: Duration,
    connect_timeout: Duration,
    tls: bool,
) -> Option<Vec<u8>> {
    let addr = SocketAddr::new(host, port);
    let tcp = match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut buf = vec![0u8; 65_536];
    let n = if tls {
        let cfg = tls_client_config();
        let connector = TlsConnector::from(cfg);
        let dns = server_name(host);
        let mut tls_stream = match timeout(connect_timeout, connector.connect(dns, tcp)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };
        if !payload.is_empty() {
            tls_stream.write_all(payload).await.ok()?;
        }
        match timeout(read_to, tls_stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        }
    } else {
        let mut tcp = tcp;
        if !payload.is_empty() {
            tcp.write_all(payload).await.ok()?;
        }
        match timeout(read_to, tcp.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        }
    };
    Some(buf[..n].to_vec())
}

async fn probe_one_tcp_port(
    host: IpAddr,
    port: u16,
    probes: &[TcpProbe],
    intensity: u8,
    connect_timeout: Duration,
) -> Option<String> {
    let mut best_soft: Option<String> = None;

    for probe in probes {
        if probe.rarity > intensity {
            continue;
        }
        if !probe_ports_ok(port, &probe.ports) {
            continue;
        }
        if probe.matches.is_empty() {
            continue;
        }

        let read_to = Duration::from_millis(probe.totalwait_ms.clamp(1, 30_000));
        let tls = use_tls_for_tcp(port, probe);
        let banner = match read_tcp_banner(
            host,
            port,
            &probe.payload,
            read_to,
            connect_timeout,
            tls,
        )
        .await
        {
            Some(b) => b,
            None => continue,
        };

        for m in &probe.matches {
            if m.soft {
                continue;
            }
            if let Some(caps) = m.regex.captures(&banner) {
                return Some(format_match(m, &caps));
            }
        }
        for m in &probe.matches {
            if !m.soft {
                continue;
            }
            if let Some(caps) = m.regex.captures(&banner) {
                best_soft = Some(format_match(m, &caps));
                break;
            }
        }
    }

    best_soft
}

async fn probe_one_udp_port(
    host: IpAddr,
    port: u16,
    probes: &[UdpProbe],
    intensity: u8,
    _connect_timeout: Duration,
) -> Option<String> {
    let mut best_soft: Option<String> = None;

    for probe in probes {
        if probe.rarity > intensity {
            continue;
        }
        if !probe_ports_ok(port, &probe.ports) {
            continue;
        }
        if probe.matches.is_empty() {
            continue;
        }

        let read_to = Duration::from_millis(probe.totalwait_ms.clamp(1, 30_000));
        let bind_addr: SocketAddr = match host {
            IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            IpAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let dst = SocketAddr::new(host, port);
        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        if !probe.payload.is_empty() {
            socket.send_to(&probe.payload, dst).await.ok()?;
        }
        let mut buf = vec![0u8; 65_536];
        let n = match timeout(read_to, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => n,
            _ => 0,
        };
        if n == 0 && !probe.payload.is_empty() {
            continue;
        }
        let banner = &buf[..n];

        for m in &probe.matches {
            if m.soft {
                continue;
            }
            if let Some(caps) = m.regex.captures(banner) {
                return Some(format_match(m, &caps));
            }
        }
        for m in &probe.matches {
            if !m.soft {
                continue;
            }
            if let Some(caps) = m.regex.captures(banner) {
                best_soft = Some(format_match(m, &caps));
                break;
            }
        }
    }

    best_soft
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
ports 80,443
match http m|^HTTP/1\.[01]\s\d\d\d| p/HTTP server/
"#;
        let sp = parse_probes(fixture).expect("parse");
        assert_eq!(sp.tcp.len(), 2);
        assert_eq!(sp.tcp[0].name, "NULL");
        assert!(sp.tcp[0].payload.is_empty());
        assert!(sp.tcp[1].ports.is_some());
    }

    #[test]
    fn q_field_decodes_hex_escape() {
        let p = parse_q_field("q|\\x00\\x01SSH|").expect("q");
        assert_eq!(p, vec![0, 1, b'S', b'S', b'H']);
    }

    #[test]
    fn parses_port_ranges() {
        let r = parse_port_ranges_list("1,3-5,443").expect("ranges");
        assert!(port_in_ranges(1, &r));
        assert!(port_in_ranges(4, &r));
        assert!(!port_in_ranges(2, &r));
    }
}

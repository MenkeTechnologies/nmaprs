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
    /// `service_name` field.
    pub service_name: String,
    /// `regex` field.
    pub regex: Regex,
    /// `product_tpl` field.
    pub product_tpl: Option<String>,
    /// `version_tpl` field.
    pub version_tpl: Option<String>,
    /// `i/` — extra info (e.g. "protocol 2.0").
    pub info_tpl: Option<String>,
    /// `o/` — operating system.
    pub os_tpl: Option<String>,
    /// `d/` — device type.
    pub device_tpl: Option<String>,
    /// `cpe:/` — Common Platform Enumeration URI(s).
    pub cpe_tpl: Vec<String>,
    /// `softmatch` — does not stop the probe sequence; used only if no hard match is found.
    pub soft: bool,
}

/// Inclusive port ranges `(lo, hi)` from Nmap `ports` / `sslports` lines.
pub type PortRanges = Vec<(u16, u16)>;
/// `TcpProbe` — see fields for layout.
#[derive(Debug)]
pub struct TcpProbe {
    /// `name` field.
    pub name: String,
    /// `payload` field.
    pub payload: Vec<u8>,
    /// `totalwait_ms` field.
    pub totalwait_ms: u64,
    /// `rarity` field.
    pub rarity: u8,
    /// `None` ⇒ probe may run against any port (Nmap default when `ports` omitted for some probes).
    pub ports: Option<PortRanges>,
    /// `sslports` field.
    pub sslports: Option<PortRanges>,
    /// `matches` field.
    pub matches: Vec<ServiceMatch>,
}
/// `UdpProbe` — see fields for layout.
#[derive(Debug)]
pub struct UdpProbe {
    /// `name` field.
    pub name: String,
    /// `payload` field.
    pub payload: Vec<u8>,
    /// `totalwait_ms` field.
    pub totalwait_ms: u64,
    /// `rarity` field.
    pub rarity: u8,
    /// `ports` field.
    pub ports: Option<PortRanges>,
    /// `matches` field.
    pub matches: Vec<ServiceMatch>,
}
/// `ServiceProbes` — see fields for layout.
#[derive(Debug, Default)]
pub struct ServiceProbes {
    /// `tcp` field.
    pub tcp: Vec<TcpProbe>,
    /// `udp` field.
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
/// `load_service_probes` — see implementation.
pub fn load_service_probes(path: &Path) -> Result<ServiceProbes> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
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

fn hex_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
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
                let a = it.next().unwrap_or('0');
                let b = it.next().unwrap_or('0');
                if let (Some(hi), Some(lo)) = (hex_nibble(a), hex_nibble(b)) {
                    out.push(hi << 4 | lo);
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
    // `apply_probe_line_*` only calls here after `match ` / `softmatch ` prefix check.
    let rest = if soft {
        &line["softmatch ".len()..]
    } else {
        &line["match ".len()..]
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

    let (product_tpl, version_tpl, info_tpl, os_tpl, device_tpl, cpe_tpl) =
        extract_p_v_templates(tail);
    Ok(Some(ServiceMatch {
        service_name: service_token.to_string(),
        regex,
        product_tpl,
        version_tpl,
        info_tpl,
        os_tpl,
        device_tpl,
        cpe_tpl,
        soft,
    }))
}

fn split_first_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
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

type PVTemplates = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
);

fn extract_p_v_templates(tail: &str) -> PVTemplates {
    let p = find_slash_field(tail, "p/");
    let v = find_slash_field(tail, "v/");
    let i = find_slash_field(tail, "i/");
    let o = find_slash_field(tail, "o/");
    let d = find_slash_field(tail, "d/");
    let cpe = find_all_slash_fields(tail, "cpe:/");
    (p, v, i, o, d, cpe)
}

fn find_all_slash_fields(s: &str, needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search = s;
    while let Some(idx) = search.find(needle) {
        let rest = &search[idx + needle.len()..];
        if let Some(end) = rest.find('/') {
            out.push(format!("cpe:/{}", &rest[..end]));
        }
        search = &search[idx + needle.len()..];
    }
    out
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
    let info = m
        .info_tpl
        .as_ref()
        .map(|t| apply_template(t, caps))
        .unwrap_or_default();
    let os = m
        .os_tpl
        .as_ref()
        .map(|t| apply_template(t, caps))
        .unwrap_or_default();
    let device = m
        .device_tpl
        .as_ref()
        .map(|t| apply_template(t, caps))
        .unwrap_or_default();
    let cpe_strs: Vec<String> = m.cpe_tpl.iter().map(|t| apply_template(t, caps)).collect();

    let prod = prod.trim();
    let ver = ver.trim();
    let info = info.trim();
    let os = os.trim();
    let device = device.trim();

    let mut parts = Vec::new();
    if !prod.is_empty() {
        parts.push(prod.to_string());
    }
    if !ver.is_empty() {
        parts.push(ver.to_string());
    }
    if !info.is_empty() {
        parts.push(format!("({})", info));
    }
    if !os.is_empty() {
        parts.push(format!("[{}]", os));
    }
    if !device.is_empty() {
        parts.push(format!("{{{}}}", device));
    }
    for c in &cpe_strs {
        let c = c.trim();
        if !c.is_empty() {
            parts.push(c.to_string());
        }
    }

    if parts.is_empty() {
        m.service_name.clone()
    } else {
        parts.join(" ")
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

    #[test]
    fn parses_port_ranges_reversed_pair_normalizes() {
        let r = parse_port_ranges_list("9-3").expect("ranges");
        assert!(port_in_ranges(5, &r));
        assert!(!port_in_ranges(2, &r));
    }

    #[test]
    fn parses_udp_probe_and_totalwaitms() {
        let fixture = r#"
Probe UDP DNSVersionBindReq q|\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|
totalwaitms 3000
rarity 2
match dns m|^[^\x00]+\x00\x00\x01\x00\x01| p/DNS server/
"#;
        let sp = parse_probes(fixture).expect("parse");
        assert_eq!(sp.tcp.len(), 0);
        assert_eq!(sp.udp.len(), 1);
        let u = &sp.udp[0];
        assert_eq!(u.name, "DNSVersionBindReq");
        assert_eq!(u.totalwait_ms, 3000);
        assert_eq!(u.rarity, 2);
        assert!(!u.payload.is_empty());
        assert_eq!(u.matches.len(), 1);
        assert!(!u.matches[0].soft);
    }

    #[test]
    fn softmatch_flag_parsed() {
        let fixture = r#"
Probe TCP NULL q||
softmatch unknown m|^.| p/Guess/
"#;
        let sp = parse_probes(fixture).expect("parse");
        assert!(sp.tcp[0].matches[0].soft);
    }

    #[test]
    fn decode_nmap_escape_backslash_and_zero() {
        let p = parse_q_field(r"q|\\\0\x41|").expect("q");
        assert_eq!(p, vec![b'\\', 0, b'A']);
    }

    #[test]
    fn decode_nmap_escape_whitespace_controls() {
        assert_eq!(
            decode_nmap_escape_bytes(r"\n\r\t"),
            vec![b'\n', b'\r', b'\t']
        );
    }

    #[test]
    fn decode_nmap_escape_plain_chars_after_backslash() {
        assert_eq!(decode_nmap_escape_bytes(r"\Q"), vec![b'Q']);
    }

    #[test]
    fn parse_q_field_custom_pipe_delimiter() {
        let p = parse_q_field("q|GET / HTTP/1.0\\r\\n\\r\\n|").expect("q");
        assert!(p.starts_with(b"GET / HTTP/1.0"));
    }

    #[test]
    fn parse_q_field_missing_delimiter_is_none() {
        assert!(parse_q_field("not-a-q-field").is_none());
    }

    #[test]
    fn parse_port_ranges_single_port() {
        let r = parse_port_ranges_list("8080").expect("ranges");
        assert_eq!(r, vec![(8080, 8080)]);
    }

    #[test]
    fn parse_port_ranges_mixed_singles_and_ranges() {
        let r = parse_port_ranges_list("22,80,443,8000-8010").expect("ranges");
        assert!(port_in_ranges(22, &r));
        assert!(port_in_ranges(80, &r));
        assert!(port_in_ranges(443, &r));
        assert!(port_in_ranges(8005, &r));
        assert!(!port_in_ranges(8011, &r));
    }

    #[test]
    fn parse_port_ranges_whitespace_tolerant() {
        let r = parse_port_ranges_list(" 80 , 443 , 1000 - 2000 ").expect("ranges");
        assert!(port_in_ranges(80, &r));
        assert!(port_in_ranges(1500, &r));
    }

    #[test]
    fn parse_port_ranges_empty_input_returns_none() {
        assert!(parse_port_ranges_list("").is_none());
        assert!(parse_port_ranges_list("  ").is_none());
        assert!(parse_port_ranges_list(",,").is_none());
    }

    #[test]
    fn parse_port_ranges_invalid_returns_none() {
        assert!(parse_port_ranges_list("abc").is_none());
        assert!(parse_port_ranges_list("80,abc,443").is_none());
        assert!(parse_port_ranges_list("99999").is_none());
    }

    #[test]
    fn port_in_ranges_boundary_inclusive() {
        let r: PortRanges = vec![(100, 200)];
        assert!(port_in_ranges(100, &r));
        assert!(port_in_ranges(200, &r));
        assert!(!port_in_ranges(99, &r));
        assert!(!port_in_ranges(201, &r));
    }

    #[test]
    fn port_in_ranges_inclusive_endpoints() {
        let r = parse_port_ranges_list("80-443").unwrap();
        assert!(port_in_ranges(80, &r));
        assert!(port_in_ranges(443, &r));
        assert!(!port_in_ranges(79, &r));
        assert!(!port_in_ranges(444, &r));
    }

    #[test]
    fn probe_ports_ok_with_no_spec_allows_any_port() {
        assert!(probe_ports_ok(22, &None));
        assert!(probe_ports_ok(8080, &None));
        assert!(probe_ports_ok(65535, &None));
    }

    #[test]
    fn probe_ports_ok_with_spec_restricts_to_listed() {
        let spec = Some(vec![(80, 80), (443, 443)]);
        assert!(probe_ports_ok(80, &spec));
        assert!(probe_ports_ok(443, &spec));
        assert!(!probe_ports_ok(22, &spec));
        assert!(!probe_ports_ok(8080, &spec));
    }

    #[test]
    fn probe_ports_ok_some_restricts_to_list() {
        let spec = parse_port_ranges_list("22,443");
        assert!(probe_ports_ok(22, &spec));
        assert!(probe_ports_ok(443, &spec));
        assert!(!probe_ports_ok(80, &spec));
    }

    #[test]
    fn hex_nibble_decimal_digits() {
        assert_eq!(hex_nibble('0'), Some(0));
        assert_eq!(hex_nibble('5'), Some(5));
        assert_eq!(hex_nibble('9'), Some(9));
    }

    #[test]
    fn hex_nibble_lowercase_letters() {
        assert_eq!(hex_nibble('a'), Some(10));
        assert_eq!(hex_nibble('f'), Some(15));
    }

    #[test]
    fn hex_nibble_uppercase_letters() {
        assert_eq!(hex_nibble('A'), Some(10));
        assert_eq!(hex_nibble('F'), Some(15));
    }

    #[test]
    fn hex_nibble_invalid_returns_none() {
        assert_eq!(hex_nibble('g'), None);
        assert_eq!(hex_nibble('G'), None);
        assert_eq!(hex_nibble('Z'), None);
        assert_eq!(hex_nibble(' '), None);
        assert_eq!(hex_nibble('-'), None);
    }

    #[test]
    fn decode_plain_ascii_passes_through() {
        assert_eq!(decode_nmap_escape_bytes("hello"), b"hello");
        assert_eq!(decode_nmap_escape_bytes(""), b"");
    }

    #[test]
    fn decode_known_letter_escapes() {
        assert_eq!(decode_nmap_escape_bytes(r"\n"), b"\n");
        assert_eq!(decode_nmap_escape_bytes(r"\r"), b"\r");
        assert_eq!(decode_nmap_escape_bytes(r"\t"), b"\t");
        assert_eq!(decode_nmap_escape_bytes(r"\\"), b"\\");
        assert_eq!(decode_nmap_escape_bytes(r"\0"), &[0u8]);
    }

    #[test]
    fn decode_hex_byte_lowercase_and_upper_prefix() {
        assert_eq!(decode_nmap_escape_bytes(r"\x41"), b"A");
        assert_eq!(decode_nmap_escape_bytes(r"\X41"), b"A");
        assert_eq!(decode_nmap_escape_bytes(r"\xff"), &[0xffu8]);
        assert_eq!(decode_nmap_escape_bytes(r"\x00"), &[0u8]);
    }

    #[test]
    fn decode_unknown_escape_takes_following_char_verbatim() {
        assert_eq!(decode_nmap_escape_bytes(r"\q"), b"q");
        assert_eq!(decode_nmap_escape_bytes(r"\Z"), b"Z");
    }

    #[test]
    fn decode_trailing_backslash_dropped() {
        let out = decode_nmap_escape_bytes("hi\\");
        assert_eq!(out, b"hi");
    }

    #[test]
    fn decode_mixed_escapes_in_sequence() {
        assert_eq!(decode_nmap_escape_bytes(r"a\nb\tc\\d"), b"a\nb\tc\\d");
        assert_eq!(decode_nmap_escape_bytes(r"GET /\r\n\r\n"), b"GET /\r\n\r\n");
    }

    #[test]
    fn parse_q_field_with_non_pipe_delimiter() {
        let p = parse_q_field("q/hello/").expect("q with /");
        assert_eq!(p, b"hello");
    }

    #[test]
    fn parse_q_field_missing_closing_delimiter_returns_none() {
        assert!(parse_q_field("q|unterminated").is_none());
    }

    #[test]
    fn parse_q_field_empty_payload() {
        let p = parse_q_field("q||").expect("q||");
        assert!(p.is_empty());
    }

    #[test]
    fn parse_q_field_without_q_prefix_returns_none() {
        assert!(parse_q_field("|hello|").is_none());
        assert!(parse_q_field("hello").is_none());
    }

    #[test]
    fn use_tls_only_when_port_on_sslports() {
        let mut probe = TcpProbe {
            name: "X".into(),
            payload: vec![],
            totalwait_ms: 1000,
            rarity: 1,
            ports: None,
            sslports: parse_port_ranges_list("443,8443"),
            matches: vec![],
        };
        assert!(use_tls_for_tcp(443, &probe));
        assert!(use_tls_for_tcp(8443, &probe));
        assert!(!use_tls_for_tcp(80, &probe));
        probe.sslports = None;
        assert!(!use_tls_for_tcp(443, &probe));
    }

    #[test]
    fn parse_match_line_extracts_product_and_version_templates() {
        let m = parse_match_line("match ssh m|^SSH-([\\d.]+)| p/OpenSSH/ v/$1/").unwrap();
        let m = m.expect("match");
        assert_eq!(m.service_name, "ssh");
        assert_eq!(m.product_tpl.as_deref(), Some("OpenSSH"));
        assert_eq!(m.version_tpl.as_deref(), Some("$1"));
        assert!(!m.soft);
    }

    #[test]
    fn parse_match_line_softmatch_flag() {
        let m = parse_match_line("softmatch guess m|^.| p/?/")
            .unwrap()
            .unwrap();
        assert!(m.soft);
    }

    #[test]
    fn parse_match_line_invalid_regex_returns_none() {
        assert!(parse_match_line("match bad m|[unclosed| p/x/")
            .unwrap()
            .is_none());
    }

    #[test]
    fn apply_template_substitutes_capture_groups() {
        let re = Regex::new(r"^SSH-(.+)-(.+)$").unwrap();
        let caps = re.captures(b"SSH-8.2p1-Ubuntu").unwrap();
        assert_eq!(apply_template("$1 on $2", &caps), "8.2p1 on Ubuntu");
    }

    #[test]
    fn apply_template_dollar_dollar_is_literal() {
        let re = Regex::new(r"x").unwrap();
        let caps = re.captures(b"x").unwrap();
        assert_eq!(apply_template("cost is $$5", &caps), "cost is $5");
    }

    #[test]
    fn format_match_joins_product_version_and_info() {
        let re = Regex::new(r"^HTTP/1\.1").unwrap();
        let caps = re.captures(b"HTTP/1.1 200 OK").unwrap();
        let m = ServiceMatch {
            service_name: "http".into(),
            regex: re,
            product_tpl: Some("Apache".into()),
            version_tpl: Some("2.4".into()),
            info_tpl: Some("protocol 2.0".into()),
            os_tpl: None,
            device_tpl: None,
            cpe_tpl: vec![],
            soft: false,
        };
        let s = format_match(&m, &caps);
        assert!(s.contains("Apache"));
        assert!(s.contains("2.4"));
        assert!(s.contains("(protocol 2.0)"));
    }

    #[test]
    fn format_match_empty_templates_falls_back_to_service_name() {
        let re = Regex::new(r".").unwrap();
        let caps = re.captures(b"x").unwrap();
        let m = ServiceMatch {
            service_name: "unknown".into(),
            regex: re,
            product_tpl: None,
            version_tpl: None,
            info_tpl: None,
            os_tpl: None,
            device_tpl: None,
            cpe_tpl: vec![],
            soft: false,
        };
        assert_eq!(format_match(&m, &caps), "unknown");
    }

    #[test]
    fn parses_sslports_and_rarity_on_tcp_probe() {
        let fixture = r#"
Probe TCP NULL q||
sslports 443,8443
rarity 3
match x m|^.| p/x/
"#;
        let sp = parse_probes(fixture).unwrap();
        let p = &sp.tcp[0];
        assert_eq!(p.rarity, 3);
        assert!(use_tls_for_tcp(443, p));
    }

    #[test]
    fn hash_comment_and_exclude_lines_skipped() {
        let fixture = r#"
# comment line
Exclude 1-65535
Probe TCP NULL q||
match x m|^.| p/x/
"#;
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.tcp.len(), 1);
    }

    #[test]
    fn consecutive_tcp_probes_both_parsed() {
        let fixture = r#"
Probe TCP A q|A|
Probe TCP B q|B|
"#;
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.tcp.len(), 2);
        assert_eq!(sp.tcp[0].name, "A");
        assert_eq!(sp.tcp[1].name, "B");
    }

    #[test]
    fn find_slash_field_extracts_info_template() {
        let tail = " p/Apache/ v/2.4/ i/protocol 2.0/ o/Linux/";
        assert_eq!(find_slash_field(tail, "i/"), Some("protocol 2.0".into()));
        assert_eq!(find_slash_field(tail, "o/"), Some("Linux".into()));
    }

    #[test]
    fn find_all_slash_fields_collects_cpe_entries() {
        let tail = " p/x/ cpe:/a:vendor:product:1.0/ cpe:/b:other:thing/";
        let cpe = find_all_slash_fields(tail, "cpe:/");
        assert_eq!(cpe.len(), 2);
        assert!(cpe[0].starts_with("cpe:/"));
    }

    #[test]
    fn match_line_with_os_and_device_templates() {
        let m = parse_match_line("match svc m|^ok| p/Px/o/FreeBSD/d/router/").unwrap();
        let m = m.unwrap();
        assert_eq!(m.os_tpl.as_deref(), Some("FreeBSD"));
        assert_eq!(m.device_tpl.as_deref(), Some("router"));
    }

    #[test]
    fn tcp_probe_then_udp_probe_flushes_tcp() {
        let fixture = r#"
Probe TCP T q|t|
Probe UDP U q|u|
"#;
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.tcp.len(), 1);
        assert_eq!(sp.udp.len(), 1);
        assert_eq!(sp.tcp[0].name, "T");
        assert_eq!(sp.udp[0].name, "U");
    }

    #[test]
    fn format_match_includes_os_and_device_brackets() {
        let re = Regex::new(r"^x").unwrap();
        let caps = re.captures(b"x").unwrap();
        let m = ServiceMatch {
            service_name: "svc".into(),
            regex: re,
            product_tpl: None,
            version_tpl: None,
            info_tpl: None,
            os_tpl: Some("Linux".into()),
            device_tpl: Some("switch".into()),
            cpe_tpl: vec![],
            soft: false,
        };
        let s = format_match(&m, &caps);
        assert!(s.contains("[Linux]"));
        assert!(s.contains("{switch}"));
    }

    #[test]
    fn parse_match_line_cpe_template() {
        let m = parse_match_line("match http m|^HTTP| p/Apache/ cpe:/a:apache:http_server/")
            .unwrap()
            .unwrap();
        assert_eq!(m.cpe_tpl.len(), 1);
        assert!(m.cpe_tpl[0].contains("apache"));
    }

    #[test]
    fn probe_ports_ok_empty_ranges_some() {
        let spec = parse_port_ranges_list("8080");
        assert!(probe_ports_ok(8080, &spec));
        assert!(!probe_ports_ok(8081, &spec));
    }

    #[test]
    fn parse_probes_default_totalwaitms_six_seconds() {
        let fixture = "Probe TCP NULL q||\n";
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.tcp[0].totalwait_ms, 6000);
    }

    #[test]
    fn parse_probes_default_rarity_five() {
        let fixture = "Probe UDP X q||\n";
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.udp[0].rarity, 5);
    }

    #[test]
    fn apply_template_missing_group_is_empty() {
        let re = Regex::new(r"^x").unwrap();
        let caps = re.captures(b"x").unwrap();
        assert_eq!(apply_template("$9", &caps), "");
    }

    #[test]
    fn parse_match_line_pipe_delimited_regex() {
        let m = parse_match_line("match ssh m|^SSH-| p/OpenSSH/")
            .unwrap()
            .unwrap();
        assert_eq!(m.service_name, "ssh");
    }

    #[test]
    fn parse_match_line_escaped_delimiter_in_pattern() {
        let m = parse_match_line(r"match x m|^foo\|bar| p/X/")
            .unwrap()
            .unwrap();
        assert_eq!(m.service_name, "x");
    }

    #[test]
    fn apply_template_multi_digit_group_index() {
        let re = Regex::new(r"^(.)(.)(.)").unwrap();
        let caps = re.captures(b"abc").unwrap();
        assert_eq!(apply_template("$1$2$3", &caps), "abc");
    }

    #[test]
    fn apply_template_group_ten_when_present() {
        let re = Regex::new(r"^(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)").unwrap();
        let caps = re.captures(b"abcdefghij").unwrap();
        assert_eq!(apply_template("$10", &caps), "j");
    }

    #[test]
    fn parse_probe_tcp_line_decodes_payload() {
        let (name, payload) =
            super::parse_probe_tcp_line("NULL q|GET / HTTP/1.0\\r\\n\\r\\n|").unwrap();
        assert_eq!(name, "NULL");
        assert!(payload.starts_with(b"GET"));
    }

    #[test]
    fn parse_probe_udp_line_decodes_payload() {
        let (name, payload) = super::parse_probe_udp_line("DNS q|\\0\\x00\\x01|").unwrap();
        assert_eq!(name, "DNS");
        assert!(!payload.is_empty());
    }

    #[test]
    fn parse_probes_tcp_ports_line_restricts_probe() {
        let fixture = "Probe TCP T q||\nports 22,80\n";
        let sp = parse_probes(fixture).unwrap();
        assert!(probe_ports_ok(22, &sp.tcp[0].ports));
        assert!(!probe_ports_ok(8080, &sp.tcp[0].ports));
    }

    #[test]
    fn parse_probes_skips_exclude_directive_line() {
        let fixture = "Exclude T\nProbe TCP T q||\n";
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.tcp.len(), 1);
        assert_eq!(sp.tcp[0].name, "T");
    }

    #[test]
    fn split_first_token_via_match_line_service_name() {
        let m = parse_match_line("match my-service m|^x| p/X/")
            .unwrap()
            .unwrap();
        assert_eq!(m.service_name, "my-service");
    }

    #[test]
    fn find_slash_field_info_template() {
        let tail = " p/Apache/ i/(Ubuntu)/ v/2.4/";
        assert_eq!(super::find_slash_field(tail, "i/"), Some("(Ubuntu)".into()));
    }

    #[test]
    fn format_match_includes_cpe_when_present() {
        let re = Regex::new(r"^HTTP").unwrap();
        let caps = re.captures(b"HTTP/1.1").unwrap();
        let m = ServiceMatch {
            service_name: "http".into(),
            regex: re,
            product_tpl: Some("Apache".into()),
            version_tpl: None,
            info_tpl: None,
            os_tpl: None,
            device_tpl: None,
            cpe_tpl: vec!["cpe:/a:apache:http_server".into()],
            soft: false,
        };
        let s = format_match(&m, &caps);
        assert!(s.contains("cpe:/a:apache:http_server"));
    }

    #[test]
    fn split_first_token_single_word() {
        let (a, b) = super::split_first_token("hello");
        assert_eq!(a, "hello");
        assert_eq!(b, "");
    }

    #[test]
    fn split_first_token_two_words() {
        let (a, b) = super::split_first_token("ssh m|^x|");
        assert_eq!(a, "ssh");
        assert_eq!(b, " m|^x|");
    }

    #[test]
    fn extract_m_delimited_simple_pattern() {
        let (pat, tail) = super::extract_m_delimited("m|^SSH-| p/OpenSSH/").unwrap();
        assert_eq!(pat, "^SSH-");
        assert!(tail.contains("p/"));
    }

    #[test]
    fn extract_p_v_templates_product_only() {
        let (p, v, _, _, _, _) = super::extract_p_v_templates(" p/Apache/ ");
        assert_eq!(p.as_deref(), Some("Apache"));
        assert!(v.is_none());
    }

    #[test]
    fn find_slash_field_missing_returns_none() {
        assert!(super::find_slash_field(" p/x/ ", "z/").is_none());
    }

    #[test]
    fn decode_nmap_escape_backslash_at_end_dropped() {
        assert_eq!(decode_nmap_escape_bytes(r"test\"), b"test");
    }

    #[test]
    fn parse_probes_udp_only_fixture() {
        let fixture = "Probe UDP X q||\n";
        let sp = parse_probes(fixture).unwrap();
        assert_eq!(sp.tcp.len(), 0);
        assert_eq!(sp.udp.len(), 1);
    }

    #[test]
    fn parse_match_line_no_m_field_returns_none() {
        assert!(parse_match_line("match ssh p/OpenSSH/").unwrap().is_none());
    }

    // Round-trip every byte 0x00..=0xFF through `\xNN` escapes (both nibble cases).
    // Catches: (a) off-by-one in `hex_nibble` boundary letters ('A'/'F'/'a'/'f');
    // (b) byte-order swap if the implementation accidentally computes `lo << 4 | hi`;
    // (c) sign-extension if the impl promotes the nibble to a signed type;
    // (d) accidental case-fold drop (existing tests cover only `ff` lower and `00`).
    #[test]
    fn decode_nmap_escape_bytes_hex_round_trip_full_byte_range() {
        for byte in 0u8..=255 {
            let upper = format!("\\x{byte:02X}");
            let lower = format!("\\x{byte:02x}");
            assert_eq!(
                decode_nmap_escape_bytes(&upper),
                vec![byte],
                "uppercase \\x{byte:02X} did not round-trip"
            );
            assert_eq!(
                decode_nmap_escape_bytes(&lower),
                vec![byte],
                "lowercase \\x{byte:02x} did not round-trip"
            );
        }
    }

    // `$0` per regex convention refers to the whole match. The implementation
    // uses `caps.get(n)` which DOES support n=0, so this should substitute the
    // entire matched text. Catches: a future refactor that special-cases or
    // skips index 0 (a common interpretation bug where `$0` means "literal $0").
    #[test]
    fn apply_template_dollar_zero_is_whole_match() {
        let re = Regex::new(r"S(SH)-(\d+)").unwrap();
        let caps = re.captures(b"prefix SSH-22 suffix").unwrap();
        assert_eq!(apply_template("[$0]", &caps), "[SSH-22]");
    }

    // `$N` for an out-of-range capture group must NOT panic — the function
    // is called per-banner across every match probe, so any out-of-range
    // template index would crash the version-scan worker. Catches: a regression
    // to `caps.get(n).unwrap()` instead of the current `if let Some(m) = ...`.
    #[test]
    fn apply_template_out_of_range_capture_silently_omitted_no_panic() {
        let re = Regex::new(r"^(\w+)$").unwrap();
        let caps = re.captures(b"hello").unwrap();
        // Group 1 = "hello", groups 2-9 do not exist. Mix of valid + invalid.
        let out = apply_template("[$1][$9]", &caps);
        assert_eq!(out, "[hello][]");
    }
}

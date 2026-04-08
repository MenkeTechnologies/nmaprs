//! Target parsing: hostnames, IPv4/IPv6, CIDR, nmap-style IPv4 octet ranges, `-iL` lines.

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use rand::Rng;
use thiserror::Error;

/// Hard cap to avoid accidental memory blow-ups on wide CIDRs.
const MAX_HOSTS_PER_TARGET: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct ExpandOpts {
    /// `-6`: resolve and expand IPv6 only.
    pub ipv6: bool,
    /// `-n`: no DNS.
    pub no_dns: bool,
}

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("invalid target: {0}")]
    Invalid(String),
    #[error("DNS resolution failed for {0}: {1}")]
    Dns(String, String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Read non-empty, non-comment lines from `-iL` (nmap-style).
pub fn read_input_list(path: &Path) -> Result<Vec<String>, TargetError> {
    let data = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(line.to_string());
    }
    if out.is_empty() {
        return Err(TargetError::Invalid("empty -iL file".into()));
    }
    Ok(out)
}

/// `-iR`: uniform random addresses (IPv4 unless `-6`).
pub fn random_addresses(count: u64, ipv6: bool) -> Vec<IpAddr> {
    let mut rng = rand::thread_rng();
    let mut v = Vec::with_capacity(count.min(65_536) as usize);
    for _ in 0..count {
        if ipv6 {
            let mut b = [0u8; 16];
            rng.fill(&mut b);
            // Bias toward global unicast space (roughly 2000::/3).
            b[0] = (b[0] & 0x0f) | 0x20;
            v.push(IpAddr::V6(Ipv6Addr::from(b)));
        } else {
            v.push(IpAddr::V4(Ipv4Addr::from(rng.gen::<u32>())));
        }
    }
    v
}

/// Expand one target token into concrete addresses (hostname → A/AAAA per `ExpandOpts`).
pub async fn expand_target(token: &str, opts: &ExpandOpts) -> Result<Vec<IpAddr>, TargetError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(TargetError::Invalid(token.to_string()));
    }

    if let Ok(net) = Ipv4Net::from_str(token) {
        let hosts: Vec<Ipv4Addr> = net.hosts().collect();
        if hosts.len() > MAX_HOSTS_PER_TARGET {
            return Err(TargetError::Invalid(format!(
                "CIDR {token} expands to {} hosts (> {MAX_HOSTS_PER_TARGET})",
                hosts.len()
            )));
        }
        return Ok(hosts.into_iter().map(IpAddr::V4).collect());
    }

    if opts.ipv6 {
        if let Ok(net) = Ipv6Net::from_str(token) {
            let hosts: Vec<Ipv6Addr> = net.hosts().take(MAX_HOSTS_PER_TARGET + 1).collect();
            if hosts.len() > MAX_HOSTS_PER_TARGET {
                return Err(TargetError::Invalid(format!(
                    "IPv6 CIDR {token} expands to too many hosts (> {MAX_HOSTS_PER_TARGET})"
                )));
            }
            return Ok(hosts.into_iter().map(IpAddr::V6).collect());
        }
    }

    if token.contains('/') && !opts.ipv6 {
        return Err(TargetError::Invalid(
            "IPv6 CIDR requires -6 (or use IPv4 CIDR)".into(),
        ));
    }

    if let Ok(ip) = Ipv4Addr::from_str(token) {
        return Ok(vec![IpAddr::V4(ip)]);
    }

    if opts.ipv6 {
        if let Ok(ip) = Ipv6Addr::from_str(token) {
            return Ok(vec![IpAddr::V6(ip)]);
        }
    }

    // nmap-style IPv4 192.168.0-255.1-254
    if token.chars().filter(|c| *c == '.').count() == 3 && token.chars().any(|c| c == '-') {
        return expand_ipv4_ranges(token).map(|v| v.into_iter().map(IpAddr::V4).collect());
    }

    if opts.no_dns {
        return Err(TargetError::Invalid(
            "numeric IP or CIDR required when -n is set".into(),
        ));
    }

    resolve_host(token, opts).await
}

fn expand_ipv4_ranges(spec: &str) -> Result<Vec<Ipv4Addr>, TargetError> {
    let parts: Vec<&str> = spec.split('.').collect();
    if parts.len() != 4 {
        return Err(TargetError::Invalid(spec.to_string()));
    }
    let mut octets: [Vec<u8>; 4] = [vec![], vec![], vec![], vec![]];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = expand_octet(p)?;
    }
    let mut out = Vec::new();
    for a in &octets[0] {
        for b in &octets[1] {
            for c in &octets[2] {
                for d in &octets[3] {
                    out.push(Ipv4Addr::new(*a, *b, *c, *d));
                    if out.len() > MAX_HOSTS_PER_TARGET {
                        return Err(TargetError::Invalid(format!(
                            "range {spec} expands to > {MAX_HOSTS_PER_TARGET} hosts"
                        )));
                    }
                }
            }
        }
    }
    Ok(out)
}

fn expand_octet(part: &str) -> Result<Vec<u8>, TargetError> {
    if let Ok(n) = part.parse::<u8>() {
        return Ok(vec![n]);
    }
    if let Some((a, b)) = part.split_once('-') {
        let start: u8 = a
            .parse()
            .map_err(|_| TargetError::Invalid(part.to_string()))?;
        let end: u8 = b
            .parse()
            .map_err(|_| TargetError::Invalid(part.to_string()))?;
        if start > end {
            return Err(TargetError::Invalid(part.to_string()));
        }
        return Ok((start..=end).collect());
    }
    Err(TargetError::Invalid(part.to_string()))
}

async fn resolve_host(host: &str, opts: &ExpandOpts) -> Result<Vec<IpAddr>, TargetError> {
    let mut addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| TargetError::Dns(host.to_string(), e.to_string()))?;
    let mut out: Vec<IpAddr> = addrs.by_ref().map(|a| a.ip()).collect();
    if opts.ipv6 {
        out.retain(|ip| ip.is_ipv6());
    } else {
        out.retain(|ip| ip.is_ipv4());
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(TargetError::Dns(
            host.to_string(),
            "no matching addresses for this address family".into(),
        ));
    }
    Ok(out)
}

pub fn resolve_host_blocking(host: &str, opts: &ExpandOpts) -> Result<Vec<IpAddr>, TargetError> {
    let mut out: Vec<IpAddr> = (host, 0)
        .to_socket_addrs()
        .map_err(|e| TargetError::Dns(host.to_string(), e.to_string()))?
        .map(|a| a.ip())
        .collect();
    if opts.ipv6 {
        out.retain(|ip| ip.is_ipv6());
    } else {
        out.retain(|ip| ip.is_ipv4());
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(TargetError::Dns(
            host.to_string(),
            "no matching addresses for this address family".into(),
        ));
    }
    Ok(out)
}

pub fn apply_exclude(
    hosts: Vec<IpAddr>,
    exclude: Option<&str>,
    exclude_file: Option<&std::path::Path>,
    opts: &ExpandOpts,
) -> Result<Vec<IpAddr>, TargetError> {
    let mut banned: HashSet<IpAddr> = HashSet::new();
    if let Some(s) = exclude {
        for t in s.split(',') {
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            for ip in expand_target_blocking(t, opts)? {
                banned.insert(ip);
            }
        }
    }
    if let Some(path) = exclude_file {
        let data = fs::read_to_string(path)
            .map_err(|e| TargetError::Invalid(format!("excludefile: {e}")))?;
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            for ip in expand_target_blocking(line, opts)? {
                banned.insert(ip);
            }
        }
    }
    Ok(hosts.into_iter().filter(|h| !banned.contains(h)).collect())
}

fn expand_target_blocking(token: &str, opts: &ExpandOpts) -> Result<Vec<IpAddr>, TargetError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(TargetError::Invalid(token.to_string()));
    }
    if let Ok(net) = Ipv4Net::from_str(token) {
        let hosts: Vec<Ipv4Addr> = net.hosts().collect();
        if hosts.len() > MAX_HOSTS_PER_TARGET {
            return Err(TargetError::Invalid(format!(
                "CIDR {token} expands to {} hosts (> {MAX_HOSTS_PER_TARGET})",
                hosts.len()
            )));
        }
        return Ok(hosts.into_iter().map(IpAddr::V4).collect());
    }
    if opts.ipv6 {
        if let Ok(net) = Ipv6Net::from_str(token) {
            let hosts: Vec<Ipv6Addr> = net.hosts().take(MAX_HOSTS_PER_TARGET + 1).collect();
            if hosts.len() > MAX_HOSTS_PER_TARGET {
                return Err(TargetError::Invalid(format!(
                    "IPv6 CIDR {token} expands to too many hosts (> {MAX_HOSTS_PER_TARGET})"
                )));
            }
            return Ok(hosts.into_iter().map(IpAddr::V6).collect());
        }
    }
    if let Ok(ip) = Ipv4Addr::from_str(token) {
        return Ok(vec![IpAddr::V4(ip)]);
    }
    if opts.ipv6 {
        if let Ok(ip) = Ipv6Addr::from_str(token) {
            return Ok(vec![IpAddr::V6(ip)]);
        }
    }
    if token.chars().filter(|c| *c == '.').count() == 3 && token.chars().any(|c| c == '-') {
        return expand_ipv4_ranges(token).map(|v| v.into_iter().map(IpAddr::V4).collect());
    }
    resolve_host_blocking(token, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_expands_v4() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let opts = ExpandOpts {
            ipv6: false,
            no_dns: true,
        };
        let ips = rt.block_on(expand_target("10.0.0.0/31", &opts)).unwrap();
        assert_eq!(ips.len(), 2);
    }
}

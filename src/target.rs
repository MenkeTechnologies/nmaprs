//! Target parsing: hostnames, IPv4, CIDR, nmap-style octet ranges.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

use ipnet::Ipv4Net;
use thiserror::Error;

/// Hard cap to avoid accidental memory blow-ups on wide CIDRs.
const MAX_HOSTS_PER_TARGET: usize = 65_536;

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("invalid target: {0}")]
    Invalid(String),
    #[error("DNS resolution failed for {0}: {1}")]
    Dns(String, String),
}

/// Expand one target token into concrete IPv4 addresses (hostname → A records).
pub async fn expand_target(token: &str, no_dns: bool) -> Result<Vec<Ipv4Addr>, TargetError> {
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
        return Ok(hosts);
    }

    if token.contains('/') {
        return Err(TargetError::Invalid(
            "IPv6 CIDR / non-IPv4 CIDR not supported in this build".into(),
        ));
    }

    if let Ok(ip) = Ipv4Addr::from_str(token) {
        return Ok(vec![ip]);
    }

    // nmap-style 192.168.0-255.1-254
    if token.chars().filter(|c| *c == '.').count() == 3 && token.chars().any(|c| c == '-') {
        return expand_ipv4_ranges(token);
    }

    if no_dns {
        return Err(TargetError::Invalid(
            "numeric IP or CIDR required when -n is set".into(),
        ));
    }

    resolve_host(token).await
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

async fn resolve_host(host: &str) -> Result<Vec<Ipv4Addr>, TargetError> {
    let mut addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| TargetError::Dns(host.to_string(), e.to_string()))?;
    let mut v4: Vec<Ipv4Addr> = addrs
        .by_ref()
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    v4.sort_unstable();
    v4.dedup();
    if v4.is_empty() {
        return Err(TargetError::Dns(
            host.to_string(),
            "no IPv4 addresses".into(),
        ));
    }
    Ok(v4)
}

/// Blocking resolve for tests / sync contexts.
pub fn resolve_host_blocking(host: &str) -> Result<Vec<Ipv4Addr>, TargetError> {
    let mut v4: Vec<Ipv4Addr> = (host, 0)
        .to_socket_addrs()
        .map_err(|e| TargetError::Dns(host.to_string(), e.to_string()))?
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    v4.sort_unstable();
    v4.dedup();
    if v4.is_empty() {
        return Err(TargetError::Dns(
            host.to_string(),
            "no IPv4 addresses".into(),
        ));
    }
    Ok(v4)
}

pub fn apply_exclude(
    hosts: Vec<Ipv4Addr>,
    exclude: Option<&str>,
    exclude_file: Option<&std::path::Path>,
) -> Result<Vec<Ipv4Addr>, TargetError> {
    let mut banned: HashSet<Ipv4Addr> = HashSet::new();
    if let Some(s) = exclude {
        for t in s.split(',') {
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            for ip in expand_target_blocking(t)? {
                banned.insert(ip);
            }
        }
    }
    if let Some(path) = exclude_file {
        let data = std::fs::read_to_string(path)
            .map_err(|e| TargetError::Invalid(format!("excludefile: {e}")))?;
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            for ip in expand_target_blocking(line)? {
                banned.insert(ip);
            }
        }
    }
    Ok(hosts.into_iter().filter(|h| !banned.contains(h)).collect())
}

fn expand_target_blocking(token: &str) -> Result<Vec<Ipv4Addr>, TargetError> {
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
        return Ok(hosts);
    }
    if let Ok(ip) = Ipv4Addr::from_str(token) {
        return Ok(vec![ip]);
    }
    if token.chars().filter(|c| *c == '.').count() == 3 && token.chars().any(|c| c == '-') {
        return expand_ipv4_ranges(token);
    }
    resolve_host_blocking(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_expands() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ips = rt.block_on(expand_target("10.0.0.0/31", true)).unwrap();
        assert_eq!(ips.len(), 2);
    }
}

//! Stream-parse Nmap `nmap-os-db` for fingerprint metadata (not full TCP/IP probe matching).
//!
//! Full OS classification like Nmap requires the probe suite (SEQ, OPS, T1–T7, etc.). When the DB
//! file is present we enrich TTL heuristics with example fingerprint titles whose `Class` OS family
//! aligns with the TTL bucket.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct OsEntry {
    pub name: String,
    pub family: String,
}

#[derive(Debug, Default, Clone)]
pub struct OsDb {
    pub entries: Vec<OsEntry>,
}

impl OsDb {
    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let reader = BufReader::new(f);
        let mut entries = Vec::new();
        let mut current_name: Option<String> = None;
        let mut got_class_for_current = false;

        for line in reader.lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(rest) = t.strip_prefix("Fingerprint ") {
                current_name = Some(rest.to_string());
                got_class_for_current = false;
            } else if t.starts_with("Class ") && current_name.is_some() && !got_class_for_current {
                if let Some(fam) = parse_class_family(t) {
                    if let Some(name) = current_name.take() {
                        entries.push(OsEntry { name, family: fam });
                        got_class_for_current = true;
                    }
                }
            }
        }

        Ok(OsDb { entries })
    }

    /// Example fingerprint titles whose `Class` family fits the TTL bucket (up to `max` items).
    pub fn examples_for_ttl(&self, ttl: Option<u8>, max: usize) -> Vec<&str> {
        let bucket = ttl_bucket(ttl);
        let mut out = Vec::new();
        for e in &self.entries {
            if family_matches_bucket(&e.family, bucket) {
                out.push(e.name.as_str());
                if out.len() >= max {
                    break;
                }
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TtlBucket {
    LinuxUnix,
    Windows,
    Network,
    Unknown,
}

fn ttl_bucket(ttl: Option<u8>) -> TtlBucket {
    match ttl {
        Some(t) if t <= 64 => TtlBucket::LinuxUnix,
        Some(t) if t <= 128 => TtlBucket::Windows,
        Some(_) => TtlBucket::Network,
        None => TtlBucket::Unknown,
    }
}

fn family_matches_bucket(family: &str, bucket: TtlBucket) -> bool {
    let f = family.to_lowercase();
    match bucket {
        TtlBucket::LinuxUnix => {
            f.contains("linux")
                || f.contains("unix")
                || f.contains("bsd")
                || f.contains("solaris")
                || f.contains("android")
        }
        TtlBucket::Windows => f.contains("windows") || f.contains("microsoft"),
        TtlBucket::Network => {
            f.contains("cisco")
                || f.contains("router")
                || f.contains("switch")
                || f.contains("embedded")
                || f.contains("VxWorks")
                || f.contains("vxworks")
        }
        TtlBucket::Unknown => false,
    }
}

/// `Class vendor | osfamily | osgen | type`
fn parse_class_family(line: &str) -> Option<String> {
    let rest = line.strip_prefix("Class ")?.trim();
    let mut parts = rest.split('|');
    let _vendor = parts.next()?.trim();
    let family = parts.next()?.trim();
    if family.is_empty() {
        return None;
    }
    Some(family.to_string())
}

/// Human-readable OS line combining TTL heuristic and optional DB examples.
pub fn format_os_guess(ttl: Option<u8>, db: Option<&OsDb>, max_examples: usize) -> String {
    let base = crate::os_detect::guess_from_ttl(ttl);
    let Some(db) = db else {
        return base.to_string();
    };
    let cap = max_examples.max(1);
    let ex = db.examples_for_ttl(ttl, cap);
    if ex.is_empty() {
        return format!("{base} (nmap-os-db loaded; full probe matching not implemented)");
    }
    format!("{base} — example DB titles: {}", ex.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_class_family() {
        let s = "Class Linux | Linux | 4.X | general purpose";
        assert_eq!(parse_class_family(s), Some("Linux".to_string()));
    }
}

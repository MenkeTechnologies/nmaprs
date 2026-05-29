//! Stream-parse Nmap `nmap-os-db` for fingerprint metadata (not full TCP/IP probe matching).
//!
//! Full OS classification like Nmap requires the probe suite (SEQ, OPS, T1–T7, etc.). When the DB
//! file is present we enrich TTL heuristics with example fingerprint titles whose `Class` OS family
//! aligns with the TTL bucket.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
/// `OsEntry` — see fields for layout.

#[derive(Debug, Clone)]
pub struct OsEntry {
    /// `name` field.
    pub name: String,
    /// `family` field.
    pub family: String,
}
/// `OsDb` — see fields for layout.

#[derive(Debug, Default, Clone)]
pub struct OsDb {
    /// `entries` field.
    pub entries: Vec<OsEntry>,
}

impl OsDb {
    /// `load` — see implementation.
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
        return format!("{base} (nmap-os-db loaded; no Class examples for this TTL bucket)");
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

    #[test]
    fn parse_class_family_empty_family_is_none() {
        let s = "Class Vendor |  | gen | type";
        assert_eq!(parse_class_family(s), None);
    }

    #[test]
    fn parse_class_family_missing_prefix_is_none() {
        assert_eq!(parse_class_family("NotClass Linux | Linux | 4.X"), None);
    }

    #[test]
    fn load_minimal_db_extracts_fingerprint_and_class() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(
            f,
            "Fingerprint Test Linux Box\nClass Linux | Linux | 4.X | general purpose\n"
        )
        .unwrap();
        f.flush().unwrap();
        let db = OsDb::load(f.path()).unwrap();
        assert_eq!(db.entries.len(), 1);
        assert_eq!(db.entries[0].name, "Test Linux Box");
        assert_eq!(db.entries[0].family, "Linux");
    }

    #[test]
    fn examples_for_ttl_linux_bucket_matches_linux_family() {
        let db = OsDb {
            entries: vec![
                OsEntry {
                    name: "Linux 1".into(),
                    family: "Linux".into(),
                },
                OsEntry {
                    name: "Windows 1".into(),
                    family: "Windows".into(),
                },
            ],
        };
        let ex = db.examples_for_ttl(Some(32), 5);
        assert_eq!(ex, vec!["Linux 1"]);
    }

    #[test]
    fn examples_for_ttl_windows_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Win7".into(),
                family: "Microsoft Windows".into(),
            }],
        };
        let ex = db.examples_for_ttl(Some(128), 3);
        assert_eq!(ex, vec!["Win7"]);
    }

    #[test]
    fn examples_for_ttl_network_bucket_cisco() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "IOS".into(),
                family: "Cisco IOS".into(),
            }],
        };
        let ex = db.examples_for_ttl(Some(255), 2);
        assert_eq!(ex, vec!["IOS"]);
    }

    #[test]
    fn examples_for_ttl_unknown_returns_empty() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Linux 1".into(),
                family: "Linux".into(),
            }],
        };
        assert!(db.examples_for_ttl(None, 5).is_empty());
    }

    #[test]
    fn examples_for_ttl_respects_max_cap() {
        let db = OsDb {
            entries: vec![
                OsEntry {
                    name: "A".into(),
                    family: "Linux".into(),
                },
                OsEntry {
                    name: "B".into(),
                    family: "BSD".into(),
                },
                OsEntry {
                    name: "C".into(),
                    family: "Solaris".into(),
                },
            ],
        };
        assert_eq!(db.examples_for_ttl(Some(60), 2).len(), 2);
    }

    #[test]
    fn format_os_guess_without_db_is_ttl_only() {
        assert_eq!(
            format_os_guess(Some(64), None, 3),
            "Linux/Unix (TTL heuristic)"
        );
    }

    #[test]
    fn format_os_guess_with_db_includes_example_titles() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Ubuntu 22".into(),
                family: "Linux".into(),
            }],
        };
        let s = format_os_guess(Some(64), Some(&db), 2);
        assert!(s.contains("Ubuntu 22"));
        assert!(s.contains("example DB titles"));
    }

    #[test]
    fn format_os_guess_loaded_db_no_bucket_match() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Win10".into(),
                family: "Windows".into(),
            }],
        };
        let s = format_os_guess(Some(64), Some(&db), 2);
        assert!(s.contains("no Class examples"));
    }

    #[test]
    fn examples_for_ttl_bsd_family_in_linux_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "FreeBSD 13".into(),
                family: "FreeBSD".into(),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(32), 1), vec!["FreeBSD 13"]);
    }

    #[test]
    fn examples_for_ttl_android_family_in_linux_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Android 12".into(),
                family: "Android".into(),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(60), 1), vec!["Android 12"]);
    }

    #[test]
    fn examples_for_ttl_microsoft_family_in_windows_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Win11".into(),
                family: "Microsoft Windows".into(),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(100), 1), vec!["Win11"]);
    }

    #[test]
    fn examples_for_ttl_cisco_in_network_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "IOS-XE".into(),
                family: "Cisco IOS".into(),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(255), 1), vec!["IOS-XE"]);
    }

    #[test]
    fn examples_for_ttl_router_keyword_in_network_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "EdgeRouter".into(),
                family: "Router OS".into(),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(200), 1), vec!["EdgeRouter"]);
    }

    #[test]
    fn examples_for_ttl_linux_does_not_match_windows_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Ubuntu".into(),
                family: "Linux".into(),
            }],
        };
        assert!(db.examples_for_ttl(Some(128), 5).is_empty());
    }

    #[test]
    fn parse_class_family_trims_whitespace() {
        let s = "Class  Vendor |  Linux  | 4.X | general purpose";
        assert_eq!(parse_class_family(s), Some("Linux".to_string()));
    }

    #[test]
    fn load_db_skips_fingerprint_without_class() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(f, "Fingerprint Orphan\n").unwrap();
        f.flush().unwrap();
        let db = OsDb::load(f.path()).unwrap();
        assert!(db.entries.is_empty());
    }

    #[test]
    fn format_os_guess_max_examples_at_least_one() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Linux A".into(),
                family: "Linux".into(),
            }],
        };
        let s = format_os_guess(Some(64), Some(&db), 0);
        assert!(s.contains("Linux A"));
    }

    #[test]
    fn examples_for_ttl_solaris_in_linux_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Solaris 11".into(),
                family: "Solaris".into(),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(50), 1), vec!["Solaris 11"]);
    }

    #[test]
    fn parse_class_family_missing_pipe_is_none() {
        assert!(parse_class_family("Class only one field").is_none());
    }

    #[test]
    fn examples_for_ttl_respects_max_examples_cap() {
        let db = OsDb {
            entries: vec![
                OsEntry {
                    name: "Linux A".into(),
                    family: "Linux".into(),
                },
                OsEntry {
                    name: "Linux B".into(),
                    family: "Linux".into(),
                },
            ],
        };
        assert_eq!(db.examples_for_ttl(Some(64), 1).len(), 1);
    }

    #[test]
    fn examples_for_ttl_unknown_bucket_empty() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "Linux".into(),
                family: "Linux".into(),
            }],
        };
        assert!(db.examples_for_ttl(None, 5).is_empty());
    }

    #[test]
    fn examples_for_ttl_macos_excluded_from_linux_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "macOS 13".into(),
                family: "Mac OS X".into(),
            }],
        };
        assert!(db.examples_for_ttl(Some(64), 1).is_empty());
    }

    #[test]
    fn examples_for_ttl_irix_excluded_from_linux_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "IRIX 6".into(),
                family: "IRIX".into(),
            }],
        };
        assert!(db.examples_for_ttl(Some(32), 1).is_empty());
    }

    #[test]
    fn load_db_multiple_fingerprints() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(f, "Fingerprint One").unwrap();
        writeln!(f, "Class Linux | Linux | 4.X | general purpose").unwrap();
        writeln!(f, "Fingerprint Two").unwrap();
        writeln!(f, "Class Windows | Windows | 10 | general purpose").unwrap();
        f.flush().unwrap();
        let db = OsDb::load(f.path()).unwrap();
        assert_eq!(db.entries.len(), 2);
    }

    #[test]
    fn format_os_guess_none_ttl_unknown() {
        assert_eq!(format_os_guess(None, None, 2), "unknown");
    }

    #[test]
    fn parse_class_family_extracts_second_field() {
        let s = "Class Vendor | Windows | 10 | general purpose";
        assert_eq!(parse_class_family(s), Some("Windows".to_string()));
    }

    #[test]
    fn examples_for_ttl_hpux_excluded_from_linux_bucket() {
        let db = OsDb {
            entries: vec![OsEntry {
                name: "HP-UX 11".into(),
                family: "HP-UX".into(),
            }],
        };
        assert!(db.examples_for_ttl(Some(60), 1).is_empty());
    }
}

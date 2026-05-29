//! Full `nmap-os-db` reference fingerprints + MatchPoints scoring (Nmap `compare_fingerprints` / `AVal_match`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

use crate::fp_match::expr_match;

/// Test order matches Nmap `FingerPrintDef` (`osscan.cc` `test_attrs`).
pub const NUM_FP_TESTS: usize = 13;

/// Per-test names matching `osscan.cc` `test_attrs` order. Indexed by
/// the same `usize` positions as `FingerPrintDef.tests[]` so a row
/// lookup is `TEST_NAMES[i]`.
pub const TEST_NAMES: [&str; NUM_FP_TESTS] = [
    "SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE",
];

/// Attribute names per test (same order as Nmap `FingerPrintDef::test_attrs`).
pub const TEST_ATTRS: [&[&str]; NUM_FP_TESTS] = [
    &["SP", "GCD", "ISR", "TI", "CI", "II", "SS", "TS"],
    &["O1", "O2", "O3", "O4", "O5", "O6"],
    &["W1", "W2", "W3", "W4", "W5", "W6"],
    &["R", "DF", "T", "TG", "W", "O", "CC", "Q"],
    &["R", "DF", "T", "TG", "S", "A", "F", "RD", "Q"],
    &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    &[
        "R", "DF", "T", "TG", "IPL", "UN", "RIPL", "RID", "RIPCK", "RUCK", "RUD",
    ],
    &["R", "DFI", "T", "TG", "CD"],
];
/// `MatchPoints` — see fields for layout.

#[derive(Debug, Clone)]
pub struct MatchPoints {
    /// `weights` field.
    pub weights: [HashMap<String, u16>; NUM_FP_TESTS],
}

impl Default for MatchPoints {
    fn default() -> Self {
        Self {
            weights: std::array::from_fn(|_| HashMap::new()),
        }
    }
}

impl MatchPoints {
    /// `parse_block` — see implementation.
    pub fn parse_block(lines: &[String]) -> Result<Self> {
        let mut weights: [HashMap<String, u16>; NUM_FP_TESTS] =
            std::array::from_fn(|_| HashMap::new());
        for line in lines {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let Some((name, body)) = parse_paren_line(t) else {
                continue;
            };
            let ti = TEST_NAMES
                .iter()
                .position(|&n| n == name)
                .with_context(|| format!("unknown MatchPoints test {name}"))?;
            for part in body.split('%') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let Some((k, v)) = part.split_once('=') else {
                    continue;
                };
                let pts: u16 = v
                    .trim()
                    .parse()
                    .with_context(|| format!("MatchPoints {name}.{k}"))?;
                weights[ti].insert(k.to_string(), pts);
            }
        }
        Ok(MatchPoints { weights })
    }
}
/// `ReferenceFingerprint` — see fields for layout.

#[derive(Debug, Clone)]
pub struct ReferenceFingerprint {
    /// `name` field.
    pub name: String,
    /// `line` field.
    pub line: usize,
    /// `family` field.
    pub family: Option<String>,
    /// `tests` field.
    pub tests: [Option<HashMap<String, String>>; NUM_FP_TESTS],
}
/// `FingerprintDb` — see fields for layout.

#[derive(Debug, Default, Clone)]
pub struct FingerprintDb {
    /// `match_points` field.
    pub match_points: MatchPoints,
    /// `references` field.
    pub references: Vec<ReferenceFingerprint>,
}

impl FingerprintDb {
    /// `load` — see implementation.
    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let reader = BufReader::new(f);
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

        let mut mp_lines: Vec<String> = Vec::new();
        let mut i = 0usize;
        while i < lines.len() {
            let t = lines[i].trim();
            if t == "MatchPoints" {
                i += 1;
                while i < lines.len() {
                    let row = lines[i].trim();
                    if row.is_empty() {
                        i += 1;
                        break;
                    }
                    if row.starts_with('#') {
                        i += 1;
                        continue;
                    }
                    if row.starts_with("Fingerprint ") {
                        break;
                    }
                    if TEST_NAMES.iter().any(|n| row.starts_with(&format!("{n}("))) {
                        mp_lines.push(lines[i].clone());
                    }
                    i += 1;
                }
                continue;
            }
            i += 1;
        }

        let match_points = MatchPoints::parse_block(&mp_lines)?;

        let mut references = Vec::new();
        i = 0;
        while i < lines.len() {
            let t = lines[i].trim();
            if let Some(rest) = t.strip_prefix("Fingerprint ") {
                let name = rest.trim().to_string();
                let line_no = i + 1;
                i += 1;
                let mut tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
                    std::array::from_fn(|_| None);
                let mut family: Option<String> = None;
                while i < lines.len() {
                    let row = lines[i].trim();
                    if row.is_empty() || row.starts_with('#') {
                        i += 1;
                        continue;
                    }
                    if row.starts_with("Fingerprint ") {
                        break;
                    }
                    if row.starts_with("CPE ") {
                        i += 1;
                        continue;
                    }
                    if family.is_none() {
                        if let Some(rest) = row.strip_prefix("Class ") {
                            let mut parts = rest.split('|');
                            let _vendor = parts.next();
                            if let Some(fam) = parts.next() {
                                let fam = fam.trim();
                                if !fam.is_empty() {
                                    family = Some(fam.to_string());
                                }
                            }
                            i += 1;
                            continue;
                        }
                    } else if row.starts_with("Class ") {
                        i += 1;
                        continue;
                    }
                    if let Some((tn, body)) = parse_paren_line(row) {
                        if let Some(ti) = TEST_NAMES.iter().position(|&n| n == tn) {
                            let mut m = HashMap::new();
                            for part in body.split('%') {
                                let part = part.trim();
                                if part.is_empty() {
                                    continue;
                                }
                                if let Some((k, v)) = part.split_once('=') {
                                    m.insert(k.to_string(), v.to_string());
                                }
                            }
                            tests[ti] = Some(m);
                        }
                    }
                    i += 1;
                }
                references.push(ReferenceFingerprint {
                    name,
                    line: line_no,
                    family,
                    tests,
                });
                continue;
            }
            i += 1;
        }

        Ok(FingerprintDb {
            match_points,
            references,
        })
    }

    /// Best accuracy in `[0,1]` and index into `references`.
    pub fn best_match(&self, subject: &SubjectFingerprint, threshold: f64) -> Option<(usize, f64)> {
        let mut best: Option<(usize, f64)> = None;
        for (idx, rf) in self.references.iter().enumerate() {
            let acc = compare_one(&self.match_points, rf, subject);
            if acc >= threshold && best.is_none_or(|(_, a)| acc > a) {
                best = Some((idx, acc));
            }
        }
        best
    }
}

/// Observed fingerprint values (ASCII test values, no reference expressions).
#[derive(Debug, Clone, Default)]
pub struct SubjectFingerprint {
    /// `tests` field.
    pub tests: [Option<HashMap<String, String>>; NUM_FP_TESTS],
}

impl FingerprintDb {
    /// Example fingerprint titles whose `Class` family fits the TTL bucket (up to `max`).
    pub fn examples_for_ttl(&self, ttl: Option<u8>, max: usize) -> Vec<&str> {
        let bucket = ttl_bucket(ttl);
        let mut out = Vec::new();
        for r in &self.references {
            if let Some(fam) = &r.family {
                if family_matches_bucket(fam, bucket) {
                    out.push(r.name.as_str());
                    if out.len() >= max {
                        break;
                    }
                }
            }
        }
        out
    }

    /// Human-readable OS line: fingerprint match → TTL + DB example titles fallback.
    pub fn format_os_guess(&self, ttl: Option<u8>, max_examples: usize) -> String {
        let base = crate::os_detect::guess_from_ttl(ttl);
        let cap = max_examples.max(1);
        let ex = self.examples_for_ttl(ttl, cap);
        if ex.is_empty() {
            return format!("{base} (nmap-os-db loaded; no Class examples for this TTL bucket)");
        }
        format!("{base} — example DB titles: {}", ex.join("; "))
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
                || f.contains("vxworks")
        }
        TtlBucket::Unknown => false,
    }
}

fn parse_paren_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let open = line.find('(')?;
    let name = line[..open].trim();
    let rest = &line[open + 1..];
    let close = rest.rfind(')')?;
    Some((name, &rest[..close]))
}

fn compare_one(
    mp: &MatchPoints,
    reference: &ReferenceFingerprint,
    subject: &SubjectFingerprint,
) -> f64 {
    let mut subtests: u64 = 0;
    let mut ok: u64 = 0;
    for ti in 0..NUM_FP_TESTS {
        let Some(ref_map) = &reference.tests[ti] else {
            continue;
        };
        let sub_map = subject.tests[ti].as_ref();
        let test_name = TEST_NAMES[ti];
        let attrs = TEST_ATTRS[ti];
        for aname in attrs.iter().copied() {
            let Some(ref_expr) = ref_map.get(aname) else {
                continue;
            };
            let Some(weight) = mp.weights[ti].get(aname) else {
                continue;
            };
            let pts = u64::from(*weight);
            let Some(obs_map) = sub_map else {
                continue;
            };
            let Some(obs_val) = obs_map.get(aname) else {
                continue;
            };
            subtests += pts;
            let nested = test_name == "OPS" || aname == "O";
            if expr_match(obs_val, ref_expr, nested) {
                ok += pts;
            }
        }
    }
    if subtests == 0 {
        return 0.0;
    }
    ok as f64 / subtests as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_matchpoints_line() {
        let lines = vec!["SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)".to_string()];
        let mp = MatchPoints::parse_block(&lines).expect("mp");
        assert_eq!(mp.weights[0].get("SP"), Some(&25));
    }

    #[test]
    fn parse_paren_line_extracts_name_and_body() {
        let (name, body) = parse_paren_line("T1(R=Y%DF=Y%T=40)").unwrap();
        assert_eq!(name, "T1");
        assert_eq!(body, "R=Y%DF=Y%T=40");
    }

    #[test]
    fn parse_paren_line_no_paren_is_none() {
        assert!(parse_paren_line("SEQ SP=25").is_none());
    }

    #[test]
    fn matchpoints_skips_comments_and_blanks() {
        let lines = vec![
            "# comment".to_string(),
            String::new(),
            "WIN(W1=15%W2=15%W3=15%W4=15%W5=15%W6=15)".to_string(),
        ];
        let mp = MatchPoints::parse_block(&lines).unwrap();
        assert_eq!(mp.weights[2].get("W1"), Some(&15));
    }

    #[test]
    fn matchpoints_unknown_test_errors() {
        let lines = vec!["NOTATEST(X=1)".to_string()];
        assert!(MatchPoints::parse_block(&lines).is_err());
    }

    #[test]
    fn compare_one_perfect_match_scores_one() {
        let mut mp = MatchPoints::default();
        mp.weights[4].insert("R".into(), 10);
        let mut ref_tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
            std::array::from_fn(|_| None);
        ref_tests[4] = Some(HashMap::from([("R".into(), "Y".into())]));
        let rf = ReferenceFingerprint {
            name: "ref".into(),
            line: 1,
            family: None,
            tests: ref_tests,
        };
        let mut sub = SubjectFingerprint::default();
        sub.tests[4] = Some(HashMap::from([("R".into(), "Y".into())]));
        assert!((compare_one(&mp, &rf, &sub) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compare_one_partial_match() {
        let mut mp = MatchPoints::default();
        mp.weights[4].insert("R".into(), 10);
        mp.weights[4].insert("DF".into(), 10);
        let mut ref_tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
            std::array::from_fn(|_| None);
        ref_tests[4] = Some(HashMap::from([
            ("R".into(), "Y".into()),
            ("DF".into(), "N".into()),
        ]));
        let rf = ReferenceFingerprint {
            name: "ref".into(),
            line: 1,
            family: None,
            tests: ref_tests,
        };
        let mut sub = SubjectFingerprint::default();
        sub.tests[4] = Some(HashMap::from([
            ("R".into(), "Y".into()),
            ("DF".into(), "Y".into()),
        ]));
        assert!((compare_one(&mp, &rf, &sub) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn compare_one_no_subject_attrs_scores_zero() {
        let mut mp = MatchPoints::default();
        mp.weights[0].insert("SP".into(), 25);
        let mut ref_tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
            std::array::from_fn(|_| None);
        ref_tests[0] = Some(HashMap::from([("SP".into(), "25".into())]));
        let rf = ReferenceFingerprint {
            name: "ref".into(),
            line: 1,
            family: None,
            tests: ref_tests,
        };
        assert_eq!(compare_one(&mp, &rf, &SubjectFingerprint::default()), 0.0);
    }

    #[test]
    fn load_minimal_fingerprint_db() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(f, "MatchPoints").unwrap();
        writeln!(
            f,
            "SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)"
        )
        .unwrap();
        writeln!(f).unwrap();
        writeln!(f, "Fingerprint Example OS").unwrap();
        writeln!(f, "Class Linux | Linux | 4.X | general purpose").unwrap();
        writeln!(
            f,
            "SEQ(SP=25%GCD=1%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)"
        )
        .unwrap();
        f.flush().unwrap();
        let db = FingerprintDb::load(f.path()).unwrap();
        assert_eq!(db.references.len(), 1);
        assert_eq!(db.references[0].name, "Example OS");
        assert_eq!(db.references[0].family.as_deref(), Some("Linux"));
    }

    #[test]
    fn best_match_returns_highest_accuracy() {
        let mut mp = MatchPoints::default();
        mp.weights[4].insert("R".into(), 10);
        let mk_ref = |name: &str, expr: &str| ReferenceFingerprint {
            name: name.into(),
            line: 1,
            family: None,
            tests: {
                let mut t: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
                    std::array::from_fn(|_| None);
                t[4] = Some(HashMap::from([("R".into(), expr.into())]));
                t
            },
        };
        let db = FingerprintDb {
            match_points: mp,
            references: vec![mk_ref("weak", "N"), mk_ref("strong", "Y")],
        };
        let mut sub = SubjectFingerprint::default();
        sub.tests[4] = Some(HashMap::from([("R".into(), "Y".into())]));
        let (idx, acc) = db.best_match(&sub, 0.5).unwrap();
        assert_eq!(idx, 1);
        assert!((acc - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn examples_for_ttl_filters_by_family() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![
                ReferenceFingerprint {
                    name: "Linux box".into(),
                    line: 1,
                    family: Some("Linux".into()),
                    tests: std::array::from_fn(|_| None),
                },
                ReferenceFingerprint {
                    name: "Win box".into(),
                    line: 2,
                    family: Some("Windows".into()),
                    tests: std::array::from_fn(|_| None),
                },
            ],
        };
        let ex = db.examples_for_ttl(Some(64), 5);
        assert_eq!(ex, vec!["Linux box"]);
    }

    #[test]
    fn format_os_guess_includes_db_titles() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![ReferenceFingerprint {
                name: "Debian 12".into(),
                line: 1,
                family: Some("Linux".into()),
                tests: std::array::from_fn(|_| None),
            }],
        };
        let s = db.format_os_guess(Some(64), 2);
        assert!(s.contains("Debian 12"));
    }

    #[test]
    fn best_match_below_threshold_returns_none() {
        let mut mp = MatchPoints::default();
        mp.weights[4].insert("R".into(), 10);
        let mk_ref = |expr: &str| ReferenceFingerprint {
            name: "r".into(),
            line: 1,
            family: None,
            tests: {
                let mut t: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
                    std::array::from_fn(|_| None);
                t[4] = Some(HashMap::from([("R".into(), expr.into())]));
                t
            },
        };
        let db = FingerprintDb {
            match_points: mp,
            references: vec![mk_ref("Y")],
        };
        let mut sub = SubjectFingerprint::default();
        sub.tests[4] = Some(HashMap::from([("R".into(), "N".into())]));
        assert!(db.best_match(&sub, 0.99).is_none());
    }

    #[test]
    fn compare_one_expr_range_match() {
        let mut mp = MatchPoints::default();
        mp.weights[4].insert("T".into(), 10);
        let mut ref_tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
            std::array::from_fn(|_| None);
        ref_tests[4] = Some(HashMap::from([("T".into(), "40-50".into())]));
        let rf = ReferenceFingerprint {
            name: "ref".into(),
            line: 1,
            family: None,
            tests: ref_tests,
        };
        let mut sub = SubjectFingerprint::default();
        sub.tests[4] = Some(HashMap::from([("T".into(), "45".into())]));
        assert!((compare_one(&mp, &rf, &sub) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_paren_line_trims_outer_whitespace() {
        let (name, body) = parse_paren_line("  T2( R=Y )  ").unwrap();
        assert_eq!(name, "T2");
        assert_eq!(body, " R=Y ");
    }

    #[test]
    fn examples_for_ttl_unknown_returns_empty() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![ReferenceFingerprint {
                name: "Linux".into(),
                line: 1,
                family: Some("Linux".into()),
                tests: std::array::from_fn(|_| None),
            }],
        };
        assert!(db.examples_for_ttl(None, 5).is_empty());
    }

    #[test]
    fn format_os_guess_no_examples_uses_loaded_message() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![ReferenceFingerprint {
                name: "Win".into(),
                line: 1,
                family: Some("Windows".into()),
                tests: std::array::from_fn(|_| None),
            }],
        };
        let s = db.format_os_guess(Some(64), 2);
        assert!(s.contains("no Class examples"));
    }

    #[test]
    fn matchpoints_parses_multiple_attributes() {
        let lines = vec!["T1(R=40%DF=50%T=60)".to_string()];
        let mp = MatchPoints::parse_block(&lines).unwrap();
        assert_eq!(mp.weights[4].get("R"), Some(&40));
        assert_eq!(mp.weights[4].get("DF"), Some(&50));
        assert_eq!(mp.weights[4].get("T"), Some(&60));
    }

    #[test]
    fn load_db_skips_cpe_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(f, "Fingerprint CPE host").unwrap();
        writeln!(f, "Class Linux | Linux | 4.X | general purpose").unwrap();
        writeln!(f, "CPE cpe:/o:linux:linux_kernel").unwrap();
        writeln!(
            f,
            "SEQ(SP=25%GCD=1%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)"
        )
        .unwrap();
        f.flush().unwrap();
        let db = FingerprintDb::load(f.path()).unwrap();
        assert_eq!(db.references.len(), 1);
        assert_eq!(db.references[0].name, "CPE host");
    }

    #[test]
    fn compare_one_missing_weight_skips_attribute() {
        let mp = MatchPoints::default();
        let mut ref_tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
            std::array::from_fn(|_| None);
        ref_tests[4] = Some(HashMap::from([("R".into(), "Y".into())]));
        let rf = ReferenceFingerprint {
            name: "ref".into(),
            line: 1,
            family: None,
            tests: ref_tests,
        };
        assert_eq!(compare_one(&mp, &rf, &SubjectFingerprint::default()), 0.0);
    }

    #[test]
    fn test_names_has_thirteen_entries() {
        assert_eq!(TEST_NAMES.len(), NUM_FP_TESTS);
        assert_eq!(TEST_NAMES[0], "SEQ");
        assert_eq!(TEST_NAMES[NUM_FP_TESTS - 1], "IE");
    }

    #[test]
    fn best_match_picks_first_when_equal_accuracy() {
        let mut mp = MatchPoints::default();
        mp.weights[4].insert("R".into(), 10);
        let mk = |name: &str| ReferenceFingerprint {
            name: name.into(),
            line: 1,
            family: None,
            tests: {
                let mut t: [Option<HashMap<String, String>>; NUM_FP_TESTS] =
                    std::array::from_fn(|_| None);
                t[4] = Some(HashMap::from([("R".into(), "Y".into())]));
                t
            },
        };
        let db = FingerprintDb {
            match_points: mp,
            references: vec![mk("first"), mk("second")],
        };
        let mut sub = SubjectFingerprint::default();
        sub.tests[4] = Some(HashMap::from([("R".into(), "Y".into())]));
        let (idx, acc) = db.best_match(&sub, 0.5).unwrap();
        assert_eq!(idx, 0);
        assert!((acc - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn examples_for_ttl_vxworks_in_network_bucket() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![ReferenceFingerprint {
                name: "VxWorks box".into(),
                line: 1,
                family: Some("VxWorks".into()),
                tests: std::array::from_fn(|_| None),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(200), 1), vec!["VxWorks box"]);
    }

    #[test]
    fn matchpoints_invalid_weight_value_errors() {
        let lines = vec!["SEQ(SP=abc)".to_string()];
        assert!(MatchPoints::parse_block(&lines).is_err());
    }

    #[test]
    fn parse_paren_line_nested_parens_in_body() {
        let line = "T1(R=Y%DF=Y%T=40%W=0)";
        let (name, body) = parse_paren_line(line).unwrap();
        assert_eq!(name, "T1");
        assert!(body.contains("R=Y"));
    }

    #[test]
    fn format_os_guess_empty_db_falls_back_to_ttl() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![],
        };
        let s = db.format_os_guess(Some(64), 2);
        assert!(!s.is_empty());
    }

    #[test]
    fn matchpoints_empty_block_yields_empty_weights() {
        let mp = MatchPoints::parse_block(&[]).unwrap();
        assert!(mp.weights[0].is_empty());
    }

    #[test]
    fn matchpoints_skips_hash_comments() {
        let lines = vec!["# comment".into(), "SEQ(SP=10)".into()];
        let mp = MatchPoints::parse_block(&lines).unwrap();
        assert_eq!(mp.weights[0].get("SP"), Some(&10));
    }

    #[test]
    fn matchpoints_unknown_test_name_errors() {
        let lines = vec!["NOPE(R=1)".into()];
        assert!(MatchPoints::parse_block(&lines).is_err());
    }

    #[test]
    fn test_attrs_seq_has_eight_keys() {
        assert_eq!(TEST_ATTRS[0].len(), 8);
    }

    #[test]
    fn test_attrs_t1_has_nine_keys() {
        assert_eq!(TEST_ATTRS[4].len(), 9);
    }

    #[test]
    fn parse_paren_line_no_paren_returns_none() {
        assert!(parse_paren_line("SEQ SP=10").is_none());
    }

    #[test]
    fn examples_for_ttl_zero_max_still_yields_one_match() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![ReferenceFingerprint {
                name: "Linux".into(),
                line: 1,
                family: Some("Linux".into()),
                tests: std::array::from_fn(|_| None),
            }],
        };
        assert_eq!(db.examples_for_ttl(Some(64), 0), vec!["Linux"]);
    }

    #[test]
    fn format_os_guess_windows_ttl_with_windows_ref() {
        let db = FingerprintDb {
            match_points: MatchPoints::default(),
            references: vec![ReferenceFingerprint {
                name: "Win10".into(),
                line: 1,
                family: Some("Windows".into()),
                tests: std::array::from_fn(|_| None),
            }],
        };
        let s = db.format_os_guess(Some(128), 1);
        assert!(s.contains("Win10"));
    }

    #[test]
    fn matchpoints_multiple_tests_in_block() {
        let lines = vec!["SEQ(SP=10)".into(), "T1(R=20)".into()];
        let mp = MatchPoints::parse_block(&lines).unwrap();
        assert_eq!(mp.weights[0].get("SP"), Some(&10));
        assert_eq!(mp.weights[4].get("R"), Some(&20));
    }

    #[test]
    fn num_fp_tests_matches_test_names_len() {
        assert_eq!(NUM_FP_TESTS, TEST_NAMES.len());
    }
}

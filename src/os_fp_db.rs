//! Full `nmap-os-db` reference fingerprints + MatchPoints scoring (Nmap `compare_fingerprints` / `AVal_match`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

use crate::fp_match::expr_match;

/// Test order matches Nmap `FingerPrintDef` (`osscan.cc` `test_attrs`).
pub const NUM_FP_TESTS: usize = 13;

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
    &["R", "DF", "T", "TG", "IPL", "UN", "RIPL", "RID", "RIPCK", "RUCK", "RUD"],
    &["R", "DFI", "T", "TG", "CD"],
];

#[derive(Debug, Clone)]
pub struct MatchPoints {
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
    pub fn parse_block(lines: &[String]) -> Result<Self> {
        let mut weights: [HashMap<String, u16>; NUM_FP_TESTS] = std::array::from_fn(|_| HashMap::new());
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
                let pts: u16 = v.trim().parse().with_context(|| format!("MatchPoints {name}.{k}"))?;
                weights[ti].insert(k.to_string(), pts);
            }
        }
        Ok(MatchPoints { weights })
    }
}

#[derive(Debug, Clone)]
pub struct ReferenceFingerprint {
    pub name: String,
    pub line: usize,
    pub tests: [Option<HashMap<String, String>>; NUM_FP_TESTS],
}

#[derive(Debug, Default, Clone)]
pub struct FingerprintDb {
    pub match_points: MatchPoints,
    pub references: Vec<ReferenceFingerprint>,
}

impl FingerprintDb {
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
                let mut tests: [Option<HashMap<String, String>>; NUM_FP_TESTS] = std::array::from_fn(|_| None);
                while i < lines.len() {
                    let row = lines[i].trim();
                    if row.is_empty() || row.starts_with('#') {
                        i += 1;
                        continue;
                    }
                    if row.starts_with("Fingerprint ") {
                        break;
                    }
                    if row.starts_with("Class ") || row.starts_with("CPE ") {
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
            if acc >= threshold && best.map_or(true, |(_, a)| acc > a) {
                best = Some((idx, acc));
            }
        }
        best
    }
}

/// Observed fingerprint values (ASCII test values, no reference expressions).
#[derive(Debug, Clone, Default)]
pub struct SubjectFingerprint {
    pub tests: [Option<HashMap<String, String>>; NUM_FP_TESTS],
}

fn parse_paren_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let open = line.find('(')?;
    let name = line[..open].trim();
    let rest = &line[open + 1..];
    let close = rest.rfind(')')?;
    Some((name, &rest[..close]))
}

fn compare_one(mp: &MatchPoints, reference: &ReferenceFingerprint, subject: &SubjectFingerprint) -> f64 {
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
}

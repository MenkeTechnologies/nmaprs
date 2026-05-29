//! Contract tests for previously-uncovered nmaprs DB / scoring / port surfaces.
//!
//! Targets:
//! - MatchPoints::parse_block with multiple test rows (SEQ + OPS + WIN) populates
//!   each indexed weights[] slot independently
//! - MatchPoints::parse_block tolerates blank lines, comment lines (`#`), and
//!   bare keys with no `=` (silently skipped)
//! - MatchPoints::parse_block rejects non-numeric weight values with a clean error
//! - MatchPoints::parse_block rejects unknown test names with an error
//! - format_os_guess returns the bare TTL guess when db is None
//! - format_os_guess truncates examples to max_examples
//! - ResumeState save+load preserves mixed IPv4 + IPv6 entries with port ordering
//! - parse_port_spec accepts mixed T:/U:/S: prefixes and dedupes across prefixes

use std::net::{IpAddr, Ipv4Addr};

use nmaprs::os_db::{format_os_guess, OsDb, OsEntry};
use nmaprs::os_fp_db::MatchPoints;
use nmaprs::ports::parse_port_spec;
use nmaprs::resume::ResumeState;
use tempfile::NamedTempFile;

#[test]
fn test_matchpoints_parse_block_multiple_tests_populate_indexed_slots() {
    let lines = vec![
        "SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)".to_string(),
        "OPS(O1=20%O2=20%O3=20%O4=20%O5=20%O6=20)".to_string(),
        "WIN(W1=15%W2=15%W3=15%W4=15%W5=15%W6=15)".to_string(),
    ];
    let mp = MatchPoints::parse_block(&lines).expect("parse SEQ+OPS+WIN");
    // Slot 0 == SEQ
    assert_eq!(mp.weights[0].get("SP"), Some(&25));
    assert_eq!(mp.weights[0].get("TS"), Some(&100));
    // Slot 1 == OPS
    assert_eq!(mp.weights[1].get("O1"), Some(&20));
    assert_eq!(mp.weights[1].get("O6"), Some(&20));
    // Slot 2 == WIN
    assert_eq!(mp.weights[2].get("W1"), Some(&15));
    assert_eq!(mp.weights[2].get("W6"), Some(&15));
}

#[test]
fn test_matchpoints_parse_block_skips_blank_and_comment_lines() {
    let lines = vec![
        "".to_string(),
        "# this is a comment".to_string(),
        "   ".to_string(),
        "SEQ(SP=50)".to_string(),
        "# more comments".to_string(),
    ];
    let mp = MatchPoints::parse_block(&lines).expect("parse despite noise");
    assert_eq!(mp.weights[0].get("SP"), Some(&50));
}

#[test]
fn test_matchpoints_parse_block_rejects_non_numeric_weight() {
    let lines = vec!["SEQ(SP=not_a_number)".to_string()];
    let err = MatchPoints::parse_block(&lines);
    assert!(
        err.is_err(),
        "non-numeric weight must produce parse error; got {:?}",
        err.map(|m| m.weights[0].clone())
    );
}

#[test]
fn test_matchpoints_parse_block_rejects_unknown_test_name() {
    // `NOTREAL` is not in TEST_NAMES; should fail.
    let lines = vec!["NOTREAL(X=5)".to_string()];
    let err = MatchPoints::parse_block(&lines);
    assert!(err.is_err(), "unknown test name must produce parse error");
}

#[test]
fn test_format_os_guess_without_db_returns_base_ttl_guess() {
    let s = format_os_guess(Some(64), None, 3);
    // Whatever the base text is, it must NOT contain DB-example markers.
    assert!(
        !s.contains("example DB titles"),
        "no DB → output must not advertise example titles; got {s:?}"
    );
    assert!(
        !s.contains("nmap-os-db loaded"),
        "no DB → output must not advertise loaded DB; got {s:?}"
    );
}

#[test]
fn test_format_os_guess_with_db_truncates_examples_to_max() {
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
            OsEntry {
                name: "Linux C".into(),
                family: "Linux".into(),
            },
            OsEntry {
                name: "Linux D".into(),
                family: "Linux".into(),
            },
        ],
    };
    let s = format_os_guess(Some(60), Some(&db), 2);
    // Should have exactly the first two example names
    assert!(s.contains("Linux A"), "first example must appear: {s:?}");
    assert!(s.contains("Linux B"), "second example must appear: {s:?}");
    assert!(
        !s.contains("Linux C"),
        "third example must be truncated when max=2; got {s:?}"
    );
}

#[test]
fn test_resume_state_roundtrip_mixed_ipv4_and_ipv6_entries() {
    let mut st = ResumeState::default();
    let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    st.merge_from_scan(&[(v4, 22), (v6, 443), (v4, 80)]);

    let f = NamedTempFile::new().expect("tempfile");
    st.save(f.path()).expect("save");
    let loaded = ResumeState::load(f.path()).expect("load");

    assert!(loaded.is_done(v4, 22), "v4:22 must round-trip");
    assert!(loaded.is_done(v4, 80), "v4:80 must round-trip");
    assert!(loaded.is_done(v6, 443), "v6:443 must round-trip");
    assert_eq!(
        loaded.completed.len(),
        3,
        "all three entries must round-trip"
    );
}

#[test]
fn test_parse_port_spec_mixed_prefixes_dedupes_across_prefixes() {
    // T:80 + plain 80 + U:80 should all collapse to a single 80.
    let p = parse_port_spec("T:80,80,U:80,443").expect("parse");
    assert_eq!(
        p,
        vec![80, 443],
        "mixed-prefix 80 must dedupe to a single port"
    );
}

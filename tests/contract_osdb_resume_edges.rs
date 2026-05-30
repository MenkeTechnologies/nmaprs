//! Contract tests for previously-uncovered surfaces:
//!   - `OsDb::examples_for_ttl(None, ...)` — Unknown TTL bucket yields empty Vec
//!     (no family matches Unknown bucket per `family_matches_bucket`).
//!   - `OsDb::examples_for_ttl` with a Windows-family DB and TTL=128 returns
//!     entries; with TTL=64 returns empty (cross-bucket isolation).
//!   - `OsDb::examples_for_ttl` with `max=1` returns exactly 1 even when more
//!     would match (early-break pin).
//!   - `format_os_guess(None, Some(&db), N)` — Unknown TTL bucket + non-empty
//!     DB produces the "no Class examples for this TTL bucket" sentinel string.
//!   - `parse_port_spec("80,80,80")` collapses three duplicates to one entry.
//!   - `parse_port_spec("443,80,22")` sorts ascending (canonical order).
//!   - `ResumeState::is_done` after `merge_from_scan` (no save/load) reflects
//!     in-memory state — pinning the merge logic separately from persistence.
//!   - `ResumeState::merge_from_scan` with empty pairs slice leaves state
//!     untouched (no spurious mutation).
//!
//! Earlier rounds pinned:
//!   - parse_port_spec mixed T:/U:/S: prefixes (NOT pure-dedupe of identical port)
//!   - ResumeState save+load roundtrip (NOT in-memory merge isolation)
//!   - format_os_guess with TTL=64+DB (NOT Unknown TTL + DB sentinel)

use std::net::{IpAddr, Ipv4Addr};

use nmaprs::os_db::{format_os_guess, OsDb, OsEntry};
use nmaprs::ports::parse_port_spec;
use nmaprs::resume::ResumeState;

fn linux_db() -> OsDb {
    OsDb {
        entries: vec![
            OsEntry {
                name: "Linux Alpha".into(),
                family: "Linux".into(),
            },
            OsEntry {
                name: "Linux Beta".into(),
                family: "Linux".into(),
            },
            OsEntry {
                name: "Linux Gamma".into(),
                family: "Linux".into(),
            },
        ],
    }
}

fn windows_db() -> OsDb {
    OsDb {
        entries: vec![
            OsEntry {
                name: "Windows 10".into(),
                family: "Windows".into(),
            },
            OsEntry {
                name: "Windows Server".into(),
                family: "Microsoft Windows".into(),
            },
        ],
    }
}

/// `examples_for_ttl(None, max)` — Unknown bucket has no family matches, must
/// return empty Vec even with non-empty DB.
#[test]
fn test_examples_for_ttl_none_returns_empty_for_unknown_bucket() {
    let db = linux_db();
    let r = db.examples_for_ttl(None, 5);
    assert!(
        r.is_empty(),
        "Unknown TTL bucket must yield no examples; got {r:?}"
    );
}

/// Windows-family DB + TTL in Linux bucket (TTL=64) returns empty: cross-bucket
/// isolation. Same DB + TTL=128 returns entries.
#[test]
fn test_examples_for_ttl_windows_db_isolated_from_linux_bucket() {
    let db = windows_db();
    let r_linux_bucket = db.examples_for_ttl(Some(64), 5);
    assert!(
        r_linux_bucket.is_empty(),
        "Windows-family DB must not match TTL=64 (Linux bucket); got {r_linux_bucket:?}"
    );
    let r_windows_bucket = db.examples_for_ttl(Some(128), 5);
    assert!(
        !r_windows_bucket.is_empty(),
        "Windows-family DB must match TTL=128 (Windows bucket); got {r_windows_bucket:?}"
    );
}

/// `max=1` cap returns exactly 1 entry even when 3 would match. Pins the
/// early-break clamp.
#[test]
fn test_examples_for_ttl_max_one_returns_exactly_one_entry() {
    let db = linux_db();
    let r = db.examples_for_ttl(Some(64), 1);
    assert_eq!(r.len(), 1, "max=1 must return exactly one entry; got {r:?}");
}

/// `format_os_guess(None, Some(&db), N)` — Unknown TTL with non-empty DB
/// produces the sentinel about no Class examples (not the bare TTL guess).
#[test]
fn test_format_os_guess_none_ttl_with_db_emits_no_examples_sentinel() {
    let db = linux_db();
    let s = format_os_guess(None, Some(&db), 3);
    assert!(
        s.contains("no Class examples") || s.contains("nmap-os-db loaded"),
        "Unknown TTL + DB must emit the no-examples sentinel; got {s:?}"
    );
}

/// `parse_port_spec("80,80,80")` must dedupe to a single entry.
#[test]
fn test_parse_port_spec_three_duplicate_ports_collapses_to_one() {
    let p = parse_port_spec("80,80,80").expect("parse");
    assert_eq!(
        p,
        vec![80],
        "three duplicate 80 must dedupe to [80]; got {p:?}"
    );
}

/// `parse_port_spec` returns ports in ascending order regardless of input order.
#[test]
fn test_parse_port_spec_sorts_ascending_regardless_of_input_order() {
    let p = parse_port_spec("443,80,22").expect("parse");
    assert_eq!(
        p,
        vec![22, 80, 443],
        "ports must be sorted ascending; got {p:?}"
    );
}

/// `ResumeState::is_done` reflects in-memory merge BEFORE any save/load. Pins
/// the merge logic separately from persistence.
#[test]
fn test_resume_state_is_done_after_in_memory_merge_no_persistence() {
    let mut st = ResumeState::default();
    let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v6: IpAddr = "2001:db8::5".parse().unwrap();
    st.merge_from_scan(&[(v4, 22), (v6, 443)]);
    assert!(
        st.is_done(v4, 22),
        "v4:22 must be done after in-memory merge"
    );
    assert!(
        st.is_done(v6, 443),
        "v6:443 must be done after in-memory merge"
    );
    assert!(!st.is_done(v4, 23), "untracked port must not be done");
}

/// `ResumeState::merge_from_scan(&[])` is a no-op: empty input leaves state
/// completely untouched.
#[test]
fn test_resume_state_merge_empty_slice_is_noop() {
    let mut st = ResumeState::default();
    let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
    st.merge_from_scan(&[(v4, 22)]);
    let before = st.completed.clone();
    st.merge_from_scan(&[]);
    assert_eq!(
        st.completed, before,
        "empty merge must not mutate completed; before={before:?} after={:?}",
        st.completed
    );
}

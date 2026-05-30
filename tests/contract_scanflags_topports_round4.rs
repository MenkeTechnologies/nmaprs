//! Round 4 contract tests for previously-uncovered surfaces:
//!   - `parse_scanflags` is order-independent: `"SYN ACK" == "ACK SYN"` and
//!     `"SYN|ACK" == "ACK|SYN"`. Pin the commutativity of the bit-OR semantics.
//!   - `parse_scanflags` with all 8 flags listed yields 0xFF (every bit of the
//!     byte set). Pins the full-coverage case explicitly so a missed entry in
//!     the KEYWORDS table is caught.
//!   - `parse_port_spec("80-80")` returns `[80]` — collapsed single-element
//!     range (no double-emission of endpoint).
//!   - `parse_port_spec("0,65535")` accepts both extremes of u16 — boundary pin.
//!   - `top_ports(N+1)` is NOT necessarily a prefix of `top_ports(N+1)` content
//!     but `top_ports(N)` must always be a SUBSET of `top_ports(N+M)` — pin the
//!     monotonic-growth contract.
//!   - `parse_exclude_ports("22,80")` returns a HashSet whose `.len()` equals
//!     the unique port count and whose membership matches the spec — pinning
//!     that the Set returned can't be silently shrunk by a future change.
//!   - `format_os_guess(Some(64), None, 5)` (TTL known, NO DB) returns the
//!     bare TTL guess string — pinning the early-return-without-DB path
//!     separately from the DB-loaded paths covered in earlier rounds.
//!
//! Earlier rounds pinned:
//!   - parse_scanflags glued/spaced/piped/mixed-case, individual flag isolation,
//!     unknown-token errors, empty errors, all-common-flags (NOT order-independence
//!     algebra explicitly; NOT all-eight-bits 0xFF check)
//!   - parse_port_spec ranges, lists, dedupe, sort, reversed-range-errors, T:/U:/S:
//!     mixed prefixes (NOT "80-80" single-element range, NOT both u16 extremes)
//!   - top_ports zero, default-subset (NOT monotonic-growth subset relation
//!     between top(N) and top(N+M))
//!   - parse_exclude_ports same-as-spec-set semantics (NOT len-equals-unique-count)
//!   - format_os_guess None/None, None/Some(db), TTL+empty-DB (NOT TTL+None DB)
//!
//! These tests pin DIFFERENT surfaces: scanflags commutativity, full-byte
//! coverage, port boundary u16 extremes, top_ports monotonic subset.

use std::collections::HashSet;

use nmaprs::os_db::format_os_guess;
use nmaprs::ports::{parse_exclude_ports, parse_port_spec, top_ports};
use nmaprs::scanflags::parse_scanflags;
use pnet::packet::tcp::TcpFlags;

/// `parse_scanflags` is order-independent at the bit-OR level: re-arranging
/// tokens must yield the same byte. Pins commutativity of `|`.
#[test]
fn test_parse_scanflags_token_order_does_not_change_result_byte() {
    let a = parse_scanflags("SYN ACK").expect("syn ack");
    let b = parse_scanflags("ACK SYN").expect("ack syn");
    assert_eq!(
        a, b,
        "scanflags must be order-independent (SYN ACK == ACK SYN)"
    );

    let c = parse_scanflags("SYN|ACK|FIN").expect("syn|ack|fin");
    let d = parse_scanflags("FIN|SYN|ACK").expect("fin|syn|ack");
    let e = parse_scanflags("ACK|FIN|SYN").expect("ack|fin|syn");
    assert_eq!(c, d, "pipe-separated order must not matter");
    assert_eq!(d, e, "any permutation must yield the same byte");
}

/// `parse_scanflags` with all 8 flag names listed yields a byte where every
/// known TCP-flag bit is set. Pin full-byte coverage — catches a missed entry
/// in the KEYWORDS table.
#[test]
fn test_parse_scanflags_all_eight_flag_names_sets_every_known_bit() {
    let all = parse_scanflags("SYN,ACK,FIN,RST,PSH,URG,ECE,CWR").expect("all eight");
    let expected = TcpFlags::SYN
        | TcpFlags::ACK
        | TcpFlags::FIN
        | TcpFlags::RST
        | TcpFlags::PSH
        | TcpFlags::URG
        | TcpFlags::ECE
        | TcpFlags::CWR;
    assert_eq!(
        all, expected,
        "all 8 flag names must OR to every known TCP-flag bit"
    );
    // Verify popcount: 8 bits set.
    assert_eq!(
        all.count_ones(),
        8,
        "all-flags byte must have popcount 8; got {} ({all:08b})",
        all.count_ones()
    );
}

/// `parse_port_spec("80-80")` collapses to `[80]` (single-element range must
/// not emit duplicates).
#[test]
fn test_parse_port_spec_single_element_range_collapses_to_one_entry() {
    let p = parse_port_spec("80-80").expect("80-80");
    assert_eq!(
        p,
        vec![80],
        "range with equal endpoints must collapse to one entry; got {p:?}"
    );
}

/// `parse_port_spec("0,65535")` accepts both u16 extremes — pin boundary case.
#[test]
fn test_parse_port_spec_accepts_both_u16_extremes_0_and_65535() {
    let p = parse_port_spec("0,65535").expect("0,65535");
    assert_eq!(p, vec![0, 65535], "both u16 extremes must parse; got {p:?}");
}

/// `top_ports(N)` is a SUBSET of `top_ports(N+M)` for M >= 0. Pins the
/// monotonic-growth contract: smaller-N's results must all appear in
/// larger-N's results.
#[test]
fn test_top_ports_smaller_n_is_subset_of_larger_n() {
    let small: HashSet<u16> = top_ports(10).into_iter().collect();
    let larger: HashSet<u16> = top_ports(50).into_iter().collect();
    assert!(
        small.is_subset(&larger),
        "top_ports(10) must be a subset of top_ports(50); small={small:?} larger={larger:?}"
    );

    let mid: HashSet<u16> = top_ports(25).into_iter().collect();
    assert!(
        small.is_subset(&mid),
        "top_ports(10) must be a subset of top_ports(25)"
    );
    assert!(
        mid.is_subset(&larger),
        "top_ports(25) must be a subset of top_ports(50)"
    );
}

/// `parse_exclude_ports("22,80,443")` returns a HashSet of exactly 3 entries
/// matching the unique port set. Pins the Set-returned cardinality contract.
#[test]
fn test_parse_exclude_ports_set_cardinality_matches_unique_count() {
    let s = parse_exclude_ports("22,80,443").expect("3 ports");
    assert_eq!(s.len(), 3, "3 unique ports must yield Set of len 3");
    assert!(s.contains(&22));
    assert!(s.contains(&80));
    assert!(s.contains(&443));

    // Dedupe at the set layer: "80,80,80" → len 1.
    let one = parse_exclude_ports("80,80,80").expect("three duplicates");
    assert_eq!(
        one.len(),
        1,
        "three identical ports must yield Set of len 1"
    );
    assert!(one.contains(&80));
}

/// `format_os_guess(Some(64), None, 5)` (TTL known, DB absent) takes the
/// no-DB early-return branch — returns the bare TTL guess string without any
/// "nmap-os-db" sentinel or "example DB titles" prefix.
#[test]
fn test_format_os_guess_with_ttl_and_no_db_returns_bare_ttl_guess_no_db_sentinel() {
    let s = format_os_guess(Some(64), None, 5);
    assert!(
        !s.contains("nmap-os-db"),
        "no-DB path must NOT mention 'nmap-os-db'; got {s:?}"
    );
    assert!(
        !s.contains("example DB titles"),
        "no-DB path must NOT mention 'example DB titles'; got {s:?}"
    );
    // The base string should be non-empty (TTL guess always produces a label).
    assert!(
        !s.trim().is_empty(),
        "no-DB path must still produce a base TTL-guess label; got {s:?}"
    );
}

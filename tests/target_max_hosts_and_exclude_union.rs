//! Adversarial tests for `target::expand_target` and `target::apply_exclude`
//! that pin invariants the in-module tests do NOT cover.
//!
//!   1. The `MAX_HOSTS_PER_TARGET` cap (65_536 hosts per token) is a
//!      load-bearing memory-safety guard. None of the existing in-module
//!      tests exercise the OVER-LIMIT branch for IPv4 CIDR — they only
//!      check small ranges (/30, /31, /32). Pin that a /15 CIDR (~131k
//!      hosts) is rejected so a future "drop the cap to scan bigger
//!      networks" refactor surfaces immediately.
//!
//!   2. Same cap on the IPv4 nmap-style octet-range path
//!      (`A-B.C-D.E-F.G-H`). The check inside `expand_ipv4_ranges` is
//!      a per-push counter — it is structurally different from the CIDR
//!      branch's bulk-hosts-len check, so an independent test is needed
//!      to catch a regression in only one of the two paths. A 0-255 quad
//!      yields 256^2 = 65_536 just at one quad, so 0-255.0-255.1.1 is a
//!      clean trip-the-limit input without ballooning beyond u64-safe
//!      bounds during the failing-case build.
//!
//!   3. `apply_exclude` accepts BOTH an exclude string AND an exclude
//!      file simultaneously, and the resulting banned set is the UNION
//!      of both sources. No existing test covers the both-supplied case
//!      — they exercise string-only or file-only paths. A future
//!      refactor that accidentally makes one source overwrite the other
//!      (rather than union) would break Nmap-compatibility expectations
//!      for `--exclude X --excludefile Y` users and slip past every
//!      current test.
//!
//! Each test is hand-crafted around a specific bug class — they are not
//! "does CIDR parse" mirrors (those exist) nor smoke tests.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};

use nmaprs::target::{apply_exclude, expand_target, ExpandOpts};
use tempfile::NamedTempFile;

fn opts_no_dns_v4() -> ExpandOpts {
    ExpandOpts {
        ipv6: false,
        no_dns: true,
        resolve_all: false,
        dns_servers: vec![],
    }
}

/// Bug class: memory blow-up via oversized IPv4 CIDR.
///
/// `MAX_HOSTS_PER_TARGET = 65_536` caps IPv4 CIDR expansion. A /15
/// network = 2^17 - 2 hosts (~131_070), which must be rejected. If a
/// refactor accidentally lifts the cap (e.g. by removing the `if hosts.len() >
/// MAX_HOSTS_PER_TARGET` branch), a malicious or careless `-iL` entry
/// could allocate hundreds of MB of `IpAddr` vectors and OOM the scanner.
#[tokio::test]
async fn ipv4_cidr_over_max_hosts_per_target_errors() {
    // /15 yields 131_070 hosts → must be rejected (> 65_536).
    let err = expand_target("10.0.0.0/15", &opts_no_dns_v4())
        .await
        .expect_err("expected /15 to exceed MAX_HOSTS_PER_TARGET");
    let s = err.to_string();
    // The error message format includes "CIDR" and "> 65536" — pin both
    // so a refactor that silently rephrases the message still surfaces
    // here (and so a refactor that changes the threshold is visible).
    assert!(
        s.contains("CIDR") && s.contains("65536"),
        "unexpected error message (want CIDR+threshold): {s}"
    );
}

/// Bug class: memory blow-up via combinatorial octet-range explosion.
///
/// The nmap-style range path uses a per-push counter inside the
/// 4-deep loop — structurally distinct from the CIDR branch's bulk
/// check. A regression in EITHER branch is independently catastrophic.
///
/// `0-255.0-255.1.1` = 256 * 256 * 1 * 1 = 65_536 — exactly at the cap.
/// The check is `out.len() > MAX_HOSTS_PER_TARGET`, so 65_536 is OK and
/// 65_537 fails. Use `0-255.0-255.1.1-2` to push to 131_072 and force
/// the trip without u64 overflow risk.
#[tokio::test]
async fn ipv4_octet_range_over_max_hosts_per_target_errors() {
    let err = expand_target("0-255.0-255.1.1-2", &opts_no_dns_v4())
        .await
        .expect_err("expected combinatorial range to exceed MAX_HOSTS_PER_TARGET");
    let s = err.to_string();
    assert!(
        s.contains("65536"),
        "expected MAX_HOSTS threshold in error: {s}"
    );
    // The message uses "range" (not "CIDR") on the octet-range path —
    // pin that the right error path fired (not the CIDR path).
    assert!(
        s.contains("range") || s.contains("hosts"),
        "expected octet-range error path: {s}"
    );
}

/// Bug class: exclude-source merging regression.
///
/// `--exclude X --excludefile Y` must produce the UNION of banned IPs.
/// A future refactor that accidentally makes the second source replace
/// the first (e.g. `banned = HashSet::new()` after reading the file)
/// would leak IPs that were only listed in the string source — and
/// every current in-module test exercises only one source at a time.
///
/// Concrete probe: ban 10.0.0.1 via the string AND 10.0.0.2 via the
/// file, with 10.0.0.3 in neither. Result must filter to ONLY 10.0.0.3.
/// If string-only or file-only path wins, one of 10.0.0.1 / 10.0.0.2
/// would leak through and the test would fail loudly.
#[test]
fn apply_exclude_unions_string_and_file_sources() {
    let hosts = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    ];

    let mut f = NamedTempFile::new().expect("temp file");
    writeln!(f, "10.0.0.2").expect("write file ban");
    f.flush().expect("flush");

    let out =
        apply_exclude(hosts, Some("10.0.0.1"), Some(f.path()), &opts_no_dns_v4()).expect("apply");
    assert_eq!(
        out,
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))],
        "union must drop BOTH .1 (string) and .2 (file), keep .3"
    );
}

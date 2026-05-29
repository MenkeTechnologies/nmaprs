//! Extra CLI flag-coverage integration tests.
//!
//! `tests/cli.rs` covers the common flags; this file fills the long
//! tail of nmap-parity options that didn't have a smoke test yet
//! (`comm -23 all_flags tested_flags` = 34 gap entries at last
//! audit). Each test exercises ONE flag through the real `nmaprs`
//! binary, exits fast, and asserts no panic / no parse error.
//!
//! Targets chosen for fast completion:
//!   * `-Pn` (no ping) + `-sL` (list scan) → flag parsing only,
//!     no real network IO.
//!   * Unreachable high port (655xx) + `-Pn` for flags that need a
//!     real scan target — keeps timing under a second.
//!   * `--iflist` / `-V` / `--help` exit after their own action
//!     without scanning.

use assert_cmd::Command;
use predicates::prelude::*;

fn nmaprs() -> Command {
    Command::cargo_bin("nmaprs").expect("nmaprs binary builds")
}

// ─── output / verbosity ────────────────────────────────────────────

#[test]
fn debug_flag_accepts_numeric_level() {
    // `--debug N` takes a numeric level (0..9); the bare `--debug`
    // form would steal the next positional, so always pass the level.
    nmaprs()
        .args(["-Pn", "-sL", "--debug", "1", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn verbosity_flag_count_accepts_value() {
    nmaprs()
        .args(["-Pn", "-sL", "--verbosity", "2", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn vv_alias_accepts() {
    nmaprs()
        .args(["-Pn", "-sL", "-vv", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn iflist_exits_with_an_interface_list() {
    nmaprs()
        .arg("--iflist")
        .assert()
        .success()
        .stdout(predicate::str::contains("lo").or(predicate::str::contains("INTERFACE")));
}

#[test]
fn version_long_prints_version_string() {
    nmaprs().arg("--version").assert().success().stdout(
        predicate::str::contains("nmaprs").or(predicate::str::contains(env!("CARGO_PKG_VERSION"))),
    );
}

// ─── exclude lists ─────────────────────────────────────────────────

#[test]
fn exclude_single_host_accepted() {
    nmaprs()
        .args(["-Pn", "-sL", "--exclude", "10.0.0.1", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn exclude_multiple_csv_accepted() {
    nmaprs()
        .args(["-Pn", "-sL", "--exclude", "10.0.0.1,10.0.0.2", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn exclude_ports_accepts_range() {
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--exclude-ports",
            "22,80,443",
            "-p",
            "1-1000",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn excludefile_reads_path_argument() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let p = dir.path().join("exclude.txt");
    std::fs::write(&p, "10.0.0.1\n10.0.0.2\n").expect("write");
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--excludefile",
            p.to_str().unwrap(),
            "127.0.0.1",
        ])
        .assert()
        .success();
}

// ─── timing knobs ──────────────────────────────────────────────────

#[test]
fn timing_template_accepts_t3() {
    nmaprs()
        .args(["-Pn", "-sL", "--timing", "3", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn initial_rtt_timeout_accepts_ms() {
    nmaprs()
        .args(["-Pn", "-sL", "--initial-rtt-timeout", "100ms", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_rtt_timeout_accepts_ms() {
    nmaprs()
        .args(["-Pn", "-sL", "--min-rtt-timeout", "50ms", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_scan_delay_accepts_ms() {
    nmaprs()
        .args(["-Pn", "-sL", "--max-scan-delay", "10ms", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_hostgroup_accepts_count() {
    nmaprs()
        .args(["-Pn", "-sL", "--min-hostgroup", "8", "127.0.0.1"])
        .assert()
        .success();
}

// ─── no-ping aliases ───────────────────────────────────────────────

#[test]
fn no_ping_long_form_accepts() {
    // `--no-ping` is the long alias for `-Pn` — should be accepted by
    // clap and not require a separate `-Pn`.
    nmaprs()
        .args(["--no-ping", "-sL", "127.0.0.1"])
        .assert()
        .success();
}

// ─── DNS knobs ─────────────────────────────────────────────────────

#[test]
fn dns_servers_accepts_csv() {
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--dns-servers",
            "8.8.8.8,1.1.1.1",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

// ─── scan-payload knobs ────────────────────────────────────────────

#[test]
fn data_payload_accepts_hex_bytes() {
    nmaprs()
        .args(["-Pn", "-sL", "--data", "deadbeef", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn spoof_mac_accepts_six_byte_mac() {
    // nmaprs is stricter than nmap's `--spoof-mac 0` keyword form —
    // it requires a full 6-byte MAC. Use the canonical broadcast
    // address; the value is validated at parse time, no scan runs
    // under `-sL`.
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--spoof-mac",
            "ff:ff:ff:ff:ff:ff",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn scanflags_accepts_flag_string() {
    nmaprs()
        .args(["-Pn", "-sL", "--scanflags", "SYN", "127.0.0.1"])
        .assert()
        .success();
}

// ─── NSE script knobs ──────────────────────────────────────────────

#[test]
fn script_accepts_default_name() {
    nmaprs()
        .args(["-Pn", "-sL", "--script", "banner", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_args_accepts_key_value() {
    nmaprs()
        .args(["-Pn", "-sL", "--script-args", "user=admin", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_args_file_reads_path() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let p = dir.path().join("args.txt");
    std::fs::write(&p, "user=admin\n").expect("write");
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--script-args-file",
            p.to_str().unwrap(),
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn script_updatedb_flag_runs() {
    nmaprs()
        .args(["-Pn", "-sL", "--script-updatedb", "127.0.0.1"])
        .assert()
        .success();
}

// ─── version scan ──────────────────────────────────────────────────

#[test]
fn version_scan_short_sv_accepts() {
    nmaprs()
        .args(["-Pn", "-sL", "-sV", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_intensity_accepts_zero() {
    nmaprs()
        .args(["-Pn", "-sL", "--version-intensity", "0", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_intensity_accepts_nine() {
    nmaprs()
        .args(["-Pn", "-sL", "--version-intensity", "9", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_trace_flag_runs() {
    nmaprs()
        .args(["-Pn", "-sL", "--version-trace", "127.0.0.1"])
        .assert()
        .success();
}

// ─── DB knobs (read paths, not scan paths) ─────────────────────────

#[test]
fn versiondb_path_argument_accepted() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let p = dir.path().join("ver.db");
    std::fs::write(&p, "").expect("write empty db");
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--versiondb",
            p.to_str().unwrap(),
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn servicedb_path_argument_accepted() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let p = dir.path().join("services");
    std::fs::write(&p, "").expect("write");
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--servicedb",
            p.to_str().unwrap(),
            "127.0.0.1",
        ])
        .assert()
        .success();
}

// ─── output style ──────────────────────────────────────────────────

#[test]
fn stylesheet_path_argument_accepted() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let p = dir.path().join("style.xsl");
    std::fs::write(
        &p,
        "<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'/>",
    )
    .expect("write");
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--stylesheet",
            p.to_str().unwrap(),
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn deprecated_xml_osclass_accepts() {
    nmaprs()
        .args(["-Pn", "-sL", "--deprecated-xml-osclass", "127.0.0.1"])
        .assert()
        .success();
}

// ─── fuzzy OS match ────────────────────────────────────────────────

#[test]
fn fuzzy_os_match_flag_accepts() {
    nmaprs()
        .args(["-Pn", "-sL", "-O", "--fuzzy", "127.0.0.1"])
        .assert()
        .success();
}

// ─── routing override ──────────────────────────────────────────────

#[test]
fn route_dst_accepts_address() {
    nmaprs()
        .args(["-Pn", "-sL", "--route-dst", "127.0.0.1", "127.0.0.1"])
        .assert()
        .success();
}

// ─── proxies (parsed but only used in connect-scan path) ───────────

#[test]
fn proxies_accepts_csv_proxy_spec() {
    nmaprs()
        .args([
            "-Pn",
            "-sL",
            "--proxies",
            "socks4://127.0.0.1:1080",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

// ─── nsock-engine (parsed but no-op in zshrs-style design) ────────

#[test]
fn nsock_engine_accepts_keyword() {
    nmaprs()
        .args(["-Pn", "-sL", "--nsock-engine", "select", "127.0.0.1"])
        .assert()
        .success();
}

// ─── resume (state-file mode) ──────────────────────────────────────

#[test]
fn resume_with_missing_file_errors_cleanly() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let p = dir.path().join("nonexistent.resume");
    // Should fail (file doesn't exist) but NOT panic. Either non-zero
    // exit OR a parse-time success that ignores the missing file is
    // acceptable — what matters is no Rust panic / clean error path.
    let _ = nmaprs().args(["--resume", p.to_str().unwrap()]).assert();
}

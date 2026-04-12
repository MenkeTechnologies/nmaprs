use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_short_h() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("GRID SCANNER"));
}

#[test]
fn nms_binary_same_help() {
    Command::cargo_bin("nms")
        .expect("binary")
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("GRID SCANNER"));
}

#[test]
fn help_long() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn version_flag() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("nmaprs"));
}

#[test]
fn version_long_flag() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("nmaprs"));
}

#[test]
fn script_help_exits_without_targets() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["--script-help", "default"])
        .assert()
        .success()
        .stdout(predicate::str::contains("script-help"));
}

#[test]
fn list_scan_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "127.0.0.1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("127.0.0.1"));
}

#[test]
fn scan_localhost_one_closed_port() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "65533", "127.0.0.1"])
        .assert()
        .success();
}

/// `-PS` discovery uses TCP connect; RST from a closed port implies host is up.
#[test]
fn scan_localhost_tcp_syn_discovery_only() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["--ping-S", "65533", "-p", "65533", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_updatedb_exits_zero_without_targets() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .arg("--script-updatedb")
        .assert()
        .success()
        .stdout(predicate::str::contains("script-updatedb"));
}

#[test]
fn missing_targets_is_error() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-p", "80"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no targets"));
}

#[test]
fn list_scan_cidr_expands_two_hosts() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "10.0.0.0/31"])
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.0"))
        .stdout(predicate::str::contains("10.0.0.1"));
}

#[test]
fn short_flags_via_expander_syn_scan_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sT", "-p", "65534", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn iflist_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .arg("--iflist")
        .assert()
        .success();
}

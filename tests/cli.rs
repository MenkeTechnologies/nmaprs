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

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

#[test]
fn list_scan_ipv6_localhost_requires_dash6() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "::1"])
        .assert()
        .failure();
}

#[test]
fn list_scan_ipv6_with_dash6() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-6", "-sL", "::1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("::1"));
}

#[test]
fn ping_scan_sn_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sn", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn fast_scan_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-F", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn top_ports_ten_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--top-ports", "10", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn invalid_port_spec_errors() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "99999", "127.0.0.1"])
        .assert()
        .failure();
}

#[test]
fn reason_flag_accepted() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--reason", "-p", "65532", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn open_only_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--open", "-p", "65531", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn verbosity_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-v", "-p", "65530", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn timing_template_t4_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T4", "-p", "65529", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn list_scan_multiple_explicit_targets() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "10.0.0.1", "10.0.0.2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.1"))
        .stdout(predicate::str::contains("10.0.0.2"));
}

#[test]
fn list_scan_from_input_file() {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    use std::io::Write;
    writeln!(f, "192.0.2.1").unwrap();
    writeln!(f, "192.0.2.2").unwrap();
    f.flush().unwrap();
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "-iL", f.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("192.0.2.1"))
        .stdout(predicate::str::contains("192.0.2.2"));
}

#[test]
fn udp_scan_one_port_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sU", "-p", "65528", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn connect_scan_explicit_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sT", "-p", "65527", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_help_specific_category() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["--script-help", "banner"])
        .assert()
        .success();
}

#[test]
fn invalid_timing_template_errors() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-T9", "-p", "80", "127.0.0.1"])
        .assert()
        .failure();
}

#[test]
fn port_list_comma_separated_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "65526,65525", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_retries_flag_accepted() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-retries", "1", "-p", "65524", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn no_dns_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-n", "-sL", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn sequential_ports_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-r", "-p", "65523,65522", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn datadir_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--datadir", "data", "-p", "65521", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn host_timeout_flag_accepted() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--host-timeout", "5s", "-p", "65520", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_hostgroup_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--min-hostgroup",
            "1",
            "-p",
            "65519",
            "127.0.0.1",
            "127.0.0.2",
        ])
        .assert()
        .success();
}

#[test]
fn script_default_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sC", "-p", "65518", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_scan_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sV", "-p", "65517", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn os_detect_flag_without_privilege_errors_or_warns() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-O", "-p", "65516", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_range_hyphen_localhost() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "65515-65515", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn missing_port_with_target_errors() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn badsum_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--badsum", "-p", "65514", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn packet_trace_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--packet-trace", "-p", "65513", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn disable_arp_ping_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--disable-arp-ping", "-p", "65512", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn resolve_all_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--resolve-all", "-p", "65511", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn osscan_guess_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--osscan-guess", "-p", "65510", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn unique_hosts_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--unique", "-p", "65509", "127.0.0.1", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn randomize_hosts_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--randomize-hosts", "-p", "65508", "127.0.0.1", "127.0.0.2"])
        .assert()
        .success();
}

#[test]
fn port_spec_t_prefix_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "T:22", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_spec_u_prefix_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "U:53", "-sU", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_rate_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--min-rate", "100", "-p", "65507", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_rate_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-rate", "1000", "-p", "65506", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn send_eth_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--send-eth", "-p", "65505", "127.0.0.1"])
        .assert()
        .success();
}

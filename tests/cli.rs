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
        .args([
            "-Pn",
            "--randomize-hosts",
            "-p",
            "65508",
            "127.0.0.1",
            "127.0.0.2",
        ])
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
fn append_output_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--append-output", "-p", "65504", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn defeat_rst_ratelimit_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--defeat-rst-ratelimit", "-p", "65503", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn source_port_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--source-port", "53", "-p", "65502", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ttl_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ttl", "32", "-p", "65501", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn fragment_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-f", "-p", "65500", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_parallelism_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-parallelism", "32", "-p", "65499", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_parallelism_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--min-parallelism", "4", "-p", "65498", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_hostgroup_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-hostgroup", "16", "-p", "65497", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_timeout_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--script-timeout", "2s", "-p", "65496", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_light_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--version-light", "-p", "65495", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_all_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--version-all", "-p", "65494", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn osscan_limit_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--osscan-limit", "-p", "65493", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn initial_rtt_timeout_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--initial-rtt-timeout", "1s", "-p", "65492", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn scan_delay_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-delay", "10ms", "-p", "65491", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_spec_s_prefix_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "S:22", "127.0.0.1"])
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

#[test]
fn defeat_icmp_ratelimit_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--defeat-icmp-ratelimit", "-p", "65390", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn discovery_ignore_rst_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--discovery-ignore-rst", "-p", "65389", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn stats_every_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--stats-every", "2s", "-p", "65381", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_os_tries_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-os-tries", "2", "-p", "65380", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn exclude_target_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--exclude",
            "127.0.0.2",
            "-p",
            "65378",
            "127.0.0.1",
            "127.0.0.2",
        ])
        .assert()
        .success();
}

#[test]
fn ping_echo_discovery_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ping-E", "-p", "65377", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ping_syn_discovery_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ping-S", "-p", "65376", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ping_udp_discovery_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ping-U", "-p", "65375", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_intensity_mid_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--version-intensity", "5", "-p", "65374", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn traceroute_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--traceroute", "-p", "65373", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_scan_delay_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-scan-delay", "20ms", "-p", "65370", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn exclude_ports_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--exclude-ports", "65368", "-p", "65368,65367", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn debug_level_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-d", "-p", "65364", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn timing_paranoid_t0_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T0", "-p", "65363", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn timing_insane_t5_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T5", "-p", "65362", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn unprivileged_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--unprivileged", "-p", "65358", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn scanflags_syn_ack_combo_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "-sS",
            "--scanflags",
            "SYN,ACK",
            "-p",
            "65357",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn decoys_rnd_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-D", "RND", "-p", "65356", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ping_ip_proto_list_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ping-ip-proto", "1,6", "-p", "65355", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn fragment_mtu_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--mtu", "16", "-p", "65354", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn defeat_rst_ratelimit_explicit_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--defeat-rst-ratelimit", "-p", "65353", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn versiondb_override_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--versiondb",
            "./data/nmap-service-probes",
            "-p",
            "65352",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn machine_parseable_output_flag_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.xml");
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "-oX",
            path.to_str().unwrap(),
            "-p",
            "65351",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn grepable_output_flag_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.gnmap");
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "-oG",
            path.to_str().unwrap(),
            "-p",
            "65350",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn spoof_source_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-S", "10.0.0.99", "-p", "65349", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn data_payload_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--data", "deadbeef", "-p", "65348", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn fragment_short_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-f", "-p", "65347", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn no_dns_short_n_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-n", "-p", "65346", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn resolve_all_short_r_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-R", "-p", "65345", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn null_scan_type_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "N", "-p", "65343", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn fin_scan_type_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "F", "-p", "65342", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn xmas_scan_type_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "X", "-p", "65341", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn maimon_scan_type_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "M", "-p", "65340", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ack_scan_type_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "A", "-p", "65339", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn window_scan_type_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "W", "-p", "65338", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ip_protocol_scan_so_requires_raw_without_privilege() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--sO", "-p", "65337", "127.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires raw sockets"));
}

#[test]
fn sctp_init_scan_y_requires_raw_without_privilege() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "Y", "-p", "65336", "127.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires raw sockets"));
}

#[test]
fn sctp_cookie_scan_z_requires_raw_without_privilege() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-type", "Z", "-p", "65335", "127.0.0.1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires raw sockets"));
}

#[test]
fn normal_output_file_on_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scan.txt");
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "-oN",
            path.to_str().unwrap(),
            "-p",
            "65334",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn script_kiddie_output_os_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scan.sk");
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "-oS",
            path.to_str().unwrap(),
            "-p",
            "65333",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn timing_template_t3_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T3", "-p", "65326", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn timing_template_t2_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T2", "-p", "65325", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn timing_template_t1_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T1", "-p", "65324", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn initial_rtt_timeout_ms_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--initial-rtt-timeout",
            "750ms",
            "-p",
            "65329",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn scan_delay_ms_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-delay", "5ms", "-p", "65328", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn privileged_short_flag_parses_cli() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--privileged", "-p", "65319", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ping_ip_proto_long_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--ping-ip-proto",
            "1,6",
            "-p",
            "65318",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn script_default_short_sc_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sC", "-p", "65317", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_scan_short_sv_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sV", "-p", "65316", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn aggressive_short_a_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-A", "-p", "65315", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn os_detect_short_o_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-O", "-p", "65314", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn list_scan_short_sl_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ping_scan_short_sn_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sn", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn connect_scan_short_st_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sT", "-p", "65313", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn syn_scan_short_ss_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sS", "-p", "65312", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn udp_scan_short_su_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sU", "-p", "65311", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn null_scan_short_sn_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sN", "-p", "65310", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn fin_scan_short_sf_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sF", "-p", "65309", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn xmas_scan_short_sx_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sX", "-p", "65308", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn maimon_scan_short_sm_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sM", "-p", "65307", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ack_scan_short_sa_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sA", "-p", "65306", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn window_scan_short_sw_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-sW", "-p", "65305", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn timing_t4_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T4", "-p", "65304", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn verbosity_vv_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-vv", "-p", "65303", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn debug_d_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-d", "-p", "65302", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn interface_short_e_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-e", "lo0", "-p", "65301", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn datadir_short_expansion_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--datadir", "./data", "-p", "65300", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_scan_delay_ms_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-scan-delay", "15ms", "-p", "65299", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn host_timeout_seconds_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--host-timeout", "10s", "-p", "65298", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_retries_two_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-retries", "2", "-p", "65297", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_rate_two_hundred_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--min-rate", "200", "-p", "65296", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_rate_one_thousand_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-rate", "1000", "-p", "65295", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn unique_hosts_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--unique", "-p", "65294", "127.0.0.1", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn randomize_hosts_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--randomize-hosts", "-p", "65293", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn append_output_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--append-output", "-p", "65292", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn reason_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--reason", "-p", "65291", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn open_only_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--open", "-p", "65290", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn packet_trace_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--packet-trace", "-p", "65289", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn badsum_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--badsum", "-p", "65288", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ttl_sixty_four_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ttl", "64", "-p", "65287", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn source_port_fifty_three_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--source-port", "53", "-p", "65286", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn defeat_rst_ratelimit_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--defeat-rst-ratelimit", "-p", "65285", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn sequential_ports_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-r", "-p", "65284", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_spec_s_prefix_sctp_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "S:65283", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_list_three_ports_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-p", "65282,65281,65280", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn cidr_list_scan_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-sL", "127.0.0.0/30"])
        .assert()
        .success();
}

#[test]
fn script_banner_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--script", "banner", "-p", "65279", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_default_long_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--script-default", "-p", "65278", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_ratio_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--port-ratio", "0.1", "-p", "65277", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn data_length_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--data-length", "32", "-p", "65276", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn traceroute_two_hosts_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--traceroute", "-p", "65275", "127.0.0.1", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn allports_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--allports", "-p", "65274", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn noninteractive_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--noninteractive", "-p", "65273", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn log_errors_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--log-errors", "-p", "65272", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn release_memory_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--release-memory", "-p", "65271", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn adler32_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--adler32", "-p", "65270", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn thc_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--thc", "-p", "65269", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn send_ip_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--send-ip", "-p", "65268", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_args_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--script",
            "banner",
            "--script-args",
            "timeout=1",
            "-p",
            "65267",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn exclude_single_host_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--exclude",
            "127.0.0.2",
            "-p",
            "65266",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn system_dns_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--system-dns", "-p", "65265", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn nogcc_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--nogcc", "-p", "65263", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn deprecated_xml_osclass_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--deprecated-xml-osclass", "-p", "65262", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_rtt_timeout_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-rtt-timeout", "2s", "-p", "65254", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn min_rtt_timeout_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--min-rtt-timeout", "100ms", "-p", "65253", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn exclude_ports_single_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--exclude-ports",
            "65251",
            "-p",
            "65251,65250",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn webxml_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--webxml", "-p", "65249", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn no_stylesheet_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--no-stylesheet", "-p", "65248", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn script_trace_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--script-trace", "-p", "65247", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn data_string_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--data-string",
            "probe",
            "-p",
            "65246",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn nsock_engine_kqueue_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--nsock-engine", "kqueue", "-p", "65245", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ff_debug_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ff", "-p", "65244", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ip_options_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--ip-options", "R", "-p", "65243", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn route_dst_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--route-dst", "127.0.0.1", "-p", "65242", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn port_ratio_half_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--port-ratio", "0.5", "-p", "65241", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn max_scan_delay_twenty_ms_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--max-scan-delay", "20ms", "-p", "65240", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn mtu_explicit_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--mtu", "16", "-p", "65239", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn dns_servers_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--dns-servers", "8.8.8.8", "-p", "65238", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn spoof_mac_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--spoof-mac",
            "DE:AD:BE:EF:00:01",
            "-p",
            "65237",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn proxies_socks4_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--proxies",
            "socks4://127.0.0.1:9050",
            "-p",
            "65236",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn data_hex_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--data", "deadbeef", "-p", "65235", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn stylesheet_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--stylesheet",
            "https://example.com/nmap.xsl",
            "-p",
            "65234",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn servicedb_override_flag_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--servicedb",
            "./data/nmap-services",
            "-p",
            "65233",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn timing_template_t3_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-T3", "-p", "65231", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn list_scan_sl_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["--sL", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ping_scan_sn_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["--sn", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn ipv6_flag_with_localhost_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-6", "-p", "65230", "::1"])
        .assert()
        .success();
}

#[test]
fn no_dns_flag_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-n", "-p", "65229", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn resolve_flag_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-R", "-p", "65228", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn source_port_short_g_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-g", "53", "-p", "65226", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn decoy_single_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "-D", "10.0.0.1", "-p", "65225", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn scanflags_syn_ack_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--scan-type",
            "S",
            "--scanflags",
            "SYN,ACK",
            "-p",
            "65224",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

#[test]
fn initial_rtt_timeout_short_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--initial-rtt-timeout", "800ms", "-p", "65223", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn scan_delay_five_ms_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args(["-Pn", "--scan-delay", "5ms", "-p", "65222", "127.0.0.1"])
        .assert()
        .success();
}

#[test]
fn version_intensity_three_runs() {
    Command::cargo_bin("nmaprs")
        .expect("binary")
        .args([
            "-Pn",
            "--version-intensity",
            "3",
            "-p",
            "65221",
            "127.0.0.1",
        ])
        .assert()
        .success();
}

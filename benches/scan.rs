//! Criterion benchmarks for TCP connect scan scheduling (localhost loopback).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nmaprs::config::{ScanKind, ScanPlan};
use nmaprs::scan::tcp_connect_scan;

fn bench_scan_localhost_closed_ports(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let plan = Arc::new(ScanPlan {
        ports: vec![65533, 65534, 65535],
        concurrency: 256,
        max_parallelism_explicit: false,
        connect_timeout: Duration::from_millis(50),
        no_ping: true,
        scan_kind: ScanKind::TcpConnect,
        tcp_scan_flags: None,
        verbosity: 0,
        debug: 0,
        sequential_ports: true,
        list_scan: false,
        ping_only: false,
        output_normal: None,
        output_grepable: None,
        output_xml: None,
        output_script_kiddie: None,
        output_all_base: None,
        datadir: None,
        append_output: false,
        show_reason: false,
        open_only: false,
        randomize_ports: false,
        aggressive: false,
        version_scan_requested: false,
        version_intensity: 7,
        os_detect_requested: false,
        script_requested: false,
        traceroute: false,
        resume_path: None,
        max_probe_rate: None,
        min_probe_rate: None,
        host_timeout: None,
        connect_retries: 0,
        scan_delay: None,
        max_scan_delay: None,
        hostgroup_min: None,
        hostgroup_max: None,
        unimplemented: vec![],
        ftp_bounce: None,
        idle_scan: None,
    });

    c.bench_function("tcp_connect_scan_localhost_3_ports", |b| {
        b.iter(|| {
            let h = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let work: Vec<_> = plan.ports.iter().map(|p| (h, *p)).collect();
            let out = rt.block_on(tcp_connect_scan(black_box(work), black_box(plan.clone())));
            black_box(out.len());
        });
    });
}

criterion_group!(benches, bench_scan_localhost_closed_ports);
criterion_main!(benches);

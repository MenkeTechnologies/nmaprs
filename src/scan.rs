//! Parallel TCP connect and UDP probes (`tokio` + bounded concurrency).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use std::thread;

use dashmap::DashMap;
use rand::Rng;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::config::{ProxyKind, ProxySpec, ScanPlan};

/// First probe per host records a start time; later probes are skipped once `limit` elapses (Nmap `--host-timeout`).
pub(crate) fn host_over_deadline(
    host_start: &DashMap<IpAddr, Instant>,
    host: IpAddr,
    limit: Duration,
) -> bool {
    let now = Instant::now();
    let start = *host_start.entry(host).or_insert(now);
    now.duration_since(start) > limit
}

/// Samples a delay for `--scan-delay` / `--max-scan-delay` (uniform in `[min, max]` when both set).
pub(crate) fn sample_inter_probe_delay(
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
) -> Option<Duration> {
    let mut rng = rand::thread_rng();
    match (scan_delay, max_scan_delay) {
        (None, None) => None,
        (Some(d), None) => Some(d),
        (None, Some(max)) => {
            let span = max.as_nanos();
            if span == 0 {
                return Some(Duration::ZERO);
            }
            let n = rng.gen_range(0u128..=span);
            Some(duration_from_nanos_saturating(n))
        }
        (Some(min), Some(max)) => {
            if max <= min {
                return Some(min);
            }
            let span = max.saturating_sub(min).as_nanos();
            let n = rng.gen_range(0u128..=span);
            Some(min.saturating_add(duration_from_nanos_saturating(n)))
        }
    }
}

fn duration_from_nanos_saturating(n: u128) -> Duration {
    if n <= u64::MAX as u128 {
        Duration::from_nanos(n as u64)
    } else {
        Duration::from_nanos(u64::MAX)
    }
}

pub(crate) async fn sleep_inter_probe_delay(
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
) {
    if let Some(d) = sample_inter_probe_delay(scan_delay, max_scan_delay) {
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
    }
}

/// Blocking SYN send loop: sleep before each probe (after host-timeout check).
pub fn sleep_inter_probe_delay_sync(
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
) {
    if let Some(d) = sample_inter_probe_delay(scan_delay, max_scan_delay) {
        if !d.is_zero() {
            thread::sleep(d);
        }
    }
}

/// Global cap on how fast probe tasks may **start** (`--max-rate`, probes/sec minimum spacing).
///
/// When `--min-rate` is set without `--max-rate`, no pacer is installed (Nmap-style floor without a
/// ceiling does not add mutex overhead here). Shared across threads (e.g. concurrent IPv4 + IPv6 SYN
/// senders) via [`Arc`].
pub struct ProbeRatePacer {
    next_slot: Mutex<Instant>,
    interval: Duration,
}

impl ProbeRatePacer {
    /// Returns a shared pacer only when `--max-rate` is set. `--min-rate` is validated in
    /// [`crate::config::ScanPlan::from_args`] against `--max-rate` when both are present.
    pub fn maybe_new(max_rate: Option<u64>, _min_rate: Option<u64>) -> Option<Arc<Self>> {
        max_rate.map(|n| Arc::new(Self::new(n as f64)))
    }

    pub fn new(probes_per_second: f64) -> Self {
        assert!(probes_per_second > 0.0 && probes_per_second.is_finite());
        Self {
            next_slot: Mutex::new(Instant::now()),
            interval: Duration::from_secs_f64(1.0 / probes_per_second),
        }
    }

    /// Async probes (TCP connect, UDP): call before acquiring the scan semaphore.
    pub async fn wait_turn(&self) {
        let sleep_for = {
            let mut next = self.next_slot.lock().expect("probe rate pacer");
            let now = Instant::now();
            let start = *next;
            if start > now {
                let w = start - now;
                *next = start + self.interval;
                w
            } else {
                *next = now + self.interval;
                Duration::ZERO
            }
        };
        if !sleep_for.is_zero() {
            tokio::time::sleep(sleep_for).await;
        }
    }

    /// Raw SYN send loop (blocking thread): call at the start of each probe iteration.
    pub fn wait_turn_sync(&self) {
        let sleep_for = {
            let mut next = self.next_slot.lock().expect("probe rate pacer");
            let now = Instant::now();
            let start = *next;
            if start > now {
                let w = start - now;
                *next = start + self.interval;
                w
            } else {
                *next = now + self.interval;
                Duration::ZERO
            }
        };
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }
}

/// Extra wait after UDP recv timeout so raw ICMP listeners can deliver matching errors (ms).
const UDP_ICMP_DRAIN_MS: u64 = 2;

/// Outcome of an ICMP error that references our UDP probe (embedded IP header + UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpIcmpOutcome {
    /// ICMPv4 type 3 code 3 / ICMPv6 type 1 code 4 — port explicitly closed.
    Closed,
    /// Other destination-unreachable codes (host/net unreachable, admin prohibited, etc.) — path/filtered.
    Filtered,
}

/// Concurrent map filled by ICMP / ICMPv6 listeners. `Closed` wins over `Filtered` if both appear.
pub type UdpIcmpNotes = Arc<DashMap<(IpAddr, u16), UdpIcmpOutcome>>;

pub(crate) fn merge_udp_icmp_note(notes: &UdpIcmpNotes, k: (IpAddr, u16), new: UdpIcmpOutcome) {
    notes
        .entry(k)
        .and_modify(|cur| {
            if new == UdpIcmpOutcome::Closed {
                *cur = UdpIcmpOutcome::Closed;
            }
        })
        .or_insert(new);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReason {
    SynAck,
    ConnRefused,
    /// RST on raw TCP ACK scan (`-sA`) — reported as `unfiltered`.
    TcpRst,
    /// RST with non-zero window on TCP window scan (`-sW`) — reported as `open` (BSD-style stacks).
    TcpWindowRst,
    Timeout,
    HostTimeout,
    Error,
    UdpResponse,
    IcmpPortUnreachable,
    IcmpUnreachableFiltered,
    /// ICMP type 3 code 2 (protocol unreachable) on `-sO` IP protocol scan.
    IcmpProtoUnreachable,
    /// FTP bounce (`-b`) data connection opened (e.g. 150).
    FtpBounceOpen,
    /// FTP bounce (`-b`) data connection refused (e.g. 425).
    FtpBounceClosed,
    /// SCTP INIT-ACK (`-sY`).
    SctpInitAck,
    /// SCTP COOKIE-ACK (`-sZ`).
    SctpCookieAck,
    /// SCTP ABORT (closed / reset path).
    SctpAbort,
    /// Idle scan: IP-ID delta suggests open (spoof path).
    IdleIpIdOpen,
    IdleIpIdClosed,
    /// Idle scan: could not read zombie IP-ID (probe port / privileges / network).
    IdleProbeFailed,
}

#[derive(Debug, Clone)]
pub struct PortLine {
    pub host: IpAddr,
    pub port: u16,
    pub proto: &'static str,
    pub state: &'static str,
    pub reason: PortReason,
    pub latency_ms: Option<u128>,
    /// Filled after scan when `-sV` matches `nmap-service-probes`.
    pub version_info: Option<String>,
}

impl PortLine {
    pub(crate) fn new(
        host: IpAddr,
        port: u16,
        proto: &'static str,
        state: &'static str,
        reason: PortReason,
        latency_ms: Option<u128>,
    ) -> Self {
        Self {
            host,
            port,
            proto,
            state,
            reason,
            latency_ms,
            version_info: None,
        }
    }
}

/// Connect through a SOCKS4 or HTTP CONNECT proxy, returning a TCP stream to the target.
async fn connect_via_proxy(proxy: &ProxySpec, target: SocketAddr) -> io::Result<TcpStream> {
    let proxy_addr: SocketAddr = SocketAddr::new(
        proxy.host.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad proxy host: {e}"))
        })?,
        proxy.port,
    );
    match proxy.kind {
        ProxyKind::Socks4 => tokio_socks::tcp::Socks4Stream::connect(proxy_addr, target)
            .await
            .map(|s| s.into_inner())
            .map_err(io::Error::other),
        ProxyKind::Http => {
            let mut stream = TcpStream::connect(proxy_addr).await?;
            let req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                target.ip(),
                target.port(),
                target.ip(),
                target.port()
            );
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(req.as_bytes()).await?;
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await?;
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp.contains("200") {
                Ok(stream)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!(
                        "HTTP CONNECT rejected: {}",
                        resp.lines().next().unwrap_or("")
                    ),
                ))
            }
        }
    }
}

/// Shared context for worker-pool TCP connect probes (one `Arc` clone per worker instead of per probe).
struct TcpConnectCtx {
    work: Vec<(IpAddr, u16)>,
    next_idx: AtomicUsize,
    timeout: Duration,
    no_ping: bool,
    max_tries: u32,
    pacer: Option<Arc<ProbeRatePacer>>,
    host_deadline: Option<Arc<DashMap<IpAddr, Instant>>>,
    host_limit: Option<Duration>,
    scan_delay: Option<Duration>,
    max_scan_delay: Option<Duration>,
    proxies: Vec<ProxySpec>,
    progress: Option<Arc<AtomicUsize>>,
}

/// Pre-allocated, lock-free result array — each slot written exactly once by a unique worker index.
struct ResultSlots {
    slots: Vec<std::cell::UnsafeCell<std::mem::MaybeUninit<PortLine>>>,
}
// Safety: each slot is written by exactly one worker (unique index via atomic fetch_add)
// and read only after all workers have joined.
unsafe impl Send for ResultSlots {}
unsafe impl Sync for ResultSlots {}

/// TCP connect scan: `conc` long-lived worker tasks drain a shared work queue via atomic index.
/// When no proxies are configured, workers use blocking `std::net::TcpStream::connect_timeout`
/// (fewer syscalls: no ioctl/fcntl non-blocking setup per probe). Falls back to async tokio
/// connect when proxies need the async I/O path.
/// `progress` is an optional atomic counter incremented after each probe completes (for `--stats-every`).
pub async fn tcp_connect_scan(
    work: Vec<(IpAddr, u16)>,
    plan: Arc<ScanPlan>,
    progress: Option<Arc<AtomicUsize>>,
) -> Vec<PortLine> {
    let n = work.len();
    if n == 0 {
        return Vec::new();
    }
    let conc = plan.effective_probe_concurrency().min(n);
    let max_tries = 1u32.saturating_add(plan.connect_retries);
    // Blocking OS threads win for large scans (fewer syscalls per probe) but have higher
    // fixed cost (thread::scope setup). Use async path for small work or when proxies need it.
    let use_blocking = plan.proxies.is_empty() && n >= 64;

    let ctx = Arc::new(TcpConnectCtx {
        work,
        next_idx: AtomicUsize::new(0),
        timeout: plan.connect_timeout,
        no_ping: plan.no_ping,
        max_tries,
        pacer: ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate),
        host_deadline: plan.host_timeout.map(|_| Arc::new(DashMap::new())),
        host_limit: plan.host_timeout,
        scan_delay: plan.scan_delay,
        max_scan_delay: plan.max_scan_delay,
        proxies: plan.proxies.clone(),
        progress,
    });

    let results = Arc::new(ResultSlots {
        slots: (0..n)
            .map(|_| std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()))
            .collect(),
    });

    if use_blocking {
        // Blocking path: OS threads with std::net::TcpStream::connect_timeout — avoids
        // tokio's per-socket ioctl(FIONBIO) + kqueue registration overhead.
        let ctx2 = ctx.clone();
        let results2 = results.clone();
        tokio::task::spawn_blocking(move || {
            thread::scope(|s| {
                for _ in 0..conc {
                    let ctx = &ctx2;
                    let results = &results2;
                    s.spawn(move || {
                        loop {
                            let i = ctx.next_idx.fetch_add(1, Ordering::Relaxed);
                            if i >= ctx.work.len() {
                                break;
                            }
                            let (host, port) = ctx.work[i];
                            let line = tcp_connect_one_probe_blocking(ctx, host, port);
                            unsafe { (*results.slots[i].get()).write(line) };
                            if let Some(ref p) = ctx.progress {
                                p.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
            });
        })
        .await
        .expect("blocking tcp connect pool");
    } else {
        // Async path: tokio tasks — required for proxy connections.
        let mut workers = Vec::with_capacity(conc);
        for _ in 0..conc {
            let ctx = ctx.clone();
            let results = results.clone();
            workers.push(tokio::spawn(async move {
                loop {
                    let i = ctx.next_idx.fetch_add(1, Ordering::Relaxed);
                    if i >= ctx.work.len() {
                        break;
                    }
                    let (host, port) = ctx.work[i];
                    let line = tcp_connect_one_probe_async(&ctx, host, port).await;
                    unsafe { (*results.slots[i].get()).write(line) };
                    if let Some(ref p) = ctx.progress {
                        p.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for w in workers {
            let _ = w.await;
        }
    }

    // Safety: every slot [0..n) was written exactly once; all workers have joined.
    let slots = Arc::try_unwrap(results).unwrap_or_else(|_| panic!("workers still hold results"));
    slots
        .slots
        .into_iter()
        .map(|cell| unsafe { cell.into_inner().assume_init() })
        .collect()
}

/// Blocking TCP connect probe — uses `std::net::TcpStream::connect_timeout` (3 syscalls:
/// socket + connect + close) instead of tokio's async path (4+ syscalls: socket + ioctl + connect + close).
fn tcp_connect_one_probe_blocking(ctx: &TcpConnectCtx, host: IpAddr, port: u16) -> PortLine {
    let addr = SocketAddr::new(host, port);
    let mut timeouts = 0u32;

    loop {
        if let (Some(limit), Some(ref hs)) = (ctx.host_limit, ctx.host_deadline.as_ref()) {
            if host_over_deadline(hs.as_ref(), host, limit) {
                return PortLine::new(host, port, "tcp", "filtered", PortReason::HostTimeout, None);
            }
        }
        if timeouts == 0 {
            sleep_inter_probe_delay_sync(ctx.scan_delay, ctx.max_scan_delay);
            if let Some(p) = ctx.pacer.as_ref() {
                p.wait_turn_sync();
            }
        }

        let start = Instant::now();
        let res = std::net::TcpStream::connect_timeout(&addr, ctx.timeout);
        let elapsed = start.elapsed().as_millis();

        match res {
            Ok(stream) => {
                drop(stream);
                return PortLine::new(host, port, "tcp", "open", PortReason::SynAck, Some(elapsed));
            }
            Err(e) => {
                let kind = e.kind();
                if kind == io::ErrorKind::ConnectionRefused {
                    return PortLine::new(
                        host,
                        port,
                        "tcp",
                        "closed",
                        PortReason::ConnRefused,
                        Some(elapsed),
                    );
                } else if kind == io::ErrorKind::TimedOut || kind == io::ErrorKind::WouldBlock {
                    timeouts += 1;
                    if timeouts >= ctx.max_tries {
                        return PortLine::new(
                            host,
                            port,
                            "tcp",
                            if ctx.no_ping {
                                "open|filtered"
                            } else {
                                "filtered"
                            },
                            PortReason::Timeout,
                            None,
                        );
                    }
                } else {
                    return PortLine::new(
                        host,
                        port,
                        "tcp",
                        "filtered",
                        PortReason::Error,
                        Some(elapsed),
                    );
                }
            }
        }
    }
}

/// Async TCP connect probe — used when proxies are configured (needs tokio I/O).
async fn tcp_connect_one_probe_async(ctx: &TcpConnectCtx, host: IpAddr, port: u16) -> PortLine {
    let addr = SocketAddr::new(host, port);
    let mut timeouts = 0u32;

    loop {
        if let (Some(limit), Some(ref hs)) = (ctx.host_limit, ctx.host_deadline.as_ref()) {
            if host_over_deadline(hs.as_ref(), host, limit) {
                return PortLine::new(host, port, "tcp", "filtered", PortReason::HostTimeout, None);
            }
        }
        if timeouts == 0 {
            sleep_inter_probe_delay(ctx.scan_delay, ctx.max_scan_delay).await;
            if let Some(p) = ctx.pacer.as_ref() {
                p.wait_turn().await;
            }
        }

        let start = Instant::now();
        let res = if let Some(proxy) = ctx.proxies.first() {
            tokio::time::timeout(ctx.timeout, connect_via_proxy(proxy, addr)).await
        } else {
            tokio::time::timeout(ctx.timeout, TcpStream::connect(addr)).await
        };
        let elapsed = start.elapsed().as_millis();

        match res {
            Ok(Ok(stream)) => {
                drop(stream);
                return PortLine::new(host, port, "tcp", "open", PortReason::SynAck, Some(elapsed));
            }
            Ok(Err(e)) => {
                let (state, reason): (&'static str, PortReason) =
                    if e.kind() == io::ErrorKind::ConnectionRefused {
                        ("closed", PortReason::ConnRefused)
                    } else {
                        ("filtered", PortReason::Error)
                    };
                return PortLine::new(host, port, "tcp", state, reason, Some(elapsed));
            }
            Err(_) => {
                timeouts += 1;
                if timeouts >= ctx.max_tries {
                    return PortLine::new(
                        host,
                        port,
                        "tcp",
                        if ctx.no_ping {
                            "open|filtered"
                        } else {
                            "filtered"
                        },
                        PortReason::Timeout,
                        None,
                    );
                }
            }
        }
    }
}

/// UDP scan: send a minimal datagram and treat any UDP reply as `open`; timeout → `open|filtered`.
///
/// When `icmp_notes` is set, ICMP destination-unreachable messages after the UDP timeout refine
/// `open|filtered` to `closed` (port unreachable) or `filtered` (other unreachable codes).
pub async fn udp_scan(
    work: Vec<(IpAddr, u16)>,
    plan: Arc<ScanPlan>,
    icmp_notes: Option<UdpIcmpNotes>,
) -> Vec<PortLine> {
    let conc = plan.effective_probe_concurrency();
    let timeout = plan.connect_timeout;
    let pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
    let host_deadline = plan.host_timeout.map(|_| Arc::new(DashMap::new()));
    let host_limit = plan.host_timeout;
    let scan_delay = plan.scan_delay;
    let max_scan_delay = plan.max_scan_delay;
    let connect_retries = plan.connect_retries;
    let max_tries = 1u32.saturating_add(connect_retries);

    let sem = Arc::new(Semaphore::new(conc));
    let n = work.len();
    let mut handles = Vec::with_capacity(n);

    for (host, port) in work {
        let sem = sem.clone();
        let icmp_notes = icmp_notes.clone();
        let pacer = pacer.clone();
        let host_deadline = host_deadline.clone();

        handles.push(tokio::spawn(async move {
            if let (Some(limit), Some(ref hs)) = (host_limit, host_deadline.as_ref()) {
                if host_over_deadline(hs.as_ref(), host, limit) {
                    return PortLine::new(
                        host,
                        port,
                        "udp",
                        "filtered",
                        PortReason::HostTimeout,
                        None,
                    );
                }
            }

            let bind_addr: SocketAddr = match host {
                IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                IpAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let dst = SocketAddr::new(host, port);
            let payload = [0x00u8];
            let overall_start = Instant::now();
            let mut timeouts = 0u32;

            let _permit = sem.acquire().await.expect("semaphore closed");
            let Some(socket) = UdpSocket::bind(bind_addr).await.ok() else {
                return PortLine::new(
                    host,
                    port,
                    "udp",
                    "filtered",
                    PortReason::Error,
                    Some(overall_start.elapsed().as_millis()),
                );
            };

            loop {
                if timeouts == 0 {
                    sleep_inter_probe_delay(scan_delay, max_scan_delay).await;
                    if let Some(p) = pacer.as_ref() {
                        p.wait_turn().await;
                    }
                }
                let start = Instant::now();
                if socket.send_to(&payload, dst).await.is_err() {
                    return PortLine::new(
                        host,
                        port,
                        "udp",
                        "filtered",
                        PortReason::Error,
                        Some(overall_start.elapsed().as_millis()),
                    );
                }
                let mut buf = [0u8; 512];
                let recv = socket.recv_from(&mut buf);
                let res = tokio::time::timeout(timeout, recv).await;
                let elapsed = start.elapsed().as_millis();
                match res {
                    Ok(Ok((n, _))) if n > 0 => {
                        return PortLine::new(
                            host,
                            port,
                            "udp",
                            "open",
                            PortReason::UdpResponse,
                            Some(elapsed),
                        );
                    }
                    Ok(_) => {
                        return PortLine::new(
                            host,
                            port,
                            "udp",
                            "open|filtered",
                            PortReason::Error,
                            Some(elapsed),
                        );
                    }
                    Err(_) => {
                        timeouts += 1;
                        if timeouts >= max_tries {
                            if let Some(ref notes) = icmp_notes {
                                tokio::time::sleep(Duration::from_millis(UDP_ICMP_DRAIN_MS)).await;
                                if let Some(out) = notes.get(&(host, port)).as_deref().copied() {
                                    return match out {
                                        UdpIcmpOutcome::Closed => PortLine::new(
                                            host,
                                            port,
                                            "udp",
                                            "closed",
                                            PortReason::IcmpPortUnreachable,
                                            None,
                                        ),
                                        UdpIcmpOutcome::Filtered => PortLine::new(
                                            host,
                                            port,
                                            "udp",
                                            "filtered",
                                            PortReason::IcmpUnreachableFiltered,
                                            None,
                                        ),
                                    };
                                }
                            }
                            return PortLine::new(
                                host,
                                port,
                                "udp",
                                "open|filtered",
                                PortReason::Timeout,
                                None,
                            );
                        }
                    }
                }
            }
        }));
    }

    let mut results = Vec::with_capacity(n);
    for handle in handles {
        results.push(handle.await.expect("udp probe task panicked"));
    }
    results
}

#[cfg(test)]
mod inter_probe_delay_tests {
    use std::time::Duration;

    use super::sample_inter_probe_delay;

    #[test]
    fn sample_fixed_when_only_scan_delay() {
        let d = Duration::from_millis(40);
        assert_eq!(
            sample_inter_probe_delay(Some(d), None),
            Some(Duration::from_millis(40))
        );
    }
}

#[cfg(test)]
mod host_deadline_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use dashmap::DashMap;

    use super::host_over_deadline;

    #[test]
    fn host_deadline_two_probes_within_limit() {
        let m = DashMap::new();
        let h = IpAddr::V4(Ipv4Addr::new(9, 8, 7, 6));
        assert!(!host_over_deadline(&m, h, Duration::from_secs(60)));
        assert!(!host_over_deadline(&m, h, Duration::from_secs(60)));
    }
}

#[cfg(test)]
mod pacer_tests {
    use std::time::{Duration, Instant};

    use super::ProbeRatePacer;

    #[test]
    fn probe_rate_pacer_high_rate_allows_back_to_back_sync() {
        let p = ProbeRatePacer::new(1_000_000.0);
        let t0 = Instant::now();
        p.wait_turn_sync();
        p.wait_turn_sync();
        assert!(t0.elapsed() < Duration::from_millis(5));
    }

    #[test]
    fn maybe_new_none_without_max_rate() {
        assert!(ProbeRatePacer::maybe_new(None, Some(100)).is_none());
    }
}

#[cfg(test)]
mod merge_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use dashmap::DashMap;

    use super::{merge_udp_icmp_note, UdpIcmpNotes, UdpIcmpOutcome};

    #[test]
    fn merge_prefers_closed_over_filtered() {
        let notes: UdpIcmpNotes = Arc::new(DashMap::new());
        let k = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Filtered);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Closed);
        assert_eq!(*notes.get(&k).unwrap(), UdpIcmpOutcome::Closed);
    }

    #[test]
    fn merge_keeps_closed_when_later_filtered() {
        let notes: UdpIcmpNotes = Arc::new(DashMap::new());
        let k = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 9);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Closed);
        merge_udp_icmp_note(&notes, k, UdpIcmpOutcome::Filtered);
        assert_eq!(*notes.get(&k).unwrap(), UdpIcmpOutcome::Closed);
    }
}

//! Parallel TCP connect and UDP probes (`tokio` + bounded concurrency).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use std::thread;

use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use rand::Rng;
use tokio::net::{TcpStream, UdpSocket};

use crate::config::ScanPlan;

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
}

/// TCP connect scan with `buffer_unordered(concurrency)` (no extra semaphore: same cap).
pub async fn tcp_connect_scan(work: Vec<(IpAddr, u16)>, plan: Arc<ScanPlan>) -> Vec<PortLine> {
    let conc = plan.effective_probe_concurrency();
    let timeout = plan.connect_timeout;
    let no_ping = plan.no_ping;
    let connect_retries = plan.connect_retries;
    let pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
    let host_deadline = plan.host_timeout.map(|_| Arc::new(DashMap::new()));
    let host_limit = plan.host_timeout;
    let scan_delay = plan.scan_delay;
    let max_scan_delay = plan.max_scan_delay;

    stream::iter(work)
        .map(|(host, port)| {
            let pacer = pacer.clone();
            let host_deadline = host_deadline.clone();
            async move {
                let addr = SocketAddr::new(host, port);
                let overall_start = Instant::now();
                let max_tries = 1u32.saturating_add(connect_retries);
                let mut timeouts = 0u32;

                loop {
                    if let (Some(limit), Some(ref hs)) = (host_limit, host_deadline.as_ref()) {
                        if host_over_deadline(hs.as_ref(), host, limit) {
                            return Some(PortLine {
                                host,
                                port,
                                proto: "tcp",
                                state: "filtered",
                                reason: PortReason::HostTimeout,
                                latency_ms: None,
                            });
                        }
                    }
                    if timeouts == 0 {
                        sleep_inter_probe_delay(scan_delay, max_scan_delay).await;
                        if let Some(p) = pacer.as_ref() {
                            p.wait_turn().await;
                        }
                    }
                    let fut = TcpStream::connect(addr);
                    let res = tokio::time::timeout(timeout, fut).await;
                    let elapsed = overall_start.elapsed().as_millis();
                    match res {
                        Ok(Ok(stream)) => {
                            drop(stream);
                            return Some(PortLine {
                                host,
                                port,
                                proto: "tcp",
                                state: "open",
                                reason: PortReason::SynAck,
                                latency_ms: Some(elapsed),
                            });
                        }
                        Ok(Err(e)) => {
                            let kind = e.kind();
                            let (state, reason): (&'static str, PortReason) =
                                if kind == io::ErrorKind::ConnectionRefused {
                                    ("closed", PortReason::ConnRefused)
                                } else {
                                    ("filtered", PortReason::Error)
                                };
                            return Some(PortLine {
                                host,
                                port,
                                proto: "tcp",
                                state,
                                reason,
                                latency_ms: Some(elapsed),
                            });
                        }
                        Err(_) => {
                            timeouts += 1;
                            if timeouts >= max_tries {
                                return Some(PortLine {
                                    host,
                                    port,
                                    proto: "tcp",
                                    state: if no_ping { "open|filtered" } else { "filtered" },
                                    reason: PortReason::Timeout,
                                    latency_ms: None,
                                });
                            }
                        }
                    }
                }
            }
        })
        .buffer_unordered(conc)
        .filter_map(|x| async move { x })
        .collect()
        .await
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

    stream::iter(work)
        .map(move |(host, port)| {
            let icmp_notes = icmp_notes.clone();
            let pacer = pacer.clone();
            let host_deadline = host_deadline.clone();
            async move {
                if let (Some(limit), Some(ref hs)) = (host_limit, host_deadline.as_ref()) {
                    if host_over_deadline(hs.as_ref(), host, limit) {
                        return Some(PortLine {
                            host,
                            port,
                            proto: "udp",
                            state: "filtered",
                            reason: PortReason::HostTimeout,
                            latency_ms: None,
                        });
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

                let Some(socket) = UdpSocket::bind(bind_addr).await.ok() else {
                    return Some(PortLine {
                        host,
                        port,
                        proto: "udp",
                        state: "filtered",
                        reason: PortReason::Error,
                        latency_ms: Some(overall_start.elapsed().as_millis()),
                    });
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
                        return Some(PortLine {
                            host,
                            port,
                            proto: "udp",
                            state: "filtered",
                            reason: PortReason::Error,
                            latency_ms: Some(overall_start.elapsed().as_millis()),
                        });
                    }
                    let mut buf = [0u8; 512];
                    let recv = socket.recv_from(&mut buf);
                    let res = tokio::time::timeout(timeout, recv).await;
                    let elapsed = start.elapsed().as_millis();
                    match res {
                        Ok(Ok((n, _))) if n > 0 => {
                            return Some(PortLine {
                                host,
                                port,
                                proto: "udp",
                                state: "open",
                                reason: PortReason::UdpResponse,
                                latency_ms: Some(elapsed),
                            });
                        }
                        Ok(_) => {
                            return Some(PortLine {
                                host,
                                port,
                                proto: "udp",
                                state: "open|filtered",
                                reason: PortReason::Error,
                                latency_ms: Some(elapsed),
                            });
                        }
                        Err(_) => {
                            timeouts += 1;
                            if timeouts >= max_tries {
                                if let Some(ref notes) = icmp_notes {
                                    tokio::time::sleep(Duration::from_millis(UDP_ICMP_DRAIN_MS))
                                        .await;
                                    if let Some(out) = notes.get(&(host, port)).as_deref().copied() {
                                        return Some(match out {
                                            UdpIcmpOutcome::Closed => PortLine {
                                                host,
                                                port,
                                                proto: "udp",
                                                state: "closed",
                                                reason: PortReason::IcmpPortUnreachable,
                                                latency_ms: None,
                                            },
                                            UdpIcmpOutcome::Filtered => PortLine {
                                                host,
                                                port,
                                                proto: "udp",
                                                state: "filtered",
                                                reason: PortReason::IcmpUnreachableFiltered,
                                                latency_ms: None,
                                            },
                                        });
                                    }
                                }
                                return Some(PortLine {
                                    host,
                                    port,
                                    proto: "udp",
                                    state: "open|filtered",
                                    reason: PortReason::Timeout,
                                    latency_ms: None,
                                });
                            }
                        }
                    }
                }
            }
        })
        .buffer_unordered(conc)
        .filter_map(|x| async move { x })
        .collect()
        .await
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

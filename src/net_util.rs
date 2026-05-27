//! Shared network utilities (cached local-IP lookup, lock-free deadline).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static LOCAL_V4: OnceLock<Ipv4Addr> = OnceLock::new();
static LOCAL_V6: OnceLock<Ipv6Addr> = OnceLock::new();

fn probe_local_ipv4() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv4 source for checksum")),
    }
}

fn probe_local_ipv6() -> io::Result<Ipv6Addr> {
    let s = UdpSocket::bind("[::]:0")?;
    s.connect("2001:4860:4860::8888:443")?;
    match s.local_addr()? {
        SocketAddr::V6(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("no IPv6 source for checksum")),
    }
}

/// Cached local IPv4 address for raw-packet checksum computation.
/// The first call probes the OS; subsequent calls return the cached result.
pub fn local_ipv4() -> io::Result<Ipv4Addr> {
    LOCAL_V4.get().copied().ok_or(()).or_else(|()| {
        let addr = probe_local_ipv4()?;
        Ok(*LOCAL_V4.get_or_init(|| addr))
    })
}

/// Cached local IPv6 address for raw-packet checksum computation.
pub fn local_ipv6() -> io::Result<Ipv6Addr> {
    LOCAL_V6.get().copied().ok_or(()).or_else(|()| {
        let addr = probe_local_ipv6()?;
        Ok(*LOCAL_V6.get_or_init(|| addr))
    })
}

/// Lock-free deadline shared between a send thread and recv thread.
///
/// Encodes `Option<Instant>` as a nanosecond offset from a shared epoch.
/// `0` = not set; any other value = nanos since `epoch`.
pub struct AtomicDeadline {
    epoch: Instant,
    nanos: AtomicU64,
}

impl AtomicDeadline {
    pub fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            nanos: AtomicU64::new(0),
        }
    }
    /// Set the deadline (called once by the send thread after all probes are sent).
    pub fn set(&self, deadline: Instant) {
        let off = deadline.saturating_duration_since(self.epoch).as_nanos() as u64;
        self.nanos.store(off.max(1), Ordering::Release);
    }
    /// Read the deadline (called repeatedly by the recv thread).
    pub fn get(&self) -> Option<Instant> {
        let v = self.nanos.load(Ordering::Acquire);
        if v == 0 {
            None
        } else {
            Some(self.epoch + Duration::from_nanos(v))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::AtomicDeadline;

    #[test]
    fn atomic_deadline_none_until_set() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        assert!(ad.get().is_none());
    }

    #[test]
    fn atomic_deadline_set_roundtrip() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        let deadline = epoch + Duration::from_millis(250);
        ad.set(deadline);
        assert_eq!(ad.get(), Some(deadline));
    }

    #[test]
    fn atomic_deadline_get_before_set_is_none() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        assert!(ad.get().is_none());
    }

    #[test]
    fn atomic_deadline_later_deadline_overwrites() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        ad.set(epoch + Duration::from_millis(100));
        ad.set(epoch + Duration::from_millis(500));
        assert_eq!(ad.get(), Some(epoch + Duration::from_millis(500)));
    }

    #[test]
    fn atomic_deadline_before_epoch_clamps_to_epoch_plus_one_nano() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        ad.set(epoch - Duration::from_secs(1));
        assert_eq!(ad.get(), Some(epoch + Duration::from_nanos(1)));
    }

    #[test]
    fn atomic_deadline_get_twice_is_stable() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        let deadline = epoch + Duration::from_millis(100);
        ad.set(deadline);
        assert_eq!(ad.get(), ad.get());
    }

    #[test]
    fn atomic_deadline_set_at_exact_epoch() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        ad.set(epoch);
        assert_eq!(ad.get(), Some(epoch + Duration::from_nanos(1)));
    }

    #[test]
    fn atomic_deadline_far_future_deadline() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        let deadline = epoch + Duration::from_secs(3600);
        ad.set(deadline);
        assert_eq!(ad.get(), Some(deadline));
    }

    #[test]
    fn atomic_deadline_one_millisecond_offset() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        let deadline = epoch + Duration::from_millis(1);
        ad.set(deadline);
        assert_eq!(ad.get(), Some(deadline));
    }

    #[test]
    fn atomic_deadline_subsequent_get_unchanged() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        let d = epoch + Duration::from_secs(5);
        ad.set(d);
        let first = ad.get();
        let second = ad.get();
        assert_eq!(first, second);
    }

    #[test]
    fn atomic_deadline_new_starts_none() {
        assert!(AtomicDeadline::new(Instant::now()).get().is_none());
    }

    #[test]
    fn atomic_deadline_overwrite_with_shorter_deadline() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        ad.set(epoch + Duration::from_secs(10));
        ad.set(epoch + Duration::from_secs(1));
        assert_eq!(ad.get(), Some(epoch + Duration::from_secs(1)));
    }

    #[test]
    fn atomic_deadline_nanosecond_precision_preserved() {
        let epoch = Instant::now();
        let ad = AtomicDeadline::new(epoch);
        let d = epoch + Duration::from_nanos(123_456);
        ad.set(d);
        assert_eq!(ad.get(), Some(d));
    }
}

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

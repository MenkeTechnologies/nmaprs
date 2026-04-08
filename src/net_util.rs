//! Shared network utilities (cached local-IP lookup for checksum computation).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::OnceLock;

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

//! TCP idle scan (`-sI zombie[:probeport]`): spoofed SYN from the zombie’s IPv4 toward targets, IP-ID
//! sampling on the zombie (closed-port RST probes). **IPv4 only**; **sequential** probes so IP-ID
//! deltas stay meaningful for one zombie.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{
    checksum as ipv4_header_checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet,
};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportReceiver};
use pnet_sys;
use rand::Rng;

use crate::config::{IdleScanTarget, ScanPlan};
use crate::scan::{
    host_over_deadline, sleep_inter_probe_delay_sync, PortLine, PortReason, ProbeRatePacer,
};
use dashmap::DashMap;
use std::sync::Arc;

const RECV_SLICE: Duration = Duration::from_millis(50);
const RX_BUF: usize = 65536;

fn local_ipv4() -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        SocketAddr::V4(v) => Ok(*v.ip()),
        _ => Err(io::Error::other("idle: no IPv4 source")),
    }
}

fn recv_ipv4_with_timeout(
    tr: &mut TransportReceiver,
    t: Duration,
) -> io::Result<Option<Ipv4Packet<'_>>> {
    let fd = tr.socket.fd;
    let old_timeout = pnet_sys::get_socket_receive_timeout(fd)?;
    pnet_sys::set_socket_receive_timeout(fd, t)?;
    let mut caddr: pnet_sys::SockAddrStorage = unsafe { mem::zeroed() };
    let r = pnet_sys::recv_from(fd, &mut tr.buffer[..], &mut caddr);
    let _ = pnet_sys::set_socket_receive_timeout(fd, old_timeout);
    match r {
        Ok(len) => {
            let buf = &tr.buffer[..len];
            Ok(Ipv4Packet::new(buf))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

fn tcp_flags_rst(tcp_slice: &[u8]) -> bool {
    TcpPacket::new(tcp_slice)
        .map(|t| t.get_flags() & TcpFlags::RST != 0)
        .unwrap_or(false)
}

/// Build IPv4 + TCP SYN (Layer3 send).
fn build_ipv4_tcp_syn(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    rng: &mut impl Rng,
) -> Vec<u8> {
    let tcp_len = MutableTcpPacket::minimum_packet_size();
    let total = 20 + tcp_len;
    let mut buf = vec![0u8; total];
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[20..]).expect("tcp");
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_reserved(0);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_checksum(0);
        tcp.set_urgent_ptr(0);
        let cks = ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
        tcp.set_checksum(cks);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..20]).expect("ipv4");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(total as u16);
        ip.set_identification(rng.gen());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_checksum(0);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_checksum(ipv4_header_checksum(&ip.to_immutable()));
    }
    buf
}

/// Probe zombie: SYN to `zombie:probe_port` (should be **closed**), read IPv4 **Identification** in RST.
fn probe_zombie_ipid(
    tx: &mut pnet::transport::TransportSender,
    rx: &mut TransportReceiver,
    my_ip: Ipv4Addr,
    zombie: Ipv4Addr,
    probe_port: u16,
    timeout: Duration,
    rng: &mut impl Rng,
) -> io::Result<u16> {
    let sport = rng.gen_range(32768..65535);
    let seq = rng.gen();
    let pkt = build_ipv4_tcp_syn(my_ip, zombie, sport, probe_port, seq, rng);
    let ip = Ipv4Packet::new(&pkt).expect("packet");
    tx.send_to(ip, IpAddr::V4(zombie))?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(RECV_SLICE);
        if let Some(ip) = recv_ipv4_with_timeout(rx, slice)? {
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            if ip.get_source() != zombie {
                continue;
            }
            if ip.get_destination() != my_ip {
                continue;
            }
            let ihl = ip.get_header_length() as usize * 4;
            let buf = ip.packet();
            if buf.len() < ihl + 20 {
                continue;
            }
            if tcp_flags_rst(&buf[ihl..]) {
                return Ok(ip.get_identification());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "idle: no TCP RST from zombie probe (wrong probe port?)",
    ))
}

/// Spoofed SYN: IPv4 source = zombie, dest = target.
fn send_spoofed_syn(
    tx: &mut pnet::transport::TransportSender,
    zombie_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    rng: &mut impl Rng,
) -> io::Result<()> {
    let seq = rng.gen();
    let pkt = build_ipv4_tcp_syn(zombie_ip, target_ip, sport, dport, seq, rng);
    let ip = Ipv4Packet::new(&pkt).expect("packet");
    tx.send_to(ip, IpAddr::V4(target_ip)).map(|_| ())
}

/// Idle scan: IPv4 targets only; **sequential** per (target, port).
pub fn idle_scan_ipv4(
    order: Vec<(Ipv4Addr, u16)>,
    target: IdleScanTarget,
    plan: Arc<ScanPlan>,
) -> io::Result<Vec<PortLine>> {
    if order.is_empty() {
        return Ok(vec![]);
    }
    let my_ip = local_ipv4()?;
    let zombie = target.zombie;
    let probe_port = target.probe_port;
    let timeout = plan.connect_timeout;
    let inter = Duration::from_millis(50).min(timeout / 4);
    let host_start = plan
        .host_timeout
        .map(|_| Arc::new(DashMap::<IpAddr, Instant>::new()));
    let host_limit = plan.host_timeout;
    let scan_delay = plan.scan_delay;
    let max_scan_delay = plan.max_scan_delay;
    let connect_retries = plan.connect_retries;
    let pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
    let max_tries = 1u32.saturating_add(connect_retries);

    let (mut tx, mut rx) = transport_channel(
        RX_BUF,
        TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Reserved),
    )?;

    let mut out = Vec::with_capacity(order.len());
    let mut rng = rand::thread_rng();

    for (dst_ip, dport) in order {
        let host = IpAddr::V4(dst_ip);
        if let (Some(limit), Some(ref hs)) = (host_limit, host_start.as_ref()) {
            if host_over_deadline(hs.as_ref(), host, limit) {
                out.push(PortLine::new(
                    host,
                    dport,
                    "tcp",
                    "filtered",
                    PortReason::HostTimeout,
                    None,
                ));
                continue;
            }
        }

        let mut failures = 0u32;
        let mut line: Option<PortLine> = None;
        while failures < max_tries && line.is_none() {
            if let Some(p) = pacer.as_ref() {
                p.wait_turn_sync();
            }
            sleep_inter_probe_delay_sync(scan_delay, max_scan_delay);

            let t0 = Instant::now();
            let r1 = probe_zombie_ipid(
                &mut tx, &mut rx, my_ip, zombie, probe_port, timeout, &mut rng,
            );
            let ipid1 = match r1 {
                Ok(v) => v,
                Err(_) => {
                    failures += 1;
                    if failures >= max_tries {
                        line = Some(PortLine::new(
                            host,
                            dport,
                            "tcp",
                            "filtered",
                            PortReason::IdleProbeFailed,
                            None,
                        ));
                    }
                    continue;
                }
            };

            if send_spoofed_syn(
                &mut tx,
                zombie,
                dst_ip,
                rng.gen_range(32768..65535),
                dport,
                &mut rng,
            )
            .is_err()
            {
                failures += 1;
                if failures >= max_tries {
                    line = Some(PortLine::new(
                        host,
                        dport,
                        "tcp",
                        "filtered",
                        PortReason::IdleProbeFailed,
                        None,
                    ));
                }
                continue;
            }

            thread::sleep(inter);

            let ipid2 = match probe_zombie_ipid(
                &mut tx, &mut rx, my_ip, zombie, probe_port, timeout, &mut rng,
            ) {
                Ok(v) => v,
                Err(_) => {
                    failures += 1;
                    if failures >= max_tries {
                        line = Some(PortLine::new(
                            host,
                            dport,
                            "tcp",
                            "filtered",
                            PortReason::IdleProbeFailed,
                            None,
                        ));
                    }
                    continue;
                }
            };

            let delta = ipid2.wrapping_sub(ipid1);
            let open = delta >= 2;
            let elapsed = t0.elapsed().as_millis();
            line = Some(PortLine::new(
                host,
                dport,
                "tcp",
                if open { "open" } else { "closed" },
                if open {
                    PortReason::IdleIpIdOpen
                } else {
                    PortReason::IdleIpIdClosed
                },
                Some(elapsed),
            ));
        }

        out.push(match line {
            Some(l) => l,
            None => PortLine::new(
                host,
                dport,
                "tcp",
                "filtered",
                PortReason::IdleProbeFailed,
                None,
            ),
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tcp_flags_tests {
    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};

    use super::tcp_flags_rst;

    #[test]
    fn tcp_flags_rst_true_when_rst_set() {
        let mut b = vec![0u8; MutableTcpPacket::minimum_packet_size()];
        let mut t = MutableTcpPacket::new(&mut b).expect("tcp");
        t.set_flags(TcpFlags::RST);
        assert!(tcp_flags_rst(&b));
    }

    #[test]
    fn tcp_flags_rst_false_for_syn_only() {
        let mut b = vec![0u8; MutableTcpPacket::minimum_packet_size()];
        let mut t = MutableTcpPacket::new(&mut b).expect("tcp");
        t.set_flags(TcpFlags::SYN);
        assert!(!tcp_flags_rst(&b));
    }

    #[test]
    fn tcp_flags_rst_false_for_truncated_slice() {
        assert!(!tcp_flags_rst(&[0u8; 4]));
    }
}

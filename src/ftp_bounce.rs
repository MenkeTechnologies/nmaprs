//! FTP bounce TCP port scan (`-b`): use a misconfigured FTP server’s active `PORT` to probe targets.
//!
//! **IPv4 targets only** (classic `PORT` encoding). Parallel sessions (one login per probe) use the same
//! `buffer_unordered(effective_probe_concurrency)` model as [`crate::scan::tcp_connect_scan`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{anyhow, bail, Result};
use futures::stream::{self, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::config::{FtpBounceTarget, ScanPlan};
use crate::scan::{
    host_over_deadline, sleep_inter_probe_delay, PortLine, PortReason, ProbeRatePacer,
};
use dashmap::DashMap;
use std::sync::Arc;

fn port_command_line(ip: Ipv4Addr, port: u16) -> String {
    let o = ip.octets();
    let ph = (port >> 8) as u8;
    let pl = (port & 0xff) as u8;
    format!("PORT {},{},{},{},{},{}", o[0], o[1], o[2], o[3], ph, pl)
}

async fn read_ftp_reply(reader: &mut BufReader<impl AsyncRead + Unpin>) -> Result<(u16, String)> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let first = line.trim_end_matches(['\r', '\n']);
    if first.len() < 3 {
        bail!("FTP: short reply: {first:?}");
    }
    let code: u16 = first[..3]
        .parse()
        .map_err(|_| anyhow!("FTP: bad code in {first:?}"))?;
    let mut body = first.to_string();
    if first.len() >= 4 && first.as_bytes().get(3) == Some(&b'-') {
        for _ in 0..256 {
            line.clear();
            reader.read_line(&mut line).await?;
            let s = line.trim_end_matches(['\r', '\n']);
            body.push('\n');
            body.push_str(s);
            if s.len() >= 4 && s.as_bytes().get(3) == Some(&b' ') {
                let c: u16 = s[..3].parse().unwrap_or(0);
                if c == code {
                    return Ok((code, body));
                }
            }
        }
        bail!("FTP: multiline reply too long");
    }
    Ok((code, body))
}

async fn send_line(writer: &mut (impl AsyncWrite + Unpin), line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await
}

/// One FTP bounce probe: login, `PORT` to victim, `LIST` to trigger active connect.
async fn bounce_one_port(
    server: SocketAddr,
    user: &str,
    pass: &str,
    victim: Ipv4Addr,
    port: u16,
    connect_timeout: std::time::Duration,
) -> Result<(bool, u128)> {
    let start = Instant::now();
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server))
        .await
        .map_err(|_| anyhow!("FTP connect timeout"))?
        .map_err(|e| anyhow!("FTP connect: {e}"))?;
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    let _ = read_ftp_reply(&mut reader).await?; // banner

    send_line(&mut write_half, &format!("USER {user}")).await?;
    let (c, _) = read_ftp_reply(&mut reader).await?;
    if c == 530 {
        bail!("FTP: USER rejected");
    }

    send_line(&mut write_half, &format!("PASS {pass}")).await?;
    let (c, _) = read_ftp_reply(&mut reader).await?;
    if c != 230 && c != 202 {
        bail!("FTP: login failed (code {c})");
    }

    let port_cmd = port_command_line(victim, port);
    send_line(&mut write_half, &port_cmd).await?;
    let (c, _) = read_ftp_reply(&mut reader).await?;
    if c != 200 && c != 250 {
        bail!("FTP: PORT failed (code {c})");
    }

    send_line(&mut write_half, "TYPE I").await?;
    let _ = read_ftp_reply(&mut reader).await?;

    send_line(&mut write_half, "LIST").await?;
    let (c, text) = read_ftp_reply(&mut reader).await?;

    // Drain completion / data transfer messages so QUIT is clean.
    if matches!(c, 150 | 125) {
        let _ = tokio::time::timeout(connect_timeout, read_ftp_reply(&mut reader)).await;
    }

    let _ = send_line(&mut write_half, "QUIT").await;

    let elapsed = start.elapsed().as_millis();

    let open = matches!(c, 150 | 125 | 250) || text.contains("150 ") || text.contains("125 ");
    if open {
        return Ok((true, elapsed));
    }
    if matches!(c, 425 | 426 | 421) {
        return Ok((false, elapsed));
    }
    Ok((false, elapsed))
}

/// Parallel FTP bounce scan (one control session per probe).
pub async fn ftp_bounce_scan(
    work: Vec<(IpAddr, u16)>,
    plan: Arc<ScanPlan>,
    target: FtpBounceTarget,
) -> Vec<PortLine> {
    let conc = plan.effective_probe_concurrency();
    let timeout = plan.connect_timeout;
    let no_ping = plan.no_ping;
    let connect_retries = plan.connect_retries;
    let pacer = ProbeRatePacer::maybe_new(plan.max_probe_rate, plan.min_probe_rate);
    let host_deadline = plan.host_timeout.map(|_| Arc::new(DashMap::new()));
    let host_limit = plan.host_timeout;
    let scan_delay = plan.scan_delay;
    let max_scan_delay = plan.max_scan_delay;
    let server = target.server;
    let user: Arc<str> = target.user.into();
    let pass: Arc<str> = target.pass.into();
    let max_tries = 1u32.saturating_add(connect_retries);

    stream::iter(work)
        .map(move |(host, port)| {
            let pacer = pacer.clone();
            let host_deadline = host_deadline.clone();
            let user = user.clone();
            let pass = pass.clone();
            async move {
                if host.is_ipv6() {
                    return Some(PortLine::new(
                        host,
                        port,
                        "tcp",
                        "filtered",
                        PortReason::Error,
                        None,
                    ));
                }
                let victim = match host {
                    IpAddr::V4(a) => a,
                    IpAddr::V6(_) => unreachable!(),
                };

                let mut failures = 0u32;
                loop {
                    if let (Some(limit), Some(ref hs)) = (host_limit, host_deadline.as_ref()) {
                        if host_over_deadline(hs.as_ref(), host, limit) {
                            return Some(PortLine::new(
                                host,
                                port,
                                "tcp",
                                "filtered",
                                PortReason::HostTimeout,
                                None,
                            ));
                        }
                    }
                    if failures == 0 {
                        sleep_inter_probe_delay(scan_delay, max_scan_delay).await;
                        if let Some(p) = pacer.as_ref() {
                            p.wait_turn().await;
                        }
                    }

                    match bounce_one_port(server, &user, &pass, victim, port, timeout).await {
                        Ok((true, ms)) => {
                            return Some(PortLine::new(
                                host,
                                port,
                                "tcp",
                                "open",
                                PortReason::FtpBounceOpen,
                                Some(ms),
                            ));
                        }
                        Ok((false, ms)) => {
                            return Some(PortLine::new(
                                host,
                                port,
                                "tcp",
                                "closed",
                                PortReason::FtpBounceClosed,
                                Some(ms),
                            ));
                        }
                        Err(_) => {
                            failures += 1;
                            if failures >= max_tries {
                                return Some(PortLine::new(
                                    host,
                                    port,
                                    "tcp",
                                    if no_ping { "open|filtered" } else { "filtered" },
                                    PortReason::Timeout,
                                    None,
                                ));
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
mod tests {
    use std::net::Ipv4Addr;

    use super::{port_command_line, read_ftp_reply};
    use tokio::io::BufReader;

    /// Drive `read_ftp_reply` against an in-memory byte buffer (`&[u8]` is `AsyncRead + Unpin`).
    fn reply(bytes: &'static [u8]) -> super::Result<(u16, String)> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut reader = BufReader::new(bytes);
            read_ftp_reply(&mut reader).await
        })
    }

    #[test]
    fn read_ftp_reply_single_line_strips_crlf_and_parses_code() {
        // Body must be the trimmed line (no trailing CRLF), code parsed from the first 3 bytes.
        let (code, body) = reply(b"220 ProFTPD ready\r\n").unwrap();
        assert_eq!(code, 220);
        assert_eq!(body, "220 ProFTPD ready");
    }

    #[test]
    fn read_ftp_reply_multiline_terminates_only_on_matching_code() {
        // A continuation line with a DIFFERENT code and a space at byte 3 must NOT end the
        // reply; only `<code><space>` with the SAME opening code terminates. A naive parser
        // that stops at the first "NNN " line would wrongly return at "200 inner".
        let (code, body) = reply(b"230-Welcome\r\n200 inner status\r\n230 Login ok\r\n").unwrap();
        assert_eq!(code, 230);
        assert_eq!(body, "230-Welcome\n200 inner status\n230 Login ok");
    }

    #[test]
    fn read_ftp_reply_three_byte_line_is_single_not_multiline() {
        // Exactly 3 bytes: `as_bytes().get(3)` is None, so the dash/space-at-index-3
        // multiline path must not fire and must not panic on the missing 4th byte.
        let (code, body) = reply(b"220\r\n").unwrap();
        assert_eq!(code, 220);
        assert_eq!(body, "220");
    }

    #[test]
    fn read_ftp_reply_short_reply_under_three_bytes_errors() {
        // `first.len() < 3` guard: prevents `first[..3]` from slicing out of bounds.
        assert!(reply(b"22\r\n").is_err());
    }

    #[test]
    fn read_ftp_reply_non_numeric_code_maps_to_error() {
        // First 3 bytes are non-digits -> u16 parse fails -> mapped error, never a panic.
        assert!(reply(b"abc def\r\n").is_err());
    }

    #[test]
    fn port_command_line_classic_ftp_encoding() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(192, 0, 2, 10), 0x0050),
            "PORT 192,0,2,10,0,80"
        );
    }

    #[test]
    fn port_command_line_high_byte_order() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(1, 2, 3, 4), 0x1122),
            "PORT 1,2,3,4,17,34"
        );
    }

    #[test]
    fn port_command_line_ephemeral() {
        let s = port_command_line(Ipv4Addr::new(10, 255, 0, 1), 49152);
        assert_eq!(s, "PORT 10,255,0,1,192,0");
    }

    #[test]
    fn port_command_line_port_zero() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(1, 2, 3, 4), 0),
            "PORT 1,2,3,4,0,0"
        );
    }

    #[test]
    fn port_command_line_port_65535() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(1, 2, 3, 4), 65535),
            "PORT 1,2,3,4,255,255"
        );
    }

    #[test]
    fn port_command_line_port_one() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(10, 0, 0, 1), 1),
            "PORT 10,0,0,1,0,1"
        );
    }

    #[test]
    fn port_command_line_port_256() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(192, 168, 1, 1), 256),
            "PORT 192,168,1,1,1,0"
        );
    }

    #[test]
    fn port_command_line_loopback() {
        assert_eq!(
            port_command_line(Ipv4Addr::LOCALHOST, 22),
            "PORT 127,0,0,1,0,22"
        );
    }

    #[test]
    fn port_command_line_broadcast_last_octet() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(255, 255, 255, 255), 8080),
            "PORT 255,255,255,255,31,144"
        );
    }

    #[test]
    fn port_command_line_high_port_bytes() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(8, 8, 8, 8), 0x1234),
            "PORT 8,8,8,8,18,52"
        );
    }

    #[test]
    fn port_command_line_starts_with_port_keyword() {
        let s = port_command_line(Ipv4Addr::new(1, 1, 1, 1), 80);
        assert!(s.starts_with("PORT "));
    }

    #[test]
    fn port_command_line_six_comma_separated_fields() {
        let s = port_command_line(Ipv4Addr::new(1, 2, 3, 4), 443);
        assert_eq!(s.matches(',').count(), 5);
    }

    #[test]
    fn port_command_line_all_zero_ip_and_port() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(0, 0, 0, 0), 0),
            "PORT 0,0,0,0,0,0"
        );
    }

    #[test]
    fn port_command_line_private_network_8443() {
        assert_eq!(
            port_command_line(Ipv4Addr::new(172, 16, 0, 1), 8443),
            "PORT 172,16,0,1,32,251"
        );
    }
}

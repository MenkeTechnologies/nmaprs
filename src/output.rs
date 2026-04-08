//! Normal (`-oN`), grepable (`-oG`), and minimal XML (`-oX`) writers.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

use crate::scan::PortLine;

pub struct OutputSet {
    pub normal: Option<File>,
    pub grep: Option<File>,
    pub xml: Option<File>,
    /// Mirrors `-oN`-style lines in script-kiddie form (Nmap `-oS`).
    pub skiddie: Option<File>,
    /// Nmap `-oM` machine-parseable (same content family as `-oG` in nmaprs).
    pub machine: Option<File>,
    /// Nmap `-oH` hex dump (placeholder).
    pub hex: Option<File>,
}

impl OutputSet {
    pub fn open(
        normal: Option<&Path>,
        grep: Option<&Path>,
        xml: Option<&Path>,
        skiddie: Option<&Path>,
        machine: Option<&Path>,
        hex: Option<&Path>,
        append: bool,
    ) -> Result<Self> {
        let open = |p: &Path| {
            if append {
                OpenOptions::new().create(true).append(true).open(p)
            } else {
                File::create(p)
            }
        };
        Ok(Self {
            normal: normal.map(open).transpose().with_context(|| "oN")?,
            grep: grep.map(open).transpose().with_context(|| "oG")?,
            xml: xml.map(open).transpose().with_context(|| "oX")?,
            skiddie: skiddie.map(open).transpose().with_context(|| "oS")?,
            machine: machine.map(open).transpose().with_context(|| "oM")?,
            hex: hex.map(open).transpose().with_context(|| "oH")?,
        })
    }

    pub fn write_headers(
        &mut self,
        cmdline: &str,
        stylesheet: Option<&str>,
        webxml: bool,
        no_stylesheet: bool,
    ) -> Result<()> {
        if let Some(f) = &mut self.xml {
            writeln!(f, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
            writeln!(
                f,
                r#"<!DOCTYPE nmaprun>"#
            )?;
            if !no_stylesheet {
                if let Some(s) = stylesheet {
                    writeln!(
                        f,
                        r#"<?xml-stylesheet href="{}" type="text/xsl"?>"#,
                        xml_escape(s)
                    )?;
                } else if webxml {
                    writeln!(
                        f,
                        r#"<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl" type="text/xsl"?>"#
                    )?;
                }
            }
            let now = chrono_timestamp();
            writeln!(
                f,
                r#"<nmaprun scanner="nmaprs" args="{}" start="{}" startstr="{}" version="0.1.0" xmloutputversion="1.05">"#,
                xml_escape(cmdline),
                now.0,
                xml_escape(&now.1)
            )?;
            writeln!(f, r#"<verbose level="0"/>"#)?;
            writeln!(f, r#"<debugging level="0"/>"#)?;
        }
        Ok(())
    }

    pub fn write_scaninfo(&mut self, scan_type: &str, protocol: &str, num_services: usize) -> Result<()> {
        if let Some(f) = &mut self.xml {
            writeln!(
                f,
                r#"<scaninfo type="{}" protocol="{}" numservices="{}"/>"#,
                xml_escape(scan_type),
                xml_escape(protocol),
                num_services
            )?;
        }
        Ok(())
    }

    pub fn write_footer(&mut self, hosts_up: usize, hosts_down: usize, hosts_total: usize) -> Result<()> {
        if let Some(f) = &mut self.xml {
            let now = chrono_timestamp();
            writeln!(f, r#"<runstats><finished time="{}" timestr="{}" summary="nmaprs done: {} IP address{} ({} host{} up)" exit="success"/>"#,
                now.0,
                xml_escape(&now.1),
                hosts_total,
                if hosts_total == 1 { "" } else { "es" },
                hosts_up,
                if hosts_up == 1 { "" } else { "s" },
            )?;
            writeln!(
                f,
                r#"<hosts up="{}" down="{}" total="{}"/>"#,
                hosts_up, hosts_down, hosts_total
            )?;
            writeln!(f, "</runstats></nmaprun>")?;
        }
        Ok(())
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
}

/// Returns (unix_timestamp, human_readable_string).
fn chrono_timestamp() -> (u64, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Format a simple UTC timestamp without pulling in chrono crate.
    // Days since epoch → date; seconds of day → HH:MM:SS.
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    // Compute year/month/day from days since 1970-01-01 (civil calendar algorithm).
    let (y, mo, d) = days_to_ymd(days);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_name = months.get(mo as usize).unwrap_or(&"???");
    let weekdays = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let dow = weekdays[(days % 7) as usize];
    (
        secs,
        format!(
            "{} {} {:2} {:02}:{:02}:{:02} {}",
            dow, month_name, d, h, m, s, y
        ),
    )
}

fn days_to_ymd(days: u64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant's chrono-compatible date library.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32 - 1, d as u32) // m-1 for 0-indexed month
}

/// Single port line as printed / written to `-oN` (tab-separated).
pub fn port_line_text(l: &PortLine, show_reason: bool) -> String {
    let mut s = if let Some(ref v) = l.version_info {
        format!("{}/{}\t{}\t{}", l.port, l.proto, l.state, v)
    } else {
        format!("{}/{}\t{}", l.port, l.proto, l.state)
    };
    if show_reason {
        s.push_str(&format!("\t{}", reason_str(l)));
    }
    s
}

pub fn print_stdout(lines: &[PortLine], open_only: bool, show_reason: bool, verbosity: u8) {
    for l in lines {
        if open_only && l.state != "open" {
            continue;
        }
        if verbosity == 0 && l.state == "closed" {
            continue;
        }
        println!("{}", port_line_text(l, show_reason));
    }
}

fn reason_str(l: &PortLine) -> &'static str {
    use crate::scan::PortReason::*;
    match l.reason {
        SynAck => "syn-ack",
        ConnRefused => "conn-refused",
        TcpRst => "reset",
        TcpWindowRst => "tcp-window",
        Timeout => "no-response",
        HostTimeout => "host-timeout",
        Error => "error",
        UdpResponse => "udp-response",
        IcmpPortUnreachable => "icmp-port-unreachable",
        IcmpUnreachableFiltered => "icmp-unreachable",
        IcmpProtoUnreachable => "icmp-proto-unreachable",
        FtpBounceOpen => "ftp-bounce-open",
        FtpBounceClosed => "ftp-bounce-closed",
        SctpInitAck => "sctp-init-ack",
        SctpCookieAck => "sctp-cookie-ack",
        SctpAbort => "sctp-abort",
        IdleIpIdOpen => "idle-ipid-open",
        IdleIpIdClosed => "idle-ipid-closed",
        IdleProbeFailed => "idle-probe-failed",
    }
}

/// Write `-oN` and/or `-oS` host sections (same tab-separated lines; `-oS` is script-kiddie transformed).
pub fn write_normal_files(
    mut normal: Option<&mut File>,
    mut skiddie: Option<&mut File>,
    host: IpAddr,
    lines: &[PortLine],
    show_reason: bool,
) -> Result<()> {
    if normal.is_none() && skiddie.is_none() {
        return Ok(());
    }
    let hdr = format!("Nmap scan report for {host}");
    if let Some(f) = normal.as_mut() {
        writeln!(f, "{}", hdr)?;
    }
    if let Some(sf) = skiddie.as_mut() {
        writeln!(sf, "{}", crate::skiddie::skid_line(&hdr))?;
    }
    for l in lines {
        let line = port_line_text(l, show_reason);
        if let Some(f) = normal.as_mut() {
            writeln!(f, "{}", line)?;
        }
        if let Some(sf) = skiddie.as_mut() {
            writeln!(sf, "{}", crate::skiddie::skid_line(&line))?;
        }
    }
    if let Some(f) = normal.as_mut() {
        writeln!(f)?;
    }
    if let Some(sf) = skiddie.as_mut() {
        writeln!(sf)?;
    }
    Ok(())
}

/// `-sn` ping scan: host up line and optional `OS guess:` line (mirrors stdout to output files).
pub fn write_sn_host_files(
    mut normal: Option<&mut File>,
    mut skiddie: Option<&mut File>,
    mut grep: Option<&mut File>,
    mut xml: Option<&mut File>,
    host: IpAddr,
    os_guess_line: Option<&str>,
) -> Result<()> {
    let report = format!("Nmap scan report for {host} - Host is up");
    if let Some(f) = normal.as_mut() {
        writeln!(f, "{}", report)?;
    }
    if let Some(sf) = skiddie.as_mut() {
        writeln!(sf, "{}", crate::skiddie::skid_line(&report))?;
    }
    if let Some(gf) = grep.as_mut() {
        writeln!(gf, "Host: {host} ()\tStatus: Up")?;
    }
    if let Some(xf) = xml.as_mut() {
        let ty = if host.is_ipv4() { "ipv4" } else { "ipv6" };
        writeln!(xf, r#"<host>"#)?;
        writeln!(xf, r#"<status state="up" reason="echo-reply" reason_ttl="0"/>"#)?;
        writeln!(xf, r#"<address addr="{host}" addrtype="{ty}"/>"#)?;
        writeln!(xf, r#"<hostnames/>"#)?;
        writeln!(xf, r#"</host>"#)?;
    }
    if let Some(line) = os_guess_line {
        if let Some(f) = normal.as_mut() {
            writeln!(f, "{}", line)?;
        }
        if let Some(sf) = skiddie.as_mut() {
            writeln!(sf, "{}", crate::skiddie::skid_line(line))?;
        }
    }
    if normal.is_some() || skiddie.is_some() {
        if let Some(f) = normal.as_mut() {
            writeln!(f)?;
        }
        if let Some(sf) = skiddie.as_mut() {
            writeln!(sf)?;
        }
    }
    Ok(())
}

pub fn write_grep(f: &mut File, host: IpAddr, lines: &[PortLine]) -> Result<()> {
    for l in lines {
        writeln!(
            f,
            "Host: {} ()\tPorts: {}/{}/open////",
            host, l.port, l.proto
        )?;
    }
    Ok(())
}

pub fn write_xml_host(f: &mut File, host: IpAddr, lines: &[PortLine], os_info: Option<&str>) -> Result<()> {
    let ty = if host.is_ipv4() { "ipv4" } else { "ipv6" };
    writeln!(f, r#"<host starttime="0" endtime="0">"#)?;
    writeln!(f, r#"<status state="up" reason="user-set" reason_ttl="0"/>"#)?;
    writeln!(f, r#"<address addr="{}" addrtype="{}"/>"#, host, ty)?;
    writeln!(f, r#"<hostnames/>"#)?;

    // Compute extraports (most common non-shown state).
    let closed_count = lines.iter().filter(|l| l.state == "closed").count();
    let filtered_count = lines.iter().filter(|l| l.state == "filtered").count();

    writeln!(f, "<ports>")?;

    // extraports: summarize closed/filtered ports
    if closed_count > 0 {
        writeln!(f, r#"<extraports state="closed" count="{}"/>"#, closed_count)?;
    }
    if filtered_count > 0 {
        writeln!(f, r#"<extraports state="filtered" count="{}"/>"#, filtered_count)?;
    }

    for l in lines {
        write!(
            f,
            r#"<port protocol="{}" portid="{}"><state state="{}" reason="{}" reason_ttl="0"/>"#,
            l.proto, l.port, l.state, reason_str(l)
        )?;
        if let Some(ref v) = l.version_info {
            // Parse version_info into product/version if possible.
            let (product, version) = split_version_info(v);
            write!(
                f,
                r#"<service name="{}" product="{}" version="{}"/>"#,
                xml_escape(&l.proto),
                xml_escape(product),
                xml_escape(version)
            )?;
        }
        writeln!(f, "</port>")?;
    }
    writeln!(f, "</ports>")?;

    if let Some(os) = os_info {
        writeln!(f, r#"<os><osmatch name="{}" accuracy="0"/></os>"#, xml_escape(os))?;
    }

    writeln!(f, "</host>")?;
    Ok(())
}

fn split_version_info(v: &str) -> (&str, &str) {
    // Version info format: "product version (info) [os] {device} cpe:/..."
    // Simple split on first space for product vs version.
    match v.split_once(' ') {
        Some((p, rest)) => (p, rest),
        None => (v, ""),
    }
}

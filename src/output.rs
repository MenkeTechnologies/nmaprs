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
}

impl OutputSet {
    pub fn open(
        normal: Option<&Path>,
        grep: Option<&Path>,
        xml: Option<&Path>,
        skiddie: Option<&Path>,
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
        })
    }

    pub fn write_headers(&mut self, cmdline: &str) -> Result<()> {
        if let Some(f) = &mut self.xml {
            writeln!(
                f,
                r#"<?xml version="1.0" encoding="UTF-8"?><nmaprs><cmdline>{}</cmdline>"#,
                xml_escape(cmdline)
            )?;
        }
        Ok(())
    }

    pub fn write_footer(&mut self) -> Result<()> {
        if let Some(f) = &mut self.xml {
            writeln!(f, "</nmaprs>")?;
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

pub fn write_xml_host(f: &mut File, host: IpAddr, lines: &[PortLine]) -> Result<()> {
    let ty = if host.is_ipv4() { "ipv4" } else { "ipv6" };
    writeln!(f, r#"  <host><address addr="{}" addrtype="{}"/>"#, host, ty)?;
    writeln!(f, "    <ports>")?;
    for l in lines {
        writeln!(
            f,
            r#"      <port protocol="{}" portid="{}"><state state="{}"/></port>"#,
            l.proto, l.port, l.state
        )?;
    }
    writeln!(f, "    </ports></host>")?;
    Ok(())
}

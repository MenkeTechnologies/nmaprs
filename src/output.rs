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
}

impl OutputSet {
    pub fn open(
        normal: Option<&Path>,
        grep: Option<&Path>,
        xml: Option<&Path>,
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

pub fn print_stdout(lines: &[PortLine], open_only: bool, show_reason: bool, verbosity: u8) {
    for l in lines {
        if open_only && l.state != "open" {
            continue;
        }
        if verbosity == 0 && l.state == "closed" {
            continue;
        }
        if show_reason {
            println!("{}/{}\t{}\t{}", l.port, l.proto, l.state, reason_str(l));
        } else {
            println!("{}/{}\t{}", l.port, l.proto, l.state);
        }
    }
}

fn reason_str(l: &PortLine) -> &'static str {
    use crate::scan::PortReason::*;
    match l.reason {
        SynAck => "syn-ack",
        ConnRefused => "conn-refused",
        Timeout => "no-response",
        Error => "error",
        UdpResponse => "udp-response",
        IcmpPortUnreachable => "icmp-port-unreachable",
    }
}

pub fn write_normal(f: &mut File, host: IpAddr, lines: &[PortLine]) -> Result<()> {
    writeln!(f, "Nmap scan report for {host}")?;
    for l in lines {
        writeln!(f, "{}/{}\t{}", l.port, l.proto, l.state)?;
    }
    writeln!(f)?;
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

//! Expand nmap-style glued short options (`-sS`, `-PS80`, `-T4`) before clap parsing.

/// Expand argv for nmaprs so clap can parse long-style flags consistently.
pub fn expand_nmap_style_argv<I>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.is_empty() {
        return args;
    }
    let mut out: Vec<String> = Vec::with_capacity(args.len() + 8);
    out.push(args[0].clone());
    let mut i = 1usize;
    while i < args.len() {
        let a = &args[i];
        // -sL list scan, -sn ping scan (no port scan)
        if a.as_str() == "-sL" {
            out.push("--sL".to_string());
            i += 1;
            continue;
        }
        if a.as_str() == "-sn" {
            out.push("--sn".to_string());
            i += 1;
            continue;
        }
        // -sO IP protocol scan (must precede generic -sX → --scan-type)
        if a.as_str() == "-sO" {
            out.push("--sO".to_string());
            i += 1;
            continue;
        }
        // -sI <zombie> (idle scan — parsed for CLI parity)
        if a.as_str() == "-sI" {
            out.push("--sI".to_string());
            i += 1;
            if i < args.len() {
                let n = &args[i];
                if !n.starts_with('-') {
                    out.push(n.clone());
                    i += 1;
                }
            }
            continue;
        }
        // -iL / -iR (nmap target input)
        if a.as_str() == "-iL" {
            out.push("--iL".to_string());
            i += 1;
            continue;
        }
        if a.as_str() == "-iR" {
            out.push("--iR".to_string());
            i += 1;
            continue;
        }
        // -oN / -oX / -oS / -oG / -oA
        if a.len() == 3 && a.starts_with("-o") {
            let k = a.as_bytes()[2] as char;
            if matches!(k, 'N' | 'X' | 'S' | 'G' | 'A' | 'M' | 'H') {
                out.push(format!("--o{k}"));
                i += 1;
                continue;
            }
        }
        if let Some(rest) = a.strip_prefix('-') {
            if rest.is_empty() {
                out.push(a.clone());
                i += 1;
                continue;
            }
            // Long options pass through
            if rest.starts_with('-') {
                out.push(a.clone());
                i += 1;
                continue;
            }
            // -sX: overloaded in nmap — scan types, -sV version, -sC script default
            if rest.len() == 2 && rest.starts_with('s') {
                let ch = rest.as_bytes()[1] as char;
                if ch.is_ascii_alphabetic() {
                    match ch {
                        'V' => {
                            out.push("--version-scan".to_string());
                            i += 1;
                            continue;
                        }
                        'C' => {
                            out.push("--script-default".to_string());
                            i += 1;
                            continue;
                        }
                        _ => {
                            out.push("--scan-type".to_string());
                            out.push(ch.to_string());
                            i += 1;
                            continue;
                        }
                    }
                }
            }
            // -Pn
            if rest == "Pn" {
                out.push("--no-ping".to_string());
                i += 1;
                continue;
            }
            // -PE / -PP / -PM (no port list)
            if matches!(rest, "PE" | "PP" | "PM") {
                let letter = rest.as_bytes()[1] as char;
                out.push(format!("--ping-{letter}"));
                i += 1;
                continue;
            }
            // -PO [protocol list] — before generic -P* so "PO" is not mistaken for --ping-O
            if rest == "PO" || rest.starts_with("PO") {
                out.push("--ping-ip-proto".to_string());
                if rest.len() > 2 {
                    out.push(rest[2..].to_string());
                } else {
                    // Nmap default IP-protocol ping list when -PO is given alone
                    out.push("1,2,4".to_string());
                }
                i += 1;
                continue;
            }
            // -PS [ports], -PA, -PU, -PY
            if rest.len() >= 2 && rest.starts_with('P') {
                let kind = rest.as_bytes()[1] as char;
                if matches!(kind, 'S' | 'A' | 'U' | 'Y') {
                    if rest.len() == 2 {
                        out.push(format!("--ping-{kind}"));
                        i += 1;
                        continue;
                    }
                    // -PS80 or -PS22,80
                    let tail = &rest[2..];
                    out.push(format!("--ping-{kind}"));
                    out.push(tail.to_string());
                    i += 1;
                    continue;
                }
            }
            // -T0 .. -T5
            if rest.len() == 2 && rest.starts_with('T') {
                let d = rest.as_bytes()[1];
                if d.is_ascii_digit() && (d - b'0') <= 5 {
                    out.push("--timing".to_string());
                    out.push((d - b'0').to_string());
                    i += 1;
                    continue;
                }
            }
            // -v, -vv, -vvv
            if rest.chars().all(|c| c == 'v') && !rest.is_empty() && rest.len() <= 5 {
                out.push(format!("--verbosity={}", rest.len()));
                i += 1;
                continue;
            }
            // -d, -dd
            if rest.chars().all(|c| c == 'd') && !rest.is_empty() && rest.len() <= 5 {
                out.push(format!("--debug={}", rest.len()));
                i += 1;
                continue;
            }
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_scan_and_timing() {
        let v = expand_nmap_style_argv(vec![
            "nmaprs".into(),
            "-sT".into(),
            "-T4".into(),
            "host".into(),
        ]);
        assert_eq!(
            v,
            vec!["nmaprs", "--scan-type", "T", "--timing", "4", "host"]
        );
    }

    #[test]
    fn expands_pn_and_ps_ports() {
        let v = expand_nmap_style_argv(vec!["nmaprs".into(), "-Pn".into(), "-PS80,443".into()]);
        assert_eq!(v, vec!["nmaprs", "--no-ping", "--ping-S", "80,443"]);
    }

    #[test]
    fn expands_so_to_long_flag_not_scan_type_o() {
        let v = expand_nmap_style_argv(vec!["nmaprs".into(), "-sO".into(), "127.0.0.1".into()]);
        assert_eq!(v, vec!["nmaprs", "--sO", "127.0.0.1"]);
    }

    #[test]
    fn expands_po_default_protos() {
        let v = expand_nmap_style_argv(vec!["nmaprs".into(), "-PO".into(), "host".into()]);
        assert_eq!(v, vec!["nmaprs", "--ping-ip-proto", "1,2,4", "host"]);
    }

    #[test]
    fn expands_po_with_tail() {
        let v = expand_nmap_style_argv(vec!["nmaprs".into(), "-PO6".into()]);
        assert_eq!(v, vec!["nmaprs", "--ping-ip-proto", "6"]);
    }

    #[test]
    fn expands_version_and_script_default_short_flags() {
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-sV".into()]),
            vec!["nmaprs", "--version-scan"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-sC".into()]),
            vec!["nmaprs", "--script-default"]
        );
    }

    #[test]
    fn expands_sl_sn_il_ir() {
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-sL".into()]),
            vec!["nmaprs", "--sL"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-sn".into()]),
            vec!["nmaprs", "--sn"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-iL".into()]),
            vec!["nmaprs", "--iL"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-iR".into()]),
            vec!["nmaprs", "--iR"]
        );
    }

    #[test]
    fn expands_si_consumes_following_non_flag() {
        let v = expand_nmap_style_argv(vec![
            "nmaprs".into(),
            "-sI".into(),
            "192.0.2.1:443".into(),
            "10.0.0.1".into(),
        ]);
        assert_eq!(v, vec!["nmaprs", "--sI", "192.0.2.1:443", "10.0.0.1",]);
    }

    #[test]
    fn expands_output_short_flags() {
        let v = expand_nmap_style_argv(vec![
            "nmaprs".into(),
            "-oN".into(),
            "out.txt".into(),
            "-oA".into(),
            "base".into(),
        ]);
        assert_eq!(v, vec!["nmaprs", "--oN", "out.txt", "--oA", "base"]);
    }

    #[test]
    fn expands_verbosity_and_debug_counts() {
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-vvv".into()]),
            vec!["nmaprs", "--verbosity=3"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-dd".into()]),
            vec!["nmaprs", "--debug=2"]
        );
    }

    #[test]
    fn expands_ping_ack_udp_sctp_tails() {
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-PA443".into()]),
            vec!["nmaprs", "--ping-A", "443"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-PU53".into()]),
            vec!["nmaprs", "--ping-U", "53"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-PY38412".into()]),
            vec!["nmaprs", "--ping-Y", "38412"]
        );
    }

    #[test]
    fn passes_through_double_dash_long_options() {
        let v = expand_nmap_style_argv(vec![
            "nmaprs".into(),
            "--no-ping".into(),
            "-p".into(),
            "22".into(),
            "127.0.0.1".into(),
        ]);
        assert_eq!(v, vec!["nmaprs", "--no-ping", "-p", "22", "127.0.0.1"]);
    }

    #[test]
    fn expand_only_binary_is_unchanged() {
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into()]),
            vec!["nmaprs"]
        );
    }

    #[test]
    fn expand_empty_argv_stays_empty() {
        assert!(expand_nmap_style_argv(Vec::<String>::new()).is_empty());
    }

    #[test]
    fn expand_pe_pm_icmp_short_flags() {
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-PE".into()]),
            vec!["nmaprs", "--ping-E"]
        );
        assert_eq!(
            expand_nmap_style_argv(vec!["nmaprs".into(), "-PM".into()]),
            vec!["nmaprs", "--ping-M"]
        );
    }

    #[test]
    fn expand_timing_t0_through_t5() {
        for n in 0u8..=5 {
            let v = expand_nmap_style_argv(vec!["nmaprs".into(), format!("-T{n}")]);
            assert_eq!(
                v,
                vec!["nmaprs".to_string(), "--timing".to_string(), n.to_string(),]
            );
        }
    }
}

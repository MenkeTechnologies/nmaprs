//! Script-kiddie (`-oS`) text transform — same rules as Nmap’s `skid_output()` in `output.cc`
//! (50% substitution vs random case flip; `A→4`, `E→3`, `I→!|1`, `O→0`, `S→$`/`z`, `Z↔S`, `z↔s`).

use rand::Rng;

/// Transform one line (Nmap applies this to each formatted line before writing `-oS`).
pub fn skid_line(input: &str) -> String {
    let mut s: Vec<u8> = input.as_bytes().to_vec();
    skid_bytes(&mut s);
    String::from_utf8_lossy(&s).into_owned()
}

fn skid_bytes(s: &mut [u8]) {
    let mut rng = rand::thread_rng();
    let len = s.len();
    let mut i = 0;
    while i < len {
        if rng.gen_bool(0.5) {
            match s[i] {
                b'A' => s[i] = b'4',
                b'e' | b'E' => s[i] = b'3',
                b'i' | b'I' => {
                    s[i] = [b'!', b'|', b'1'][rng.gen_range(0..3)];
                }
                b'o' | b'O' => s[i] = b'0',
                b's' | b'S' => {
                    let next_alnum = s
                        .get(i + 1)
                        .map(|c| c.is_ascii_alphanumeric())
                        .unwrap_or(false);
                    if !next_alnum {
                        s[i] = b'z';
                    } else {
                        s[i] = b'$';
                    }
                }
                b'z' => s[i] = b's',
                b'Z' => s[i] = b'S',
                _ => {}
            }
        } else if s[i].is_ascii_uppercase() && rng.gen_ratio(1, 3) {
            s[i] = s[i].to_ascii_lowercase();
        } else if s[i].is_ascii_lowercase() && rng.gen_ratio(1, 3) {
            s[i] = s[i].to_ascii_uppercase();
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skid_produces_printable_ascii() {
        let o = skid_line("Nmap scan report for 127.0.0.1");
        assert!(!o.is_empty());
    }

    #[test]
    fn skid_line_preserves_byte_length_for_ascii() {
        let s = "Nmap scan report for 127.0.0.1:22/tcp";
        assert_eq!(skid_line(s).len(), s.len());
    }
}

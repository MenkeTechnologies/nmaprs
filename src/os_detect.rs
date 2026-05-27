//! Heuristic OS guess from ICMP TTL (`-O` / `-A` with `-sn` or ping).

pub fn guess_from_ttl(ttl: Option<u8>) -> &'static str {
    match ttl {
        Some(t) if t <= 64 => "Linux/Unix (TTL heuristic)",
        Some(t) if t <= 128 => "Windows (TTL heuristic)",
        Some(_) => "Network device (TTL heuristic)",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::guess_from_ttl;

    #[test]
    fn ttl_boundaries() {
        assert_eq!(guess_from_ttl(None), "unknown");
        assert_eq!(guess_from_ttl(Some(1)), "Linux/Unix (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(64)), "Linux/Unix (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(65)), "Windows (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(128)), "Windows (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(129)), "Network device (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(255)), "Network device (TTL heuristic)");
    }

    #[test]
    fn ttl_boundary_64_vs_65() {
        assert_eq!(guess_from_ttl(Some(64)), "Linux/Unix (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(65)), "Windows (TTL heuristic)");
    }

    #[test]
    fn ttl_boundary_128_vs_129() {
        assert_eq!(guess_from_ttl(Some(128)), "Windows (TTL heuristic)");
        assert_eq!(guess_from_ttl(Some(129)), "Network device (TTL heuristic)");
    }

    #[test]
    fn ttl_one_is_linux_bucket() {
        assert_eq!(guess_from_ttl(Some(1)), "Linux/Unix (TTL heuristic)");
    }

    #[test]
    fn ttl_mid_windows_bucket() {
        assert_eq!(guess_from_ttl(Some(100)), "Windows (TTL heuristic)");
    }
}

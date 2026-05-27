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

    #[test]
    fn ttl_zero_is_linux_bucket() {
        assert_eq!(guess_from_ttl(Some(0)), "Linux/Unix (TTL heuristic)");
    }

    #[test]
    fn ttl_two_is_linux_bucket() {
        assert_eq!(guess_from_ttl(Some(2)), "Linux/Unix (TTL heuristic)");
    }

    #[test]
    fn ttl_thirty_two_is_linux_bucket() {
        assert_eq!(guess_from_ttl(Some(32)), "Linux/Unix (TTL heuristic)");
    }

    #[test]
    fn ttl_sixty_three_is_linux_bucket() {
        assert_eq!(guess_from_ttl(Some(63)), "Linux/Unix (TTL heuristic)");
    }

    #[test]
    fn ttl_sixty_six_is_windows_bucket() {
        assert_eq!(guess_from_ttl(Some(66)), "Windows (TTL heuristic)");
    }

    #[test]
    fn ttl_ninety_nine_is_windows_bucket() {
        assert_eq!(guess_from_ttl(Some(99)), "Windows (TTL heuristic)");
    }

    #[test]
    fn ttl_one_twenty_seven_is_windows_bucket() {
        assert_eq!(guess_from_ttl(Some(127)), "Windows (TTL heuristic)");
    }

    #[test]
    fn ttl_one_thirty_is_network_bucket() {
        assert_eq!(guess_from_ttl(Some(130)), "Network device (TTL heuristic)");
    }

    #[test]
    fn ttl_two_fifty_four_is_network_bucket() {
        assert_eq!(guess_from_ttl(Some(254)), "Network device (TTL heuristic)");
    }

    #[test]
    fn ttl_two_hundred_is_network_bucket() {
        assert_eq!(guess_from_ttl(Some(200)), "Network device (TTL heuristic)");
    }

    #[test]
    fn unknown_when_ttl_absent() {
        assert_eq!(guess_from_ttl(None), "unknown");
    }

    #[test]
    fn ttl_exactly_255_is_network_bucket() {
        assert_eq!(guess_from_ttl(Some(255)), "Network device (TTL heuristic)");
    }

    #[test]
    fn ttl_exactly_64_is_linux_bucket() {
        assert_eq!(guess_from_ttl(Some(64)), "Linux/Unix (TTL heuristic)");
    }

    #[test]
    fn ttl_exactly_128_is_windows_bucket() {
        assert_eq!(guess_from_ttl(Some(128)), "Windows (TTL heuristic)");
    }
}

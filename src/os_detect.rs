//! Heuristic OS guess from ICMP TTL (`-O` / `-A` with `-sn` or ping).

pub fn guess_from_ttl(ttl: Option<u8>) -> &'static str {
    match ttl {
        Some(t) if t <= 64 => "Linux/Unix (TTL heuristic)",
        Some(t) if t <= 128 => "Windows (TTL heuristic)",
        Some(_) => "Network device (TTL heuristic)",
        _ => "unknown",
    }
}

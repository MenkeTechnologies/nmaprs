//! Nmap-compatible fingerprint expression matching — delegates to upstream `expr_match` in `c/expr_match.c`.

extern "C" {
    fn nmap_expr_match(
        val: *const std::ffi::c_char,
        vlen: usize,
        expr: *const std::ffi::c_char,
        explen: usize,
        do_nested: std::os::raw::c_int,
    ) -> u8;
}

/// Compare an observed value to a reference expression (`3B-47`, `8|A`, `>10`, nested `M[>500]ST11`, …).
#[must_use]
pub fn expr_match(val: &str, expr: &str, tcp_opt_style: bool) -> bool {
    // Rust `str` is not NUL-terminated; empty `expr` is handled here so C never sees `strlen` edge cases.
    if expr.is_empty() {
        return val.is_empty();
    }
    // Safety: C reads at most `vlen` / `explen` bytes (no strlen on Rust pointers).
    unsafe {
        nmap_expr_match(
            val.as_ptr().cast(),
            val.len(),
            expr.as_ptr().cast(),
            expr.len(),
            i32::from(tcp_opt_style),
        ) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_hex() {
        assert!(expr_match("40", "3B-47", false));
        assert!(!expr_match("30", "3B-47", false));
    }

    #[test]
    fn or_clause() {
        assert!(expr_match("FAF0", "F424|FAF0", false));
        assert!(expr_match("F424", "F424|FAF0", false));
        assert!(!expr_match("FFFF", "F424|FAF0", false));
    }

    #[test]
    fn empty_expr_non_empty_val() {
        assert!(!expr_match("a", "", false));
    }

    #[test]
    fn both_empty() {
        assert!(expr_match("", "", false));
    }

    #[test]
    fn greater_than_numeric() {
        assert!(expr_match("15", ">10", false));
        assert!(!expr_match("5", ">10", false));
    }
}

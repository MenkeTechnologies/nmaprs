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

    #[test]
    fn less_than_numeric() {
        assert!(expr_match("5", "<10", false));
        assert!(!expr_match("15", "<10", false));
    }

    #[test]
    fn exact_hex_match() {
        assert!(expr_match("FAF0", "FAF0", false));
        assert!(!expr_match("FAF1", "FAF0", false));
    }

    #[test]
    fn range_inclusive_endpoints() {
        assert!(expr_match("3B", "3B-3B", false));
        assert!(expr_match("47", "3B-47", false));
        assert!(!expr_match("48", "3B-47", false));
    }

    #[test]
    fn or_two_alternatives_second_branch() {
        assert!(expr_match("FAF0", "F424|FAF0", false));
        assert!(!expr_match("FFFF", "F424|FAF0", false));
    }

    #[test]
    fn empty_val_non_empty_expr_fails() {
        assert!(!expr_match("", "3B-47", false));
    }

    #[test]
    fn single_char_or_match() {
        assert!(expr_match("Y", "Y|N", false));
        assert!(expr_match("N", "Y|N", false));
    }

    #[test]
    fn greater_than_hex() {
        assert!(expr_match("100", ">FF", false));
        assert!(!expr_match("FF", ">FF", false));
    }

    #[test]
    fn long_hex_string_exact() {
        assert!(expr_match(
            "0123456789ABCDEF",
            "0123456789ABCDEF",
            false
        ));
    }

    #[test]
    fn or_with_hex_and_decimal_mixed() {
        assert!(expr_match("255", "FF|255", false));
        assert!(expr_match("FF", "255|FF", false));
    }

    #[test]
    fn less_than_hex_upper_bound() {
        assert!(expr_match("3A", "<3B", false));
        assert!(!expr_match("3B", "<3B", false));
    }

    #[test]
    fn equal_numeric_match() {
        assert!(expr_match("10", "10", false));
    }

    #[test]
    fn range_single_value_only() {
        assert!(expr_match("40", "40", false));
    }

    #[test]
    fn hex_range_lower_boundary() {
        assert!(expr_match("3B", "3B-47", false));
    }

    #[test]
    fn hex_range_upper_boundary() {
        assert!(expr_match("47", "3B-47", false));
    }

    #[test]
    fn greater_than_decimal_boundary() {
        assert!(!expr_match("10", ">10", false));
        assert!(expr_match("11", ">10", false));
    }

    #[test]
    fn less_than_decimal_boundary() {
        assert!(expr_match("9", "<10", false));
        assert!(!expr_match("10", "<10", false));
    }

    #[test]
    fn or_first_branch_matches() {
        assert!(expr_match("F424", "F424|FAF0", false));
    }

    #[test]
    fn range_excludes_below_lower_bound() {
        assert!(!expr_match("3A", "3B-47", false));
    }

    #[test]
    fn range_excludes_above_upper_bound() {
        assert!(!expr_match("48", "3B-47", false));
    }

    #[test]
    fn empty_val_empty_expr_matches() {
        assert!(expr_match("", "", false));
    }

    #[test]
    fn greater_than_at_boundary_fails() {
        assert!(!expr_match("10", ">10", false));
    }
}

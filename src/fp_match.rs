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
        assert!(expr_match("0123456789ABCDEF", "0123456789ABCDEF", false));
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

    #[test]
    fn or_three_alternatives_third_matches() {
        assert!(expr_match("BEEF", "F424|FAF0|BEEF", false));
    }

    #[test]
    fn range_single_hex_digit() {
        assert!(expr_match("A", "A-A", false));
        assert!(!expr_match("B", "A-A", false));
    }

    #[test]
    fn less_than_zero_decimal() {
        assert!(expr_match("0", "<1", false));
        assert!(!expr_match("1", "<1", false));
    }

    #[test]
    fn greater_than_hex_ff() {
        assert!(expr_match("100", ">FF", false));
        assert!(!expr_match("FE", ">FF", false));
    }

    #[test]
    fn exact_match_case_sensitive_hex() {
        assert!(expr_match("AB", "AB", false));
        assert!(!expr_match("ab", "AB", false));
    }

    #[test]
    fn range_decimal_inclusive() {
        assert!(expr_match("10", "10-12", false));
        assert!(expr_match("12", "10-12", false));
        assert!(!expr_match("13", "10-12", false));
    }

    #[test]
    fn non_empty_val_non_matching_expr_fails() {
        assert!(!expr_match("dead", "beef", false));
    }

    #[test]
    fn less_than_at_zero_boundary() {
        assert!(!expr_match("0", "<0", false));
    }

    #[test]
    fn or_neither_branch_matches_fails() {
        assert!(!expr_match("dead", "beef|cafe", false));
    }

    #[test]
    fn greater_than_at_exact_boundary_fails() {
        assert!(!expr_match("FF", ">FF", false));
    }

    #[test]
    fn range_hex_midpoint_matches() {
        assert!(expr_match("40", "3F-41", false));
    }

    #[test]
    fn single_digit_decimal_exact() {
        assert!(expr_match("7", "7", false));
    }

    #[test]
    fn or_with_three_hex_alts() {
        assert!(expr_match("AB", "AA|AB|AC", false));
    }

    #[test]
    fn greater_than_at_boundary_plus_one() {
        assert!(expr_match("11", ">10", false));
    }

    #[test]
    fn less_than_at_boundary_minus_one() {
        assert!(expr_match("9", "<10", false));
    }

    #[test]
    fn range_hex_single_value_endpoints() {
        assert!(expr_match("FF", "FF-FF", false));
    }

    #[test]
    fn or_first_branch_decimal() {
        assert!(expr_match("10", "10|20", false));
    }

    #[test]
    fn exact_match_lowercase_differs_from_upper_hex() {
        assert!(!expr_match("ab", "AB", false));
    }

    #[test]
    fn empty_val_with_or_expr_fails() {
        assert!(!expr_match("", "A|B", false));
    }

    #[test]
    fn range_decimal_single_point() {
        assert!(expr_match("5", "5-5", false));
    }

    #[test]
    fn greater_than_zero_decimal() {
        assert!(expr_match("1", ">0", false));
    }

    #[test]
    fn less_than_one_decimal() {
        assert!(expr_match("0", "<1", false));
    }

    #[test]
    fn or_second_branch_hex() {
        assert!(expr_match("BEEF", "DEAD|BEEF", false));
    }

    #[test]
    fn range_inclusive_below_start_fails() {
        assert!(!expr_match("09", "10-12", false));
    }

    #[test]
    fn range_inclusive_above_end_fails() {
        assert!(!expr_match("13", "10-12", false));
    }

    #[test]
    fn greater_than_hex_ff_boundary() {
        assert!(expr_match("100", ">FF", false));
        assert!(!expr_match("FF", ">FF", false));
    }

    #[test]
    fn tcp_opt_style_mss_literal_match() {
        assert!(expr_match("M1460", "M1460", true));
    }

    #[test]
    fn tcp_opt_style_mss_or_range_alternative() {
        assert!(expr_match("M1400", "M1400|M1500", true));
    }

    #[test]
    fn tcp_opt_style_window_scale_match() {
        assert!(expr_match("W10", "W10", true));
    }

    #[test]
    fn tcp_opt_style_sack_permitted() {
        assert!(expr_match("S", "S", true));
    }

    #[test]
    fn tcp_opt_style_timestamp_present() {
        assert!(expr_match("T", "T", true));
    }

    #[test]
    fn tcp_opt_style_nop_match() {
        assert!(expr_match("N", "N", true));
    }

    #[test]
    fn tcp_opt_style_or_two_options() {
        assert!(expr_match("M1460", "M1400|M1460", true));
    }

    #[test]
    fn decimal_range_midpoint_inclusive() {
        assert!(expr_match("50", "40-60", false));
    }

    #[test]
    fn hex_or_lowercase_branch() {
        assert!(expr_match("ab", "ab|cd", false));
    }

    #[test]
    fn exact_match_single_zero() {
        assert!(expr_match("0", "0", false));
    }

    #[test]
    fn greater_than_single_digit() {
        assert!(expr_match("2", ">1", false));
    }

    #[test]
    fn less_than_single_digit() {
        assert!(expr_match("0", "<1", false));
    }

    #[test]
    fn or_four_alternatives_last_matches() {
        assert!(expr_match("D", "A|B|C|D", false));
    }

    #[test]
    fn range_hex_a_through_f() {
        assert!(expr_match("C", "A-F", false));
        assert!(!expr_match("G", "A-F", false));
    }
}

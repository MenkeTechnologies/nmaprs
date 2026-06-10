//! Adversarial tests for `expand_nmap_style_argv` short-flag rewriting.
//!
//! These tests pin behavior on three specific bug classes that the existing
//! in-module tests do NOT cover:
//!
//!   1. `-sI` must NOT swallow a following arg that begins with `-`
//!      (e.g. `-sI -p 80`). If it did, the user's `-p` flag would be
//!      silently consumed as the zombie host and `-p` would vanish from
//!      argv. The src/argv_expand.rs guard at the consume site only checks
//!      `!n.starts_with('-')` — pin that this guard actually works in
//!      a real `-sI <next-is-flag>` sequence.
//!
//!   2. `-sI` at end-of-argv (no zombie token at all) must not panic via
//!      out-of-bounds index, must not consume past the end, and must
//!      still produce a valid `--sI` rewrite. The `i < args.len()` guard
//!      after `i += 1` is the load-bearing check.
//!
//!   3. `-vvvvv` (5 v's) expands but `-vvvvvv` (6 v's) does NOT — the
//!      `rest.len() <= 5` cap is a hard boundary. Pin both sides of the
//!      boundary so future "clamp to max" refactors don't silently
//!      flip the over-cap behavior from "pass through unchanged" to
//!      "expand to verbosity=N" without an explicit test update.
//!
//! Each test is hand-crafted around a specific bug class — not a mirror
//! of "does the obvious case work" (those are already covered by the
//! 60+ tests in src/argv_expand.rs).

use nmaprs::argv_expand::expand_nmap_style_argv;

/// Bug class: argv-eating. If the `-sI` branch ever drops its
/// `!n.starts_with('-')` guard, a subsequent flag (here `-p`) would be
/// silently consumed as the "zombie" positional and lost from clap's
/// view. Pin that `-p` survives to the output.
#[test]
fn dash_s_i_does_not_consume_following_flag() {
    let v = expand_nmap_style_argv(vec![
        "nmaprs".into(),
        "-sI".into(),
        "-p".into(),
        "80".into(),
        "10.0.0.1".into(),
    ]);
    // `--sI` is emitted, then `-p`/`80`/`10.0.0.1` flow through unchanged.
    // Critically: `-p` is NOT pushed as the zombie arg of `--sI`.
    assert_eq!(
        v,
        vec!["nmaprs", "--sI", "-p", "80", "10.0.0.1"],
        "-sI must not consume a following arg that starts with '-'; \
         consuming it would silently lose the -p flag"
    );
}

/// Bug class: out-of-bounds panic / off-by-one. The `-sI` branch
/// increments `i` then checks `i < args.len()` before indexing. If the
/// bounds check were ever dropped, this test would panic with an
/// out-of-bounds index. Also pins that the standalone `-sI` (no zombie)
/// still produces a valid `--sI` rewrite without dropping it.
#[test]
fn dash_s_i_at_end_of_argv_does_not_panic_and_still_emits_long_form() {
    let v = expand_nmap_style_argv(vec!["nmaprs".into(), "-sI".into()]);
    assert_eq!(
        v,
        vec!["nmaprs", "--sI"],
        "-sI at EOF must not panic and must still emit --sI"
    );
}

/// Bug class: off-by-one on a hard length cap. `-vvvvv` (5 v's) IS the
/// max accepted verbosity expansion; `-vvvvvv` (6 v's) is one over the
/// cap and must pass through unchanged (NOT clamp to `--verbosity=5`).
/// This test pins BOTH sides of the boundary so a refactor to "clamp
/// instead of pass through" would force an explicit decision rather
/// than silently change behavior.
#[test]
fn verbosity_six_vs_passes_through_unchanged_not_clamped() {
    // Five v's: expansion succeeds.
    assert_eq!(
        expand_nmap_style_argv(vec!["nmaprs".into(), "-vvvvv".into()]),
        vec!["nmaprs", "--verbosity=5"],
        "5 v's must expand to verbosity=5 (existing behavior)"
    );
    // Six v's: cap exceeded → arg passes through verbatim, NOT clamped.
    assert_eq!(
        expand_nmap_style_argv(vec!["nmaprs".into(), "-vvvvvv".into()]),
        vec!["nmaprs", "-vvvvvv"],
        "6 v's must pass through unchanged — pinning that the rest.len() <= 5 \
         cap does not silently clamp; clap will reject downstream"
    );
}

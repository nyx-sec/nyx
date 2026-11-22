mod common;

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::PathBuf;
use std::sync::OnceLock;

fn state_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("state")
}

fn state_config() -> Config {
    let mut cfg = common::test_config(AnalysisMode::Full);
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg
}

/// Scan the fixtures directory once and cache the result for all tests.
/// Every test in this module filters the shared result by filename.
fn scan_all_fixtures() -> &'static Vec<Diag> {
    static DIAGS: OnceLock<Vec<Diag>> = OnceLock::new();
    DIAGS.get_or_init(|| {
        let cfg = state_config();
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed")
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn state_diags_for(filename: &str) -> Vec<&'static Diag> {
    scan_all_fixtures()
        .iter()
        .filter(|d| d.path.contains(filename) && d.id.starts_with("state-"))
        .collect()
}

fn state_ids_for(filename: &str) -> Vec<String> {
    state_diags_for(filename)
        .iter()
        .map(|d| d.id.clone())
        .collect()
}

fn has_rule(filename: &str, rule_id: &str) -> bool {
    state_diags_for(filename).iter().any(|d| d.id == rule_id)
}

fn has_rule_prefix(filename: &str, prefix: &str) -> bool {
    state_diags_for(filename)
        .iter()
        .any(|d| d.id.starts_with(prefix))
}

fn assert_has(filename: &str, rule_id: &str) {
    assert!(
        has_rule(filename, rule_id),
        "Expected {rule_id} in {filename}.\n  Got: {:?}",
        state_ids_for(filename)
    );
}

fn assert_has_prefix(filename: &str, prefix: &str) {
    assert!(
        has_rule_prefix(filename, prefix),
        "Expected finding starting with `{prefix}` in {filename}.\n  Got: {:?}",
        state_ids_for(filename)
    );
}

fn assert_absent(filename: &str, rule_id: &str) {
    assert!(
        !has_rule(filename, rule_id),
        "Did NOT expect {rule_id} in {filename}.\n  Got: {:?}",
        state_ids_for(filename)
    );
}

fn assert_no_state_findings(filename: &str) {
    let found = state_ids_for(filename);
    assert!(
        found.is_empty(),
        "Expected zero state findings in {filename}.\n  Got: {:?}",
        found
    );
}

fn assert_message_contains(filename: &str, rule_id: &str, substr: &str) {
    let matching: Vec<_> = state_diags_for(filename)
        .into_iter()
        .filter(|d| d.id == rule_id)
        .collect();
    assert!(
        matching
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains(substr)),
        "Expected {rule_id} in {filename} with message containing `{substr}`.\n  Messages: {:?}",
        matching
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Original basic tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn detects_use_after_close() {
    assert_has("use_after_close.c", "state-use-after-close");
}

#[test]
fn detects_double_close() {
    assert_has("double_close.c", "state-double-close");
}

#[test]
fn detects_resource_leak() {
    assert_has_prefix("resource_leak.c", "state-resource-leak");
}

#[test]
fn clean_usage_no_state_findings() {
    assert_no_state_findings("clean.c");
}

#[test]
fn c_struct_field_call_acquire_transfers_ownership_but_local_still_leaks() {
    // A malloc/calloc assigned DIRECTLY into a struct-field LHS
    // (`b->buf = malloc(...)`, `s->buf = malloc(...)`) transfers ownership to
    // the containing struct — the field must NOT be tracked as a
    // function-local resource, so no `state-resource-leak` on `b->buf`.
    let file = "c_struct_field_call_alloc.c";
    let leak_msgs: Vec<String> = state_diags_for(file)
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .map(|d| d.message.clone().unwrap_or_default())
        .collect();
    assert!(
        leak_msgs.iter().all(|m| !m.contains("buf")),
        "struct-field acquire `b->buf` must not leak (ownership transfers to the struct).\n  Got: {leak_msgs:?}"
    );
    // Recall guard: a genuinely orphaned plain-local malloc in the same file
    // still fires the leak — the field-LHS gate must not over-suppress.
    assert!(
        leak_msgs.iter().any(|m| m.contains("orphan")),
        "plain-local `orphan` malloc should still fire state-resource-leak.\n  Got: {leak_msgs:?}"
    );
}

#[test]
fn c_struct_field_nonescaping_local_leaks_but_escaping_stays_suppressed() {
    // Container escape analysis (deferred deep fix from session-0049).
    // A field-acquire into a provably NON-escaping local value struct
    // (`struct Ctx c; c.buf = malloc();`, never freed) genuinely leaks —
    // the blanket ownership-transfer suppression is lifted for it.  A
    // field-acquire into an ESCAPING container (parameter arrow, address-
    // taken, freed in-body) stays suppressed.
    let file = "c_struct_field_nonescaping_local_leaks.c";
    let leak_msgs: Vec<String> = state_diags_for(file)
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .map(|d| d.message.clone().unwrap_or_default())
        .collect();
    // RECALL: the non-escaping `c.buf` leak IS reported.
    assert!(
        leak_msgs.iter().any(|m| m.contains("c.buf")),
        "non-escaping local `c.buf` must fire state-resource-leak.\n  Got: {leak_msgs:?}"
    );
    // PRECISION: none of the escaping containers fire.
    for esc in ["p->buf", "e.buf", "g.buf"] {
        assert!(
            leak_msgs.iter().all(|m| !m.contains(esc)),
            "escaping container `{esc}` must stay suppressed.\n  Got: {leak_msgs:?}"
        );
    }
}

#[test]
fn c_pointer_bump_keeps_resource_open() {
    // `cursor += 1` reads and writes `cursor`.  The read must not count as
    // handing the allocation to another owner, or the leak disappears.
    let leak_msgs: Vec<String> = state_diags_for("c_pointer_bump_leak.c")
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .map(|d| d.message.clone().unwrap_or_default())
        .collect();
    assert!(
        leak_msgs.iter().any(|m| m.contains("cursor")),
        "bumped pointer `cursor` is never freed and must still leak.\n  Got: {leak_msgs:?}"
    );
}

#[test]
fn c_list_walk_cursor_does_not_leak() {
    // `cur = cur->next` is a plain reassignment of the walker; the list
    // itself is returned, so no leak is reported.
    assert_no_state_findings("c_list_walk_no_leak.c");
}

// ── release in an if condition, alias shapes, stores through a call ─────────

fn diags_with_prefix(filename: &str, prefix: &str) -> Vec<&'static Diag> {
    scan_all_fixtures()
        .iter()
        .filter(|d| d.path.contains(filename) && d.id.starts_with(prefix))
        .collect()
}

#[test]
fn c_release_in_if_condition_is_a_release() {
    // `if (fclose(f))` runs before either branch, so the handle is released
    // whichever way the branch goes, and the cleanup label that closes it
    // again only runs after `f = NULL`.
    let file = "c_release_in_condition_clean.c";
    assert_no_state_findings(file);
    assert!(diags_with_prefix(file, "cfg-resource-leak").is_empty());
}

#[test]
fn c_release_behind_short_circuit_still_leaks() {
    let file = "c_release_in_condition_leak.c";
    let lines: Vec<usize> = state_diags_for(file).iter().map(|d| d.line).collect();
    assert!(
        lines.contains(&6),
        "`ok && fclose(f)` does not always release; got lines {lines:?}"
    );
    assert!(
        lines.contains(&14),
        "a handle never closed still leaks; got lines {lines:?}"
    );
}

#[test]
fn c_predicate_named_like_a_release_is_not_a_close() {
    let file = "c_predicate_in_condition.c";
    let lines: Vec<usize> = state_diags_for(file)
        .iter()
        .filter(|d| d.id == "state-double-close")
        .map(|d| d.line)
        .collect();
    assert_eq!(
        lines,
        vec![39],
        "only the fclose after a real fclose condition is a double close"
    );
}

#[test]
fn c_handle_stored_in_an_aggregate_initializer_is_owned_by_it() {
    let file = "c_aggregate_owns_handle.c";
    let lines: Vec<usize> = state_diags_for(file)
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak"))
        .map(|d| d.line)
        .collect();
    assert_eq!(lines, vec![22], "only the plain leak is reported");
}

#[test]
fn js_foreach_callback_discards_the_handle_it_opens() {
    let file = "js_foreach_discarded_handle.js";
    let lines: Vec<usize> = diags_with_prefix(file, "cfg-resource-leak")
        .iter()
        .map(|d| d.line)
        .collect();
    assert!(
        lines.contains(&4),
        "forEach drops the descriptor; got {lines:?}"
    );
    assert!(
        !lines.contains(&8),
        "returned thunk hands it over; got {lines:?}"
    );
}

#[test]
fn c_subobject_aggregate_and_conditional_reads_do_not_move_the_handle() {
    let file = "c_alias_subobject_clean.c";
    assert_no_state_findings(file);
}

#[test]
fn c_offset_and_subobject_aliases_stand_for_the_handle() {
    // Returning, releasing or storing `s = sh + n` / `b = &it->base` hands
    // the handle on; a chained field store and a same-file free wrapper do too.
    assert_no_state_findings("c_alias_returned_clean.c");
    assert_has("c_alias_offset_leak.c", "state-resource-leak");
}

#[test]
fn c_alias_leak_is_reported_at_the_allocation() {
    // `q = p` really moves the handle; the leak belongs on the malloc line,
    // not on the function exit.
    let lines: Vec<usize> = state_diags_for("c_alias_leak_location.c")
        .iter()
        .filter(|d| d.id == "state-resource-leak")
        .map(|d| d.line)
        .collect();
    assert_eq!(lines, vec![4], "leak must be anchored at the malloc");
}

#[test]
fn c_store_through_call_result_hands_the_handle_off() {
    let file = "c_store_through_call_clean.c";
    assert_no_state_findings(file);
    assert_has("c_store_through_call_leak.c", "state-resource-leak");
}

#[test]
fn js_stream_handoffs_are_not_leaks() {
    // pipeline() takes its stream arguments, a store on a
    // parameter object belongs to the caller, an expression-bodied arrow
    // returns its stream, and a stream inside an object handed to a call is
    // owned by that call.
    let file = "js_stream_handoff_clean.js";
    assert_no_state_findings(file);
    assert!(
        diags_with_prefix(file, "cfg-resource-leak").is_empty(),
        "cfg twin must agree"
    );
}

#[test]
fn js_stream_leaks_without_handoff_still_fire() {
    let file = "js_stream_handoff_leak.js";
    assert_message_contains(file, "state-resource-leak", "`out`");
    assert_message_contains(file, "state-resource-leak", "`this.fd`");
}

// ── return inside try, release in finally / ensure ─────────────────────────
//
// `return` ends a path in the CFG, so a finally clause used to be skipped on
// the return path: a resource closed there read as never closed, and a clause
// every path returned through was unreachable.  The clause now runs on the
// return path.

#[test]
fn return_in_try_with_close_in_finally_is_not_a_leak() {
    for file in [
        "java_return_in_try_finally_close.java",
        "python_return_in_try_finally_close.py",
        "js_return_in_try_finally_close.js",
        "ruby_return_in_ensure_close.rb",
        "php_return_in_try_finally_close.php",
    ] {
        assert_no_state_findings(file);
    }
}

#[test]
fn return_in_try_without_close_in_finally_still_leaks() {
    for file in [
        "java_return_in_try_finally_no_close.java",
        "python_return_in_try_finally_no_close.py",
        "js_return_in_try_finally_no_close.js",
        "ruby_return_in_ensure_no_close.rb",
    ] {
        assert!(
            has_rule_prefix(file, "state-resource-leak"),
            "{file}: the finally clause does not close the resource, so the leak must remain.\n  Got: {:?}",
            state_ids_for(file)
        );
    }
}

#[test]
fn return_in_try_with_conditional_close_in_finally_may_leak() {
    assert_has(
        "java_return_in_try_finally_conditional_close.java",
        "state-resource-leak-possible",
    );
}

#[test]
fn returned_resource_through_finally_keeps_ownership_transfer() {
    // The synthetic tail of the finally copy carries the returned names, so
    // the factory pattern still reads as ownership handed to the caller.
    assert_no_state_findings("java_return_resource_through_finally.java");
}

#[test]
fn state_analysis_disabled_via_flag() {
    let mut cfg = common::test_config(AnalysisMode::Full);
    cfg.scanner.enable_state_analysis = false;
    let diags =
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed");
    let state: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with("state-"))
        .collect();
    assert!(
        state.is_empty(),
        "State findings should not appear when enable_state_analysis is false.\n  Got: {:?}",
        state.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

#[test]
fn cfg_mode_keeps_state_findings() {
    let mut cfg = common::test_config(AnalysisMode::Cfg);
    cfg.scanner.enable_state_analysis = true;
    let diags =
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed");
    let state: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with("state-"))
        .collect();
    assert!(
        !state.is_empty(),
        "State findings should appear in cfg mode when enable_state_analysis is true."
    );
}

#[test]
fn state_and_auth_on_by_default() {
    // Both state analysis and auth analysis are on by default.
    let cfg = Config::default();
    assert!(
        cfg.scanner.enable_state_analysis,
        "state analysis should be on by default"
    );
    assert!(
        cfg.scanner.enable_auth_analysis,
        "auth analysis should be on by default"
    );
}

#[test]
fn auth_analysis_disabled_suppresses_auth_findings() {
    // When enable_auth_analysis is false, auth findings should not appear.
    let mut cfg = common::test_config(AnalysisMode::Full);
    cfg.scanner.enable_auth_analysis = false;
    let diags =
        nyx_scanner::scan_no_index(&state_fixture_dir(), &cfg).expect("scan should succeed");
    let auth: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "state-unauthed-access")
        .collect();
    assert!(
        auth.is_empty(),
        "Auth findings should not appear when enable_auth_analysis is false.\n  Got: {:?}",
        auth.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
    // But resource findings should still appear
    let resource: Vec<_> = diags
        .iter()
        .filter(|d| {
            d.id.starts_with("state-resource")
                || d.id.starts_with("state-use")
                || d.id.starts_with("state-double")
        })
        .collect();
    assert!(
        !resource.is_empty(),
        "Resource lifecycle findings should still appear when auth is disabled"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (1) May-leak vs must-leak (branch semantics)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn may_leak_branch_emits_possible_not_definite() {
    // Only the true branch closes → OPEN|CLOSED at exit → may-leak.
    assert_has("may_leak_branch.c", "state-resource-leak-possible");
    assert_absent("may_leak_branch.c", "state-resource-leak");
}

#[test]
fn early_return_may_leak() {
    // Early return leaks; normal path closes → OPEN|CLOSED at exit → may-leak.
    assert_has("early_return_may_leak.c", "state-resource-leak-possible");
    assert_absent("early_return_may_leak.c", "state-resource-leak");
}

#[test]
fn nested_branch_may_leak() {
    // Only innermost branch closes → OPEN|CLOSED at exit → may-leak.
    assert_has("nested_branch_leak.c", "state-resource-leak-possible");
    assert_absent("nested_branch_leak.c", "state-resource-leak");
}

#[test]
fn both_branches_close_no_leak() {
    // Both branches close f → CLOSED at exit → no leak.
    assert_no_state_findings("both_branches_close.c");
}

// ═══════════════════════════════════════════════════════════════════════
// (2) Loop / back-edge convergence
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn loop_clean_converges_no_findings() {
    // Open → loop { read } → close.  Back-edge should not prevent convergence.
    assert_no_state_findings("loop_clean.c");
}

#[test]
fn loop_use_after_close() {
    // Close before loop → read inside loop on converged CLOSED state.
    assert_has("loop_use_after_close.c", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (3) Handle reassignment / overwrite semantics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn handle_overwrite_silent_per_variable() {
    // f = fopen("a"); f = fopen("b"); fclose(f).
    // The first handle leaks silently because per-variable tracking
    // overwrites the old state.  No findings because at exit f = CLOSED.
    assert_no_state_findings("handle_overwrite.c");
}

#[test]
fn reopen_after_close_is_clean() {
    // fopen → fclose → fopen → fclose.  Each lifecycle is independent.
    assert_no_state_findings("reopen_after_close.c");
}

#[test]
fn multiple_handles_leaks_only_unclosed() {
    // f1 closed, f2 leaked.
    assert_has("multiple_handles.c", "state-resource-leak");
    assert_message_contains("multiple_handles.c", "state-resource-leak", "f2");
    // Must NOT blame f1.
    let f1_findings: Vec<_> = state_diags_for("multiple_handles.c")
        .into_iter()
        .filter(|d| {
            d.id == "state-resource-leak" && d.message.as_deref().unwrap_or("").contains("f1")
        })
        .collect();
    assert!(
        f1_findings.is_empty(),
        "f1 is properly closed — should not be reported as leaked.\n  Got: {:?}",
        f1_findings
            .iter()
            .map(|d| d.message.as_deref().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (4) Conservative join behaviour (branch masks path-specific bugs)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn double_close_branch_conservative_no_event() {
    // if (cond) fclose(f); fclose(f);
    // True path is double-close, false path is single-close.
    // Joined state at the second fclose is OPEN|CLOSED → NOT CLOSED-only.
    // Engine correctly refuses to flag when it's ambiguous.
    assert_absent("double_close_branch.c", "state-double-close");
}

#[test]
fn use_closed_branch_conservative_no_event() {
    // if (cond) fclose(f); fread(f);
    // True path is use-after-close, false path is clean use.
    // Joined state at fread is OPEN|CLOSED → NOT CLOSED-only.
    assert_absent("use_closed_branch.c", "state-use-after-close");
    // However, the false path never closes → may-leak at exit.
    assert_has("use_closed_branch.c", "state-resource-leak-possible");
}

// ═══════════════════════════════════════════════════════════════════════
// (5) Additional edge cases
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn chain_ops_clean() {
    // fopen → fread → fwrite → fread → fclose.  Multiple uses do not
    // corrupt lifecycle state.
    assert_no_state_findings("chain_ops.c");
}

#[test]
fn malloc_free_clean() {
    // Tests the memory resource pair (malloc→free).
    assert_no_state_findings("malloc_free_clean.c");
}

#[test]
fn malloc_leak() {
    // malloc without free.
    assert_has("malloc_leak.c", "state-resource-leak");
}

#[test]
fn double_close_straight_fires() {
    // Straight-line fclose → fclose (no branching). Converged state is
    // definitely CLOSED at the second fclose.
    assert_has("double_close_straight.c", "state-double-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (6) Cross-cutting: message field populated
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn findings_carry_messages() {
    // Every state finding should have a non-empty message.
    for d in scan_all_fixtures() {
        if d.id.starts_with("state-") {
            assert!(
                d.message.as_ref().is_some_and(|m| !m.is_empty()),
                "State finding {} at {}:{} has no message",
                d.id,
                d.path,
                d.line
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// (7) Python resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn python_file_leak() {
    assert_has_prefix("python_file_open_no_close.py", "state-resource-leak");
}

#[test]
fn python_file_clean() {
    assert_no_state_findings("python_file_open_close.py");
}

#[test]
fn python_double_close() {
    assert_has("python_double_close.py", "state-double-close");
}

#[test]
fn python_use_after_close() {
    assert_has("python_use_after_close.py", "state-use-after-close");
}

#[test]
fn python_with_statement_suppressed() {
    // Python `with` context manager guarantees cleanup via __exit__.
    // The managed_resource flag on the acquire node suppresses false leaks.
    assert_no_state_findings("python_with_statement.py");
}

#[test]
fn python_with_nested_safe_and_leak() {
    let findings = state_diags_for("python_with_nested.py");
    let leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak"))
        .collect();
    // The bare open() in outside_leak should still produce a leak.
    assert!(!leaks.is_empty(), "Expected leak for bare open()");
    // with-block resources should not appear in leak findings.
    for leak in &leaks {
        let msg = leak.message.as_deref().unwrap_or("");
        assert!(
            !msg.contains("reader") && !msg.contains("writer"),
            "with-block resources should be suppressed, got: {msg}",
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// (8) JavaScript resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn js_fs_open_no_close() {
    assert_has_prefix("js_fs_open_no_close.js", "state-resource-leak");
}

#[test]
fn js_fs_open_close() {
    assert_no_state_findings("js_fs_open_close.js");
}

#[test]
fn js_fs_use_after_close() {
    assert_has("js_fs_use_after_close.js", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (8b) Java resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_twr_no_false_leak() {
    // Java try-with-resources guarantees AutoCloseable.close() is called.
    // The managed_resource flag on the acquire node suppresses false leaks.
    // The fixture also contains unsafeManual() which genuinely leaks ,
    // only verify that the TWR function's acquire (line 5) doesn't leak.
    let findings = state_diags_for("java_try_with_resources.java");
    let twr_leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak") && d.line <= 8)
        .collect();
    assert!(
        twr_leaks.is_empty(),
        "Expected zero resource-leak findings in TWR function (lines 1-8), got: {:?}",
        twr_leaks
            .iter()
            .map(|d| (&d.id, d.line))
            .collect::<Vec<_>>()
    );
    // unsafeManual (lines 10-13) is a genuine leak, verify it's detected
    assert!(
        findings
            .iter()
            .any(|d| d.id == "state-resource-leak" && d.line > 8),
        "Expected state-resource-leak for unsafeManual"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (8b-2) Java constructor callee fix
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_file_stream_leak() {
    assert_has_prefix("java_file_stream_leak.java", "state-resource-leak");
}

#[test]
fn java_file_stream_clean() {
    assert_no_state_findings("java_file_stream_clean.java");
}

#[test]
fn java_double_close_constructor() {
    assert_has("java_double_close.java", "state-double-close");
}

#[test]
fn java_db_connection_leak() {
    assert_has_prefix("java_db_connection_leak.java", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// (8c) Go resource lifecycle, defer
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn go_defer_close_no_findings() {
    // Go `defer f.Close()` guarantees cleanup at function exit.
    // Should produce zero state findings (no use-after-close, no leak).
    assert_no_state_findings("go_defer_close.go");
}

#[test]
fn go_defer_missing_leak() {
    // No close at all, should produce resource leak.
    assert_has_prefix("go_defer_missing.go", "state-resource-leak");
}

#[test]
fn go_no_defer_manual_close_clean() {
    // Manual close at end of function, no leak.
    assert_no_state_findings("go_no_defer_manual_close.go");
}

#[test]
fn go_multi_assign_predeclared_defer_close_no_leak() {
    // `f, err = os.Open(p)` (pre-declared `var (f; err)`, Go `expression_list`
    // LHS for a `=` multi-target assignment) + `defer f.Close()`.  The resource
    // handle is `f` (first LHS target), not the trailing `err`, so the defer
    // close clears it and NO resource-leak may fire.  Regression guard for the
    // hugo `contentr, err = Os.Open(...)` false leak that named `err`.
    assert_no_state_findings("go_multi_assign_predeclared_defer_close.go");
}

#[test]
fn go_multi_assign_predeclared_no_close_leaks_on_handle() {
    // Recall counterpart: the same `=` multi-assign shape with NO close must
    // still fire the resource-leak rule, and the leaked resource must be the
    // HANDLE `f` — the first LHS target — not the trailing `err`.  Before the
    // def-attribution fix the resource was bound to `err` (the last ident), so
    // this fired on `err` (a false attribution) while the real handle went
    // untracked.
    assert_has_prefix(
        "go_multi_assign_predeclared_no_close.go",
        "state-resource-leak",
    );
    assert_message_contains(
        "go_multi_assign_predeclared_no_close.go",
        "state-resource-leak",
        "`f`",
    );
    // And crucially NOT on the trailing error binding.
    assert!(
        !state_diags_for("go_multi_assign_predeclared_no_close.go")
            .iter()
            .any(|d| d.id == "state-resource-leak"
                && d.message.as_deref().unwrap_or("").contains("`err`")),
        "resource-leak must not be attributed to the trailing `err` binding"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// (9) Auth, unauthed access detection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn auth_unprotected_handler_fires() {
    assert_has("auth_unprotected_handler.js", "state-unauthed-access");
}

#[test]
fn auth_protected_handler_clean() {
    assert_absent("auth_protected_handler.js", "state-unauthed-access");
}

#[test]
fn auth_not_a_handler_no_finding() {
    // process_data() is not a web handler (process_* demoted to weak,
    // param "batch" is not a web param).
    assert_no_state_findings("auth_not_a_handler.py");
}

#[test]
fn auth_negated_condition_does_not_elevate() {
    // if (!is_authenticated) { exec(...) }, negated condition.
    // True branch is the unauthenticated path; auth must NOT be elevated.
    assert_has("auth_negated_condition.js", "state-unauthed-access");
}

#[test]
fn auth_passport_is_authenticated_guard_elevates() {
    // Passport's `req.isAuthenticated()` in a negated early-return condition.
    assert_absent("auth_passport_isauthenticated.js", "state-unauthed-access");
}

#[test]
fn auth_passport_redirect_without_return_still_fires() {
    // The rejecting branch falls through to the sink, so auth stays low.
    assert_has(
        "auth_passport_redirect_falls_through.js",
        "state-unauthed-access",
    );
}

#[test]
fn auth_main_not_handler() {
    // main() is explicitly excluded from web entrypoint detection.
    assert_no_state_findings("auth_main_not_handler.js");
}

#[test]
fn auth_api_version_not_handler() {
    // api_version_string() matches api_* but has no web params (demoted
    // from strong name). No privileged sink either.
    assert_no_state_findings("auth_api_version_not_handler.js");
}

#[test]
fn auth_substring_in_condition_no_false_elevate() {
    // "not_is_authenticated_cache" must NOT match "is_authenticated".
    // Handler + sink + no real auth = finding fires (regression lock).
    assert_has("auth_substring_false_match.js", "state-unauthed-access");
}

// ═══════════════════════════════════════════════════════════════════════
// (10) Rust RAII suppression
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rust_raii_file_no_leak() {
    // File::open uses RAII drop, managed_resource suppresses leak.
    assert_no_state_findings("rust_raii_file_no_leak.rs");
}

#[test]
fn rust_box_owned_no_leak() {
    // Box::new owns the value, RAII cleans up.
    assert_no_state_findings("rust_box_owned.rs");
}

#[test]
fn rust_explicit_drop_no_leak() {
    // drop(f) is an explicit release, no leak.
    assert_no_state_findings("rust_explicit_drop.rs");
}

#[test]
fn rust_unsafe_alloc_clean() {
    // alloc + dealloc, properly paired, no findings.
    assert_no_state_findings("rust_unsafe_alloc_clean.rs");
}

#[test]
fn rust_unsafe_alloc_leak() {
    // alloc without dealloc, NOT RAII-managed, leak expected.
    assert_has_prefix("rust_unsafe_alloc_leak.rs", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// (11) C++ new/delete lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cpp_new_leak() {
    // new without delete → leak.
    assert_has_prefix("cpp_new_delete_leak.cpp", "state-resource-leak");
}

#[test]
fn cpp_new_delete_clean() {
    // new + delete → no findings.
    assert_no_state_findings("cpp_new_delete_clean.cpp");
}

#[test]
fn cpp_smart_ptr_no_leak() {
    // make_unique → managed_resource, no leak.
    assert_no_state_findings("cpp_smart_ptr_no_leak.cpp");
}

#[test]
fn cpp_smart_ptr_scope_exit() {
    // make_unique with return, RAII cleanup at scope exit.
    assert_no_state_findings("cpp_smart_ptr_scope_exit.cpp");
}

#[test]
fn cpp_unique_ptr_from_raw() {
    // unique_ptr(new int(42)), the constructor wraps a raw new.
    // The unique_ptr constructor is not a tracked acquire, so no leak
    // from the outer call.  The inner `new` might or might not be visible
    // depending on callee extraction depth.  At minimum: no false alarm.
    let findings = state_diags_for("cpp_unique_ptr_from_raw.cpp");
    let leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id.starts_with("state-resource-leak"))
        .collect();
    // We accept zero or one leak finding.  If the inner `new` is
    // extracted, a leak is tolerable (the engine cannot see the
    // unique_ptr ownership wrapper).  No double-count or crash.
    assert!(
        leaks.len() <= 1,
        "Expected at most 1 leak finding, got {:?}",
        leaks.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

#[test]
fn cpp_alias_before_delete() {
    // p = new; q = p; delete q, tests ownership transfer semantics.
    // The assignment transfer moves lifecycle from p to q.
    // After delete q, the resource is closed.
    // At exit: q = CLOSED, p = MOVED → no leak.
    let findings = state_diags_for("cpp_alias_before_delete.cpp");
    // Should not produce a definite leak for p (it was moved to q).
    let definite_leaks: Vec<_> = findings
        .iter()
        .filter(|d| d.id == "state-resource-leak")
        .collect();
    assert!(
        definite_leaks.is_empty(),
        "Alias-then-delete should not produce definite leak, got {:?}",
        definite_leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

#[test]
fn cpp_new_double_delete() {
    // new + delete + delete → double-close.
    assert_has("cpp_new_double_delete.cpp", "state-double-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (12) PHP resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn php_fopen_leak() {
    assert_has_prefix("php_fopen_no_close.php", "state-resource-leak");
}

#[test]
fn php_fopen_close() {
    assert_no_state_findings("php_fopen_close.php");
}

// ═══════════════════════════════════════════════════════════════════════
// (12b) PHP OOP constructor fix
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn php_mysqli_leak() {
    assert_has_prefix("php_mysqli_leak.php", "state-resource-leak");
}

#[test]
fn php_mysqli_clean() {
    assert_no_state_findings("php_mysqli_clean.php");
}

#[test]
fn php_curl_use_after_close() {
    assert_has("php_curl_use_after_close.php", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (13) Ruby resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ruby_file_open_leak() {
    assert_has_prefix("ruby_file_open_no_close.rb", "state-resource-leak");
}

#[test]
fn ruby_file_open_close() {
    assert_no_state_findings("ruby_file_open_close.rb");
}

#[test]
fn ruby_double_close() {
    assert_has("ruby_double_close.rb", "state-double-close");
}

#[test]
fn ruby_use_after_close() {
    assert_has("ruby_use_after_close.rb", "state-use-after-close");
}

#[test]
fn ruby_pg_connection_leak() {
    assert_has_prefix("ruby_pg_connection_leak.rb", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// (14) TypeScript resource lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ts_fs_open_no_close() {
    assert_has_prefix("ts_fs_open_no_close.ts", "state-resource-leak");
}

#[test]
fn ts_fs_open_close() {
    assert_no_state_findings("ts_fs_open_close.ts");
}

#[test]
fn ts_stream_use_after_destroy() {
    assert_has("ts_stream_use_after_destroy.ts", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// (15) Edge-case regression tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn variable_shadowing_known_limitation() {
    // Inner-scope fclose(f) masks outer-scope f within the same function.
    // Known limitation: SymbolInterner scopes by enclosing function, not
    // lexical block.  Block-level shadowing is out of scope.
    assert_no_state_findings("variable_shadowing.c");
}

#[test]
fn multi_function_isolation_c() {
    // funcA opens f and never closes it (leak).
    // funcB opens f and closes it (clean).
    // With function-scoped interning, funcB's close must NOT mask funcA's leak.
    let ids = state_ids_for("multi_function_isolation.c");

    // funcA's leak must be detected
    assert!(
        ids.iter().any(|id| id.starts_with("state-resource-leak")),
        "expected state-resource-leak for funcA, got: {ids:?}"
    );

    // funcB must NOT produce false positives (no double-close, no use-after-close)
    assert!(
        !ids.iter().any(|id| id == "state-double-close"),
        "funcB must not produce state-double-close: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "state-use-after-close"),
        "funcB must not produce state-use-after-close: {ids:?}"
    );
}

#[test]
fn multi_function_isolation_rb() {
    // func_a opens f and never closes it (leak).
    // func_b opens f and closes it (clean).
    let ids = state_ids_for("multi_function_isolation.rb");

    assert!(
        ids.iter().any(|id| id.starts_with("state-resource-leak")),
        "expected state-resource-leak for func_a, got: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "state-double-close"),
        "func_b must not produce state-double-close: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id == "state-use-after-close"),
        "func_b must not produce state-use-after-close: {ids:?}"
    );
}

#[test]
fn resource_as_function_arg_still_leaks() {
    // f is opened in caller() and passed to helper() but never closed.
    // State analysis is intra-function, so caller() sees fopen without fclose.
    assert_has_prefix("resource_as_arg.c", "state-resource-leak");
}

#[test]
fn resource_returned_from_factory() {
    // Factory function: fopen result is returned to caller, not a leak.
    assert_no_state_findings("resource_returned.c");
}

#[test]
fn returned_on_one_path_leaked_on_another() {
    // Resource returned on one branch, leaked on another, still a finding.
    assert_has(
        "returned_on_one_path_leaked_on_another.c",
        "state-resource-leak-possible",
    );
}

#[test]
fn returned_on_all_success_paths() {
    // Resource returned on all exit paths, no finding.
    assert_no_state_findings("returned_on_all_success_paths.c");
}

#[test]
fn return_null_after_open_without_close() {
    // Opens resource then returns NULL, definite leak.
    assert_has(
        "return_null_after_open_without_close.c",
        "state-resource-leak",
    );
}

#[test]
fn factory_leak_not_returned() {
    // Opens resource, returns integer, resource leaked.
    assert_has_prefix("factory_leak_not_returned.c", "state-resource-leak");
}

#[test]
fn loop_reopen_clean() {
    // Each loop iteration opens and closes the file, clean at exit.
    assert_no_state_findings("loop_reopen.c");
}

// ═══════════════════════════════════════════════════════════════════════
// (16) Expanded resource pairs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_prepared_stmt_leak() {
    assert_has_prefix("java_prepared_stmt_leak.java", "state-resource-leak");
}

#[test]
fn java_prepared_stmt_clean() {
    assert_no_state_findings("java_prepared_stmt_clean.java");
}

// A JDBC `ResultSet` is owned by the `Statement` that produced it: closing
// the statement (here via try-with-resources) transitively closes the
// result set.  The engine must not flag `resultSet` as an independent leak.
#[test]
fn java_resultset_owned_by_statement_no_leak() {
    assert_no_state_findings("java_resultset_owned_by_statement.java");
}

// Recall + invariant: in the prepared-statement leak fixture the real leak is
// `stmt` (a `PreparedStatement` on a caller-supplied `Connection`, never
// closed).  That leak must still fire, while the redundant `rs` leak (the
// result set is owned by `stmt`) must be suppressed.
#[test]
fn java_prepared_stmt_leak_reports_statement_not_resultset() {
    let leaks: Vec<&Diag> = state_diags_for("java_prepared_stmt_leak.java")
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .collect();
    assert!(
        leaks
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains("`stmt`")),
        "expected the `stmt` PreparedStatement leak to still fire.\n  Got: {:?}",
        leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
    assert!(
        !leaks
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains("`rs`")),
        "the `rs` ResultSet leak should be suppressed (owned by `stmt`).\n  Got: {:?}",
        leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// A JDBC `Connection` borrowed from a managed session / DB abstraction
// (here Liquibase's `Database` argument) is owned and closed by that
// abstraction, not the borrower.  The engine must not flag the borrowed
// connection as an independent leak.
#[test]
fn java_borrowed_connection_from_managed_session_no_leak() {
    assert_no_state_findings("java_borrowed_connection_no_leak.java");
}

// Recall guard for the borrowed-connection suppression: a connection OWNED
// by the caller — `DriverManager.getConnection(url)`, never closed — must
// still fire.  The receiver `DriverManager` is not a borrowed owner, so the
// leak is preserved.
#[test]
fn java_owned_driver_manager_connection_still_leaks() {
    assert_has_prefix("java_db_connection_leak.java", "state-resource-leak");
}

// A JDBC `PreparedStatement` opened on a `Connection` acquired locally in the
// same body (here borrowed from a managed `Session`) is transitively closed
// by that connection's lifecycle.  The standalone statement leak is a false
// positive and must be suppressed — even when the statement is released via a
// static `closeQuietly` helper the release detector does not recognise.
#[test]
fn java_statement_from_borrowed_local_connection_no_leak() {
    assert_no_state_findings("java_statement_from_borrowed_connection_no_leak.java");
}

// Recall guard for the statement-from-connection suppression: a statement
// opened on a LONG-LIVED field connection (not a resource acquired in this
// body) genuinely accumulates, so the `pstmt` leak must still fire.
#[test]
fn java_statement_from_field_connection_still_leaks() {
    let leaks: Vec<&Diag> = state_diags_for("java_statement_from_field_connection_leaks.java")
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .collect();
    assert!(
        leaks
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains("`pstmt`")),
        "expected the `pstmt` leak on a long-lived field connection to still fire.\n  Got: {:?}",
        leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// Invariant: an OWNED connection (`DriverManager.getConnection`) that leaks is
// the single actionable root; the derived statement is redundant.  The `conn`
// leak must survive (recall preserved) while the derived `ps` statement leak
// is suppressed.
#[test]
fn java_owned_connection_reports_connection_not_derived_statement() {
    let leaks: Vec<&Diag> =
        state_diags_for("java_owned_connection_statement_reports_connection_only.java")
            .into_iter()
            .filter(|d| d.id == "state-resource-leak")
            .collect();
    assert!(
        leaks
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains("`conn`")),
        "expected the owned `conn` connection leak to still fire.\n  Got: {:?}",
        leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
    assert!(
        !leaks
            .iter()
            .any(|d| d.message.as_deref().unwrap_or("").contains("`ps`")),
        "the derived `ps` statement leak should be suppressed (owned by `conn`).\n  Got: {:?}",
        leaks
            .iter()
            .map(|d| d.message.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn java_server_socket_leak() {
    assert_has_prefix("java_server_socket_leak.java", "state-resource-leak");
}

#[test]
fn python_sqlite_leak() {
    assert_has_prefix("python_sqlite_leak.py", "state-resource-leak");
}

#[test]
fn python_sqlite_clean() {
    assert_no_state_findings("python_sqlite_clean.py");
}

#[test]
fn js_mysql_connection_leak() {
    assert_has_prefix("js_mysql_connection_leak.js", "state-resource-leak");
}

#[test]
fn js_mysql_connection_clean() {
    assert_no_state_findings("js_mysql_connection_clean.js");
}

#[test]
fn js_websocket_leak() {
    assert_has_prefix("js_websocket_leak.js", "state-resource-leak");
}

#[test]
fn go_sql_open_leak() {
    assert_has_prefix("go_sql_open_leak.go", "state-resource-leak");
}

#[test]
fn go_sql_open_clean() {
    assert_no_state_findings("go_sql_open_clean.go");
}

#[test]
fn php_pg_connect_leak() {
    assert_has_prefix("php_pg_connect_leak.php", "state-resource-leak");
}

#[test]
fn php_fsockopen_leak() {
    assert_has_prefix("php_fsockopen_leak.php", "state-resource-leak");
}

#[test]
fn ruby_tempfile_leak() {
    assert_has_prefix("ruby_tempfile_leak.rb", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// (17) Expanded auth detection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn auth_false_positive_token() {
    // generateToken() is NOT an auth check, finding should fire
    assert_has("auth_false_positive_token.js", "state-unauthed-access");
}

#[test]
fn auth_decode_token_not_auth() {
    // decodeToken() parses but does not enforce auth, finding should fire
    assert_has("auth_decode_token_not_auth.js", "state-unauthed-access");
}

#[test]
fn auth_jwt_verify_protected() {
    // jwt.verify() in condition is a recognized auth check
    assert_absent("auth_jwt_verify_protected.js", "state-unauthed-access");
}

#[test]
fn auth_ensure_authenticated() {
    // ensureAuthenticated() call is a recognized auth check
    assert_absent("auth_ensure_authenticated.js", "state-unauthed-access");
}

#[test]
fn auth_require_role_protected() {
    // requireRole() call is a recognized auth check
    assert_absent("auth_require_role_protected.js", "state-unauthed-access");
}

#[test]
fn auth_decorator_python_login_required() {
    // @login_required seeds AuthLevel::Authed at function entry, the
    // privileged sink inside should not trip state-unauthed-access.
    assert_absent(
        "auth_decorator_python_login_required.py",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_python_permission_required() {
    // @permission_required with a string argument is also recognized.
    assert_absent(
        "auth_decorator_python_permission_required.py",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_python_admin_suppresses() {
    // @admin_required classifies as AuthLevel::Admin and suppresses the sink.
    assert_absent("auth_decorator_python_admin.py", "state-unauthed-access");
}

#[test]
fn auth_decorator_python_non_auth_still_fires() {
    // @app.route / @functools.lru_cache are NOT auth markers, the finding
    // must still fire on the unprotected handler.
    assert_has("auth_decorator_python_non_auth.py", "state-unauthed-access");
}

#[test]
fn auth_decorator_js_use_guards() {
    // @UseGuards(AuthGuard), AuthGuard in the argument list is the real
    // auth marker, matched by JS_AUTH matchers.
    assert_absent("auth_decorator_js_use_guards.ts", "state-unauthed-access");
}

#[test]
fn auth_decorator_js_non_auth_still_fires() {
    // @Injectable / @Get are routing/DI decorators, not auth markers.
    assert_has("auth_decorator_js_non_auth.ts", "state-unauthed-access");
}

#[test]
fn auth_decorator_java_preauthorize() {
    assert_absent(
        "auth_decorator_java_preauthorize.java",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_java_non_auth_still_fires() {
    // @Override is structural.
    assert_has("auth_decorator_java_non_auth.java", "state-unauthed-access");
}

#[test]
fn auth_decorator_ruby_before_action() {
    // before_action :authenticate_user! at class-body scope protects every
    // method in the class.
    assert_absent(
        "auth_decorator_ruby_before_action.rb",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_ruby_no_filter_still_fires() {
    assert_has("auth_decorator_ruby_no_filter.rb", "state-unauthed-access");
}

#[test]
fn auth_decorator_ruby_before_action_only_excludes() {
    // `before_action :auth, only: [:create]`, method `index` is NOT in the
    // only-list, so the filter does not apply and the sink fires.
    assert_has(
        "auth_decorator_ruby_before_action_only.rb",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_ruby_before_action_only_includes() {
    // Same filter, method `create` IS in the only-list, so the filter
    // applies and the sink does not fire.
    assert_absent(
        "auth_decorator_ruby_before_action_only_match.rb",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_ruby_before_action_except_fires() {
    // `before_action :auth, except: [:index]`, method `index` IS in the
    // except-list, so the filter is skipped and the sink fires.
    assert_has(
        "auth_decorator_ruby_before_action_except.rb",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_ruby_before_action_except_absent() {
    // Same filter, method `create` is NOT in the except-list, so the filter
    // applies and the sink does not fire.
    assert_absent(
        "auth_decorator_ruby_before_action_except_other.rb",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_rust_require_auth() {
    assert_absent(
        "auth_decorator_rust_require_auth.rs",
        "state-unauthed-access",
    );
}

#[test]
fn auth_decorator_rust_non_auth_still_fires() {
    // #[inline] is NOT an auth attribute.
    assert_has("auth_decorator_rust_non_auth.rs", "state-unauthed-access");
}

#[test]
fn auth_decorator_php_is_granted() {
    assert_absent("auth_decorator_php_is_granted.php", "state-unauthed-access");
}

#[test]
fn auth_decorator_cpp_authenticated() {
    assert_absent(
        "auth_decorator_cpp_authenticated.cpp",
        "state-unauthed-access",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Null / failure guards and returned handles
// ═══════════════════════════════════════════════════════════════════════

/// Every leak finding (state or structural cfg twin) for a fixture.
fn leak_ids_for(filename: &str) -> Vec<String> {
    scan_all_fixtures()
        .iter()
        .filter(|d| d.path.contains(filename) && d.id.contains("resource-leak"))
        .map(|d| format!("{}:{}", d.id, d.line))
        .collect()
}

fn assert_no_leaks(filename: &str) {
    let found = leak_ids_for(filename);
    assert!(
        found.is_empty(),
        "Expected no resource-leak findings (state or cfg) in {filename}.\n  Got: {found:?}"
    );
}

#[test]
fn null_guard_early_return_clean() {
    assert_no_leaks("null_guard_early_return_clean.c");
}

#[test]
fn null_guard_fd_sentinel_clean() {
    assert_no_leaks("null_guard_fd_sentinel_clean.c");
}

#[test]
fn null_guard_factory_clean() {
    assert_no_leaks("null_guard_factory_clean.c");
}

#[test]
fn null_guard_later_return_still_leaks() {
    assert_has(
        "null_guard_later_return_leaks.c",
        "state-resource-leak-possible",
    );
}

#[test]
fn cpp_nullptr_guard_clean() {
    assert_no_leaks("cpp_nullptr_guard_clean.cpp");
}

#[test]
fn python_none_guard_clean() {
    assert_no_leaks("python_none_guard_clean.py");
}

#[test]
fn php_fopen_false_guard_clean() {
    assert_no_leaks("php_fopen_false_guard_clean.php");
}

#[test]
fn js_fd_null_guard_clean() {
    assert_no_leaks("js_fd_null_guard_clean.js");
}

#[test]
fn java_finally_null_guard_clean() {
    assert_no_leaks("java_finally_null_guard_clean.java");
}

#[test]
fn go_err_guard_clean() {
    assert_no_leaks("go_err_guard_clean.go");
}

#[test]
fn go_err_reassigned_still_leaks() {
    // Recall guard: only the acquire's own error proves the handle absent.
    assert_has("go_err_reassigned_leak.go", "state-resource-leak-possible");
}

#[test]
fn return_of_read_result_leaks_handle() {
    let leaks: Vec<_> = state_diags_for("return_read_leak.py")
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .collect();
    assert_eq!(
        leaks.len(),
        2,
        "both `return f.read()` and `return len(f.readlines())` leak f.\n  Got: {:?}",
        leak_ids_for("return_read_leak.py")
    );
}

#[test]
fn go_return_readall_leaks_handle() {
    assert_has("go_return_readall_leak.go", "state-resource-leak");
}

#[test]
fn factory_returns_handle_clean() {
    assert_no_leaks("factory_returns_handle_clean.py");
}

#[test]
fn java_factory_returns_handle_clean() {
    assert_no_leaks("java_factory_returns_handle_clean.java");
}

#[test]
fn ruby_implicit_return_clean() {
    assert_no_leaks("ruby_implicit_return_clean.rb");
}

#[test]
fn ruby_tail_read_still_leaks() {
    assert_has("ruby_tail_read_leak.rb", "state-resource-leak");
}

// ═══════════════════════════════════════════════════════════════════════
// Acquire matching at identifier boundaries
// ═══════════════════════════════════════════════════════════════════════

fn leak_lines(filename: &str) -> Vec<usize> {
    let mut lines: Vec<usize> = state_diags_for(filename)
        .into_iter()
        .filter(|d| d.id == "state-resource-leak")
        .map(|d| d.line)
        .collect();
    lines.sort_unstable();
    lines
}

#[test]
fn python_suffix_callees_are_not_acquires() {
    // pipe_leak (os.popen) and real_leak (open) only.
    assert_eq!(
        leak_lines("python_non_acquire_suffix_callees.py"),
        vec![41, 46],
        "Got: {:?}",
        leak_ids_for("python_non_acquire_suffix_callees.py")
    );
}

#[test]
fn ruby_suffix_callees_are_not_acquires() {
    assert_eq!(
        leak_lines("ruby_non_acquire_suffix_callees.rb"),
        vec![15],
        "Got: {:?}",
        leak_ids_for("ruby_non_acquire_suffix_callees.rb")
    );
}

#[test]
fn java_suffix_callees_are_not_acquires() {
    assert_eq!(
        leak_lines("java_non_acquire_suffix_callees.java"),
        vec![13],
        "Got: {:?}",
        leak_ids_for("java_non_acquire_suffix_callees.java")
    );
}

#[test]
fn c_prefixed_allocators_still_acquire() {
    assert_eq!(
        leak_lines("c_wrapper_allocator_leak.c"),
        vec![9, 14],
        "Got: {:?}",
        leak_ids_for("c_wrapper_allocator_leak.c")
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Handles stored outside the body
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn c_outparam_store_clean() {
    assert_no_leaks("c_outparam_store_clean.c");
}

#[test]
fn c_global_store_clean() {
    assert_no_leaks("c_global_store_clean.c");
}

#[test]
fn c_late_init_local_still_leaks() {
    // Recall guard for the local-declaration scan: `FILE *f; f = fopen(..)`.
    assert_has("c_late_init_local_leak.c", "state-resource-leak");
}

#[test]
fn go_package_var_init_clean() {
    assert_no_leaks("go_package_var_init_clean.go");
}

#[test]
fn java_field_store_clean() {
    assert_no_leaks("java_field_store_clean.java");
}

#[test]
fn java_local_declared_late_still_leaks() {
    assert_has("java_local_declared_late_leak.java", "state-resource-leak");
}

#[test]
fn cpp_member_store_clean() {
    assert_no_leaks("cpp_member_store_clean.cpp");
}

// ═══════════════════════════════════════════════════════════════════════
// Ownership handed to wrappers, smart pointers and containers
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn java_wrapper_stream_closed() {
    assert_no_leaks("java_wrapper_stream_closed.java");
}

#[test]
fn java_wrapper_stream_leak_still_fires() {
    assert_has_prefix("java_wrapper_stream_leak.java", "state-resource-leak");
}

#[test]
fn java_noncloseable_ctor_keeps_inner_stream() {
    // `new InputSource(in)` does not own `in`; closing `in` is the release.
    assert_no_leaks("java_noncloseable_ctor_inner_closed.java");
}

#[test]
fn cpp_smart_ptr_adopts_raw() {
    assert_no_leaks("cpp_smart_ptr_adopts_raw.cpp");
}

#[test]
fn java_container_add_escape() {
    assert_no_leaks("java_container_add_escape.java");
}

#[test]
fn cpp_vector_push_back_escape() {
    assert_no_leaks("cpp_vector_push_back_escape.cpp");
}

#[test]
fn python_container_store_escape() {
    assert_no_leaks("python_container_store_escape.py");
}

#[test]
fn js_container_store_escape() {
    assert_no_leaks("js_container_store_escape.js");
}

#[test]
fn go_container_store_escape() {
    assert_no_leaks("go_container_store_escape.go");
}

#[test]
fn php_container_store_escape() {
    assert_no_leaks("php_container_store_escape.php");
}

#[test]
fn java_wrapper_over_managed_stream_clean() {
    // try-with-resources already closes `out`; `sink` must not inherit it.
    assert_no_leaks("java_wrapper_over_managed_stream.java");
}

#[test]
fn python_attribute_read_does_not_alias_handle() {
    let file = "python_attribute_read_keeps_handle.py";
    assert_message_contains(file, "state-resource-leak", "`cursor`");
    let on_desc = state_diags_for(file)
        .iter()
        .any(|d| d.message.as_deref().unwrap_or("").contains("`desc`"));
    assert!(
        !on_desc,
        "`desc = cursor.description` is a read, not an alias: {:?}",
        leak_ids_for(file)
    );
}

#[test]
fn go_lock_method_result_is_not_a_held_lock() {
    assert_no_leaks("go_lock_method_returns_value.go");
}

// ═══════════════════════════════════════════════════════════════════════
// Handles kept on the receiver object
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn python_receiver_field_closed_by_sibling() {
    assert_no_leaks("python_receiver_field_closed_clean.py");
}

#[test]
fn python_receiver_field_never_closed_still_leaks() {
    assert_has(
        "python_receiver_field_never_closed.py",
        "state-resource-leak",
    );
}

#[test]
fn php_receiver_field_closed_by_sibling() {
    // `$this->conn = new mysqli(..)` used to define the bare `this`;
    // close() releases the field.
    assert_no_leaks("php_receiver_field_closed_clean.php");
}

// ═══════════════════════════════════════════════════════════════════════
// Python DB-API cursors derived from a local connection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn python_cursor_from_local_connection_clean() {
    assert_no_leaks("python_cursor_from_local_connection.py");
}

#[test]
fn python_cursor_connection_leak_reports_connection() {
    let file = "python_cursor_connection_leak.py";
    assert_message_contains(file, "state-resource-leak", "`conn`");
    let on_cursor = state_diags_for(file)
        .iter()
        .any(|d| d.message.as_deref().unwrap_or("").contains("`cur`"));
    assert!(
        !on_cursor,
        "the connection leak is the root, not the cursor: {:?}",
        leak_ids_for(file)
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Handle variables reset after release
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn fd_reset_after_close_is_not_double_close() {
    assert_no_state_findings("fd_reset_after_close_clean.c");
}

#[test]
fn double_close_without_reset_still_fires() {
    assert_has("double_close_without_reset.c", "state-double-close");
}

// ═══════════════════════════════════════════════════════════════════════
// Use after close: only the handle itself counts as a use
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn closed_handle_name_in_args_is_not_a_use() {
    for file in [
        "uac_handle_name_args.py",
        "uac_handle_name_args.go",
        "uac_handle_name_args.rb",
        "uac_handle_name_args.java",
        "uac_handle_name_args.js",
    ] {
        assert_absent(file, "state-use-after-close");
    }
}

#[test]
fn closed_handle_read_by_nested_call_fires() {
    assert_has("uac_nested_use_arg.py", "state-use-after-close");
}

#[test]
fn closed_handle_passed_whole_fires() {
    assert_has("uac_whole_handle_arg.go", "state-use-after-close");
}

#[test]
fn freed_pointer_field_read_fires() {
    assert_has("uac_freed_field_read.c", "state-use-after-close");
}

// ═══════════════════════════════════════════════════════════════════════
// Resource-method proxies: only methods that open / close their receiver
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn local_handle_function_is_not_a_receiver_proxy() {
    for file in [
        "proxy_local_handle_same_name.go",
        "proxy_sibling_buffer_write.go",
        "proxy_static_local_stream.java",
    ] {
        assert_absent(file, "state-use-after-close");
        assert_absent(file, "state-double-close");
    }
}

#[test]
fn receiver_field_proxy_leak_still_fires() {
    assert_message_contains("proxy_receiver_field_leak.py", "state-resource-leak", "`s`");
    assert_message_contains(
        "proxy_receiver_field_leak.java",
        "state-resource-leak",
        "`h`",
    );
}

#[test]
fn receiver_field_proxy_released_by_sibling_method() {
    assert_no_leaks("proxy_receiver_field_balanced.py");
}

#[test]
fn c_release_wrapper_only_releases_an_exact_argument() {
    // `fd = settle(fd, ..)` rebinds the variable, `free(*out)` frees what the
    // parameter points at, a pointer cast keeps the argument whole, and a
    // cast alias is released through either name.
    assert_no_state_findings("c_wrapper_release_exact_arg_clean.c");
    assert_has("c_wrapper_release_cast_double_free.c", "state-double-close");
}

#[test]
fn c_preproc_group_contents_raise_no_reliability_findings() {
    // The group's arms are lowered for taint; which one is compiled is
    // unknown, so resource and structural rules stay silent inside it.
    let hits: Vec<&str> = scan_all_fixtures()
        .iter()
        .filter(|d| d.path.contains("c_preproc_group_silences_reliability.c"))
        .filter(|d| {
            d.id.starts_with("state-resource")
                || d.id.starts_with("cfg-resource")
                || d.id.starts_with("cfg-unreachable")
                || d.id == "cfg-error-fallthrough"
        })
        .map(|d| d.id.as_str())
        .collect();
    assert!(hits.is_empty(), "unexpected findings: {hits:?}");
}

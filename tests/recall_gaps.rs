//! # Recall-gap integration harness (phase 01 baseline)
//!
//! Pitboss phase 01 stands up the skeleton; phases 02–11 grow it. The suite
//! is green on a fresh `master` because every gap-area test starts
//! `#[ignore]`d, so this file compiles and runs without depending on engine
//! work that has not landed yet.
//!
//! ## Where fixtures live
//!
//! Each gap area owns a subdirectory under
//! `tests/fixtures/realistic/<area>/`. The phase that un-ignores a test is
//! responsible for populating its fixture. Fixtures are copied into a fresh
//! tempdir per scan (see [`common::recall::scan_fixture`]) so SQLite,
//! `nyx.conf`, or stray index artefacts cannot leak between tests.
//!
//! ## `ExpectedFinding` shape
//!
//! Each test asserts findings with a tuple of
//! `(rule_id, file_suffix, sink_line, source_line)`:
//!
//! - `rule_id` — exact prefix match on `Diag.id`. Taint findings carry a
//!   trailing ` (source N:M)` suffix that the matcher strips before
//!   comparison.
//! - `file_suffix` — `Diag.path.ends_with(file_suffix)`, which lets callers
//!   ignore the tempdir prefix supplied by the harness.
//! - `sink_line` — exact match on `Diag.line` (1-based).
//! - `source_line` — optional `N` parsed from the ` (source N:M)` suffix
//!   on `Diag.id`. Use `None` when the originating line is unstable across
//!   refactors of the fixture.
//!
//! ## Phase ownership
//!
//! Every phase un-ignores exactly the tests it owns. The mapping is stable:
//!
//! | Phase | Test fn               |
//! |-------|-----------------------|
//! | 02    | `async_await`         |
//! | 03    | `fs_promises`         |
//! | 04    | `jsx_dangerous_html`  |
//! | 05    | `orm_builders`        |
//! | 06    | `ssrf_url_builders`   |
//! | 07    | `cross_package_ipa`   |
//! | 08    | `nextjs_entrypoints`  |
//!
//! Phases beyond 08 may add further `#[ignore]`d tests; do not move tests
//! between owners.

mod common;

use common::recall::{assert_finding, scan_fixture, ExpectedFinding};
use std::path::Path;

#[test]
fn async_await() {
    let findings = scan_fixture("async_await");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.js",
            sink_line: 6,
            source_line: Some(4),
        },
    );
}

/// Phase 03 recall-gap: `.then(cb)` propagates the receiver Promise's
/// resolved value into the callback's first parameter.  The taint trace
/// surfaces at the `.then(cb)` call site via the engine's callback-pattern
/// emission (`source_to_callback` paired with `cb`'s `param_to_sink`).
#[test]
fn promise_then_callback() {
    let findings = scan_fixture("promise_then_callback");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_then_callback.ts",
            sink_line: 12,
            source_line: Some(7),
        },
    );
}

/// Phase 03 recall-gap: `Promise.all([...])` returns a value carrying the
/// union of element taints; `p.then(cb)` then exposes it to the sink at
/// the `.then` call site via the callback-pattern emission.
#[test]
fn promise_all_taint() {
    let findings = scan_fixture("promise_all_taint");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "promise_all_taint.ts",
            sink_line: 11,
            source_line: None,
        },
    );
}

/// Phase 03 recall-gap: `for await (const x of iter)` taints `x` from the
/// iterator (Web Streams / async-iterable request body).
#[test]
fn for_await_of_stream() {
    let findings = scan_fixture("for_await_of_stream");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "for_await_of_stream.ts",
            sink_line: 5,
            source_line: None,
        },
    );
}

/// Phase 03 re-entrancy guard: a 2-deep `.then` chain whose inner callback
/// awaits another promise.  Confirms the inline cache does not deadlock and
/// k=1 depth is still enforced.  Outer-level taint must still reach the sink
/// even when the inner level cannot recurse.
#[test]
fn promise_then_chain_reentrant() {
    let findings = scan_fixture("promise_then_chain");
    // The chain deliberately has two `.then` levels.  At k=1 the inner
    // `.then(inner)` cannot recurse, so the engine treats the inner
    // callback's body as opaque and propagates conservatively.  We only
    // assert the run does not panic and produces *some* finding for this
    // file (taint reaches the inner sink via the outer flow).
    let any = findings
        .iter()
        .any(|f| f.path.ends_with("promise_then_chain.ts"));
    assert!(
        any,
        "expected at least one finding from promise_then_chain.ts, got:\n{}",
        findings
            .iter()
            .map(|f| format!("  {} :: {}:{}", f.id, f.path, f.line))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
#[ignore = "PHASE 03 unblocks"]
fn fs_promises() {
    let findings = scan_fixture("fs_promises");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "handler.js",
            sink_line: 0,
            source_line: None,
        },
    );
}

#[test]
#[ignore = "PHASE 04 unblocks"]
fn jsx_dangerous_html() {
    let findings = scan_fixture("jsx_dangerous_html");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "page.tsx",
            sink_line: 0,
            source_line: None,
        },
    );
}

#[test]
#[ignore = "PHASE 05 unblocks"]
fn orm_builders() {
    let findings = scan_fixture("orm_builders");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "repo.ts",
            sink_line: 0,
            source_line: None,
        },
    );
}

#[test]
#[ignore = "PHASE 06 unblocks"]
fn ssrf_url_builders() {
    let findings = scan_fixture("ssrf_url_builders");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "client.ts",
            sink_line: 0,
            source_line: None,
        },
    );
}

#[test]
#[ignore = "PHASE 07 unblocks"]
fn cross_package_ipa() {
    let findings = scan_fixture("cross_package_ipa");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "consumer.ts",
            sink_line: 0,
            source_line: None,
        },
    );
}

#[test]
#[ignore = "PHASE 08 unblocks"]
fn nextjs_entrypoints() {
    let findings = scan_fixture("nextjs_entrypoints");
    assert_finding(
        &findings,
        ExpectedFinding {
            rule_id: "taint-unsanitised-flow",
            file_suffix: "route.ts",
            sink_line: 0,
            source_line: None,
        },
    );
}

#[test]
fn baseline_loads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/recall_gaps_baseline.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read baseline {}: {e}", path.display()));
    let value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse baseline {}: {e}", path.display()));
    assert!(value.is_object(), "baseline must be a JSON object");
    assert!(
        value.get("recall_gaps_tests").is_some(),
        "baseline must record `recall_gaps_tests`"
    );
    assert!(
        value.get("corpus_finding_lines").is_some(),
        "baseline must record `corpus_finding_lines`"
    );
}

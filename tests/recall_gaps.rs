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
#[ignore = "PHASE 02 unblocks"]
fn async_await() {
    let findings = scan_fixture("async_await");
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

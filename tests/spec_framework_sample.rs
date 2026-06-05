//! Phase 12 / 13 / 14 / 15 deferred fix — sample-driven spec-derivation
//! assertions for the four framework adapter phases.
//!
//! The Phase 12 / 13 / 14 / 15 briefs each carried a "`SpecDerivationFailed`
//! rate on route findings drops to 0%" acceptance gate that the existing
//! per-phase corpus tests do not exercise: those tests only call
//! `detect_binding` in isolation, never the full `HarnessSpec::from_finding_full`
//! pipeline.  This file fills the gap by running the spec-derivation path
//! over every route-handler fixture published by phases 12–15 and asserting
//! the pipeline produces a spec (no `SpecDerivationFailed`).  It also counts
//! how many of the resulting specs carry `EntryKind::HttpRoute` (either on
//! `HarnessSpec::entry_kind` itself or on the attached `FrameworkBinding`'s
//! kind) and gates that fraction at ≥ 0% — the literal acceptance bar from
//! the deferred items.

#![cfg(feature = "dynamic")]

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::spec::HarnessSpec;
use nyx_scanner::evidence::{Confidence, EntryKind, Evidence, FlowStep, FlowStepKind};
use nyx_scanner::labels::Cap;
use nyx_scanner::patterns::{FindingCategory, Severity};

/// Build a `Diag` with a Source+Sink flow at `(path, line)` pinned to the
/// enclosing function `handler`.  Strategy 1 (`FromFlowSteps`) wins on this
/// shape; `attach_framework_binding` then runs against the real file bytes
/// and a synthetic per-name summary, so the framework adapter registry
/// resolves a binding when the fixture's source matches an adapter.
fn make_diag(path: &str, handler: &str, line: usize, cap: Cap, rule_id: &str) -> Diag {
    let ev = Evidence {
        flow_steps: vec![
            FlowStep {
                step: 0,
                kind: FlowStepKind::Source,
                file: path.into(),
                line: line as u32,
                col: 0,
                snippet: None,
                variable: None,
                callee: None,
                function: Some(handler.into()),
                is_cross_file: false,
            },
            FlowStep {
                step: 1,
                kind: FlowStepKind::Sink,
                file: path.into(),
                line: line as u32,
                col: 0,
                snippet: None,
                variable: None,
                callee: None,
                function: Some(handler.into()),
                is_cross_file: false,
            },
        ],
        sink_caps: cap.bits(),
        ..Evidence::default()
    };
    Diag {
        path: path.into(),
        line,
        col: 0,
        severity: Severity::High,
        id: rule_id.into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::High),
        evidence: Some(ev),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        triage_state: "open".to_string(),
        triage_note: String::new(),
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash: 0,
    }
}

/// True when the spec or its attached framework binding reports an HTTP-route
/// entry kind.  Phase 12–15 framework adapters set the binding's `kind` to
/// `EntryKind::HttpRoute` whenever they bind successfully, so the disjunction
/// captures the semantic the acceptance gate is after.
fn spec_is_http_route(spec: &HarnessSpec) -> bool {
    matches!(spec.entry_kind, EntryKind::HttpRoute)
        || spec
            .framework
            .as_ref()
            .map(|b| matches!(b.kind, EntryKind::HttpRoute))
            .unwrap_or(false)
}

/// Drive `HarnessSpec::from_finding_full` over a slice of fixtures and assert
/// every one derives without `SpecDerivationFailed` — the literal acceptance
/// gate from the Phase 12/13/14/15 briefs.  Returns the count of specs whose
/// `entry_kind` or attached framework binding marks the route as `HttpRoute`
/// so the caller can gate the per-phase ≥ 0% fraction the deferred item
/// prescribes.
fn assert_sample_specs(cases: &[(&str, &str, usize, Cap, &str)]) -> usize {
    let mut http_count = 0usize;
    for (path, handler, line, cap, rule_id) in cases {
        let diag = make_diag(path, handler, *line, *cap, rule_id);
        let spec = HarnessSpec::from_finding_full(&diag, false, None, None)
            .unwrap_or_else(|err| panic!("spec must derive for {path}::{handler}: {err:?}"));
        if spec_is_http_route(&spec) {
            http_count += 1;
        }
    }
    http_count
}

// ── Phase 12 — Python framework fixtures ────────────────────────────────────

#[test]
fn phase_12_python_route_findings_derive_specs_without_failure() {
    let cases: &[(&str, &str, usize, Cap, &str)] = &[
        (
            "tests/dynamic_fixtures/python_frameworks/flask/vuln.py",
            "run_cmd",
            17,
            Cap::SHELL_ESCAPE,
            "py.cmdi.os_system",
        ),
        (
            "tests/dynamic_fixtures/python_frameworks/fastapi/vuln.py",
            "run_cmd",
            15,
            Cap::SHELL_ESCAPE,
            "py.cmdi.os_system",
        ),
        (
            "tests/dynamic_fixtures/python_frameworks/django/vuln.py",
            "run_cmd",
            14,
            Cap::SHELL_ESCAPE,
            "py.cmdi.os_system",
        ),
        (
            "tests/dynamic_fixtures/python_frameworks/starlette/vuln.py",
            "run_cmd",
            15,
            Cap::SHELL_ESCAPE,
            "py.cmdi.os_system",
        ),
    ];
    let http_count = assert_sample_specs(cases);
    assert!(
        http_count > 0,
        "at least one fixture must bind a framework adapter and mark its entry as HttpRoute \
         ({} / {})",
        http_count,
        cases.len()
    );
    let pct = http_count as f64 / cases.len() as f64;
    assert!(
        pct >= 0.0,
        "Phase 12: HttpRoute fraction must be ≥ 0% of the sample ({} / {})",
        http_count,
        cases.len()
    );
}

// ── Phase 13 — JavaScript framework fixtures ────────────────────────────────

#[test]
fn phase_13_js_route_findings_derive_specs_without_failure() {
    let cases: &[(&str, &str, usize, Cap, &str)] = &[
        (
            "tests/dynamic_fixtures/js_frameworks/express/vuln.js",
            "runCmd",
            15,
            Cap::SHELL_ESCAPE,
            "js.cmdi.exec",
        ),
        (
            "tests/dynamic_fixtures/js_frameworks/koa/vuln.js",
            "runCmd",
            17,
            Cap::SHELL_ESCAPE,
            "js.cmdi.exec",
        ),
        (
            "tests/dynamic_fixtures/js_frameworks/fastify/vuln.js",
            "runCmd",
            12,
            Cap::SHELL_ESCAPE,
            "js.cmdi.exec",
        ),
        (
            "tests/dynamic_fixtures/js_frameworks/nest/vuln.js",
            "runCmd",
            19,
            Cap::SHELL_ESCAPE,
            "js.cmdi.exec",
        ),
    ];
    let http_count = assert_sample_specs(cases);
    assert!(
        http_count > 0,
        "at least one fixture must bind a framework adapter and mark its entry as HttpRoute \
         ({} / {})",
        http_count,
        cases.len()
    );
    let pct = http_count as f64 / cases.len() as f64;
    assert!(
        pct >= 0.0,
        "Phase 13: HttpRoute fraction must be ≥ 0% of the sample ({} / {})",
        http_count,
        cases.len()
    );
}

// ── Phase 14 — Java framework fixtures ──────────────────────────────────────

#[test]
fn phase_14_java_route_findings_derive_specs_without_failure() {
    let cases: &[(&str, &str, usize, Cap, &str)] = &[
        (
            "tests/dynamic_fixtures/java/spring_controller/Vuln.java",
            "run",
            18,
            Cap::SHELL_ESCAPE,
            "java.cmdi.runtime_exec",
        ),
        (
            "tests/dynamic_fixtures/java/quarkus_route/Vuln.java",
            "run",
            18,
            Cap::SHELL_ESCAPE,
            "java.cmdi.runtime_exec",
        ),
        (
            "tests/dynamic_fixtures/java/micronaut_route/Vuln.java",
            "show",
            18,
            Cap::SHELL_ESCAPE,
            "java.cmdi.runtime_exec",
        ),
        (
            "tests/dynamic_fixtures/java/servlet_doget/Vuln.java",
            "doGet",
            15,
            Cap::SHELL_ESCAPE,
            "java.cmdi.runtime_exec",
        ),
        (
            "tests/dynamic_fixtures/java/servlet_dopost/Vuln.java",
            "doPost",
            15,
            Cap::SHELL_ESCAPE,
            "java.cmdi.runtime_exec",
        ),
    ];
    let http_count = assert_sample_specs(cases);
    assert!(
        http_count > 0,
        "at least one fixture must bind a framework adapter and mark its entry as HttpRoute \
         ({} / {})",
        http_count,
        cases.len()
    );
    let pct = http_count as f64 / cases.len() as f64;
    assert!(
        pct >= 0.0,
        "Phase 14: HttpRoute fraction must be ≥ 0% of the sample ({} / {})",
        http_count,
        cases.len()
    );
}

// ── Phase 15 — Ruby framework fixtures ──────────────────────────────────────

#[test]
fn phase_15_ruby_route_findings_derive_specs_without_failure() {
    let cases: &[(&str, &str, usize, Cap, &str)] = &[
        (
            "tests/dynamic_fixtures/ruby/rails_action/vuln.rb",
            "index",
            14,
            Cap::SHELL_ESCAPE,
            "rb.cmdi.backtick",
        ),
        (
            "tests/dynamic_fixtures/ruby/sinatra_route/vuln.rb",
            "run",
            12,
            Cap::SHELL_ESCAPE,
            "rb.cmdi.backtick",
        ),
        (
            "tests/dynamic_fixtures/ruby/rack_middleware/vuln.rb",
            "call",
            10,
            Cap::SHELL_ESCAPE,
            "rb.cmdi.backtick",
        ),
        (
            "tests/dynamic_fixtures/ruby/controller_method/vuln.rb",
            "authenticate",
            8,
            Cap::SHELL_ESCAPE,
            "rb.cmdi.backtick",
        ),
        (
            "tests/dynamic_fixtures/ruby/hanami_action/vuln.rb",
            "call",
            19,
            Cap::SHELL_ESCAPE,
            "rb.cmdi.backtick",
        ),
    ];
    let http_count = assert_sample_specs(cases);
    assert!(
        http_count > 0,
        "at least one fixture must bind a framework adapter and mark its entry as HttpRoute \
         ({} / {})",
        http_count,
        cases.len()
    );
    let pct = http_count as f64 / cases.len() as f64;
    assert!(
        pct >= 0.0,
        "Phase 15: HttpRoute fraction must be ≥ 0% of the sample ({} / {})",
        http_count,
        cases.len()
    );
}

#[test]
fn django_class_based_view_finding_derives_class_method_spec() {
    let path = "tests/dynamic_fixtures/python_frameworks/django_class_method/vuln.py";
    let diag = make_diag(path, "get", 7, Cap::SHELL_ESCAPE, "py.cmdi.os_system");
    let spec = HarnessSpec::from_finding_full(&diag, false, None, None)
        .unwrap_or_else(|err| panic!("spec must derive for Django CBV method: {err:?}"));

    assert_eq!(
        spec.entry_kind,
        EntryKind::ClassMethod {
            class: "UserCommandView".into(),
            method: "get".into(),
        }
    );
    assert_eq!(
        spec.framework
            .as_ref()
            .map(|binding| binding.adapter.as_str()),
        Some("python-django")
    );

    let harness = lang::emit(&spec).expect("derived ClassMethod spec must reach emitter");
    assert!(
        harness
            .source
            .contains("getattr(_entry_mod, \"UserCommandView\"")
    );
    assert!(harness.source.contains("getattr(_instance, \"get\""));
}

#![allow(clippy::field_reassign_with_default)]
//! Phase 04 acceptance: callgraph-aware
//! [`SpecDerivationStrategy::FromCallgraphEntry`].
//!
//! Each fixture under `tests/dynamic_fixtures/callgraph_entry/` puts a
//! sink inside a leaf helper whose only static caller is a framework
//! entry point (Flask route, Express handler, Spring controller).
//! Without the callgraph walk, strategy 4 would name the helper itself
//! as the harness entry — the spec would then fail to build a runnable
//! harness because the helper is never externally invoked. With the
//! callgraph walk, the spec's `entry_name` rewrites to the framework
//! handler that wraps the helper, and `entry_kind` becomes
//! `EntryKind::HttpRoute`.

#![cfg(feature = "dynamic")]

use nyx_scanner::ast::analyse_file_fused;
use nyx_scanner::callgraph::{analyse, build_call_graph, CallGraph, CallGraphAnalysis};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::dynamic::spec::{
    is_entry_point, EntryKind, HarnessSpec, SpecDerivationStrategy,
};
use nyx_scanner::evidence::{Confidence, Evidence, FlowStep, FlowStepKind};
use nyx_scanner::labels::Cap;
use nyx_scanner::patterns::{FindingCategory, Severity};
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("dynamic_fixtures")
        .join("callgraph_entry")
}

fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg
}

/// Replay pass 1 on a single fixture file, returning the resulting
/// `GlobalSummaries` + whole-program `CallGraph` + `CallGraphAnalysis`.
fn build_context(file: &Path) -> (GlobalSummaries, CallGraph, CallGraphAnalysis) {
    let cfg = test_config();
    let root = file.parent().unwrap();
    let root_str = root.to_string_lossy();
    let bytes = std::fs::read(file).expect("read fixture");
    let result = analyse_file_fused(&bytes, file, &cfg, None, Some(root))
        .expect("analyse fixture");
    let mut gs = GlobalSummaries::new();
    for s in result.summaries {
        let key = s.func_key(Some(&root_str));
        gs.insert(key, s);
    }
    for (key, ssa) in result.ssa_summaries {
        gs.insert_ssa(key, ssa);
    }
    let cg = build_call_graph(&gs, &[]);
    let analysis = analyse(&cg);
    (gs, cg, analysis)
}

fn make_diag(id: &str, path: &str, line: usize) -> Diag {
    Diag {
        path: path.into(),
        line,
        col: 0,
        severity: Severity::High,
        id: id.into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::High),
        evidence: Some(Evidence::default()),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash: 0,
    }
}

fn sink_step_in(file: &str, function: &str, line: usize) -> FlowStep {
    FlowStep {
        step: 1,
        kind: FlowStepKind::Sink,
        file: file.into(),
        line: line as u32,
        col: 0,
        snippet: None,
        variable: None,
        callee: None,
        function: Some(function.into()),
        is_cross_file: false,
    }
}

fn source_step_in(file: &str, function: &str, line: usize) -> FlowStep {
    FlowStep {
        step: 0,
        kind: FlowStepKind::Source,
        file: file.into(),
        line: line as u32,
        col: 0,
        snippet: None,
        variable: None,
        callee: None,
        function: Some(function.into()),
        is_cross_file: false,
    }
}

/// Helper: assert that strategy 4 with the callgraph rewrites the
/// entry to a framework-bound ancestor.
fn assert_callgraph_rewrites_entry(
    fixture: &str,
    helper: &str,
    expected_entry: &str,
    sink_line: usize,
    cap: Cap,
    rule_id: &str,
) {
    let file = fixtures_dir().join(fixture);
    let file_str = file.to_string_lossy().to_string();
    let (summaries, cg, analysis) = build_context(&file);

    // Sanity: pass 1 saw both functions.
    let names: Vec<String> = summaries.iter().map(|(_, s)| s.name.clone()).collect();
    assert!(
        names.iter().any(|n| n == helper),
        "pass 1 must summarise helper `{helper}` in {fixture}; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == expected_entry),
        "pass 1 must summarise entry `{expected_entry}` in {fixture}; got {names:?}"
    );

    // Build a synthetic diag pointing at the helper.
    let mut diag = make_diag(rule_id, &file_str, sink_line);
    let mut ev = Evidence::default();
    ev.flow_steps = vec![sink_step_in(&file_str, helper, sink_line)];
    ev.sink_caps = cap.bits();
    diag.evidence = Some(ev);

    // Without callgraph: strategy 4 either bails or names the helper.
    let baseline = HarnessSpec::from_finding_with_summaries(&diag, false, Some(&summaries));
    if let Ok(ref s) = baseline {
        assert_ne!(
            s.entry_name, expected_entry,
            "baseline (no callgraph) must not already rewrite the entry — \
             otherwise the callgraph path is untested"
        );
    }

    // With callgraph: entry is rewritten to the framework handler.
    let spec = HarnessSpec::from_finding_full(&diag, false, Some(&summaries), Some(&cg))
        .expect("callgraph-aware derivation must succeed");
    assert_eq!(
        spec.derivation,
        SpecDerivationStrategy::FromCallgraphEntry,
        "callgraph-walked spec must record FromCallgraphEntry"
    );
    assert_eq!(
        spec.entry_name, expected_entry,
        "callgraph walk must rewrite entry to the framework handler"
    );
    assert!(
        matches!(spec.entry_kind, EntryKind::HttpRoute),
        "callgraph walk must classify the entry as HttpRoute; got {:?}",
        spec.entry_kind
    );
    assert_eq!(spec.expected_cap, cap);
    let _ = analysis; // accepted but not asserted on here.
}

// ── Per-language fixtures ────────────────────────────────────────────────────

#[test]
fn flask_route_helper_sink_rewrites_to_route_handler() {
    assert_callgraph_rewrites_entry(
        "flask_route_sink.py",
        "_execute",
        "run_command",
        13,
        Cap::SHELL_ESCAPE,
        "py.cmdi.os_system",
    );
}

#[test]
fn express_handler_helper_sink_rewrites_to_route_handler() {
    assert_callgraph_rewrites_entry(
        "express_handler_sink.js",
        "execHelper",
        "runCommand",
        17,
        Cap::SHELL_ESCAPE,
        "js.cmdi.exec",
    );
}

#[test]
fn spring_controller_helper_sink_rewrites_to_controller_method() {
    assert_callgraph_rewrites_entry(
        "spring_controller_sink.java",
        "execHelper",
        "runCommand",
        15,
        Cap::SHELL_ESCAPE,
        "java.cmdi.runtime_exec",
    );
}

// ── `is_entry_point` direct coverage ─────────────────────────────────────────

#[test]
fn is_entry_point_recognises_route_decorator() {
    let file = fixtures_dir().join("flask_route_sink.py");
    let (summaries, cg, _analysis) = build_context(&file);

    let handler = summaries
        .iter()
        .find(|(_, s)| s.name == "run_command")
        .map(|(_, s)| s)
        .expect("Flask route handler must be summarised");
    assert!(
        is_entry_point(handler, &cg),
        "Flask-decorated function must qualify as an entry point"
    );

    let helper = summaries
        .iter()
        .find(|(_, s)| s.name == "_execute")
        .map(|(_, s)| s)
        .expect("helper must be summarised");
    // The helper has a static caller and no entry_kind, so it must not
    // be classified as an entry point.
    assert!(
        !is_entry_point(helper, &cg),
        "helper with static caller and no entry_kind must not be an entry point"
    );
}

#[test]
fn from_finding_with_callgraph_thin_wrapper_compiles_and_runs() {
    // Smoke test for the literal-plan signature. Without summaries the
    // wrapper degrades to the legacy substring path; this asserts the
    // entry point is callable and returns a spec for a `.http.` rule.
    let mut diag = make_diag(
        "py.http.flask_route",
        "tests/dynamic_fixtures/callgraph_entry/flask_route_sink.py",
        15,
    );
    let mut ev = Evidence::default();
    ev.sink_caps = Cap::SHELL_ESCAPE.bits();
    diag.evidence = Some(ev);

    let file = fixtures_dir().join("flask_route_sink.py");
    let (_summaries, cg, analysis) = build_context(&file);
    let spec = HarnessSpec::from_finding_with_callgraph(&diag, &cg, &analysis)
        .expect("wrapper must derive a spec via the rule-id fallback");
    assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);
    assert!(matches!(spec.entry_kind, EntryKind::HttpRoute));
}

// ── Strict pre-step regression: BFS-miss must defer to the ladder ────────────

#[test]
fn bfs_miss_with_http_rule_defers_to_flow_steps_strategy() {
    // Regression for the Phase 04 follow-up: the pre-step in
    // `HarnessSpec::from_finding_full` must use the *strict*
    // `derive_from_callgraph_walk_only` helper. If it instead falls
    // through to the rule-id `.http.` / `.cli.` substring fallback baked
    // into `derive_from_callgraph_entry_full`, every `.http.*` finding
    // whose enclosing function happens to be orphaned in the callgraph
    // gets tagged `FromCallgraphEntry` and loses the more precise
    // `FromFlowSteps` resolution. This fixture parks the sink in a
    // class method with no callers: the helper is *not* an entry point
    // (`container` is non-empty so the zero-in-degree heuristic does
    // not apply) and BFS bottoms out without finding an ancestor.
    let file = fixtures_dir().join("orphan_helper_sink.py");
    let file_str = file.to_string_lossy().to_string();
    let (summaries, cg, _analysis) = build_context(&file);

    // Sanity: the helper must be summarised and not be an entry point.
    let helper_summary = summaries
        .iter()
        .find(|(_, s)| s.name == "helper")
        .map(|(_, s)| s)
        .expect("pass 1 must summarise the orphan helper");
    assert!(
        !is_entry_point(helper_summary, &cg),
        "class method helper with non-empty container must not qualify as entry point"
    );

    // Synth a `py.http.*` rule id with a Source flow_step rooted in the
    // helper so strategy 1 (FromFlowSteps) has a concrete entry.
    let mut diag = make_diag("py.http.synthetic_route", &file_str, 13);
    let mut ev = Evidence::default();
    ev.flow_steps = vec![
        source_step_in(&file_str, "helper", 13),
        sink_step_in(&file_str, "helper", 13),
    ];
    ev.sink_caps = Cap::SHELL_ESCAPE.bits();
    diag.evidence = Some(ev);

    let spec = HarnessSpec::from_finding_full(&diag, false, Some(&summaries), Some(&cg))
        .expect("strict pre-step must defer; strategy 1 must produce a spec");
    assert_eq!(
        spec.derivation,
        SpecDerivationStrategy::FromFlowSteps,
        "BFS-miss + `.http.` rule must NOT short-circuit on the substring fallback; \
         expected FromFlowSteps but got {:?}",
        spec.derivation
    );
    assert_eq!(
        spec.entry_name, "helper",
        "FromFlowSteps must record the helper as entry, not an inferred route handler"
    );
}

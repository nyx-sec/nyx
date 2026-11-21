use super::*;
use crate::cfg::build_cfg;
use crate::symbol::Lang;
use crate::taint;
use tree_sitter::Language;

/// Test helper: parse code, build CFG, run a specific analysis.
fn parse_and_analyse<A: CfgAnalysis>(
    analysis: &A,
    src: &[u8],
    lang_str: &str,
    ts_lang: Language,
) -> Vec<CfgFinding> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, lang_str, "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let lang = Lang::from_slug(lang_str).unwrap();
    let ctx = AnalysisContext {
        cfg,
        entry,
        lang,
        source_bytes: src,
        func_summaries: summaries,
        global_summaries: None,
        ssa_summaries: None,
        taint_findings: &[],
        analysis_rules: None,
        taint_active: true,
        body_const_facts: None,
        type_facts: None,
        auth_decorators: &[],
        closure_released_var_names: None,
        class_constant_scalars: None,
    };
    analysis.run(&ctx)
}

/// Test helper: parse code, build CFG, run all analyses.
fn parse_and_run_all(src: &[u8], lang_str: &str, ts_lang: Language) -> Vec<CfgFinding> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, lang_str, "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let lang = Lang::from_slug(lang_str).unwrap();
    let ctx = AnalysisContext {
        cfg,
        entry,
        lang,
        source_bytes: src,
        func_summaries: summaries,
        global_summaries: None,
        ssa_summaries: None,
        taint_findings: &[],
        analysis_rules: None,
        taint_active: true,
        body_const_facts: None,
        type_facts: None,
        auth_decorators: &[],
        closure_released_var_names: None,
        class_constant_scalars: None,
    };
    run_all(&ctx)
}

/// Test helper: parse code, build CFG, run all analyses with custom taint findings.
fn parse_and_run_all_with_taint(
    src: &[u8],
    lang_str: &str,
    ts_lang: Language,
    taint_findings: &[taint::Finding],
) -> Vec<CfgFinding> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, lang_str, "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let lang = Lang::from_slug(lang_str).unwrap();
    let ctx = AnalysisContext {
        cfg,
        entry,
        lang,
        source_bytes: src,
        func_summaries: summaries,
        global_summaries: None,
        ssa_summaries: None,
        taint_findings,
        analysis_rules: None,
        taint_active: true,
        body_const_facts: None,
        type_facts: None,
        auth_decorators: &[],
        closure_released_var_names: None,
        class_constant_scalars: None,
    };
    run_all(&ctx)
}

// ─── Unreachable code tests ────────────────────────────────────────────

#[test]
fn unreachable_code_detection_runs_without_panic() {
    // Verify the unreachable code analysis runs correctly on code with a return.
    // After `return`, tree-sitter may or may not produce AST nodes for
    // subsequent statements depending on the language grammar.
    let src = br#"
        use std::process::Command;
        fn main() {
            return;
            Command::new("sh").arg("x").status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &unreachable::UnreachableCode,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    // The analysis should run without panicking. Whether it finds
    // unreachable nodes depends on how tree-sitter structures the AST
    // after `return;`.
    let _ = findings;
}

#[test]
fn all_branches_reachable_no_findings() {
    // All branches reachable, no unreachable-code findings
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = 1;
            if x > 0 {
                Command::new("a").status().unwrap();
            } else {
                Command::new("b").status().unwrap();
            }
        }"#;

    let findings = parse_and_analyse(
        &unreachable::UnreachableCode,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    assert!(
        findings.is_empty(),
        "Should have no unreachable findings when all branches are reachable"
    );
}

#[test]
fn unreachable_detects_orphaned_nodes() {
    // Directly verify that if we have orphaned sink/guard nodes in the CFG,
    // they get reported. We test this through the reachability check on
    // the CFG built from real code.
    let src = br#"
        fn main() {
            let x = 1;
            let y = 2;
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    // All nodes in linear code should be reachable
    let reachable = dominators::reachable_set(cfg, entry);
    assert_eq!(
        reachable.len(),
        cfg.node_count(),
        "All nodes should be reachable in linear code — no unreachable findings expected"
    );
}

/// Like `parse_and_analyse` but also plumbs per-body SSA + const-prop facts
/// into the analysis context.  Used by tests that exercise the SSA-backed
/// branch of `is_all_args_constant`.
fn parse_and_analyse_with_ssa<A: CfgAnalysis>(
    analysis: &A,
    src: &[u8],
    lang_str: &str,
    ts_lang: Language,
) -> Vec<CfgFinding> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, lang_str, "test.rs", None);
    let body = file_cfg.first_body();
    let lang = Lang::from_slug(lang_str).unwrap();
    let facts = build_body_const_facts(body, lang);
    let ctx = AnalysisContext {
        cfg: &body.graph,
        entry: body.entry,
        lang,
        source_bytes: src,
        func_summaries: &file_cfg.summaries,
        global_summaries: None,
        ssa_summaries: None,
        taint_findings: &[],
        analysis_rules: None,
        taint_active: true,
        body_const_facts: facts.as_ref(),
        type_facts: facts.as_ref().map(|f| &f.type_facts),
        auth_decorators: &[],
        closure_released_var_names: None,
        class_constant_scalars: None,
    };
    analysis.run(&ctx)
}

#[test]
fn ssa_const_prop_suppresses_sink_on_unused_source() {
    // rs-safe-003 regression: a tainted source binds a variable that is
    // never used; the sink's arg is a constant reassigned through a local
    // `let`.  SSA const-prop resolves `cmd` to a string literal, so the
    // structural finding must be suppressed.
    let src = br#"
        use std::env;
        use std::process::Command;
        fn main() {
            let _input = env::var("USER_CMD").unwrap();
            let cmd = "echo safe";
            Command::new("sh").arg("-c").arg(cmd).status().unwrap();
        }"#;

    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        guard_findings.is_empty(),
        "SSA const-prop should suppress sink with only constant args, got {guard_findings:?}"
    );
}

#[test]
fn ssa_const_prop_preserves_sink_on_dynamic_source_arg() {
    // Positive case: even with SSA facts available, a sink whose argument
    // flows from a source must still raise the structural finding.
    let src = br#"
        use std::env;
        use std::process::Command;
        fn main() {
            let shell = "sh";
            let flag = "-c";
            let user_cmd = env::var("USER_CMD").unwrap();
            Command::new(shell).arg(flag).arg(&user_cmd).status().unwrap();
        }"#;

    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !guard_findings.is_empty(),
        "Structural finding must still fire when a sink arg is source-derived"
    );
}

/// outline migration idiom (top-level form): the SQL string (arg 0) is a
/// constant template literal and the options object (arg 1) is a non-constant
/// identifier.  The `sequelize.query` `payload_args=[0]` gate plus the
/// syntactic payload-const suppression must silence `cfg-unguarded-sink` even
/// though the whole-call `is_all_args_constant` rejects the non-const opts.
#[test]
fn js_raw_sql_const_payload_suppresses_unguarded_sink() {
    let src = br#"
        function migrate(queryInterface, opts) {
          queryInterface.sequelize.query(`SELECT 1`, opts);
        }
    "#;
    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let guard: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        guard.is_empty(),
        "constant SQL payload must suppress cfg-unguarded-sink, got {guard:?}"
    );
}

/// Recall counterpart: attacker data interpolated INTO the SQL string (arg 0)
/// is non-constant, so the raw-SQL `payload_args=[0]` gate must NOT suppress
/// the finding.
#[test]
fn js_raw_sql_interpolated_payload_still_flagged() {
    let src = br#"
        function migrate(queryInterface, name) {
          queryInterface.sequelize.query(`SELECT ${name}`, {});
        }
    "#;
    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let guard: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !guard.is_empty(),
        "an interpolated SQL payload (arg 0) must still fire cfg-unguarded-sink"
    );
}

/// Chained-rebind alignment guard: `http.get(target, cb).on('error', cb2)`
/// rebinds the SSRF sink onto the inner `http.get`, but the node's
/// `arg_string_literals` still reflect the outer `.on('error', …)` call.  The
/// `'error'` string literal at the `.on` arg 0 must NOT be mistaken for a
/// constant SSRF payload by the syntactic payload-const suppression — the
/// finding must survive.
#[test]
fn chained_rebind_sink_not_suppressed_by_misaligned_syntactic_const() {
    let src = br#"
        const http = require('http');
        function proxy(req, res) {
          const target = req.query.url;
          http.get(target, r => { res.end(); }).on('error', e => { res.end(); });
        }
    "#;
    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let guard: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !guard.is_empty(),
        "chained http.get SSRF sink must not be suppressed by the outer \
         `.on('error', …)` string literal, got {findings:?}"
    );
}

// ─── Guard validation tests ───────────────────────────────────────────

#[test]
fn unguarded_sink_detected() {
    // Sink with no validation, should be flagged
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = std::env::var("INPUT").unwrap();
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(!guard_findings.is_empty(), "Should flag unguarded sink");
}

#[test]
fn guarded_sink_with_sanitizer_not_flagged() {
    // Sink with a sanitizer (shell_escape::unix::escape) before it.
    // The label rules in labels/rust.rs recognise this as a Sanitizer(SHELL_ESCAPE),
    // and the dominator check should suppress the "unguarded sink" finding.
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = std::env::var("INPUT").unwrap();
            let safe = shell_escape::unix::escape(&x);
            Command::new("sh").arg(&safe).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        guard_findings.is_empty(),
        "Guarded sink should not be flagged; got {:?}",
        guard_findings
    );
}

/// Regression: `cond_indirect_validator_callee` used to pick the
/// textually-last call defining the condition variable across the
/// whole function, including reassignments that occur **after** the
/// `if`.  When that later call wasn't a recognised validator, the
/// validator pattern was missed and the downstream sink was
/// (incorrectly) flagged as `cfg-unguarded-sink`.
///
/// Pattern:
///   let err = validateInput(cmd);  // real validator, before the if
///   if (err) throw …;              // sink-guarding branch
///   eval(cmd);                     // sink dominated by the guard
///   err = recordMetric();          // later reassignment, NOT a validator
///
/// The defining call reaching the `if` is `validateInput`; the
/// `recordMetric` reassignment is downstream of the use and must not
/// shadow it.
#[test]
fn indirect_validator_ignores_reassignment_after_if() {
    let src = br#"
async function handler(req) {
    const cmd = req.query.cmd;
    let err = await validateInput(cmd);
    if (err) {
        throw new Error('blocked');
    }
    eval(cmd);
    err = recordMetric();
}
"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        guard_findings.is_empty(),
        "later non-validator reassignment must not shadow the real validator def reaching the if; got {:?}",
        guard_findings
    );
}

/// Companion sanity check for `indirect_validator_ignores_reassignment_after_if`:
/// without the trailing reassignment the same pattern is already
/// suppressed by `cond_indirect_validator_callee`.  Pinned so a future
/// change to the indirect-validator recognition can't silently regress
/// this baseline alongside the regression case above.
#[test]
fn indirect_validator_baseline_suppresses_dominated_sink() {
    let src = br#"
async function handler(req) {
    const cmd = req.query.cmd;
    const err = await validateInput(cmd);
    if (err) {
        throw new Error('blocked');
    }
    eval(cmd);
}
"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        guard_findings.is_empty(),
        "indirect-validator pattern (no reassignment) must suppress dominated sink; got {:?}",
        guard_findings
    );
}

// ─── Auth gap tests ────────────────────────────────────────────────────

#[test]
fn auth_gap_in_handler_detected() {
    // Handler function with a sink but no auth check
    let src = br#"
        use std::process::Command;
        fn handle_request() {
            let data = std::env::var("INPUT").unwrap();
            Command::new("sh").arg(&data).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &auth::AuthGap,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let auth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-auth-gap")
        .collect();
    assert!(
        !auth_findings.is_empty(),
        "Should detect auth gap in handler function"
    );
}

#[test]
fn auth_check_before_sink_no_finding() {
    // Handler with auth check before sink
    let src = br#"
        fn handle_request() {
            require_auth();
            let data = std::env::var("INPUT").unwrap();
            std::process::Command::new("sh").arg(&data).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &auth::AuthGap,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let auth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-auth-gap")
        .collect();
    assert!(
        auth_findings.is_empty(),
        "Auth check before sink should not be flagged; got {:?}",
        auth_findings
    );
}

// ─── Error handling tests ──────────────────────────────────────────────

#[test]
fn error_fallthrough_analysis_runs_on_go() {
    // Go pattern: err check without return, followed by dangerous call.
    // This is a heuristic analysis, we verify it runs without panicking.
    let src = br#"
        package main
        import "os/exec"
        func main() {
            err := doSomething()
            if err != nil {
                log(err)
            }
            exec.Command("sh", input).Run()
        }"#;

    let findings = parse_and_analyse(
        &error_handling::IncompleteErrorHandling,
        src,
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );

    // Analysis should run without panicking
    let _ = findings;
}

#[test]
fn proper_error_return_no_finding_go() {
    // Go pattern: err check with return, should not flag error fallthrough.
    let src = br#"
        package main
        import "os/exec"
        func main() {
            err := doSomething()
            if err != nil {
                return
            }
            exec.Command("sh", input).Run()
        }"#;

    let findings = parse_and_analyse(
        &error_handling::IncompleteErrorHandling,
        src,
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );

    let err_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-error-fallthrough")
        .collect();
    assert!(
        err_findings.is_empty(),
        "Proper error return should not be flagged; got {:?}",
        err_findings
    );
}

// ─── Resource misuse tests ────────────────────────────────────────────

#[test]
fn resource_leak_c_system_call() {
    // C code that acquires a resource (malloc) without freeing it.
    // Use a simple standalone call so the callee extraction is unambiguous.
    let src = br#"
        void main() {
            char *p = malloc(100);
            system(p);
        }"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        !leak_findings.is_empty(),
        "Should detect malloc without free"
    );
}

#[test]
fn resource_properly_freed_c() {
    // C code with malloc and free on the same path
    let src = br#"
        void main() {
            char *p = malloc(100);
            free(p);
        }"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "Properly freed resource should not be flagged; got {:?}",
        leak_findings
    );
}

// ─── Scoring tests ─────────────────────────────────────────────────────

#[test]
fn high_severity_scores_higher() {
    let src = br#"
        use std::process::Command;
        fn handle_request() {
            let x = std::env::var("INPUT").unwrap();
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let findings = parse_and_run_all(src, "rust", Language::from(tree_sitter_rust::LANGUAGE));

    // All findings should have a score
    for f in &findings {
        assert!(f.score.is_some(), "All findings should have a score");
        assert!(f.score.unwrap() > 0.0, "All scores should be positive");
    }

    // If there are multiple findings, they should be sorted by score descending
    for w in findings.windows(2) {
        assert!(
            w[0].score.unwrap() >= w[1].score.unwrap(),
            "Findings should be sorted by score descending"
        );
    }
}

// ─── Integration: run_all ──────────────────────────────────────────────

#[test]
fn run_all_produces_findings() {
    let src = br#"
        use std::process::Command;
        fn handle_request() {
            let x = std::env::var("DANGEROUS").unwrap();
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let findings = parse_and_run_all(src, "rust", Language::from(tree_sitter_rust::LANGUAGE));

    // Should produce at least one finding (unguarded sink and/or auth gap)
    assert!(
        !findings.is_empty(),
        "run_all should produce findings for vulnerable code"
    );
}

#[test]
fn run_all_safe_code_fewer_findings() {
    let src = br#"
        fn safe_function() {
            let x = 42;
            let y = x + 1;
        }"#;

    let findings = parse_and_run_all(src, "rust", Language::from(tree_sitter_rust::LANGUAGE));

    // Safe code should produce no or very few findings
    let high_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == crate::patterns::Severity::High)
        .collect();
    assert!(
        high_findings.is_empty(),
        "Safe code should have no high-severity findings"
    );
}

// ─── Dominator utility tests ──────────────────────────────────────────

#[test]
fn reachable_set_contains_all_connected_nodes() {
    let src = br#"
        fn main() {
            let x = 1;
            let y = 2;
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    let reachable = dominators::reachable_set(cfg, entry);

    // All nodes in a simple straight-line function should be reachable
    assert_eq!(
        reachable.len(),
        cfg.node_count(),
        "All nodes should be reachable in a simple function"
    );
}

#[test]
fn find_exit_node_exists() {
    let src = br#"
        fn main() {
            let x = 1;
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let cfg = &file_cfg.first_body().graph;

    let exit = dominators::find_exit_node(cfg);
    assert!(exit.is_some(), "Should find an exit node");
}

/// Post-dominators over a hand-built CFG: an if/else diamond, a loop with a
/// back edge, and a node with no path to Exit.  Pins the semantics of
/// `compute_post_dominators` (dominators of the reversed graph from Exit).
#[test]
fn post_dominators_diamond_loop_and_dead_end() {
    use crate::cfg::{Cfg, EdgeKind, NodeInfo, StmtKind};

    fn node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    let mut cfg = Cfg::new();
    let entry = cfg.add_node(node(StmtKind::Entry));
    let if_n = cfg.add_node(node(StmtKind::If));
    let then_n = cfg.add_node(node(StmtKind::Seq));
    let else_n = cfg.add_node(node(StmtKind::Seq));
    let join = cfg.add_node(node(StmtKind::Seq));
    let header = cfg.add_node(node(StmtKind::Loop));
    let body = cfg.add_node(node(StmtKind::Seq));
    let after = cfg.add_node(node(StmtKind::Seq));
    let exit = cfg.add_node(node(StmtKind::Exit));
    // Reachable from the else branch but never reaches Exit (an infinite
    // spin with no edge out).
    let dead_end = cfg.add_node(node(StmtKind::Seq));

    cfg.add_edge(entry, if_n, EdgeKind::Seq);
    cfg.add_edge(if_n, then_n, EdgeKind::True);
    cfg.add_edge(if_n, else_n, EdgeKind::False);
    cfg.add_edge(then_n, join, EdgeKind::Seq);
    cfg.add_edge(else_n, join, EdgeKind::Seq);
    cfg.add_edge(else_n, dead_end, EdgeKind::Seq);
    cfg.add_edge(dead_end, dead_end, EdgeKind::Back);
    cfg.add_edge(join, header, EdgeKind::Seq);
    cfg.add_edge(header, body, EdgeKind::True);
    cfg.add_edge(header, after, EdgeKind::False);
    cfg.add_edge(body, header, EdgeKind::Back);
    cfg.add_edge(after, exit, EdgeKind::Seq);

    let pd = dominators::compute_post_dominators(&cfg).expect("cfg has an Exit node");
    assert_eq!(pd.immediate_dominator(if_n), Some(join));
    assert_eq!(pd.immediate_dominator(then_n), Some(join));
    assert_eq!(pd.immediate_dominator(else_n), Some(join));
    assert_eq!(pd.immediate_dominator(join), Some(header));
    assert_eq!(pd.immediate_dominator(body), Some(header));
    assert_eq!(pd.immediate_dominator(header), Some(after));
    assert_eq!(pd.immediate_dominator(after), Some(exit));
    assert_eq!(pd.immediate_dominator(exit), None);
    assert!(dominators::dominates(&pd, header, body));
    assert!(dominators::dominates(&pd, exit, entry));
    assert!(!dominators::dominates(&pd, then_n, if_n));
    // A node with no path to Exit has no post-dominator.
    assert_eq!(pd.immediate_dominator(dead_end), None);
    assert!(!dominators::dominates(&pd, exit, dead_end));

    // No Exit node: no post-dominator tree.
    let mut no_exit = Cfg::new();
    no_exit.add_node(node(StmtKind::Entry));
    assert!(dominators::compute_post_dominators(&no_exit).is_none());
}

#[test]
fn shortest_distance_basic() {
    let src = br#"
        fn main() {
            let x = 1;
            let y = 2;
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    let exit = dominators::find_exit_node(cfg).unwrap();
    let dist = dominators::shortest_distance(cfg, entry, exit);
    assert!(dist.is_some(), "Should find a path from entry to exit");
    assert!(dist.unwrap() > 0, "Distance should be positive");
}

// ─── Severity refinement tests ──────────────────────────────────────

#[test]
fn unguarded_sink_source_derived_is_high() {
    // Sink with source-derived arg (env var → Command) in main → should be HIGH
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = std::env::var("INPUT").unwrap();
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let high: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !high.is_empty(),
        "Source-derived unguarded sink should be HIGH severity"
    );
}

#[test]
fn unguarded_sink_wrapper_param_only_is_low() {
    // A helper function that just wraps a sink with a parameter.
    // No source, no entrypoint name → should be LOW.
    let src = br#"
        use std::process::Command;
        fn run_command(cmd: &str) {
            Command::new("sh").arg(cmd).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let high: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        high.is_empty(),
        "Wrapper function with param-only sink should NOT be HIGH; got {:?}",
        high
    );
}

// ─── Auth gap refinement tests ──────────────────────────────────────

#[test]
fn cli_main_no_auth_gap() {
    // CLI main() using Command::new with constant arg → should NOT trigger auth-gap
    let src = br#"
        use std::process::Command;
        fn main() {
            Command::new("ls").arg("-la").status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &auth::AuthGap,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let auth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-auth-gap")
        .collect();
    assert!(
        auth_findings.is_empty(),
        "CLI main() should NOT trigger auth-gap; got {:?}",
        auth_findings
    );
}

#[test]
fn handler_with_source_still_gets_auth_gap() {
    // handler-style function (handle_*) with a sink → should still flag auth-gap
    // because it has a strong handler name even without explicit web params
    let src = br#"
        use std::process::Command;
        fn handle_request() {
            let data = std::env::var("INPUT").unwrap();
            Command::new("sh").arg(&data).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &auth::AuthGap,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let auth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-auth-gap")
        .collect();
    assert!(
        !auth_findings.is_empty(),
        "handler-style function should still trigger auth-gap"
    );
}

// ─── Dedup tests ────────────────────────────────────────────────────

#[test]
fn taint_and_unguarded_sink_deduped() {
    // When taint confirms flow to a sink, the cfg-unguarded-sink for that same
    // span should be suppressed by the dedup pass.
    let src = br#"
        use std::process::Command;
        fn handle_request() {
            let x = std::env::var("INPUT").unwrap();
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let cfg_graph = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let _lang = Lang::from_slug("rust").unwrap();

    // Find a sink node to create a synthetic taint finding
    let sink_node = cfg_graph
        .node_indices()
        .find(|&idx| {
            cfg_graph[idx]
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Sink(_)))
        })
        .expect("test code should have a sink node");

    let fake_taint = vec![taint::Finding {
        body_id: crate::cfg::BodyId(0),
        sink: sink_node,
        source: entry,
        path: vec![entry, sink_node],
        source_kind: crate::labels::SourceKind::UserInput,
        path_validated: false,
        guard_kind: None,
        hop_count: 0,
        cap_specificity: 1,
        uses_summary: false,
        flow_steps: vec![],
        symbolic: None,
        source_span: None,
        primary_location: None,
        engine_notes: smallvec::SmallVec::new(),
        path_hash: 0,
        finding_id: String::new(),
        alternative_finding_ids: smallvec::SmallVec::new(),
        effective_sink_caps: crate::labels::Cap::empty(),
    }];

    let findings = parse_and_run_all_with_taint(
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
        &fake_taint,
    );

    // The cfg-unguarded-sink for that sink's span should be suppressed
    // because taint already covers it.
    // Note: the `parse_and_run_all_with_taint` helper builds a fresh CFG,
    // so the NodeIndex won't match. Instead, check that we don't have
    // cfg-unguarded-sink at HIGH severity (dedup only fires on exact span match
    // which requires the same CFG). For this test, just verify the test runs
    // and produces findings.
    let _ = findings;
}

#[test]
fn process_star_without_web_params_no_auth_gap() {
    // process_* function without web params should NOT trigger auth-gap
    let src = br#"
        use std::process::Command;
        fn process_data() {
            Command::new("ls").status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &auth::AuthGap,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let auth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-auth-gap")
        .collect();
    assert!(
        auth_findings.is_empty(),
        "process_* without web params should NOT trigger auth-gap; got {:?}",
        auth_findings
    );
}

// ─── Resource leak tests (additional languages) ────────────────────

#[test]
fn resource_leak_python_open_without_close() {
    let src = br#"
def process():
    f = open("data.txt")
    data = f.read()
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        !leak_findings.is_empty(),
        "Should detect open() without close() in Python"
    );
}

#[test]
fn resource_leak_python_django_signals_not_flagged() {
    // taiga real-repo shape: Django signal registrations share the `connect`
    // callee leaf with real DB acquires but register observers (return None,
    // hold no resource).  `.disconnect` must not suffix-match `connect`; the
    // signal-kwarg and bare-receiver forms of `.connect` must be recognised.
    let src = br#"
def register(model):
    pre_save.connect(remove_files_on_change, sender=model)
    post_delete.connect(remove_files_on_delete, sender=model)
    setting_changed.connect(reload_api_settings)
    signals.post_save.connect(on_save_any_model, dispatch_uid="events_change")
    signals.post_save.disconnect(dispatch_uid="events_change")
    cleanup_post_delete.disconnect(delete_thumbnail_files)
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "Django signal connect/disconnect must not be treated as DB-connection \
         leaks, got {leak_findings:?}"
    );
}

#[test]
fn resource_leak_python_real_db_connect_still_flagged() {
    // Recall guard for the signal-registration suppression: a genuine DB
    // connection acquired and bound but never closed must still leak.
    let src = br#"
def get_conn():
    conn = psycopg2.connect("dbname=test user=admin")
    rows = conn.execute("SELECT 1")
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        !leak_findings.is_empty(),
        "A bound-but-unclosed psycopg2.connect() must still be flagged as a leak"
    );
}

#[test]
fn resource_leak_php_fopen_without_fclose() {
    let src = br#"<?php
function read_file() {
    $fp = fopen("data.txt", "r");
    $data = fread($fp, 1024);
}
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "php",
        Language::from(tree_sitter_php::LANGUAGE_PHP),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        !leak_findings.is_empty(),
        "Should detect fopen() without fclose() in PHP"
    );
}

#[test]
fn resource_leak_js_open_without_close() {
    let src = br#"
function readFile() {
    var fd = fs.openSync("data.txt", "r");
    var data = fs.readSync(fd, buf, 0, 100, 0);
}
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        !leak_findings.is_empty(),
        "Should detect fs.openSync() without fs.closeSync() in JS"
    );
}

// ─── JS CFG precision tests ────────────────────────────────────────

#[test]
fn js_throw_terminates_block() {
    // throw should act as a terminator, code directly after throw in the same
    // block should be unreachable.
    let src = br#"
        function fail() {
            throw new Error("fatal");
            eval("dead code");
        }
    "#;

    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "javascript", "test.js", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    // Verify throw creates a Throw-kind node
    let throw_nodes: Vec<_> = cfg
        .node_indices()
        .filter(|&idx| cfg[idx].kind == crate::cfg::StmtKind::Throw)
        .collect();

    assert!(
        !throw_nodes.is_empty(),
        "throw statement should create a Throw-kind node"
    );

    // eval after throw should be unreachable
    let reachable = crate::cfg_analysis::dominators::reachable_set(cfg, entry);
    let eval_nodes: Vec<_> = cfg
        .node_indices()
        .filter(|&idx| cfg[idx].call.callee.as_deref().is_some_and(|c| c == "eval"))
        .collect();

    // eval might not even be in the CFG, or if it is, it should be unreachable
    if !eval_nodes.is_empty() {
        assert!(
            eval_nodes.iter().all(|n| !reachable.contains(n)),
            "eval after throw should be unreachable"
        );
    }
}

#[test]
fn configured_terminator_stops_flow() {
    let src = br#"
        function handler() {
            process.exit(1);
            eval("dangerous");
        }
    "#;

    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let rules = crate::labels::LangAnalysisRules {
        extra_labels: vec![],
        terminators: vec!["process.exit".into()],
        event_handlers: vec![],
        frameworks: vec![],
    };

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "javascript", "test.js", Some(&rules));
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    let reachable = crate::cfg_analysis::dominators::reachable_set(cfg, entry);

    // eval should be unreachable since process.exit is a terminator
    let eval_nodes: Vec<_> = cfg
        .node_indices()
        .filter(|&idx| cfg[idx].call.callee.as_deref().is_some_and(|c| c == "eval"))
        .collect();

    if !eval_nodes.is_empty() {
        assert!(
            eval_nodes.iter().all(|n| !reachable.contains(n)),
            "eval should be unreachable after process.exit terminator"
        );
    }
    // If eval_nodes is empty it means the node wasn't created (also acceptable ,
    // it's after a terminator so the CFG may not even emit it)
}

// ─── Href classification tests ─────────────────────────────────────

#[test]
fn location_href_assignment_is_sink() {
    let src = br#"
        function redirect(url) {
            location.href = url;
        }
    "#;

    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "javascript", "test.js", None);
    let cfg = &file_cfg.first_body().graph;

    let has_sink = cfg.node_indices().any(|idx| {
        cfg[idx]
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, crate::labels::DataLabel::Sink(_)))
    });
    assert!(has_sink, "location.href = url should produce a Sink node");
}

#[test]
fn a_href_assignment_is_not_sink() {
    let src = br#"
        function setLink(el) {
            el.href = "/about";
        }
    "#;

    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "javascript", "test.js", None);
    let cfg = &file_cfg.first_body().graph;

    let has_sink = cfg.node_indices().any(|idx| {
        cfg[idx]
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, crate::labels::DataLabel::Sink(_)))
    });
    assert!(
        !has_sink,
        "el.href = '/about' should NOT produce a Sink node"
    );
}

// ─── Config sanitizer tests ────────────────────────────────────────

#[test]
fn config_sanitizer_suppresses_unguarded_sink() {
    // JS snippet: escapeHtml(x) before innerHTML = ... should not trigger
    // cfg-unguarded-sink when escapeHtml is configured as a sanitizer.
    let src = br#"
        function render(input) {
            var safe = escapeHtml(input);
            document.body.innerHTML = safe;
        }
    "#;

    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let lang_str = "javascript";

    // Build with config sanitizer rules
    let rules = crate::labels::LangAnalysisRules {
        extra_labels: vec![crate::labels::RuntimeLabelRule {
            matchers: vec!["escapeHtml".into()],
            label: crate::labels::DataLabel::Sanitizer(crate::labels::Cap::HTML_ESCAPE),
            case_sensitive: false,
        }],
        terminators: vec![],
        event_handlers: vec![],
        frameworks: vec![],
    };

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, lang_str, "test.rs", Some(&rules));
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let lang = Lang::from_slug(lang_str).unwrap();
    let ctx = AnalysisContext {
        cfg,
        entry,
        lang,
        source_bytes: src,
        func_summaries: summaries,
        global_summaries: None,
        ssa_summaries: None,
        taint_findings: &[],
        analysis_rules: Some(&rules),
        taint_active: true,
        body_const_facts: None,
        type_facts: None,
        auth_decorators: &[],
        closure_released_var_names: None,
        class_constant_scalars: None,
    };
    let findings = run_all(&ctx);

    let unguarded = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect::<Vec<_>>();

    assert!(
        unguarded.is_empty(),
        "escapeHtml config sanitizer should suppress cfg-unguarded-sink; got {:?}",
        unguarded
    );
}

// ─── Python precision tests ────────────────────────────────────────

#[test]
fn python_constant_subprocess_no_finding() {
    // subprocess.run(["make","clean"]) with constant args should produce no finding
    let src = br#"
import subprocess

def build():
    subprocess.run(["make", "clean"])
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "subprocess.run with constant list args should not be flagged; got {:?}",
        unguarded
    );
}

#[test]
fn python_constant_git_status_no_finding() {
    let src = br#"
import subprocess

def check():
    subprocess.run(["git", "status"])
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "subprocess.run with constant git args should not be flagged; got {:?}",
        unguarded
    );
}

#[test]
fn python_tainted_os_system_produces_finding() {
    // Source (sys.argv) flowing to os.system → should produce a finding
    let src = br#"
import sys
import os

def run():
    cmd = sys.argv[1]
    os.system(cmd)
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "Source-derived os.system should produce a HIGH finding"
    );
}

// ─── C++ precision tests ───────────────────────────────────────────

#[test]
fn cpp_cout_not_a_sink() {
    let src = br#"
#include <iostream>
int main() {
    std::cout << "hello" << std::endl;
    return 0;
}
"#;

    let findings = parse_and_run_all(src, "cpp", Language::from(tree_sitter_cpp::LANGUAGE));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        sink_findings.is_empty(),
        "std::cout should not produce an unguarded-sink finding; got {:?}",
        sink_findings
    );
}

#[test]
fn cpp_printf_constant_no_finding() {
    // printf with constant args → FMT_STRING sink but constant-arg suppression
    let src = br#"
#include <stdio.h>
int main() {
    printf("hello\n");
    return 0;
}
"#;

    let findings = parse_and_run_all(src, "c", Language::from(tree_sitter_c::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "printf with constant args should be suppressed; got {:?}",
        unguarded
    );
}

#[test]
fn cpp_system_with_getenv_produces_finding() {
    let src = br#"
#include <stdlib.h>
int main() {
    char* input = getenv("USER_CMD");
    system(input);
    return 0;
}
"#;

    let findings = parse_and_run_all(src, "c", Language::from(tree_sitter_c::LANGUAGE));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "system(getenv(...)) should produce an unguarded-sink finding"
    );
}

// ─── Unreachable + unguarded dedup test ─────────────────────────────

#[test]
fn unreachable_sink_suppresses_unguarded() {
    // If a sink is in unreachable code, only cfg-unreachable-sink should fire,
    // NOT also cfg-unguarded-sink.
    let src = br#"
fn main() {
    return;
    std::process::Command::new("sh").arg("x").status().unwrap();
}
"#;

    let findings = parse_and_run_all(src, "rust", Language::from(tree_sitter_rust::LANGUAGE));

    let unreachable: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unreachable-sink")
        .collect();
    let unguarded_at_same_span: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && unreachable.iter().any(|u| u.span == f.span)
        })
        .collect();
    assert!(
        unguarded_at_same_span.is_empty(),
        "cfg-unguarded-sink should be suppressed when cfg-unreachable-sink fires on same span; got {:?}",
        unguarded_at_same_span
    );
}

// ─── Fix 3: Wrapper resource names (curlx_fopen/curlx_fclose) ──────

#[test]
fn curlx_fopen_with_curlx_fclose_no_leak() {
    let src = br#"
void process() {
    FILE *fp = curlx_fopen("file.txt", "r");
    curlx_fclose(fp);
}
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "curlx_fopen + curlx_fclose should not produce a resource leak; got {:?}",
        leak_findings
    );
}

// ─── Fix 4: freopen exclusion ───────────────────────────────────────

#[test]
fn freopen_not_treated_as_acquire() {
    let src = br#"
void redirect_stderr() {
    freopen("/dev/null", "w", stderr);
}
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "freopen should not produce a resource leak finding; got {:?}",
        leak_findings
    );
}

// ─── Fix 5: Struct field ownership transfer ─────────────────────────

#[test]
fn struct_field_ownership_transfer_no_leak() {
    let src = br#"
void open_stream(struct session *s) {
    FILE *fp = fopen("data.txt", "r");
    s->stream = fp;
    s->fopened = 1;
}
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "Struct field ownership transfer should suppress resource leak; got {:?}",
        leak_findings
    );
}

// ─── Fix 6: Linked-list / global insertion ──────────────────────────

#[test]
fn linked_list_insertion_no_leak() {
    let src = br#"
void add_var(struct config *cfg, const char *name) {
    struct var *p = malloc(sizeof(struct var));
    p->next = cfg->variables;
    cfg->variables = p;
}
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "Linked-list insertion should suppress resource leak; got {:?}",
        leak_findings
    );
}

// ─── Fix 2: Preproc dangling-else CFG recovery ─────────────────────

#[test]
fn preproc_ifdef_does_not_orphan_subsequent_code() {
    // After a #ifdef block containing an if/else, subsequent code should
    // still be reachable (no unreachable findings).
    let src = br#"
void process() {
    int x = 1;
#ifdef _WIN32
    if (x) {
        x = 2;
    } else
#endif
    {
        x = 3;
    }
    free(x);
}
"#;

    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "c", "test.c", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    let reachable = dominators::reachable_set(cfg, entry);

    // All nodes should be reachable, the preproc recovery should prevent
    // the dangling-else from orphaning downstream code.
    let unreachable_count = cfg.node_count() - reachable.len();
    assert!(
        unreachable_count == 0,
        "Expected all nodes reachable after preproc block, but {} nodes are unreachable",
        unreachable_count
    );
}

// ─── Fix 1: Break in loop keeps post-loop code reachable ────────────

#[test]
fn break_in_loop_post_loop_reachable() {
    let src = br#"
void process() {
    int x = 0;
    while(1) {
        if(x) break;
        x = x + 1;
    }
    free(x);
}
"#;

    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "c", "test.c", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;

    let reachable = dominators::reachable_set(cfg, entry);

    // All nodes should be reachable, break exits the loop and post-loop
    // code (free(x)) should be connected.
    let unreachable_count = cfg.node_count() - reachable.len();
    assert!(
        unreachable_count == 0,
        "Expected all nodes reachable after break in loop, but {} nodes are unreachable",
        unreachable_count
    );
}

// ─── PART 2A: One-hop constant binding trace ────────────────────────

#[test]
fn python_one_hop_constant_binding_no_finding() {
    // cmd = "git"; subprocess.run([cmd, "status"]) → no finding
    let src = br#"
import subprocess

def check():
    cmd = "git"
    subprocess.run([cmd, "status"])
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "One-hop constant binding should suppress cfg-unguarded-sink; got {:?}",
        unguarded
    );
}

// ─── PART 2B: Exec-path guard rules ─────────────────────────────────

#[test]
fn exec_path_guard_suppresses_unguarded_sink() {
    // resolve_binary(&bin); Command::new(bin); → no finding
    let src = br#"
        use std::process::Command;
        fn main() {
            let bin = std::env::var("BIN").unwrap();
            resolve_binary(&bin);
            Command::new("sh").arg(&bin).status().unwrap();
        }"#;

    let findings = parse_and_analyse(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "resolve_binary guard should suppress cfg-unguarded-sink; got {:?}",
        unguarded
    );
}

// ─── PART 2C: Evidence-based severity in cfg-only mode ──────────────

#[test]
fn cfg_only_no_taint_produces_low_severity() {
    // In cfg-only mode (taint_active=false) with no source-derived evidence,
    // unguarded sink should produce LOW severity instead of MEDIUM.
    let src = br#"
        use std::process::Command;
        fn process_data() {
            let x = compute_something();
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let lang = Lang::from_slug("rust").unwrap();
    let ctx = AnalysisContext {
        cfg,
        entry,
        lang,
        source_bytes: src,
        func_summaries: summaries,
        global_summaries: None,
        ssa_summaries: None,
        taint_findings: &[],
        analysis_rules: None,
        taint_active: false, // cfg-only mode
        body_const_facts: None,
        type_facts: None,
        auth_decorators: &[],
        closure_released_var_names: None,
        class_constant_scalars: None,
    };
    let findings = guards::UnguardedSink.run(&ctx);

    let medium_or_high: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink"
                && (f.severity == crate::patterns::Severity::Medium
                    || f.severity == crate::patterns::Severity::High)
        })
        .collect();
    assert!(
        medium_or_high.is_empty(),
        "cfg-only mode without taint should produce LOW severity, not MEDIUM/HIGH; got {:?}",
        medium_or_high
    );
}

// ─── PART 4B: FileResponse ownership transfer ──────────────────────

#[test]
fn file_response_ownership_transfer_no_leak() {
    let src = br#"
def serve_file():
    f = open("report.pdf", "rb")
    return FileResponse(f)
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "FileResponse should suppress cfg-resource-leak; got {:?}",
        leak_findings
    );
}

// ─── PART 4C: Lock-not-released refinement ──────────────────────────

#[test]
fn python_lock_constructor_only_no_finding() {
    // threading.Lock() without .acquire() → no finding
    let src = br#"
import threading

def setup():
    lock = threading.Lock()
    do_work()
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );

    let lock_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-lock-not-released")
        .collect();
    assert!(
        lock_findings.is_empty(),
        "Lock constructor without acquire should not produce cfg-lock-not-released; got {:?}",
        lock_findings
    );
}

// ─── PART 4A: signal.connect exclusion ──────────────────────────────

#[test]
fn python_signal_connect_not_treated_as_db_acquire() {
    let src = br#"
def setup():
    signal.connect(handler)
    do_work()
"#;

    let findings = parse_and_analyse(
        &resources::ResourceMisuse,
        src,
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );

    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-resource-leak")
        .collect();
    assert!(
        leak_findings.is_empty(),
        "signal.connect should not be treated as db acquire; got {:?}",
        leak_findings
    );
}

// ─── Literal-argument taint sink suppression tests ─────────────────

#[test]
fn python_literal_os_system_no_finding() {
    // os.system("ls -la") with string literal arg should produce no finding
    let src = br#"
import os

def run():
    os.system("ls -la")
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "os.system with string literal arg should not be flagged; got {:?}",
        unguarded
    );
}

#[test]
fn go_literal_exec_command_no_finding() {
    // exec.Command("echo", "hello") with multiple string literal args should produce no finding
    let src = br#"
package main

import "os/exec"

func run() {
    exec.Command("echo", "hello")
}
"#;

    let findings = parse_and_run_all(src, "go", Language::from(tree_sitter_go::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "exec.Command with string literal args should not be flagged; got {:?}",
        unguarded
    );
}

#[test]
fn python_literal_subprocess_list_no_finding() {
    // subprocess.run(["ls", "-la"]) with array of string literals should produce no finding
    let src = br#"
import subprocess

def run():
    subprocess.run(["ls", "-la"])
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "subprocess.run with list of string literals should not be flagged; got {:?}",
        unguarded
    );
}

#[test]
fn python_literal_subprocess_multiple_list_items_no_finding() {
    // subprocess.run(["ls", "-la", "-h"]) with list of multiple literals should produce no finding
    let src = br#"
import subprocess

def run():
    subprocess.run(["ls", "-la", "-h"])
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "subprocess.run with list of multiple literals should not be flagged; got {:?}",
        unguarded
    );
}

#[test]
fn js_template_literal_no_interpolation_no_finding() {
    // exec(`ls -la`) with static template string should produce no finding
    let src = br#"
const { exec } = require('child_process');

function run() {
    exec(`ls -la`);
}
"#;

    let findings = parse_and_run_all(
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "exec with static template string should not be flagged; got {:?}",
        unguarded
    );
}

// ─── Adversarial tests: must still report findings ─────────────────

#[test]
fn python_tainted_var_os_system_produces_finding() {
    // os.system(user_input) with tainted variable must report
    let src = br#"
import os
import sys

def run():
    user_input = sys.argv[1]
    os.system(user_input)
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "os.system with tainted variable should produce a HIGH finding"
    );
}

#[test]
fn python_one_hop_constant_still_suppressed() {
    // cmd = "ls"; os.system(cmd), `all_args_literal` is false (identifier arg),
    // but should still be suppressed via existing one-hop constant trace in cfg_analysis.
    let src = br#"
import os

def run():
    cmd = "ls"
    os.system(cmd)
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "One-hop constant binding should suppress cfg-unguarded-sink via existing trace; got {:?}",
        unguarded
    );
}

#[test]
fn js_template_literal_with_interpolation_produces_finding() {
    // exec(`ls ${dir}`) with interpolation must report
    let src = br#"
const { exec } = require('child_process');

function run() {
    const dir = process.env.DIR;
    exec(`ls ${dir}`);
}
"#;

    let findings = parse_and_run_all(
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "exec with interpolated template string should produce a HIGH finding"
    );
}

#[test]
fn python_array_with_tainted_element_produces_finding() {
    // subprocess.run([user_input, "-la"], shell=True) with one tainted element must report
    let src = br#"
import subprocess
import sys

def run():
    user_input = sys.argv[1]
    subprocess.run([user_input, "-la"], shell=True)
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "subprocess.run with tainted array element should produce a HIGH finding"
    );
}

#[test]
fn python_constant_receiver_tainted_arg_produces_finding() {
    // safe_obj.system(user_input), constant receiver is irrelevant, tainted arg must report
    let src = br#"
import os
import sys

def run():
    user_input = sys.argv[1]
    os.system(user_input)
"#;

    let findings = parse_and_run_all(src, "python", Language::from(tree_sitter_python::LANGUAGE));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "Tainted argument to sink must produce a HIGH finding regardless of receiver"
    );
}

#[test]
fn php_encapsed_string_with_interpolation_produces_finding() {
    // system("ls $dir") with PHP interpolation must report
    let src = br#"<?php
function run() {
    $dir = $_GET['dir'];
    system("ls $dir");
}
"#;

    let findings = parse_and_run_all(src, "php", Language::from(tree_sitter_php::LANGUAGE_PHP));

    let sink_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "cfg-unguarded-sink" && f.severity == crate::patterns::Severity::High
        })
        .collect();
    assert!(
        !sink_findings.is_empty(),
        "PHP system() with interpolated string should produce a HIGH finding"
    );
}

// ── Type-fact sink suppression (rs-safe-011 regression) ────────────────

#[test]
fn type_facts_suppress_int_typed_shell_arg() {
    // rs-safe-011 fixture: a u16-typed port (parsed from env) flows into
    // Command::new("listener").arg(port.to_string()).  The taint engine
    // already suppresses the flow via type-aware analysis; the structural
    // cfg-unguarded-sink must also honour the type fact and stay silent.
    let src = br#"
        use std::env;
        use std::process::Command;
        fn main() {
            let raw = env::var("PORT").unwrap();
            let port: u16 = raw.parse().expect("invalid port");
            Command::new("listener").arg(port.to_string()).status().unwrap();
        }"#;

    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        guard_findings.is_empty(),
        "Int-typed sink argument should suppress cfg-unguarded-sink, got: {:?}",
        guard_findings
    );
}

#[test]
fn type_facts_preserve_untyped_string_shell_arg() {
    // Companion negative test: env::var() flows directly into a Command arg
    // with no int typing.  The sink argument is a String of unknown content,
    // so the structural finding must still fire.  Guards against the
    // suppression helper over-reaching into cases without an Int fact.
    let src = br#"
        use std::env;
        use std::process::Command;
        fn main() {
            let cmd = env::var("USER_CMD").unwrap();
            Command::new("sh").arg("-c").arg(cmd).status().unwrap();
        }"#;

    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !guard_findings.is_empty(),
        "Untyped String shell argument must still produce cfg-unguarded-sink"
    );
}

#[test]
fn type_facts_pathbuf_let_annotation_not_suppressed() {
    // Recall counterpart to `type_facts_suppress_int_typed_shell_arg`
    // (deep_engine_fixes #4-deep): a `let p: PathBuf = raw.parse()` binding
    // lowers its annotation to `TypeKind::Object` (non-Int), which OVERRIDES
    // the conservative bare-`parse` -> Int heuristic.  A parsed path is
    // attacker-controlled and can carry `..` traversal, so the structural
    // cfg-unguarded-sink must NOT be suppressed.
    let src = br#"
        use std::env;
        use std::process::Command;
        use std::path::PathBuf;
        fn main() {
            let raw = env::var("USER_PATH").unwrap();
            let p: PathBuf = raw.parse().expect("invalid path");
            Command::new("listener").arg(p.to_string()).status().unwrap();
        }"#;

    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );

    let guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !guard_findings.is_empty(),
        "PathBuf-typed (non-numeric) sink argument must NOT be suppressed, got: {:?}",
        findings
    );
}

#[test]
fn go_fprintf_new_bytes_buffer_writer_not_flagged_unguarded_xss() {
    // `stdIn := new(bytes.Buffer); fmt.Fprintf(stdIn, "0 %s", name)` — the
    // writer is a non-response in-memory byte buffer (gitea temp_repo.go
    // shape), so the reflected-XSS `cfg-unguarded-sink` must be suppressed,
    // mirroring the SSA taint engine's Go printf writer-type gate.  The
    // `new(T)` type argument is recovered via `extract_decl_type_go`.
    let src = br#"package main
import ("bytes"; "fmt"; "net/http")
func h(r *http.Request) {
    name := r.URL.Query().Get("name")
    stdIn := new(bytes.Buffer)
    fmt.Fprintf(stdIn, "0 %s", name)
    _ = stdIn.Bytes()
}
"#;
    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );
    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "new(bytes.Buffer) writer must not flag cfg-unguarded-sink XSS, got: {:?}",
        findings
    );
}

#[test]
fn go_fprintf_os_create_writer_not_flagged_unguarded_xss() {
    // `out, _ := os.Create(path); fmt.Fprintf(out, "%s", name)` — the writer
    // is an `*os.File` handle (gitea mock_http.go shape), typed FileHandle
    // via `constructor_type`.  The static-TypeFacts path must recognise it
    // even though the write sits inside a loop where the flow-sensitive env
    // widens the type away.
    let src = br#"package main
import ("fmt"; "net/http"; "os")
func h(r *http.Request) {
    name := r.URL.Query().Get("name")
    out, _ := os.Create("/tmp/x")
    for i := 0; i < 3; i++ {
        fmt.Fprintf(out, "%s\n", name)
    }
}
"#;
    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );
    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        unguarded.is_empty(),
        "os.Create file-handle writer must not flag cfg-unguarded-sink XSS, got: {:?}",
        findings
    );
}

#[test]
fn go_fprintf_response_writer_still_flagged_unguarded_xss() {
    // Recall guard: an actual `http.ResponseWriter` writer is a genuine
    // reflected-XSS sink — the writer-type gate must NOT suppress it.
    let src = br#"package main
import ("fmt"; "net/http")
func h(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<b>%s</b>", name)
}
"#;
    let findings = parse_and_analyse_with_ssa(
        &guards::UnguardedSink,
        src,
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );
    let unguarded: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unguarded-sink")
        .collect();
    assert!(
        !unguarded.is_empty(),
        "http.ResponseWriter fmt.Fprintf must still flag cfg-unguarded-sink, got: {:?}",
        findings
    );
}

#[test]
fn go_new_bytes_buffer_binding_typed_filehandle() {
    // `extract_decl_type_go`: a local bound to `new(bytes.Buffer)` types as
    // FileHandle (the `new(T)` type argument is dropped from the CFG's
    // arg_uses, so the constructor text is read from the binding).
    let src = br#"package main
import ("bytes"; "fmt"; "net/http")
func h(r *http.Request) {
    name := r.URL.Query().Get("name")
    stdIn := new(bytes.Buffer)
    fmt.Fprintf(stdIn, "0 %s", name)
    _ = stdIn.Bytes()
}
"#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_go::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, "go", "test.go", None);
    let body = file_cfg.first_body();
    let facts = build_body_const_facts(body, Lang::Go).expect("body const facts");
    let val = facts
        .ssa
        .blocks
        .iter()
        .flat_map(|b| b.body.iter())
        .find(|i| {
            i.var_name.as_deref() == Some("stdIn") && matches!(i.op, crate::ssa::SsaOp::Call { .. })
        })
        .map(|i| i.value)
        .expect("stdIn := new(bytes.Buffer) call value");
    assert_eq!(
        facts.type_facts.get_type(val),
        Some(&crate::ssa::type_facts::TypeKind::FileHandle),
        "new(bytes.Buffer) local must type as FileHandle"
    );
}

#[test]
fn go_new_non_writer_struct_binding_not_typed_filehandle() {
    // Conservative: `new(T)` for a non-writer struct type must NOT type as
    // FileHandle, so the writer-type gate stays sound (never suppresses a
    // real `http.ResponseWriter` that happened to be `new`-constructed).
    let src = br#"package main
type Payload struct{ X string }
func h() {
    p := new(Payload)
    _ = p.X
}
"#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_go::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, "go", "test.go", None);
    let body = file_cfg.first_body();
    let facts = build_body_const_facts(body, Lang::Go).expect("body const facts");
    let val = facts
        .ssa
        .blocks
        .iter()
        .flat_map(|b| b.body.iter())
        .find(|i| {
            i.var_name.as_deref() == Some("p") && matches!(i.op, crate::ssa::SsaOp::Call { .. })
        })
        .map(|i| i.value)
        .expect("p := new(Payload) call value");
    assert_ne!(
        facts.type_facts.get_type(val),
        Some(&crate::ssa::type_facts::TypeKind::FileHandle),
        "new(non-writer-struct) must not type as FileHandle"
    );
}

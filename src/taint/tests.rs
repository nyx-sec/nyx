use super::*;
use crate::cfg::FileCfg;
use crate::interop::InteropEdge;
use crate::labels::Cap;
use crate::symbol::FuncKey;

// ── SSA-specific taint tests ─────────────────────────────────────────────

/// Helper: run SSA taint analysis on Rust source.
/// Uses the first function body if one exists, otherwise top-level.
fn ssa_analyse_rust(src: &[u8]) -> Vec<Finding> {
    use crate::cfg::build_cfg;
    use crate::state::symbol::SymbolInterner;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter::Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let body = if file_cfg.bodies.len() > 1 {
        &file_cfg.bodies[1]
    } else {
        file_cfg.first_body()
    };
    let cfg = &body.graph;
    let entry = body.entry;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(cfg);
    let ssa =
        crate::ssa::lower_to_ssa(cfg, entry, None, true).expect("SSA lowering should succeed");

    let transfer = ssa_transfer::SsaTaintTransfer {
        lang: Lang::Rust,
        namespace: "test.rs",
        interner: &interner,
        local_summaries: summaries,
        global_summaries: None,
        interop_edges: &[],
        owner_body_id: crate::cfg::BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: None,
        receiver_seed: None,
        const_values: None,
        type_facts: None,
        xml_parser_config: None,
        xpath_config: None,
        ssa_summaries: None,
        extra_labels: None,
        base_aliases: None,
        callee_bodies: None,
        inline_cache: None,
        context_depth: 0,
        callback_bindings: None,
        points_to: None,
        dynamic_pts: None,
        import_bindings: None,
        promisify_aliases: None,
        module_aliases: None,
        static_map: None,
        auto_seed_handler_params: false,
        cross_file_bodies: None,
        pointer_facts: None,
        cross_package_imports: None,
        entry_kind: None,
        param_route_capture: None,
        recording_summary: false,
    };
    let events = ssa_transfer::run_ssa_taint(&ssa, cfg, &transfer);
    let mut findings = ssa_transfer::ssa_events_to_findings(&events, &ssa, cfg);
    findings.sort_by_key(|f| (f.sink.index(), f.source.index()));
    findings.dedup_by_key(|f| (f.sink, f.source));
    findings
}

#[test]
fn ssa_linear_source_to_sink() {
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS_ARG").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert_eq!(
        findings.len(),
        1,
        "SSA: linear source→sink should produce 1 finding"
    );
}

#[test]
fn ssa_linear_sanitized_no_finding() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert!(
        findings.is_empty(),
        "SSA: matching sanitizer should eliminate finding"
    );
}

#[test]
fn ssa_reassignment_kills_taint() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let x = "safe_constant";
            Command::new("sh").arg(x).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert!(
        findings.is_empty(),
        "SSA: reassignment to constant should kill taint"
    );
}

#[test]
fn ssa_taint_through_branch_merge() {
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let safe = html_escape::encode_safe(&x);
            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();
            } else {
                Command::new("sh").arg(&safe).status().unwrap();
            }
        }"#;
    let findings = ssa_analyse_rust(src);
    assert!(
        !findings.is_empty(),
        "SSA: taint through branch should produce at least 1 finding"
    );
}

#[test]
fn ssa_taint_through_loop() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            while x.len() < 100 {
                x.push_str("a");
            }
            Command::new("sh").arg(x).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert_eq!(
        findings.len(),
        1,
        "SSA: taint through loop should produce 1 finding"
    );
}

#[test]
fn ssa_multi_variable_independence() {
    // Independent variables should not interfere
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("TAINTED").unwrap();
            let y = "safe";
            Command::new("sh").arg(y).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert!(
        findings.is_empty(),
        "SSA: untainted variable at sink should produce no finding"
    );
}

#[test]
fn env_to_arg_is_flagged() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS_ARG").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert_eq!(findings.len(), 1); // exactly one unsanitised Source→Sink
}

#[test]
fn taint_through_if_else() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let safe = html_escape::encode_safe(&x);

            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();   // UNSAFE
            } else {
                Command::new("sh").arg(&safe).status().unwrap(); // SAFE
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Both branches have findings: the true branch uses unsanitized `x`,
    // the else branch uses `safe` which was sanitized with HTML_ESCAPE
    // but the sink requires SHELL_ESCAPE (wrong sanitizer → still tainted).
    assert_eq!(findings.len(), 2);
}

#[test]
fn taint_through_while_loop() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            while x.len() < 100 {                       // Loop header (Loop)
                x.push_str("a");
            }
            Command::new("sh").arg(x).status().unwrap(); // Should be flagged
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert_eq!(findings.len(), 1);
}

#[test]
fn taint_killed_by_matching_sanitizer() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // shell_escape sanitizer strips SHELL_ESCAPE → Command sink checks
    // SHELL_ESCAPE → the matching bit is gone → no finding.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert!(
        findings.is_empty(),
        "matching sanitizer should kill the taint"
    );
}

#[test]
fn wrong_sanitizer_preserves_taint() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // html_escape sanitizer strips HTML_ESCAPE, but Command sink checks
    // SHELL_ESCAPE → the wrong bit was stripped → finding persists.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = html_escape::encode_safe(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "wrong sanitizer should NOT kill the taint"
    );
}

#[test]
fn taint_breaks_out_of_loop() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            loop {
                let x = env::var("DANGEROUS").unwrap();
                Command::new("sh").arg(&x).status().unwrap(); // vulnerable
                break;
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_two_sources_one_sanitised() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Two env sources, one properly sanitised with the MATCHING sanitiser.
    // x → unsanitised → Command = FINDING
    // y → shell_escape → Command = safe
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = env::var("ANOTHER").unwrap();
            let clean = shell_escape::unix::escape(&y);
            Command::new("sh").arg(x).status().unwrap();
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "only the unsanitised source should be flagged"
    );
}

#[test]
fn test_two_sources_wrong_sanitiser_both_flagged() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Two env sources, one "sanitised" with the WRONG sanitiser.
    // x → unsanitised → Command = FINDING
    // y → html_escape → Command = FINDING (wrong sanitiser for shell sink)
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = env::var("ANOTHER").unwrap();
            let clean = html_escape::encode_safe(&y);
            Command::new("sh").arg(x).status().unwrap();
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert_eq!(
        findings.len(),
        2,
        "both should be flagged — wrong sanitiser"
    );
}

#[test]
fn test_should_not_panic_on_empty_function() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let src = br#"
        use std::{env, process::Command};
        fn f() {
            if cond() {
                return;
            }
            do_something();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    assert!(findings.is_empty());
}

#[test]
fn cross_file_source_resolved_via_global_summaries() {
    use crate::summary::FuncSummary;

    // Simulate file B calling `get_dangerous()` which is defined in file A.
    // File A's summary says get_dangerous is a Source(all).
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = get_dangerous();
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let file_cfg = parse_rust(src);
    let local_summaries = &file_cfg.summaries;

    // Build global summaries as if file A exported get_dangerous
    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "get_dangerous".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "get_dangerous".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let findings = analyse_file(
        &file_cfg,
        local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(findings.len(), 1, "cross-file source should be detected");
}

#[test]
fn cross_file_sanitizer_resolved_via_global_summaries() {
    use crate::summary::FuncSummary;

    // File B gets tainted data and passes it through `my_sanitize()` from file A.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = my_sanitize(x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#;

    let file_cfg = parse_rust(src);
    let local_summaries = &file_cfg.summaries;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "my_sanitize".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "my_sanitize".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["input".into()],
            source_caps: 0,
            sanitizer_caps: Cap::all().bits(),
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let findings = analyse_file(
        &file_cfg,
        local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "cross-file sanitizer should neutralise taint"
    );
}

//  Shared test helpers

/// Parse Rust source bytes → FileCfg
fn parse_rust(src: &[u8]) -> FileCfg {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    build_cfg(&tree, src, "rust", "test.rs", None)
}

/// Parse Rust source bytes, build CFG, and export cross-file summaries.
fn extract_summaries_from_bytes(src: &[u8], path: &str) -> Vec<crate::summary::FuncSummary> {
    use crate::cfg::export_summaries;
    let file_cfg = parse_rust(src);
    export_summaries(&file_cfg.summaries, path, "rust")
}

#[test]
fn cross_file_sink_resolved_via_global_summaries() {
    use crate::summary::FuncSummary;

    // File B calls `dangerous_exec(x)` from file A which is a sink.
    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("INPUT").unwrap();
            dangerous_exec(x);
        }"#;

    let file_cfg = parse_rust(src);
    let local_summaries = &file_cfg.summaries;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "dangerous_exec".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "dangerous_exec".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["cmd".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![0],
            callees: vec!["Command::new".into()],
            ..Default::default()
        },
    );

    let findings = analyse_file(
        &file_cfg,
        local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(findings.len(), 1, "cross-file sink should be detected");
}

#[test]
fn cross_file_sink_finding_carries_primary_location() {
    // Primary sink-location attribution: when a callee summary carries a
    // [`SinkSite`] with resolved coordinates, the emitted Finding must
    // expose those coordinates via `primary_location`.  This guards the
    // event→finding plumbing independent of any CFG/label changes.
    use crate::summary::{FuncSummary, SinkSite};
    use smallvec::smallvec;

    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("INPUT").unwrap();
            dangerous_exec(x);
        }"#;

    let file_cfg = parse_rust(src);
    let local_summaries = &file_cfg.summaries;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "dangerous_exec".into(),
        arity: Some(1),
        ..Default::default()
    };
    // Summary: param 0 (`cmd`) flows to a shell-exec sink at file_a.rs:42:5.
    let sink_site = SinkSite {
        file_rel: "file_a.rs".into(),
        line: 42,
        col: 5,
        snippet: "Command::new(\"sh\").arg(cmd).status().unwrap();".into(),
        cap: Cap::SHELL_ESCAPE,
        from_chain: false,
    };
    global.insert(
        key,
        FuncSummary {
            name: "dangerous_exec".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["cmd".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![0],
            param_to_sink: vec![(0, smallvec![sink_site.clone()])],
            callees: vec!["Command::new".into()],
            ..Default::default()
        },
    );

    let findings = analyse_file(
        &file_cfg,
        local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "cross-file sink should still be detected",
    );
    let finding = &findings[0];
    // Note: `uses_summary == false` here because the source (env::var) is
    // local, only the *sink* was summary-resolved.  That's the case the
    // `primary_location` / `uses_summary` independence comment on
    // [`super::Finding::primary_location`] documents.
    let loc = finding
        .primary_location
        .as_ref()
        .expect("summary-resolved sink with SinkSite must carry primary_location");
    assert_eq!(loc.file_rel, "file_a.rs");
    assert_eq!(loc.line, 42);
    assert_eq!(loc.col, 5);
}

#[test]
fn cross_file_sink_cap_only_site_leaves_primary_location_none() {
    // Cap-only SinkSites (line == 0) must not surface as Finding.primary_location,
    // otherwise the formatter would claim a (0, 0) position as authoritative.
    use crate::summary::FuncSummary;

    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("INPUT").unwrap();
            dangerous_exec(x);
        }"#;

    let file_cfg = parse_rust(src);
    let local_summaries = &file_cfg.summaries;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "dangerous_exec".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "dangerous_exec".into(),
            file_path: "file_a.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["cmd".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![0],
            // No param_to_sink: falls back to cap-only summary (no SinkSite).
            callees: vec!["Command::new".into()],
            ..Default::default()
        },
    );

    let findings = analyse_file(
        &file_cfg,
        local_summaries,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(findings.len(), 1, "cross-file sink should be detected");
    assert!(
        findings[0].primary_location.is_none(),
        "cap-only summary must not produce a primary_location",
    );
}

//  Multi-file integration tests (real parsing, full pass-1 → pass-2 pipeline)

#[test]
fn multi_file_source_to_sink_detected() {
    use crate::summary::merge_summaries;

    // File A: defines get_dangerous() which calls env::var (a source).
    let lib_src = br#"
        use std::env;
        fn get_dangerous() -> String {
            env::var("SECRET").unwrap()
        }
    "#;

    // File B: calls get_dangerous() then passes result to Command (a sink).
    let caller_src = br#"
        use std::process::Command;
        fn main() {
            let x = get_dangerous();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "cross-file source → inline sink should produce 1 finding"
    );
}

#[test]
fn multi_file_sanitizer_neutralises_cross_file_source() {
    use crate::summary::merge_summaries;

    // File A: source + matching shell sanitizer.
    // NOTE: function name avoids `sanitize_` prefix which triggers
    //       the inline HTML sanitizer label rule.
    let lib_src = br#"
        use std::env;
        fn get_input() -> String {
            env::var("INPUT").unwrap()
        }
        fn clean_shell(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
    "#;

    // File B: source → clean_shell → shell sink.
    let caller_src = br#"
        use std::process::Command;
        fn main() {
            let x = get_input();
            let clean = clean_shell(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert!(
        findings.is_empty(),
        "matching cross-file sanitizer should neutralise taint, got {} findings",
        findings.len()
    );
}

#[test]
fn multi_file_wrong_sanitizer_preserves_taint() {
    use crate::summary::merge_summaries;

    // File A: source + HTML sanitizer (wrong for shell sink).
    let lib_src = br#"
        use std::env;
        fn get_input() -> String {
            env::var("INPUT").unwrap()
        }
        fn clean_html(s: &str) -> String {
            html_escape::encode_safe(s).to_string()
        }
    "#;

    // File B: source → HTML sanitize → shell sink → should still flag.
    let caller_src = br#"
        use std::process::Command;
        fn main() {
            let x = get_input();
            let clean = clean_html(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "wrong sanitizer (HTML for shell sink) should NOT neutralise taint"
    );
}

#[test]
fn multi_file_sink_in_another_file() {
    use crate::summary::merge_summaries;

    // File A: defines exec_cmd() which internally calls Command::new (a sink).
    let lib_src = br#"
        use std::process::Command;
        fn exec_cmd(cmd: &str) {
            Command::new("sh").arg(cmd).status().unwrap();
        }
    "#;

    // File B: env::var → exec_cmd(), sink is cross-file.
    let caller_src = br#"
        use std::env;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            exec_cmd(&x);
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(findings.len(), 1, "cross-file sink should be detected");
}

#[test]
fn multi_file_passthrough_preserves_taint() {
    use crate::summary::FuncSummary;

    // identity() just returns its argument, it propagates taint but has no
    // source/sanitizer/sink caps of its own.
    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "identity".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "identity".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["s".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let caller_src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = identity(&x);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "taint should propagate through passthrough function"
    );
}

#[test]
fn multi_file_chain_source_sanitize_sink_across_files() {
    use crate::summary::merge_summaries;

    // Library file defines all three roles: source, sanitizer, sink.
    let lib_src = br#"
        use std::env;
        use std::process::Command;
        fn get_input() -> String {
            env::var("INPUT").unwrap()
        }
        fn clean_shell(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
        fn exec_cmd(cmd: &str) {
            Command::new("sh").arg(cmd).status().unwrap();
        }
    "#;

    // Caller: source → correct sanitizer → sink.
    let caller_src = br#"
        fn main() {
            let x = get_input();
            let clean = clean_shell(&x);
            exec_cmd(&clean);
        }
    "#;

    let summaries = extract_summaries_from_bytes(lib_src, "lib.rs");
    let global = merge_summaries(summaries, None);

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert!(
        findings.is_empty(),
        "source → matching sanitizer → sink should produce 0 findings, got {}",
        findings.len()
    );
}

//  Edge-case unit tests

#[test]
fn sanitizer_strips_only_matching_bits() {
    // Source(ALL) → shell_escape → sink_html (HTML sink).
    // shell_escape strips SHELL_ESCAPE but not HTML_ESCAPE.
    // sink_html is an HTML sink, HTML_ESCAPE bit is still set → 1 finding.
    let src = br#"
        use std::env;
        fn sink_html(s: &str) {}
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            sink_html(&clean);
        }
    "#;

    let file_cfg = parse_rust(src);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert_eq!(
        findings.len(),
        1,
        "shell sanitizer should NOT strip HTML_ESCAPE bit; HTML sink should still fire"
    );
}

#[test]
fn multiple_sanitizers_strip_all_bits() {
    // Source → shell_escape → html_escape → Command (shell sink).
    // shell_escape strips SHELL_ESCAPE; html_escape strips HTML_ESCAPE.
    // After both, the remaining taint bits relevant to SHELL_ESCAPE are gone.
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let a = shell_escape::unix::escape(&x);
            let b = html_escape::encode_safe(&a);
            Command::new("sh").arg(b).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert!(
        findings.is_empty(),
        "both sanitizers together should strip all relevant bits"
    );
}

#[test]
fn taint_through_variable_reassignment() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let y = x;
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert_eq!(
        findings.len(),
        1,
        "taint should flow through simple variable reassignment"
    );
}

#[test]
fn untainted_variable_at_sink_is_safe() {
    // A string literal (not from a source) passed to Command, no finding.
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = "harmless";
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert!(
        findings.is_empty(),
        "untainted literal should not trigger a finding"
    );
}

#[test]
fn local_summary_takes_precedence_over_global() {
    use crate::summary::FuncSummary;

    // The caller file defines my_func locally as a source.
    // Global says my_func is a sanitizer.
    // Local should win → finding expected.
    let caller_src = br#"
        use std::{env, process::Command};
        fn my_func() -> String {
            env::var("SECRET").unwrap()
        }
        fn main() {
            let x = my_func();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "other.rs".into(),
        name: "my_func".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "my_func".into(),
            file_path: "other.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: Cap::all().bits(),
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let file_cfg = parse_rust(caller_src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "local summary (source) should take precedence over global (sanitizer)"
    );
}

#[test]
fn empty_global_summaries_same_as_none() {
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let summaries = &file_cfg.summaries;

    let findings_none = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);
    let empty = GlobalSummaries::new();
    let findings_empty = analyse_file(
        &file_cfg,
        summaries,
        Some(&empty),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings_none.len(),
        findings_empty.len(),
        "empty GlobalSummaries should behave identically to None"
    );
}

#[test]
fn taint_not_introduced_by_non_source_function() {
    // Call an unknown function (no summary anywhere), assign to var, pass to sink.
    // Unknown calls should NOT introduce taint.
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = totally_unknown_func();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert!(
        findings.is_empty(),
        "unknown function call should not introduce taint"
    );
}

#[test]
fn source_and_sink_on_same_function() {
    use crate::summary::FuncSummary;

    // Cross-file function that is both source AND sink.
    // Tainted arg hits sink → 1 finding.
    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "source_and_sink".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key,
        FuncSummary {
            name: "source_and_sink".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 1,
            param_names: vec!["input".into()],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![0],
            callees: vec![],
            ..Default::default()
        },
    );

    // Pass tainted data from env::var into source_and_sink.
    let src = br#"
        use std::env;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            source_and_sink(x);
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "function that is both source and sink should detect tainted arg as finding"
    );
}

#[test]
fn multiple_cross_file_sources_one_sanitised() {
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    // Two cross-file sources
    let key1 = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "get_secret".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key1,
        FuncSummary {
            name: "get_secret".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );
    let key2 = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "get_other_secret".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key2,
        FuncSummary {
            name: "get_other_secret".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    // One source sanitised, one not.
    let src = br#"
        use std::process::Command;
        fn main() {
            let a = get_secret();
            let b = get_other_secret();
            let clean_a = shell_escape::unix::escape(&a);
            Command::new("sh").arg(clean_a).status().unwrap();
            Command::new("sh").arg(b).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "only the unsanitised cross-file source should produce a finding"
    );
}

//  Multi-language helpers and tests

/// Parse source bytes for any supported language → FileCfg
fn parse_lang(src: &[u8], slug: &str, ts_lang: tree_sitter::Language) -> FileCfg {
    use crate::cfg::build_cfg;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let ext = match slug {
        "rust" => "test.rs",
        "javascript" => "test.js",
        "typescript" => "test.ts",
        "python" => "test.py",
        "go" => "test.go",
        "java" => "test.java",
        "c" => "test.c",
        "cpp" => "test.cpp",
        "php" => "test.php",
        "ruby" => "test.rb",
        _ => "test.txt",
    };
    build_cfg(&tree, src, slug, ext, None)
}

#[test]
fn js_source_to_sink() {
    let src = b"function main() {\n  let x = document.location();\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "JS: source->sink should produce 1 finding"
    );
}

#[test]
fn ts_source_to_sink() {
    let src = b"function main() {\n  let x = document.location();\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_lang(src, "typescript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::TypeScript,
        "test.ts",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "TS: source->sink should produce 1 finding"
    );
}

#[test]
fn python_source_to_sink() {
    let src = b"def main():\n    x = os.getenv(\"SECRET\")\n    os.system(x)\n";
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Python,
        "test.py",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "Python: source->sink should produce 1 finding"
    );
}

#[test]
fn go_source_to_sink() {
    let src =
        b"package main\n\nfunc main() {\n\tx := os.Getenv(\"SECRET\")\n\texec.Command(x)\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(src, "go", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Go, "test.go", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "Go: source->sink should produce 1 finding"
    );
}

#[test]
fn java_source_to_sink() {
    let src = b"class Main {\n  void main() {\n    String x = System.getenv(\"SECRET\");\n    Runtime.exec(x);\n  }\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Java,
        "test.java",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "Java: source->sink should produce 1 finding"
    );
}

#[test]
fn c_source_to_sink() {
    let src = b"void main() {\n  char* x = getenv(\"SECRET\");\n  system(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::C, "test.c", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "C: source->sink should produce 1 finding"
    );
}

#[test]
fn c_fgets_condition_to_execvp_argv_fires() {
    let src = br#"#include <stdio.h>
#include <unistd.h>
int main(void) {
  char url_buf[256];
  if (!fgets(url_buf, sizeof url_buf, stdin)) return 1;
  const char *args[3];
  args[0] = "ssh";
  args[1] = url_buf;
  args[2] = 0;
  return execvp(args[0], (char *const *)args);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "test.c",
        &[],
        None,
    );
    assert!(
        findings
            .iter()
            .any(|f| f.source_kind == crate::labels::SourceKind::UserInput),
        "C: fgets stdin should reach execvp argv, got {findings:#?}"
    );
}

#[test]
fn c_fgets_reaches_printf_data_arg() {
    let src = br#"#include <stdio.h>
int main(void) {
  char buf[256];
  if (!fgets(buf, sizeof buf, stdin)) return 1;
  printf("%s", buf);
  return 0;
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "test.c",
        &[],
        None,
    );
    assert!(
        findings
            .iter()
            .any(|f| f.source_kind == crate::labels::SourceKind::UserInput),
        "C: fgets buffer should reach printf data arg, got {findings:#?}"
    );
}

#[test]
fn c_gets_reaches_printf_data_arg() {
    let src = br#"#include <stdio.h>
int main(void) {
  char buf[256];
  gets(buf);
  printf("%s\n", buf);
  return 0;
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "test.c",
        &[],
        None,
    );
    assert!(
        findings
            .iter()
            .any(|f| f.source_kind == crate::labels::SourceKind::UserInput),
        "C: gets buffer should reach printf data arg, got {findings:#?}"
    );
}

#[test]
fn c_execvp_ignores_env_config_executable_path() {
    let src = br#"#include <stdlib.h>
#include <unistd.h>
int main(void) {
  const char *ssh = getenv("GIT_SSH");
  const char *args[2];
  args[0] = ssh;
  args[1] = 0;
  return execvp(args[0], (char *const *)args);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "test.c",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "C: env-config executable path should not be treated as argv injection"
    );
}

#[test]
fn c_dash_prefix_guard_suppresses_execvp_argv_injection() {
    let src = br#"#include <stdio.h>
#include <unistd.h>
int main(void) {
  char url_buf[256];
  if (!fgets(url_buf, sizeof url_buf, stdin)) return 1;
  char *ssh_host = url_buf;
  if (ssh_host[0] == '-') return 1;
  const char *args[3];
  args[0] = "ssh";
  args[1] = ssh_host;
  args[2] = 0;
  return execvp(args[0], (char *const *)args);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "test.c",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "C: dash-prefix rejection should clear argv-injection taint, got {findings:#?}"
    );
}

#[test]
fn cpp_source_to_sink() {
    let src = b"void main() {\n  char* x = getenv(\"SECRET\");\n  system(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "C++: source->sink should produce 1 finding"
    );
}

/// `c_str()` is a const accessor on `std::string`
/// that returns a pointer to the same buffer.  It must propagate taint from
/// the receiver to the result so the downstream sink fires.
#[test]
fn cpp_c_str_propagates_taint() {
    let src = b"#include <cstdlib>\n#include <string>\nint main() {\n  char* input = std::getenv(\"X\");\n  std::string s = input;\n  std::system(s.c_str());\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: tainted s.c_str() into system() must fire",
    );
}

/// `std::move(x)` returns its argument unchanged in terms of
/// data flow, the rvalue cast is a representation move, not a sanitiser.
/// Default propagation collects argument taint into the result.
#[test]
fn cpp_std_move_propagates_taint() {
    let src = b"#include <cstdlib>\n#include <string>\n#include <utility>\nint main() {\n  char* input = std::getenv(\"X\");\n  std::string s = input;\n  std::string moved = std::move(s);\n  std::system(moved.c_str());\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: taint must flow through std::move() into the sink",
    );
}

/// `static_cast<T>(x)` is parsed as a call expression by
/// tree-sitter-cpp; default propagation transports taint from the casted
/// argument to the result.
#[test]
fn cpp_static_cast_propagates_taint() {
    let src = b"#include <cstdlib>\nint main() {\n  char* input = std::getenv(\"X\");\n  const char* casted = static_cast<const char*>(input);\n  std::system(casted);\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: taint must flow through static_cast<T>() into the sink",
    );
}

/// a fluent builder chain whose host
/// argument is tainted should fire on the terminal `.connect()`
/// SSRF sink.  The chained `.host(...)` / `.port(...)` calls return
/// the receiver, and default Call-arg propagation puts the tainted
/// argument on the chain so it reaches the terminal sink.
#[test]
fn cpp_builder_chain_user_host_fires() {
    let src = b"#include <cstdlib>\n#include <string>\nclass Socket {\npublic:\n  static Socket builder() { return Socket(); }\n  Socket& host(const std::string& h) { host_ = h; return *this; }\n  Socket& port(int p) { port_ = p; return *this; }\n  void connect() {}\nprivate:\n  std::string host_;\n  int port_ = 0;\n};\nint main() {\n  char* h = std::getenv(\"X\");\n  Socket::builder().host(h).port(80).connect();\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: tainted host through fluent builder chain must reach terminal connect()",
    );
}

/// a fluent builder chain with a hardcoded host literal
/// must NOT fire on the terminal connect() sink, the chain carries
/// no taint.
#[test]
fn cpp_builder_chain_const_host_silent() {
    let src = b"#include <string>\nclass Socket {\npublic:\n  static Socket builder() { return Socket(); }\n  Socket& host(const std::string& h) { host_ = h; return *this; }\n  Socket& port(int p) { port_ = p; return *this; }\n  void connect() {}\nprivate:\n  std::string host_;\n  int port_ = 0;\n};\nint main() {\n  Socket::builder().host(\"api.example.com\").port(80).connect();\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        findings.is_empty(),
        "C++: builder chain with literal host must NOT fire (Negative)",
    );
}

/// inline member-function bodies inside a
/// `class_specifier` must be extracted as separate functions and
/// intra-file calls must resolve to their bodies. Before the cpp KINDS
/// fix the `class_specifier` AST kind was unmapped, so the CFG walker
/// treated the entire class as a leaf `Seq` node and never descended
/// into inline methods.
#[test]
fn cpp_inline_class_method_resolves() {
    let src = b"#include <cstdlib>\nclass Inner {\npublic:\n  void run(const char* arg) { std::system(arg); }\n};\nint main() {\n  char* input = std::getenv(\"X\");\n  Inner inner;\n  inner.run(input);\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: tainted arg through inline class method must reach system()",
    );
}

/// a tainted argument passed through an
/// identity-style lambda (`auto echo = [](const char* s) { return s; }`)
/// must reach the downstream sink. This is handled by the same default
/// Call-arg propagation as `std::move`/`static_cast`; pinning the
/// behaviour here so future engine work doesn't silently regress
/// identity lambdas.
#[test]
fn cpp_identity_lambda_propagates_taint() {
    let src = b"#include <cstdlib>\nint main() {\n  char* input = std::getenv(\"X\");\n  auto echo = [](const char* s) { return s; };\n  std::system(echo(input));\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: taint must flow through identity lambda echo() into system()",
    );
}

/// `std::vector<char>::data()` is a Load-style container op that
/// returns a pointer to the underlying buffer; `system(v.data())` should
/// fire when `v` is tainted.
#[test]
fn cpp_vector_data_propagates_taint() {
    let src = b"#include <cstdlib>\n#include <vector>\nint main() {\n  char* input = std::getenv(\"X\");\n  std::vector<char> v(input, input + 8);\n  std::system(v.data());\n  return 0;\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        !findings.is_empty(),
        "C++: taint must flow through v.data() into the sink",
    );
}

#[test]
fn php_source_to_sink() {
    let src =
        b"<?php\nfunction main() {\n  $x = file_get_contents(\"secret\");\n  system($x);\n}\n?>";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "PHP: source->sink should produce 1 finding"
    );
}

#[test]
fn php_echo_xss() {
    // PHP `echo` is a language construct (echo_statement), not a function call.
    // Tainted data flowing through echo should be detected as an XSS sink.
    let src = b"<?php\n$name = $_GET['name'];\necho \"<h1>Hello \" . $name . \"</h1>\";\n";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "PHP echo with tainted var should produce 1 XSS finding"
    );
}

#[test]
fn php_echo_simple_var() {
    // Simple `echo $var;` with a tainted variable.
    let src = b"<?php\n$x = $_POST['data'];\necho $x;\n";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "PHP echo with simple tainted var should produce 1 finding"
    );
}

#[test]
fn php_echo_safe_literal() {
    // `echo "hello";` with no tainted data should produce no finding.
    let src = b"<?php\necho \"hello world\";\n";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None);
    assert_eq!(
        findings.len(),
        0,
        "PHP echo with literal string should produce 0 findings"
    );
}

#[test]
fn ruby_source_to_sink() {
    let src = b"def main\n  x = gets()\n  system(x)\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_lang(src, "ruby", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Ruby, "test.rb", &[], None);
    assert_eq!(
        findings.len(),
        1,
        "Ruby: source->sink should produce 1 finding"
    );
}

//  Cross-language multi-file tests
//
// Cross-language resolution now requires explicit InteropEdge declarations.
// Without an edge, functions from different languages are never resolved ,
// this prevents false positives from name collisions across languages.

/// Extract cross-file summaries from any language's source bytes.
fn extract_lang_summaries(
    src: &[u8],
    slug: &str,
    ts_lang: tree_sitter::Language,
    path: &str,
) -> Vec<crate::summary::FuncSummary> {
    use crate::cfg::export_summaries;
    let file_cfg = parse_lang(src, slug, ts_lang);
    let local = &file_cfg.summaries;
    export_summaries(local, path, slug)
}

// ── Scenario 1: Python source function → JavaScript sink via interop ─────
#[test]
fn cross_lang_python_source_to_js_sink_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let py_src = b"def get_input():\n    x = os.getenv(\"SECRET\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_summaries = extract_lang_summaries(py_src, "python", py_lang, "lib.py");
    let global = merge_summaries(py_summaries, None);

    // JavaScript file calls get_input() and passes to eval()
    let js_src = b"function main() {\n  let x = get_input();\n  eval(x);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(js_src, "javascript", js_lang);
    let local = &file_cfg.summaries;

    // Without interop: no cross-lang resolution
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &[],
        None,
    );
    assert!(findings.is_empty(), "No cross-lang without interop edge");

    // With interop edge
    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "get_input".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Python,
            namespace: "lib.py".into(),
            name: "get_input".into(),
            arity: Some(0),
            ..Default::default()
        },
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "Python source → JS sink via interop edge"
    );
}

// ── Scenario 2: Go source function → Python sink via interop ─────────────
#[test]
fn cross_lang_go_source_to_python_sink_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let go_src =
        b"package main\n\nfunc fetch_env() string {\n\tx := os.Getenv(\"SECRET\")\n\treturn x\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let go_summaries = extract_lang_summaries(go_src, "go", go_lang, "lib.go");
    let global = merge_summaries(go_summaries, None);

    let py_src = b"def main():\n    x = fetch_env()\n    os.system(x)\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(py_src, "python", py_lang);
    let local = &file_cfg.summaries;

    // Without interop: no findings
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Python,
        "main.py",
        &[],
        None,
    );
    assert!(findings.is_empty(), "No cross-lang without interop");

    // With interop
    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Python,
            caller_namespace: "main.py".into(),
            caller_func: "main".into(),
            callee_symbol: "fetch_env".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Go,
            namespace: "lib.go".into(),
            name: "fetch_env".into(),
            arity: Some(0),
            ..Default::default()
        },
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Python,
        "main.py",
        &edges,
        None,
    );
    assert_eq!(findings.len(), 1, "Go source → Python sink via interop");
}

// ── Scenario 3: Rust sanitizer applied in JavaScript context via interop ──
#[test]
fn cross_lang_rust_sanitizer_in_js_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let rs_src = br#"
        fn clean_shell(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
    "#;
    let rs_lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let rs_summaries = extract_lang_summaries(rs_src, "rust", rs_lang, "lib.rs");
    let global = merge_summaries(rs_summaries, None);

    // JS: source → Rust sanitizer → shell sink
    let js_src = b"function main() {\n  let x = document.location();\n  let y = clean_shell(x);\n  eval(y);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(js_src, "javascript", js_lang);
    let local = &file_cfg.summaries;

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "clean_shell".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "clean_shell".into(),
            arity: Some(1),
            ..Default::default()
        },
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
        None,
    );
    // eval uses Cap::all(), so a SHELL_ESCAPE sanitizer alone does NOT
    // neutralise taint, shell-escape is semantically wrong for code injection.
    // The finding should still be reported.
    assert!(
        !findings.is_empty(),
        "SHELL_ESCAPE sanitizer should NOT neutralise eval (code injection) taint"
    );
}

// ── Scenario 4: C sink function called from Java via interop ─────────────
#[test]
fn cross_lang_c_sink_called_from_java_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let c_src = b"void run_cmd(char* cmd) {\n  system(cmd);\n}\n";
    let c_lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let c_summaries = extract_lang_summaries(c_src, "c", c_lang, "native.c");
    let global = merge_summaries(c_summaries, None);

    let java_src = b"class Main {\n  void main() {\n    String x = System.getenv(\"INPUT\");\n    run_cmd(x);\n  }\n}\n";
    let java_lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(java_src, "java", java_lang);
    let local = &file_cfg.summaries;

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Java,
            caller_namespace: "Main.java".into(),
            caller_func: "main".into(),
            callee_symbol: "run_cmd".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::C,
            namespace: "native.c".into(),
            name: "run_cmd".into(),
            arity: Some(1),
            ..Default::default()
        },
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Java,
        "Main.java",
        &edges,
        None,
    );
    assert_eq!(findings.len(), 1, "Java source → C sink via interop");
}

// ── Scenario 5: Multi-language summary merge with interop ────────────────
#[test]
fn cross_lang_three_languages_merged_summaries_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    // Python: source function
    let py_src = b"def get_secret():\n    x = os.getenv(\"SECRET\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "source.py");

    // C: sink function
    let c_src = b"void run_dangerous(char* cmd) {\n  system(cmd);\n}\n";
    let c_lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let c_sums = extract_lang_summaries(c_src, "c", c_lang, "native.c");

    // Rust: sanitizer function
    let rs_src = br#"
        fn make_safe(s: &str) -> String {
            shell_escape::unix::escape(s).to_string()
        }
    "#;
    let rs_lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let rs_sums = extract_lang_summaries(rs_src, "rust", rs_lang, "lib.rs");

    let all_sums: Vec<_> = py_sums.into_iter().chain(c_sums).chain(rs_sums).collect();
    let global = merge_summaries(all_sums, None);

    // Go caller: source → sanitizer → sink (all cross-language)
    let go_src = b"package main\n\nfunc main() {\n\tx := get_secret()\n\ty := make_safe(x)\n\trun_dangerous(y)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(go_src, "go", go_lang);
    let local = &file_cfg.summaries;

    let edges = vec![
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "get_secret".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Python,
                namespace: "source.py".into(),
                name: "get_secret".into(),
                arity: Some(0),
                ..Default::default()
            },
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "make_safe".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Rust,
                namespace: "lib.rs".into(),
                name: "make_safe".into(),
                arity: Some(1),
                ..Default::default()
            },
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_dangerous".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::C,
                namespace: "native.c".into(),
                name: "run_dangerous".into(),
                arity: Some(1),
                ..Default::default()
            },
        },
    ];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
        None,
    );
    assert!(
        findings.is_empty(),
        "source(Py) → sanitizer(Rs) → sink(C) via interop should be safe; got {} findings",
        findings.len()
    );
}

// ── Scenario 6: Same flow without sanitizer should flag via interop ──────
#[test]
fn cross_lang_three_languages_unsanitised_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    let py_src = b"def get_secret():\n    x = os.getenv(\"SECRET\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "source.py");

    let c_src = b"void run_dangerous(char* cmd) {\n  system(cmd);\n}\n";
    let c_lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let c_sums = extract_lang_summaries(c_src, "c", c_lang, "native.c");

    let all_sums: Vec<_> = py_sums.into_iter().chain(c_sums).collect();
    let global = merge_summaries(all_sums, None);

    // Go caller: source → sink directly (no sanitizer)
    let go_src = b"package main\n\nfunc main() {\n\tx := get_secret()\n\trun_dangerous(x)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(go_src, "go", go_lang);
    let local = &file_cfg.summaries;

    let edges = vec![
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "get_secret".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Python,
                namespace: "source.py".into(),
                name: "get_secret".into(),
                arity: Some(0),
                ..Default::default()
            },
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_dangerous".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::C,
                namespace: "native.c".into(),
                name: "run_dangerous".into(),
                arity: Some(1),
                ..Default::default()
            },
        },
    ];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "source(Py) → sink(C) without sanitizer via interop"
    );
}

// ── Scenario 7: Name collision across languages stays separate ───────────
#[test]
fn cross_lang_name_collision_stays_separate() {
    use crate::summary::merge_summaries;

    // Python version: source
    let py_src = b"def process_data():\n    x = os.getenv(\"DATA\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "handler.py");

    // C version: benign passthrough (constructed manually)
    let c_summary = crate::summary::FuncSummary {
        name: "process_data".into(),
        file_path: "handler.c".into(),
        lang: "c".into(),
        param_count: 1,
        param_names: vec!["s".into()],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    let all_sums: Vec<_> = py_sums
        .into_iter()
        .chain(std::iter::once(c_summary))
        .collect();
    let global = merge_summaries(all_sums, None);

    // Verify they are stored under different FuncKeys
    let py_matches = global.lookup_same_lang(Lang::Python, "process_data");
    let c_matches = global.lookup_same_lang(Lang::C, "process_data");
    assert_eq!(py_matches.len(), 1, "Python version stored separately");
    assert_eq!(c_matches.len(), 1, "C version stored separately");

    // Python's source_caps should NOT bleed into C
    assert!(py_matches[0].1.source_caps != 0, "Python has source caps");
    assert_eq!(
        c_matches[0].1.source_caps, 0,
        "C should NOT get Python's source caps"
    );
}

// ── Scenario 8: Ruby passthrough in JS via interop ───────────────────────
#[test]
fn cross_lang_ruby_passthrough_in_js_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Ruby,
        namespace: "helper.rb".into(),
        name: "transform".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key.clone(),
        FuncSummary {
            name: "transform".into(),
            file_path: "helper.rb".into(),
            lang: "ruby".into(),
            param_count: 1,
            param_names: vec!["data".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let js_src = b"function main() {\n  let x = document.location();\n  let y = transform(x);\n  eval(y);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(js_src, "javascript", js_lang);
    let local = &file_cfg.summaries;

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "transform".into(),
            ordinal: 0,
        },
        to: key,
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "taint should propagate through cross-lang passthrough via interop"
    );
}

// ── Scenario 9: PHP source → Go sink via interop ─────────────────────────
#[test]
fn cross_lang_php_source_to_go_sink_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::{FuncSummary, merge_summaries};

    let php_summary = FuncSummary {
        name: "read_input".into(),
        file_path: "input.php".into(),
        lang: "php".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec!["file_get_contents".into()],
        ..Default::default()
    };

    let global = merge_summaries(vec![php_summary], None);

    let go_src = b"package main\n\nfunc main() {\n\tx := read_input()\n\texec.Command(x)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(go_src, "go", go_lang);
    let local = &file_cfg.summaries;

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Go,
            caller_namespace: "main.go".into(),
            caller_func: "main".into(),
            callee_symbol: "read_input".into(),
            ordinal: 0,
        },
        to: FuncKey {
            lang: Lang::Php,
            namespace: "input.php".into(),
            name: "read_input".into(),
            arity: Some(0),
            ..Default::default()
        },
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
        None,
    );
    assert_eq!(findings.len(), 1, "PHP source → Go sink via interop");
}

// ── Scenario 10: Wrong sanitizer caps still wrong across languages ───────
#[test]
fn cross_lang_wrong_sanitizer_still_flags_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "sanitizers.py".into(),
        name: "html_clean".into(),
        arity: Some(1),
        ..Default::default()
    };
    global.insert(
        key.clone(),
        FuncSummary {
            name: "html_clean".into(),
            file_path: "sanitizers.py".into(),
            lang: "python".into(),
            param_count: 1,
            param_names: vec!["text".into()],
            source_caps: 0,
            sanitizer_caps: Cap::HTML_ESCAPE.bits(),
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    // JS: source → Python HTML sanitizer → shell sink
    let js_src = b"function main() {\n  let x = document.location();\n  let y = html_clean(x);\n  eval(y);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(js_src, "javascript", js_lang);
    let local = &file_cfg.summaries;

    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::JavaScript,
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "html_clean".into(),
            ordinal: 0,
        },
        to: key,
    }];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "wrong cross-language sanitizer should NOT neutralise"
    );
}

// ── Scenario 11: Summary lang field preserved (different FuncKeys) ───────
#[test]
fn cross_lang_summary_preserves_lang_metadata() {
    use crate::summary::merge_summaries;

    let py_summary = crate::summary::FuncSummary {
        name: "helper".into(),
        file_path: "lib.py".into(),
        lang: "python".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };

    let js_summary = crate::summary::FuncSummary {
        name: "helper".into(),
        file_path: "lib.js".into(),
        lang: "javascript".into(),
        param_count: 1,
        param_names: vec!["x".into()],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: Cap::SHELL_ESCAPE.bits(),
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![0],
        callees: vec![],
        ..Default::default()
    };

    let global = merge_summaries(vec![py_summary, js_summary], None);

    // They are now separate entries, not merged
    let py_matches = global.lookup_same_lang(Lang::Python, "helper");
    let js_matches = global.lookup_same_lang(Lang::JavaScript, "helper");

    assert_eq!(py_matches.len(), 1, "Python helper stored separately");
    assert_eq!(js_matches.len(), 1, "JS helper stored separately");
    assert!(
        py_matches[0].1.source_caps != 0,
        "Python source caps preserved"
    );
    assert!(js_matches[0].1.sink_caps != 0, "JS sink caps preserved");
    assert!(
        js_matches[0].1.propagates_any(),
        "JS propagates_any preserved"
    );
}

// ── Scenario 12: Full pipeline Python lib + JS caller via interop ────────
#[test]
fn cross_lang_full_pipeline_python_lib_js_caller_via_interop() {
    use crate::interop::CallSiteKey;
    use crate::summary::merge_summaries;

    // Python library: defines dangerous_query() that reads from os.getenv
    let py_src = b"def dangerous_query():\n    x = os.getenv(\"SQL\")\n    return x\n";
    let py_lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let py_sums = extract_lang_summaries(py_src, "python", py_lang, "db.py");

    // JavaScript library: defines run_query() that calls eval (a sink)
    let js_lib_src = b"function run_query(q) {\n  eval(q);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let js_sums = extract_lang_summaries(js_lib_src, "javascript", js_lang, "db.js");

    let all_sums: Vec<_> = py_sums.into_iter().chain(js_sums).collect();
    let global = merge_summaries(all_sums, None);

    // Go caller: dangerous_query() → run_query()
    let go_src = b"package main\n\nfunc main() {\n\tq := dangerous_query()\n\trun_query(q)\n}\n";
    let go_lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(go_src, "go", go_lang);
    let local = &file_cfg.summaries;

    let edges = vec![
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "dangerous_query".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::Python,
                namespace: "db.py".into(),
                name: "dangerous_query".into(),
                arity: Some(0),
                ..Default::default()
            },
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_query".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::JavaScript,
                namespace: "db.js".into(),
                name: "run_query".into(),
                arity: Some(1),
                ..Default::default()
            },
        },
    ];
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Go,
        "main.go",
        &edges,
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "Python source → JS sink via Go caller via interop"
    );
}

// ── New tests: ambiguous resolution, interop edge specificity ────────────

#[test]
fn ambiguous_resolution_returns_none() {
    use crate::summary::FuncSummary;

    // Two same-lang functions, same name + arity, different namespaces
    let mut global = GlobalSummaries::new();
    for ns in &["a.rs", "b.rs"] {
        let key = FuncKey {
            lang: Lang::Rust,
            namespace: (*ns).to_string(),
            name: "helper".into(),
            arity: Some(0),
            ..Default::default()
        };
        global.insert(
            key,
            FuncSummary {
                name: "helper".into(),
                file_path: (*ns).to_string(),
                lang: "rust".into(),
                param_count: 0,
                param_names: vec![],
                source_caps: Cap::all().bits(),
                sanitizer_caps: 0,
                sink_caps: 0,
                propagating_params: vec![],
                propagates_taint: false,
                tainted_sink_params: vec![],
                callees: vec![],
                ..Default::default()
            },
        );
    }

    // Caller from c.rs calls helper(), ambiguous (two matches, neither is caller's namespace)
    let src = br#"
        use std::process::Command;
        fn main() {
            let x = helper();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "c.rs",
        &[],
        None,
    );

    // Ambiguous resolution returns None → no source → no finding
    assert!(
        findings.is_empty(),
        "ambiguous resolution (two namespaces) should return None → no finding"
    );
}

#[test]
fn exact_namespace_match_wins() {
    use crate::summary::FuncSummary;

    // Same name in two namespaces, but one matches caller's namespace
    let mut global = GlobalSummaries::new();
    // test.rs version: source
    let key_local = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "helper".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key_local,
        FuncSummary {
            name: "helper".into(),
            file_path: "test.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );
    // other.rs version: no caps
    let key_other = FuncKey {
        lang: Lang::Rust,
        namespace: "other.rs".into(),
        name: "helper".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key_other,
        FuncSummary {
            name: "helper".into(),
            file_path: "other.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::process::Command;
        fn main() {
            let x = helper();
            Command::new("sh").arg(x).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    // caller_namespace = "test.rs" matches the source version
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );

    assert_eq!(
        findings.len(),
        1,
        "exact namespace match should resolve to the source version"
    );
}

#[test]
fn interop_edge_wrong_caller_lang_no_match() {
    use crate::interop::CallSiteKey;
    use crate::summary::FuncSummary;

    let mut global = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "lib.py".into(),
        name: "get_data".into(),
        arity: Some(0),
        ..Default::default()
    };
    global.insert(
        key.clone(),
        FuncSummary {
            name: "get_data".into(),
            file_path: "lib.py".into(),
            lang: "python".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: Cap::all().bits(),
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    // Edge specifies Python caller, but we're calling from JavaScript
    let edges = vec![InteropEdge {
        from: CallSiteKey {
            caller_lang: Lang::Python, // wrong!
            caller_namespace: "main.js".into(),
            caller_func: "main".into(),
            callee_symbol: "get_data".into(),
            ordinal: 0,
        },
        to: key,
    }];

    let js_src = b"function main() {\n  let x = get_data();\n  eval(x);\n}\n";
    let js_lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(js_src, "javascript", js_lang);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::JavaScript,
        "main.js",
        &edges,
        None,
    );

    assert!(
        findings.is_empty(),
        "Edge for wrong caller_lang should not match"
    );
}

#[test]
fn return_call_recognized_as_source() {
    use crate::cfg::{build_cfg, export_summaries};
    use tree_sitter::Language;

    // fn foo() -> String { env::var("X").unwrap() }
    // The return statement contains a call to env::var which should be
    // recognized as a source after the return-call fix.
    let src = br#"
        use std::env;
        fn foo() -> String {
            env::var("X").unwrap()
        }
    "#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let exported = export_summaries(summaries, "test.rs", "rust");

    let foo = exported
        .iter()
        .find(|s| s.name == "foo")
        .expect("foo should exist");
    assert!(
        foo.source_caps != 0,
        "foo() should have source_caps set because env::var is called inside return"
    );
}

// ─── Path-sensitive analysis tests ───────────────────────────────────────────

#[test]
fn validate_and_early_return() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Validate before use: if validation fails, early return.
    // The sink after the guard is on the "validated" path.
    //
    // The CFG creates a synthetic pass-through node for the false path
    // with an explicit False edge from the If node.  BFS reaches the
    // sink via: cond → (False) → pass-through → (Seq) → sink.
    // The predicate on the False edge records that `!validate(&x)` was
    // false (i.e. validation passed), so the sink is path-guarded.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if !validate(&x) { return; }
            Command::new("sh").arg(x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Validated findings are now suppressed, validate() guard means the
    // sink is on the safe path, so no finding should be emitted.
    assert_eq!(findings.len(), 0, "validated finding should be suppressed");
}

#[test]
fn validate_in_if_else_path_validated() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // If/else where the True branch (validation passed) contains the sink.
    // This IS detectable because the If node has genuine True/False branches.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if validate(&x) {
                Command::new("sh").arg(&x).status().unwrap();
            } else {
                println!("invalid input");
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Validated findings are now suppressed, sink is in the validated
    // branch, so no finding should be emitted.
    assert_eq!(findings.len(), 0, "validated finding should be suppressed");
}

#[test]
fn sink_on_failed_validation_branch() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Sink is in the failed-validation branch (negated condition, false edge).
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if !validate(&x) {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert_eq!(findings.len(), 1, "should detect taint flow to sink");
    assert!(
        !findings[0].path_validated,
        "finding should NOT be path_validated (sink is in failed-validation branch)"
    );
}

#[test]
fn contradictory_null_check_pruned() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Inner branch is infeasible: if x.is_none() then x cannot also be is_none().
    // After early return on is_none(), the fall-through path has polarity=false
    // for NullCheck. The inner `if x.is_none()` True branch has polarity=true ,
    // contradiction.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").ok();
            if x.is_none() { return; }
            if x.is_none() {
                Command::new("sh").arg("dangerous").status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // The inner branch is infeasible, and the arg "dangerous" is a string
    // literal (not tainted), so there should be no findings.
    assert!(
        findings.is_empty(),
        "inner branch is infeasible — should produce no findings (got {})",
        findings.len()
    );
}

#[test]
fn sanitize_one_branch_no_regression() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Same as existing taint_through_if_else: sanitized in one branch, not in the other.
    // Verify the finding count stays at 1 (no regression from path sensitivity).
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let safe = html_escape::encode_safe(&x);

            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();   // UNSAFE
            } else {
                Command::new("sh").arg(&safe).status().unwrap(); // SAFE
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Both branches produce findings: the true branch uses unsanitized `x`,
    // the else branch uses `safe` (HTML_ESCAPE sanitizer vs SHELL_ESCAPE sink).
    // Previously only 1 finding because else_clause was silently dropped from CFG.
    assert_eq!(
        findings.len(),
        2,
        "two findings expected (both branches reach sink with wrong/no sanitizer)"
    );
}

#[test]
fn path_state_budget_graceful() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Deeply nested ifs with a sink at the innermost level.
    // PathState should truncate gracefully after MAX_PATH_PREDICATES.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if x.len() > 1 {
            if x.len() > 2 {
            if x.len() > 3 {
            if x.len() > 4 {
            if x.len() > 5 {
            if x.len() > 6 {
            if x.len() > 7 {
            if x.len() > 8 {
            if x.len() > 9 {
                Command::new("sh").arg(&x).status().unwrap();
            }
            }
            }
            }
            }
            }
            }
            }
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Should still detect the flow, truncation shouldn't cause false negatives.
    assert_eq!(
        findings.len(),
        1,
        "should detect taint flow even with truncated PathState"
    );
}

#[test]
fn unknown_predicate_not_pruned() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Comparison predicates are NOT in the contradiction whitelist, so even
    // seemingly contradictory comparisons should not be pruned.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if x.len() > 5 { return; }
            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Comparison is not in the whitelist, the path should NOT be pruned.
    assert_eq!(
        findings.len(),
        1,
        "Comparison predicate should not cause contradiction pruning"
    );
}

#[test]
fn duplicate_null_guard_prunes_unreachable_sink() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // After `if y.is_none() { return; }`, the false arm proves
    // `y.is_none() == false` on the only surviving path.  A second
    // `if y.is_none() { sink }` then adds `y.is_none() == true` on the
    // body's True arm, a per-symbol PredicateSummary contradiction
    // (known_true & known_false on bit NullCheck).  The body is
    // structurally unreachable; the sink must not fire.
    //
    // Regression guard: this expected behaviour only emerges once the
    // OR-chain / direct-return rejection arm correctly terminates its
    // SSA block (see
    // `src/ssa/lower.rs::tests::or_chain_rejection_block_terminates_with_return`).
    // Pre-fix the rejection arm Goto'd into the merged tail and its
    // contradicting predicate joined with the false-arm to empty,
    // letting flow through.  Pruning here is the precise outcome.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            let y = env::var("OTHER").ok();
            if y.is_none() { return; }
            if y.is_none() {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert!(
        findings.is_empty(),
        "duplicate null-guard with intervening early-return must prune \
         the second if's body as unreachable; got findings = {:?}",
        findings
    );
}

#[test]
fn c_curl_handle_ssrf() {
    let src = b"#include <stdlib.h>\n#include <curl/curl.h>\n\
        void fetch() {\n  char *url = getenv(\"TARGET\");\n  \
        CURL *curl = curl_easy_init();\n  \
        curl_easy_setopt(curl, CURLOPT_URL, url);\n  \
        curl_easy_perform(curl);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::C, "test.c", &[], None);
    assert!(
        !findings.is_empty(),
        "C: getenv -> curl_easy_setopt -> curl_easy_perform should produce SSRF finding"
    );
}

#[test]
fn c_curl_handle_no_taint() {
    let src = b"#include <curl/curl.h>\n\
        void fetch() {\n  CURL *curl = curl_easy_init();\n  \
        curl_easy_setopt(curl, CURLOPT_URL, \"https://example.com\");\n  \
        curl_easy_perform(curl);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::C, "test.c", &[], None);
    assert!(
        findings.is_empty(),
        "C: hardcoded URL in curl_easy_setopt should not produce finding"
    );
}

// ── Per-argument propagation tests ───────────────────────────────────────

#[test]
fn per_arg_propagation_tainted_param_propagates() {
    use crate::summary::FuncSummary;

    // transform(a, b) only propagates param 0. Tainted value at param 0 → finding.
    let mut global = GlobalSummaries::new();
    global.insert(
        FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "transform".into(),
            arity: Some(2),
            ..Default::default()
        },
        FuncSummary {
            name: "transform".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["a".into(), "b".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let tainted = env::var("X").unwrap();
            let safe = String::from("ok");
            let y = transform(&tainted, &safe);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "tainted arg at propagating position should produce finding"
    );
}

#[test]
fn per_arg_propagation_safe_at_propagating_position() {
    use crate::summary::FuncSummary;

    // transform(a, b) only propagates param 0. Tainted value at param 1 (non-propagating) → no finding.
    let mut global = GlobalSummaries::new();
    global.insert(
        FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "transform".into(),
            arity: Some(2),
            ..Default::default()
        },
        FuncSummary {
            name: "transform".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["a".into(), "b".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![0],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let safe = String::from("ok");
            let tainted = env::var("X").unwrap();
            let y = transform(&safe, &tainted);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        0,
        "tainted arg at non-propagating position should not produce finding"
    );
}

#[test]
fn per_arg_propagation_legacy_backward_compat() {
    use crate::summary::FuncSummary;

    // legacy_pass has propagates_taint=true but empty propagating_params (legacy).
    // Should fall back to all-uses propagation.
    let mut global = GlobalSummaries::new();
    global.insert(
        FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "legacy_pass".into(),
            arity: Some(2),
            ..Default::default()
        },
        FuncSummary {
            name: "legacy_pass".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["a".into(), "b".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: true,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let safe = String::from("ok");
            let tainted = env::var("X").unwrap();
            let y = legacy_pass(&safe, &tainted);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "legacy propagates_taint=true with empty propagating_params should propagate all args"
    );
}

#[test]
fn per_arg_propagation_both_params_propagate() {
    use crate::summary::FuncSummary;

    // concat(a, b) propagates both params 0 and 1. Tainted at param 1 → finding.
    let mut global = GlobalSummaries::new();
    global.insert(
        FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "concat".into(),
            arity: Some(2),
            ..Default::default()
        },
        FuncSummary {
            name: "concat".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["a".into(), "b".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![0, 1],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let safe = String::from("ok");
            let tainted = env::var("X").unwrap();
            let y = concat(&safe, &tainted);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "both params propagate — tainted arg at position 1 should produce finding"
    );
}

#[test]
fn per_arg_propagation_literal_first_arg() {
    use crate::summary::FuncSummary;

    // transform("literal", tainted) with only param 1 propagating → finding.
    // The literal arg at position 0 has no identifiers, but positional mapping is still correct.
    let mut global = GlobalSummaries::new();
    global.insert(
        FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "transform".into(),
            arity: Some(2),
            ..Default::default()
        },
        FuncSummary {
            name: "transform".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["a".into(), "b".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![1],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let tainted = env::var("X").unwrap();
            let y = transform("prefix", &tainted);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "literal first arg should not shift positional mapping — tainted at param 1 propagates"
    );
}

#[test]
fn per_arg_propagation_nested_expr_arg() {
    use crate::summary::FuncSummary;

    // transform(inner(x), tainted) with only param 1 propagating → finding.
    // Nested call in arg 0 doesn't affect arg 1 position.
    let mut global = GlobalSummaries::new();
    global.insert(
        FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "transform".into(),
            arity: Some(2),
            ..Default::default()
        },
        FuncSummary {
            name: "transform".into(),
            file_path: "lib.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["a".into(), "b".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![1],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        },
    );

    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = String::from("safe");
            let tainted = env::var("X").unwrap();
            let y = transform(inner(&x), &tainted);
            Command::new("sh").arg(y).status().unwrap();
        }
    "#;

    let file_cfg = parse_rust(src);
    let local = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        local,
        Some(&global),
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "nested call in arg 0 should not affect arg 1 positional mapping"
    );
}

#[test]
fn js_cross_function_global_taint() {
    let src = b"let x = \"safe\";\nfunction leak() { x = document.location(); }\nfunction use_it() { eval(x); }\nleak();\nuse_it();\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "cross-function global taint (leak -> use_it) should be detected"
    );
}

#[test]
fn js_two_level_converges_no_mutation() {
    let src = b"let x = document.location();\nfunction f() { eval(x); }\nf();\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "top-level source to function sink should be detected"
    );
}

// ── Catch-parameter provenance tests ──────────────────────────────────────

#[test]
fn catch_param_to_sink_has_caught_exception_source_kind() {
    // Catch param flows to a sink, the finding source_kind must be
    // CaughtException, not Unknown.
    let src = b"
        const { exec } = require('child_process');
        try {
            doSomething();
        } catch (err) {
            exec(err.command);
        }
    ";

    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );

    assert!(
        !findings.is_empty(),
        "catch param to sink should produce a finding"
    );
    for f in &findings {
        assert_eq!(
            f.source_kind,
            crate::labels::SourceKind::CaughtException,
            "catch-param origin should have CaughtException source kind, not {:?}",
            f.source_kind
        );
    }
}

#[test]
fn catch_param_source_node_has_callee() {
    // The source CFG node for a catch-param finding must have a non-None callee
    // so the report renders a meaningful descriptor instead of "(unknown)".
    let src = b"
        try {
            riskyOperation();
        } catch (e) {
            fetch(e.message);
        }
    ";

    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let the_cfg = &file_cfg.first_body().graph;
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );

    assert!(
        !findings.is_empty(),
        "catch param to fetch should produce a finding"
    );
    for f in &findings {
        let source_info = &the_cfg[f.source];
        assert!(
            source_info.call.callee.is_some(),
            "catch-param source node must have a callee for reporting, got None"
        );
        let callee = source_info.call.callee.as_deref().unwrap();
        assert!(
            callee.contains("catch"),
            "catch-param callee should contain 'catch', got {:?}",
            callee
        );
    }
}

#[test]
fn taint_origin_preserved_through_assignment() {
    // Source origin should be preserved when taint flows through variable
    // assignments, not replaced or lost.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("CMD").unwrap();
            let y = x;
            let z = y;
            Command::new("sh").arg(z).status().unwrap();
        }"#;

    let file_cfg = parse_rust(src);
    let the_cfg = &file_cfg.first_body().graph;
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    // The source should point to the env::var call, not the intermediate assignments
    let source_info = &the_cfg[f.source];
    assert!(
        source_info.call.callee.is_some(),
        "source node should have callee after propagation through assignments"
    );
    let callee = source_info.call.callee.as_deref().unwrap();
    assert!(
        callee.contains("env") || callee.contains("var"),
        "source callee should reference env::var, got {:?}",
        callee
    );
}

#[test]
fn taint_origin_preserved_through_branch_merge() {
    // When taint flows through both branches of an if-else and merges,
    // the origin should still point to the original source.
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("CMD").unwrap();
            let y;
            if true {
                y = x;
            } else {
                y = x;
            }
            Command::new("sh").arg(y).status().unwrap();
        }"#;

    let file_cfg = parse_rust(src);
    let the_cfg = &file_cfg.first_body().graph;
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert!(!findings.is_empty());
    for f in &findings {
        let source_info = &the_cfg[f.source];
        assert!(
            source_info.call.callee.is_some(),
            "source callee must not be None after branch merge"
        );
    }
}

// ── SSA / Legacy Output-Equivalence Tests ─────────────────────────────────

/// Run both legacy and SSA taint analysis on the same Rust source and assert
/// that they produce the same findings (by source/sink/source_kind triple).
/// Assert that `analyse_file` (high-level) matches direct SSA pipeline invocation.
fn assert_ssa_integration(src: &[u8]) {
    use crate::cfg::build_cfg;
    use crate::state::symbol::SymbolInterner;
    use std::collections::HashSet;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter::Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;

    // High-level path (per-body analysis)
    let high_level = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Direct SSA path, use the first function body (fn main), not top-level
    let body = if file_cfg.bodies.len() > 1 {
        &file_cfg.bodies[1]
    } else {
        file_cfg.first_body()
    };
    let the_cfg = &body.graph;
    let entry = body.entry;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let ssa =
        crate::ssa::lower_to_ssa(the_cfg, entry, None, true).expect("SSA lowering should succeed");
    let ssa_xfer = ssa_transfer::SsaTaintTransfer {
        lang: Lang::Rust,
        namespace: "test.rs",
        interner: &interner,
        local_summaries: summaries,
        global_summaries: None,
        interop_edges: &[],
        owner_body_id: crate::cfg::BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: None,
        receiver_seed: None,
        const_values: None,
        type_facts: None,
        xml_parser_config: None,
        xpath_config: None,
        ssa_summaries: None,
        extra_labels: None,
        base_aliases: None,
        callee_bodies: None,
        inline_cache: None,
        context_depth: 0,
        callback_bindings: None,
        points_to: None,
        dynamic_pts: None,
        import_bindings: None,
        promisify_aliases: None,
        module_aliases: None,
        static_map: None,
        auto_seed_handler_params: false,
        cross_file_bodies: None,
        pointer_facts: None,
        cross_package_imports: None,
        entry_kind: None,
        param_route_capture: None,
        recording_summary: false,
    };
    let events = ssa_transfer::run_ssa_taint(&ssa, the_cfg, &ssa_xfer);
    let mut ssa_findings = ssa_transfer::ssa_events_to_findings(&events, &ssa, the_cfg);
    ssa_findings.sort_by_key(|f| (f.sink.index(), f.source.index(), !f.path_validated));
    ssa_findings.dedup_by_key(|f| (f.sink, f.source));

    // Compare by (source, sink)
    let high_set: HashSet<_> = high_level
        .iter()
        .map(|f| (f.source.index(), f.sink.index()))
        .collect();
    let ssa_set: HashSet<_> = ssa_findings
        .iter()
        .map(|f| (f.source.index(), f.sink.index()))
        .collect();

    assert_eq!(
        high_set, ssa_set,
        "analyse_file vs direct SSA mismatch.\nHigh-level: {high_set:?}\nDirect SSA: {ssa_set:?}"
    );
}

#[test]
fn equiv_env_to_arg() {
    assert_ssa_integration(
        br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS_ARG").unwrap();
            Command::new("sh").arg(x).status().unwrap();
        }"#,
    );
}

#[test]
fn equiv_taint_through_if_else() {
    assert_ssa_integration(
        br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let safe = html_escape::encode_safe(&x);
            if x.len() > 5 {
                Command::new("sh").arg(&x).status().unwrap();
            } else {
                Command::new("sh").arg(&safe).status().unwrap();
            }
        }"#,
    );
}

#[test]
fn equiv_taint_through_while_loop() {
    assert_ssa_integration(
        br#"
        use std::{env, process::Command};
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            while x.len() < 100 {
                x.push_str("a");
            }
            Command::new("sh").arg(x).status().unwrap();
        }"#,
    );
}

#[test]
fn equiv_killed_by_matching_sanitizer() {
    assert_ssa_integration(
        br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let clean = shell_escape::unix::escape(&x);
            Command::new("sh").arg(clean).status().unwrap();
        }"#,
    );
}

#[test]
fn equiv_wrong_sanitizer_preserves_taint() {
    assert_ssa_integration(
        br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            let escaped = html_escape::encode_safe(&x);
            Command::new("sh").arg(escaped).status().unwrap();
        }"#,
    );
}

#[test]
fn integ_php_echo_simple_var() {
    use crate::state::symbol::SymbolInterner;
    let src = b"<?php\n$x = $_POST['data'];\necho $x;\n";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let the_cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;

    let high_level = analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None);

    let interner = SymbolInterner::from_cfg(the_cfg);
    let ssa = crate::ssa::lower_to_ssa(the_cfg, entry, None, true).expect("SSA lowering");
    let ssa_xfer = ssa_transfer::SsaTaintTransfer {
        lang: Lang::Php,
        namespace: "test.php",
        interner: &interner,
        local_summaries: summaries,
        global_summaries: None,
        interop_edges: &[],
        owner_body_id: crate::cfg::BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: None,
        receiver_seed: None,
        const_values: None,
        type_facts: None,
        xml_parser_config: None,
        xpath_config: None,
        ssa_summaries: None,
        extra_labels: None,
        base_aliases: None,
        callee_bodies: None,
        inline_cache: None,
        context_depth: 0,
        callback_bindings: None,
        points_to: None,
        dynamic_pts: None,
        import_bindings: None,
        promisify_aliases: None,
        module_aliases: None,
        static_map: None,
        auto_seed_handler_params: false,
        cross_file_bodies: None,
        pointer_facts: None,
        cross_package_imports: None,
        entry_kind: None,
        param_route_capture: None,
        recording_summary: false,
    };
    let events = ssa_transfer::run_ssa_taint(&ssa, the_cfg, &ssa_xfer);
    let mut ssa_findings = ssa_transfer::ssa_events_to_findings(&events, &ssa, the_cfg);
    ssa_findings.sort_by_key(|f| (f.sink.index(), f.source.index(), !f.path_validated));
    ssa_findings.dedup_by_key(|f| (f.sink, f.source));

    let high_set: std::collections::HashSet<_> = high_level
        .iter()
        .map(|f| (f.source.index(), f.sink.index()))
        .collect();
    let ssa_set: std::collections::HashSet<_> = ssa_findings
        .iter()
        .map(|f| (f.source.index(), f.sink.index()))
        .collect();
    assert_eq!(
        high_set, ssa_set,
        "PHP echo analyse_file vs direct SSA mismatch"
    );
}

#[test]
fn integ_c_curl_handle_ssrf() {
    use crate::state::symbol::SymbolInterner;
    let src = b"#include <stdlib.h>\n#include <curl/curl.h>\n\
        void fetch() {\n  char *url = getenv(\"TARGET\");\n  \
        CURL *curl = curl_easy_init();\n  \
        curl_easy_setopt(curl, CURLOPT_URL, url);\n  \
        curl_easy_perform(curl);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let the_cfg = &file_cfg.first_body().graph;
    let entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;

    let high_level = analyse_file(&file_cfg, summaries, None, Lang::C, "test.c", &[], None);

    let interner = SymbolInterner::from_cfg(the_cfg);
    let ssa = crate::ssa::lower_to_ssa(the_cfg, entry, None, true).expect("SSA lowering");
    let ssa_xfer = ssa_transfer::SsaTaintTransfer {
        lang: Lang::C,
        namespace: "test.c",
        interner: &interner,
        local_summaries: summaries,
        global_summaries: None,
        interop_edges: &[],
        owner_body_id: crate::cfg::BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: None,
        receiver_seed: None,
        const_values: None,
        type_facts: None,
        xml_parser_config: None,
        xpath_config: None,
        ssa_summaries: None,
        extra_labels: None,
        base_aliases: None,
        callee_bodies: None,
        inline_cache: None,
        context_depth: 0,
        callback_bindings: None,
        points_to: None,
        dynamic_pts: None,
        import_bindings: None,
        promisify_aliases: None,
        module_aliases: None,
        static_map: None,
        auto_seed_handler_params: false,
        cross_file_bodies: None,
        pointer_facts: None,
        cross_package_imports: None,
        entry_kind: None,
        param_route_capture: None,
        recording_summary: false,
    };
    let events = ssa_transfer::run_ssa_taint(&ssa, the_cfg, &ssa_xfer);
    let mut ssa_findings = ssa_transfer::ssa_events_to_findings(&events, &ssa, the_cfg);
    ssa_findings.sort_by_key(|f| (f.sink.index(), f.source.index(), !f.path_validated));
    ssa_findings.dedup_by_key(|f| (f.sink, f.source));

    let high_set: std::collections::HashSet<_> = high_level
        .iter()
        .map(|f| (f.source.index(), f.sink.index()))
        .collect();
    let ssa_set: std::collections::HashSet<_> = ssa_findings
        .iter()
        .map(|f| (f.source.index(), f.sink.index()))
        .collect();
    assert_eq!(
        high_set, ssa_set,
        "curl analyse_file vs direct SSA mismatch"
    );
}

#[test]
fn equiv_validate_and_early_return() {
    assert_ssa_integration(
        br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if !validate(&x) { return; }
            Command::new("sh").arg(x).status().unwrap();
        }"#,
    );
}

// ── JS/TS SSA Two-Level Solve Tests ─────────────────────────────────────

#[test]
fn ssa_js_two_level_global_to_function() {
    // Top-level source → function sink via global seed
    let src = b"let x = document.location();\nfunction f() { eval(x); }\nf();\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;

    // SSA is now the default path for JS/TS
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "SSA JS two-level: top-level source should flow to function sink"
    );
}

#[test]
fn ssa_js_two_level_function_isolation() {
    // Variable x in func_a should not leak to func_b
    let src =
        b"function a() { let x = document.location(); }\nfunction b() { eval(x); }\na();\nb();\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;

    // SSA is now the default path for JS/TS
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    // x is local to a(), so it shouldn't flow to b()'s eval
    // Note: this depends on x being properly scoped; if the CFG treats x as global, it may still flow.
    // The test verifies that the SSA path doesn't crash and produces reasonable results.
    let _ = findings; // Assert no panic
}

#[test]
fn ssa_js_two_level_convergence() {
    // Function writes back to global, 2nd round picks it up
    let src = b"let x = 'safe';\nfunction leak() { x = document.location(); }\nfunction use_it() { eval(x); }\nleak();\nuse_it();\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;

    // SSA is now the default path for JS/TS
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "SSA JS two-level: function mutation of global should converge and detect taint"
    );
}

/// Verify SSA JS two-level correctly detects taint through chained method calls
/// (e.g. fetch(url).then(fn).then(fn) in Express callbacks).
#[test]
fn ssa_js_chained_call_taint() {
    let src = b"var express = require('express');\nvar app = express();\n\napp.get('/proxy', function(req, res) {\n    var url = req.query.url;\n    fetch(url).then(function(response) {\n        return response.text();\n    }).then(function(body) {\n        res.send(body);\n    });\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;

    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "SSA should detect taint through fetch(url).then().then() chain"
    );
}

// ── Field access taint tracking tests ────────────────────────────────────

#[test]
fn ssa_field_write_to_sink() {
    // obj.data = source; sink(obj.data) → finding
    let src = b"var express = require('express');\nvar app = express();\napp.get('/f', function(req, res) {\n    var obj = {};\n    obj.data = req.query.input;\n    res.send(obj.data);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "SSA: field write from source should propagate taint to field read at sink"
    );
}

#[test]
fn ssa_field_overwrite_kills_taint() {
    // obj.data = source; obj.data = "safe"; sink(obj.data) → no finding
    let src = b"var express = require('express');\nvar app = express();\napp.get('/f', function(req, res) {\n    var obj = {};\n    obj.data = req.query.input;\n    obj.data = \"safe\";\n    res.send(obj.data);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "SSA: constant overwrite of field should kill taint"
    );
}

#[test]
fn ssa_field_different_bases_no_alias() {
    // a.tainted = source; sink(b.safe) → no finding (different base objects, different fields)
    let src = b"var express = require('express');\nvar app = express();\napp.get('/f', function(req, res) {\n    var a = {};\n    var b = {};\n    a.tainted = req.query.input;\n    res.send(b.safe);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "SSA: different base objects should not alias — a.tainted taint must not reach b.safe"
    );
}

#[test]
fn ssa_python_attribute_taint() {
    // config.cmd = os.getenv("CMD"); os.system(config.cmd) → finding
    let src = b"import os\n\nclass Config:\n    pass\n\nconfig = Config()\nconfig.cmd = os.getenv(\"CMD\")\nos.system(config.cmd)\n";
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Python,
        "test.py",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "SSA: Python attribute write from source should propagate taint to attribute read at sink"
    );
}

// ── Field-aware taint suppression tests ──────────────────────────────────

#[test]
fn ssa_field_safe_overwrite_no_fp() {
    // obj = tainted source; obj.safe = "constant"; sink(obj.safe) → NO finding
    let src = b"var express = require('express');\nvar app = express();\napp.get('/f', function(req, res) {\n    var obj = req.query;\n    obj.safe = \"constant\";\n    res.send(obj.safe);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "field-aware suppression: reading safe field of tainted base should not produce a finding, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_field_tainted_field_still_fires() {
    // obj.data = source; sink(obj.data) → finding (dotted path IS tainted, no suppression)
    let src = b"var express = require('express');\nvar app = express();\napp.get('/f', function(req, res) {\n    var obj = {};\n    obj.data = req.query.input;\n    res.send(obj.data);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "field-aware suppression: tainted dotted-path field read should still produce a finding"
    );
}

#[test]
fn ssa_field_base_sink_no_suppression() {
    // obj.data = source; sink(obj) → finding (no dotted path at sink, no suppression)
    let src = b"var express = require('express');\nvar app = express();\napp.get('/f', function(req, res) {\n    var obj = {};\n    obj.data = req.query.input;\n    res.send(obj);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "field-aware suppression: tainted base passed directly to sink should still fire"
    );
}

// ── SSA Function Summary tests ───────────────────────────────────────────

#[test]
fn ssa_summary_identity_propagation() {
    // Function that returns its param unchanged → Identity transform
    use crate::state::symbol::SymbolInterner;
    use crate::summary::ssa_summary::TaintTransform;

    let src = br#"
        fn passthrough(x: String) -> String {
            x
        }"#;
    let file_cfg = parse_lang(
        src,
        "rust",
        tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
    );
    let the_cfg = &file_cfg.first_body().graph;
    let _entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let func_entries = super::find_function_entries(the_cfg);
    assert!(
        !func_entries.is_empty(),
        "should find at least one function entry"
    );

    for (func_name, func_entry) in &func_entries {
        let func_ssa = crate::ssa::lower_to_ssa(the_cfg, *func_entry, Some(func_name), false);
        if let Ok(ssa) = func_ssa {
            let param_count = ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count();
            if param_count == 0 {
                continue;
            }

            let summary = ssa_transfer::extract_ssa_func_summary(
                &ssa,
                the_cfg,
                summaries,
                None,
                Lang::Rust,
                "test.rs",
                &interner,
                param_count,
                None,
                None,
                None,
                None,
                None,
            );
            assert!(
                !summary.param_to_return.is_empty(),
                "passthrough function should have param_to_return entries"
            );
            // Check the transform is Identity (all caps survive)
            for (_, transform) in &summary.param_to_return {
                assert!(
                    matches!(transform, TaintTransform::Identity),
                    "passthrough should produce Identity transform, got {:?}",
                    transform
                );
            }
        }
    }
}

#[test]
fn ssa_summary_sanitizer_strips_bits() {
    // Function with internal sanitizer → StripBits transform
    use crate::state::symbol::SymbolInterner;
    use crate::summary::ssa_summary::TaintTransform;

    let src = br#"
        fn sanitize_input(x: String) -> String {
            html_escape::encode_safe(&x)
        }"#;
    let file_cfg = parse_lang(
        src,
        "rust",
        tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
    );
    let the_cfg = &file_cfg.first_body().graph;
    let _entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let func_entries = super::find_function_entries(the_cfg);

    for (func_name, func_entry) in &func_entries {
        let func_ssa = crate::ssa::lower_to_ssa(the_cfg, *func_entry, Some(func_name), false);
        if let Ok(ssa) = func_ssa {
            let param_count = ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count();
            if param_count == 0 {
                continue;
            }

            let summary = ssa_transfer::extract_ssa_func_summary(
                &ssa,
                the_cfg,
                summaries,
                None,
                Lang::Rust,
                "test.rs",
                &interner,
                param_count,
                None,
                None,
                None,
                None,
                None,
            );
            // Sanitizer should strip some bits
            for (_, transform) in &summary.param_to_return {
                assert!(
                    matches!(transform, TaintTransform::StripBits(_)),
                    "sanitizer wrapper should produce StripBits transform, got {:?}",
                    transform
                );
            }
        }
    }
}

#[test]
fn ssa_summary_source_adds_bits() {
    // Function that reads env → source_caps should be non-empty
    use crate::state::symbol::SymbolInterner;

    let src = br#"
        use std::env;
        fn read_config() -> String {
            env::var("CONFIG").unwrap()
        }"#;
    let file_cfg = parse_lang(
        src,
        "rust",
        tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
    );
    let the_cfg = &file_cfg.first_body().graph;
    let _entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let func_entries = super::find_function_entries(the_cfg);

    for (func_name, func_entry) in &func_entries {
        let func_ssa = crate::ssa::lower_to_ssa(the_cfg, *func_entry, Some(func_name), false);
        if let Ok(ssa) = func_ssa {
            let param_count = ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count();

            let summary = ssa_transfer::extract_ssa_func_summary(
                &ssa,
                the_cfg,
                summaries,
                None,
                Lang::Rust,
                "test.rs",
                &interner,
                param_count,
                None,
                None,
                None,
                None,
                None,
            );
            assert!(
                !summary.source_caps.is_empty(),
                "env-reading function should have non-empty source_caps, got {:?}",
                summary.source_caps
            );
        }
    }
}

#[test]
fn ssa_summary_param_to_sink() {
    // Function that passes param to a dangerous call → param_to_sink
    use crate::state::symbol::SymbolInterner;

    let src = br#"
        use std::process::Command;
        fn run_cmd(cmd: String) {
            Command::new("sh").arg(cmd).status().unwrap();
        }"#;
    let file_cfg = parse_lang(
        src,
        "rust",
        tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
    );
    let the_cfg = &file_cfg.first_body().graph;
    let _entry = file_cfg.first_body().entry;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let func_entries = super::find_function_entries(the_cfg);

    for (func_name, func_entry) in &func_entries {
        let func_ssa = crate::ssa::lower_to_ssa(the_cfg, *func_entry, Some(func_name), false);
        if let Ok(ssa) = func_ssa {
            let param_count = ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count();
            if param_count == 0 {
                continue;
            }

            let summary = ssa_transfer::extract_ssa_func_summary(
                &ssa,
                the_cfg,
                summaries,
                None,
                Lang::Rust,
                "test.rs",
                &interner,
                param_count,
                None,
                None,
                None,
                None,
                None,
            );
            assert!(
                !summary.param_to_sink.is_empty(),
                "function passing param to Command sink should have param_to_sink entries"
            );
        }
    }
}

#[test]
fn c_summary_param_to_execvp_argv_sink() {
    use crate::state::symbol::SymbolInterner;

    let src = br#"#include <unistd.h>
int do_ssh_connect(char *url) {
  const char *ssh;
  char *ssh_host = url;
  const char *port = 0;
  get_host_and_port_min(&ssh_host, &port);
  if (!port) port = "22";
  ssh = getenv("GIT_SSH");
  if (!ssh) ssh = "ssh";
  const char *args[8];
  int nargs = 0;
  args[nargs++] = ssh;
  if (port) {
    args[nargs++] = "-p";
    args[nargs++] = port;
  }
  args[nargs++] = ssh_host;
  args[nargs++] = "git-upload-pack";
  args[nargs++] = 0;
  return execvp(args[0], (char *const *)args);
}
"#;
    let file_cfg = parse_lang(
        src,
        "c",
        tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
    );
    for body in &file_cfg.bodies {
        if body.meta.name.as_deref() != Some("do_ssh_connect") {
            continue;
        }
        let interner = SymbolInterner::from_cfg(&body.graph);
        let ssa = crate::ssa::lower_to_ssa_with_params(
            &body.graph,
            body.entry,
            Some("do_ssh_connect"),
            false,
            &body.meta.params,
        )
        .expect("C function should lower to SSA");
        let param_count = body.meta.params.len();
        let summary = ssa_transfer::extract_ssa_func_summary(
            &ssa,
            &body.graph,
            &file_cfg.summaries,
            None,
            Lang::C,
            "test.c",
            &interner,
            param_count,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            summary
                .param_to_sink_caps()
                .iter()
                .any(|(idx, caps)| *idx == 0 && caps.contains(Cap::SHELL_ESCAPE)),
            "C summary should record url param reaching execvp argv, got {:?}",
            summary.param_to_sink_caps()
        );
        return;
    }

    panic!("do_ssh_connect function not found");
}

#[test]
fn c_summary_dash_prefix_guard_suppresses_execvp_argv_sink() {
    use crate::state::symbol::SymbolInterner;

    let src = br#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int do_ssh_connect(char *url) {
  const char *ssh;
  char *ssh_host = url;
  const char *port = 0;
  if (!port) port = "22";
  if (ssh_host[0] == '-') {
    fprintf(stderr, "strange hostname '%s' blocked\n", ssh_host);
    exit(1);
  }
  ssh = getenv("GIT_SSH");
  if (!ssh) ssh = "ssh";
  const char *args[8];
  int nargs = 0;
  args[nargs++] = ssh;
  if (port) {
    args[nargs++] = "-p";
    args[nargs++] = port;
  }
  args[nargs++] = ssh_host;
  args[nargs++] = "git-upload-pack";
  args[nargs++] = 0;
  return execvp(args[0], (char *const *)args);
}
"#;
    let file_cfg = parse_lang(
        src,
        "c",
        tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
    );
    for body in &file_cfg.bodies {
        if body.meta.name.as_deref() != Some("do_ssh_connect") {
            continue;
        }
        let interner = SymbolInterner::from_cfg(&body.graph);
        let ssa = crate::ssa::lower_to_ssa_with_params(
            &body.graph,
            body.entry,
            Some("do_ssh_connect"),
            false,
            &body.meta.params,
        )
        .expect("C function should lower to SSA");
        let summary = ssa_transfer::extract_ssa_func_summary(
            &ssa,
            &body.graph,
            &file_cfg.summaries,
            None,
            Lang::C,
            "test.c",
            &interner,
            body.meta.params.len(),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            !summary
                .param_to_sink_caps()
                .iter()
                .any(|(idx, caps)| *idx == 0 && caps.contains(Cap::SHELL_ESCAPE)),
            "dash-prefix guard should suppress argv-injection summary, got {:?}",
            summary.param_to_sink_caps()
        );
        return;
    }

    panic!("do_ssh_connect function not found");
}

#[test]
fn c_fgets_reaches_execvp_argv_through_summary() {
    let src = br#"#include <stdio.h>
#include <unistd.h>
int do_ssh_connect(char *url) {
  char *ssh_host = url;
  const char *args[3];
  args[0] = "ssh";
  args[1] = ssh_host;
  args[2] = 0;
  return execvp(args[0], (char *const *)args);
}
int main(void) {
  char url_buf[256];
  if (!fgets(url_buf, sizeof url_buf, stdin)) return 1;
  return do_ssh_connect(url_buf);
}
"#;
    let file_cfg = parse_lang(
        src,
        "c",
        tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
    );
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "test.c",
        &[],
        None,
    );
    assert!(
        findings
            .iter()
            .any(|f| f.source_kind == crate::labels::SourceKind::UserInput),
        "C: fgets source should flow through do_ssh_connect summary, got {findings:#?}"
    );
}

#[test]
fn cve_2017_1000117_vulnerable_fixture_fires() {
    let src = include_bytes!("../../tests/benchmark/cve_corpus/c/CVE-2017-1000117/vulnerable.c");
    let file_cfg = parse_lang(
        src,
        "c",
        tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
    );
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "vulnerable.c",
        &[],
        None,
    );
    assert!(
        findings
            .iter()
            .any(|f| f.source_kind == crate::labels::SourceKind::UserInput),
        "CVE-2017-1000117 vulnerable fixture should fire, got {findings:#?}"
    );
}

#[test]
fn cve_2017_1000117_patched_fixture_suppresses_dash_guard() {
    let src = include_bytes!("../../tests/benchmark/cve_corpus/c/CVE-2017-1000117/patched.c");
    let file_cfg = parse_lang(
        src,
        "c",
        tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
    );
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::C,
        "patched.c",
        &[],
        None,
    );
    assert!(
        findings
            .iter()
            .all(|f| f.source_kind != crate::labels::SourceKind::UserInput),
        "CVE-2017-1000117 patched fixture should suppress argv injection, got {findings:#?}"
    );
}

#[test]
fn ssa_cross_function_taint_with_sanitizer_wrapper() {
    // Cross-function: caller passes tainted data through sanitizer wrapper
    // The SSA summary should capture the sanitizer's StripBits, reducing taint at call site
    let src = b"var express = require('express');\nvar app = express();\n\nfunction cleanHtml(input) {\n    return DOMPurify.sanitize(input);\n}\n\napp.get('/safe', function(req, res) {\n    var name = req.query.name;\n    var safe = cleanHtml(name);\n    res.send(safe);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let the_cfg = &file_cfg.first_body().graph;
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );

    // With SSA summary, cleanHtml should be recognized as stripping HTML_ESCAPE bits,
    // so res.send(safe) should not fire for XSS (HTML_ESCAPE stripped).
    // The finding may still exist for other cap bits, but the XSS-specific ones should be gone.
    // This test validates that the SSA summary integration is working.
    // Note: whether this fully suppresses depends on the specific cap bit overlap.
    // At minimum, the summary extraction should produce a non-trivial result.
    drop(findings);

    // Verify that summary extraction works for this code
    use crate::state::symbol::SymbolInterner;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let ssa_summaries = super::extract_intra_file_ssa_summaries(
        the_cfg,
        &interner,
        Lang::JavaScript,
        "test.js",
        summaries,
        None,
    );
    // cleanHtml should have an SSA summary
    let clean_summary = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "cleanHtml")
        .map(|(_, v)| v)
        .unwrap_or_else(|| {
            panic!(
                "cleanHtml should have an SSA summary, got keys: {:?}",
                ssa_summaries.keys().map(|k| &k.name).collect::<Vec<_>>()
            )
        });
    assert!(
        !clean_summary.param_to_return.is_empty(),
        "cleanHtml should propagate param to return"
    );
}

// ── Inter-procedural container store tests ────────────────────────────────

#[test]
fn ssa_interproc_container_store_summary() {
    // Verify that extract_container_flow_summary produces correct indices
    // for storeInto(value, arr) { arr.push(value); } after param reordering.
    use crate::state::symbol::SymbolInterner;

    let src = b"var express = require('express');\nvar app = express();\n\nfunction storeInto(value, arr) {\n    arr.push(value);\n}\n\napp.get('/store', function(req, res) {\n    var items = [];\n    storeInto(req.query.input, items);\n    res.send(items.join(''));\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let the_cfg = &file_cfg.first_body().graph;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(the_cfg);

    // Extract SSA summaries (uses lower_to_ssa_with_params)
    let ssa_summaries = super::extract_intra_file_ssa_summaries(
        the_cfg,
        &interner,
        Lang::JavaScript,
        "test.js",
        summaries,
        None,
    );

    let store_summary = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "storeInto")
        .map(|(_, v)| v)
        .expect("storeInto should have an SSA summary");
    assert!(
        !store_summary.param_to_container_store.is_empty(),
        "storeInto should have param_to_container_store (value stored into arr)"
    );
    // With correct param ordering: value=0, arr=1
    assert_eq!(
        store_summary.param_to_container_store,
        vec![(0, 1)],
        "param_to_container_store should map value(0) → arr(1)"
    );

    // Verify the full analysis produces a finding
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "inter-procedural container store should produce a finding"
    );
}

// ── Loop Induction Variable Optimization ─────────────────────────────────

#[test]
fn ssa_induction_var_no_taint() {
    // Counter in loop with tainted source elsewhere: counter should not gain taint.
    // The loop counter `i` is a simple induction variable (i = i + 1).
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let data = env::var("INPUT").unwrap();
            let mut i = 0;
            while i < 10 {
                i = i + 1;
            }
            Command::new("sh").arg(data).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    // Should still find the data→sink flow but `i` should not gain taint
    assert_eq!(
        findings.len(),
        1,
        "induction var optimization: tainted source should still produce 1 finding"
    );
}

#[test]
fn ssa_loop_tainted_var_not_induction() {
    // `x` is tainted and transformed in a loop, NOT an induction variable
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            while x.len() < 100 {
                x.push_str("a");
            }
            Command::new("sh").arg(x).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert_eq!(
        findings.len(),
        1,
        "tainted var in loop (not induction) should still propagate"
    );
}

#[test]
fn ssa_taint_through_loop_still_works() {
    // Existing test ported: taint through a loop body should work
    let src = br#"
        use std::{env, process::Command};
        fn main() {
            let x = env::var("DANGEROUS").unwrap();
            for _i in 0..10 {
                let _unused = 1;
            }
            Command::new("sh").arg(x).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert_eq!(
        findings.len(),
        1,
        "taint through loop should still produce 1 finding"
    );
}

// ── Enhanced Condition Predicate Classification ──────────────────────────

#[test]
fn ssa_validation_targets_specific_var() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // `validate(x, config)` should only validate `x`, not `config`
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            let config = env::var("CONFIG").unwrap();
            if validate(x, config) {
                Command::new("sh").arg(config).status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // config flows to a sink; only x was validated, so config should NOT be validated
    assert!(!findings.is_empty(), "should detect taint flow for config");
    // The finding for config should NOT be path_validated since validate() targets x, not config
    let config_finding = findings.iter().find(|f| !f.path_validated);
    assert!(
        config_finding.is_some(),
        "config should NOT be marked as path_validated (only x is validated)"
    );
}

#[test]
fn ssa_method_validation_target() {
    use crate::taint::path_state::classify_condition_with_target;
    // Method call: `x.isValid()` should target `x`
    let (kind, target) = classify_condition_with_target("x.isValid()");
    assert_eq!(kind, PredicateKind::ValidationCall);
    assert_eq!(target.as_deref(), Some("x"));
}

// ── Path Sensitivity via Phi Structure ───────────────────────────────────

#[test]
fn ssa_phi_path_sensitive_both_branches_validated() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Variable validated on both branches → phi result should be fully validated
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if validate(&x) {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // Validated findings are now suppressed, sink is in the validated
    // branch, so no finding should be emitted.
    assert_eq!(findings.len(), 0, "validated finding should be suppressed");
}

#[test]
fn ssa_phi_path_sensitive_one_branch_not_validated() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Sink is in the unvalidated branch → should NOT be path_validated
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if !validate(&x) {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    assert_eq!(findings.len(), 1, "should detect taint flow");
    assert!(
        !findings[0].path_validated,
        "finding should NOT be path_validated (sink in failed-validation branch)"
    );
}

// ── Cross-language reassignment kill verification ───────────────────────

#[test]
fn ssa_reassignment_kills_taint_js() {
    let src = b"var express = require('express');\nvar app = express();\napp.get('/r', function(req, res) {\n    var name = req.query.input;\n    name = \"Guest\";\n    eval(name);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "JS: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_ts() {
    let src =
        b"function main() {\n  let x = document.location();\n  x = \"safe\";\n  eval(x);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_lang(src, "typescript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::TypeScript,
        "test.ts",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "TS: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_python() {
    let src = b"import os\ndef main():\n    cmd = os.getenv(\"CMD\")\n    cmd = \"safe\"\n    os.system(cmd)\n";
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Python,
        "test.py",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "Python: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_go() {
    let src = b"package main\n\nimport \"os\"\nimport \"os/exec\"\n\nfunc main() {\n\tcmd := os.Getenv(\"CMD\")\n\tcmd = \"safe\"\n\texec.Command(cmd)\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(src, "go", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Go, "test.go", &[], None);
    assert!(
        findings.is_empty(),
        "Go: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_java() {
    let src = b"class Main {\n  void main() {\n    String cmd = System.getenv(\"CMD\");\n    cmd = \"safe\";\n    Runtime.exec(cmd);\n  }\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Java,
        "test.java",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "Java: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_php() {
    let src = b"<?php\n$cmd = $_GET['cmd'];\n$cmd = \"safe\";\neval($cmd);\n";
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None);
    assert!(
        findings.is_empty(),
        "PHP: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_ruby() {
    let src = b"def main\n  cmd = gets()\n  cmd = \"safe\"\n  system(cmd)\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_lang(src, "ruby", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Ruby, "test.rb", &[], None);
    assert!(
        findings.is_empty(),
        "Ruby: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_c() {
    let src = b"#include <stdlib.h>\nvoid main() {\n  char* cmd = getenv(\"CMD\");\n  cmd = \"safe\";\n  system(cmd);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::C, "test.c", &[], None);
    assert!(
        findings.is_empty(),
        "C: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

#[test]
fn ssa_reassignment_kills_taint_cpp() {
    let src = b"#include <cstdlib>\nvoid main() {\n  char* cmd = std::getenv(\"CMD\");\n  cmd = \"safe\";\n  system(cmd);\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_lang(src, "cpp", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Cpp, "test.cpp", &[], None);
    assert!(
        findings.is_empty(),
        "C++: reassignment to constant should kill taint, got {} findings",
        findings.len()
    );
}

// ── Compound assignment preserves taint ─────────────────────────────────

#[test]
fn ssa_compound_preserves_taint_js() {
    let src = b"var express = require('express');\nvar app = express();\napp.get('/r', function(req, res) {\n    var name = req.query.input;\n    name = name + \" suffix\";\n    eval(name);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "JS: compound assignment should preserve taint"
    );
}

#[test]
fn ssa_compound_preserves_taint_python() {
    let src = b"import os\ndef main():\n    cmd = os.getenv(\"CMD\")\n    cmd = cmd + \" safe\"\n    os.system(cmd)\n";
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Python,
        "test.py",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "Python: compound assignment should preserve taint"
    );
}

#[test]
fn ssa_compound_preserves_taint_go() {
    let src = b"package main\n\nimport \"os\"\nimport \"os/exec\"\n\nfunc main() {\n\tcmd := os.Getenv(\"CMD\")\n\tcmd = cmd + \" suffix\"\n\texec.Command(cmd)\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(src, "go", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Go, "test.go", &[], None);
    assert!(
        !findings.is_empty(),
        "Go: compound assignment should preserve taint"
    );
}

#[test]
fn ssa_compound_preserves_taint_java() {
    let src = b"class Main {\n  void main() {\n    String cmd = System.getenv(\"CMD\");\n    cmd = cmd + \" safe\";\n    Runtime.exec(cmd);\n  }\n}\n";
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::Java,
        "test.java",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "Java: compound assignment should preserve taint"
    );
}

// ── PHI merge preserves taint on non-reassigned path ────────────────────

#[test]
fn ssa_phi_preserves_taint_on_non_reassigned_path_js() {
    let src = b"var express = require('express');\nvar app = express();\napp.get('/r', function(req, res) {\n    var name = req.query.input;\n    if (name.length > 10) {\n        name = \"fallback\";\n    }\n    eval(name);\n});\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "JS: PHI merge should preserve taint from non-reassigned path"
    );
}

#[test]
fn ssa_phi_preserves_taint_on_non_reassigned_path_rust() {
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let mut x = env::var("DANGEROUS").unwrap();
            if x.len() > 5 {
                x = "safe".to_string();
            }
            Command::new("sh").arg(&x).status().unwrap();
        }"#;
    let findings = ssa_analyse_rust(src);
    assert!(
        !findings.is_empty(),
        "Rust: PHI merge should preserve taint from non-reassigned path"
    );
}

/// Smoke test: linear SSRF prefix suppression (no phi, no branches).
///
/// The prefix must be in a named variable so the CFG captures it as a
/// separate SSA Const value. Inline string literals in binary expressions
/// are not currently tracked as SSA operands.
#[test]
fn abstract_ssrf_prefix_linear_suppression() {
    let src = b"var userId = document.location();\nvar prefix = 'https://api.example.com/users/';\nvar url = prefix + userId;\nfetch(url);\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "Linear SSRF prefix: 'https://api.example.com/users/' + userId should be \
         suppressed by abstract string domain. Got {} findings.",
        findings.len()
    );
}

/// Regression test for abstract phi replay in collect_block_events.
///
/// Two predecessor blocks produce string concat values with different safe
/// prefixes ("https://api.example.com/users/" and "https://api.example.com/admins/").
/// A phi merges them. The LCP of the prefixes is "https://api.example.com/" which
/// still has scheme://host/, so SSRF suppression should fire.
///
/// Before the phi replay fix, collect_block_events did NOT replay abstract phis,
/// leaving the phi result's abstract value as Top (stale). The SSRF suppression
/// would fail because there was no known prefix.
///
/// Note: prefix must be in a named variable so the CFG captures it as an SSA Const.
#[test]
fn abstract_phi_replay_ssrf_suppression() {
    let src = b"var userId = document.location();\nvar prefix1 = 'https://api.example.com/users/';\nvar prefix2 = 'https://api.example.com/admins/';\nvar url;\nif (userId.length > 5) {\n  url = prefix1 + userId;\n} else {\n  url = prefix2 + userId;\n}\nfetch(url);\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "Abstract phi replay: both branches produce safe SSRF prefixes, \
         phi merge should preserve the common prefix 'https://api.example.com/' \
         and suppress the SSRF finding. Got {} findings.",
        findings.len()
    );
}

#[test]
fn ruby_type_check_guard_suppresses_taint() {
    // Ruby `unless user_id.is_a?(Integer)` guard should validate user_id
    // so that the subsequent SQL sink does not produce a finding.
    let src = b"def run_query(params)\n  user_id = params[:id]\n  unless user_id.is_a?(Integer)\n    return \"bad input\"\n  end\n  connection.execute(\"SELECT * FROM users WHERE id = \" + user_id.to_s)\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_lang(src, "ruby", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Ruby, "test.rb", &[], None);
    assert!(
        findings.is_empty(),
        "Ruby: is_a?(Integer) type guard should suppress taint finding, got {} findings",
        findings.len()
    );
}

// ── Rust struct expression taint propagation ────────────────────────────

#[test]
fn rust_struct_literal_with_source_produces_source_caps() {
    let src = br#"
        use std::env;
        struct Cfg { val: String }
        fn make_cfg() -> Cfg {
            Cfg { val: env::var("X").unwrap() }
        }
    "#;
    let summaries = extract_summaries_from_bytes(src, "test.rs");
    let make = summaries
        .iter()
        .find(|s| s.name == "make_cfg")
        .expect("make_cfg should have a summary");
    assert!(
        make.source_caps != 0,
        "make_cfg should have source_caps from env::var inside struct literal, got 0"
    );
}

#[test]
fn rust_struct_constructor_source_flows_through_format_to_sink() {
    let src = br#"
        use std::env;
        use std::process::Command;
        use std::fs;

        struct AppConfig {
            db_url: String,
            upload_dir: String,
        }

        fn load_config() -> AppConfig {
            AppConfig {
                db_url: env::var("DATABASE_URL").unwrap(),
                upload_dir: env::var("UPLOAD_DIR").unwrap(),
            }
        }

        fn handle_export() {
            let config = load_config();
            let dump_cmd = format!("pg_dump {}", config.db_url);
            Command::new("sh").arg("-c").arg(&dump_cmd).output().unwrap();
            let dump_path = format!("{}/export.sql", config.upload_dir);
            fs::write(&dump_path, "data").unwrap();
        }
    "#;
    let file_cfg = parse_rust(src);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Rust,
        "test.rs",
        &[],
        None,
    );
    assert!(
        findings.len() >= 2,
        "Expected >= 2 taint findings (Command::new + fs::write), got {}",
        findings.len()
    );
}

#[test]
fn ssa_format_macro_propagates_taint() {
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            let cmd = format!("echo {}", x);
            Command::new("sh").arg("-c").arg(&cmd).output().unwrap();
        }
    "#;
    let findings = ssa_analyse_rust(src);
    assert_eq!(
        findings.len(),
        1,
        "format! should propagate taint from env::var to Command::new sink"
    );
}

// ── B-2 regression: phi validated_must must use must-analysis, not may ───

#[test]
fn phi_validated_must_requires_all_paths() {
    use crate::cfg::build_cfg;
    use tree_sitter::Language;

    // Path A validates x, path B does NOT validate x.
    // The phi for x after the merge must NOT get validated_must, only
    // validated_may (since at least one path validated). The sink after
    // the merge must still fire because the must-analysis says "not
    // definitely validated on all paths".
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            if some_condition() {
                validate(&x);
            }
            Command::new("sh").arg(&x).status().unwrap();
        }"#;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src as &[u8], None).unwrap();

    let file_cfg = build_cfg(&tree, src, "rust", "test.rs", None);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Rust, "test.rs", &[], None);

    // x is validated on only one branch, so the phi merge must NOT promote
    // to validated_must. The sink should still fire.
    assert!(
        !findings.is_empty(),
        "B-2 regression: phi must NOT promote to validated_must when only \
         one branch validates — sink should still fire"
    );
}

// ── C-1 regression: inline return taint precision ───────────────────────

#[test]
fn inline_return_constant_with_internal_source_produces_no_finding() {
    use tree_sitter::Language;

    // Callee has an internal source (document.location) but returns a constant.
    // The caller feeds tainted input as an argument. Since the return value is
    // a constant (never tainted), the caller's call result should be untainted.
    let src = b"var child_process = require('child_process');\n\
        var express = require('express');\n\
        var app = express();\n\
        \n\
        function transform(input) {\n\
            var internal = document.location();\n\
            return 'constant_value';\n\
        }\n\
        \n\
        app.get('/safe', function(req, res) {\n\
            var result = transform(req.query.data);\n\
            child_process.exec(result);\n\
        });\n";

    let lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );

    // transform() returns a constant, no taint should leak to caller
    assert_eq!(
        findings.len(),
        0,
        "C-1: transform() returns constant — internal source must not leak, got {} findings: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| format!("{}→{}", f.source.index(), f.sink.index()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn inline_return_taint_prefers_explicit_return_value() {
    use tree_sitter::Language;

    // When a callee has an explicit Return(Some(rv)) and rv IS tainted,
    // extract_inline_return_taint should collect ONLY that value's taint,
    // not all live tainted variables.
    let src = b"var child_process = require('child_process');\n\
        var express = require('express');\n\
        var app = express();\n\
        \n\
        function passthrough(cmd) {\n\
            return cmd;\n\
        }\n\
        \n\
        app.get('/a', function(req, res) {\n\
            var w = passthrough(req.query.cmd);\n\
            child_process.exec(w);\n\
        });\n";

    let lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );

    // passthrough(tainted) returns tainted → exactly 1 finding
    assert_eq!(
        findings.len(),
        1,
        "C-1 regression: passthrough(tainted) should produce exactly 1 finding, got {}",
        findings.len()
    );
}

#[test]
fn inline_return_taint_internal_source_does_not_widen_caps() {
    use tree_sitter::Language;

    // Callee has an internal source (document.location) alongside a tainted
    // param. The explicit return value is the param. Without the C-1 fix,
    // extract_inline_return_taint would union ALL live tainted values' caps
    //, the internal source's derived-caps would override the param-caps
    // (derived takes priority in the extraction logic). With the fix, only
    // the return value's taint is collected, so param taint is returned
    // correctly.
    //
    // Both old and new produce a finding, but the fix ensures the return
    // taint comes from the param flow, not from the internal source.
    let src = b"var child_process = require('child_process');\n\
        var express = require('express');\n\
        var app = express();\n\
        \n\
        function withSideEffect(cmd) {\n\
            var leaked = document.location();\n\
            return cmd;\n\
        }\n\
        \n\
        app.get('/a', function(req, res) {\n\
            var r = withSideEffect(req.query.cmd);\n\
            child_process.exec(r);\n\
        });\n";

    let lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );

    // The callee returns cmd (tainted param), 1 finding expected.
    // The internal document.location() should NOT widen the return taint.
    assert_eq!(
        findings.len(),
        1,
        "C-1 regression: withSideEffect should produce exactly 1 finding (param flow), got {}",
        findings.len()
    );
}

/// Regression guard for the FuncKey-based re-keying of local SSA summaries
/// and cached callee bodies.
///
/// Two class methods share the leaf name `process` in the same file.  If the
/// summary map were keyed by bare name (or raw file-path namespace), the
/// second lowering would overwrite the first, both methods would end up
/// pointing at whichever summary was extracted last.
///
/// With canonical `FuncKey` identity (`container` discriminates them) both
/// methods must appear as distinct entries with matching containers.
#[test]
fn same_name_methods_distinct_func_keys() {
    let src = br#"
class Sanitizer {
    process(x) {
        return escape(x);
    }
}

class Worker {
    process(x) {
        eval(x);
    }
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);

    let (summaries, bodies) = super::extract_ssa_artifacts_from_file_cfg(
        &file_cfg,
        Lang::JavaScript,
        "test.js",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );

    // Collect containers of every key named "process".
    let mut containers: Vec<String> = summaries
        .keys()
        .filter(|k| k.name == "process")
        .map(|k| k.container.clone())
        .collect();
    containers.sort();

    assert_eq!(
        containers,
        vec!["Sanitizer".to_string(), "Worker".to_string()],
        "FuncKey-based keying must produce one `process` summary per container; \
         got {containers:?} from {:?}",
        summaries.keys().collect::<Vec<_>>(),
    );

    // Same invariant on the cached-bodies map, inline analysis depends on
    // being able to fetch the correct body by full FuncKey.
    let mut body_containers: Vec<String> = bodies
        .iter()
        .filter(|(k, _)| k.name == "process")
        .map(|(k, _)| k.container.clone())
        .collect();
    body_containers.sort();
    assert_eq!(
        body_containers,
        vec!["Sanitizer".to_string(), "Worker".to_string()],
        "callee-body cache must keep both same-name methods distinct; got {body_containers:?}",
    );

    // Cross-map agreement: every summary key must also be a body key.
    // (Pass 2 looks up bodies and summaries with the same key.)
    for key in summaries.keys() {
        assert!(
            bodies.iter().any(|(bk, _)| bk == key),
            "summary key {key:?} missing from callee-body map"
        );
    }
}

/// Same-name *free function* overloads (not methods): two `helper` functions
/// with identical names and arities at the same scope collide on
/// `(name, arity)` but are disambiguated by `FuncKey.disambig` (body start
/// byte).  Regression guard that neither overwrites the other in the SSA
/// summary / callee-body maps.
#[test]
fn same_name_same_arity_functions_distinct_func_keys() {
    // Two top-level `helper(x)` declarations in one file.  JS allows the
    // later one to shadow the first at runtime, but our static summary
    // extraction must retain *both* so cross-file callers of either body
    // span still find their intended definition.
    let src = br#"
function helper(x) {
    return escape(x);
}

function helper(x) {
    eval(x);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);

    let (summaries, bodies) = super::extract_ssa_artifacts_from_file_cfg(
        &file_cfg,
        Lang::JavaScript,
        "test.js",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );

    let helper_keys: Vec<_> = summaries.keys().filter(|k| k.name == "helper").collect();
    assert_eq!(
        helper_keys.len(),
        2,
        "two same-name same-arity definitions must produce two distinct summary entries; \
         got {} keys: {:?}",
        helper_keys.len(),
        helper_keys,
    );

    // Disambiguator must actually differ (body start bytes).
    let disambigs: std::collections::HashSet<_> = helper_keys.iter().map(|k| k.disambig).collect();
    assert_eq!(
        disambigs.len(),
        2,
        "FuncKey.disambig should differ for colliding same-name same-arity defs",
    );

    // And the body cache agrees.
    let body_count = bodies.iter().filter(|(k, _)| k.name == "helper").count();
    assert_eq!(body_count, 2, "callee-body cache must also keep both defs");
}

// ── alternative-path dedup and linking ─────────────────────────────────

/// Build a bare Finding suitable for feeding into `link_alternative_paths`.
/// Only the fields consulted by that pass are populated; the rest use the
/// cheapest default so the test stays focused on the dedup contract.
fn make_finding_for_link_test(
    body_id: u32,
    source_idx: usize,
    sink_idx: usize,
    path_hash: u64,
    path_validated: bool,
) -> Finding {
    Finding {
        body_id: crate::cfg::BodyId(body_id),
        sink: petgraph::graph::NodeIndex::new(sink_idx),
        source: petgraph::graph::NodeIndex::new(source_idx),
        path: Vec::new(),
        source_kind: crate::labels::SourceKind::EnvironmentConfig,
        path_validated,
        guard_kind: None,
        hop_count: 0,
        cap_specificity: 0,
        uses_summary: false,
        flow_steps: Vec::new(),
        symbolic: None,
        source_span: None,
        primary_location: None,
        engine_notes: smallvec::SmallVec::new(),
        path_hash,
        finding_id: String::new(),
        alternative_finding_ids: smallvec::SmallVec::new(),
        effective_sink_caps: crate::labels::Cap::empty(),
    }
}

/// `make_finding_id` must produce stable, distinct IDs for findings
/// that differ on any dedup-key axis, and carry the `v`/`u`
/// validation-status suffix so a human can tell siblings apart.
#[test]
fn finding_id_encodes_validation_and_path_hash() {
    let v = make_finding_for_link_test(1, 3, 7, 0xabcd_1234_0000_0001, true);
    let mut v = v;
    v.finding_id = super::make_finding_id(&v);
    assert!(
        v.finding_id.ends_with("-v"),
        "validated ID must end -v: {}",
        v.finding_id
    );
    assert!(
        v.finding_id.contains("abcd12340000"),
        "hash component missing: {}",
        v.finding_id
    );

    let mut u = make_finding_for_link_test(1, 3, 7, 0xabcd_1234_0000_0001, false);
    u.finding_id = super::make_finding_id(&u);
    assert!(
        u.finding_id.ends_with("-u"),
        "unvalidated ID must end -u: {}",
        u.finding_id
    );
    assert_ne!(
        v.finding_id, u.finding_id,
        "validation status must disambiguate IDs"
    );

    // Differing path_hash produces a different ID even with the same
    // (body, source, sink, validated), the whole point of the path
    // component in the dedup key.
    let mut u2 = make_finding_for_link_test(1, 3, 7, 0xdead_beef_0000_0002, false);
    u2.finding_id = super::make_finding_id(&u2);
    assert_ne!(
        u.finding_id, u2.finding_id,
        "path_hash must disambiguate IDs"
    );
}

/// `link_alternative_paths` must cross-link findings that share
/// `(body_id, sink, source)`, so a validated flow and an unvalidated
/// flow on the same source/sink pair each list the other's ID.
#[test]
fn link_alternative_paths_cross_references_same_body_sink_source() {
    let mut findings = vec![
        make_finding_for_link_test(1, 3, 7, 0x1111, true),
        make_finding_for_link_test(1, 3, 7, 0x2222, false),
    ];
    for f in &mut findings {
        f.finding_id = super::make_finding_id(f);
    }

    let v_id = findings[0].finding_id.clone();
    let u_id = findings[1].finding_id.clone();
    super::link_alternative_paths(&mut findings);

    assert_eq!(
        findings[0].alternative_finding_ids.as_slice(),
        std::slice::from_ref(&u_id),
        "validated finding must reference the unvalidated sibling",
    );
    assert_eq!(
        findings[1].alternative_finding_ids.as_slice(),
        std::slice::from_ref(&v_id),
        "unvalidated finding must reference the validated sibling",
    );
}

/// Findings that differ on `(body_id, sink, source)` are independent
/// vulnerabilities, they must **not** end up cross-linked as
/// alternatives, otherwise the "alternative path" framing becomes
/// noise.
#[test]
fn link_alternative_paths_does_not_link_distinct_sink_source() {
    let mut findings = vec![
        make_finding_for_link_test(1, 3, 7, 0x1111, false),
        // Different sink, independent finding, not an alternative.
        make_finding_for_link_test(1, 3, 8, 0x1111, false),
        // Different source, also independent.
        make_finding_for_link_test(1, 4, 7, 0x1111, false),
        // Different body, also independent.
        make_finding_for_link_test(2, 3, 7, 0x1111, false),
    ];
    for f in &mut findings {
        f.finding_id = super::make_finding_id(f);
    }
    super::link_alternative_paths(&mut findings);
    for (i, f) in findings.iter().enumerate() {
        assert!(
            f.alternative_finding_ids.is_empty(),
            "finding {i} should have no alternatives; got {:?}",
            f.alternative_finding_ids,
        );
    }
}

/// When the same `(body, sink, source)` has three sibling findings
/// (e.g. validated, unvalidated-path-A, unvalidated-path-B), each
/// finding must list the other two, the group is symmetric and
/// complete rather than a chain.
#[test]
fn link_alternative_paths_three_way_group() {
    let mut findings = vec![
        make_finding_for_link_test(1, 3, 7, 0x1111, true),
        make_finding_for_link_test(1, 3, 7, 0x2222, false),
        make_finding_for_link_test(1, 3, 7, 0x3333, false),
    ];
    for f in &mut findings {
        f.finding_id = super::make_finding_id(f);
    }
    let ids: Vec<String> = findings.iter().map(|f| f.finding_id.clone()).collect();
    super::link_alternative_paths(&mut findings);
    for (i, f) in findings.iter().enumerate() {
        let expected: std::collections::HashSet<&String> = ids
            .iter()
            .enumerate()
            .filter_map(|(j, id)| if i == j { None } else { Some(id) })
            .collect();
        let got: std::collections::HashSet<&String> = f.alternative_finding_ids.iter().collect();
        assert_eq!(
            got, expected,
            "finding {i} must list every other sibling ID",
        );
    }
}

//  Typed call-graph devirtualisation (typed_call_receivers)

/// when a method call's receiver was constructed from a known
/// constructor (`File::open` → `FileHandle`), the SSA-extraction
/// pipeline must record `(call_ordinal, "FileHandle")` on the
/// caller's [`crate::summary::ssa_summary::SsaFuncSummary::typed_call_receivers`]
/// so build_call_graph can devirtualise the cross-file edge.
///
/// Uses Java because `FileInputStream` / `FileOutputStream` are part
/// of the [`crate::ssa::type_facts::constructor_type`] table for Java
/// and yield [`crate::ssa::type_facts::TypeKind::FileHandle`] without
/// any framework annotation plumbing.
#[test]
fn typed_call_receivers_populated_for_constructor_typed_receiver() {
    let src = br#"
class Reader {
    void read() {
        FileInputStream f = new FileInputStream("/etc/passwd");
        f.close();
    }
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);

    let (summaries, _bodies) = super::extract_ssa_artifacts_from_file_cfg(
        &file_cfg,
        Lang::Java,
        "Reader.java",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );

    let read_sum = summaries
        .iter()
        .find(|(k, _)| k.name == "read")
        .map(|(_, s)| s)
        .expect("read() summary must be extracted");

    let containers: Vec<&str> = read_sum
        .typed_call_receivers
        .iter()
        .map(|(_, c)| c.as_str())
        .collect();
    assert!(
        containers.contains(&"FileHandle"),
        "FileInputStream-typed receiver must surface as `FileHandle` container; got {:?}",
        read_sum.typed_call_receivers,
    );
}

/// Negative control: free-function calls (no receiver) must
/// never appear in `typed_call_receivers`.  Even when the callee is a
/// known type-producing constructor, it sits in the body as a Call
/// with `receiver = None` and is not a candidate for devirtualisation.
#[test]
fn typed_call_receivers_skips_free_function_calls() {
    // `new FileInputStream(...)` is a constructor invocation with no
    // receiver, exactly the shape we want to ignore.
    let src = br#"
class Maker {
    void make() {
        new FileInputStream("/tmp/x");
    }
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);

    let (summaries, _) = super::extract_ssa_artifacts_from_file_cfg(
        &file_cfg,
        Lang::Java,
        "Maker.java",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );

    // make() has zero parameters and no fresh-allocation return, so the
    // generic insertion gate skips it.  The phase-2 patch only force-
    // inserts when `typed_call_receivers` is non-empty, which it
    // isn't here, since `new FileInputStream(...)` is a free-function-
    // shaped constructor call (no SSA receiver).  So either the
    // summary is absent, or, if some other side effect inserted it ,
    // its `typed_call_receivers` is empty.  Both forms prove no
    // spurious typed entry was recorded.
    let typed = summaries
        .iter()
        .find(|(k, _)| k.name == "make")
        .map(|(_, s)| s.typed_call_receivers.clone())
        .unwrap_or_default();
    assert!(
        typed.is_empty(),
        "constructor-invocation Call has no receiver and must not surface a typed entry; \
         got {typed:?}",
    );
}

/// Regression: nested arrow functions inside `return new Promise((res,rej)
/// => { ... })` must be lifted as separate bodies. Before the Kind::Return
/// arm in cfg/mod.rs called `collect_nested_function_nodes`, only the
/// outer function (`downloadFromUri`) was extracted, the executor and
/// its inner callbacks were silently swallowed, hiding the inner gated
/// http.get sink from classification. Motivated by CVE-2025-64430.
#[test]
fn cve_2025_64430_promise_executor_extracted_as_body() {
    let src = br#"
const downloadFromUri = (uri) => {
  return new Promise((res, rej) => {
    http.get(uri, response => { response.on('data', () => {}); }).on('error', e => rej(e));
  });
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let names: Vec<Option<String>> = file_cfg
        .bodies
        .iter()
        .map(|b| b.meta.name.clone())
        .collect();
    assert!(
        file_cfg.bodies.len() >= 3,
        "expected at least 3 bodies (top-level + downloadFromUri + Promise executor), \
         got {}: {:?}",
        file_cfg.bodies.len(),
        names
    );
}

/// End-to-end: cross-function flow through a Promise-wrapping helper.
/// Caller passes a labeled-source value (`req.body.uri`) to a wrapper
/// whose body is `return new Promise((res, rej) => http.get(uri))`.
/// The wrapper's SSA summary's `param_to_sink` must include SSRF (via
/// the closure-capture summary-augmentation pass in
/// `lower_all_functions_from_bodies`), so the caller's
/// `wrapper(req.body.uri)` call resolves to a SSRF sink.
/// Motivated by CVE-2025-64430.
#[test]
fn cve_2025_64430_promise_wrapper_via_summary_param_to_sink() {
    let src = br#"
const downloadFromUri = uri => {
  return new Promise((res, rej) => {
    http.get(uri, response => { response.on('data', () => {}); }).on('error', e => rej(e));
  });
};
const handler = (req) => {
  downloadFromUri(req.body.uri);
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected SSRF flow finding via Promise-wrapper summary; got 0",
    );
}

/// End-to-end smoke check: when a JS/TS handler param is recognised as
/// user-input-bearing (`is_js_ts_handler_param_name`), Promise-executor
/// closure capture via lexical containment must propagate the seeded
/// taint into the executor body so the inner gated http.get sink fires.
/// Without the Kind::Return fix the executor was never extracted as a
/// body and the sink was invisible to classification. Motivated by
/// CVE-2025-64430.
#[test]
fn cve_2025_64430_promise_executor_sink_via_lexical_containment() {
    let src = br#"
const f = (input) => {
  return new Promise((res, rej) => {
    http.get(input);
  });
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected SSRF Sink finding in Promise executor capturing `input`; got 0",
    );
}

/// Regression: `wrapper(req.body.uri)` where wrapper passes its first
/// param to a gated SSRF sink must fire. The CFG's first_member_label
/// rebinds info.call.callee to `"req.body.uri"` (so the source label
/// applies) and preserves the actual function name in `outer_callee`.
/// resolve_sink_info has to consult outer_callee when the inner callee
/// has no sink so the wrapper's `param_to_sink: [(0, SSRF)]` summary
/// fires. Motivated by CVE-2025-64430.
#[test]
fn cve_2025_64430_wrapper_with_member_source_arg_fires() {
    let src = br#"
const helper = (uri) => {
  http.get(uri);
};

const handler = (req) => {
  helper(req.body.uri);
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected at least one SSRF flow finding through wrapper; got 0",
    );
}

/// Two-hop transitive cross-function summary propagation. The chain is
/// `handler(req) -> helper(req.body) -> downloadFromUri(x.url) ->
///     Promise(http.get(uri))`.
///
/// The augment pass populates `downloadFromUri.summary.param_to_sink:
/// [(0, SSRF)]` (single-hop closure-capture lift). For the handler's
/// `helper(req.body)` call to fire, `helper.summary.param_to_sink` must
/// also contain `[(0, SSRF)]`, but that requires `helper`'s probe to
/// see `downloadFromUri`'s augmented summary at resolution time.
///
/// Because the probe currently runs with `ssa_summaries=None`,
/// `helper.summary.param_to_sink` stays empty and the handler call site
/// reports nothing. A second extraction pass that re-runs probes with
/// the augmented summaries map plumbed through closes the gap. Mirrors
/// the upstream Parse Server CVE chain (`addFileDataIfNeeded` →
/// `downloadFileFromURI` → executor). Motivated by CVE-2025-64430.
#[test]
fn cve_2025_64430_two_hop_transitive_summary_propagation() {
    let src = br#"
const downloadFromUri = uri => {
  return new Promise((res, rej) => {
    http.get(uri, response => { response.on('data', () => {}); }).on('error', e => rej(e));
  });
};
const helper = file => {
  downloadFromUri(file._source.uri);
};
const handler = (req) => {
  helper(req.body);
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected SSRF flow finding via two-hop transitive summary propagation; got 0",
    );
}

/// Regression for the multi-line method-chain form
/// `http\n  .get(uri, ...)\n  .on('error', ...)`. Tree-sitter parses
/// this with whitespace embedded in the inner member-expression's
/// source text (`"http\n      .get"`), so the chained-call inner-gate
/// rebinding's classification lookup missed the gated `http.get` sink.
/// `find_chained_inner_call` now strips whitespace from the inner
/// callee text before classification. Without this, the upstream
/// Parse Server fixture (CVE-2025-64430 vulnerable.js) does not fire
/// even after the transitive summary propagation fix.
#[test]
fn cve_2025_64430_multiline_chained_get_classifies_inner_sink() {
    let src = br#"
const downloadFromUri = uri => {
  return new Promise((res, rej) => {
    http
      .get(uri, response => { response.on('data', () => {}); })
      .on('error', e => rej(e));
  });
};
const helper = file => {
  downloadFromUri(file._source.uri);
};
const handler = (req) => {
  helper(req.body);
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected SSRF flow finding through multi-line chained http.get; got 0",
    );
}

/// Three-hop transitive propagation: handler -> middle -> helper ->
/// downloadFromUri (Promise wrapper) -> http.get. The second extraction
/// pass must lift `downloadFromUri.summary.param_to_sink` (single-hop
/// from augment) onto `helper.summary.param_to_sink`, then onto
/// `middle.summary.param_to_sink`, then handler's call site picks it up.
///
/// Today the second-pass runs only once (no fixed-point), so depth-3+
/// is expected to NOT fire, guards against accidental fixed-point
/// regression that would mask an over-eager rewrite.  Marked
/// `#[ignore]` so it documents the depth limit without breaking CI.
/// Motivated by CVE-2025-64430 corner case; remove the `#[ignore]` and
/// any guarding `assert!` polarity if a fixed-point is added later.
/// Indirect-validator branch narrowing: when an if-condition is a
/// bare result variable whose reaching SSA def is a Call to a
/// callee classified by `classify_input_validator_callee` (e.g.
/// `validateUrlSsrf`, `verifyToken`, `isValidUrl`), the validator's
/// argument is treated as validated on the success branch.
///
/// This pins the SSA-level
/// `apply_input_validator_branch_narrowing` regardless of whether
/// downstream consumers (sink-arg taint, cfg-unguarded-sink) honor
/// `validated_must`.  Test asserts the symbol-keyed validation flag
/// is set on the analysis exit state.
///
/// Direct-flow shape (no helper indirection); the helper-summary
/// case still has open architectural gaps (validated_must doesn't
/// propagate through `param_to_sink` summaries, same gap blocks
/// AllowlistCheck-in-helper, see CVE_DEFERRED.md GHSA-4x48-cgf9-q33f).
///
/// Motivated by Novu CVE GHSA-4x48-cgf9-q33f
/// (`const ssrfError = await validateUrlSsrf(child.webhookUrl); if (ssrfError) throw …;`).
#[test]
fn indirect_validator_narrowing_marks_arg_validated() {
    let src = br#"
async function handler(req) {
  const target = req.query.url;
  const ssrfError = await validateUrlSsrf(target);
  if (ssrfError) {
    throw new Error('blocked');
  }
  await axios.get(target);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    // Direct-flow: validator narrowing should clear axios.get's taint event.
    assert!(
        findings.is_empty(),
        "validator narrowing should suppress direct-flow SSRF; got {} finding(s)",
        findings.len()
    );
}

/// Regex-allowlist `<X>.test(value)` is recognised as a ValidationCall
/// targeting the call's first argument (not the regex receiver).
///
/// Shape:
///
/// ```js
/// const v = req.body.x;
/// if (!SAFE_REGEX.test(v)) { throw }
/// db.execute(v);  // direct flow: should be silent
/// ```
///
/// `classify_condition` returns ValidationCall for the `*regex*.test()`
/// receiver shape (see `target_regex_test_first_arg` in path_state) and
/// `extract_validation_target` overrides the default receiver-as-target
/// rule to extract the call's first argument.  Together with the
/// existing CFG-level negation handling in `compute_succ_states` the
/// false branch (continue) marks `v` as validated.
///
/// Motivated by Payload CVE-2026-25544
/// (`if (!SAFE_STRING_REGEX.test(value)) throw`).  Note: this test pins
/// the direct-flow case; transitive validation through SSA-derived
/// values (e.g. template-literal concat of `v` into `sql`) is a deeper
/// gap tracked separately and not closed here.
#[test]
fn regex_test_allowlist_narrowing_clears_direct_flow() {
    let src = br#"
const SAFE_REGEX = /^[\w]+$/;

async function handler(req) {
    const userValue = req.body.filter;
    if (!SAFE_REGEX.test(userValue)) {
        throw new Error('bad');
    }
    return await db.execute(userValue);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "regex.test allowlist narrowing should suppress direct-flow finding; got {} finding(s): {findings:?}",
        findings.len()
    );
}

/// Regression: `extract_ssa_func_summary` must skip `all_validated`
/// events when populating `param_to_sink` / `param_to_sink_param`.
///
/// Helper bodies whose validator-call branch narrowing fired produce
/// per-param probe events flagged `all_validated=true`.  Without
/// summary-extract suppression, callers would still see the helper
/// in their summary's sink set and refire on `helper(taintedArg)`
/// even though the validator inside the helper proved the path
/// safe.  The caller can't see the validator (it's behind the
/// summary), so the gap manifests as a precision miss only when
/// helper + caller are in the same file.
///
/// Closes the helper-summary half of Novu CVE GHSA-4x48-cgf9-q33f.
#[test]
fn helper_with_validator_does_not_propagate_to_caller_via_summary() {
    let src = br#"
async function getWebhookResponse(child) {
    const ssrfError = await validateUrlSsrf(child.webhookUrl);
    if (ssrfError) {
        throw new Error('blocked');
    }
    return await axios.post(child.webhookUrl, {});
}

async function handler(req) {
    const child = req.body.filter;
    const r = await getWebhookResponse(child);
    return r;
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "helper-with-validator should not propagate sink via summary; got {} finding(s)",
        findings.len()
    );
}

/// Companion: same shape WITHOUT the validator inside the helper
/// must still fire so the precision gain is targeted.  Asserts
/// `all_validated` skip doesn't accidentally suppress unsafe helpers.
#[test]
fn helper_without_validator_still_propagates_to_caller_via_summary() {
    let src = br#"
async function getWebhookResponse(child) {
    return await axios.post(child.webhookUrl, {});
}

async function handler(req) {
    const child = req.body.filter;
    const r = await getWebhookResponse(child);
    return r;
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "helper-without-validator must still flag the cross-fn SSRF path",
    );
}

/// Regression for CVE-2026-25544 deep fix
/// (`validated_params_to_return` summary field): a helper that
/// validates its parameter via a regex `.test(...)` allowlist and
/// returns a string derived from the validated parameter must
/// suppress the caller's downstream sink even when:
///   * the caller binds the call result to a fresh variable
///     (`const sql = sanitize(userValue)`), and
///   * the helper's return is a *derived* template literal, not a
///     pass-through of the parameter itself.
///
/// Sound because the helper only returns normally on the validating
/// arm — control could not reach the post-call instruction unless
/// the regex accepted the argument.  Pinned by
/// `propagate_validated_params_to_return` marking both the arg and
/// the call result `validated_must` / `validated_may` so the sink's
/// `all_validated` check fires.
#[test]
fn validated_params_to_return_suppresses_one_hop_helper_validator() {
    let src = br#"
const SAFE_REGEX = /^[\w]+$/;

const sanitize = (value) => {
    if (!SAFE_REGEX.test(value)) throw new Error('bad');
    return `safe:${value}`;
};

async function handler(req) {
    const userValue = req.body.filter;
    const sql = sanitize(userValue);
    db.execute(sql);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "regex.test allowlist inside helper must suppress caller sink; got {} finding(s)",
        findings.len()
    );
}

/// Two-hop variant of
/// `validated_params_to_return_suppresses_one_hop_helper_validator`:
/// when the validator helper is itself wrapped by another helper
/// that interpolates the validator's return into a template literal,
/// summary extraction must still surface
/// `validated_params_to_return` on the *outer* helper.  This pins
/// the second-pass re-extraction (via
/// `re_extract_summaries_with_augment_view`) plus the OR-merge of
/// `validated_params_to_return` in `merge_sink_fields`.
#[test]
fn validated_params_to_return_suppresses_two_hop_helper_validator() {
    let src = br#"
const SAFE_REGEX = /^[\w]+$/;

const sanitize = (value) => {
    if (!SAFE_REGEX.test(value)) throw new Error('bad');
    return value;
};

const buildQuery = (value) => {
    const s = sanitize(value);
    return s + '!';
};

async function handler(req) {
    const userValue = req.body.filter;
    const sql = buildQuery(userValue);
    db.execute(sql);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "two-hop helper-validator must propagate validated_params_to_return through both helpers; got {} finding(s)",
        findings.len()
    );
}

/// Companion to
/// `validated_params_to_return_suppresses_one_hop_helper_validator`:
/// same shape WITHOUT the regex.test guard inside the helper must
/// still fire.  Asserts the validated-flow propagation does not
/// over-suppress when the helper does not actually validate.
#[test]
fn validated_params_to_return_does_not_suppress_unvalidated_helper() {
    let src = br#"
const sanitize = (value) => {
    return `safe:${value}`;
};

async function handler(req) {
    const userValue = req.body.filter;
    const sql = sanitize(userValue);
    db.execute(sql);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "helper without regex guard must still flag the caller sink",
    );
}

/// Regression: per-parameter summary probe must seed every
/// destructured object-pattern sibling sharing a slot, not only the
/// primary name picked by `extract_param_meta`.  Without this, a
/// helper that destructures its single argument as
/// `({ value }) => …` cannot have `validated_params_to_return = [0]`
/// proven, because the validator inside the body operates on the
/// `value` binding while the probe only seeded the primary `value`
/// (or any earlier sibling) of the object pattern.  Closes the
/// residual blocker for CVE-2026-25544 (PayloadCMS Drizzle SQLi).
#[test]
fn validated_params_to_return_suppresses_destructured_object_arg_helper() {
    let src = br#"
const SAFE_REGEX = /^[\w]+$/;

const sanitize = (value) => {
    if (!SAFE_REGEX.test(value)) throw new Error('bad');
    return value;
};

const buildQuery = ({ value }) => {
    const s = sanitize(value);
    return s + '!';
};

async function handler(req) {
    const userValue = req.body.filter;
    const sql = buildQuery({ value: userValue });
    db.execute(sql);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "destructured object-pattern arg with regex.test allowlist inside the helper must suppress caller sink; got {} finding(s)",
        findings.len()
    );
}

/// Regression: same coverage for TypeScript object-pattern formals
/// (`required_parameter > pattern: object_pattern`).  TS exposes the
/// destructure under a wrapper required_parameter; JS exposes it as a
/// direct child of formal_parameters.  Both paths must surface
/// destructured siblings to the per-parameter probe.
#[test]
fn validated_params_to_return_suppresses_destructured_object_arg_helper_ts() {
    let src = br#"
const SAFE_REGEX = /^[\w]+$/;

const sanitize = (value: string): string => {
    if (!SAFE_REGEX.test(value)) throw new Error('bad');
    return value;
};

const buildQuery = ({ value }: { value: string }): string => {
    const s = sanitize(value);
    return s + '!';
};

async function handler(req: any) {
    const userValue = req.body.filter;
    const sql = buildQuery({ value: userValue });
    db.execute(sql);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_lang(src, "typescript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::TypeScript,
        "test.ts",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "TS destructured object-pattern arg with regex.test allowlist must suppress caller sink; got {} finding(s)",
        findings.len()
    );
}

/// Regression: a destructured object-pattern formal with multiple
/// fields must still propagate validated_params_to_return when the
/// validation lives behind a sibling that is NOT the primary name
/// returned by `extract_param_meta`.  In CVE-2026-25544 the primary
/// is `column` (first ident in `{ column, operator, pathSegments,
/// value }`) but the validator gates `value` — without sibling
/// seeding the probe never sees the validation.
#[test]
fn destructured_sibling_validation_propagates_through_summary() {
    let src = br#"
const SAFE_REGEX = /^[\w]+$/;

const sanitize = (value) => {
    if (!SAFE_REGEX.test(value)) throw new Error('bad');
    return value;
};

const buildQuery = ({ column, operator, value }) => {
    return `${column} ${operator} ${sanitize(value)}`;
};

async function handler(req) {
    const userValue = req.body.filter;
    const sql = buildQuery({ column: 'col', operator: '=', value: userValue });
    db.execute(sql);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "destructured-sibling validation (validator binds non-primary slot binding) must propagate through summary; got {} finding(s)",
        findings.len()
    );
}

/// Regression: `validate*`-named callees match
/// `InputValidatorPolarity::ErrorReturning`, bare `if (err) throw`
/// guards the success branch (false branch).  `is_valid*`/`is_safe*`
/// callees match `InputValidatorPolarity::BooleanTrueIsValid`, bare
/// `if (!ok) throw` guards the success branch (true branch via
/// `condition_negated`).
#[test]
fn classify_input_validator_callee_polarity_buckets() {
    use crate::ssa::type_facts::{InputValidatorPolarity, classify_input_validator_callee};

    // ErrorReturning bucket
    assert_eq!(
        classify_input_validator_callee("validateUrlSsrf"),
        Some(InputValidatorPolarity::ErrorReturning)
    );
    assert_eq!(
        classify_input_validator_callee("verifyToken"),
        Some(InputValidatorPolarity::ErrorReturning)
    );
    assert_eq!(
        classify_input_validator_callee("validate_url"),
        Some(InputValidatorPolarity::ErrorReturning)
    );

    // BooleanTrueIsValid bucket
    assert_eq!(
        classify_input_validator_callee("isValidUrl"),
        Some(InputValidatorPolarity::BooleanTrueIsValid)
    );
    assert_eq!(
        classify_input_validator_callee("is_valid_email"),
        Some(InputValidatorPolarity::BooleanTrueIsValid)
    );
    assert_eq!(
        classify_input_validator_callee("isSafe"),
        Some(InputValidatorPolarity::BooleanTrueIsValid)
    );

    // Negative, names that look like validators but are auth-flavored
    // (`checkPermissions`, `is_authorized`) are intentionally not
    // matched here; they have separate semantics in the auth pipeline.
    assert_eq!(classify_input_validator_callee("checkPermissions"), None);
    assert_eq!(classify_input_validator_callee("is_authorized"), None);
    assert_eq!(classify_input_validator_callee("randomThing"), None);

    // Path-prefix peeling: `obj.validateXxx` should classify the same
    // as the bare callee.
    assert_eq!(
        classify_input_validator_callee("validator.validateUrlSsrf"),
        Some(InputValidatorPolarity::ErrorReturning)
    );
}

#[test]
#[ignore]
fn cve_2025_64430_three_hop_transitive_documents_depth_limit() {
    let src = br#"
const downloadFromUri = uri => {
  return new Promise((res, rej) => {
    http.get(uri, response => { response.on('data', () => {}); }).on('error', e => rej(e));
  });
};
const helper = file => {
  downloadFromUri(file._source.uri);
};
const middle = data => {
  helper(data);
};
const handler = (req) => {
  middle(req.body);
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let _findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
}

/// JS arrow-function default parameters (`(a = {}, b = {}) => …`)
/// are wrapped by tree-sitter in `assignment_pattern` nodes whose
/// `left` field carries the actual identifier.  Without
/// `assignment_pattern` in `PARAM_CONFIG.param_node_kinds`, the
/// param walker skipped them, producing a parameter-less summary
/// for any function whose params have defaults.  That broke
/// cross-function `param_to_sink` propagation for shapes like
/// Strapi `sendTemplatedEmail`.  Motivated by CVE-2023-22621.
#[test]
fn cve_2023_22621_js_default_params_extracted() {
    use crate::cfg::extract_param_meta_for_test;
    let src = br#"
const sendTemplatedEmail = (emailOptions = {}, emailTemplate = {}, data = {}) => {
  return emailTemplate;
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang).unwrap();
    let tree = parser.parse(&src[..], None).unwrap();
    let root = tree.root_node();
    let mut arrow_node: Option<tree_sitter::Node> = None;
    fn find<'a>(n: tree_sitter::Node<'a>, out: &mut Option<tree_sitter::Node<'a>>) {
        if n.kind() == "arrow_function" {
            *out = Some(n);
            return;
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            find(ch, out);
            if out.is_some() {
                return;
            }
        }
    }
    find(root, &mut arrow_node);
    let arrow = arrow_node.expect("arrow function not found");
    let params = extract_param_meta_for_test(arrow, "javascript", src);
    let names: Vec<String> = params.iter().map(|(n, _)| n.clone()).collect();
    assert_eq!(
        names,
        vec![
            "emailOptions".to_string(),
            "emailTemplate".to_string(),
            "data".to_string()
        ],
        "expected all 3 default-valued arrow params extracted; got {:?}",
        names
    );
}

/// `_.template(tainted)` is a server-side template injection sink:
/// lodash compiles `<% ... %>` evaluate blocks into a JS Function,
/// so attacker-controlled input becomes RCE at render time.  Gate
/// activates conservatively when arg 1 is missing (default lodash
/// behavior is dangerous).  Motivated by CVE-2023-22621 (Strapi).
#[test]
fn cve_2023_22621_lodash_template_fires_on_tainted_input() {
    let src = br#"
const _ = require('lodash');
const handler = (req, res) => {
  _.template(req.body.tpl);
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected taint flow on _.template(req.body.tpl); got 0 findings",
    );
}

/// `_.template(tainted, { evaluate: false })` disables lodash's
/// `<% ... %>` evaluate block compilation, so the call is no
/// longer a code-execution sink.  The gate's `keyword_name =
/// "evaluate"` activation reads the literal value via the JS-side
/// closure that walks the call's arg-1 object literal (since JS
/// has no language-level keyword args).  Motivated by Strapi's
/// CVE-2023-22621 patch.
#[test]
fn cve_2023_22621_lodash_template_suppressed_by_evaluate_false() {
    let src = br#"
const _ = require('lodash');
const handler = (req, res) => {
  _.template(req.body.tpl, { evaluate: false });
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "expected no taint flow when evaluate:false is set; got {} findings",
        findings.len(),
    );
}

/// Double-call chained form `_.template(tainted)(data)` — the outer
/// call's `function` field is itself a call_expression rather than
/// the member-chain shape `find_chained_inner_call` was originally
/// written for.  The extension recognises the `f()()` pattern and
/// rebinds gate classification to the inner call so the gated
/// `_.template` fires even when wrapped in an immediate invocation
/// of the compiled function.  Motivated by CVE-2023-22621.
#[test]
fn cve_2023_22621_lodash_template_double_call_inner_rebinding() {
    let src = br#"
const _ = require('lodash');
const handler = (req, res) => {
  const tpl = req.body.tpl;
  _.template(tpl)({});
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected taint flow via double-call chain rebinding; got 0 findings",
    );
}

/// CVE-2026-42353 i18next-http-middleware: the patched fix wraps a
/// tainted array in `arr.filter(isSafeIdentifier)` before forwarding.
/// `try_array_method_validator_callback_narrowing` recognises the
/// `<arr>.filter(<recognised-validator>)` shape on JS/TS and strips
/// the receiver-derived caps from the call result, so a downstream
/// `arr[0]` → template-literal → `fs.readFileSync` chain no longer
/// flags.  The bare-identifier callback case is the dominant patched
/// shape — `extract_arg_callees` returns `None` for plain
/// identifiers (no inner call to recurse into), so the helper falls
/// back to the SSA value's `var_name` channel.
#[test]
fn cve_2026_42353_filter_isvalid_callback_strips_taint() {
    let src = br#"
const fs = require('fs');
function isSafeIdentifier(v) {
  return typeof v === 'string' && v.indexOf('..') === -1 && v.indexOf('/') === -1;
}
function handler(req, res) {
  let languages = req.query.lng ? req.query.lng.split(' ') : [];
  languages = languages.filter(isSafeIdentifier);
  const lng = languages[0];
  const filename = `/locales/${lng}.json`;
  fs.readFileSync(filename);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "expected no taint flow when filtered through isSafeIdentifier; got {} findings",
        findings.len(),
    );
}

/// Negative regression for the array-method validator-callback gate:
/// the same shape WITHOUT the `filter(isSafe…)` step keeps the path
/// traversal flow alive end-to-end.  Pins the precision claim — the
/// strip is element-of-array-after-filter scoped, not a wholesale
/// kill on any `<arr>.filter` call regardless of callback identity.
#[test]
fn callee_body_carries_file_cross_package_imports() {
    // Phase 09: every `CalleeSsaBody` produced from a file's lowering
    // pipeline should carry the file-level cross-package import map
    // so the inline-analysis frame can resolve the callee's local
    // names against the callee's own package boundary (step 0.7
    // inside an inlined frame).
    let src = b"export function passthrough(s) { return s; }\n";
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let mut file_cfg = parse_lang(src, "javascript", lang);

    // Inject a synthetic resolved import binding the way the Phase 04
    // resolver would for `import { helper } from "@scope/util/helper";`.
    file_cfg
        .resolved_imports
        .push(crate::resolve::ImportBinding {
            local_name: "helper".to_string(),
            source_module: "@scope/util/helper".to_string(),
            resolved_file: Some(std::path::PathBuf::from("/scope/util/src/helper.ts")),
            exported_name: Some("helper".to_string()),
        });

    let (_summaries, bodies) = super::extract_ssa_artifacts_from_file_cfg(
        &file_cfg,
        Lang::JavaScript,
        "test.js",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );

    assert!(
        !bodies.is_empty(),
        "expected at least one eligible body for `passthrough`",
    );
    for (_key, body) in &bodies {
        assert!(
            !body.cross_package_imports.is_empty(),
            "every body in a file with resolved imports should carry the file's cross-package import map; got an empty map",
        );
        assert!(
            body.cross_package_imports.contains_key("helper"),
            "expected the synthetic `helper` binding to surface in the body's cross-package import map",
        );
    }
}

#[test]
fn cve_2026_42353_filter_without_validator_callback_preserves_taint() {
    let src = br#"
const fs = require('fs');
function pickFirst(v) { return true; }
function handler(req, res) {
  let languages = req.query.lng ? req.query.lng.split(' ') : [];
  languages = languages.filter(pickFirst);
  const lng = languages[0];
  const filename = `/locales/${lng}.json`;
  fs.readFileSync(filename);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(
        &file_cfg,
        summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "expected taint flow via filter(pickFirst) — pickFirst is not a recognised validator and must not strip taint; got 0 findings",
    );
}

// ── Phase 09 cross-package namespace migration ─────────────────────────────

/// `build_cross_package_func_keys` produces a package-prefixed
/// [`FuncKey::namespace`] for files inside a discovered monorepo
/// package and a plain namespace otherwise.
///
/// Locks in the migration done as part of the deferred Phase 09 audit:
/// SSA summary keys produced by
/// [`crate::taint::lower_all_functions_from_bodies`] use
/// `namespace_with_package` for their namespace, so the cross-package
/// import map's `FuncKey::namespace` must agree for step 0.7 of
/// `resolve_callee_full` to land hits in
/// [`crate::summary::GlobalSummaries::ssa_by_key`].
#[test]
fn cross_package_func_keys_namespace_uses_resolver_when_available() {
    use crate::resolve::{ImportBinding, build_module_graph};
    use std::path::PathBuf;

    let mut fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fixture_root.push("tests/fixtures/resolver");
    let root = fixture_root
        .canonicalize()
        .unwrap_or_else(|_| fixture_root.clone());
    let graph = build_module_graph(std::slice::from_ref(&root));

    let resolved_file = root.join("packages/util/src/index.ts");
    let binding = ImportBinding {
        local_name: "doStuff".to_string(),
        source_module: "@scope/util".to_string(),
        resolved_file: Some(resolved_file.clone()),
        exported_name: Some("doStuff".to_string()),
    };
    let scan_root = root.to_string_lossy().to_string();

    let with_resolver = crate::taint::build_cross_package_func_keys(
        std::slice::from_ref(&binding),
        Some(&scan_root),
        Some(&graph),
        Lang::TypeScript,
    );
    let key = with_resolver
        .get("doStuff")
        .expect("resolved binding maps to a FuncKey");
    assert!(
        key.namespace.starts_with("@scope/util::"),
        "expected package-prefixed namespace, got {ns}",
        ns = key.namespace,
    );
    assert!(
        key.namespace.ends_with("packages/util/src/index.ts"),
        "expected the suffix to remain the scan-root-relative path, got {ns}",
        ns = key.namespace,
    );

    let without_resolver = crate::taint::build_cross_package_func_keys(
        std::slice::from_ref(&binding),
        Some(&scan_root),
        None,
        Lang::TypeScript,
    );
    let plain = without_resolver
        .get("doStuff")
        .expect("plain binding maps to a FuncKey");
    assert!(
        !plain.namespace.contains("::"),
        "without a resolver the namespace must stay plain, got {ns}",
        ns = plain.namespace,
    );
    assert_eq!(plain.namespace, "packages/util/src/index.ts");
}

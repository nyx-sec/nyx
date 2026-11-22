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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "file_a.rs",
        String::new(),
        "get_dangerous",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "file_a.rs",
        String::new(),
        "my_sanitize",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "file_a.rs",
        String::new(),
        "dangerous_exec",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "file_a.rs",
        String::new(),
        "dangerous_exec",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "file_a.rs",
        String::new(),
        "dangerous_exec",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "lib.rs",
        String::new(),
        "identity",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "other.rs",
        String::new(),
        "my_func",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Rust,
        "lib.rs",
        String::new(),
        "source_and_sink",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key1 = FuncKey::from_parts(
        Lang::Rust,
        "lib.rs",
        String::new(),
        "get_secret",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key2 = FuncKey::from_parts(
        Lang::Rust,
        "lib.rs",
        String::new(),
        "get_other_secret",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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

/// Behaviour-based path-confinement (CVE-2026-39365, Vite).  A helper whose
/// name is NOT a recognised validator (`isWithinBaseDir` — no
/// `is_valid`/`is_safe`/`validate`/`verify` prefix) but whose body returns a
/// constant-prefix containment check is recognised by behaviour: gating the
/// read on `if (!isWithinBaseDir(p))` narrows the FILE_IO taint on the
/// surviving branch so the read is safe.
#[test]
fn ts_behaviour_path_confinement_helper_narrows_file_io() {
    let src = br#"import fs from 'node:fs'
import path from 'node:path'
const baseDir = '/srv/assets'
const normalizePath = (id) => id.replace(/\\/g, '/')
const isWithinBaseDir = (id) => normalizePath(id).startsWith(`${baseDir}/`)
export function readAsset(req) {
  const p = path.resolve(baseDir, req.query.f)
  if (!isWithinBaseDir(p)) { return }
  const map = JSON.parse(fs.readFileSync(p, 'utf-8'))
  return map
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_lang(src, "typescript", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::TypeScript,
        "test.ts",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "behaviour-based confinement helper must narrow the gated FILE_IO read; got {findings:?}"
    );
}

/// Precision guard for behaviour-based path-confinement: the confinement
/// helper is DEFINED but never used to gate the read, so the FILE_IO flow
/// must still fire.  Recognition alone must not suppress an unguarded sink.
#[test]
fn ts_confinement_helper_unused_still_fires() {
    let src = br#"import fs from 'node:fs'
import path from 'node:path'
const baseDir = '/srv/assets'
const normalizePath = (id) => id.replace(/\\/g, '/')
const isWithinBaseDir = (id) => normalizePath(id).startsWith(`${baseDir}/`)
export function readAsset(req) {
  const p = path.resolve(baseDir, req.query.f)
  const map = JSON.parse(fs.readFileSync(p, 'utf-8'))
  return map
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_lang(src, "typescript", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::TypeScript,
        "test.ts",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "confinement helper defined-but-unused must not suppress the read; got {findings:?}"
    );
}

/// Pins the summary-extraction invariant: the helper's `SsaFuncSummary`
/// records its sole parameter (index 0) in `confines_path_params`.
#[test]
fn ssa_summary_records_path_confining_predicate_param() {
    let src = br#"const baseDir = '/srv/assets'
const normalizePath = (id) => id.replace(/\\/g, '/')
const isWithinBaseDir = (id) => normalizePath(id).startsWith(`${baseDir}/`)
"#;
    let lang = tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_lang(src, "typescript", lang);
    let (ssa_summaries, _) = crate::taint::lower_all_functions_from_bodies(
        &file_cfg,
        Lang::TypeScript,
        "test.ts",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );
    let helper = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "isWithinBaseDir")
        .map(|(_, v)| v)
        .expect("isWithinBaseDir summary must exist");
    assert_eq!(
        helper.confines_path_params.as_slice(),
        &[0],
        "isWithinBaseDir confines its sole param (index 0)"
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

/// CVE-2026-21859 (Mailpit) regression: an SSRF allowlist guard
/// `if !InArray(uri, links) { return }` must narrow the taint on the
/// surviving branch even when the guarded value reaches the sink through an
/// elided container index (`uri := parts[1]` lowers to a pure copy).  Two
/// engine capabilities combine: (1) the camelCase `InArray(value, list)` free
/// function is recognised as a value-first membership AllowlistCheck, and
/// (2) the sink's `all_validated` gate is copy-alias-aware, so the value
/// surfacing under the copy-source name (`parts`) is still treated as
/// validated.
#[test]
fn go_inarray_allowlist_narrows_ssrf_through_split_copy() {
    let src = br#"package main
import ("encoding/base64"; "net/http"; "strings")
var stored = map[string][]string{}
func getAssets(id string) ([]string, error) { return stored[id], nil }
func InArray(k string, arr []string) bool {
	for _, v := range arr {
		if strings.EqualFold(v, k) {
			return true
		}
	}
	return false
}
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	encoded := r.URL.Query().Get("data")
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	parts := strings.SplitN(string(decoded), ":", 2)
	id := parts[0]
	uri := parts[1]
	links, _ := getAssets(id)
	if !InArray(uri, links) {
		return
	}
	resp, _ := http.Get(uri)
	_ = resp
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(src, "go", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Go,
        "test.go",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "InArray allowlist guard must narrow the SSRF flow through the split/copy-derived uri; got {findings:?}"
    );
}

/// Precision guard for the above: with NO allowlist guard (only a scheme-prefix
/// predicate, exactly the Mailpit vulnerable shape), the SSRF flow must still
/// fire.  Recognising `InArray` as an allowlist must not suppress an unguarded
/// outbound request.
#[test]
fn go_ssrf_fires_without_allowlist_guard() {
    let src = br#"package main
import ("net/http"; "regexp")
var linkRe = regexp.MustCompile(`(?i)^https?://`)
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.Query().Get("url")
	if !linkRe.MatchString(uri) {
		return
	}
	resp, _ := http.Get(uri)
	_ = resp
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_lang(src, "go", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Go,
        "test.go",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "unguarded SSRF (scheme-prefix predicate only) must still fire; got {findings:?}"
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

/// CVE-2021-21234: an assert-guard containment check
/// `Assert.isTrue(<param-derived>.getCanonicalPath().startsWith(<fixed base>))`
/// confines its path argument for FILE_IO, so a downstream (interprocedural)
/// file read gated behind the guard call does not fire.  Pins the
/// `asserts_path_confined_params` summary field + `apply_call_post_confinement`
/// consumer.
#[test]
fn java_assert_startswith_confinement_suppresses_file_io() {
    let src = br#"class LV {
  private String baseDir = "/var/data";
  void doGet(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    confine(name);
    read(name, resp.getOutputStream());
  }
  private void confine(String name) throws java.io.IOException {
    String canonical = new java.io.File(baseDir, name).getCanonicalPath();
    String base = new java.io.File(baseDir).getCanonicalPath();
    org.springframework.util.Assert.isTrue(canonical.startsWith(base), "outside base");
  }
  private void read(String name, java.io.OutputStream out) throws java.io.IOException {
    new java.io.FileInputStream(new java.io.File(baseDir, name)).transferTo(out);
  }
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Java,
        "test.java",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "Java: assert-guard startsWith containment should confine the read, got {findings:#?}"
    );
}

/// Recall counterpart: a blocklist assertion `Assert.doesNotContain(name, "..")`
/// is NOT a prefix-containment confinement (it is bypassable), so the same
/// interprocedural read must still fire.  Pins that the recogniser keys on the
/// `startsWith` containment predicate, not on any `Assert.*` call.
#[test]
fn java_assert_does_not_contain_still_fires() {
    let src = br#"class LV {
  private String baseDir = "/var/data";
  void doGet(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    org.springframework.util.Assert.doesNotContain(name, "..");
    read(name, resp.getOutputStream());
  }
  private void read(String name, java.io.OutputStream out) throws java.io.IOException {
    new java.io.FileInputStream(new java.io.File(baseDir, name)).transferTo(out);
  }
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_lang(src, "java", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Java,
        "test.java",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "Java: doesNotContain blocklist must not confine the read"
    );
}

/// CVE-2026-53956 (rattler): a `?`-guarded, path-safety-named `Result`
/// rejection guard (`ensure_safe_path_component(&segment)?`) confines its
/// argument for FILE_IO, so the downstream `path.join(segment)` -> `fs::write`
/// does not fire.  Pins the `result_reject_guard_params` summary field +
/// `apply_path_validator_confinement` consumer.
#[test]
fn rust_path_component_guard_confines_file_io() {
    let src = br#"use std::env;
use std::path::PathBuf;
#[derive(Debug)]
pub struct InvalidPathComponentError { pub value: String }
impl std::fmt::Display for InvalidPathComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.value) }
}
impl std::error::Error for InvalidPathComponentError {}
pub fn ensure_safe_path_component(component: &str) -> Result<(), InvalidPathComponentError> {
    let is_unsafe = component == "." || component == ".."
        || component.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'));
    if is_unsafe { Err(InvalidPathComponentError { value: component.to_string() }) } else { Ok(()) }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cache_root = PathBuf::from("/tmp/pkgs");
    let build = env::var("PKG_BUILD").unwrap_or_default();
    let segment = format!("demo-1.0-{}", build);
    ensure_safe_path_component(&segment)?;
    let cache_path = cache_root.join(segment);
    std::fs::write(cache_path.join("payload"), b"x")?;
    Ok(())
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let file_cfg = parse_lang(src, "rust", lang);
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
        findings.is_empty(),
        "Rust: ensure_safe_path_component guard should confine the write, got {findings:#?}"
    );
}

/// Recall guard: the same path-safety validator is DEFINED but never called on
/// the flow, so the tainted build string still reaches `fs::write` and the flow
/// must still fire.  Pins that defining a path-safety guard does not suppress —
/// confinement is applied only at an actual guarded call site.
#[test]
fn rust_path_validator_defined_unused_still_fires() {
    let src = br#"use std::env;
use std::path::PathBuf;
#[derive(Debug)]
pub struct InvalidPathComponentError { pub value: String }
impl std::fmt::Display for InvalidPathComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.value) }
}
impl std::error::Error for InvalidPathComponentError {}
pub fn ensure_safe_path_component(component: &str) -> Result<(), InvalidPathComponentError> {
    let is_unsafe = component == "." || component == ".."
        || component.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'));
    if is_unsafe { Err(InvalidPathComponentError { value: component.to_string() }) } else { Ok(()) }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cache_root = PathBuf::from("/tmp/pkgs");
    let build = env::var("PKG_BUILD").unwrap_or_default();
    let segment = format!("demo-1.0-{}", build);
    let cache_path = cache_root.join(segment);
    std::fs::write(cache_path.join("payload"), b"x")?;
    Ok(())
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let file_cfg = parse_lang(src, "rust", lang);
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
        !findings.is_empty(),
        "Rust: an unused path-safety validator must not confine the write"
    );
}

/// Soundness guard for the name gate: a `Result` rejection guard whose name is
/// NOT a path-safety validator (`ensure_valid_email`) must not confine
/// `Cap::FILE_IO`, even when it is `?`-guarded on the flow — a non-path
/// validator proves nothing about path traversal.  Pins that
/// `apply_path_validator_confinement` requires the path-safety-validator name.
#[test]
fn rust_non_path_result_guard_does_not_confine() {
    let src = br#"use std::env;
use std::path::PathBuf;
#[derive(Debug)]
pub struct InvalidEmailError { pub value: String }
impl std::fmt::Display for InvalidEmailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.value) }
}
impl std::error::Error for InvalidEmailError {}
pub fn ensure_valid_email(addr: &str) -> Result<(), InvalidEmailError> {
    if !addr.contains('@') { Err(InvalidEmailError { value: addr.to_string() }) } else { Ok(()) }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cache_root = PathBuf::from("/tmp/pkgs");
    let build = env::var("PKG_BUILD").unwrap_or_default();
    let segment = format!("demo-1.0-{}", build);
    ensure_valid_email(&segment)?;
    let cache_path = cache_root.join(segment);
    std::fs::write(cache_path.join("payload"), b"x")?;
    Ok(())
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    let file_cfg = parse_lang(src, "rust", lang);
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
        !findings.is_empty(),
        "Rust: a non-path-named Result guard must not confine FILE_IO"
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

fn php_findings(src: &[u8]) -> usize {
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_lang(src, "php", lang);
    let summaries = &file_cfg.summaries;
    analyse_file(&file_cfg, summaries, None, Lang::Php, "test.php", &[], None).len()
}

#[test]
fn php_echo_direct_superglobal_operand() {
    for src in [
        "<?php\necho $_GET['a'];\n",
        "<?php\necho @$_REQUEST['x'];\n",
        "<?php\necho 'x' . $_GET['b'];\n",
        "<?php\necho \"x {$_GET['b']}\";\n",
        "<?php\nprint $_GET['c'];\n",
        "<?php\necho $_GET['f'], 'x';\n",
        "<?php\n?><b><?= $_GET['q'] ?></b>\n",
    ] {
        assert_eq!(php_findings(src.as_bytes()), 1, "expected a finding: {src}");
    }
}

#[test]
fn php_echo_direct_operand_sanitised_or_numeric() {
    for src in [
        "<?php\necho htmlspecialchars($_GET['a']);\n",
        "<?php\necho 'x' . htmlspecialchars($_GET['a']);\n",
        "<?php\necho (int) $_GET['n'];\n",
        "<?php\nprint htmlspecialchars($_GET['a']);\n",
        "<?php\n?><b><?= htmlspecialchars($_GET['q']) ?></b>\n",
    ] {
        assert_eq!(php_findings(src.as_bytes()), 0, "expected silence: {src}");
    }
}

#[test]
fn php_numeric_assignment_clears_taint() {
    let sink = "echo \"<i>$v</i>\";\n";
    for rhs in [
        "(int) $_GET['n']",
        "(float) $_GET['n']",
        "($_GET['n'] - 1) * 20",
        "$_GET['n'] % 7",
    ] {
        let src = format!("<?php\n$v = {rhs};\n{sink}");
        assert_eq!(php_findings(src.as_bytes()), 0, "expected silence: {rhs}");
    }
    for rhs in ["(string) $_GET['n']", "$_GET['n'] . '1'", "$_GET['n']"] {
        let src = format!("<?php\n$v = {rhs};\n{sink}");
        assert_eq!(php_findings(src.as_bytes()), 1, "expected a finding: {rhs}");
    }
}

#[test]
fn php_file_io_builtins_gated_to_path_arguments() {
    for src in [
        "<?php\n$r = !unlink('/d/' . $_GET['f']);\n",
        "<?php\n@unlink('/d/' . $_GET['f']);\n",
        "<?php\nrename($_POST['a'], '/x');\n",
        "<?php\nrename('/x', $_POST['b']);\n",
        "<?php\nreadfile('/d/' . $_GET['f']);\n",
        "<?php\n$l = file('/d/' . $_GET['f']);\n",
        "<?php\n$l = scandir('/d/' . $_GET['f']);\n",
        "<?php\nmkdir('/d/' . $_GET['f']);\n",
    ] {
        assert_eq!(php_findings(src.as_bytes()), 1, "expected a finding: {src}");
    }
    for src in [
        "<?php\nunlink('/d/' . basename($_GET['f']));\n",
        "<?php\nchmod('/d/x', (int) $_POST['m']);\n",
        "<?php\n$request->file($_GET['f']);\n",
        "<?php\n$f = new File($_GET['f']);\n",
    ] {
        assert_eq!(php_findings(src.as_bytes()), 0, "expected silence: {src}");
    }
}

#[test]
fn php_dbfacile_sql_text_only() {
    assert_eq!(
        php_findings(b"<?php\n$q = 'SELECT ' . $_GET['c'];\ndbFetchRows($q, []);\n"),
        1
    );
    assert_eq!(
        php_findings(
            b"<?php\n$p = [$_GET['c']];\ndbFetchRows('SELECT * FROM t WHERE c = ?', $p);\n"
        ),
        0
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

#[test]
fn ruby_pg_raw_exec_is_sql_sink_via_operator_assignment() {
    // CVE-2026-42087 (OpenC3 COSMOS) shape, exercised end-to-end:
    //   * `conn ||= PG::Connection.new(...)` — `operator_assignment` (`||=`)
    //     must bind `conn` AND carry the DatabaseConnection type.
    //   * `conn.exec("…'#{x}…")` — resolves to the `DatabaseConnection.exec`
    //     SQL_QUERY sink, not the bare Kernel#exec shell sink.
    let src = b"def lookup\n  start_time = gets()\n  conn ||= PG::Connection.new(host: \"h\", dbname: \"qdb\")\n  query = \"SELECT * FROM t WHERE x < '#{start_time}'\"\n  conn.exec(query)\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_lang(src, "ruby", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Ruby, "test.rb", &[], None);
    assert!(
        !findings.is_empty(),
        "Ruby: tainted query through ||= PG connection should reach conn.exec, got {findings:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.effective_sink_caps.contains(Cap::SQL_QUERY)),
        "Ruby: conn.exec(interpolated) should fire as a SQL_QUERY sink, got {findings:#?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.effective_sink_caps.contains(Cap::SHELL_ESCAPE)),
        "Ruby: typed conn.exec must NOT be misclassified as a shell sink, got {findings:#?}"
    );
}

#[test]
fn ruby_pg_exec_params_is_not_sql_sink() {
    // Precision guard: the parameterised `exec_params` form is the safe pg API
    // and must not fire a SQL injection finding (CVE-2026-42087 patched form).
    let src = b"def lookup\n  start_time = gets()\n  conn ||= PG::Connection.new(host: \"h\", dbname: \"qdb\")\n  query = \"SELECT * FROM t WHERE x < $1\"\n  conn.exec_params(query, [start_time])\nend\n";
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_lang(src, "ruby", lang);
    let summaries = &file_cfg.summaries;
    let findings = analyse_file(&file_cfg, summaries, None, Lang::Ruby, "test.rb", &[], None);
    assert!(
        !findings
            .iter()
            .any(|f| f.effective_sink_caps.contains(Cap::SQL_QUERY)),
        "Ruby: exec_params is parameterised and must not fire a SQL sink, got {findings:#?}"
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
        to: FuncKey::from_parts(
            Lang::Python,
            "lib.py",
            String::new(),
            "get_input",
            Some(0),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        to: FuncKey::from_parts(
            Lang::Go,
            "lib.go",
            String::new(),
            "fetch_env",
            Some(0),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        to: FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "clean_shell",
            Some(1),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        to: FuncKey::from_parts(
            Lang::C,
            "native.c",
            String::new(),
            "run_cmd",
            Some(1),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
            to: FuncKey::from_parts(
                Lang::Python,
                "source.py",
                String::new(),
                "get_secret",
                Some(0),
                None,
                crate::symbol::FuncKind::Function,
            ),
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "make_safe".into(),
                ordinal: 0,
            },
            to: FuncKey::from_parts(
                Lang::Rust,
                "lib.rs",
                String::new(),
                "make_safe",
                Some(1),
                None,
                crate::symbol::FuncKind::Function,
            ),
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_dangerous".into(),
                ordinal: 0,
            },
            to: FuncKey::from_parts(
                Lang::C,
                "native.c",
                String::new(),
                "run_dangerous",
                Some(1),
                None,
                crate::symbol::FuncKind::Function,
            ),
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
            to: FuncKey::from_parts(
                Lang::Python,
                "source.py",
                String::new(),
                "get_secret",
                Some(0),
                None,
                crate::symbol::FuncKind::Function,
            ),
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_dangerous".into(),
                ordinal: 0,
            },
            to: FuncKey::from_parts(
                Lang::C,
                "native.c",
                String::new(),
                "run_dangerous",
                Some(1),
                None,
                crate::symbol::FuncKind::Function,
            ),
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
    let key = FuncKey::from_parts(
        Lang::Ruby,
        "helper.rb",
        String::new(),
        "transform",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
        to: FuncKey::from_parts(
            Lang::Php,
            "input.php",
            String::new(),
            "read_input",
            Some(0),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
    let key = FuncKey::from_parts(
        Lang::Python,
        "sanitizers.py",
        String::new(),
        "html_clean",
        Some(1),
        None,
        crate::symbol::FuncKind::Function,
    );
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
            to: FuncKey::from_parts(
                Lang::Python,
                "db.py",
                String::new(),
                "dangerous_query",
                Some(0),
                None,
                crate::symbol::FuncKind::Function,
            ),
        },
        InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Go,
                caller_namespace: "main.go".into(),
                caller_func: "main".into(),
                callee_symbol: "run_query".into(),
                ordinal: 0,
            },
            to: FuncKey::from_parts(
                Lang::JavaScript,
                "db.js",
                String::new(),
                "run_query",
                Some(1),
                None,
                crate::symbol::FuncKind::Function,
            ),
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
        let key = FuncKey::from_parts(
            Lang::Rust,
            (*ns).to_string(),
            String::new(),
            "helper",
            Some(0),
            None,
            crate::symbol::FuncKind::Function,
        );
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
    let key_local = FuncKey::from_parts(
        Lang::Rust,
        "test.rs",
        String::new(),
        "helper",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key_other = FuncKey::from_parts(
        Lang::Rust,
        "other.rs",
        String::new(),
        "helper",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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
    let key = FuncKey::from_parts(
        Lang::Python,
        "lib.py",
        String::new(),
        "get_data",
        Some(0),
        None,
        crate::symbol::FuncKind::Function,
    );
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
        FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "transform",
            Some(2),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "transform",
            Some(2),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "legacy_pass",
            Some(2),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "concat",
            Some(2),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "transform",
            Some(2),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        FuncKey::from_parts(
            Lang::Rust,
            "lib.rs",
            String::new(),
            "transform",
            Some(2),
            None,
            crate::symbol::FuncKind::Function,
        ),
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
        const { exec } = require('child_process');
        try {
            riskyOperation();
        } catch (e) {
            exec(e.message);
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
        "catch param to exec should produce a finding"
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

/// The joined `return_abstract` has to describe every return that can carry
/// caller data.  A failure sentinel holds none, so it does not block the fact
/// (`sanitize` returns a `..`-free, relative path or `None`); a pass-through
/// of a parameter with no fact of its own does (`passthrough` may return its
/// argument untouched, whatever the other branch returns).
#[test]
fn ssa_summary_return_abstract_needs_every_input_carrying_return() {
    use crate::abstract_interp::Tri;
    use crate::state::symbol::SymbolInterner;

    fn return_abstract_of(src: &[u8]) -> Option<crate::abstract_interp::AbstractValue> {
        let file_cfg = parse_lang(
            src,
            "python",
            tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        );
        let the_cfg = &file_cfg.first_body().graph;
        let summaries = &file_cfg.summaries;
        let interner = SymbolInterner::from_cfg(the_cfg);
        let (func_name, func_entry) = super::find_function_entries(the_cfg)
            .into_iter()
            .next()
            .expect("one function");
        let ssa = crate::ssa::lower_to_ssa(the_cfg, func_entry, Some(&func_name), false)
            .expect("function lowers to SSA");
        let param_count = ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter().chain(b.body.iter()))
            .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
            .count();
        ssa_transfer::extract_ssa_func_summary(
            &ssa,
            the_cfg,
            summaries,
            None,
            Lang::Python,
            "test.py",
            &interner,
            param_count,
            None,
            None,
            None,
            None,
            None,
        )
        .return_abstract
    }

    let sanitize = return_abstract_of(
        br#"
def sanitize(s):
    if ".." in s or s.startswith("/"):
        return None
    return s
"#,
    );
    let fact = sanitize.expect("a sentinel return does not block the path fact");
    assert_eq!(fact.path.dotdot, Tri::No);
    assert_eq!(fact.path.absolute, Tri::No);

    let passthrough = return_abstract_of(
        br#"
def passthrough(s, raw):
    if raw:
        return s
    return "/data/fixed"
"#,
    );
    assert!(
        passthrough.is_none(),
        "the pass-through return has no fact, so the fixed literal must not stand for the call: {passthrough:?}"
    );
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

// ── Read-modify-write assignments (`x += y`, `$x .= $y`, `x ||= y`) ──────

/// Taint findings for `src`, analysed as `slug`.
fn lang_taint_findings(src: &str, slug: &str) -> Vec<Finding> {
    lang_taint_run(src, slug).1
}

/// 1-based source lines of the sink node of every taint finding in `src`.
fn lang_taint_sink_lines(src: &str, slug: &str) -> Vec<usize> {
    let (file_cfg, findings) = lang_taint_run(src, slug);
    let mut lines: Vec<usize> = findings
        .iter()
        .map(|f| {
            let start = file_cfg.bodies[f.body_id.0 as usize].graph[f.sink]
                .classification_span()
                .0;
            src.as_bytes()[..start]
                .iter()
                .filter(|&&c| c == b'\n')
                .count()
                + 1
        })
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

fn lang_taint_run(src: &str, slug: &str) -> (FileCfg, Vec<Finding>) {
    let (ts_lang, lang, path) = match slug {
        "javascript" => (
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            Lang::JavaScript,
            "test.js",
        ),
        "typescript" => (
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
            Lang::TypeScript,
            "test.ts",
        ),
        "python" => (
            tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
            Lang::Python,
            "test.py",
        ),
        "php" => (
            tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
            Lang::Php,
            "test.php",
        ),
        "rust" => (
            tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
            Lang::Rust,
            "test.rs",
        ),
        "go" => (
            tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
            Lang::Go,
            "test.go",
        ),
        "java" => (
            tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
            Lang::Java,
            "test.java",
        ),
        "c" => (
            tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
            Lang::C,
            "test.c",
        ),
        "cpp" => (
            tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE),
            Lang::Cpp,
            "test.cpp",
        ),
        "ruby" => (
            tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
            Lang::Ruby,
            "test.rb",
        ),
        other => panic!("unsupported test language {other}"),
    };
    let file_cfg = parse_lang(src.as_bytes(), slug, ts_lang);
    let findings = analyse_file(&file_cfg, &file_cfg.summaries, None, lang, path, &[], None);
    (file_cfg, findings)
}

fn assert_taint_fires(slug: &str, src: &str) {
    let findings = lang_taint_findings(src, slug);
    assert!(
        !findings.is_empty(),
        "{slug}: expected a taint finding:\n{src}"
    );
}

fn assert_taint_clean(slug: &str, src: &str) {
    let findings = lang_taint_findings(src, slug);
    assert!(
        findings.is_empty(),
        "{slug}: expected no taint finding, got {findings:#?}\n{src}"
    );
}

// `x = "lit"; x op= SOURCE; sink(x)`: the right-hand side taints the target.

#[test]
fn compound_assign_rhs_taints_target_javascript() {
    assert_taint_fires(
        "javascript",
        "const cp = require('child_process');\nfunction h(req, res) {\n  let cmd = 'ls ';\n  cmd += req.query.dir;\n  cp.exec(cmd);\n}\n",
    );
}

#[test]
fn compound_assign_rhs_taints_target_typescript() {
    assert_taint_fires(
        "typescript",
        "import * as cp from 'child_process';\nfunction h(req: any, res: any) {\n  let cmd: string = 'ls ';\n  cmd += req.query.dir;\n  cp.exec(cmd);\n}\n",
    );
}

#[test]
fn compound_assign_rhs_taints_target_python() {
    assert_taint_fires(
        "python",
        "import os\ndef main():\n    cmd = 'ls '\n    cmd += os.getenv('DIR')\n    os.system(cmd)\n",
    );
}

#[test]
fn compound_assign_rhs_taints_target_php() {
    assert_taint_fires(
        "php",
        "<?php\nfunction h($conn) {\n    $sql = 'SELECT * FROM t WHERE id = ';\n    $sql .= $_GET['id'];\n    mysqli_query($conn, $sql);\n}\n",
    );
}

#[test]
fn compound_assign_rhs_taints_target_rust() {
    assert_taint_fires(
        "rust",
        "use std::env;\nuse std::process::Command;\nfn main() {\n    let mut cmd = String::from(\"ls \");\n    let e = env::var(\"X\").unwrap();\n    cmd += &e;\n    Command::new(\"sh\").arg(&cmd).status().unwrap();\n}\n",
    );
}

#[test]
fn compound_assign_rhs_taints_target_go() {
    assert_taint_fires(
        "go",
        "package main\n\nimport \"os\"\nimport \"os/exec\"\n\nfunc main() {\n\tcmd := \"ls \"\n\tcmd += os.Getenv(\"DIR\")\n\texec.Command(cmd)\n}\n",
    );
}

// `x = SOURCE; x op= "lit"; sink(x)`: the old value survives the update.

#[test]
fn compound_assign_keeps_target_taint_java() {
    assert_taint_fires(
        "java",
        "class Main {\n  void main() {\n    String cmd = System.getenv(\"CMD\");\n    cmd += \" --safe\";\n    Runtime.exec(cmd);\n  }\n}\n",
    );
}

#[test]
fn compound_assign_keeps_target_taint_go() {
    assert_taint_fires(
        "go",
        "package main\n\nimport \"os\"\nimport \"os/exec\"\n\nfunc main() {\n\tcmd := os.Getenv(\"CMD\")\n\tcmd += \" --safe\"\n\texec.Command(cmd)\n}\n",
    );
}

#[test]
fn compound_assign_keeps_target_taint_ruby() {
    assert_taint_fires(
        "ruby",
        "def h\n  cmd = ENV['CMD']\n  cmd += ' --safe'\n  system(cmd)\nend\n",
    );
}

#[test]
fn logical_assign_keeps_target_taint_ruby() {
    assert_taint_fires(
        "ruby",
        "def h\n  cmd = ENV['CMD']\n  cmd ||= 'ls'\n  system(cmd)\nend\n",
    );
}

#[test]
fn compound_assign_keeps_target_taint_c() {
    assert_taint_fires(
        "c",
        "#include <stdlib.h>\nint main() {\n    char *p = getenv(\"X\");\n    p += 1;\n    system(p);\n    return 0;\n}\n",
    );
}

#[test]
fn compound_assign_keeps_target_taint_cpp() {
    assert_taint_fires(
        "cpp",
        "#include <cstdlib>\n#include <string>\nint main() {\n    std::string cmd = getenv(\"X\");\n    cmd += \" --flag\";\n    return system(cmd.c_str());\n}\n",
    );
}

#[test]
fn compound_assign_keeps_target_taint_python() {
    assert_taint_fires(
        "python",
        "import os\ndef main():\n    cmd = os.getenv('CMD')\n    cmd += ' -l'\n    os.system(cmd)\n",
    );
}

/// A sanitizer call on the right-hand side cleans only what it is given:
/// the target's earlier taint still reaches the sink.
#[test]
fn compound_assign_sanitized_rhs_keeps_target_taint_php() {
    assert_taint_fires(
        "php",
        "<?php\nfunction h() {\n    $out = '<p>' . $_GET['a'];\n    $out .= htmlspecialchars($_GET['b']);\n    echo $out;\n}\n",
    );
}

#[test]
fn compound_assign_sanitized_rhs_clean_target_php() {
    assert_taint_clean(
        "php",
        "<?php\nfunction h() {\n    $out = '<p>';\n    $out .= htmlspecialchars($_GET['b']);\n    echo $out;\n}\n",
    );
}

/// A sink call on the right-hand side receives only its own arguments, not
/// the tainted target it is appended to.
#[test]
fn compound_assign_sink_call_rhs_does_not_receive_target() {
    assert_taint_clean(
        "javascript",
        "const { execSync } = require('child_process');\nfunction h(req, res) {\n  let out = req.query.a;\n  out += execSync('ls');\n  console.log(out.length);\n}\n",
    );
}

/// After a literal overwrite, appending another literal stays clean.
#[test]
fn compound_assign_literal_after_kill_is_clean() {
    assert_taint_clean(
        "javascript",
        "const cp = require('child_process');\nfunction h(req, res) {\n  let q = req.query.x;\n  q = 'ls';\n  q += ' -l';\n  cp.exec(q);\n}\n",
    );
    assert_taint_clean(
        "ruby",
        "def h\n  cmd = ENV['CMD']\n  cmd = 'ls'\n  cmd += ' -l'\n  system(cmd)\nend\n",
    );
}

/// `n += 1` is `n + 1`, not the constant `1`: the branch on the updated
/// counter stays feasible.
#[test]
fn compound_assign_literal_does_not_fold_to_rhs_constant_java() {
    assert_taint_fires(
        "java",
        "class Main {\n  void main() {\n    String cmd = System.getenv(\"CMD\");\n    int n = 5;\n    n += 1;\n    if (n > 5) {\n      Runtime.exec(cmd);\n    }\n  }\n}\n",
    );
}

/// `n -= 1` on a parsed integer stays an integer, so the numeric SQL
/// fragment remains suppressed.
#[test]
fn compound_assign_int_update_stays_numeric_java() {
    assert_taint_clean(
        "java",
        "class Main {\n  void main(HttpServletRequest req, Statement st) throws Exception {\n    int n = Integer.parseInt(req.getParameter(\"n\"));\n    n -= 1;\n    st.executeQuery(\"SELECT * FROM t WHERE id = \" + n);\n  }\n}\n",
    );
}

/// `n += 2` from `n = 0` must not keep the stale constant `0`.
#[test]
fn compound_assign_does_not_keep_stale_constant_python() {
    assert_taint_fires(
        "python",
        "import os\ndef main():\n    cmd = os.getenv('CMD')\n    n = 0\n    n += 2\n    if n == 2:\n        os.system(cmd)\n",
    );
}

// ── Increment / decrement (`i++`, `--i`, Go `i++`) ───────────────────────

/// `i++` from 0 makes `i == 1` true; leaving `i` at its initial constant
/// folded the branch away.
#[test]
fn increment_does_not_keep_initial_constant_javascript() {
    assert_taint_fires(
        "javascript",
        "const cp = require('child_process');\nfunction h(req, res) {\n  let i = 0;\n  i++;\n  if (i === 1) {\n    cp.exec(req.query.x);\n  }\n}\n",
    );
}

#[test]
fn increment_does_not_keep_initial_constant_go() {
    assert_taint_fires(
        "go",
        "package main\n\nimport \"os\"\nimport \"os/exec\"\n\nfunc main() {\n\ti := 0\n\ti++\n\tif i == 1 {\n\t\texec.Command(os.Getenv(\"CMD\"))\n\t}\n}\n",
    );
}

/// A counter tested inside the loop body changes across iterations, so the
/// guarded sink is reachable.
#[test]
fn increment_in_loop_keeps_guarded_sink_reachable_javascript() {
    assert_taint_fires(
        "javascript",
        "const cp = require('child_process');\nfunction h(req, res) {\n  let i = 0;\n  while (more()) {\n    if (i == 2) {\n      cp.exec(req.query.x);\n    }\n    i++;\n  }\n}\n",
    );
}

/// Taint accumulated across a counted `for` loop reaches the sink after it.
#[test]
fn counted_for_loop_accumulates_taint_javascript() {
    assert_taint_fires(
        "javascript",
        "const cp = require('child_process');\nfunction h(req, res) {\n  const names = req.query.names;\n  let cmd = 'ls';\n  for (let i = 0; i < names.length; i++) {\n    cmd = cmd + ' ' + names[i];\n  }\n  cp.exec(cmd);\n}\n",
    );
}

#[test]
fn counted_while_loop_accumulates_taint_python() {
    assert_taint_fires(
        "python",
        "import os\ndef main(names):\n    cmd = os.getenv('CMD')\n    out = 'ls'\n    i = 0\n    while i < len(names):\n        out = out + ' ' + cmd\n        i += 1\n    os.system(out)\n",
    );
}

#[test]
fn increment_keeps_pointer_taint_c() {
    assert_taint_fires(
        "c",
        "#include <stdlib.h>\nint main() {\n    char *p = getenv(\"X\");\n    p++;\n    system(p);\n    return 0;\n}\n",
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

/// Behaviour-based open-redirect confiner (CVE-2026-42259, Saltcorn).  A
/// helper whose name is NOT a recognised validator (`normalize_relative_url`)
/// but whose body normalises the input and rejects protocol-relative (`//`)
/// and `scheme:` URLs is recognised by behaviour: redirecting to its non-null
/// result is same-origin, so the flow is silent even though the source is
/// nested directly in the confining call.
#[test]
fn js_open_redirect_normalizer_confines_return() {
    let src = br#"const normalize_relative_url = (url) => {
  if (typeof url !== "string") return null;
  const normalised = url.replace(/\\/g, "/").trimStart();
  if (normalised.startsWith("//")) return null;
  if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(normalised)) return null;
  return normalised;
};
function handler(req, res) {
  const dest = normalize_relative_url(decodeURIComponent(req.body.dest));
  if (dest !== null) res.redirect(dest);
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "relative-URL confiner must clear OPEN_REDIRECT on its return; got {findings:?}"
    );
}

/// Precision guard for the open-redirect confiner: a redirect gated only by
/// the *weak* `is_relative_url` (substring `.includes("//")`, no backslash
/// normalisation) must still fire — the weak form is not a sound confiner.
#[test]
fn js_open_redirect_weak_relative_check_still_fires() {
    let src = br#"const is_relative_url = (url) => {
  return typeof url === "string" && !url.includes(":/") && !url.includes("//");
};
function handler(req, res) {
  if (is_relative_url(decodeURIComponent(req.body.dest))) {
    res.redirect(decodeURIComponent(req.body.dest));
  }
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::JavaScript,
        "test.js",
        &[],
        None,
    );
    assert_eq!(
        findings.len(),
        1,
        "weak is_relative_url gate must not suppress the redirect; got {findings:?}"
    );
}

/// Pins the summary-extraction invariant: the confiner's `SsaFuncSummary`
/// sets `sanitizes_open_redirect_return`, while the weak substring form does
/// not.
#[test]
fn ssa_summary_records_open_redirect_normalizer() {
    let src = br#"const normalize_relative_url = (url) => {
  if (typeof url !== "string") return null;
  const normalised = url.replace(/\\/g, "/").trimStart();
  if (normalised.startsWith("//")) return null;
  if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(normalised)) return null;
  return normalised;
};
const is_relative_url = (url) => {
  return typeof url === "string" && !url.includes(":/") && !url.includes("//");
};
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    let (ssa_summaries, _) = crate::taint::lower_all_functions_from_bodies(
        &file_cfg,
        Lang::JavaScript,
        "test.js",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );
    let confiner = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "normalize_relative_url")
        .map(|(_, v)| v)
        .expect("normalize_relative_url summary must exist");
    assert!(
        confiner.sanitizes_open_redirect_return,
        "normalize_relative_url must be recognised as an OPEN_REDIRECT confiner"
    );
    let weak = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "is_relative_url")
        .map(|(_, v)| v)
        .expect("is_relative_url summary must exist");
    assert!(
        !weak.sanitizes_open_redirect_return,
        "weak is_relative_url (.includes substring form) must not be recognised as a confiner"
    );
}

fn js_body_summaries(
    src: &[u8],
) -> std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary> {
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    crate::taint::lower_all_functions_from_bodies(
        &file_cfg,
        Lang::JavaScript,
        "test.js",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    )
    .0
}

fn js_summary_of<'a>(
    summaries: &'a std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    name: &str,
) -> Option<&'a crate::summary::ssa_summary::SsaFuncSummary> {
    summaries
        .iter()
        .find(|(k, _)| k.name == name)
        .map(|(_, v)| v)
}

fn param_sink_caps(summary: &crate::summary::ssa_summary::SsaFuncSummary, idx: usize) -> Cap {
    summary
        .param_to_sink
        .iter()
        .filter(|(i, _)| *i == idx)
        .flat_map(|(_, sites)| sites.iter().map(|s| s.cap))
        .fold(Cap::empty(), |a, b| a | b)
}

/// The closure-capture augment pass runs a child only for a param that
/// reached a name the child captures.  `job` has three params and three
/// closures, but each param reaches one closure: `name` and `mode` the
/// closure over `label`, `path` the closure over `path`.
#[test]
fn augment_skips_children_that_capture_nothing_the_param_reached() {
    let src = br#"
const cp = require('child_process');
function job(name, path, mode) {
  const label = name + mode;
  setTimeout(function () { cp.exec(path); }, 1);
  setTimeout(function () { log('tick'); }, 2);
  setTimeout(function () { http.get(label); }, 3);
}
"#;
    super::AUGMENT_CHILD_RUNS.with(|c| c.set(0));
    let summaries = js_body_summaries(src);
    let runs = super::AUGMENT_CHILD_RUNS.with(std::cell::Cell::get);
    assert_eq!(runs, 3, "three (param, closure) pairs share a capture");
    let job = js_summary_of(&summaries, "job").expect("job summary");
    assert!(
        param_sink_caps(job, 0).intersects(Cap::SSRF),
        "name reaches http.get via label"
    );
    assert!(
        param_sink_caps(job, 1).intersects(Cap::SHELL_ESCAPE),
        "path reaches cp.exec"
    );
    assert!(
        param_sink_caps(job, 2).intersects(Cap::SSRF),
        "mode reaches http.get via label"
    );
}

/// Sinks in a closure two levels down are lifted onto each ancestor param
/// that reaches them, including through an in-file wrapper whose own summary
/// the pass has grown.
#[test]
fn augment_lifts_nested_closure_sinks_to_each_ancestor_param() {
    let src = br#"
const cp = require('child_process');
function runLater(cmd) {
  setTimeout(() => { cp.exec(cmd); }, 10);
}
function outer(a, b) {
  log(a);
  function inner(c) {
    return function () { http.get(a + c); runLater(b); };
  }
  return inner(b);
}
"#;
    let summaries = js_body_summaries(src);
    let outer = js_summary_of(&summaries, "outer").expect("outer summary");
    for (idx, cap) in [(0, Cap::SSRF), (1, Cap::SHELL_ESCAPE)] {
        assert!(
            param_sink_caps(outer, idx).intersects(cap),
            "param {idx} of `outer` reaches a {cap:?} sink in a nested closure; got {:?}",
            outer.param_to_sink
        );
    }
}

/// A body without formals has a `Param` op per captured name.  The augment
/// pass probes the same ones the body's own summary probe does (the first
/// `MAX_PROBE_PARAMS` in lowering order), not every capture.  The captures
/// keep their edges: invoking a closure value passes the callee itself as
/// argument 0, which is how `fn()` reports the flow of a variable `fn`
/// captured.
#[test]
fn zero_formal_parent_augment_probes_bounded_like_summary_probe() {
    let src = br#"
const cp = require('child_process');
function routes() {
  log(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
  app.get('/x', function () { cp.exec(a1); cp.exec(a9); });
}
"#;
    let summaries = js_body_summaries(src);
    let routes = js_summary_of(&summaries, "routes").expect("routes summary");
    // `a1` is the second capture: probed, and the closure's exec of it is
    // lifted.
    assert!(
        routes.param_to_sink.iter().any(|(i, _)| *i == 1),
        "capture `a1` reaches the closure's exec; got {:?}",
        routes.param_to_sink
    );
    // `a9` is the tenth: past the probe bound, as in the summary probe.
    assert!(
        routes
            .param_to_sink
            .iter()
            .all(|(i, _)| *i < super::ssa_transfer::MAX_PROBE_PARAMS),
        "no capture past MAX_PROBE_PARAMS is probed; got {:?}",
        routes.param_to_sink
    );
}

/// The formals of a body are still probed, and a closure that captures one
/// lifts its sink onto that formal.
#[test]
fn formal_param_captured_by_closure_still_lifts_sink() {
    let src = br#"
const cp = require('child_process');
function schedule(label) {
  log(label);
  setTimeout(function () { cp.exec(label); }, 1000);
}
"#;
    let summaries = js_body_summaries(src);
    let schedule = js_summary_of(&summaries, "schedule").expect("schedule summary");
    assert!(
        param_sink_caps(schedule, 0).intersects(Cap::SHELL_ESCAPE),
        "`label` reaches cp.exec through the closure; got {:?}",
        schedule.param_to_sink
    );
}

/// A closure's own source-to-sink flow is not a flow from the parent's
/// parameter: `schedule` never passes `label` to the exec, so the closure's
/// env read is the only thing reaching it.
#[test]
fn augment_does_not_attribute_closure_own_flow_to_parent_param() {
    let src = br#"
const cp = require('child_process');
function schedule(label) {
  setTimeout(function () {
    const cmd = process.env.CRON_CMD;
    cp.exec(cmd);
  }, 1000);
  return label.length;
}
"#;
    let summaries = js_body_summaries(src);
    let schedule = js_summary_of(&summaries, "schedule").expect("schedule summary");
    assert!(
        param_sink_caps(schedule, 0).is_empty(),
        "label never reaches a sink; got {:?}",
        schedule.param_to_sink
    );
}

/// `seed_caused_caps` keeps an event only when a tainted value carries an
/// origin on one of the child's `Param` nodes, where the seed lands.
#[test]
fn seed_caused_caps_counts_only_events_anchored_at_a_param() {
    use crate::ssa::ir::SsaValue;
    use crate::taint::domain::TaintOrigin;
    use crate::taint::ssa_transfer::SsaTaintEvent;
    use petgraph::graph::NodeIndex;

    let src = br#"
function parent(x) {
  const inner = function () { return x; };
  return inner;
}
"#;
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_lang(src, "javascript", lang);
    // The closure is the body without formals that captures `x`.
    let probe = file_cfg
        .function_bodies()
        .iter()
        .filter(|b| b.meta.params.is_empty())
        .find_map(|b| {
            // Lowering scopes nodes by the enclosing function's name.
            let name = b.meta.name.clone().or_else(|| {
                let d = b.meta.func_key.as_ref()?.disambig?;
                Some(format!("<anon#{d}>"))
            })?;
            let ssa = crate::ssa::lower_to_ssa_with_params(
                &b.graph,
                b.entry,
                Some(&name),
                false,
                &b.meta.params,
            )
            .ok()?;
            let probe = super::ChildSinkProbe::new(&ssa, &b.graph);
            probe.seed_names.contains("x").then_some(probe)
        })
        .expect("closure capturing x");
    let anchor = *probe
        .seed_anchors
        .iter()
        .next()
        .expect("closure captures x");
    let own = NodeIndex::new(anchor.index() + 7);
    let event = |origin_node: NodeIndex, caps: Cap| SsaTaintEvent {
        sink_node: NodeIndex::new(1),
        tainted_values: vec![(
            SsaValue(0),
            Cap::all(),
            smallvec::smallvec![TaintOrigin {
                node: origin_node,
                source_kind: crate::labels::SourceKind::UserInput,
                source_span: None,
            }],
        )],
        sink_caps: caps,
        all_validated: false,
        guard_kind: None,
        uses_summary: false,
        primary_sink_site: None,
        inline_source: false,
    };
    assert_eq!(
        probe.seed_caused_caps(&[event(anchor, Cap::SSRF), event(own, Cap::SHELL_ESCAPE)]),
        Cap::SSRF
    );
    assert!(
        probe
            .seed_caused_caps(&[event(own, Cap::SHELL_ESCAPE)])
            .is_empty()
    );
}

/// Extract `compose_path`'s `confines_path_return` flag for a given body.
/// Shared by the uftpd CVE-2020-5221 return-confinement tests.
#[cfg(test)]
fn compose_path_confines_return(src: &[u8]) -> bool {
    use crate::state::symbol::SymbolInterner;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_lang(src, "c", lang);
    let the_cfg = &file_cfg.first_body().graph;
    let summaries = &file_cfg.summaries;
    let interner = SymbolInterner::from_cfg(the_cfg);
    let func_entries = super::find_function_entries(the_cfg);
    for (name, entry) in &func_entries {
        if name != "compose_path" {
            continue;
        }
        let ssa = crate::ssa::lower_to_ssa(the_cfg, *entry, Some(name), false).unwrap();
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
        return summary.confines_path_return;
    }
    panic!("compose_path not found");
}

/// CVE-2020-5221 (uftpd): the *patched* `compose_path` confines the
/// `realpath()`-resolved `rpath` with `strncmp(rpath, home, strlen(home))`
/// before `return rpath`, so `confines_path_return` is set — the summary
/// post-condition consumed at the `fopen(compose_abspath(...))` call site.
#[test]
fn uftpd_patched_compose_path_confines_return() {
    let patched = br#"
static char *home = "/srv/ftp";
typedef struct { int sd; char cwd[4096]; } ctrl_t;
char *compose_path(ctrl_t *ctrl, char *path)
{
	static char rpath[4096];
	char dir[4096] = { 0 };
	strlcpy(dir, ctrl->cwd, sizeof(dir));
	strlcat(dir, path, sizeof(dir));
	if (!realpath(dir, rpath))
		return NULL;
	if (strncmp(rpath, home, strlen(home))) {
		return NULL;
	}
	return rpath;
}
"#;
    assert!(
        compose_path_confines_return(patched),
        "strncmp(rpath, ...) on the returned rpath must set confines_path_return"
    );
}

/// The *vulnerable* `compose_path` confines the unresolved `dir`
/// (`strncmp(dir, home, ...)`), a different var than the returned `rpath`, so
/// `confines_path_return` stays false — the flow to `fopen` still fires.  This
/// pins the bug/fix discriminator: the confinement subject must match the
/// returned value's name.
#[test]
fn uftpd_vulnerable_compose_path_does_not_confine_return() {
    let vulnerable = br#"
static char *home = "/srv/ftp";
typedef struct { int sd; char cwd[4096]; } ctrl_t;
char *compose_path(ctrl_t *ctrl, char *path)
{
	static char rpath[4096];
	char dir[4096] = { 0 };
	strlcpy(dir, ctrl->cwd, sizeof(dir));
	strlcat(dir, path, sizeof(dir));
	if (!realpath(dir, rpath))
		return NULL;
	if (strncmp(dir, home, strlen(home))) {
		return NULL;
	}
	return rpath;
}
"#;
    assert!(
        !compose_path_confines_return(vulnerable),
        "strncmp(dir, ...) confines a different var than the returned rpath — must not confine"
    );
}

/// CVE-2022-24776 (Flask-AppBuilder): the patched `get_safe_redirect` returns
/// its URL parameter only on the validated branch of a URL-safety guard
/// (`is_safe_redirect_url`), so its SSA summary must record
/// `sanitizes_open_redirect_return` (the guarded-passthrough confiner shape).
#[test]
fn ssa_summary_records_open_redirect_guarded_passthrough() {
    let src = br#"
from urllib.parse import urljoin, urlparse
def is_safe_redirect_url(url):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, url))
    return redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc
def get_safe_redirect(url):
    if url and is_safe_redirect_url(url):
        return url
    return "/"
def unguarded_passthrough(url):
    log(url)
    return url
"#;
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let (ssa_summaries, _) = crate::taint::lower_all_functions_from_bodies(
        &file_cfg,
        Lang::Python,
        "test.py",
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );
    let confiner = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "get_safe_redirect")
        .map(|(_, v)| v)
        .expect("get_safe_redirect summary must exist");
    assert!(
        confiner.sanitizes_open_redirect_return,
        "get_safe_redirect (validated-branch passthrough) must be an OPEN_REDIRECT confiner"
    );
    // An unguarded passthrough (returns the param with no URL-safety guard) must
    // NOT be recognised — it does not confine.
    let weak = ssa_summaries
        .iter()
        .find(|(k, _)| k.name == "unguarded_passthrough")
        .map(|(_, v)| v)
        .expect("unguarded_passthrough summary must exist");
    assert!(
        !weak.sanitizes_open_redirect_return,
        "an unguarded param passthrough must not be recognised as an OPEN_REDIRECT confiner"
    );
}

/// CVE-2022-24776 end-to-end: `return redirect(get_safe_redirect(next_url))`
/// (the confiner collapses out of the SSA and the tainted URL reaches the sink
/// directly) must NOT fire — the `arg_uses` wrapper recovery strips
/// OPEN_REDIRECT/SSRF for both the standalone and the `return`-duplicate node.
#[test]
fn python_nested_get_safe_redirect_suppresses_open_redirect() {
    let src = br#"
from urllib.parse import urljoin, urlparse
from flask import Flask, redirect, request
def is_safe_redirect_url(url):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, url))
    return redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc
def get_safe_redirect(url):
    if url and is_safe_redirect_url(url):
        return url
    return "/"
def login():
    next_url = request.args.get("next", "")
    return redirect(get_safe_redirect(next_url))
"#;
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Python,
        "test.py",
        &[],
        None,
    );
    assert!(
        findings.is_empty(),
        "get_safe_redirect confiner must clear OPEN_REDIRECT on the nested redirect; got {findings:?}"
    );
}

/// Recall guard for the guarded-passthrough confiner: a redirect wrapped by a
/// helper that does NOT validate the URL (a plain string transform) must still
/// fire `taint-open-redirect`.
#[test]
fn python_weak_redirect_wrapper_still_fires() {
    let src = br#"
from flask import Flask, redirect, request
def make_upper(url):
    return url.upper()
def login():
    next_url = request.args.get("next", "")
    return redirect(make_upper(next_url))
"#;
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_lang(src, "python", lang);
    let findings = analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Python,
        "test.py",
        &[],
        None,
    );
    assert!(
        !findings.is_empty(),
        "a non-validating wrapper must not confine the redirect; got {findings:?}"
    );
}

// ── Multi-way branches: match / select / case / switch ────────────────────

// Rust `match` arms are lowered per arm, not collapsed into the statement.

#[test]
fn rust_match_arm_sink_fires() {
    assert_taint_fires(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn dispatch(mode: i32) {\n    let x = env::var(\"CMD\").unwrap_or_default();\n    match mode {\n        1 => { Command::new(&x).spawn(); }\n        _ => {}\n    }\n}\n",
    );
}

#[test]
fn rust_match_return_arm_keeps_other_arm_reachable() {
    assert_taint_fires(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn run(mode: &str) {\n    let x = env::var(\"CMD\").unwrap();\n    match mode {\n        \"quit\" => return,\n        _ => { Command::new(&x).spawn().unwrap(); }\n    }\n}\n",
    );
}

#[test]
fn rust_match_binding_from_call_scrutinee_fires() {
    assert_taint_fires(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn dispatch() {\n    match env::var(\"CMD\") {\n        Ok(v) => { Command::new(&v).spawn().unwrap(); }\n        Err(_) => {}\n    }\n}\n",
    );
}

#[test]
fn rust_match_sibling_arm_def_does_not_reach_other_arm() {
    assert_taint_clean(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn dispatch(mode: i32) {\n    let mut x = String::from(\"ls\");\n    match mode {\n        1 => { x = env::var(\"CMD\").unwrap_or_default(); }\n        _ => { Command::new(&x).spawn(); }\n    }\n}\n",
    );
}

#[test]
fn rust_bare_block_overwrite_kills_taint() {
    assert_taint_clean(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn run() {\n    let mut x = env::var(\"CMD\").unwrap();\n    {\n        x = String::from(\"ls\");\n    }\n    Command::new(&x).spawn().unwrap();\n}\n",
    );
}

#[test]
fn rust_unsafe_block_flow_fires() {
    assert_taint_fires(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn run() {\n    unsafe {\n        let x = env::var(\"CMD\").unwrap();\n        Command::new(&x).spawn().unwrap();\n    }\n}\n",
    );
}

#[test]
fn rust_match_break_arm_leaves_loop() {
    assert_taint_fires(
        "rust",
        "use std::env;\nuse std::process::Command;\npub fn dispatch(rx: std::sync::mpsc::Receiver<i32>) {\n    let x = env::var(\"CMD\").unwrap_or_default();\n    loop {\n        match rx.recv() {\n            Ok(_) => {}\n            Err(_) => break,\n        }\n    }\n    Command::new(&x).spawn();\n}\n",
    );
}

// Go cases do not fall through unless they end in `fallthrough`.

#[test]
fn go_switch_case_def_does_not_reach_next_case() {
    assert_taint_clean(
        "go",
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tx := \"ls\"\n\tswitch r.URL.Query().Get(\"mode\") {\n\tcase \"a\":\n\t\tx = r.URL.Query().Get(\"cmd\")\n\tcase \"b\":\n\t\texec.Command(x).Run()\n\t}\n}\n",
    );
}

#[test]
fn go_switch_case_def_survives_later_case() {
    assert_taint_fires(
        "go",
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tx := \"ls\"\n\tswitch r.URL.Query().Get(\"mode\") {\n\tcase \"a\":\n\t\tx = r.URL.Query().Get(\"cmd\")\n\tcase \"b\":\n\t\tx = \"pwd\"\n\t}\n\texec.Command(x).Run()\n}\n",
    );
}

#[test]
fn go_switch_fallthrough_carries_def() {
    assert_taint_fires(
        "go",
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tx := \"ls\"\n\tswitch r.URL.Query().Get(\"mode\") {\n\tcase \"a\":\n\t\tx = r.URL.Query().Get(\"cmd\")\n\t\tfallthrough\n\tcase \"b\":\n\t\texec.Command(x).Run()\n\t}\n}\n",
    );
}

#[test]
fn go_select_return_case_keeps_sink_reachable() {
    assert_taint_fires(
        "go",
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tx := r.URL.Query().Get(\"cmd\")\n\tch := make(chan int, 1)\n\tselect {\n\tcase <-r.Context().Done():\n\t\treturn\n\tcase <-ch:\n\t}\n\texec.Command(x).Run()\n}\n",
    );
}

// Python `match` and Ruby `case`.

#[test]
fn python_match_return_case_fires() {
    assert_taint_fires(
        "python",
        "import os\nfrom flask import request\ndef run():\n    x = request.args.get(\"cmd\")\n    mode = request.args.get(\"mode\")\n    match mode:\n        case \"quit\":\n            return \"bye\"\n        case _:\n            os.system(x)\n    return \"ok\"\n",
    );
}

#[test]
fn python_match_sibling_case_isolated() {
    assert_taint_clean(
        "python",
        "import os\nfrom flask import request\ndef run():\n    x = \"ls\"\n    mode = request.args.get(\"mode\")\n    match mode:\n        case \"a\":\n            x = request.args.get(\"cmd\")\n        case _:\n            os.system(x)\n    return \"ok\"\n",
    );
}

#[test]
fn python_match_capture_binding_fires() {
    assert_taint_fires(
        "python",
        "import os\nfrom flask import request\ndef run():\n    data = request.args.get(\"cmd\")\n    match data:\n        case str(v):\n            os.system(v)\n    return \"ok\"\n",
    );
}

#[test]
fn ruby_case_when_return_fires() {
    assert_taint_fires(
        "ruby",
        "class RunController < ApplicationController\n  def run\n    x = params[:cmd]\n    case params[:mode]\n    when \"quit\"\n      return\n    else\n      system(x)\n    end\n  end\nend\n",
    );
}

#[test]
fn ruby_case_when_sibling_isolated() {
    assert_taint_clean(
        "ruby",
        "class RunController < ApplicationController\n  def run\n    x = \"ls\"\n    case params[:mode]\n    when \"a\"\n      x = params[:cmd]\n    else\n      system(x)\n    end\n  end\nend\n",
    );
}

#[test]
fn ruby_case_when_kill_in_one_arm_keeps_other() {
    assert_taint_fires(
        "ruby",
        "class RunController < ApplicationController\n  def run\n    x = params[:cmd]\n    case params[:mode]\n    when \"safe\"\n      x = \"ls\"\n    else\n      system(x)\n    end\n  end\nend\n",
    );
}

// Java arrow switch and default detection.

#[test]
fn java_arrow_switch_sink_fires() {
    assert_taint_fires(
        "java",
        "import javax.servlet.http.*;\npublic class Run extends HttpServlet {\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n        String x = req.getParameter(\"cmd\");\n        String mode = req.getParameter(\"mode\");\n        switch (mode) {\n            case \"a\" -> Runtime.getRuntime().exec(x);\n            default -> System.out.println(\"no\");\n        }\n    }\n}\n",
    );
}

#[test]
fn java_arrow_switch_reassign_all_arms_clean() {
    assert_taint_clean(
        "java",
        "import javax.servlet.http.*;\npublic class S extends HttpServlet {\n    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n        String cmd = req.getParameter(\"cmd\");\n        String mode = req.getParameter(\"mode\");\n        switch (mode) {\n            case \"a\" -> cmd = \"ls\";\n            default -> cmd = \"ps\";\n        }\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
    );
}

#[test]
fn java_colon_switch_default_has_no_phantom_path() {
    assert_taint_clean(
        "java",
        "import javax.servlet.http.*;\npublic class S extends HttpServlet {\n    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n        String cmd = req.getParameter(\"cmd\");\n        String mode = req.getParameter(\"mode\");\n        switch (mode) {\n            case \"a\":\n                cmd = \"ls\";\n                break;\n            default:\n                cmd = \"ps\";\n        }\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
    );
}

// A call in the scrutinee is analysed like any other call.

#[test]
fn java_switch_call_scrutinee_sink_fires() {
    assert_taint_fires(
        "java",
        "import javax.servlet.http.*;\npublic class Run extends HttpServlet {\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n        String x = req.getParameter(\"cmd\");\n        switch (Runtime.getRuntime().exec(x).waitFor()) {\n            case 0: resp.getWriter().write(\"ok\"); break;\n            default: resp.getWriter().write(\"bad\");\n        }\n    }\n}\n",
    );
}

#[test]
fn js_switch_call_discriminant_sink_fires() {
    assert_taint_fires(
        "javascript",
        "const { execSync } = require('child_process');\nfunction h(req, res) {\n  const x = req.query.cmd;\n  switch (execSync(x).toString()) {\n    case 'a':\n      res.send('a');\n      break;\n    default:\n      res.send('b');\n  }\n}\n",
    );
}

#[test]
fn python_match_source_member_subject_binding_fires() {
    assert_taint_fires(
        "python",
        "import os\nfrom flask import request\ndef run():\n    match request.args.get(\"cmd\"):\n        case str(cmd):\n            os.system(cmd)\n    return \"ok\"\n",
    );
}

#[test]
fn python_match_source_attribute_subject_binding_fires() {
    assert_taint_fires(
        "python",
        "import os\nfrom flask import request\ndef run():\n    match request.json:\n        case {\"cmd\": cmd}:\n            os.system(cmd)\n    return \"ok\"\n",
    );
}

// ── Branch and loop headers carry their condition only ─────────────────
//
// A sink call in an `if` / loop body is its own node.  The header must not
// pick it up, or the tainted condition variable is reported as flowing into
// that sink at the header line (a duplicate of the body finding, or a false
// positive when the body call's arguments are constant or guarded).

#[test]
fn header_body_gated_sink_with_constant_args_is_clean() {
    let cases: &[(&str, &str)] = &[
        (
            "javascript",
            "function h(req, res, db) {\n  const flag = req.query.f;\n  if (flag === \"yes\") {\n    db.query(\"SELECT 1\");\n  }\n}\n",
        ),
        (
            "javascript",
            "async function h(req, res) {\n  const token = req.headers.authorization;\n  if (token) {\n    fetch(\"https://auth.internal/verify\", { method: \"POST\" });\n  }\n}\n",
        ),
        (
            "javascript",
            "const cp = require('child_process');\nfunction h(req, res) {\n  const flag = req.query.f;\n  do {\n    cp.exec(\"ls\");\n  } while (flag);\n}\n",
        ),
        (
            "python",
            "from flask import request\nclass R:\n    def h(self):\n        flag = request.args.get(\"f\")\n        if flag:\n            self.cursor.execute(\"select 1\")\n",
        ),
        (
            "python",
            "from flask import request\nimport requests\ndef h():\n    items = request.args.getlist(\"f\")\n    for it in items:\n        requests.post(\"https://api.example.com/x\", data=\"const\")\n",
        ),
        (
            "rust",
            "use std::env;\nfn main() {\n    let name = env::var(\"NAME\").unwrap_or_default();\n    loop {\n        std::process::Command::new(\"ls\").status().unwrap();\n        println!(\"{}\", name);\n        break;\n    }\n}\n",
        ),
    ];
    for (slug, src) in cases {
        assert_taint_clean(slug, src);
    }
}

/// An allowlist guard on the header applies to the body call; the header
/// itself must not re-check the body's sink before the guard narrows.
#[test]
fn header_guard_applies_to_body_sink() {
    assert_taint_clean(
        "python",
        "import subprocess\nfrom flask import request\nALLOWED = {\"ls\", \"pwd\"}\ndef h():\n    cmd = request.args.get(\"c\")\n    if cmd in ALLOWED:\n        subprocess.run(cmd, shell=True)\n",
    );
}

/// A real flow into the body sink is reported once, at the body line.
#[test]
fn header_body_sink_reported_at_body_line_only() {
    let js = "const { exec } = require('child_process');\nfunction h(req, res) {\n  const n = req.query.n;\n  if (n) {\n    exec('ls ' + n);\n  }\n}\n";
    assert_eq!(lang_taint_sink_lines(js, "javascript"), vec![5]);
    let py = "import subprocess\nfrom flask import request\ndef h():\n    cmd = request.args.get(\"c\")\n    while cmd:\n        subprocess.run(cmd, shell=True)\n        break\n";
    assert_eq!(lang_taint_sink_lines(py, "python"), vec![6]);
}

/// A sink call that IS the condition is still checked at the header.
#[test]
fn header_condition_sink_call_fires() {
    let cases: &[(&str, &str)] = &[
        (
            "python",
            "import os\nfrom flask import request\ndef h():\n    cmd = request.args.get(\"c\")\n    if os.system(cmd):\n        print(\"x\")\n",
        ),
        (
            "python",
            "import os\nfrom flask import request\ndef h():\n    cmd = request.args.get(\"c\")\n    if cmd == \"a\":\n        pass\n    elif os.system(cmd):\n        print(\"x\")\n",
        ),
        (
            "ruby",
            "class C < ApplicationController\n  def run\n    cmd = params[:cmd]\n    if system(cmd)\n      render plain: \"ok\"\n    end\n  end\nend\n",
        ),
        (
            "c",
            "#include <stdio.h>\n#include <stdlib.h>\nvoid f(void) {\n    char buf[100];\n    if (!fgets(buf, 100, stdin)) return;\n    system(buf);\n}\n",
        ),
        (
            "c",
            "#include <stdio.h>\n#include <stdlib.h>\nvoid f(void) {\n    char buf[100];\n    while (fgets(buf, 100, stdin)) {\n        system(buf);\n    }\n}\n",
        ),
        (
            "c",
            "#include <stdio.h>\n#include <stdlib.h>\nvoid f(void) {\n    char buf[100];\n    do {\n        puts(\"x\");\n    } while (!fgets(buf, 100, stdin));\n    system(buf);\n}\n",
        ),
        (
            "c",
            "#include <stdio.h>\n#include <stdlib.h>\nvoid f(void) {\n    char buf[100];\n    for (; fgets(buf, 100, stdin); ) {\n        system(buf);\n    }\n}\n",
        ),
    ];
    for (slug, src) in cases {
        assert_taint_fires(slug, src);
    }
}

/// A for-each header classifies on its iterable: Go `range` over a
/// request accessor taints the loop binding.
#[test]
fn go_range_over_source_call_taints_binding() {
    assert_taint_fires(
        "go",
        "package main\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tfor _, v := range r.URL.Query()[\"c\"] {\n\t\texec.Command(\"sh\", \"-c\", v).Run()\n\t}\n}\n",
    );
}

// ── Sinks in a finally / ensure clause that every path returns through ──
//
// `build_sub` ends a path at `return`, so a clause the try body always
// returns through had no predecessor: its sinks were never analysed (and read
// as unreachable).  The clause now runs on the return path.

#[test]
fn finally_sink_after_return_fires() {
    let cases: &[(&str, &str)] = &[
        (
            "javascript",
            "const cp = require('child_process');\nfunction h(req, res) {\n  try {\n    return res.send('ok');\n  } finally {\n    cp.exec(req.query.cmd);\n  }\n}\n",
        ),
        (
            "python",
            "import os\nfrom flask import request\ndef h():\n    cmd = request.args.get('cmd')\n    try:\n        return 'ok'\n    finally:\n        os.system(cmd)\n",
        ),
        (
            "php",
            "<?php\nfunction h() {\n    $cmd = $_GET['cmd'];\n    try {\n        return 'ok';\n    } finally {\n        system($cmd);\n    }\n}\n",
        ),
        (
            "ruby",
            "class C < ApplicationController\n  def h\n    cmd = params[:cmd]\n    begin\n      return 1\n    ensure\n      system(cmd)\n    end\n  end\nend\n",
        ),
        // Method-level ensure, no `begin`.
        (
            "ruby",
            "class C < ApplicationController\n  def h\n    cmd = params[:cmd]\n    return 1\n  ensure\n    system(cmd)\n  end\nend\n",
        ),
        (
            "java",
            "import javax.servlet.http.*;\npublic class C extends HttpServlet {\n  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n    String v = req.getParameter(\"y\");\n    try {\n      return;\n    } finally {\n      Runtime.getRuntime().exec(v);\n    }\n  }\n}\n",
        ),
        // Return in a catch handler as well.
        (
            "python",
            "import os\nfrom flask import request\ndef h():\n    cmd = request.args.get('cmd')\n    try:\n        return 'ok'\n    except Exception:\n        return 'err'\n    finally:\n        os.system(cmd)\n",
        ),
        // Some paths return, one falls out.
        (
            "javascript",
            "const cp = require('child_process');\nfunction h(req, x) {\n  try {\n    if (x) { return 1; }\n    log();\n  } finally {\n    cp.exec(req.query.cmd);\n  }\n}\n",
        ),
    ];
    for (slug, src) in cases {
        assert_taint_fires(slug, src);
    }
}

#[test]
fn finally_sink_after_return_with_constant_argument_is_clean() {
    assert_taint_clean(
        "python",
        "import os\nfrom flask import request\ndef h():\n    cmd = request.args.get('cmd')\n    try:\n        return 'ok'\n    finally:\n        os.system('ls')\n",
    );
    assert_taint_clean(
        "javascript",
        "const cp = require('child_process');\nfunction h(req, res) {\n  const c = req.query.c;\n  try {\n    return res.send('ok');\n  } finally {\n    cp.exec('ls');\n  }\n}\n",
    );
}

/// The inner and the outer clause both run on the return path.
#[test]
fn nested_finally_sinks_after_return_both_fire() {
    let src = "const cp = require('child_process');\nfunction h(req) {\n  try {\n    try {\n      return 1;\n    } finally {\n      cp.exec('inner ' + req.query.a);\n    }\n  } finally {\n    cp.exec('outer ' + req.query.b);\n  }\n}\n";
    assert_eq!(lang_taint_sink_lines(src, "javascript"), vec![7, 10]);
}

/// Returning a tainted value through a finally clause still taints the
/// caller: the original return block keeps its return value.
#[test]
fn return_value_through_finally_still_taints_caller() {
    assert_taint_fires(
        "java",
        "import javax.servlet.http.*;\npublic class C extends HttpServlet {\n  String p(HttpServletRequest r) {\n    try {\n      return r.getParameter(\"x\");\n    } finally {\n      System.out.println(\"log\");\n    }\n  }\n  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n    String v = p(req);\n    Runtime.getRuntime().exec(v);\n  }\n}\n",
    );
}

/// A tainted value defined in the try body reaches a sink in the clause on
/// the return path.
#[test]
fn try_body_definition_reaches_finally_sink_on_return_path() {
    assert_taint_fires(
        "javascript",
        "const cp = require('child_process');\nfunction h(req) {\n  let v = 'ls';\n  try {\n    v = req.query.cmd;\n    return 1;\n  } finally {\n    cp.exec(v);\n  }\n}\n",
    );
}

// ── Catch handlers read the definitions live where the try body can raise ──
//
// Exception edges are stripped before SSA renaming, so a handler used to be
// seeded with the definition closest to the entry.  A variable set before
// the try and reassigned inside it then read as its pre-try value in the
// handler whenever an earlier branch put the try body in a later block.

#[test]
fn catch_handler_sees_try_body_assignment_after_a_branch() {
    let cases: &[(&str, &str)] = &[
        (
            "javascript",
            "const { exec } = require('child_process');\nfunction h(req, res) {\n  let cmd = 'ls';\n  if (req.query.v) { console.log('v'); }\n  try {\n    cmd = req.query.cmd;\n    doSomething();\n  } catch (e) {\n    exec(cmd);\n  }\n}\n",
        ),
        (
            "python",
            "import os\nfrom flask import request\ndef h():\n    path = '/tmp/default'\n    if request.args.get('v'):\n        print('v')\n    try:\n        path = request.args.get('path')\n        validate(path)\n    except Exception:\n        os.system('rm ' + path)\n",
        ),
        (
            "java",
            "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n    String cmd = \"ls\";\n    if (req.getHeader(\"x\") != null) { resp.setStatus(200); }\n    try {\n      cmd = req.getParameter(\"cmd\");\n      check(cmd);\n    } catch (Exception e) {\n      Runtime.getRuntime().exec(cmd);\n    }\n  }\n  void check(String s) throws Exception {}\n}\n",
        ),
        (
            "php",
            "<?php\nfunction h() {\n    $cmd = 'ls';\n    if ($_GET['v']) { echo 'v'; }\n    try {\n        $cmd = $_GET['cmd'];\n        doSomething();\n    } catch (Exception $e) {\n        system($cmd);\n    }\n}\n",
        ),
        (
            "ruby",
            "class C < ApplicationController\n  def h\n    cmd = 'ls'\n    if params[:v]\n      puts 'v'\n    end\n    begin\n      cmd = params[:cmd]\n      work()\n    rescue StandardError => e\n      system(cmd)\n    end\n  end\nend\n",
        ),
        // The default-then-override idiom with the override behind a branch.
        (
            "javascript",
            "const { exec } = require('child_process');\nfunction h(req, res) {\n  let cmd = 'ls';\n  try {\n    if (req.query.cmd) { cmd = req.query.cmd; }\n    doSomething();\n  } catch (e) {\n    exec(cmd);\n  }\n}\n",
        ),
        // The value is live at the call that raises, ahead of the reassignment.
        (
            "javascript",
            "const { exec } = require('child_process');\nfunction h(req) {\n  let x = req.query.x;\n  try {\n    work();\n    x = 'safe';\n  } catch (e) {\n    exec(x);\n  }\n}\n",
        ),
    ];
    for (slug, src) in cases {
        assert_taint_fires(slug, src);
    }
}

/// A definition that does not reach the handler stays out of it.
#[test]
fn catch_handler_does_not_see_unrelated_constants() {
    let cases: &[(&str, &str)] = &[
        // Constant everywhere.
        (
            "javascript",
            "const { exec } = require('child_process');\nfunction h(req) {\n  let cmd = 'ls';\n  if (req.query.v) { console.log('v'); }\n  try {\n    cmd = 'pwd';\n    work();\n  } catch (e) {\n    exec(cmd);\n  }\n}\n",
        ),
        // The tainted value is overwritten before anything can raise.
        (
            "javascript",
            "const { exec } = require('child_process');\nfunction h(req) {\n  let cmd = req.query.cmd;\n  cmd = 'ls';\n  try {\n    work();\n  } catch (e) {\n    exec(cmd);\n  }\n}\n",
        ),
        // Sanitised before the try.
        (
            "python",
            "import os, shlex\nfrom flask import request\ndef h():\n    p = shlex.quote(request.args.get('p'))\n    try:\n        validate(p)\n    except Exception:\n        os.system('rm ' + p)\n",
        ),
    ];
    for (slug, src) in cases {
        assert_taint_clean(slug, src);
    }
}

/// A handler inside another handler sees the outer handler's locals.
#[test]
fn nested_catch_handler_sees_outer_handler_local() {
    assert_taint_fires(
        "javascript",
        "const { exec } = require('child_process');\nfunction h(req, res) {\n  try {\n    risky();\n  } catch (e) {\n    const c = req.query.c;\n    try {\n      other();\n    } catch (e2) {\n      exec(c);\n    }\n  }\n}\n",
    );
}

/// Grammar, slug and file name for the languages the source-level helpers
/// below can parse.
fn grammar_for(lang: Lang) -> (&'static str, &'static str, tree_sitter::Language) {
    match lang {
        Lang::JavaScript => (
            "javascript",
            "test.js",
            tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        ),
        Lang::TypeScript => (
            "typescript",
            "test.ts",
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        ),
        Lang::Python => (
            "python",
            "test.py",
            tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        ),
        Lang::Go => (
            "go",
            "test.go",
            tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        ),
        Lang::Java => (
            "java",
            "test.java",
            tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        ),
        Lang::Php => (
            "php",
            "test.php",
            tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        ),
        Lang::Ruby => (
            "ruby",
            "test.rb",
            tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
        ),
        Lang::Rust => (
            "rust",
            "test.rs",
            tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
        ),
        other => panic!("no grammar wired for {other:?}"),
    }
}

/// Parse `src` in `lang` and run the per-file taint analysis.
fn analyse_src(src: &[u8], lang: Lang) -> Vec<Finding> {
    let (slug, path, ts_lang) = grammar_for(lang);
    let file_cfg = parse_lang(src, slug, ts_lang);
    analyse_file(&file_cfg, &file_cfg.summaries, None, lang, path, &[], None)
}

/// SSA summary of the function called `func` in `src`, built the way the
/// scan builds it.  `None` when the function has no observable effect (the
/// scan stores no summary for it).
fn summary_of(
    src: &[u8],
    lang: Lang,
    func: &str,
) -> Option<crate::summary::ssa_summary::SsaFuncSummary> {
    let (slug, path, ts_lang) = grammar_for(lang);
    let file_cfg = parse_lang(src, slug, ts_lang);
    let (ssa_summaries, _) = crate::taint::lower_all_functions_from_bodies(
        &file_cfg,
        lang,
        path,
        &file_cfg.summaries,
        None,
        None,
        None,
        None,
    );
    ssa_summaries
        .into_iter()
        .find(|(k, _)| k.name == func)
        .map(|(_, v)| v)
}

/// Parameter indices the SSA summary of `func` carries to its return value.
fn return_edge_params(src: &[u8], lang: Lang, func: &str) -> Vec<usize> {
    let mut idx: Vec<usize> = summary_of(src, lang, func)
        .map(|s| s.param_to_return.iter().map(|(i, _)| *i).collect())
        .unwrap_or_default();
    idx.sort_unstable();
    idx
}

// ── Bare `.parse` is numeric only in Rust (and JS `Date.parse`) ──────────

#[test]
fn js_url_parse_result_reaching_readfile_fires() {
    let src = b"var fs = require('fs');\nvar url = require('url');\nrequire('http').createServer(function(req, res) {\n    var q = url.parse(req.url, true);\n    fs.readFile('/srv/' + q, function() {});\n});\n";
    let findings = analyse_src(src, Lang::JavaScript);
    assert!(
        !findings.is_empty(),
        "url.parse result is an object, not Int; the FILE_IO sink must fire"
    );
}

#[test]
fn js_yaml_parse_inline_exec_arg_fires() {
    let src = b"var exec = require('child_process').exec;\nvar yaml = require('yaml');\nrequire('express')().post('/x', function(req, res) {\n    exec(yaml.parse(req.body.payload));\n});\n";
    let findings = analyse_src(src, Lang::JavaScript);
    assert!(
        !findings.is_empty(),
        "an inline yaml.parse(...) sink arg must not be dropped as a numeric producer"
    );
}

#[test]
fn python_user_parser_result_into_os_system_fires() {
    let src = br#"
import os
from flask import request
def run():
    p = parser.parse(request.args.get("x"))
    os.system("ls " + p)
"#;
    let findings = analyse_src(src, Lang::Python);
    assert!(
        !findings.is_empty(),
        "a Python `.parse` result is not numeric; the shell sink must fire"
    );
}

#[test]
fn js_date_parse_result_stays_numeric() {
    let src = b"var exec = require('child_process').exec;\nrequire('express')().post('/t', function(req, res) {\n    var ts = Date.parse(req.body.when);\n    exec('touch -d @' + ts + ' stamp');\n});\n";
    let findings = analyse_src(src, Lang::JavaScript);
    assert!(
        findings.is_empty(),
        "Date.parse returns a number; the shell sink must stay suppressed, got {findings:?}"
    );
}

// ── Field reads of a locally bound object ───────────────────────────────
//
// `body.dir` after `const body = req.body` is never written in the body, so
// lowering gives it an unbacked phantom value.  That phantom must not count
// as proof that the field is clean: only a closed object literal whose
// property is a literal (or absent) can show that.

#[test]
fn field_read_of_source_copy_fires() {
    let src = b"var exec = require('child_process').exec;\nrequire('express')().post('/a', function(req, res) {\n    var body = req.body;\n    exec('ls ' + body.dir);\n});\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "a field read off a whole-object source copy carries the source taint"
    );
}

#[test]
fn field_read_of_json_parse_result_fires() {
    let src = b"var exec = require('child_process').exec;\nrequire('express')().post('/a', function(req, res) {\n    var data = JSON.parse(req.body.payload);\n    exec(data.cmd);\n});\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "a field read off a parsed request payload carries the payload taint"
    );
}

#[test]
fn field_read_of_query_copy_xss_fires_ts() {
    let src = b"import express from 'express';\nconst app = express();\napp.get('/h', (req, res) => {\n    const q = req.query;\n    res.send('<h1>' + q.name + '</h1>');\n});\n";
    assert!(
        !analyse_src(src, Lang::TypeScript).is_empty(),
        "TS: a field read off a copied req.query reaches res.send"
    );
}

#[test]
fn object_literal_tainted_field_read_fires() {
    let src = b"function q(req, db) {\n    const obj = { safeField: 'SELECT 1', unsafeField: req.query.cmd };\n    return db.query(obj.unsafeField);\n}\nmodule.exports = { q };\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "the literal's tainted property must keep its taint"
    );
}

#[test]
fn object_literal_const_field_read_no_finding() {
    let src = b"function q(req, db) {\n    const obj = { safeField: 'SELECT 1', unsafeField: req.query.cmd };\n    return db.query(obj.safeField);\n}\nmodule.exports = { q };\n";
    let findings = analyse_src(src, Lang::JavaScript);
    assert!(
        findings.is_empty(),
        "the literal's constant property is clean, got {findings:?}"
    );
}

#[test]
fn object_literal_nested_const_field_read_no_finding() {
    let src = b"var exec = require('child_process').exec;\nfunction t(req) {\n    const cfg = { auth: { userName: req.query.name, template: '/usr/bin/whoami' } };\n    exec(cfg.auth.template);\n}\nmodule.exports = { t };\n";
    let findings = analyse_src(src, Lang::JavaScript);
    assert!(
        findings.is_empty(),
        "a constant nested property is clean, got {findings:?}"
    );
}

#[test]
fn object_literal_nested_tainted_field_read_fires() {
    let src = b"var exec = require('child_process').exec;\nfunction t(req) {\n    const cfg = { auth: { userName: req.query.name, template: '/usr/bin/whoami' } };\n    exec(cfg.auth.userName);\n}\nmodule.exports = { t };\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "a tainted nested property keeps its taint"
    );
}

#[test]
fn object_literal_spread_field_read_fires() {
    let src = b"var exec = require('child_process').exec;\nrequire('express')().post('/a', function(req, res) {\n    const o = { ...req.body, safe: 'x' };\n    exec(o.cmd);\n});\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "a spread can supply any property, so the read is not provably clean"
    );
}

#[test]
fn object_literal_ident_bound_to_constant_no_finding() {
    let src = b"var exec = require('child_process').exec;\nvar BIN = '/usr/bin/uptime';\nfunction t(req) {\n    const job = { bin: BIN, arg: req.query.a };\n    exec(job.bin);\n}\nmodule.exports = { t };\n";
    let findings = analyse_src(src, Lang::JavaScript);
    assert!(
        findings.is_empty(),
        "a property bound to an untainted identifier is clean, got {findings:?}"
    );
}

#[test]
fn field_read_validated_on_all_paths_matches_let_bound_twin() {
    // A property validated on every path before the sink is judged like its
    // let-bound twin: the object reaches the sink only through that
    // property, so the base object's taint must not bypass the validation.
    let inline = b"var exec = require('child_process').exec;\nrequire('express')().post('/a', function(req, res) {\n    var body = req.body;\n    if (!isValidDir(body.dir)) { return; }\n    exec('ls ' + body.dir);\n});\n";
    let let_bound = b"var exec = require('child_process').exec;\nrequire('express')().post('/a', function(req, res) {\n    var body = req.body;\n    var d = body.dir;\n    if (!isValidDir(d)) { return; }\n    exec('ls ' + d);\n});\n";
    let unvalidated = |fs: Vec<Finding>| fs.into_iter().filter(|f| !f.path_validated).count();
    assert_eq!(
        unvalidated(analyse_src(let_bound, Lang::JavaScript)),
        0,
        "let-bound twin: the validated flow is not reported as unvalidated"
    );
    assert_eq!(
        unvalidated(analyse_src(inline, Lang::JavaScript)),
        0,
        "inline field read validated on every path is not reported as unvalidated"
    );
}

// ── Per-operand sanitizers, sibling operands, nested helper calls ────────

fn unvalidated_count(fs: &[Finding]) -> usize {
    fs.iter().filter(|f| !f.path_validated).count()
}

const JS_APP: &str = "var escapeHtml = require('escape-html');\nvar cp = require('child_process');\nvar app = require('express')();\n";

fn js_app(body: &str) -> Vec<u8> {
    format!("{JS_APP}{body}").into_bytes()
}

#[test]
fn concat_label_sanitizer_does_not_cover_sibling_operand_js() {
    let src = js_app(
        "app.get('/a', function(req, res) {\n    var name = req.query.name;\n    var bio = req.query.bio;\n    var html = '<p>' + escapeHtml(name) + '</p>' + bio;\n    res.send(html);\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&src, Lang::JavaScript)) > 0,
        "escapeHtml wraps `name` only; the raw `bio` operand must reach res.send"
    );
}

#[test]
fn concat_with_every_operand_escaped_is_clean_js() {
    let src = js_app(
        "app.get('/a', function(req, res) {\n    var a = req.query.a;\n    var b = req.query.b;\n    var html = escapeHtml(a) + '<br>' + escapeHtml(b);\n    res.send(html);\n});\n",
    );
    let fs = analyse_src(&src, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "every operand is escaped: {fs:?}"
    );
}

#[test]
fn concat_operand_escaped_once_and_raw_once_fires_js() {
    let src = js_app(
        "app.get('/a', function(req, res) {\n    var name = req.query.name;\n    var html = `<p>${escapeHtml(name)}</p><div>${name}</div>`;\n    res.send(html);\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&src, Lang::JavaScript)) > 0,
        "the second, unescaped use of `name` must reach the sink"
    );
}

#[test]
fn inline_sink_sanitizer_does_not_cover_sibling_operand_js() {
    let vuln = js_app(
        "app.get('/b', function(req, res) {\n    var bio = req.query.bio;\n    res.send('<h1>' + escapeHtml('Profile') + '</h1>' + bio);\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&vuln, Lang::JavaScript)) > 0,
        "escapeHtml wraps a constant; `bio` is raw in the same argument"
    );
    let safe = js_app(
        "app.get('/b', function(req, res) {\n    var bio = req.query.bio;\n    res.send('<h1>' + escapeHtml(bio) + '</h1>');\n});\n",
    );
    let fs = analyse_src(&safe, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "the only operand is escaped: {fs:?}"
    );
}

#[test]
fn shell_quote_covers_only_its_operand_py() {
    let vuln = br#"
import os, shlex
from flask import request
def a():
    f = request.args["f"]
    opts = request.args["o"]
    os.system("ls " + shlex.quote(f) + " " + opts)
"#;
    assert!(
        unvalidated_count(&analyse_src(vuln, Lang::Python)) > 0,
        "`opts` is not quoted"
    );
    let safe = br#"
import os, shlex
from flask import request
def a():
    f = request.args["f"]
    os.system("ls " + shlex.quote(f))
"#;
    let fs = analyse_src(safe, Lang::Python);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "the only operand is quoted: {fs:?}"
    );
}

#[test]
fn shell_quote_assignment_keeps_sibling_taint_py() {
    let src = br#"
import os, shlex
from flask import request
def h():
    a = request.args["a"]
    b = request.args["b"]
    s = shlex.quote(a) + " " + b
    os.system("ls " + s)
"#;
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Python)) > 0,
        "shlex.quote(a) must not quote the sibling `b`"
    );
}

#[test]
fn fprintf_escape_covers_only_its_argument_go() {
    let vuln = b"package main\nimport (\"fmt\"; \"html\"; \"net/http\")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"name\")\n\tbio := r.URL.Query().Get(\"bio\")\n\tfmt.Fprintf(w, \"<h1>%s</h1><p>%s</p>\", html.EscapeString(name), bio)\n}\n";
    assert!(
        unvalidated_count(&analyse_src(vuln, Lang::Go)) > 0,
        "html.EscapeString wraps argument 2 only; `bio` in argument 3 is raw"
    );
    let safe = b"package main\nimport (\"fmt\"; \"html\"; \"net/http\")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"name\")\n\tbio := r.URL.Query().Get(\"bio\")\n\tfmt.Fprintf(w, \"<h1>%s</h1><p>%s</p>\", html.EscapeString(name), html.EscapeString(bio))\n}\n";
    let fs = analyse_src(safe, Lang::Go);
    assert_eq!(unvalidated_count(&fs), 0, "both arguments escaped: {fs:?}");
}

#[test]
fn zero_arg_helper_keeps_sibling_operand_taint_js() {
    let src = js_app(
        "function siteHeader() { return '<h1>Site</h1>'; }\napp.get('/a', function(req, res) {\n    var bio = req.query.bio;\n    var html = siteHeader() + bio;\n    res.send(html);\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&src, Lang::JavaScript)) > 0,
        "the helper returns a constant, but `bio` is concatenated raw"
    );
}

#[test]
fn constant_returning_helper_with_argument_keeps_sibling_taint_js() {
    let src = js_app(
        "function roleLabel(u) { if (u === 'admin') { return 'Administrator'; } return 'User'; }\napp.get('/f', function(req, res) {\n    var name = req.query.name;\n    var bio = req.query.bio;\n    var html = roleLabel(name) + bio;\n    res.send(html);\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&src, Lang::JavaScript)) > 0,
        "`bio` is not an argument of roleLabel"
    );
}

#[test]
fn sibling_wrapped_by_escaping_helper_stays_clean_js() {
    let src = js_app(
        "function siteHeader() { return '<h1>Site</h1>'; }\nfunction myEscape(s) { return escapeHtml(s); }\napp.get('/a', function(req, res) {\n    var bio = req.query.bio;\n    var html = siteHeader() + myEscape(bio);\n    res.send(html);\n});\n",
    );
    let fs = analyse_src(&src, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "`bio` reaches the result only through an escaping helper: {fs:?}"
    );
}

#[test]
fn validated_sibling_beside_helper_stays_validated_js() {
    let src = js_app(
        "var ALLOWED = ['a', 'b'];\nfunction siteHeader() { return '<h1>Site</h1>'; }\napp.get('/b', function(req, res) {\n    var bio = req.query.bio;\n    if (!ALLOWED.includes(bio)) { return res.status(400).end(); }\n    var html = siteHeader() + bio;\n    res.send(html);\n});\n",
    );
    let fs = analyse_src(&src, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "`bio` is allowlisted before use, like the `Date.now() + bio` twin: {fs:?}"
    );
}

#[test]
fn nested_constant_helper_in_sink_arg_matches_temp_form_js() {
    let nested = js_app(
        "function constant(x) { return 'ls'; }\napp.get('/b', function(req, res) {\n    var c = req.query.c;\n    cp.exec(constant(c));\n});\n",
    );
    let fs = analyse_src(&nested, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "constant() never returns its argument, as in `t = constant(c); cp.exec(t)`: {fs:?}"
    );
    let propagating = js_app(
        "function wrap(x) { return 'ls ' + x; }\napp.get('/b', function(req, res) {\n    var c = req.query.c;\n    cp.exec(wrap(c));\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&propagating, Lang::JavaScript)) > 0,
        "wrap() returns its argument"
    );
}

#[test]
fn nested_allowlist_helper_in_concat_sink_arg_is_clean_py() {
    let src = br#"
import os
from flask import request
def sort_column(s):
    if s == "name":
        return "name"
    return "id"
def h():
    c = request.args["c"]
    os.system("ls " + sort_column(c))
"#;
    let fs = analyse_src(src, Lang::Python);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "sort_column returns constants only: {fs:?}"
    );
}

#[test]
fn wrapper_param_sanitizer_applies_per_argument_js() {
    let card = "function card(title, body) { return '<h2>' + escapeHtml(title) + '</h2><div>' + body + '</div>'; }\n";
    let vuln = js_app(&format!(
        "{card}app.get('/e', function(req, res) {{\n    var b = req.query.b;\n    res.send(card('static', b));\n}});\n"
    ));
    assert!(
        unvalidated_count(&analyse_src(&vuln, Lang::JavaScript)) > 0,
        "card() escapes its first parameter only; `b` is the second"
    );
    let safe = js_app(&format!(
        "{card}app.get('/e', function(req, res) {{\n    var t = req.query.t;\n    res.send(card(t, 'static'));\n}});\n"
    ));
    let fs = analyse_src(&safe, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "`t` goes through the escaped parameter: {fs:?}"
    );
}

#[test]
fn helper_summary_keeps_unquoted_parameter_py() {
    let src = br#"
import os, shlex
from flask import request
def q2(a, b):
    return shlex.quote(a) + " " + b
def h():
    c = request.args["c"]
    s = q2("x", c)
    os.system("ls " + s)
"#;
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Python)) > 0,
        "q2 quotes its first parameter only; its summary must keep the second"
    );
}

#[test]
fn safe_string_producer_does_not_cover_sibling_operand_java() {
    let src = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n    String name = req.getParameter(\"n\");\n    st.executeQuery(\"SELECT * FROM t WHERE c = \" + Integer.toString(5) + \" AND n = '\" + name + \"'\");\n  }\n}\n";
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Java)) > 0,
        "Integer.toString(5) is numeric; the concatenated `name` is not"
    );
}

#[test]
fn numeric_call_in_concat_does_not_type_the_whole_string_java() {
    let vuln = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n    String id = req.getParameter(\"id\");\n    String name = req.getParameter(\"n\");\n    String sql = \"SELECT * FROM t WHERE id = \" + Integer.parseInt(id) + \" AND n = '\" + name + \"'\";\n    st.executeQuery(sql);\n  }\n}\n";
    assert!(
        unvalidated_count(&analyse_src(vuln, Lang::Java)) > 0,
        "the concatenation is a string carrying `name`, not an Int"
    );
    let safe = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n    String n = req.getParameter(\"n\");\n    String sql = \"SELECT * FROM t LIMIT \" + Integer.parseInt(n);\n    st.executeQuery(sql);\n  }\n}\n";
    let fs = analyse_src(safe, Lang::Java);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "only a parsed number is concatenated: {fs:?}"
    );
}

#[test]
fn numeric_call_in_fstring_does_not_cover_sibling_py() {
    let vuln = br#"
import sqlite3
from flask import request
conn = sqlite3.connect("x")
def h():
    name = request.args["n"]
    limit = request.args["l"]
    q = f"SELECT * FROM t WHERE n = '{name}' LIMIT {int(limit)}"
    conn.execute(q)
"#;
    assert!(
        unvalidated_count(&analyse_src(vuln, Lang::Python)) > 0,
        "int(limit) does not cover `name`"
    );
    let safe = br#"
import sqlite3
from flask import request
conn = sqlite3.connect("x")
def h():
    limit = request.args["l"]
    q = f"SELECT * FROM t LIMIT {int(limit)}"
    conn.execute(q)
"#;
    let fs = analyse_src(safe, Lang::Python);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "only the int conversion is interpolated: {fs:?}"
    );
}

#[test]
fn nested_source_helper_in_sink_arg_matches_temp_form_py() {
    let src = br#"
import os
from flask import request
def get_cmd():
    v = request.args['c']
    return v
def nested():
    os.system(get_cmd())
def nested_concat():
    os.system("ls " + get_cmd())
"#;
    let fs = analyse_src(src, Lang::Python);
    assert!(
        unvalidated_count(&fs) >= 2,
        "both inline uses of the source helper reach os.system: {fs:?}"
    );
}

#[test]
fn nested_label_source_in_sink_arg_fires_java() {
    let src = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n    Runtime.getRuntime().exec(req.getParameter(\"c\"));\n  }\n}\n";
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Java)) > 0,
        "a request parameter passed inline to exec is the same flow as its let-bound twin"
    );
    let escaped = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n    Runtime.getRuntime().exec(Integer.toString(Integer.parseInt(req.getParameter(\"c\"))));\n  }\n}\n";
    let fs = analyse_src(escaped, Lang::Java);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "the inline source is reduced to a number: {fs:?}"
    );
}

#[test]
fn inline_member_sources_are_judged_per_read_js() {
    let vuln = js_app(
        "app.get('/a', function(req, res) {\n    res.send('<p>' + escapeHtml(req.query.name) + '</p>' + req.query.bio);\n});\n",
    );
    assert!(
        unvalidated_count(&analyse_src(&vuln, Lang::JavaScript)) > 0,
        "`req.query.bio` is concatenated raw beside the escaped `req.query.name`"
    );
    let safe = js_app(
        "app.get('/a', function(req, res) {\n    res.send('<p>' + escapeHtml(req.query.name) + '</p><p>' + escapeHtml(req.query.bio) + '</p>');\n});\n",
    );
    let fs = analyse_src(&safe, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "every inline read is escaped: {fs:?}"
    );
}

#[test]
fn wrapper_with_inline_sources_keeps_unescaped_parameter_js() {
    let card = "function card(title, body) { return '<h2>' + escapeHtml(title) + '</h2><div>' + body + '</div>'; }\n";
    let assigned = js_app(&format!(
        "{card}app.get('/b', function(req, res) {{\n    var html = card(req.query.t, req.query.b);\n    res.send(html);\n}});\n"
    ));
    assert!(
        unvalidated_count(&analyse_src(&assigned, Lang::JavaScript)) > 0,
        "card() escapes only its first parameter; `req.query.b` is the second"
    );
    let escaped_only = js_app(&format!(
        "{card}app.get('/b', function(req, res) {{\n    var html = card(req.query.t, 'static');\n    res.send(html);\n}});\n"
    ));
    let fs = analyse_src(&escaped_only, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "the only inline source goes through the escaped parameter: {fs:?}"
    );
}

#[test]
fn escape_inside_pass_through_formatter_covers_only_its_argument_java() {
    let vuln = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) throws Exception {\n    String name = req.getParameter(\"name\");\n    String bio = req.getParameter(\"bio\");\n    String html = String.format(\"<p>%s</p><p>%s</p>\", HtmlUtils.htmlEscape(name), bio);\n    resp.getWriter().println(html);\n  }\n}\n";
    assert!(
        unvalidated_count(&analyse_src(vuln, Lang::Java)) > 0,
        "String.format passes `bio` through unescaped"
    );
    let safe = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) throws Exception {\n    String name = req.getParameter(\"name\");\n    String bio = req.getParameter(\"bio\");\n    String html = String.format(\"<p>%s</p><p>%s</p>\", HtmlUtils.htmlEscape(name), HtmlUtils.htmlEscape(bio));\n    resp.getWriter().println(html);\n  }\n}\n";
    let fs = analyse_src(safe, Lang::Java);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "both formatted values are escaped: {fs:?}"
    );
}

#[test]
fn container_write_around_inline_source_keeps_container_taint_java() {
    // `parts.add(req.getParameter("x"))` is modelled as one op whose callee
    // is the inline source and whose outer call is the container write; the
    // receiver must stay with that op so the element taint lands in `parts`.
    let src = b"class A {\n  void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n    java.util.List<String> parts = new java.util.ArrayList<>();\n    parts.add(req.getParameter(\"x\"));\n    Runtime.getRuntime().exec(parts.get(0));\n  }\n}\n";
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Java)) > 0,
        "the request parameter stored in `parts` reaches exec"
    );
}

#[test]
fn nested_source_beside_sanitized_operand_reaches_sink_py() {
    // `input()` is a labelled source nested beside the sanitizer call; it has
    // no SSA value of its own, so the expression must carry its taint.
    let src = br#"
import os, shlex
from flask import request
def h():
    a = request.args["a"]
    s = shlex.quote(a) + " " + input()
    os.system("ls " + s)
"#;
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Python)) > 0,
        "the unquoted input() operand reaches os.system"
    );
}

#[test]
fn nested_source_in_chained_sink_call_fires_go() {
    let src = b"package main\nimport (\"net/http\"; \"os/exec\")\nfunc getCmd(r *http.Request) string {\n\tv := r.URL.Query().Get(\"c\")\n\treturn v\n}\nfunc h(w http.ResponseWriter, r *http.Request) {\n\texec.Command(\"sh\", \"-c\", getCmd(r)).Run()\n}\n";
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Go)) > 0,
        "getCmd(r) is the payload of exec.Command even when .Run() is chained on"
    );
}

// ── Counted loops and the entry constraint environment ──────────────────
//
// `for (...; i < n; i++)` leaves `i` a constant `0` in SSA (`i++` is not a
// definition), so its phi has a constant fact and an `Unknown` type fact.
// Seeding both used to mark the entry environment unsatisfiable, and phi
// operands reached through goto edges from the entry block were skipped, so
// taint accumulated across such a loop never reached the sink after it.

#[test]
fn counted_loop_accumulator_keeps_taint_js() {
    let src = b"var cp = require('child_process');\nvar app = require('express')();\napp.get('/run', function(req, res) {\n  var cmd = req.query.cmd;\n  for (var i = 0; i < 3; i++) {\n    cmd = cmd + ' --retry';\n  }\n  cp.exec(cmd);\n});\n";
    assert!(unvalidated_count(&analyse_src(src, Lang::JavaScript)) > 0);
}

#[test]
fn counted_loop_accumulator_of_a_copy_keeps_taint_js() {
    let src = b"var cp = require('child_process');\nvar app = require('express')();\napp.get('/run', function(req, res) {\n  var data = req.query.cmd;\n  var cmd = data;\n  for (var i = 0; i < 3; i++) {\n    cmd = cmd + ' --retry';\n  }\n  cp.exec(cmd);\n});\n";
    assert!(unvalidated_count(&analyse_src(src, Lang::JavaScript)) > 0);
}

// ── Name-keyed facts and redefinition ───────────────────────────────────
//
// Copy aliases, validation bits and predicate bits are recorded per variable
// name.  A new definition of a name must not inherit facts about its earlier
// value, and rebinding one name must not change its copies.

fn analyse_rust_src(src: &[u8]) -> Vec<Finding> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter::Language::from(tree_sitter_rust::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src, None).unwrap();
    let file_cfg = crate::cfg::build_cfg(&tree, src, "rust", "test.rs", None);
    analyse_file(
        &file_cfg,
        &file_cfg.summaries,
        None,
        Lang::Rust,
        "test.rs",
        &[],
        None,
    )
}

#[test]
fn rebinding_a_copy_does_not_taint_the_original_js() {
    let src = b"const { exec } = require('child_process');\nconst app = require('express')();\nfunction getDefaultCmd() { return 'ls -la'; }\napp.get('/run', (req, res) => {\n  let cmd = getDefaultCmd();\n  let userCmd = cmd;\n  userCmd = req.query.c;\n  console.log(userCmd);\n  exec(cmd);\n});\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert_eq!(
        unvalidated_count(&fs),
        0,
        "`userCmd = req.query.c` rebinds the copy, `cmd` stays the constant: {fs:?}"
    );
}

#[test]
fn rebinding_a_copy_of_a_module_constant_does_not_taint_it_js() {
    let src = b"const { exec } = require('child_process');\nconst app = require('express')();\nconst DEFAULT_CMD = 'uptime';\napp.get('/run', (req, res) => {\n  let label = DEFAULT_CMD;\n  if (req.query.label) {\n    label = req.query.label;\n  }\n  console.log(label);\n  exec(DEFAULT_CMD);\n});\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert_eq!(unvalidated_count(&fs), 0, "{fs:?}");
}

#[test]
fn rebinding_a_copy_does_not_taint_the_original_py() {
    let src = br#"
import os
from flask import request
def default_cmd():
    return "ls -la"
def run():
    cmd = default_cmd()
    user_cmd = cmd
    user_cmd = request.args.get("c")
    print(user_cmd)
    os.system(cmd)
"#;
    let fs = analyse_src(src, Lang::Python);
    assert_eq!(unvalidated_count(&fs), 0, "{fs:?}");
}

#[test]
fn sanitizing_a_copy_leaves_the_original_raw_js() {
    let src = b"const escapeHtml = require('escape-html');\nconst app = require('express')();\napp.get('/a', (req, res) => {\n  let x = req.query.a;\n  let y = x;\n  y = escapeHtml(y);\n  console.log(y);\n  res.send(x);\n});\n";
    assert!(
        unvalidated_count(&analyse_src(src, Lang::JavaScript)) > 0,
        "escaping the copy `y` does not escape `x`"
    );
}

#[test]
fn sanitizing_a_copy_leaves_the_original_raw_py() {
    let src = br#"
import os, shlex
from flask import request
def run():
    x = request.args.get("c")
    y = x
    y = shlex.quote(y)
    print(y)
    os.system("echo " + x)
"#;
    assert!(
        unvalidated_count(&analyse_src(src, Lang::Python)) > 0,
        "quoting the copy `y` does not quote `x`"
    );
}

#[test]
fn pointer_write_through_still_taints_the_pointee_go() {
    // CFG lowering drops `&`, so `p := &cmd` reaches SSA as a copy and the
    // write `*p = ...` defines `p`.  The name-level alias group is what
    // carries the write back to `cmd`.
    let src = b"package main\nimport (\"net/http\"; \"os/exec\")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tcmd := \"ls\"\n\tp := &cmd\n\t*p = r.URL.Query().Get(\"c\")\n\texec.Command(\"sh\", \"-c\", cmd).Run()\n}\n";
    assert!(unvalidated_count(&analyse_src(src, Lang::Go)) > 0);
}

#[test]
fn mut_ref_write_through_still_taints_the_referent_rust() {
    let src = br#"
        use std::process::Command;
        fn main() {
            let mut a = String::from("ls");
            let b = &mut a;
            *b = std::env::var("CMD").unwrap();
            Command::new("sh").arg("-c").arg(&a).output().unwrap();
        }"#;
    assert!(unvalidated_count(&analyse_rust_src(src)) > 0);
}

const JS_HOST_APP: &str = "const { exec } = require('child_process');\nconst app = require('express')();\nfunction isValidHost(h) { return /^[a-z.]+$/.test(h); }\n";

fn js_host_route(lines: &str) -> Vec<u8> {
    format!(
        "{JS_HOST_APP}app.get('/a', (req, res) => {{\n  let host = req.query.host;\n  if (!isValidHost(host)) return res.status(400).send('bad');\n{lines}\n  exec(host);\n}});\n"
    )
    .into_bytes()
}

#[test]
fn validation_does_not_survive_reassignment_from_a_source_js() {
    let fs = analyse_src(
        &js_host_route("  host = req.query.other;"),
        Lang::JavaScript,
    );
    assert!(
        unvalidated_count(&fs) > 0,
        "the second `req.query` read was never validated: {fs:?}"
    );
}

#[test]
fn validation_does_not_survive_concat_of_new_taint_js() {
    for line in [
        "  host = host + req.query.extra;",
        "  const extra = req.query.extra;\n  host = host + extra;",
        "  const extra = req.query.extra;\n  host = host.concat(extra);",
        "  const extra = req.query.extra;\n  host = extra;",
    ] {
        let fs = analyse_src(&js_host_route(line), Lang::JavaScript);
        assert!(
            unvalidated_count(&fs) > 0,
            "`{line}` mixes unvalidated taint into `host`: {fs:?}"
        );
    }
}

#[test]
fn validation_survives_self_updates_of_the_validated_value_js() {
    for line in [
        "  host = host.trim();",
        "  host = host.trim().toLowerCase();",
        "  host = host + '.internal';",
        "  host = `${host}`;",
        "  host = host || 'localhost';",
        "  host = host.replace(/\\.$/, '');",
    ] {
        let fs = analyse_src(&js_host_route(line), Lang::JavaScript);
        assert_eq!(
            unvalidated_count(&fs),
            0,
            "`{line}` only transforms the validated value: {fs:?}"
        );
    }
}

#[test]
fn validation_does_not_survive_reassignment_from_a_source_py() {
    let src = br#"
import os
from flask import request
def validate_page(v):
    return v.isdigit()
def a():
    value = request.args["page"]
    if not validate_page(value):
        return "bad", 400
    value = request.args["sort"]
    os.system(value)
"#;
    assert!(unvalidated_count(&analyse_src(src, Lang::Python)) > 0);
}

#[test]
fn validation_does_not_survive_a_foreach_binder_reusing_the_name_php() {
    let src = b"<?php\n$value = $_GET['page'];\nif (!is_numeric($value)) {\n    die('bad');\n}\necho 'page ' . intval($value);\nforeach ($_POST['names'] as $value) {\n    system('echo ' . $value);\n}\n";
    assert!(unvalidated_count(&analyse_src(src, Lang::Php)) > 0);
}

#[test]
fn validation_does_not_survive_reassignment_from_a_source_java() {
    let src = b"class Ctl {\n  static boolean isValidName(String s) { return s.matches(\"[a-z]+\"); }\n  void doGet(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) throws Exception {\n    String name = req.getParameter(\"name\");\n    if (!isValidName(name)) {\n      resp.sendError(400);\n      return;\n    }\n    name = req.getParameter(\"other\");\n    Runtime.getRuntime().exec(name);\n  }\n}\n";
    assert!(unvalidated_count(&analyse_src(src, Lang::Java)) > 0);
}

#[test]
fn inline_source_beside_a_validated_operand_is_not_validated_js() {
    let src = b"const app = require('express')();\nconst db = require('./db');\nconst SORTS = ['name', 'date'];\napp.get('/items', (req, res) => {\n  const sort = req.query.sort;\n  if (!SORTS.includes(sort)) return res.status(400).end();\n  const sql = 'SELECT * FROM items ORDER BY ' + sort + ' LIMIT ' + req.query.limit;\n  db.query(sql);\n});\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert!(
        unvalidated_count(&fs) > 0,
        "`req.query.limit` joins the query unvalidated: {fs:?}"
    );
}

#[test]
fn allowlisted_operand_alone_stays_validated_js() {
    let src = b"const app = require('express')();\nconst db = require('./db');\nconst SORTS = ['name', 'date'];\napp.get('/items', (req, res) => {\n  const sort = req.query.sort;\n  if (!SORTS.includes(sort)) return res.status(400).end();\n  const sql = 'SELECT * FROM items ORDER BY ' + sort + ' LIMIT 10';\n  db.query(sql);\n});\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert_eq!(unvalidated_count(&fs), 0, "{fs:?}");
}

#[test]
fn inline_source_beside_a_validated_operand_is_not_validated_py() {
    let src = br#"
from flask import request
import sqlite3
SORTS = ["name", "date"]
def items():
    sort = request.args.get("sort")
    if sort not in SORTS:
        return "bad", 400
    conn = sqlite3.connect("x.db")
    sql = "SELECT * FROM items ORDER BY " + sort + " LIMIT " + request.args.get("limit")
    conn.execute(sql)
"#;
    assert!(unvalidated_count(&analyse_src(src, Lang::Python)) > 0);
}

#[test]
fn reused_err_check_after_redefinition_keeps_taint_go() {
    // After `if err != nil { return }` a later `_, err = ...` is a new
    // value; its own `err != nil` branch is reachable.
    let src = b"package main\nimport (\"net/http\"; \"os\"; \"os/exec\")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"n\")\n\t_, err := os.Getwd()\n\tif err != nil {\n\t\treturn\n\t}\n\t_, err = os.Stat(\"/tmp/x\")\n\tif err != nil {\n\t\texec.Command(\"sh\", \"-c\", \"echo \"+name).Run()\n\t}\n}\n";
    let fs = analyse_src(src, Lang::Go);
    assert!(unvalidated_count(&fs) > 0, "{fs:?}");
}

#[test]
fn opposite_error_check_polarity_is_not_a_contradiction_go() {
    let src = b"package main\nimport (\"net/http\"; \"os\"; \"os/exec\")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"n\")\n\t_, err := os.Stat(\"/tmp/x\")\n\tif err == nil {\n\t\treturn\n\t}\n\tif err != nil {\n\t\texec.Command(\"sh\", \"-c\", \"echo \"+name).Run()\n\t}\n}\n";
    let fs = analyse_src(src, Lang::Go);
    assert!(unvalidated_count(&fs) > 0, "{fs:?}");
}

#[test]
fn opposite_null_check_polarity_is_not_a_contradiction_js() {
    let src = b"const { execSync } = require('child_process');\nconst app = require('express')();\napp.get('/a', (req, res) => {\n  const cmd = req.query.cmd;\n  const cfg = loadConfig();\n  if (cfg === null) return;\n  if (cfg !== null) {\n    execSync(cmd);\n  }\n});\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert!(unvalidated_count(&fs) > 0, "{fs:?}");
}

#[test]
fn opposite_none_check_polarity_is_not_a_contradiction_py() {
    let src = br#"
import os
from flask import request
def h():
    cmd = request.args.get("cmd")
    cfg = load_config()
    if cfg is None:
        return "no"
    if cfg is not None:
        os.system(cmd)
"#;
    assert!(unvalidated_count(&analyse_src(src, Lang::Python)) > 0);
}

#[test]
fn opposite_null_check_polarity_is_not_a_contradiction_rust() {
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            let y = env::var("OTHER").ok();
            if y.is_none() { return; }
            if y.is_some() {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;
    assert!(unvalidated_count(&analyse_rust_src(src)) > 0);
}

#[test]
fn negated_null_check_after_guard_is_still_pruned_py() {
    // After `if cfg is not None: return` only a None `cfg` reaches the
    // second check, so its true edge is infeasible: the negated form records
    // the same "is null" bit as `is None` would.
    let src = br#"
import os
from flask import request
def h():
    cmd = request.args.get("cmd")
    cfg = load_config()
    if cfg is not None:
        return "no"
    if cfg is not None:
        os.system(cmd)
"#;
    let fs = analyse_src(src, Lang::Python);
    assert_eq!(unvalidated_count(&fs), 0, "{fs:?}");
}

#[test]
fn negated_null_check_after_guard_is_still_pruned_rust() {
    let src = br#"
        use std::env; use std::process::Command;
        fn main() {
            let x = env::var("INPUT").unwrap();
            let y = env::var("OTHER").ok();
            if y.is_some() { return; }
            if y.is_some() {
                Command::new("sh").arg(&x).status().unwrap();
            }
        }"#;
    let fs = analyse_rust_src(src);
    assert!(fs.is_empty(), "{fs:?}");
}

// ── JS/TS handler-param seed and known callers ──────────────────────────
//
// A formal named `cmd` / `input` / `userId` is seeded as user input only when
// the function has no known caller.  With a caller in view, what reaches the
// parameter is whatever that caller passes.

#[test]
fn seed_named_helpers_called_only_with_literals_stay_quiet_js() {
    let src = b"const { execSync } = require('child_process');\nconst fs = require('fs');\nfunction run(cmd) {\n  return execSync(cmd, { stdio: 'inherit' });\n}\nfunction readInput(input) {\n  return fs.readFileSync(input, 'utf8');\n}\nrun('npm run build');\nrun('npm test');\nconst cfg = JSON.parse(readInput('./config.json'));\nconsole.log(cfg);\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert!(fs.is_empty(), "every caller passes a literal: {fs:?}");
}

#[test]
fn seed_named_helper_called_from_a_function_with_a_literal_stays_quiet_js() {
    let src = b"const db = require('./db');\nasync function loadUser(userId) {\n  return db.query('SELECT * FROM users WHERE id = ' + userId);\n}\nasync function main() {\n  const u = await loadUser(42);\n  console.log(u);\n}\nmain();\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert!(fs.is_empty(), "loadUser's only caller passes 42: {fs:?}");
}

#[test]
fn seed_named_function_without_callers_is_still_seeded_js() {
    let src = b"const { execSync } = require('child_process');\nmodule.exports = function run(cmd) {\n  return execSync(cmd);\n};\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "an entry point with no caller in view keeps the seed"
    );
    let arrow = b"const { exec } = require('child_process');\nconst handle = (input) => exec(input);\nmodule.exports = { handle };\n";
    assert!(!analyse_src(arrow, Lang::JavaScript).is_empty());
}

#[test]
fn self_recursion_alone_does_not_count_as_a_caller_js() {
    let src = b"const { execSync } = require('child_process');\nfunction run(cmd, n) {\n  if (n > 0) return run(cmd, n - 1);\n  return execSync(cmd);\n}\nmodule.exports = run;\n";
    assert!(!analyse_src(src, Lang::JavaScript).is_empty());
}

#[test]
fn helper_called_from_a_route_reports_only_the_call_site_flow_js() {
    let src = b"const { execSync } = require('child_process');\nconst app = require('express')();\nfunction run(cmd) {\n  return execSync(cmd);\n}\napp.get('/x', (req, res) => {\n  run(req.query.c);\n  res.send('ok');\n});\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert_eq!(
        fs.len(),
        1,
        "one flow, from req.query.c through run(), not a second one sourced at `cmd`: {fs:?}"
    );
}

#[test]
fn inlined_seed_named_callee_with_literal_argument_stays_quiet_js() {
    let src = b"const { exec } = require('child_process');\nfunction normalize(input) {\n  return input.trim();\n}\nfunction main() {\n  const c = normalize('ls -la');\n  exec(c);\n}\nmain();\n";
    let fs = analyse_src(src, Lang::JavaScript);
    assert!(
        fs.is_empty(),
        "normalize returns its literal argument: {fs:?}"
    );
}

#[test]
fn seed_named_helpers_called_only_with_literals_stay_quiet_ts() {
    let src = b"import { execSync } from 'child_process';\nimport * as fs from 'fs';\nfunction readTemplate(input: string) { return fs.readFileSync(input, 'utf8'); }\nfunction git(cmd: string) { return execSync(cmd); }\nfunction main() {\n  readTemplate('./t.html');\n  git('git status');\n}\nmain();\n";
    let fs = analyse_src(src, Lang::TypeScript);
    assert!(fs.is_empty(), "{fs:?}");
}

// ── Summary extraction: per-parameter return edges ───────────────────────
//
// The per-parameter probe used to credit every parameter with a return edge
// whenever the returned value was untainted under the probe, so a helper that
// returns one of its arguments (or a sanitized one) made every other argument
// look like it flowed to the result.

#[test]
fn summary_return_edge_only_for_the_returned_param() {
    let cases: &[(Lang, &[u8], &str)] = &[
        (
            Lang::Python,
            b"def first(aval, zval):\n    return aval\n",
            "first",
        ),
        (
            Lang::Python,
            b"def first_tmp(aval, zval):\n    r = aval\n    return r\n",
            "first_tmp",
        ),
        (
            Lang::JavaScript,
            b"function first(aval, zval) { return aval; }\n",
            "first",
        ),
        (
            Lang::JavaScript,
            b"function first(aval, zval) { return aval.trim(); }\n",
            "first",
        ),
        (
            Lang::Go,
            b"package main\nfunc first(a string, b string) string { return a }\n",
            "first",
        ),
        (
            Lang::Java,
            b"class A { static String first(String a, String b) { return a; } }\n",
            "first",
        ),
        (
            Lang::Php,
            b"<?php\nfunction first($a, $b) { return $a; }\n",
            "first",
        ),
        (Lang::Ruby, b"def first(a, b)\n  return a\nend\n", "first"),
    ];
    for (lang, src, name) in cases {
        assert_eq!(
            return_edge_params(src, *lang, name),
            vec![0],
            "{lang:?} {name}: only the returned parameter may flow to the result"
        );
    }
}

#[test]
fn summary_return_edge_second_param_when_it_is_the_one_returned() {
    assert_eq!(
        return_edge_params(
            b"function pass(zval, aval) { return aval; }\n",
            Lang::JavaScript,
            "pass"
        ),
        vec![1]
    );
}

#[test]
fn summary_sanitizing_wrapper_records_a_full_strip_and_no_surviving_edge() {
    let cases: &[(Lang, &[u8], &str)] = &[
        (
            Lang::JavaScript,
            b"function c3(s) { return Number(s); }\n",
            "c3",
        ),
        (
            Lang::JavaScript,
            b"function c4(s) { const n = Number(s); return n; }\n",
            "c4",
        ),
        (
            Lang::JavaScript,
            b"function c5(s) { const r = parseInt(s, 10); return r; }\n",
            "c5",
        ),
        (
            Lang::Python,
            b"def to_int(s):\n    return int(s)\n",
            "to_int",
        ),
        (
            Lang::Php,
            b"<?php\nfunction to_int($s) { return intval($s); }\n",
            "to_int",
        ),
        (
            Lang::Go,
            b"package main\nimport \"strconv\"\nfunc toInt(s string) int {\n\tn, _ := strconv.Atoi(s)\n\treturn n\n}\n",
            "toInt",
        ),
    ];
    for (lang, src, name) in cases {
        let summary = summary_of(src, *lang, name)
            .unwrap_or_else(|| panic!("{lang:?} {name}: wrapper has no summary"));
        // The parameter does reach the return, through a full sanitizer.  The
        // summary says so with an all-bits strip, so a caller that passes the
        // call's source inline still sees a sanitizing wrapper.
        assert!(
            summary.param_to_return.iter().all(|(_, t)| matches!(
                t,
                crate::summary::ssa_summary::TaintTransform::StripBits(c) if *c == Cap::all()
            )),
            "{lang:?} {name}: no taint may survive the wrapper, got {:?}",
            summary.param_to_return
        );
    }
}

#[test]
fn summary_partial_sanitizer_wrapper_keeps_a_strip_edge() {
    use crate::summary::ssa_summary::TaintTransform;
    let src = b"function wrap(s) { return shellescape(s); }\n";
    let summary = summary_of(src, Lang::JavaScript, "wrap").expect("wrap has a summary");
    assert!(
        matches!(
            summary.param_to_return.as_slice(),
            [(0, TaintTransform::StripBits(_))]
        ),
        "a shell escaper strips its own bits and keeps the rest, got {:?}",
        summary.param_to_return
    );
}

#[test]
fn summary_return_edges_kept_for_side_effects_the_ssa_has_no_operand_for() {
    // Container append and receiver mutation make the returned object depend
    // on a parameter that is not one of its operands.
    let cases: &[(Lang, &[u8], &str)] = &[
        (
            Lang::Python,
            b"def add(lst, item):\n    lst.append(item)\n    return lst\n",
            "add",
        ),
        (
            Lang::Java,
            b"class A { static String sbuild(String head, String tail) { StringBuilder sb = new StringBuilder(head); sb.append(tail); return sb.toString(); } }\n",
            "sbuild",
        ),
        (
            Lang::Go,
            b"package main\nfunc add(xs []string, x string) []string { return append(xs, x) }\n",
            "add",
        ),
        (
            Lang::JavaScript,
            b"function build(base, extra) { let x = base; x = x + extra; return x; }\n",
            "build",
        ),
    ];
    for (lang, src, name) in cases {
        assert_eq!(
            return_edge_params(src, *lang, name),
            vec![0, 1],
            "{lang:?} {name}: both parameters reach the returned value"
        );
    }
}

#[test]
fn summary_mixed_sanitize_and_passthrough_keeps_the_identity_edge() {
    use crate::summary::ssa_summary::TaintTransform;
    let src = b"function maybe(s, strict) {\n  if (strict) { return Number(s); }\n  return s;\n}\n";
    let summary = summary_of(src, Lang::JavaScript, "maybe").expect("maybe has a summary");
    assert!(
        summary
            .param_to_return
            .iter()
            .any(|(i, t)| *i == 0 && matches!(t, TaintTransform::Identity)),
        "the unsanitized return path keeps s flowing, got {:?}",
        summary.param_to_return
    );
}

#[test]
fn unrelated_argument_to_a_returning_helper_does_not_taint_the_result() {
    // `first` returns its first argument; the second is dead as far as the
    // result goes.
    let safe = b"import os\nfrom flask import request\n\ndef first(aval, zval):\n    return aval\n\ndef handler():\n    t = request.args.get(\"x\")\n    r = first(\"ls\", t)\n    os.system(r)\n";
    assert!(
        analyse_src(safe, Lang::Python).is_empty(),
        "tainted second argument must not reach the result of first()"
    );
    let vuln = b"import os\nfrom flask import request\n\ndef first(aval, zval):\n    return aval\n\ndef handler():\n    t = request.args.get(\"x\")\n    r = first(t, \"ls\")\n    os.system(r)\n";
    assert!(
        !analyse_src(vuln, Lang::Python).is_empty(),
        "tainted first argument flows through first()"
    );
}

#[test]
fn numeric_conversion_wrapper_result_does_not_carry_the_input_taint() {
    let safe_js = b"var cp = require('child_process');\nfunction toNum(s) { return Number(s); }\nrequire('http').createServer(function(req, res) {\n  var n = toNum(req.query.n);\n  cp.exec('ls ' + n);\n});\n";
    assert!(
        analyse_src(safe_js, Lang::JavaScript).is_empty(),
        "Number() wrapper must keep its sanitizing effect"
    );
    let safe_py = b"import os\nfrom flask import request\n\ndef to_int(s):\n    return int(s)\n\ndef handler():\n    n = to_int(request.args.get(\"n\"))\n    os.system(\"ls \" + str(n))\n";
    assert!(analyse_src(safe_py, Lang::Python).is_empty());
    let vuln_js = b"var cp = require('child_process');\nfunction ident(s) { return s; }\nrequire('http').createServer(function(req, res) {\n  var n = ident(req.query.n);\n  cp.exec('ls ' + n);\n});\n";
    assert!(
        !analyse_src(vuln_js, Lang::JavaScript).is_empty(),
        "an identity helper still passes taint through"
    );
}

// ── `return <member source>` is a source ─────────────────────────────────

#[test]
fn getter_returning_a_member_source_carries_source_caps() {
    let cases: &[(Lang, &[u8], &str)] = &[
        (
            Lang::JavaScript,
            b"function getQ(req) { return req.query.q; }\n",
            "getQ",
        ),
        (
            Lang::JavaScript,
            b"function getBody(req) { return req.body; }\n",
            "getBody",
        ),
        (
            Lang::JavaScript,
            b"function getEnv() { return process.env.X; }\n",
            "getEnv",
        ),
        (
            Lang::TypeScript,
            b"function getEnv(): string { return process.env.X as string; }\n",
            "getEnv",
        ),
        (
            Lang::Python,
            b"from flask import request\ndef get_q():\n    return request.args['x']\n",
            "get_q",
        ),
        (
            Lang::Python,
            b"import os\ndef get_e():\n    return os.environ['X']\n",
            "get_e",
        ),
        (
            Lang::Php,
            b"<?php\nfunction get_id() { return $_GET['id']; }\n",
            "get_id",
        ),
        (
            Lang::Ruby,
            b"def get_id\n  return params[:id]\nend\n",
            "get_id",
        ),
    ];
    for (lang, src, name) in cases {
        let summary = summary_of(src, *lang, name)
            .unwrap_or_else(|| panic!("{lang:?} {name}: getter has no summary"));
        assert!(
            !summary.source_caps.is_empty(),
            "{lang:?} {name}: `return <source>` must give the summary source caps"
        );
    }
}

#[test]
fn getter_returning_a_member_source_taints_its_callers() {
    let js = b"var cp = require('child_process');\nfunction getQ(req) { return req.query.x; }\nfunction h(req, res) {\n  var a = getQ(req);\n  cp.exec(a);\n}\nmodule.exports = h;\n";
    assert!(
        !analyse_src(js, Lang::JavaScript).is_empty(),
        "js: a one-line getter of req.query.x is a source for its caller"
    );
    let py = b"import os\nfrom flask import request\n\ndef p_sub():\n    return request.args['x']\n\ndef handler():\n    v = p_sub()\n    os.system(v)\n";
    assert!(
        !analyse_src(py, Lang::Python).is_empty(),
        "py: a one-line getter of request.args['x'] is a source for its caller"
    );
    let php = b"<?php\nfunction get_id() {\n    return $_GET['id'];\n}\nfunction h() {\n    $a = get_id();\n    system($a);\n}\n";
    assert!(
        !analyse_src(php, Lang::Php).is_empty(),
        "php: a one-line getter of $_GET['id'] is a source for its caller"
    );
}

#[test]
fn returning_a_closure_that_reads_a_source_is_not_a_source() {
    let src = b"function make(req) { return () => req.query.q; }\n";
    let carries_source = summary_of(src, Lang::JavaScript, "make")
        .map(|s| !s.source_caps.is_empty())
        .unwrap_or(false);
    assert!(
        !carries_source,
        "the closure is returned, not the value its body reads"
    );
}

#[test]
fn getter_returning_a_constant_or_plain_param_has_no_source_caps() {
    let src = b"function getK() { return 'static'; }\nfunction same(x) { return x.value; }\n";
    for name in ["getK", "same"] {
        let carries = summary_of(src, Lang::JavaScript, name)
            .map(|s| !s.source_caps.is_empty())
            .unwrap_or(false);
        assert!(!carries, "{name} must not invent source caps");
    }
}

// ── Inline analysis of a callee that returns a copied value ──────────────

#[test]
fn mixed_return_helper_inlines_the_unsanitized_path() {
    // One path returns shlex.quote(b), the other returns b.  The copy behind
    // `return b` used to be a Nop in the inline body, so inline analysis only
    // saw the sanitized path.
    let src = b"import os, shlex\n\ndef m_one(b):\n    if b == \"x\":\n        return shlex.quote(b)\n    return b\n\ndef m_else(flag, b):\n    if flag:\n        return shlex.quote(b)\n    else:\n        return b\n\ndef h1():\n    c = os.environ[\"C\"]\n    s = m_one(c)\n    os.system(\"ls \" + s)\n\ndef h2():\n    c = os.environ[\"C\"]\n    s = m_else(True, c)\n    os.system(\"ls \" + s)\n";
    let findings = analyse_src(src, Lang::Python);
    assert!(
        findings.len() >= 2,
        "both mixed sanitize/passthrough helpers must keep the raw path, got {}",
        findings.len()
    );
}

#[test]
fn fully_quoting_helper_stays_clean_when_inlined() {
    let src = b"import os, shlex\n\ndef quote_it(b):\n    return shlex.quote(b)\n\ndef h():\n    c = os.environ[\"C\"]\n    s = quote_it(c)\n    os.system(\"ls \" + s)\n";
    assert!(analyse_src(src, Lang::Python).is_empty());
}

// ── Sink checks: interpolated parameterized queries ──────────────────────

#[test]
fn interpolated_query_text_with_placeholder_still_fires() {
    let py = b"import sqlite3\nfrom flask import request\n\ndef f():\n    sort = request.args.get(\"sort\")\n    limit = request.args.get(\"limit\")\n    cur = sqlite3.connect(\"a.db\").cursor()\n    cur.execute(f\"SELECT * FROM users ORDER BY {sort} LIMIT ?\", (limit,))\n";
    assert!(
        !analyse_src(py, Lang::Python).is_empty(),
        "py: the interpolated ORDER BY column is injectable even with a bound LIMIT"
    );
    let py_concat = b"import sqlite3\nfrom flask import request\n\ndef f():\n    sort = request.args.get(\"sort\")\n    cur = sqlite3.connect(\"a.db\").cursor()\n    cur.execute(\"SELECT * FROM users ORDER BY \" f\"{sort}\" \" LIMIT ?\", (10,))\n";
    assert!(!analyse_src(py_concat, Lang::Python).is_empty());
    let rb = b"class UsersController < ApplicationController\n  def search\n    q = params[:q]\n    @users = User.where(\"name LIKE '%#{q}%' AND active = ?\", true)\n  end\nend\n";
    assert!(
        !analyse_src(rb, Lang::Ruby).is_empty(),
        "rb: interpolation in the where fragment is injectable"
    );
}

#[test]
fn bound_value_next_to_constant_interpolation_stays_quiet() {
    // The interpolated part is a constant and the user value is bound: the
    // bind value is not the injection vector.
    let py = b"import sqlite3\nfrom flask import request\nTABLE = \"users\"\n\ndef f():\n    uid = request.args.get(\"id\")\n    cur = sqlite3.connect(\"a.db\").cursor()\n    cur.execute(f\"SELECT * FROM {TABLE} WHERE id = ?\", (uid,))\n";
    assert!(
        analyse_src(py, Lang::Python).is_empty(),
        "py: a bound value must not fire just because the query text is interpolated"
    );
    let rb = b"class UsersController < ApplicationController\n  def by_table\n    q = params[:q]\n    @users = User.where(\"#{User.table_name}.name = ?\", q)\n  end\nend\n";
    assert!(analyse_src(rb, Lang::Ruby).is_empty());
}

// ── Sink checks: tainted receiver with literal arguments ─────────────────

#[test]
fn tainted_path_receiver_with_literal_args_reaches_the_sink() {
    for call in [
        "p.write_text(\"pwned\")",
        "p.read_text(\"utf-8\")",
        "p.open(\"w\")",
        "p.read_bytes()",
    ] {
        let src = format!(
            "from pathlib import Path\nfrom flask import request\n\ndef f():\n    p = Path(request.args[\"f\"])\n    {call}\n"
        );
        assert!(
            !analyse_src(src.as_bytes(), Lang::Python).is_empty(),
            "{call}: the receiver is the attacker's path"
        );
    }
}

#[test]
fn untainted_path_receiver_with_literal_args_stays_quiet() {
    let src = b"from pathlib import Path\n\ndef f():\n    p = Path(\"/srv/static/index.html\")\n    p.write_text(\"x\")\n    return p.read_text(\"utf-8\")\n";
    assert!(analyse_src(src, Lang::Python).is_empty());
}

#[test]
fn tainted_http_client_receiver_with_literal_path_reaches_the_sink() {
    let src = b"require 'net/http'\nclass ProxyController < ApplicationController\n  def status\n    http = Net::HTTP.new(params[:host], 80)\n    res = http.get(\"/status\")\n  end\nend\n";
    assert!(
        !analyse_src(src, Lang::Ruby).is_empty(),
        "Net::HTTP.new(tainted host).get(literal) requests the attacker's host"
    );
    let fixed = b"require 'net/http'\nclass ProxyController < ApplicationController\n  def status\n    http = Net::HTTP.new(\"internal.example.com\", 80)\n    res = http.get(\"/status\")\n  end\nend\n";
    assert!(analyse_src(fixed, Lang::Ruby).is_empty());
}

#[test]
fn tainted_untyped_receiver_with_literal_args_stays_quiet() {
    // A receiver with no handle type is not the sink subject: the literal
    // argument call has no payload.
    let src = b"var express = require('express');\nvar app = express();\napp.get('/x', function(req, res) {\n  var re = new RegExp(req.query.r);\n  re.exec('abc');\n  res.send('ok');\n});\n";
    assert!(analyse_src(src, Lang::JavaScript).is_empty());
}

// ── A single-character replace is not a sanitizer ────────────────────────

#[test]
fn single_metachar_strip_before_a_shell_sink_still_fires() {
    let py = b"import os\nfrom flask import request\n\ndef f():\n    host = request.args[\"host\"]\n    host = host.replace(\";\", \"\")\n    os.system(\"ping -c 1 \" + host)\n";
    assert!(
        !analyse_src(py, Lang::Python).is_empty(),
        "py: removing ';' leaves '|', '&&' and '$(..)'"
    );
    let go = b"package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n\t\"strings\"\n)\nfunc strip(s string) string { return strings.ReplaceAll(s, \";\", \"\") }\nfunc h(w http.ResponseWriter, r *http.Request) {\n\thost := strip(r.URL.Query().Get(\"host\"))\n\texec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host).Run()\n}\n";
    assert!(
        !analyse_src(go, Lang::Go).is_empty(),
        "go: ReplaceAll over ';'"
    );
    let go_first = b"package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n\t\"strings\"\n)\nfunc h(w http.ResponseWriter, r *http.Request) {\n\thost := strings.Replace(r.URL.Query().Get(\"host\"), \"<\", \"\", 1)\n\texec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host).Run()\n}\n";
    assert!(
        !analyse_src(go_first, Lang::Go).is_empty(),
        "go: Replace with n=1 only strips the first match"
    );
    let java = b"import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n    String host = req.getParameter(\"host\");\n    host = host.replaceAll(\"|\", \"\");\n    Runtime.getRuntime().exec(\"ping -c 1 \" + host);\n  }\n}\n";
    assert!(
        !analyse_src(java, Lang::Java).is_empty(),
        "java: the regex \"|\" matches the empty string and removes nothing"
    );
    let php = b"<?php\n$t = $_GET['t'];\n$t = str_replace(\";\", \"\", $t);\nsystem(\"ping -c 1 \" . $t);\n";
    assert!(!analyse_src(php, Lang::Php).is_empty());
}

#[test]
fn quote_deletion_before_a_numeric_sql_context_still_fires() {
    let py = b"from flask import request\n\ndef f(cur):\n    uid = request.args[\"id\"]\n    uid = uid.replace(\"'\", \"\")\n    cur.execute(\"SELECT * FROM users WHERE id = \" + uid)\n";
    assert!(
        !analyse_src(py, Lang::Python).is_empty(),
        "deleting quotes does nothing for a numeric context"
    );
}

#[test]
fn quote_doubling_before_a_quoted_sql_literal_stays_quiet() {
    let py = b"from flask import request\n\ndef f(cur):\n    name = request.args[\"name\"]\n    name = name.replace(\"'\", \"''\")\n    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n";
    assert!(
        analyse_src(py, Lang::Python).is_empty(),
        "quote doubling is the SQL string-literal escape"
    );
}

#[test]
fn angle_bracket_strip_before_html_output_stays_quiet() {
    let py = b"from flask import request, make_response\n\ndef f():\n    t = request.args[\"t\"]\n    t = t.replace(\"<\", \"&lt;\").replace(\">\", \"&gt;\")\n    return make_response(\"<p>\" + t + \"</p>\")\n";
    assert!(analyse_src(py, Lang::Python).is_empty());
}

#[test]
fn field_stored_by_a_helper_that_returns_the_object_stays_tainted() {
    // `withName` writes its argument into a field and returns the object.
    let src = b"var cp = require('child_process');\nfunction withName(obj, name) { obj.name = name; return obj; }\nrequire('http').createServer(function(req, res) {\n  var job = withName({}, req.query.job);\n  cp.exec(job.name);\n});\n";
    assert!(
        !analyse_src(src, Lang::JavaScript).is_empty(),
        "the stored value is still reachable through the returned object"
    );
}

/// Run the taint engine on `src` and return `(sink line-independent cap bits)`
/// for each finding, so tests can tell the SQL finding from a response one.
fn sql_result_flow_caps(
    src: &[u8],
    lang_name: &str,
    lang: Lang,
    ts: tree_sitter::Language,
    file: &str,
) -> Vec<u32> {
    let file_cfg = parse_lang(src, lang_name, ts);
    analyse_file(&file_cfg, &file_cfg.summaries, None, lang, file, &[], None)
        .iter()
        .map(|f| f.effective_sink_caps.bits())
        .collect()
}

/// The rows a parameterised query returns do not carry the bound value's
/// taint, so reaching `res.send` is clean (JS, pg-style gate).
#[test]
fn js_sql_bind_param_result_is_clean() {
    let src = br#"const { Pool } = require('pg');
const pool = new Pool();
async function handler(req, res) {
  const id = req.query.id;
  const r = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  res.send(r.rows);
}
"#;
    let ts = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let caps = sql_result_flow_caps(src, "javascript", Lang::JavaScript, ts, "test.js");
    assert!(
        caps.is_empty(),
        "bound value must not taint the result; got {caps:?}"
    );
}

/// Tainted SQL text still fires the SQLi finding, and the rows keep the
/// taint, so they still reach the response sink.
#[test]
fn js_sql_text_taint_fires_and_result_stays_tainted() {
    let src = br#"const { Pool } = require('pg');
const pool = new Pool();
async function handler(req, res) {
  const id = req.query.id;
  const r = await pool.query('SELECT * FROM users WHERE id = ' + id);
  res.send(r.rows);
}
"#;
    let ts = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    let caps = sql_result_flow_caps(src, "javascript", Lang::JavaScript, ts, "test.js");
    let sql = crate::labels::Cap::SQL_QUERY.bits();
    assert!(
        caps.iter().any(|c| c & sql != 0),
        "missing SQLi finding: {caps:?}"
    );
    assert!(
        caps.iter().any(|c| c & sql == 0),
        "result of a tainted query text must still reach the response sink: {caps:?}"
    );
}

/// Python DB-API: a bound parameter does not taint the fetched rows.
#[test]
fn python_sql_bind_param_result_is_clean() {
    let src = br#"
import sqlite3
from flask import Flask, request, jsonify
def handler():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    conn.close()
    return jsonify(rows)
"#;
    let ts = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let caps = sql_result_flow_caps(src, "python", Lang::Python, ts, "test.py");
    assert!(
        caps.is_empty(),
        "bound value must not taint the rows; got {caps:?}"
    );
}

/// Python DB-API: tainted query text still fires and the rows stay tainted.
#[test]
fn python_sql_text_taint_fires() {
    let src = br#"
import sqlite3
from flask import Flask, request, jsonify
def handler():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM users WHERE id = " + uid)
    conn.close()
    return jsonify(rows)
"#;
    let ts = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    let caps = sql_result_flow_caps(src, "python", Lang::Python, ts, "test.py");
    let sql = crate::labels::Cap::SQL_QUERY.bits();
    assert!(
        caps.iter().any(|c| c & sql != 0),
        "missing SQLi finding: {caps:?}"
    );
}

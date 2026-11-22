use super::*;
use petgraph::visit::EdgeRef;
use tree_sitter::Language;

fn parse_and_build(src: &[u8], lang_str: &str, ts_lang: Language) -> (Cfg, NodeIndex) {
    let file_cfg = parse_to_file_cfg(src, lang_str, ts_lang);
    // If there's a function body, return it (most tests wrap code in a function).
    // Otherwise return the top-level body.
    let body = if file_cfg.bodies.len() > 1 {
        &file_cfg.bodies[1]
    } else {
        &file_cfg.bodies[0]
    };
    (body.graph.clone(), body.entry)
}

fn parse_to_file_cfg(src: &[u8], lang_str: &str, ts_lang: Language) -> FileCfg {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    build_cfg(&tree, src, lang_str, "test.js", None)
}

#[test]
fn js_try_catch_has_exception_edges() {
    let src = b"function f() { try { foo(); } catch (e) { bar(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    assert!(
        !exception_edges.is_empty(),
        "Expected at least one Exception edge"
    );
    // Verify source is a Call node
    for e in &exception_edges {
        assert_eq!(cfg[e.source()].kind, StmtKind::Call);
    }
}

/// When a classifiable call (here `eval`, a built-in JS sink) is nested
/// inside a multi-line statement, the CFG node's `classification_span()`
/// should point at the inner call, not at the outer statement's start ,
/// so finding display reports the line the dangerous call actually lives
/// on.  `ast.span` must still cover the whole outer statement for
/// structural passes that need the statement grain.
#[test]
fn inner_call_override_narrows_classification_span() {
    // Byte offsets chosen so the outer statement spans two lines:
    //   line 2 (row 1): `x = \``
    //   line 3 (row 2): `  ${eval('1')}`
    //   line 4 (row 3): `\`;`
    let src = b"function f() {\n  x = `\n  ${eval('1')}\n  `;\n}\n";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    // Find the node whose callee was overridden to `eval`.
    let sink = cfg
        .node_indices()
        .find(|&i| cfg[i].call.callee.as_deref() == Some("eval"))
        .expect("inner-call override should produce a node with callee=eval");

    let info = &cfg[sink];

    // The outer `ast.span` starts at the `x = ...` expression statement
    // on line 2; the inner eval call lives on line 3.
    let outer_byte = info.ast.span.0;
    let inner_byte = info.classification_span().0;
    assert!(
        inner_byte > outer_byte,
        "classification span should start *inside* the outer statement (outer={outer_byte}, inner={inner_byte})"
    );

    let line_of = |b: usize| src[..b].iter().filter(|&&c| c == b'\n').count() + 1;
    assert_eq!(line_of(outer_byte), 2, "outer ast.span on line 2");
    assert_eq!(line_of(inner_byte), 3, "classification_span on eval's line");

    // callee_span must be populated (that's the whole point).
    assert!(
        info.call.callee_span.is_some(),
        "inner-call override should record callee_span"
    );
}

/// Ruby (and any language without an `expression_statement` wrapper)
/// reaches `push_node` with `ast.kind() == "call"` (`Kind::CallMethod`)
/// for top-level statement-position calls.  The inner-call fallback at
/// `push_node` line ~1690 must include `Kind::CallFn | Kind::CallMethod
/// | Kind::CallMacro` in its kind gate, otherwise an unclassified outer
/// wrapper around a sink (e.g. `YAML.safe_load(File.read(filename))`,
/// `String.new(File.read(x))`, `JSON.parse(File.read(x))` — every
/// chain-style sink wrapper used in real Ruby helpers) loses the inner
/// sink's classification entirely.  Cross-function summary extraction
/// then misses the wrapper's `param_to_sink` and downstream callers
/// silently lose detection.  Regression guard for CVE-2023-38337
/// (rswag-api `parse_file → load_yaml/load_json → File.read` chain)
/// and CVE-2021-21288 (CarrierWave `download → OpenURI.open_uri`).
#[test]
fn ruby_inner_call_fallback_classifies_wrapper_around_file_read() {
    let src = b"def f(x)\n  YAML.safe_load(File.read(x))\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    // The outer call `YAML.safe_load(...)` does not classify by itself;
    // the fallback must descend into its argument list and pick up the
    // inner `File.read(x)` Sink(FILE_IO) label.
    let sink = cfg
        .node_indices()
        .find(|&i| cfg[i].call.callee.as_deref() == Some("File.read"))
        .expect(
            "inner-call fallback should override the outer YAML.safe_load callee with File.read",
        );

    let info = &cfg[sink];
    assert!(
        info.taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(crate::labels::Cap::FILE_IO))),
        "wrapper-around-File.read node must carry the FILE_IO sink label"
    );
    // outer_callee should preserve the original callee text so cross-fn
    // summary lookup can still find the wrapping function.
    assert_eq!(
        info.call.outer_callee.as_deref(),
        Some("YAML.safe_load"),
        "outer_callee must preserve the original wrapping callee"
    );
}

/// Identical-shape regression guard for the *bare-function* call
/// variant (`outer(File.read(x))`) — exercises the `Kind::CallFn`
/// branch of the gate, where Ruby/Python/etc.'s top-level free
/// function calls lacking a method receiver land.
#[test]
fn ruby_inner_call_fallback_classifies_bare_outer_around_file_read() {
    let src = b"def f(x)\n  outer(File.read(x))\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    let sink = cfg
        .node_indices()
        .find(|&i| cfg[i].call.callee.as_deref() == Some("File.read"))
        .expect("inner-call fallback must override `outer` callee with File.read");

    let info = &cfg[sink];
    assert!(
        info.taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(crate::labels::Cap::FILE_IO))),
        "wrapper-around-File.read node must carry FILE_IO sink label"
    );
}

/// A FILE_IO sink nested as an argument to a *Sanitizer*-labelled outer call
/// (`JSON.parse(fs.readFileSync(x))`) must still be surfaced: the outer
/// sanitizer label fills `labels`, so the legacy `labels.is_empty()` gate
/// skipped it and the inner sink was shadowed.  `find_inner_sink_call`
/// recurses PAST the non-sink outer call.  Motivated by vite CVE-2026-39365.
#[test]
fn js_sanitizer_shadow_surfaces_inner_file_io_sink() {
    let src =
        b"function f(x) {\n  const m = JSON.parse(fs.readFileSync(x, 'utf-8'));\n  return m;\n}\n";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let sink = cfg
        .node_indices()
        .find(|&i| cfg[i].call.callee.as_deref() == Some("fs.readFileSync"))
        .expect("inner FILE_IO sink must be surfaced past the JSON.parse sanitizer");
    let info = &cfg[sink];
    assert!(
        info.taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(crate::labels::Cap::FILE_IO))),
        "nested fs.readFileSync under JSON.parse must carry the FILE_IO sink label"
    );
    assert_eq!(
        info.call.outer_callee.as_deref(),
        Some("JSON.parse"),
        "outer_callee must preserve the wrapping JSON.parse sanitizer callee"
    );
}

/// Same Sanitizer-shadow shape, but the inner sink is the `node:fs/promises`
/// import-alias form (`fsp.readFile`) whose label is only resolvable once the
/// per-file import view is built (the gated post-pass).
/// `apply_gated_label_rules` must walk into the JSON.parse argument and surface
/// the import-gated FILE_IO sink.  Verbatim vite CVE-2026-39365 sink shape.
#[test]
fn js_sanitizer_shadow_surfaces_inner_fsp_readfile_via_import_view() {
    let src = b"import fsp from 'node:fs/promises';\nasync function f(x) {\n  const m = JSON.parse(await fsp.readFile(x, 'utf-8'));\n  return m;\n}\n";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let sink = cfg
        .node_indices()
        .find(|&i| cfg[i].call.callee.as_deref() == Some("fsp.readFile"))
        .expect("import-gated fsp.readFile must be surfaced past the JSON.parse sanitizer");
    let info = &cfg[sink];
    assert!(
        info.taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(crate::labels::Cap::FILE_IO))),
        "nested fsp.readFile under JSON.parse must carry the FILE_IO sink label"
    );
    assert_eq!(
        info.call.outer_callee.as_deref(),
        Some("JSON.parse"),
        "outer_callee must preserve the wrapping JSON.parse sanitizer callee"
    );
}

/// `classification_span()` must fall back to `ast.span` when no narrower
/// sub-expression was recorded, so existing structural code paths keep
/// working unchanged for nodes whose classification applies to the whole
/// outer node.
#[test]
fn classification_span_falls_back_to_ast_span() {
    let info = NodeInfo {
        ast: AstMeta {
            span: (100, 200),
            enclosing_func: None,
        },
        ..Default::default()
    };
    assert!(info.call.callee_span.is_none());
    assert_eq!(info.classification_span(), (100, 200));

    let narrowed = NodeInfo {
        ast: AstMeta {
            span: (100, 200),
            enclosing_func: None,
        },
        call: CallMeta {
            callee_span: Some((150, 170)),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(narrowed.classification_span(), (150, 170));
    assert_eq!(narrowed.ast.span, (100, 200));
}

/// The narrowed `callee_span` must remain strictly narrower than
/// `ast.span` on real-world CFG nodes.  When the classification applies
/// to (or degenerates to) the outer node, `callee_span` is left `None`
/// so we don't bloat every labeled node with a redundant span copy.
#[test]
fn callee_span_unset_when_no_narrowing_is_possible() {
    // A bare `eval(x);` on one line: `first_call_ident` finds the
    // call_expression whose span is nearly the whole expression_statement
    // (different by the trailing `;`).  `classification_span` still
    // returns a sensible line, but the exact trimming is an
    // implementation detail.  What we assert here is the invariant:
    // if callee_span *is* set, it must be contained in ast.span.
    let src = b"function f() { eval(x); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let sink = cfg
        .node_indices()
        .find(|&i| cfg[i].call.callee.as_deref() == Some("eval"))
        .expect("should find eval call");
    let info = &cfg[sink];
    if let Some(cs) = info.call.callee_span {
        assert!(
            cs.0 >= info.ast.span.0 && cs.1 <= info.ast.span.1,
            "callee_span {:?} must be contained in ast.span {:?}",
            cs,
            info.ast.span,
        );
        assert_ne!(
            cs, info.ast.span,
            "callee_span should only be set when it narrows ast.span"
        );
    }
}

#[test]
fn js_try_finally_no_exception_edges() {
    let src = b"function f() { try { foo(); } finally { cleanup(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    // No catch clause → no exception edges
    assert!(
        exception_edges.is_empty(),
        "Expected no Exception edges for try/finally without catch"
    );

    // Verify finally nodes are reachable from entry
    let mut reachable = HashSet::new();
    let mut bfs = petgraph::visit::Bfs::new(&cfg, _entry);
    while let Some(nx) = bfs.next(&cfg) {
        reachable.insert(nx);
    }
    assert_eq!(
        reachable.len(),
        cfg.node_count(),
        "All nodes should be reachable (finally connected to try body)"
    );
}

#[test]
fn java_try_catch_has_exception_edges() {
    let src = b"class Foo { void bar() { try { baz(); } catch (Exception e) { qux(); } } }";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "java", ts_lang);

    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    assert!(
        !exception_edges.is_empty(),
        "Expected at least one Exception edge in Java try/catch"
    );
    for e in &exception_edges {
        assert_eq!(cfg[e.source()].kind, StmtKind::Call);
    }
}

#[test]
fn js_try_catch_finally_all_reachable() {
    let src = b"function f() { try { foo(); } catch (e) { bar(); } finally { baz(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, entry) = parse_and_build(src, "javascript", ts_lang);

    // All nodes should be reachable
    let mut reachable = HashSet::new();
    let mut bfs = petgraph::visit::Bfs::new(&cfg, entry);
    while let Some(nx) = bfs.next(&cfg) {
        reachable.insert(nx);
    }
    assert_eq!(
        reachable.len(),
        cfg.node_count(),
        "All nodes should be reachable in try/catch/finally"
    );

    // Should have exception edges
    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    assert!(!exception_edges.is_empty());
}

#[test]
fn js_throw_in_try_catch_has_exception_edge() {
    let src = b"function f() { try { throw new Error('bad'); } catch (e) { handle(e); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    assert!(
        !exception_edges.is_empty(),
        "throw inside try should create exception edge to catch"
    );
}

#[test]
fn java_multiple_catch_clauses() {
    let src = b"class Foo { void bar() { try { baz(); } catch (IOException e) { a(); } catch (Exception e) { b(); } } }";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "java", ts_lang);

    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    // Should have exception edges to both catch clauses
    assert!(
        exception_edges.len() >= 2,
        "Expected exception edges to multiple catch clauses, got {}",
        exception_edges.len()
    );
}

#[test]
fn js_catch_param_defines_variable() {
    let src = b"function f() { try { foo(); } catch (e) { bar(e); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    // Find the synthetic catch-param node
    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert_eq!(
        catch_param_nodes.len(),
        1,
        "Expected exactly one catch_param node"
    );
    let cp = &cfg[catch_param_nodes[0]];
    assert_eq!(cp.taint.defines.as_deref(), Some("e"));
    assert_eq!(cp.kind, StmtKind::Seq);

    // Exception edges should target the synthetic node
    let exception_targets: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .map(|e| e.target())
        .collect();
    assert!(exception_targets.iter().all(|&t| t == catch_param_nodes[0]));
}

#[test]
fn java_catch_param_extracted() {
    let src = b"class Foo { void bar() { try { baz(); } catch (Exception e) { qux(e); } } }";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "java", ts_lang);

    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert_eq!(
        catch_param_nodes.len(),
        1,
        "Expected exactly one catch_param node in Java"
    );
    assert_eq!(
        cfg[catch_param_nodes[0]].taint.defines.as_deref(),
        Some("e")
    );
}

#[test]
fn js_catch_no_param_no_synthetic() {
    // catch {} with no parameter should not create a catch_param node
    let src = b"function f() { try { foo(); } catch { bar(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert!(
        catch_param_nodes.is_empty(),
        "catch without parameter should not create a catch_param node"
    );
}

//  Ruby begin/rescue/ensure tests

#[test]
fn ruby_begin_rescue_has_exception_edges() {
    let src = b"def f()\n  begin\n    foo()\n  rescue => e\n    bar(e)\n  end\nend";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    let exception_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .collect();
    assert!(
        !exception_edges.is_empty(),
        "begin/rescue should produce exception edges"
    );
}

#[test]
fn ruby_rescue_catch_param_defines_variable() {
    let src = b"def f()\n  begin\n    foo()\n  rescue StandardError => e\n    bar(e)\n  end\nend";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert_eq!(
        catch_param_nodes.len(),
        1,
        "Expected exactly one catch_param node in Ruby rescue"
    );
    let cp = &cfg[catch_param_nodes[0]];
    assert_eq!(cp.taint.defines.as_deref(), Some("e"));
    assert_eq!(cp.kind, StmtKind::Seq);

    // Exception edges should target the synthetic node
    let exception_targets: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .map(|e| e.target())
        .collect();
    assert!(exception_targets.iter().all(|&t| t == catch_param_nodes[0]));
}

#[test]
fn ruby_begin_rescue_ensure_complete() {
    let src =
        b"def f()\n  begin\n    foo()\n  rescue => e\n    bar(e)\n  ensure\n    baz()\n  end\nend";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    // Should have exception edges
    let exception_count = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .count();
    assert!(
        exception_count > 0,
        "begin/rescue/ensure should have exception edges"
    );

    // All nodes should be reachable (no orphaned nodes beyond entry/exit)
    let node_count = cfg.node_count();
    assert!(node_count > 3, "CFG should have multiple nodes");
}

#[test]
fn ruby_rescue_no_variable() {
    // bare rescue without => e
    let src = b"def f()\n  begin\n    foo()\n  rescue\n    bar()\n  end\nend";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    // No catch_param node should be created
    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert!(
        catch_param_nodes.is_empty(),
        "rescue without variable should not create a catch_param node"
    );

    // But exception edges should still exist
    let exception_count = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .count();
    assert!(
        exception_count > 0,
        "rescue without variable should still have exception edges"
    );
}

#[test]
fn ruby_body_statement_implicit_begin() {
    // def method body with inline rescue (no explicit begin)
    let src = b"def f()\n  foo()\nrescue => e\n  bar(e)\nend";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    let exception_count = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .count();
    assert!(
        exception_count > 0,
        "implicit begin via body_statement should produce exception edges"
    );

    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert_eq!(
        catch_param_nodes.len(),
        1,
        "implicit begin rescue should have one catch_param node"
    );
    assert_eq!(
        cfg[catch_param_nodes[0]].taint.defines.as_deref(),
        Some("e")
    );
}

#[test]
fn ruby_multiple_rescue_clauses() {
    let src = b"def f()\n  begin\n    foo()\n  rescue IOError => e\n    handle_io(e)\n  rescue => e\n    handle_other(e)\n  end\nend";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    let catch_param_nodes: Vec<_> = cfg.node_indices().filter(|&n| cfg[n].catch_param).collect();
    assert_eq!(
        catch_param_nodes.len(),
        2,
        "Two rescue clauses should produce two catch_param nodes"
    );

    // Both should define "e"
    for &cp in &catch_param_nodes {
        assert_eq!(cfg[cp].taint.defines.as_deref(), Some("e"));
    }

    // Exception edges should target both synthetic nodes
    let exception_targets: std::collections::HashSet<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Exception))
        .map(|e| e.target())
        .collect();
    for &cp in &catch_param_nodes {
        assert!(
            exception_targets.contains(&cp),
            "Exception edges should target each catch_param node"
        );
    }
}

//  Short-circuit evaluation tests

/// Helper: collect all If nodes from the CFG.
fn if_nodes(cfg: &Cfg) -> Vec<NodeIndex> {
    cfg.node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::If)
        .collect()
}

/// Helper: check if an edge of the given kind exists from `src` to `dst`.
fn has_edge(cfg: &Cfg, src: NodeIndex, dst: NodeIndex, kind_match: fn(&EdgeKind) -> bool) -> bool {
    cfg.edges(src)
        .any(|e| e.target() == dst && kind_match(e.weight()))
}

#[test]
fn js_if_and_short_circuit() {
    // `if (a && b) { then(); }`
    // Should produce 2 If nodes: [a] --True--> [b]
    // False from a → else-path, False from b → else-path
    let src = b"function f() { if (a && b) { then(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        2,
        "Expected 2 If nodes for `a && b`, got {}",
        ifs.len()
    );

    // Find which is `a` and which is `b` by condition_vars
    let a_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
        .copied()
        .unwrap();
    let b_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
        .copied()
        .unwrap();

    // True edge from a to b
    assert!(
        has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::True)),
        "Expected True edge from a to b"
    );

    // Both a and b should have False edges going somewhere (else-path)
    let a_false: Vec<_> = cfg
        .edges(a_node)
        .filter(|e| matches!(e.weight(), EdgeKind::False))
        .collect();
    let b_false: Vec<_> = cfg
        .edges(b_node)
        .filter(|e| matches!(e.weight(), EdgeKind::False))
        .collect();
    assert!(!a_false.is_empty(), "Expected False edge from a");
    assert!(!b_false.is_empty(), "Expected False edge from b");
}

#[test]
fn js_if_or_short_circuit() {
    // `if (a || b) { then(); }`
    // Should produce 2 If nodes: [a] --False--> [b]
    // True from a → then-path, True from b → then-path
    let src = b"function f() { if (a || b) { then(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        2,
        "Expected 2 If nodes for `a || b`, got {}",
        ifs.len()
    );

    let a_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
        .copied()
        .unwrap();
    let b_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
        .copied()
        .unwrap();

    // False edge from a to b
    assert!(
        has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::False)),
        "Expected False edge from a to b"
    );

    // Both a and b should have True edges
    let a_true: Vec<_> = cfg
        .edges(a_node)
        .filter(|e| matches!(e.weight(), EdgeKind::True))
        .collect();
    let b_true: Vec<_> = cfg
        .edges(b_node)
        .filter(|e| matches!(e.weight(), EdgeKind::True))
        .collect();
    assert!(!a_true.is_empty(), "Expected True edge from a");
    assert!(!b_true.is_empty(), "Expected True edge from b");
}

#[test]
fn js_if_nested_and_or() {
    // `if (a && (b || c)) { then(); }`
    // 3 If nodes: [a] --True--> [b], [b] --False--> [c]
    // True from b or c → then; False from a or c → else
    let src = b"function f() { if (a && (b || c)) { then(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        3,
        "Expected 3 If nodes for `a && (b || c)`, got {}",
        ifs.len()
    );

    let a_node = ifs
        .iter()
        .find(|&&n| {
            let vars = &cfg[n].condition_vars;
            vars.contains(&"a".to_string()) && vars.len() == 1
        })
        .copied()
        .unwrap();
    let b_node = ifs
        .iter()
        .find(|&&n| {
            let vars = &cfg[n].condition_vars;
            vars.contains(&"b".to_string()) && vars.len() == 1
        })
        .copied()
        .unwrap();
    let c_node = ifs
        .iter()
        .find(|&&n| {
            let vars = &cfg[n].condition_vars;
            vars.contains(&"c".to_string()) && vars.len() == 1
        })
        .copied()
        .unwrap();

    // a --True--> b
    assert!(has_edge(&cfg, a_node, b_node, |e| matches!(
        e,
        EdgeKind::True
    )));
    // b --False--> c
    assert!(has_edge(&cfg, b_node, c_node, |e| matches!(
        e,
        EdgeKind::False
    )));
}

#[test]
fn js_while_and_short_circuit() {
    // `while (a && b) { body(); }`
    // Loop header + 2 If nodes, back-edge goes to header
    let src = b"function f() { while (a && b) { body(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        2,
        "Expected 2 If nodes in while condition, got {}",
        ifs.len()
    );

    // There should be a Loop header
    let loop_headers: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .collect();
    assert_eq!(loop_headers.len(), 1, "Expected 1 Loop header");
    let header = loop_headers[0];

    // Back-edges should go to header
    let back_edges: Vec<_> = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Back))
        .collect();
    assert!(!back_edges.is_empty(), "Expected back edges");
    for e in &back_edges {
        assert_eq!(
            e.target(),
            header,
            "Back edge should go to loop header, not into condition chain"
        );
    }
}

#[test]
fn python_if_and() {
    // Python uses `boolean_operator` with `and` token
    let src = b"def f():\n    if a and b:\n        pass\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "python", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        2,
        "Expected 2 If nodes for Python `a and b`, got {}",
        ifs.len()
    );

    let a_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
        .copied()
        .unwrap();
    let b_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
        .copied()
        .unwrap();

    assert!(
        has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::True)),
        "Expected True edge from a to b in Python and"
    );
}

#[test]
fn ruby_unless_and() {
    // `unless a && b`, chain built, branches swapped
    // Body should run when condition is false
    let src = b"def f\n  unless a && b\n    x\n  end\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "ruby", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        2,
        "Expected 2 If nodes for Ruby `unless a && b`, got {}",
        ifs.len()
    );

    let a_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"a".to_string()))
        .copied()
        .unwrap();
    let b_node = ifs
        .iter()
        .find(|&&n| cfg[n].condition_vars.contains(&"b".to_string()))
        .copied()
        .unwrap();

    // Still has True edge from a to b (the chain is the same)
    assert!(
        has_edge(&cfg, a_node, b_node, |e| matches!(e, EdgeKind::True)),
        "Expected True edge from a to b in unless"
    );

    // For `unless`, the False exits should connect to the body with False edge
    // (since body runs when condition is false)
    let a_false_targets: Vec<_> = cfg
        .edges(a_node)
        .filter(|e| matches!(e.weight(), EdgeKind::False))
        .map(|e| e.target())
        .collect();
    // a's false exit should connect to the body (not to a pass-through)
    // because for `unless (a && b)`, when a is false the full condition is false,
    // meaning the body should execute
    assert!(
        !a_false_targets.is_empty(),
        "a should have False edges in unless"
    );
}

#[test]
fn while_short_circuit_continue() {
    // `while (a && b) { if (cond) { continue; } body(); }`
    // Verify continue goes to loop header
    let src = b"function f() { while (a && b) { if (cond) { continue; } body(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let loop_headers: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .collect();
    assert_eq!(loop_headers.len(), 1);
    let header = loop_headers[0];

    // Continue nodes should have back-edge to header
    let continue_nodes: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Continue)
        .collect();
    assert!(!continue_nodes.is_empty(), "Expected continue node");
    for &cont in &continue_nodes {
        assert!(
            has_edge(&cfg, cont, header, |e| matches!(e, EdgeKind::Back)),
            "Continue should have back-edge to loop header"
        );
    }
}

#[test]
fn negated_boolean_no_decomposition() {
    // `!(a && b)` should NOT be decomposed (De Morgan out of scope)
    let src = b"function f() { if (!(a && b)) { then(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    // Should be exactly 1 If node (no decomposition)
    assert_eq!(
        ifs.len(),
        1,
        "Negated boolean should NOT be decomposed, got {} If nodes",
        ifs.len()
    );
}

#[test]
fn js_triple_and_chain() {
    // `if (a && b && c) { then(); }`
    // Tree-sitter parses as `(a && b) && c` → left-to-right chain
    let src = b"function f() { if (a && b && c) { then(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        3,
        "Expected 3 If nodes for `a && b && c`, got {}",
        ifs.len()
    );
}

#[test]
fn js_or_precedence_with_and() {
    // `if (a || b && c) { then(); }`
    // Tree-sitter respects precedence: `a || (b && c)`
    // → [a] --False--> [b] --True--> [c]
    // True from a or c → then; False from c (and b) → else
    let src = b"function f() { if (a || b && c) { then(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(
        ifs.len(),
        3,
        "Expected 3 If nodes for `a || b && c`, got {}",
        ifs.len()
    );
}

// ── first_call_ident tests ──────────────────────────────────────────

/// Helper: parse source with a given language, return the root tree-sitter node.
fn parse_tree(src: &[u8], ts_lang: Language) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    parser.parse(src, None).unwrap()
}

#[test]
fn first_call_ident_skips_lambda_body() {
    // `process(lambda: eval(dangerous))`, Python-style.
    // first_call_ident should return "process", not "eval".
    let src = b"process(lambda: eval(dangerous))";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let tree = parse_tree(src, ts_lang);
    let root = tree.root_node();
    let result = first_call_ident(root, "python", src);
    assert_eq!(result.as_deref(), Some("process"));
}

#[test]
fn first_call_ident_skips_arrow_function_body() {
    // `process(() => eval(dangerous))`, JS arrow function in argument.
    let src = b"process(() => eval(dangerous))";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let tree = parse_tree(src, ts_lang);
    let root = tree.root_node();
    let result = first_call_ident(root, "javascript", src);
    assert_eq!(result.as_deref(), Some("process"));
}

#[test]
fn first_call_ident_skips_named_function_in_arg() {
    // `process(function inner() { eval(dangerous); })`, named function expression in arg.
    let src = b"process(function inner() { eval(dangerous); })";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let tree = parse_tree(src, ts_lang);
    let root = tree.root_node();
    let result = first_call_ident(root, "javascript", src);
    assert_eq!(result.as_deref(), Some("process"));
}

#[test]
fn first_call_ident_normal_nested_call() {
    // `outer(inner(x))`, inner is NOT behind a function boundary, should be reachable.
    let src = b"outer(inner(x))";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let tree = parse_tree(src, ts_lang);
    let root = tree.root_node();
    let result = first_call_ident(root, "javascript", src);
    // first_call_ident returns the first call it encounters (outer)
    assert_eq!(result.as_deref(), Some("outer"));
}

#[test]
fn first_call_ident_finds_call_not_blocked_by_function() {
    // Ensure a call at the same level as a function literal is still found.
    // `[function() {}, actual_call()]`, array with function and call.
    let src = b"[function() {}, actual_call()]";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let tree = parse_tree(src, ts_lang);
    let root = tree.root_node();
    let result = first_call_ident(root, "javascript", src);
    assert_eq!(result.as_deref(), Some("actual_call"));
}

// ── Callee classification with nested function regression ───────────

#[test]
fn callee_not_resolved_from_nested_function_arg() {
    // `safe_wrapper(function() { eval(user_input); })`, the CFG for the
    // outer call should resolve the callee as "safe_wrapper", never "eval".
    let src = b"function f() { safe_wrapper(function() { eval(user_input); }); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);

    // Find the node whose callee is "safe_wrapper"
    let body = &file_cfg.bodies[1]; // function body
    let has_safe = body
        .graph
        .node_weights()
        .any(|info| info.call.callee.as_deref() == Some("safe_wrapper"));
    assert!(has_safe, "expected a node with callee 'safe_wrapper'");

    // The outer body should NOT have a node with callee "eval" attributed
    // to the outer expression, eval lives inside the nested function body.
    let outer_eval = body.graph.node_weights().any(|info| {
        info.call.callee.as_deref() == Some("eval") && info.ast.enclosing_func.is_none()
    });
    assert!(
        !outer_eval,
        "eval should not appear as a callee in the outer scope from a nested function"
    );
}

// ── NodeInfo sub-struct refactor tests ──────────────────────────────

#[test]
fn nodeinfo_default_is_valid() {
    let n = NodeInfo::default();
    assert_eq!(n.kind, StmtKind::Seq);
    assert!(n.call.callee.is_none());
    assert!(n.call.outer_callee.is_none());
    assert_eq!(n.call.call_ordinal, 0);
    assert!(n.call.arg_uses.is_empty());
    assert!(n.call.receiver.is_none());
    assert!(n.call.sink_payload_args.is_none());
    assert!(n.taint.labels.is_empty());
    assert!(n.taint.const_text.is_none());
    assert!(n.taint.defines.is_none());
    assert!(n.taint.uses.is_empty());
    assert!(n.taint.extra_defines.is_empty());
    assert_eq!(n.ast.span, (0, 0));
    assert!(n.ast.enclosing_func.is_none());
    assert!(!n.all_args_literal);
    assert!(!n.catch_param);
    assert!(n.condition_text.is_none());
    assert!(n.condition_vars.is_empty());
    assert!(!n.condition_negated);
    assert!(n.arg_callees.is_empty());
    assert!(n.cast_target_type.is_none());
    assert!(n.bin_op.is_none());
    assert!(n.bin_op_const.is_none());
    assert!(!n.managed_resource);
    assert!(!n.in_defer);
    assert!(!n.is_eq_with_const);
}

#[test]
fn callmeta_default() {
    let c = CallMeta::default();
    assert!(c.callee.is_none());
    assert!(c.outer_callee.is_none());
    assert_eq!(c.call_ordinal, 0);
    assert!(c.arg_uses.is_empty());
    assert!(c.receiver.is_none());
    assert!(c.sink_payload_args.is_none());
}

#[test]
fn taintmeta_default() {
    let t = TaintMeta::default();
    assert!(t.labels.is_empty());
    assert!(t.const_text.is_none());
    assert!(t.defines.is_none());
    assert!(t.uses.is_empty());
    assert!(t.extra_defines.is_empty());
}

#[test]
fn astmeta_default() {
    let a = AstMeta::default();
    assert_eq!(a.span, (0, 0));
    assert!(a.enclosing_func.is_none());
}

#[test]
fn synthetic_catch_param_node_structure() {
    let n = NodeInfo {
        kind: StmtKind::Seq,
        ast: AstMeta {
            span: (100, 100),
            enclosing_func: Some("handle_request".into()),
        },
        taint: TaintMeta {
            defines: Some("e".into()),
            ..Default::default()
        },
        call: CallMeta {
            callee: Some("catch(e)".into()),
            ..Default::default()
        },
        catch_param: true,
        ..Default::default()
    };
    assert_eq!(n.kind, StmtKind::Seq);
    assert_eq!(n.ast.span, (100, 100));
    assert_eq!(n.ast.enclosing_func.as_deref(), Some("handle_request"));
    assert_eq!(n.taint.defines.as_deref(), Some("e"));
    assert_eq!(n.call.callee.as_deref(), Some("catch(e)"));
    assert!(n.catch_param);
    assert!(n.taint.labels.is_empty());
    assert!(n.call.arg_uses.is_empty());
}

#[test]
fn synthetic_passthrough_node_structure() {
    let n = NodeInfo {
        kind: StmtKind::Seq,
        ast: AstMeta {
            span: (50, 50),
            enclosing_func: Some("main".into()),
        },
        ..Default::default()
    };
    assert_eq!(n.kind, StmtKind::Seq);
    assert_eq!(n.ast.span, (50, 50));
    assert!(n.taint.defines.is_none());
    assert!(n.call.callee.is_none());
    assert!(!n.catch_param);
}

#[test]
fn normal_call_node_structure() {
    let n = NodeInfo {
        kind: StmtKind::Call,
        call: CallMeta {
            callee: Some("eval".into()),
            receiver: Some("window".into()),
            call_ordinal: 3,
            arg_uses: vec![vec!["x".into()], vec!["y".into()]],
            sink_payload_args: Some(vec![0]),
            ..Default::default()
        },
        taint: TaintMeta {
            labels: {
                let mut v = SmallVec::new();
                v.push(crate::labels::DataLabel::Sink(
                    crate::labels::Cap::CODE_EXEC,
                ));
                v
            },
            defines: Some("result".into()),
            uses: vec!["x".into(), "y".into()],
            ..Default::default()
        },
        ast: AstMeta {
            span: (10, 50),
            enclosing_func: Some("handler".into()),
        },
        ..Default::default()
    };
    assert_eq!(n.call.callee.as_deref(), Some("eval"));
    assert_eq!(n.call.receiver.as_deref(), Some("window"));
    assert_eq!(n.call.call_ordinal, 3);
    assert_eq!(n.call.arg_uses.len(), 2);
    assert_eq!(n.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
    assert_eq!(n.taint.labels.len(), 1);
    assert_eq!(n.taint.defines.as_deref(), Some("result"));
    assert_eq!(n.taint.uses, vec!["x", "y"]);
    assert_eq!(n.ast.span, (10, 50));
    assert_eq!(n.ast.enclosing_func.as_deref(), Some("handler"));
}

#[test]
fn condition_node_preserves_fields() {
    let n = NodeInfo {
        kind: StmtKind::If,
        ast: AstMeta {
            span: (0, 20),
            enclosing_func: None,
        },
        condition_text: Some("x > 0".into()),
        condition_vars: vec!["x".into()],
        condition_negated: true,
        ..Default::default()
    };
    assert_eq!(n.kind, StmtKind::If);
    assert_eq!(n.condition_text.as_deref(), Some("x > 0"));
    assert_eq!(n.condition_vars, vec!["x"]);
    assert!(n.condition_negated);
}

#[test]
fn clone_preserves_all_sub_structs() {
    let original = NodeInfo {
        kind: StmtKind::Call,
        call: CallMeta {
            callee: Some("foo".into()),
            callee_text: Some("obj.foo".into()),
            outer_callee: Some("bar".into()),
            callee_span: Some((7, 17)),
            call_ordinal: 5,
            arg_uses: vec![vec!["a".into()]],
            receiver: Some("obj".into()),
            sink_payload_args: Some(vec![1, 2]),
            sink_reaching_uses: Some(vec!["a".into()]),
            kwargs: vec![("shell".into(), vec!["True".into()])],
            arg_string_literals: vec![Some("lit".into())],
            arg_string_prefixes: vec![None],
            arg_bare_names: 0b1,
            arg_raw_string_mask: 0b10,
            destination_uses: None,
            gate_filters: Vec::new(),
            is_constructor: false,
            callee_nesting: CalleeNesting::Own,
            ctor_owned_args: vec!["in".into()],
            produces_null_proto: false,
            hoisted_sink: Some(Box::new(crate::cfg::HoistedSink {
                payload_args: Some(vec![0]),
                arg_string_literals: vec![Some("SELECT 1".into())],
            })),
            nested_calls: Some(Box::new(NestedCallTree {
                calls: vec![NestedCall {
                    callee: "foo".into(),
                    span: (7, 17),
                    parent: None,
                    slot: CallSlot::Other,
                    arity: Some(1),
                    exact_arg: false,
                    label_source: crate::labels::Cap::empty(),
                    label_strip: crate::labels::Cap::HTML_ESCAPE,
                    label_sink: false,
                    labelled: true,
                }],
                anchor: Some(0),
                uses: vec![NestedUse {
                    text: "a".into(),
                    call: None,
                    slot: CallSlot::Other,
                }],
            })),
            receiver_decl_type: Some(crate::ssa::type_facts::TypeKind::JdbcTemplate),
            kw_arg_positions: Vec::new(),
        },
        taint: TaintMeta {
            labels: {
                let mut v = SmallVec::new();
                v.push(crate::labels::DataLabel::Source(crate::labels::Cap::all()));
                v
            },
            const_text: Some("42".into()),
            const_collection: false,
            defines: Some("r".into()),
            uses: vec!["a".into(), "b".into()],
            extra_defines: vec!["c".into()],
            array_pattern_indices: smallvec::SmallVec::new(),
            rhs_array_elements: smallvec::SmallVec::new(),
            rhs_object_literal: Some(Box::new(crate::cfg::RhsObjectLiteral {
                fields: smallvec::smallvec![("k".into(), crate::cfg::RhsObjectSlot::Literal)],
                open: false,
            })),
        },
        ast: AstMeta {
            span: (10, 100),
            enclosing_func: Some("main".into()),
        },
        all_args_literal: true,
        catch_param: true,
        ..Default::default()
    };
    let cloned = original.clone();
    assert_eq!(cloned.call.callee, original.call.callee);
    assert_eq!(cloned.call.outer_callee, original.call.outer_callee);
    assert_eq!(cloned.call.call_ordinal, original.call.call_ordinal);
    assert_eq!(cloned.call.arg_uses, original.call.arg_uses);
    assert_eq!(cloned.call.receiver, original.call.receiver);
    assert_eq!(
        cloned.call.sink_payload_args,
        original.call.sink_payload_args
    );
    assert_eq!(
        cloned.call.sink_reaching_uses,
        original.call.sink_reaching_uses
    );
    assert_eq!(cloned.call.kwargs, original.call.kwargs);
    assert_eq!(
        cloned.call.receiver_decl_type,
        original.call.receiver_decl_type
    );
    assert_eq!(cloned.taint.labels.len(), original.taint.labels.len());
    assert_eq!(cloned.taint.const_text, original.taint.const_text);
    assert_eq!(cloned.taint.defines, original.taint.defines);
    assert_eq!(cloned.taint.uses, original.taint.uses);
    assert_eq!(cloned.taint.extra_defines, original.taint.extra_defines);
    assert_eq!(
        cloned.taint.rhs_object_literal,
        original.taint.rhs_object_literal
    );
    assert_eq!(cloned.ast.span, original.ast.span);
    assert_eq!(cloned.ast.enclosing_func, original.ast.enclosing_func);
    assert_eq!(cloned.all_args_literal, original.all_args_literal);
    assert_eq!(cloned.catch_param, original.catch_param);
}

#[test]
fn cfg_output_equivalence_js_catch() {
    // This test verifies that the refactored NodeInfo produces the same
    // CFG structure as before for a JS try/catch.
    let src = b"function f() { try { foo(x); } catch(e) { bar(e); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let body = file_cfg.first_body();

    // Verify catch-param node exists with correct nested field access
    let catch_params: Vec<_> = body
        .graph
        .node_weights()
        .filter(|n| n.catch_param)
        .collect();
    assert_eq!(catch_params.len(), 1);
    assert_eq!(catch_params[0].taint.defines.as_deref(), Some("e"));
    assert!(
        catch_params[0]
            .call
            .callee
            .as_deref()
            .unwrap()
            .starts_with("catch(")
    );
}

#[test]
fn cfg_output_equivalence_condition_chain() {
    // Verify If nodes use the correct sub-struct paths
    let src = b"function f(x) { if (x > 0) { sink(x); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let if_nodes: Vec<_> = cfg
        .node_weights()
        .filter(|n| n.kind == StmtKind::If)
        .collect();
    assert!(!if_nodes.is_empty());
    // Condition text and vars should be on the If node directly
    let if_node = if_nodes[0];
    assert!(if_node.condition_text.is_some() || !if_node.condition_vars.is_empty());
    // Labels should be empty on If nodes (they're structural)
    assert!(if_node.taint.labels.is_empty());
}

#[test]
fn make_empty_node_info_uses_sub_structs() {
    let n = make_empty_node_info(StmtKind::Entry, (0, 100), Some("test_func"));
    assert_eq!(n.kind, StmtKind::Entry);
    assert_eq!(n.ast.span, (0, 100));
    assert_eq!(n.ast.enclosing_func.as_deref(), Some("test_func"));
    assert!(n.call.callee.is_none());
    assert!(n.taint.defines.is_none());
    assert!(n.taint.uses.is_empty());
}

// ── Import alias binding tests ──────────────────────────────────

#[test]
fn js_import_alias_bindings() {
    let src = b"import { getInput as fetchInput } from './source';";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    assert_eq!(file_cfg.import_bindings.len(), 1);
    let b = &file_cfg.import_bindings["fetchInput"];
    assert_eq!(b.original, "getInput");
    assert_eq!(b.module_path.as_deref(), Some("./source"));
}

#[test]
fn js_same_name_import_not_recorded() {
    let src = b"import { exec } from 'child_process';";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    assert!(file_cfg.import_bindings.is_empty());
}

#[test]
fn python_import_alias_bindings() {
    let src = b"from os import getenv as fetch_env";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "python", ts_lang);
    assert_eq!(file_cfg.import_bindings.len(), 1);
    let b = &file_cfg.import_bindings["fetch_env"];
    assert_eq!(b.original, "getenv");
    assert_eq!(b.module_path.as_deref(), Some("os"));
}

#[test]
fn python_multiple_aliased_imports() {
    let src = b"from source import get_input as fetch_input, run_query as exec_query";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "python", ts_lang);
    assert_eq!(file_cfg.import_bindings.len(), 2);
    assert_eq!(
        file_cfg.import_bindings["fetch_input"].original,
        "get_input"
    );
    assert_eq!(file_cfg.import_bindings["exec_query"].original, "run_query");
}

#[test]
fn python_same_name_import_not_recorded() {
    let src = b"from os import getenv";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "python", ts_lang);
    assert!(file_cfg.import_bindings.is_empty());
}

#[test]
fn php_namespace_alias_bindings() {
    let src = b"<?php\nuse App\\Security\\Sanitizer as Clean;\n";
    let ts_lang = Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_to_file_cfg(src, "php", ts_lang);
    assert_eq!(file_cfg.import_bindings.len(), 1);
    let b = &file_cfg.import_bindings["Clean"];
    assert_eq!(b.original, "Sanitizer");
    assert_eq!(b.module_path.as_deref(), Some("App\\Security\\Sanitizer"));
}

#[test]
fn php_no_alias_not_recorded() {
    let src = b"<?php\nuse App\\Security\\Sanitizer;\n";
    let ts_lang = Language::from(tree_sitter_php::LANGUAGE_PHP);
    let file_cfg = parse_to_file_cfg(src, "php", ts_lang);
    assert!(file_cfg.import_bindings.is_empty());
}

#[test]
fn rust_use_as_alias_bindings() {
    let src = b"use std::collections::HashMap as Map;";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "rust", ts_lang);
    assert_eq!(file_cfg.import_bindings.len(), 1);
    let b = &file_cfg.import_bindings["Map"];
    assert_eq!(b.original, "HashMap");
    assert_eq!(b.module_path.as_deref(), Some("std::collections::HashMap"));
}

#[test]
fn rust_no_alias_not_recorded() {
    let src = b"use std::collections::HashMap;";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "rust", ts_lang);
    assert!(file_cfg.import_bindings.is_empty());
}

#[test]
fn rust_nested_use_as_alias() {
    let src = b"use std::io::{Read as IoRead, Write};";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "rust", ts_lang);
    assert_eq!(file_cfg.import_bindings.len(), 1);
    let b = &file_cfg.import_bindings["IoRead"];
    assert_eq!(b.original, "Read");
}

/// `Ok(Reader { meta: <tainted>, tasks: File::open(const) })` collapses the
/// whole aggregate into one CFG node whose `Sink(FILE_IO)` label is
/// contributed by the nested `File::open`.  The node's def-use set includes
/// the tainted sibling field `meta`, which is NOT the sink's argument.
/// `sink_reaching_uses` must capture the inner sink call's own identifiers
/// (`dir`) and exclude the sibling (`meta`) so the taint sink scan does not
/// spuriously report `meta` as reaching the `File::open` path argument
/// (meilisearch `crates/dump/src/reader/v{2..6}/mod.rs`).
#[test]
fn rust_inner_sink_in_aggregate_records_reaching_uses_excluding_sibling() {
    let src = br#"
fn open(dir: &std::path::Path) -> std::io::Result<Reader> {
    let meta_file = std::fs::read(dir.join("metadata.json")).unwrap();
    let meta = String::from_utf8(meta_file).unwrap();
    Ok(Reader { meta, tasks: File::open(dir.join("data.jsonl")).unwrap() })
}
"#;
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let node = cfg
        .node_indices()
        .find(|&n| {
            let info = &cfg[n];
            info.call.outer_callee.as_deref() == Some("Ok")
                && info.call.sink_reaching_uses.is_some()
        })
        .expect("expected an inner-sink override node (outer=Ok) with sink_reaching_uses");
    let reaching = cfg[node].call.sink_reaching_uses.as_ref().unwrap();
    assert!(
        reaching.iter().any(|u| u == "dir"),
        "inner File::open path ident `dir` must be recorded, got {reaching:?}"
    );
    assert!(
        !reaching.iter().any(|u| u == "meta"),
        "sibling struct field `meta` must NOT be recorded, got {reaching:?}"
    );
}

/// `format!("{x}")` uses x even though x is captured via the format
/// string's named-argument syntax rather than as a separate AST
/// argument.  Without this lift, taint stops at the macro boundary
/// for any caller whose format string reads a tainted variable by
/// name (matrix-rust-sdk CVE-2025-53549, log!() / println!() across
/// most Rust 1.58+ codebases).
#[test]
fn rust_format_macro_named_arg_lifted_into_uses() {
    let src = b"fn f() { let x = 1; let y = format!(\"v={x}\"); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let mut found = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("y") {
            assert!(
                info.taint.uses.iter().any(|u| u == "x"),
                "expected `x` in uses for `let y = format!(\"v={{x}}\")`; got {:?}",
                info.taint.uses
            );
            found = true;
        }
    }
    assert!(found, "no node found defining `y`");
}

#[test]
fn rust_format_macro_named_arg_with_format_spec() {
    let src = b"fn f() { let x = 1; let y = format!(\"{x:?}\"); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let mut found = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("y") {
            assert!(
                info.taint.uses.iter().any(|u| u == "x"),
                "expected `x` lifted past `{{x:?}}` format spec; got {:?}",
                info.taint.uses
            );
            found = true;
        }
    }
    assert!(found, "no node found defining `y`");
}

#[test]
fn rust_format_macro_escaped_braces_not_lifted() {
    // `{{` and `}}` are escapes for literal `{` / `}`, NOT named
    // argument captures.  No identifier should be lifted from the
    // sequence between them.
    let src = b"fn f() { let q = format!(\"{{x}}\"); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("q") {
            assert!(
                !info.taint.uses.iter().any(|u| u == "x"),
                "must not lift `x` from escaped `{{{{x}}}}`; got {:?}",
                info.taint.uses
            );
        }
    }
}

#[test]
fn rust_format_macro_positional_index_not_lifted() {
    // Positional placeholders like `{0}` reference args by position,
    // not by name.  Don't accidentally treat a digit as an identifier.
    let src = b"fn f() { let a = 1; let q = format!(\"{0}\", a); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("q") {
            assert!(
                !info.taint.uses.iter().any(|u| u == "0"),
                "must not lift digit-only positional placeholder; got {:?}",
                info.taint.uses
            );
            assert!(
                info.taint.uses.iter().any(|u| u == "a"),
                "expected `a` in uses (positional arg) for `format!(\"{{0}}\", a)`; got {:?}",
                info.taint.uses
            );
        }
    }
}

#[test]
fn rust_println_macro_named_arg_lifted() {
    let src = b"fn f() { let user = String::from(\"x\"); println!(\"hi {user}\"); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let mut found = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.call.callee.as_deref() == Some("println") {
            assert!(
                info.taint.uses.iter().any(|u| u == "user"),
                "expected `user` lifted into println! uses; got {:?}",
                info.taint.uses
            );
            found = true;
        }
    }
    assert!(found, "no println! macro_invocation node found");
}

/// `format!(URL_FMT, path)` where `URL_FMT` resolves to a top-level
/// `const &str` literal must seed a `string_prefix` on the let-binding
/// node so `is_string_safe_for_ssrf` can lock the host the same way
/// `format!("https://api/{}", path)` does. The bridge fires only when
/// the first non-string token in the macro is an identifier whose
/// matching `const_item` has a string-literal value.
#[test]
fn rust_format_macro_const_first_arg_seeds_string_prefix() {
    let src = b"const URL_FMT: &str = \"https://api.example.com/users/{}\";\n\
                fn f(path: String) { let u = format!(URL_FMT, path); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let mut prefix: Option<String> = None;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("u")
            && let Some(p) = info.string_prefix.as_deref()
        {
            prefix = Some(p.to_string());
        }
    }
    assert_eq!(
        prefix.as_deref(),
        Some("https://api.example.com/users/"),
        "expected URL_FMT const to bridge into the format!() string_prefix",
    );
}

/// Counter-test: when the named const has no string-literal initializer
/// (e.g. `const X: usize = 4;`), the bridge must not fabricate a
/// prefix from a non-string value.
#[test]
fn rust_format_macro_const_first_arg_non_string_skipped() {
    let src = b"const N: usize = 4;\n\
                fn f(path: String) { let u = format!(N, path); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("u") {
            assert!(
                info.string_prefix.is_none(),
                "non-string const must not seed a prefix; got {:?}",
                info.string_prefix
            );
        }
    }
}

/// `static NAME: &str = "...";` declarations participate alongside
/// `const_item`: both shapes carry a `name` field and a string-literal
/// `value` so the bridge resolves either form identically.
#[test]
fn rust_format_macro_static_first_arg_seeds_string_prefix() {
    let src = b"static API_BASE: &str = \"https://api.example.com/users/{}\";\n\
                fn f(path: String) { let u = format!(API_BASE, path); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let mut prefix: Option<String> = None;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("u")
            && let Some(p) = info.string_prefix.as_deref()
        {
            prefix = Some(p.to_string());
        }
    }
    assert_eq!(
        prefix.as_deref(),
        Some("https://api.example.com/users/"),
        "expected static API_BASE to bridge into the format!() string_prefix",
    );
}

/// A const declared inside a function body must not bridge: only
/// file-level `const_item` declarations participate to keep the
/// lookup deterministic. (The macro's first arg can shadow a
/// file-level const with an inner-fn const, but inner consts are
/// off-scope for the AST-time prefix bridge.)
#[test]
fn rust_format_macro_inner_const_not_bridged() {
    let src = b"fn f(path: String) {\n\
                  const URL_FMT: &str = \"https://api/{}\";\n\
                  let u = format!(URL_FMT, path);\n\
                }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("u") {
            assert!(
                info.string_prefix.is_none(),
                "inner-fn const must not bridge; got {:?}",
                info.string_prefix
            );
        }
    }
}

#[test]
fn go_no_import_bindings() {
    let src = b"package main\nimport alias \"fmt\"\n";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "go", ts_lang);
    assert!(file_cfg.import_bindings.is_empty());
}

#[test]
fn java_no_import_bindings() {
    let src = b"import java.util.List;";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "java", ts_lang);
    assert!(file_cfg.import_bindings.is_empty());
}

// ── Promisify alias binding tests ───────────────────────────────

#[test]
fn js_promisify_alias_member_expression() {
    let src = b"const execAsync = util.promisify(child_process.exec);";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let alias = file_cfg
        .promisify_aliases
        .get("execAsync")
        .expect("execAsync should be recorded");
    assert_eq!(alias.wrapped, "child_process.exec");
}

#[test]
fn js_promisify_alias_bare_identifier() {
    // `promisify` imported directly from util (destructured).
    let src = b"const run = promisify(foo);";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    assert_eq!(
        file_cfg
            .promisify_aliases
            .get("run")
            .map(|a| a.wrapped.as_str()),
        Some("foo")
    );
}

#[test]
fn js_promisify_labels_carry_to_alias_call() {
    // The post-pass should union `child_process.exec`'s Sink(SHELL_ESCAPE)
    // into every call site of the alias.
    let src = b"const runAsync = util.promisify(child_process.exec);\n\
                    function f(userCmd) { runAsync(userCmd); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    assert!(file_cfg.promisify_aliases.contains_key("runAsync"));
    let any_runasync_sink = file_cfg.bodies.iter().any(|b| {
        b.graph.node_weights().any(|n| {
            n.call.callee.as_deref() == Some("runAsync")
                && n.taint.labels.iter().any(|lbl| {
                    matches!(
                        lbl,
                        crate::labels::DataLabel::Sink(c)
                            if c.intersects(crate::labels::Cap::SHELL_ESCAPE)
                    )
                })
        })
    });
    assert!(
        any_runasync_sink,
        "runAsync call site should inherit child_process.exec's SHELL_ESCAPE sink"
    );
}

#[test]
fn js_promisify_execfile_alias_carries_payload_args() {
    // A promisify alias of `execFile` must inherit not only the SHELL_ESCAPE
    // sink label but also the `=execFile` gate's `payload_args: &[0]`, so that
    // only arg 0 (the binary) is taint-checked and a tainted argv element at
    // arg 1 (`execFileAsync(cmd, [.., dest])`) does not spuriously fire.
    // Regression guard for OneUptime CVE-2026-27728's patched (execFile) form.
    let src = b"const execFileAsync = util.promisify(child_process.execFile);\n\
                function f(bin, args) { execFileAsync(bin, args); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    assert!(file_cfg.promisify_aliases.contains_key("execFileAsync"));
    let alias_node = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .find(|n| n.call.callee.as_deref() == Some("execFileAsync"))
        .expect("execFileAsync call site present");
    assert!(
        alias_node.taint.labels.iter().any(|lbl| matches!(
            lbl,
            crate::labels::DataLabel::Sink(c) if c.intersects(crate::labels::Cap::SHELL_ESCAPE)
        )),
        "promisify(execFile) alias should carry SHELL_ESCAPE sink"
    );
    assert_eq!(
        alias_node.call.sink_payload_args.as_deref(),
        Some(&[0usize][..]),
        "promisify(execFile) alias should inherit the =execFile gate's payload_args=[0]"
    );
}

#[test]
fn js_promisify_exec_alias_carries_payload_args() {
    // `promisify(exec)` (shell string at arg 0) likewise inherits payload_args=[0].
    let src = b"const execAsync = util.promisify(child_process.exec);\n\
                function f(cmd, opts) { execAsync(cmd, opts); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let alias_node = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .find(|n| n.call.callee.as_deref() == Some("execAsync"))
        .expect("execAsync call site present");
    assert_eq!(
        alias_node.call.sink_payload_args.as_deref(),
        Some(&[0usize][..]),
        "promisify(exec) alias should inherit payload_args=[0]"
    );
}

#[test]
fn js_promisify_ignored_for_non_js_langs() {
    let src = b"const x = util.promisify(exec)";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "python", ts_lang);
    assert!(file_cfg.promisify_aliases.is_empty());
}

#[test]
fn js_promisify_non_call_value_ignored() {
    // RHS is not a promisify call, no binding should be captured.
    let src = b"const execAsync = child_process.exec;";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    assert!(file_cfg.promisify_aliases.is_empty());
}

/// Every call node in `file_cfg` whose callee text is `callee`.
fn js_call_nodes<'a>(file_cfg: &'a FileCfg, callee: &str) -> Vec<&'a NodeInfo> {
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter(|n| n.call.callee.as_deref() == Some(callee))
        .collect()
}

fn has_sink(n: &NodeInfo, cap: Cap) -> bool {
    n.taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(cap)))
}

#[test]
fn js_regex_and_query_exec_are_not_shell_sinks() {
    let src = b"const re = /a(b)/;\n\
                function f(x, Model) { re.exec(x); Model.find({ a: x }).exec(); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let shell_nodes: Vec<_> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter(|n| has_sink(n, Cap::SHELL_ESCAPE))
        .map(|n| n.call.callee.clone())
        .collect();
    assert!(
        shell_nodes.is_empty(),
        "unexpected shell sinks: {shell_nodes:?}"
    );
}

#[test]
fn js_child_process_alias_is_import_gated_shell_sink() {
    // `cp.spawn` is a sink only because `cp` is bound to child_process; arg 0
    // is the payload, and `{ shell: true }` adds the argv array at arg 1.
    let src = b"const cp = require('child_process');\n\
                function a(bin, args) { cp.spawn(bin, args); }\n\
                function b(bin, args) { cp.spawn(bin, args, { shell: true }); }\n\
                function c(bin, args) { cp.spawn(bin, args, { shell: false, cwd: '/' }); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let nodes = js_call_nodes(&file_cfg, "cp.spawn");
    assert_eq!(nodes.len(), 3);
    let mut payloads: Vec<Vec<usize>> = nodes
        .iter()
        .map(|n| {
            assert!(
                has_sink(n, Cap::SHELL_ESCAPE),
                "cp.spawn should be a shell sink"
            );
            n.call.sink_payload_args.clone().unwrap_or_default()
        })
        .collect();
    payloads.sort();
    assert_eq!(payloads, vec![vec![0], vec![0], vec![0, 1]]);
}

#[test]
fn js_import_gated_chain_head_sink_checks_head_payload() {
    // `execFileSync` is a sink only through the import binding, so the gated
    // post-pass labels the chained call `execFileSync(..).toString()`.  The
    // head call's payload (arg 0) is what reaches the sink; a constant
    // binary with request data in the argv array is not a sink at all.
    let src = b"const { execFileSync } = require('child_process');\n\
                function f(bin) { return execFileSync(bin).toString(); }\n\
                function g(file) { return execFileSync('docker', ['ps', file]).trim(); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let shell: Vec<_> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter(|n| has_sink(n, Cap::SHELL_ESCAPE))
        .collect();
    assert!(
        !shell.is_empty(),
        "execFileSync(bin).toString() is a shell sink"
    );
    for n in &shell {
        assert_eq!(
            n.call.sink_reaching_uses.as_deref(),
            Some(&["bin".to_string()][..]),
            "only the head call's binary argument reaches the sink"
        );
    }
}

#[test]
fn js_require_member_call_uses_module_callee() {
    let src = b"function f(x) { require('node:child_process').exec(x, { cwd: x }); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let nodes = js_call_nodes(&file_cfg, "child_process.exec");
    assert_eq!(
        nodes.len(),
        1,
        "require('node:child_process').exec canonicalises"
    );
    assert!(has_sink(nodes[0], Cap::SHELL_ESCAPE));
    assert_eq!(
        nodes[0].call.sink_payload_args.as_deref(),
        Some(&[0usize][..])
    );
}

#[test]
fn js_split_shell_argv_array_is_shell_payload() {
    // `spawnSync('bash', ['-c', cmd])`: the shell is arg 0, its `-c` command
    // lives in the argv array at arg 1.
    let src = b"function f(spawnSync, cmd) { spawnSync('bash', ['-c', 'ls ' + cmd]); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let nodes = js_call_nodes(&file_cfg, "spawnSync");
    assert_eq!(nodes.len(), 1);
    assert!(has_sink(nodes[0], Cap::SHELL_ESCAPE));
    assert_eq!(
        nodes[0].call.sink_payload_args.as_deref(),
        Some(&[1usize][..])
    );
    assert_eq!(
        nodes[0].call.destination_uses.as_deref(),
        Some(&["cmd".to_string()][..])
    );
}

#[test]
fn js_timer_string_arg_is_code_exec_but_callbacks_are_not() {
    // Only a string-valued first argument is compiled.  Callbacks (literal,
    // named, bound, a Promise `resolve`) and unresolved names are not.
    let src = b"function retry() {}\n\
                class P { start() { setInterval(this.poll, 10); } poll() {} }\n\
                function f(cb, name) {\n\
                  const code = location.hash.substring(1);\n\
                  setTimeout(code, 10);\n\
                  setTimeout('render(' + name + ')', 10);\n\
                  setTimeout(() => console.log(name), 10);\n\
                  setTimeout(retry, 10);\n\
                  setTimeout(cb, 10);\n\
                  setTimeout(this.tick.bind(this, name), 10);\n\
                  return new Promise((resolve) => setTimeout(resolve, 10));\n\
                }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let mut code_exec: Vec<Vec<String>> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter(|n| has_sink(n, Cap::CODE_EXEC))
        .map(|n| n.call.arg_uses.first().cloned().unwrap_or_default())
        .collect();
    code_exec.sort();
    assert_eq!(
        code_exec,
        vec![vec!["code".to_string()], vec!["name".to_string()]],
        "only the string-valued timer arguments compile code"
    );
}

#[test]
fn js_inner_sink_under_zero_arg_chain_keeps_its_sink() {
    // The inner `child_process.execSync(cmd)` call supplies the node's sink;
    // the outer zero-arg `.toString().trim()` call must not empty its
    // payload set.
    let src = b"function f(hash) {\n\
                  return require('child_process').execSync('git show ' + hash).toString().trim();\n\
                }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let nodes = js_call_nodes(&file_cfg, "child_process.execSync");
    assert!(
        !nodes.is_empty(),
        "the inner execSync call classifies the node"
    );
    assert!(nodes.iter().all(|n| has_sink(n, Cap::SHELL_ESCAPE)));
}

#[test]
fn js_fluent_response_chain_classifies_by_final_method() {
    let src = b"function h(req, res) {\n\
                  res.status(200).send(req.query.q);\n\
                  res.set('Content-Type', 'text/html').send(req.query.q);\n\
                  return res.status(302).redirect(req.query.next);\n\
                }\n\
                function e(req, res) { res.status(204).json(); }\n\
                function g(db, q) { db.collection('users').find(q); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let sends = js_call_nodes(&file_cfg, "res.send");
    assert_eq!(sends.len(), 2, "both chains end in res.send");
    for n in &sends {
        assert!(has_sink(n, Cap::HTML_ESCAPE));
        assert!(
            !has_sink(n, Cap::HEADER_INJECTION),
            "the res.set chain head must not label the send call"
        );
        assert_eq!(n.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
    }
    // The `return` wrapper and its call both carry the callee.
    let redirects = js_call_nodes(&file_cfg, "res.redirect");
    assert!(!redirects.is_empty());
    assert!(redirects.iter().all(|n| has_sink(n, Cap::OPEN_REDIRECT)));
    // `res.status(204).json()` passes no body, so it is not a sink.  It sits
    // in its own function: in one that sets `text/html` a `res.json` call
    // is named `res.send`.
    let empty_bodies: Vec<_> = js_call_nodes(&file_cfg, "res.json");
    assert_eq!(empty_bodies.len(), 1);
    assert!(!has_sink(empty_bodies[0], Cap::HTML_ESCAPE));
    // `collection` is not a fluent response method: the chain keeps its text.
    assert!(js_call_nodes(&file_cfg, "db.find").is_empty());
}

#[test]
fn sql_placeholder_detection() {
    // Positive cases
    assert!(has_sql_placeholders("SELECT * FROM users WHERE id = $1"));
    assert!(has_sql_placeholders("SELECT * FROM users WHERE id = ?"));
    assert!(has_sql_placeholders("SELECT * FROM users WHERE id = %s"));
    assert!(has_sql_placeholders("INSERT INTO t (a, b) VALUES ($1, $2)"));
    assert!(has_sql_placeholders("SELECT * FROM t WHERE x = :name"));
    assert!(has_sql_placeholders("WHERE id = ? AND name = ?"));

    // Negative cases
    assert!(!has_sql_placeholders("SELECT * FROM users"));
    assert!(!has_sql_placeholders("SELECT * FROM users WHERE id = 1"));
    assert!(!has_sql_placeholders("SELECT $dollar FROM t")); // $d not $N
    assert!(!has_sql_placeholders("SELECT * FROM t WHERE x = $0")); // $0 not valid
    assert!(!has_sql_placeholders("ratio = 50%")); // %<not s>
}

/// The first node whose callee ends with `suffix`, across all bodies.
fn node_with_callee_suffix(file_cfg: &FileCfg, suffix: &str) -> NodeInfo {
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .find(|n| {
            n.call
                .callee
                .as_deref()
                .is_some_and(|c| c.ends_with(suffix))
        })
        .unwrap_or_else(|| panic!("no call ending with {suffix}"))
        .clone()
}

#[test]
fn parameterized_query_constant_text_is_skipped() {
    let src = b"def f(cur, uid):\n    cur.execute(\"SELECT * FROM t WHERE id = ?\", (uid,))\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "python", ts_lang), "execute");
    assert!(n.parameterized_query);
    assert!(!n.parameterized_query_interpolated);
}

#[test]
fn parameterized_query_python_fstring_keeps_the_sink_on_arg0() {
    let src = b"def f(cur, sort, n):\n    cur.execute(f\"SELECT * FROM t ORDER BY {sort} LIMIT ?\", (n,))\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "python", ts_lang), "execute");
    assert!(!n.parameterized_query);
    assert!(n.parameterized_query_interpolated);
    assert_eq!(n.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
}

#[test]
fn parameterized_query_python_concatenated_fstring_part() {
    let src = b"def f(cur, sort, n):\n    cur.execute(\"SELECT * FROM t ORDER BY \" f\"{sort}\" \" LIMIT ?\", (n,))\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "python", ts_lang), "execute");
    assert!(!n.parameterized_query);
    assert!(n.parameterized_query_interpolated);
    assert_eq!(n.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
}

#[test]
fn parameterized_query_placeholder_inside_interpolation_is_not_a_placeholder() {
    // The `?` belongs to the embedded expression, so this is not a
    // parameterized query at all: no skip, and no payload narrowing.
    let src = b"def f(cur, a, b, n):\n    cur.execute(f\"SELECT {a if b else 1} FROM t\", (n,))\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "python", ts_lang), "execute");
    assert!(!n.parameterized_query);
    assert!(!n.parameterized_query_interpolated);
}

#[test]
fn parameterized_query_ruby_interpolated_where() {
    let src = b"def index\n  q = params[:q]\n  User.where(\"name LIKE '%#{q}%' AND active = ?\", true)\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "ruby", ts_lang), "where");
    assert!(!n.parameterized_query);
    assert!(n.parameterized_query_interpolated);
    assert_eq!(n.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
}

#[test]
fn parameterized_query_ruby_constant_where_is_skipped() {
    let src = b"def index\n  User.where(\"name = ? AND active = ?\", params[:q], true)\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "ruby", ts_lang), "where");
    assert!(n.parameterized_query);
    assert!(!n.parameterized_query_interpolated);
}

#[test]
fn parameterized_query_js_template_with_substitution() {
    let src = b"async function f(pool, t, id) { await pool.query(`SELECT * FROM ${t} WHERE id = $1`, [id]); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let n = node_with_callee_suffix(&parse_to_file_cfg(src, "javascript", ts_lang), "query");
    assert!(!n.parameterized_query);
    assert!(n.parameterized_query_interpolated);
    assert_eq!(n.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
}

/// Every Sanitizer cap set that landed on a node of a Go snippet.
fn go_body_sanitizer_caps(src: &[u8]) -> Vec<Cap> {
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "go", ts_lang);
    cfg.node_indices()
        .flat_map(|i| cfg[i].taint.labels.clone())
        .filter_map(|l| match l {
            DataLabel::Sanitizer(c) => Some(c),
            _ => None,
        })
        .collect()
}

#[test]
fn go_replace_single_metachar_strip_earns_no_credit() {
    for call in [
        r#"strings.ReplaceAll(s, ";", "")"#,
        r#"strings.ReplaceAll(s, "|", "")"#,
        r#"strings.ReplaceAll(s, "'", "")"#,
        r#"strings.Replace(s, ";", "", -1)"#,
    ] {
        let src = format!("package main\nfunc f(s string) string {{\n\treturn {call}\n}}\n");
        let caps = go_body_sanitizer_caps(src.as_bytes());
        assert!(
            caps.is_empty(),
            "{call} must not earn sanitizer credit; got {caps:?}"
        );
    }
}

#[test]
fn go_replace_complete_escape_earns_credit() {
    let src = b"package main\nfunc f(s string) string {\n\treturn strings.ReplaceAll(s, \"<\", \"\")\n}\n";
    let caps = go_body_sanitizer_caps(src);
    assert!(
        caps.iter().any(|c| c.contains(Cap::HTML_ESCAPE)),
        "tag strip should earn HTML_ESCAPE; got {caps:?}"
    );
    let src = b"package main\nfunc f(s string) string {\n\treturn strings.ReplaceAll(s, \"..\", \"\")\n}\n";
    let caps = go_body_sanitizer_caps(src);
    assert!(
        caps.iter().any(|c| c.contains(Cap::FILE_IO)),
        "traversal strip should earn FILE_IO; got {caps:?}"
    );
}

#[test]
fn go_replace_with_count_is_only_a_full_replace_for_minus_one() {
    let full = b"package main\nfunc f(s string) string {\n\treturn strings.Replace(s, \"<\", \"\", -1)\n}\n";
    assert!(
        go_body_sanitizer_caps(full)
            .iter()
            .any(|c| c.contains(Cap::HTML_ESCAPE)),
        "Replace(.., -1) is a full replace"
    );
    let first_only = b"package main\nfunc f(s string) string {\n\treturn strings.Replace(s, \"<\", \"\", 1)\n}\n";
    assert!(
        go_body_sanitizer_caps(first_only).is_empty(),
        "Replace(.., 1) only strips the first match"
    );
}

#[test]
fn replace_chain_single_shell_or_quote_strip_earns_no_credit() {
    for body in [
        r#"s.replace(";", "")"#,
        r#"s.replace("|", "").replace("&", "")"#,
        r#"s.replace("'", "")"#,
        r#"s.replace("--", "")"#,
    ] {
        let src = format!("fn f(s: &str) -> String {{\n    {body}\n}}\n");
        let caps = rust_body_sanitizer_caps(src.as_bytes());
        assert!(
            caps.is_empty(),
            "{body} must not earn sanitizer credit; got {caps:?}"
        );
    }
}

#[test]
fn replace_chain_replacen_hop_earns_no_credit_but_keeps_the_walk() {
    // replacen only strips the first n matches.
    let src = br#"
fn f(s: &str) -> String {
    s.replacen("<", "", 1)
}
"#;
    assert!(rust_body_sanitizer_caps(src).is_empty());
    // A real full strip beneath a replacen hop still counts.
    let src = br#"
fn f(s: &str) -> String {
    s.replace("..", "").replacen("x", "y", 1)
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.iter().any(|c| c.contains(Cap::FILE_IO)),
        "the replace hop under replacen should still earn FILE_IO; got {caps:?}"
    );
}

#[test]
fn c_function_extracts_param_names() {
    let src = b"void handle_command(int cmd, char *arg) { }";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "c", ts_lang);
    let params: Vec<_> = file_cfg
        .summaries
        .values()
        .flat_map(|s| s.param_names.iter().cloned())
        .collect();
    assert!(
        params.contains(&"cmd".to_string()),
        "expected 'cmd' in params, got: {:?}",
        params
    );
    assert!(
        params.contains(&"arg".to_string()),
        "expected 'arg' in params, got: {:?}",
        params
    );
}

#[test]
fn c_pointer_returning_functions_keep_param_names() {
    let src = b"static FILE *open_pipe(char *cmd, int mode) { return 0; }\n\
char **table(char *key) { return 0; }\n\
void *(*pick(int sel))(void) { return 0; }\n";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "c", ts_lang);
    let by_name = |n: &str| {
        file_cfg
            .summaries
            .iter()
            .find(|(k, _)| k.name == n)
            .map(|(_, s)| s.param_names.clone())
    };
    assert_eq!(
        by_name("open_pipe"),
        Some(vec!["cmd".into(), "mode".into()])
    );
    assert_eq!(by_name("table"), Some(vec!["key".into()]));
    assert_eq!(by_name("pick"), Some(vec!["sel".into()]));
}

#[test]
fn c_condition_assignment_defines_target() {
    let src = b"void f(void) {\n\
    char *e;\n\
    int c;\n\
    if ((e = getenv(\"X\")) == NULL) return;\n\
    while ((c = getc(stdin)) != EOF) { }\n\
    if (!(e = getenv(\"Y\"))) return;\n\
    if ((c += 1) > 2) return;\n\
}\n";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let (g, _entry) = parse_and_build(src, "c", ts_lang);
    let defs: Vec<(StmtKind, Option<String>)> = g
        .node_indices()
        .filter(|&i| matches!(g[i].kind, StmtKind::If | StmtKind::Loop))
        .map(|i| (g[i].kind, g[i].taint.defines.clone()))
        .collect();
    assert_eq!(
        defs,
        vec![
            (StmtKind::If, Some("e".to_string())),
            (StmtKind::Loop, Some("c".to_string())),
            (StmtKind::If, Some("e".to_string())),
            (StmtKind::If, None),
        ],
        "plain assignments in a condition define their target; compound ones do not"
    );
}

#[test]
fn c_preproc_group_bodies_are_lowered() {
    let src = b"#ifndef X\nvoid f(void) { char *e = getenv(\"A\"); system(e); }\n#endif\n";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "c", ts_lang);
    assert!(
        file_cfg.summaries.keys().any(|k| k.name == "f"),
        "a function inside #ifndef must be summarised"
    );
}

#[test]
fn cpp_function_extracts_param_names() {
    let src = b"void process(int x, std::string name) { }";
    let ts_lang = Language::from(tree_sitter_cpp::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "cpp", ts_lang);
    let params: Vec<_> = file_cfg
        .summaries
        .values()
        .flat_map(|s| s.param_names.iter().cloned())
        .collect();
    assert!(
        params.contains(&"x".to_string()),
        "expected 'x' in params, got: {:?}",
        params
    );
    assert!(
        params.contains(&"name".to_string()),
        "expected 'name' in params, got: {:?}",
        params
    );
}

// ── callee-site metadata extraction ──────────────────────────────────

/// Callees collected into `LocalFuncSummary` should now carry structured
/// arity, receiver, and qualifier fields, not just a bare name.
#[test]
fn local_summary_callees_carry_arity_and_receiver() {
    // Two calls: one is a plain function call with 2 args, the other is
    // a method call on an explicit receiver.
    let src = br"
            function outer(x, y) {
                helper(x, y);
                obj.method(x);
            }
        ";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let summaries = &file_cfg.summaries;

    // Pull the outer function's summary.
    let (_key, outer) = summaries
        .iter()
        .find(|(k, _)| k.name == "outer")
        .expect("outer summary should exist");

    // Both calls should be recorded.
    let helper_site = outer
        .callees
        .iter()
        .find(|c| c.name == "helper")
        .expect("helper call should be recorded with structured metadata");
    assert_eq!(
        helper_site.arity,
        Some(2),
        "helper has 2 positional args at the call site"
    );
    assert_eq!(
        helper_site.receiver, None,
        "helper is not a method call — no receiver"
    );

    // JS `obj.method(x)` is a CallFn in tree-sitter-javascript whose
    // `function` child is a `member_expression`.  push_node now unwraps
    // that member expression and populates the structured `receiver`
    // field directly, so `qualifier` stays `None`.
    let method_site = outer
        .callees
        .iter()
        .find(|c| c.name.ends_with("method"))
        .expect("method call should be recorded");
    assert_eq!(method_site.arity, Some(1), "method has 1 positional arg");
    assert_eq!(
        method_site.receiver.as_deref(),
        Some("obj"),
        "js CallFn over member_expression should populate structured receiver"
    );
    assert_eq!(
        method_site.qualifier, None,
        "qualifier is suppressed once receiver is populated"
    );
}

/// JS `obj.method(x)` is modeled as `call_expression` whose `function`
/// child is a `member_expression`.  Kind::CallFn push_node must surface
/// the receiver identifier through `CallMeta.receiver`.
#[test]
fn local_summary_callees_js_method_receiver() {
    let src = br"
            function outer(obj, x) {
                obj.method(x);
            }
        ";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let (_key, outer) = file_cfg
        .summaries
        .iter()
        .find(|(k, _)| k.name == "outer")
        .expect("js outer summary should exist");

    let method_site = outer
        .callees
        .iter()
        .find(|c| c.name.ends_with("method"))
        .expect("js method call should be recorded");
    assert_eq!(method_site.arity, Some(1));
    assert_eq!(
        method_site.receiver.as_deref(),
        Some("obj"),
        "js CallFn over member_expression should populate structured receiver"
    );
}

/// Python `obj.method(x)` is modeled as `call` whose `function` child is
/// an `attribute`.  Kind::CallFn push_node must surface the receiver
/// identifier through `CallMeta.receiver`.
#[test]
fn local_summary_callees_python_method_receiver() {
    let src = b"
def outer(obj, x):
    obj.method(x)
";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "python", ts_lang);
    let (_key, outer) = file_cfg
        .summaries
        .iter()
        .find(|(k, _)| k.name == "outer")
        .expect("python outer summary should exist");

    let method_site = outer
        .callees
        .iter()
        .find(|c| c.name.ends_with("method"))
        .expect("python method call should be recorded");
    assert_eq!(method_site.arity, Some(1));
    assert_eq!(
        method_site.receiver.as_deref(),
        Some("obj"),
        "python CallFn over attribute should populate structured receiver"
    );
}

/// Java `obj.method(x)` IS classified as CallMethod (via
/// `method_invocation`), so the structured `receiver` field
/// should be populated directly rather than falling through to
/// the `qualifier` dotted-name fallback.
#[test]
fn local_summary_callees_java_method_receiver() {
    let src = br"
class Outer {
    void outer(Bar obj, int x) {
        obj.method(x);
    }
}
";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "java", ts_lang);
    let (_key, outer) = file_cfg
        .summaries
        .iter()
        .find(|(k, _)| k.name == "outer")
        .expect("java outer summary should exist");

    let method_site = outer
        .callees
        .iter()
        .find(|c| c.name.ends_with("method"))
        .expect("java method call should be recorded");
    assert_eq!(method_site.arity, Some(1));
    assert_eq!(
        method_site.receiver.as_deref(),
        Some("obj"),
        "java CallMethod should populate the structured receiver field"
    );
}

/// Python keyword arguments should be captured separately from positional
/// `arg_uses` and surfaced through `CallMeta.kwargs` as `(name, uses)`.
#[test]
fn call_node_kwargs_populated_for_python() {
    let src = b"
def outer(cmd):
    subprocess.run(cmd, shell=True, check=False)
";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "python", ts_lang);
    let call_node = cfg
        .node_weights()
        .find(|n| {
            n.kind == StmtKind::Call && n.call.callee.as_deref().is_some_and(|c| c.ends_with("run"))
        })
        .expect("subprocess.run call node should exist");

    // Receiver (`subprocess`) is a separate channel on `CallMeta.receiver`;
    // `arg_uses` holds positional arguments only. Keyword args must not
    // appear in positional slots.
    assert_eq!(
        call_node.call.arg_uses.len(),
        1,
        "arg_uses should be [cmd] — receiver is separate, kwargs are not positional"
    );
    assert_eq!(call_node.call.arg_uses[0], vec!["cmd".to_string()]);
    assert_eq!(call_node.call.receiver.as_deref(), Some("subprocess"));

    let kwargs = &call_node.call.kwargs;
    assert_eq!(kwargs.len(), 2, "two keyword arguments expected");
    assert_eq!(kwargs[0].0, "shell");
    assert_eq!(kwargs[1].0, "check");
}

/// JS object-literal positional args lift their `pair` children into
/// `kwargs` so consumers like xml_config's `processEntities` /
/// `resolve_entities` opt-in detector can read them without re-walking
/// the tree-sitter AST.
#[test]
fn call_node_kwargs_lifts_javascript_object_literal_pairs() {
    let src = br"
            function outer(cmd) {
                child_process.exec(cmd, { shell: true });
            }
        ";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let call_node = cfg
        .node_weights()
        .find(|n| {
            n.kind == StmtKind::Call
                && n.call
                    .callee
                    .as_deref()
                    .is_some_and(|c| c.ends_with("exec"))
        })
        .expect("child_process.exec call node should exist");
    let kwargs = &call_node.call.kwargs;
    assert!(
        kwargs
            .iter()
            .any(|(k, vs)| k == "shell" && vs.iter().any(|v| v == "true")),
        "JS object-literal `{{ shell: true }}` should surface as kwarg, got {kwargs:?}"
    );
}

/// Ordinals on callees should match `CallMeta.call_ordinal` so
/// downstream consumers can address a specific call site.
#[test]
fn local_summary_callees_have_distinct_ordinals() {
    let src = br"
            function outer() {
                a();
                a();
                b();
            }
        ";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let (_key, outer) = file_cfg
        .summaries
        .iter()
        .find(|(k, _)| k.name == "outer")
        .unwrap();

    // Dedup key is (name, arity, receiver, qualifier, ordinal), the two
    // `a()` sites have different ordinals, so both must appear.
    let a_sites: Vec<_> = outer.callees.iter().filter(|c| c.name == "a").collect();
    assert_eq!(
        a_sites.len(),
        2,
        "two a() calls should produce two entries with distinct ordinals, got: {:?}",
        a_sites
    );
    let ord0 = a_sites[0].ordinal;
    let ord1 = a_sites[1].ordinal;
    assert_ne!(ord0, ord1, "ordinals must differ across sites");
}

//  Anonymous function body naming via syntactic context
//  (derive_anon_fn_name_from_context coverage)

fn js_body_names(src: &[u8]) -> Vec<String> {
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    file_cfg
        .bodies
        .iter()
        .filter_map(|b| b.meta.func_key.as_ref().map(|k| k.name.clone()))
        .collect()
}

fn js_body_kinds(src: &[u8]) -> Vec<BodyKind> {
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    file_cfg.bodies.iter().map(|b| b.meta.kind).collect()
}

#[test]
fn anon_fn_named_from_var_declarator_js() {
    let src = b"var handler = function(x) { child_process.exec(x); };";
    let names = js_body_names(src);
    assert!(
        names.iter().any(|n| n == "handler"),
        "expected body named `handler` from var declarator, got: {:?}",
        names
    );
}

#[test]
fn anon_arrow_named_from_const_declarator_js() {
    let src = b"const run = (x) => { eval(x); };";
    let names = js_body_names(src);
    assert!(
        names.iter().any(|n| n == "run"),
        "expected body named `run` from const arrow declarator, got: {:?}",
        names
    );
}

#[test]
fn anon_fn_named_from_member_assignment_js() {
    let src = b"this.run = function(x) { eval(x); };";
    let names = js_body_names(src);
    assert!(
        names.iter().any(|n| n == "run"),
        "expected body named `run` from member assignment, got: {:?}",
        names
    );
}

#[test]
fn anon_fn_passed_as_arg_stays_anonymous_js() {
    // Function literal passed directly as argument has no stable
    // syntactic binding → must remain a synthetic anon name.
    let src = b"apply(function(x) { eval(x); });";
    let names = js_body_names(src);
    let kinds = js_body_kinds(src);
    assert!(
        kinds.contains(&BodyKind::AnonymousFunction),
        "expected at least one AnonymousFunction body, got: {:?}",
        kinds
    );
    assert!(
        names.iter().any(|n| is_anon_fn_name(n)),
        "expected synthetic anon name on FuncKey for call-argument fn literal, got: {:?}",
        names
    );
    assert!(
        !names.iter().any(|n| n == "apply"),
        "must not leak callee name onto its argument function, got: {:?}",
        names
    );
}

#[test]
fn named_fn_declaration_unchanged_js() {
    let src = b"function real_name(x) { eval(x); }";
    let names = js_body_names(src);
    assert!(
        names.iter().any(|n| n == "real_name"),
        "named declaration must retain its name, got: {:?}",
        names
    );
}

#[test]
fn anon_fn_named_from_short_var_decl_go() {
    let src = b"package main\nfunc main() { run := func(x string) { exec(x) }; run(\"hi\") }";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "go", ts_lang);
    let names: Vec<String> = file_cfg
        .bodies
        .iter()
        .filter_map(|b| b.meta.func_key.as_ref().map(|k| k.name.clone()))
        .collect();
    assert!(
        names.iter().any(|n| n == "run"),
        "expected func literal body keyed as `run` via Go short-var decl, got: {:?}",
        names
    );
}

#[test]
fn iife_callee_resolves_to_anon_body_js() {
    // `(function(arg){eval(arg);})(q)`, the CallFn arm must produce
    // a synthetic anon callee name so that taint can match the
    // inline body's FuncKey.
    let src = b"(function(arg){ eval(arg); })(q);";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let top = &file_cfg.bodies[0];
    let callee_names: Vec<String> = top
        .graph
        .node_indices()
        .filter_map(|i| top.graph[i].call.callee.clone())
        .collect();
    assert!(
        callee_names.iter().any(|c| is_anon_fn_name(c)),
        "IIFE call site should record synthetic anon callee, got: {:?}",
        callee_names
    );
}

/// Helper: collect every Sanitizer cap set that landed on any CFG node in
/// the function body for a Rust snippet.  Used by the replace-chain
/// detector tests.
fn rust_body_sanitizer_caps(src: &[u8]) -> Vec<Cap> {
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    cfg.node_indices()
        .flat_map(|i| cfg[i].taint.labels.clone())
        .filter_map(|l| match l {
            DataLabel::Sanitizer(c) => Some(c),
            _ => None,
        })
        .collect()
}

#[test]
fn replace_chain_strips_file_io_for_path_traversal_literals() {
    // `.replace("..", "").replace("/", "_")` should earn FILE_IO stripping.
    let src = br#"
fn sanitize_input(s: &str) -> String {
    s.replace("..", "").replace("/", "_")
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.iter().any(|c| c.contains(Cap::FILE_IO)),
        "Expected a Sanitizer(FILE_IO) on the replace chain; got {:?}",
        caps
    );
}

#[test]
fn replace_chain_strips_html_escape_for_angle_brackets() {
    // Stripping `<` and `>` earns HTML_ESCAPE, not FILE_IO.
    let src = br#"
fn strip_tags(s: &str) -> String {
    s.replace("<", "").replace(">", "")
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.iter().any(|c| c.contains(Cap::HTML_ESCAPE)),
        "Expected a Sanitizer(HTML_ESCAPE) on angle-bracket strip; got {:?}",
        caps
    );
    assert!(
        !caps.iter().any(|c| c.contains(Cap::FILE_IO)),
        "Angle-bracket strip should NOT earn FILE_IO credit; got {:?}",
        caps
    );
}

#[test]
fn replace_chain_rejects_unrecognised_literals() {
    // `.replace("foo", "bar")` contains no dangerous pattern, must NOT be
    // credited as a sanitizer.  Preserves the FP→TN guard: replace calls
    // that don't strip anything dangerous must stay transparent to taint.
    let src = br#"
fn rewrite(s: &str) -> String {
    s.replace("foo", "bar").replace("baz", "qux")
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.is_empty(),
        "Generic replace chain should not earn sanitizer credit; got {:?}",
        caps
    );
}

#[test]
fn replace_chain_rejects_when_replacement_reintroduces_pattern() {
    // `.replace("x", "..")` strips `x` but *reintroduces* `..`, be
    // maximally conservative and abandon all credit for this chain.
    let src = br#"
fn evil(s: &str) -> String {
    s.replace("x", "..")
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.is_empty(),
        "Replacement reintroducing dangerous pattern must kill credit; got {:?}",
        caps
    );
}

#[test]
fn replace_chain_rejects_dynamic_arg() {
    // `.replace(var, "")`, search is not a literal; pattern analysis can
    // say nothing about what was stripped.  Must not earn credit.
    let src = br#"
fn dynamic(s: &str, needle: &str) -> String {
    s.replace(needle, "")
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.is_empty(),
        "Dynamic replace arg must not earn credit; got {:?}",
        caps
    );
}

#[test]
fn replace_chain_rejects_non_identifier_base() {
    // `get_s().replace("..", "")`, innermost receiver is a call, not a
    // parameter.  We have no reason to believe `get_s()` returns a value
    // that benefits the caller; refuse credit.
    let src = br#"
fn base_is_call() -> String {
    get_s().replace("..", "")
}
"#;
    let caps = rust_body_sanitizer_caps(src);
    assert!(
        caps.is_empty(),
        "Non-identifier chain base must not earn credit; got {:?}",
        caps
    );
}

// ── is_numeric_length_access detector ─────────────────────────────────

fn find_node_defining<'a>(cfg: &'a Cfg, var: &str) -> Option<&'a NodeInfo> {
    cfg.node_indices()
        .map(|i| &cfg[i])
        .find(|n| n.taint.defines.as_deref() == Some(var))
}

#[test]
fn numeric_length_access_detected_on_js_property_read() {
    // `var count = items.length`, property access on a member expression
    // should mark the CFG node as a numeric-length access so the
    // type-fact analysis infers TypeKind::Int for `count`.
    let src = br#"function f(items) {
            var count = items.length;
            return count;
        }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let node = find_node_defining(&cfg, "count").expect("defines count");
    assert!(
        node.is_numeric_length_access,
        "Expected is_numeric_length_access=true for `count = items.length`"
    );
}

#[test]
fn numeric_length_access_detected_on_js_zero_arg_method_call() {
    // `var n = str.length()`, zero-arg method call form (uncommon in JS
    // but present in other languages).  Detector should unwrap a
    // zero-arg call around a member expression.
    let src = br#"function f(list) {
            var n = list.size();
            return n;
        }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let node = find_node_defining(&cfg, "n").expect("defines n");
    assert!(
        node.is_numeric_length_access,
        "Expected is_numeric_length_access=true for `n = list.size()`"
    );
}

#[test]
fn numeric_length_access_ignores_unrelated_properties() {
    // `var v = arr.foo`, arbitrary property reads must not be flagged.
    let src = br#"function f(arr) {
            var v = arr.foo;
            return v;
        }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let node = find_node_defining(&cfg, "v").expect("defines v");
    assert!(
        !node.is_numeric_length_access,
        "is_numeric_length_access must stay false for unrelated property `arr.foo`"
    );
}

#[test]
fn numeric_length_access_ignores_method_calls_with_args() {
    // `var r = s.indexOf('x')`, the detector must reject any call with
    // positional arguments because those aren't pure length reads.
    let src = br#"function f(s) {
            var r = s.indexOf('x');
            return r;
        }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let node = find_node_defining(&cfg, "r").expect("defines r");
    assert!(
        !node.is_numeric_length_access,
        "is_numeric_length_access must stay false for arg-bearing calls"
    );
}

//── subscript lowering tests ────────────────────────

/// Scope for tests that flip `NYX_POINTER_ANALYSIS=1` so the CFG-side
/// subscript synthesis activates.  The env-var is restored afterwards
/// so the rest of the test suite stays bit-identical to the unset
/// state.  Mirrors the env-var serialisation pattern used elsewhere in
/// the test suite (see `tests/pointer_disabled_bit_identity.rs`).
use std::sync::Mutex;
static POINTER_ENV_GUARD: Mutex<()> = Mutex::new(());

fn with_pointer_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
    let _lock = POINTER_ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("NYX_POINTER_ANALYSIS").ok();
    unsafe {
        match value {
            Some(v) => std::env::set_var("NYX_POINTER_ANALYSIS", v),
            None => std::env::remove_var("NYX_POINTER_ANALYSIS"),
        }
    }
    let r = f();
    unsafe {
        match prev {
            Some(v) => std::env::set_var("NYX_POINTER_ANALYSIS", v),
            None => std::env::remove_var("NYX_POINTER_ANALYSIS"),
        }
    }
    r
}

fn with_pointer_on<R>(f: impl FnOnce() -> R) -> R {
    with_pointer_env(Some("1"), f)
}

fn count_nodes_with_callee(cfg: &Cfg, callee: &str) -> usize {
    cfg.node_indices()
        .filter(|i| cfg[*i].call.callee.as_deref() == Some(callee))
        .count()
}

fn find_node_with_callee<'a>(cfg: &'a Cfg, callee: &str) -> Option<&'a NodeInfo> {
    cfg.node_indices()
        .map(|i| &cfg[i])
        .find(|n| n.call.callee.as_deref() == Some(callee))
}

#[test]
fn js_subscript_read_lowers_to_index_get_call() {
    with_pointer_on(|| {
        // `arr[0]` as a sink call argument should be pre-emitted as a
        // synth `__index_get__` call before the consuming sink.
        let src = br#"function f(arr) {
            sink(arr[0]);
        }"#;
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
        let node = find_node_with_callee(&cfg, "__index_get__")
            .expect("__index_get__ node should be present");
        assert_eq!(node.call.receiver.as_deref(), Some("arr"));
        assert_eq!(node.call.arg_uses.len(), 1, "expect one arg group (index)");
        assert_eq!(node.call.arg_uses[0], vec!["0"]);
        assert!(
            node.taint
                .defines
                .as_deref()
                .is_some_and(|d| d.starts_with("__nyx_idxget_")),
            "synth defines should use the __nyx_idxget_ prefix"
        );
    });
}

#[test]
fn js_subscript_write_lowers_to_index_set_call() {
    with_pointer_on(|| {
        let src = br#"function f(arr, v) {
            arr[0] = v;
        }"#;
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
        let node = find_node_with_callee(&cfg, "__index_set__")
            .expect("__index_set__ node should be present");
        assert_eq!(node.call.receiver.as_deref(), Some("arr"));
        assert_eq!(
            node.call.arg_uses.len(),
            2,
            "expect arg_uses [[idx], [val]]"
        );
        assert_eq!(node.call.arg_uses[0], vec!["0"]);
        assert_eq!(node.call.arg_uses[1], vec!["v"]);
    });
}

#[test]
fn py_subscript_read_lowers_to_index_get_call() {
    with_pointer_on(|| {
        let src = br#"def f(arr):
    sink(arr[0])
"#;
        let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "python", ts_lang);
        let node = find_node_with_callee(&cfg, "__index_get__")
            .expect("python: __index_get__ node should be present");
        assert_eq!(node.call.receiver.as_deref(), Some("arr"));
    });
}

#[test]
fn py_subscript_write_lowers_to_index_set_call() {
    with_pointer_on(|| {
        let src = br#"def f(arr, v):
    arr[0] = v
"#;
        let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "python", ts_lang);
        let node = find_node_with_callee(&cfg, "__index_set__")
            .expect("python: __index_set__ node should be present");
        assert_eq!(node.call.receiver.as_deref(), Some("arr"));
        assert_eq!(node.call.arg_uses.len(), 2);
        assert_eq!(node.call.arg_uses[1], vec!["v"]);
    });
}

#[test]
fn go_selector_expression_call_sets_receiver() {
    // Regression for Phase 15 deferred GORM tuple-return case.
    // Go's `userDb.Raw(sql)` parses as `call_expression` whose `function`
    // field is a `selector_expression` (operand=userDb, field=Raw).
    // The CFG-side `Kind::CallFn` arm must extract `userDb` as the
    // receiver so type-qualified resolution can rewrite `userDb.Raw` →
    // `GormDb.Raw` once `userDb`'s SSA value is tagged via
    // `constructor_type(Lang::Go, "gorm.Open")`.  Pre-fix the arm only
    // recognised JS/TS `member_expression`, Python `attribute`, and Rust
    // `field_expression`; Go fell through to receiver=None.
    let src = br#"package main
func f(userDb int) {
    userDb.Raw("SELECT 1")
}
"#;
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "go", ts_lang);
    let node =
        find_node_with_callee(&cfg, "userDb.Raw").expect("go: userDb.Raw node should be present");
    assert_eq!(node.call.receiver.as_deref(), Some("userDb"));
}

#[test]
fn go_multi_target_assign_binds_first_ident_as_primary_define() {
    // `f, err = os.Open(p)` — a bare multi-target `=` assignment whose LHS is
    // Go's `expression_list` (not a recognised destructure pattern).  The
    // primary `defines` must be the FIRST target `f` (the acquired resource
    // handle), with the trailing `err` recorded as an `extra_define` — never
    // dropped and never made primary.  Before the fix `def_use`'s Assignment
    // arm used `idents.pop()` (the LAST ident) so `err` became the primary
    // define: the resource-lifecycle transfer then bound the file handle to
    // Go's trailing `error` return (never closeable) and every
    // `handle, err = open()` reported a false resource-leak on `err` while the
    // real handle went untracked.  Distilled from hugo
    // internal/js/esbuild/build.go:139 (`contentr, err = hugofs.Os.Open(...)`).
    let src = br#"package main
import "os"
func run(p string) error {
    var (
        f   *os.File
        err error
    )
    f, err = os.Open(p)
    _ = f
    return err
}
"#;
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "go", ts_lang);
    let node = find_node_with_callee(&cfg, "os.Open").expect("go: os.Open node should be present");
    assert_eq!(
        node.taint.defines.as_deref(),
        Some("f"),
        "resource handle `f` (first LHS target) must be the primary define, not the trailing `err`"
    );
    assert!(
        node.taint.extra_defines.contains(&"err".to_string()),
        "trailing `err` must be recorded as an extra define, not dropped: {:?}",
        node.taint.extra_defines
    );
}

#[test]
fn go_index_expr_read_lowers_to_index_get_call() {
    with_pointer_on(|| {
        let src = br#"package main
func f(arr []string) {
    sink(arr[0])
}
"#;
        let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "go", ts_lang);
        let node = find_node_with_callee(&cfg, "__index_get__")
            .expect("go: __index_get__ node should be present");
        assert_eq!(node.call.receiver.as_deref(), Some("arr"));
    });
}

#[test]
fn go_index_expr_write_lowers_to_index_set_call() {
    with_pointer_on(|| {
        let src = br#"package main
func f(m map[string]int, k string, v int) {
    m[k] = v
}
"#;
        let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "go", ts_lang);
        let node = find_node_with_callee(&cfg, "__index_set__")
            .expect("go: __index_set__ node should be present");
        assert_eq!(node.call.receiver.as_deref(), Some("m"));
        assert_eq!(node.call.arg_uses.len(), 2);
        assert_eq!(node.call.arg_uses[0], vec!["k"]);
        assert_eq!(node.call.arg_uses[1], vec!["v"]);
    });
}

#[test]
fn pointer_disabled_skips_subscript_synthesis() {
    // Strict-additive contract: when NYX_POINTER_ANALYSIS=0 the CFG
    // must contain zero __index_get__/__index_set__ nodes regardless
    // of the source shape.  This is the off-by-default invariant the
    // bit-identity gate relies on.
    with_pointer_env(Some("0"), || {
        let src = br#"function f(arr, v) {
            sink(arr[0]);
            arr[1] = v;
        }"#;
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
        assert_eq!(count_nodes_with_callee(&cfg, "__index_get__"), 0);
        assert_eq!(count_nodes_with_callee(&cfg, "__index_set__"), 0);
    });
}

//   Gap-filling: switch / for / do-while / nested loops / re-throw

/// JS `switch` should produce one synthetic dispatch `If` node per
/// case (default excluded when at the tail), plus True edges into
/// each case body. Verifies the discriminant cascade is wired.
#[test]
fn js_switch_cascade_has_one_if_per_case() {
    let src = br#"function f(x) {
        switch (x) {
            case 1: a(); break;
            case 2: b(); break;
            default: c();
        }
    }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    // Two non-default cases => 2 dispatch If nodes (the tail default
    // is wired via the previous header's False edge, not its own If).
    assert_eq!(
        if_nodes(&cfg).len(),
        2,
        "switch with 2 explicit cases + default should emit 2 dispatch If nodes"
    );

    // Each dispatch If must have at least one True and one False edge
    // (True → case body, False → next case / default).
    for i in if_nodes(&cfg) {
        let trues = cfg
            .edges(i)
            .filter(|e| matches!(e.weight(), EdgeKind::True))
            .count();
        let falses = cfg
            .edges(i)
            .filter(|e| matches!(e.weight(), EdgeKind::False))
            .count();
        assert!(
            trues >= 1,
            "case dispatch should have at least one True edge"
        );
        assert!(
            falses >= 1,
            "case dispatch should have at least one False edge"
        );
    }
}

/// Default case in the *middle* of a switch must be reordered to the
/// tail so the dispatch cascade stays a clean True/False chain. The
/// observable CFG shape (number of If nodes, presence of True/False
/// edges per dispatch) should match the all-default-at-tail case.
#[test]
fn js_switch_default_in_middle_reorders_to_tail() {
    let src = br#"function f(x) {
        switch (x) {
            case 1: a(); break;
            default: c(); break;
            case 2: b(); break;
        }
    }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    // 2 non-default cases ⇒ 2 If dispatch nodes (default reordered to tail).
    assert_eq!(
        if_nodes(&cfg).len(),
        2,
        "default-in-middle should still produce one If per non-default case"
    );
}

/// JS switch fall-through (`case 1: a(); case 2: b();`), case 1's
/// exit should flow into case 2's body so taint from `first()`
/// reaches `second()`'s sinks.
///
/// We assert two things:
///   (a) Reachability: `second()` is reachable from `first()` over
///       forward edges. This is the semantic property taint analysis
///       depends on; checking it directly avoids over-fitting to the
///       structural shape.
///   (b) `first()` has a non-Back forward out-edge that lands inside
///       the case-2 sub-graph (the actual fall-through wire), so we
///       prove there *is* a fall-through edge, not just an
///       Entry→…→Exit path that happens to walk through both calls
///       via the dispatch chain.
///
/// Note on the structural shape: case bodies are wrapped in synthetic
/// Seq passthrough nodes (one per surrounding scope), so the
/// fall-through edge from `first()` lands on the *first wrapper
/// Seq node* of case 2, not on `second()` itself. Asserting that
/// `second()` has ≥2 in-edges would therefore be wrong, the True
/// edge from the case-2 dispatch If targets the wrapper node, and
/// only a single Seq chain leads from there to `second()`.
#[test]
fn js_switch_fallthrough_no_break() {
    use std::collections::HashSet;
    let src = br#"function f(x) {
        switch (x) {
            case 1: first();
            case 2: second(); break;
        }
    }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let first = cfg
        .node_indices()
        .find(|&n| cfg[n].call.callee.as_deref() == Some("first"))
        .expect("expected a Call node for `first`");
    let second = cfg
        .node_indices()
        .find(|&n| cfg[n].call.callee.as_deref() == Some("second"))
        .expect("expected a Call node for `second`");

    // (a) Reachability from first → second over forward (non-Back) edges.
    let mut seen: HashSet<NodeIndex> = HashSet::new();
    let mut stack = vec![first];
    while let Some(n) = stack.pop() {
        if !seen.insert(n) {
            continue;
        }
        for e in cfg.edges(n) {
            if matches!(e.weight(), EdgeKind::Seq | EdgeKind::True | EdgeKind::False) {
                stack.push(e.target());
            }
        }
    }
    assert!(
        seen.contains(&second),
        "fall-through: `second` must be reachable from `first` over forward edges"
    );

    // (b) Prove the fall-through edge exists: `first()` must have at
    //     least one outgoing forward edge whose target is *not*
    //     reachable from the function entry without first going
    //     through `first()`. The straightforward check: `first()`
    //     itself must have at least one outgoing Seq edge (the
    //     fall-through wire is always Seq).
    let first_seq_outs = cfg
        .edges(first)
        .filter(|e| matches!(e.weight(), EdgeKind::Seq))
        .count();
    assert!(
        first_seq_outs >= 1,
        "fall-through: `first()` must have a Seq out-edge (the fall-through wire)"
    );
}

/// `for (i = 0; i < 10; i++) { body(); }` should produce a Loop node
/// with at least one Back edge from the body back to the loop header.
#[test]
fn js_for_loop_has_back_edge() {
    let src = br#"function f() { for (let i = 0; i < 10; i++) { body(); } }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let loop_nodes: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .collect();
    assert_eq!(loop_nodes.len(), 1, "expected exactly one Loop node");

    let back_edges = cfg
        .edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Back))
        .count();
    assert!(
        back_edges >= 1,
        "for loop must have at least one Back edge to its header"
    );
}

/// `do { ... } while (cond);` is mapped to `Kind::While` for many
/// languages but the grammar puts the body *before* the condition.
/// The CFG must still produce a Loop node and at least one Back edge.
#[test]
fn js_do_while_has_loop_node_and_back_edge() {
    let src = br#"function f() { do { body(); } while (cond); }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let loop_count = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .count();
    assert_eq!(loop_count, 1, "do-while should produce one Loop node");
    assert!(
        cfg.edge_references()
            .any(|e| matches!(e.weight(), EdgeKind::Back)),
        "do-while must have at least one Back edge"
    );
}

/// In `outer: while (a) { while (b) { break; } }`, the `break`
/// terminates only the *inner* loop. Equivalent for our CFG: the
/// break's predecessors should reach the inner loop's exit frontier
/// without crossing the outer loop's body again. We can verify this
/// structurally: there must be exactly two Loop nodes and at least
/// one Break node whose forward (Seq) successor is *not* the outer
/// header.
#[test]
fn js_nested_while_break_targets_inner_loop() {
    let src = br#"function f() {
        while (a) {
            while (b) { break; }
            inner_after();
        }
    }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let loops: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .collect();
    assert_eq!(loops.len(), 2, "expected two Loop nodes");

    let breaks: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Break)
        .collect();
    assert_eq!(breaks.len(), 1, "expected exactly one Break node");

    // The inner loop body's break should NOT close back via Back edge
    // onto the outer header (outer header is loops[0] in source order).
    let outer_header = loops[0];
    let brk = breaks[0];
    let crosses_outer = cfg
        .edges(brk)
        .any(|e| e.target() == outer_header && matches!(e.weight(), EdgeKind::Back));
    assert!(
        !crosses_outer,
        "inner break must not back-edge onto the outer loop header"
    );
}

/// `continue` in the inner loop must back-edge onto the *inner*
/// header, not the outer. With nested while loops we expect exactly
/// one Continue node and at least one Back edge originating at it
/// going to the inner (second-emitted) Loop header.
#[test]
fn js_nested_while_continue_targets_inner_loop() {
    let src = br#"function f() {
        while (a) {
            while (b) { continue; }
        }
    }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let loops: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .collect();
    assert_eq!(loops.len(), 2, "expected two Loop nodes");
    let outer_header = loops[0];
    let inner_header = loops[1];

    let cont = cfg
        .node_indices()
        .find(|&n| cfg[n].kind == StmtKind::Continue)
        .expect("expected Continue node");

    let back_edges_from_cont: Vec<_> = cfg
        .edges(cont)
        .filter(|e| matches!(e.weight(), EdgeKind::Back))
        .collect();
    assert!(
        !back_edges_from_cont.is_empty(),
        "continue must originate at least one Back edge"
    );
    assert!(
        back_edges_from_cont
            .iter()
            .any(|e| e.target() == inner_header),
        "continue's Back edge must target the inner loop header"
    );
    assert!(
        !back_edges_from_cont
            .iter()
            .any(|e| e.target() == outer_header),
        "continue must not back-edge onto the outer loop header"
    );
}

/// `throw` inside a `catch` block should still register a throw
/// target so a surrounding outer try (or function-level exit) can
/// receive it. We verify here that the throw produces a Throw node
/// even when it is reached only via an Exception edge from the inner
/// try body (i.e. the re-throw path is preserved structurally).
#[test]
fn js_throw_inside_catch_emits_throw_node() {
    let src = br#"function f() {
        try {
            try { foo(); } catch (e) { throw e; }
        } catch (e2) {
            handle();
        }
    }"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let throws: Vec<_> = cfg
        .node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Throw)
        .collect();
    assert_eq!(
        throws.len(),
        1,
        "expected exactly one Throw node for the inner re-throw"
    );

    // The outer `catch (e2)` body must be reachable. Check that the
    // `handle()` call exists and has at least one incoming edge.
    let handle = cfg
        .node_indices()
        .find(|&n| cfg[n].call.callee.as_deref() == Some("handle"))
        .expect("expected `handle()` call node");
    let in_edges = cfg
        .edges_directed(handle, petgraph::Direction::Incoming)
        .count();
    assert!(in_edges >= 1, "outer catch body must be reachable");
}

/// Empty if/else branches (e.g., `if (a) {} else {}`) must not panic
/// and the resulting CFG must still have a single If node with both
/// True and False edges going somewhere reachable. This guards
/// against off-by-one bugs in `then_first_node`/exits handling.
#[test]
fn js_if_with_empty_branches_does_not_panic() {
    let src = b"function f() { if (a) {} else {} return; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let ifs = if_nodes(&cfg);
    assert_eq!(ifs.len(), 1, "expected one If node");
    let i = ifs[0];

    let trues: Vec<_> = cfg
        .edges(i)
        .filter(|e| matches!(e.weight(), EdgeKind::True))
        .collect();
    let falses: Vec<_> = cfg
        .edges(i)
        .filter(|e| matches!(e.weight(), EdgeKind::False))
        .collect();
    assert!(!trues.is_empty(), "empty-then If must still emit True edge");
    assert!(
        !falses.is_empty(),
        "empty-else If must still emit False edge"
    );
}

/// A function body with no statements should still produce a
/// well-formed CFG (entry/exit only); no panic, no orphan nodes from
/// `build_sub` returning an empty exit set.
#[test]
fn js_empty_function_body_well_formed() {
    let src = b"function f() {}";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    // We expect 2 bodies: top-level + the function body. Both must be
    // valid graphs with at least an entry node.
    assert!(
        file_cfg.bodies.len() >= 2,
        "expected at least 2 bodies (top-level + function)"
    );
    for body in &file_cfg.bodies {
        assert!(
            body.graph.node_count() >= 1,
            "every body must have at least one node"
        );
    }
}

//  Loop CFG structure: every loop variant must produce a Loop header
//  with at least one Back edge that targets that header. Without these
//  invariants the SSA loop-induction-variable phi placement is wrong
//  and the abstract-interp widening points are missed.

fn loop_headers(cfg: &Cfg) -> Vec<NodeIndex> {
    cfg.node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Loop)
        .collect()
}

fn back_edges(cfg: &Cfg) -> Vec<(NodeIndex, NodeIndex)> {
    cfg.edge_references()
        .filter(|e| matches!(e.weight(), EdgeKind::Back))
        .map(|e| (e.source(), e.target()))
        .collect()
}

fn assert_loop_with_back_edge(cfg: &Cfg, label: &str) {
    let headers = loop_headers(cfg);
    assert!(
        !headers.is_empty(),
        "{label}: expected at least one Loop header, found none"
    );
    let backs = back_edges(cfg);
    assert!(
        !backs.is_empty(),
        "{label}: expected at least one Back edge"
    );
    for (_, dst) in &backs {
        assert!(
            headers.contains(dst),
            "{label}: Back edge target {:?} is not a Loop header (headers={:?})",
            dst,
            headers
        );
    }
}

#[test]
fn js_for_loop_back_edge() {
    let src = b"function f() { for (let i = 0; i < 10; i++) { body(i); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    assert_loop_with_back_edge(&cfg, "js classic for");
}

#[test]
fn js_do_while_back_edge() {
    let src = b"function f() { do { body(); } while (cond()); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    assert_loop_with_back_edge(&cfg, "js do-while");
}

#[test]
fn js_for_in_back_edge() {
    let src = b"function f() { for (let k in obj) { use(k); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    assert_loop_with_back_edge(&cfg, "js for-in");
}

#[test]
fn js_for_of_back_edge() {
    let src = b"function f() { for (const x of items) { use(x); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    // for-of is usually classified the same as for-in / for via
    // for_in_statement. Still, body-with-back-edge invariant must hold.
    assert_loop_with_back_edge(&cfg, "js for-of");
}

#[test]
fn python_for_loop_back_edge() {
    let src = b"def f():\n    for x in items:\n        use(x)\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "python", ts_lang);
    assert_loop_with_back_edge(&cfg, "python for");
}

#[test]
fn python_while_loop_back_edge() {
    let src = b"def f():\n    while cond():\n        use(x)\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "python", ts_lang);
    assert_loop_with_back_edge(&cfg, "python while");
}

#[test]
fn java_enhanced_for_back_edge() {
    let src = b"class A { void f(int[] xs) { for (int x : xs) { use(x); } } }";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "java", ts_lang);
    assert_loop_with_back_edge(&cfg, "java enhanced-for");
}

#[test]
fn java_do_while_back_edge() {
    let src = b"class A { void f() { do { body(); } while (cond()); } }";
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "java", ts_lang);
    assert_loop_with_back_edge(&cfg, "java do-while");
}

#[test]
fn cpp_range_for_back_edge() {
    let src = b"void f(int* xs) { for (int x : range) { use(x); } }";
    let ts_lang = Language::from(tree_sitter_cpp::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "cpp", ts_lang);
    assert_loop_with_back_edge(&cfg, "cpp range-for");
}

#[test]
fn c_do_while_back_edge() {
    let src = b"void f() { do { body(); } while (cond()); }";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "c", ts_lang);
    assert_loop_with_back_edge(&cfg, "c do-while");
}

#[test]
fn go_for_loop_back_edge() {
    let src = b"package p\nfunc f() { for i := 0; i < 10; i++ { body(i) } }";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "go", ts_lang);
    assert_loop_with_back_edge(&cfg, "go for");
}

/// Pins the structural fix in `def_use` Kind::For arm for Go's
/// `for ident, ident := range iter` shape.  Tree-sitter wraps the binding
/// pattern + iterable in a `range_clause` child of the `for_statement`
/// (rather than direct `left`/`right` fields like Python / JS).  Without
/// this, the loop binding never becomes a CFG def and taint from the
/// iterable cannot reach uses of the binding inside the loop body.
/// Original gap: CVE-2026-41422 (daptin) goqu.L SQL injection.
#[test]
fn go_for_range_loop_binding_is_defined() {
    let src = b"package p\nfunc f(xs []string) { for _, p := range xs { use(p) } }";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "go", ts_lang);

    let loop_node = cfg
        .node_indices()
        .find(|&n| matches!(cfg[n].kind, StmtKind::Loop))
        .expect("for-range loop should produce a Loop header");
    let info = &cfg[loop_node];
    let all_defs: Vec<&str> = info
        .taint
        .defines
        .iter()
        .map(String::as_str)
        .chain(info.taint.extra_defines.iter().map(String::as_str))
        .collect();
    assert!(
        all_defs.contains(&"p"),
        "loop binding `p` should appear in defines/extra_defines, got {:?}",
        all_defs
    );
    assert!(
        info.taint.uses.iter().any(|u| u == "xs"),
        "iterable `xs` should appear in uses, got {:?}",
        info.taint.uses
    );
}

#[test]
fn ruby_while_back_edge() {
    let src = b"def f\n  while cond\n    body\n  end\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "ruby", ts_lang);
    assert_loop_with_back_edge(&cfg, "ruby while");
}

#[test]
fn ruby_until_back_edge() {
    // `until cond` is `while not cond`; should still produce a loop.
    let src = b"def f\n  until done\n    body\n  end\nend\n";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "ruby", ts_lang);
    assert_loop_with_back_edge(&cfg, "ruby until");
}

#[test]
fn php_foreach_back_edge() {
    let src = b"<?php function f($items) { foreach ($items as $x) { use($x); } }";
    let ts_lang = Language::from(tree_sitter_php::LANGUAGE_PHP);
    let (cfg, _) = parse_and_build(src, "php", ts_lang);
    assert_loop_with_back_edge(&cfg, "php foreach");
}

#[test]
fn rust_for_loop_back_edge() {
    let src = b"fn f() { for x in 0..10 { use_fn(x); } }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "rust", ts_lang);
    assert_loop_with_back_edge(&cfg, "rust for");
}

#[test]
fn rust_while_loop_back_edge() {
    let src = b"fn f() { while cond() { body(); } }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "rust", ts_lang);
    assert_loop_with_back_edge(&cfg, "rust while");
}

#[test]
fn nested_loops_two_headers_two_back_edges() {
    // Nested loops must produce two distinct loop headers and a back
    // edge for each. This guards against headers being collapsed and
    // back edges being mis-routed to the outer header.
    let src = b"function f() { for (let i = 0; i < 10; i++) { for (let j = 0; j < 10; j++) { use(i, j); } } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let headers = loop_headers(&cfg);
    assert_eq!(headers.len(), 2, "expected 2 loop headers in nested loops");
    let backs = back_edges(&cfg);
    assert!(
        backs.len() >= 2,
        "expected ≥2 back edges in nested loops, got {}",
        backs.len()
    );
    // Every back edge must target one of the two headers.
    for (_, dst) in &backs {
        assert!(headers.contains(dst), "back edge target not a loop header");
    }
    // Each header should be the target of at least one back edge.
    let mut hit = std::collections::HashSet::new();
    for (_, dst) in &backs {
        hit.insert(*dst);
    }
    assert_eq!(
        hit.len(),
        2,
        "each header must receive at least one back edge"
    );
}

#[test]
fn loop_with_break_no_back_edge_from_break() {
    // A `break` short-circuits the loop body, its edge must NOT be a
    // back edge to the header (it leaves the loop entirely).
    let src = b"function f() { while (cond()) { if (done()) break; body(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let headers = loop_headers(&cfg);
    assert_eq!(headers.len(), 1, "expected 1 loop header");
    let header = headers[0];

    // Find any Break node and verify none of its outgoing edges are
    // Back edges to the header.
    for n in cfg.node_indices() {
        if cfg[n].kind != StmtKind::Break {
            continue;
        }
        for e in cfg.edges(n) {
            assert!(
                !(matches!(e.weight(), EdgeKind::Back) && e.target() == header),
                "break must not produce a back edge to the loop header"
            );
        }
    }
}

#[test]
fn loop_with_continue_back_edge_to_header() {
    // `continue` must produce a Back edge to the loop header.
    let src = b"function f() { while (cond()) { if (skip()) continue; body(); } }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let headers = loop_headers(&cfg);
    assert_eq!(headers.len(), 1);
    let header = headers[0];

    let mut found = false;
    for n in cfg.node_indices() {
        if cfg[n].kind != StmtKind::Continue {
            continue;
        }
        for e in cfg.edges(n) {
            if matches!(e.weight(), EdgeKind::Back) && e.target() == header {
                found = true;
            }
        }
    }
    assert!(
        found,
        "expected at least one Back edge from a Continue node to the loop header"
    );
}

/// Regression guard for the 2026-04-27 chained-method-call inner-gate
/// rebinding (CVE-2025-64430 hunt session).  Without the fix, the outer
/// `.on('error', cb)` call swallows classification of the inner
/// `http.get(uri, cb)` so neither the gate label nor `sink_payload_args`
/// are populated for this CFG node.
#[test]
fn chained_method_call_rebinds_to_inner_gated_sink() {
    // Use `https.get` (a gated SSRF sink) so the gate fires only when
    // the inner-call rebinding works.  The outer `.on(...)` is a plain
    // method call that does not classify on its own.
    let src = b"function f(uri) { https.get(uri, r => {}).on('error', e => {}); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);

    // Find a Call node whose `text` was rebound to the inner gated callee.
    let mut found = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.kind != StmtKind::Call {
            continue;
        }
        let Some(callee) = info.call.callee.as_deref() else {
            continue;
        };
        // The inner callee is `https.get`; the outer chained `.on` should
        // no longer be the recorded callee for this node.
        if callee.ends_with("https.get") {
            // The inner-gate path must have populated sink_payload_args
            // (the gate's payload arg is position 0, the URL string).
            assert!(
                info.call.sink_payload_args.is_some(),
                "expected sink_payload_args to be populated for chained \
                 inner-gate https.get; got None on call node with callee {callee:?}"
            );
            found = true;
            break;
        }
    }
    assert!(
        found,
        "expected at least one Call node whose callee was rebound from \
         the outer `.on(...)` to the inner `https.get` after the chained- \
         call inner-gate rebinding fired"
    );
}

/// Regression guard for RUSTSEC-2022-0072 (hyper-staticfile open redirect).
/// The gated `header` Location sink sits in the MIDDLE of a builder chain
/// (`new().status(..).header(LOCATION, target).body(..)`).  The original
/// `find_chained_inner_call` descended to the structurally-innermost
/// `.status(..)` call, so the rebind dispatch saw no gate and the
/// open-redirect flow was lost.  `find_chained_gated_sink_call` selects the
/// chain level by GATE MATCH, so the chained node rebinds to `.header` and
/// the Location gate populates `sink_payload_args` (payload arg position 1).
#[test]
fn chained_builder_rebinds_to_middle_gated_location_sink() {
    let src =
        b"fn f(target: String) { B::new().status(301).header(\"Location\", target).body(e); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "rust", ts_lang);

    let mut found = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.kind != StmtKind::Call {
            continue;
        }
        let Some(callee) = info.call.callee.as_deref() else {
            continue;
        };
        if callee.contains("header") && info.call.sink_payload_args.is_some() {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "expected the builder chain to rebind to the middle `.header` gated \
         Location sink and populate sink_payload_args"
    );
}

/// Ternary-RHS branches are lowered into a diamond CFG by
/// `build_ternary_diamond` so the condition is control-flow and the
/// branches are data-flow that joins at a phi.  But push_node only does
/// suffix/prefix matching on the branch text, so a source-shaped member
/// expression like `req.query.lng` does not classify (the rule matcher
/// is `req.query`, which neither suffix-matches nor prefix-matches
/// `req.query.lng`).  `lower_ternary_branch` runs the segment-strip-
/// and-retry classifier on the branch AST to recover the source label,
/// mirroring what `pre_emit_arg_source_nodes` does for call arguments.
///
/// Without this, `let arr = cond ? req.query.lng : "";` lowers each
/// branch to a labelless Assign-with-empty-uses, the join phi sees no
/// taint, and downstream sinks miss the flow.  Motivated by the
/// i18next-http-middleware advisory GHSA-jfgf-83c5-2c4m / CVE-2026-42353.
#[test]
fn js_ternary_branch_member_expression_classified_as_source() {
    let src = b"function h(req) { const arr = req.query.lng ? req.query.lng : ''; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let mut found_source_branch = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("arr")
            && info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
        {
            found_source_branch = true;
            break;
        }
    }
    assert!(
        found_source_branch,
        "expected at least one ternary branch defining `arr` to carry a \
         Source label after segment-strip classification of `req.query.lng`"
    );
}

#[test]
fn js_ternary_branch_const_strings_have_no_source() {
    // Both branches are constant strings -> no Source label should be
    // synthesised by the segment-strip pass.  Pins precision: the fix
    // only fires when first_member_label finds a real source-shaped
    // expression in the branch AST.
    let src = b"function h(cond) { const x = cond ? 'a' : 'b'; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("x") {
            assert!(
                !info
                    .taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, crate::labels::DataLabel::Source(_))),
                "constant-string ternary branch must not carry a Source label; \
                 got labels = {:?}",
                info.taint.labels
            );
        }
    }
}

#[test]
fn js_ternary_branch_subscript_source_classified() {
    // Subscript-form sources (`req.body['key']`) reach via the
    // first_member_label subscript-expression arm.  Pins the same fix
    // for subscript-shaped source branches.
    let src = b"function h(req) { const x = req.body ? req.body['k'] : ''; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let mut found_source_branch = false;
    for n in cfg.node_indices() {
        let info = &cfg[n];
        if info.taint.defines.as_deref() == Some("x")
            && info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
        {
            found_source_branch = true;
            break;
        }
    }
    assert!(
        found_source_branch,
        "expected ternary subscript branch defining `x` to carry a Source label"
    );
}

/// `extract_arg_string_literals` must capture an interpolation-free JS/TS
/// template literal (backtick) as a constant string, and return `None` for a
/// template with `${...}` interpolation.  This is what lets the raw-SQL
/// payload-const suppression recognise `sequelize.query(`…const DDL…`, opts)`.
#[test]
fn extract_arg_string_literals_handles_template_literals() {
    fn first_call<'a>(n: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        if n.kind() == "call_expression" {
            return Some(n);
        }
        let mut w = n.walk();
        for c in n.children(&mut w) {
            if let Some(f) = first_call(c) {
                return Some(f);
            }
        }
        None
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .unwrap();

    // No-interpolation template → captured as a literal.
    let src_const = b"q(`SELECT * FROM t`, opts);";
    let tree = parser.parse(src_const.as_ref(), None).unwrap();
    let call = first_call(tree.root_node()).unwrap();
    let lits = extract_arg_string_literals(call, src_const);
    assert_eq!(lits.len(), 2, "two positional args");
    assert!(
        lits[0].is_some(),
        "no-interpolation template literal (arg 0) must be captured, got {lits:?}"
    );
    assert!(
        lits[1].is_none(),
        "the `opts` identifier (arg 1) is not a literal, got {lits:?}"
    );

    // Interpolated template → NOT a constant.
    let src_interp = b"q(`SELECT ${name}`, opts);";
    let tree = parser.parse(src_interp.as_ref(), None).unwrap();
    let call = first_call(tree.root_node()).unwrap();
    let lits = extract_arg_string_literals(call, src_interp);
    assert!(
        lits[0].is_none(),
        "an interpolated template literal must NOT be captured as constant, got {lits:?}"
    );
}

/// Regression: Go's `switch` with no `default` arm and an only-case body
/// that returns must keep post-switch statements reachable from entry.
///
/// `expression_case` / `default_case` / `type_case` / `communication_case`
/// all map to `Kind::Block` so the case body is iterated by the Block
/// handler, but `build_switch`'s container fallback ("first Block child")
/// would latch onto the FIRST case as the container.  Walking the case's
/// interior for case-like children finds nothing, the empty-cases early
/// return fires, and the dispatch If has no False edge: every post-switch
/// statement becomes unreachable, lighting up `cfg-unreachable-sanitizer`
/// on real code (gin's `binding/form_mapping.go::setTimeField`, line 469
/// `if isUTC, _ := strconv.ParseBool(...); isUTC` after a no-default
/// `switch tf := strings.ToLower(timeFormat); tf` on the unix epoch
/// formats).
#[test]
fn go_switch_no_default_keeps_post_switch_reachable() {
    use petgraph::visit::Bfs;
    use std::collections::HashSet;
    let src = br#"package p
func f(x string) bool {
    switch tf := x; tf {
    case "unix":
        return false
    }
    after()
    return true
}
"#;
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, entry) = parse_and_build(src, "go", ts_lang);

    let mut reachable: HashSet<NodeIndex> = HashSet::new();
    let mut bfs = Bfs::new(&cfg, entry);
    while let Some(n) = bfs.next(&cfg) {
        reachable.insert(n);
    }

    let after = cfg
        .node_indices()
        .find(|&n| cfg[n].call.callee.as_deref() == Some("after"))
        .expect("expected after() Call node");
    assert!(
        reachable.contains(&after),
        "post-switch `after()` must be reachable from entry; got reachable={:?}",
        reachable
    );
}

/// `qs = User.objects` at module/function level lowers as a Python
/// `expression_statement` wrapping an `assignment`.  The CFG-level
/// `member_field` detector must unwrap the wrapper and pick up
/// `Some("objects")` from the inner RHS so the type-fact pass can tag
/// the bound value as `DjangoQuerySet`.
#[test]
fn python_member_field_assignment_detected_for_bare_objects() {
    let src = b"def view(req):\n    qs = User.objects\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "python", ts_lang);
    let detected: Vec<Option<String>> = cfg
        .node_indices()
        .filter_map(|n| {
            let info = &cfg[n];
            if info.taint.defines.as_deref() == Some("qs") {
                Some(info.member_field.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(
        detected.iter().any(|m| m.as_deref() == Some("objects")),
        "expected at least one `qs = ...` CFG node with member_field=Some(\"objects\"); got {:?}",
        detected
    );
}

/// Negative shape: `qs = User.something_else` must NOT set
/// `member_field == Some("objects")`.  Guards against the unwrap
/// accidentally picking up the wrong field name.
#[test]
fn python_member_field_assignment_non_objects_does_not_match() {
    let src = b"def view(req):\n    qs = User.profile\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "python", ts_lang);
    let detected: Vec<Option<String>> = cfg
        .node_indices()
        .filter_map(|n| {
            let info = &cfg[n];
            if info.taint.defines.as_deref() == Some("qs") {
                Some(info.member_field.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(
        detected.iter().any(|m| m.as_deref() == Some("profile")),
        "expected `qs = User.profile` to detect member_field=Some(\"profile\"); got {:?}",
        detected
    );
    assert!(
        detected.iter().all(|m| m.as_deref() != Some("objects")),
        "must not falsely tag non-`objects` field; got {:?}",
        detected
    );
}

/// Phase 15 chained-shape closure: a Java local of the form
/// `Session sess = sf.openSession();` registers `(fn_start, "sess")`
/// → `TypeKind::HibernateSession` in the per-file local-receiver-types
/// map, so `find_classifiable_inner_call` can rewrite the chained
/// inner `sess.createNativeQuery(...)` to
/// `HibernateSession.createNativeQuery` when the legacy literal-
/// receiver classify misses.
#[test]
fn java_hibernate_session_open_registers_local_receiver_type() {
    let src = br#"
class Foo {
    void bar(SessionFactory sf, String sql) {
        Session sess = sf.openSession();
        sess.createNativeQuery(sql).getResultList();
    }
}
"#;
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let _ = parse_to_file_cfg(src, "java", ts_lang);
    // The TLS map is cleared at the end of `build_cfg`, but the
    // public lookup helper consults it during construction.  Re-run
    // population manually for the assertion.
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_java::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src.as_slice(), None).unwrap();
    super::populate_local_receiver_types(&tree, "java", src);
    // Walk to find the function body's start_byte.
    fn find_method_start(node: tree_sitter::Node<'_>) -> Option<usize> {
        if node.kind() == "method_declaration" {
            return Some(node.start_byte());
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            if let Some(s) = find_method_start(child) {
                return Some(s);
            }
        }
        None
    }
    let fn_start = find_method_start(tree.root_node()).expect("method_declaration in fixture");
    let got = super::lookup_local_receiver_type(fn_start, "sess");
    assert_eq!(
        got,
        Some(crate::ssa::type_facts::TypeKind::HibernateSession),
        "local `Session sess = sf.openSession()` should bind to HibernateSession"
    );
    // Cleanup so the TLS state doesn't leak into other tests.
    super::LOCAL_RECEIVER_TYPES.with(|cell| cell.borrow_mut().clear());
}

/// Same Java per-file map: a local whose RHS is unrelated (no
/// `constructor_type` match) must NOT register.  Confirms the
/// recogniser is anchored on `constructor_type`'s callee classifier
/// rather than the declared receiver type, so a generic
/// `Session foo = computeFoo()` doesn't bleed an unrelated method
/// into the type-qualified pool.
#[test]
fn java_unrecognised_rhs_does_not_register_local_receiver_type() {
    let src = br#"
class Foo {
    void bar() {
        Session sess = computeSomethingUnrelated();
        sess.doSomething();
    }
}
"#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&Language::from(tree_sitter_java::LANGUAGE))
        .unwrap();
    let tree = parser.parse(src.as_slice(), None).unwrap();
    super::populate_local_receiver_types(&tree, "java", src);
    fn find_method_start(node: tree_sitter::Node<'_>) -> Option<usize> {
        if node.kind() == "method_declaration" {
            return Some(node.start_byte());
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            if let Some(s) = find_method_start(child) {
                return Some(s);
            }
        }
        None
    }
    let fn_start = find_method_start(tree.root_node()).expect("method_declaration in fixture");
    let got = super::lookup_local_receiver_type(fn_start, "sess");
    assert_eq!(
        got, None,
        "unrecognised RHS `computeSomethingUnrelated()` must not register a receiver-type"
    );
    super::LOCAL_RECEIVER_TYPES.with(|cell| cell.borrow_mut().clear());
}

/// `collect_array_pattern_bindings_indexed` walks JS/TS `array_pattern`
/// children in source order and records `(name, position)` for each
/// simple-identifier binding. Skip slots (commas with no binding
/// between) advance the position counter without emitting a binding,
/// so `const [, b]` produces `[("b", 1)]` and `const [a, ,]` produces
/// `[("a", 0)]`. Complex sub-patterns (`assignment_pattern`,
/// `rest_pattern`, nested `array_pattern`) cause the helper to return
/// an empty vec so the lowering rewrite falls back to scalar union.
#[test]
fn array_pattern_indexed_bindings_recognise_skip_slots() {
    use super::helpers::collect_array_pattern_bindings_indexed;
    fn first_array_pattern<'t>(n: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        if n.kind() == "array_pattern" {
            return Some(n);
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            if let Some(found) = first_array_pattern(child) {
                return Some(found);
            }
        }
        None
    }
    fn parse_first(src: &[u8]) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_javascript::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        (tree, src.to_vec())
    }
    fn run_case(src: &[u8]) -> Vec<(String, usize)> {
        let (tree, bytes) = parse_first(src);
        let pat = first_array_pattern(tree.root_node()).expect("array_pattern in fixture");
        collect_array_pattern_bindings_indexed(pat, &bytes)
            .into_iter()
            .collect()
    }
    assert_eq!(
        run_case(b"const [a, b] = x;"),
        vec![("a".into(), 0), ("b".into(), 1)],
    );
    assert_eq!(run_case(b"const [, b] = x;"), vec![("b".into(), 1)]);
    assert_eq!(run_case(b"const [a, ,] = x;"), vec![("a".into(), 0)]);
    assert_eq!(
        run_case(b"const [a, , c] = x;"),
        vec![("a".into(), 0), ("c".into(), 2)],
    );
    // Rest patterns bail to empty so callers fall back to scalar union.
    assert!(run_case(b"const [a, ...rest] = x;").is_empty());
    // Default value patterns also bail.
    assert!(run_case(b"const [a = 1, b] = x;").is_empty());
    // Nested array patterns bail.
    assert!(run_case(b"const [[a, b], c] = x;").is_empty());
}

/// Rust `tuple_pattern` shares the helper. The `_` wildcard
/// (`_pattern` node) advances the position counter without binding,
/// mirroring JS skip-slot semantics. Other complex sub-patterns
/// (tuple-struct, parenthesized) bail to empty.
#[test]
fn tuple_pattern_indexed_bindings_recognise_rust_wildcards() {
    use super::helpers::collect_array_pattern_bindings_indexed;
    fn first_tuple_pattern<'t>(n: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        if n.kind() == "tuple_pattern" {
            return Some(n);
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            if let Some(found) = first_tuple_pattern(child) {
                return Some(found);
            }
        }
        None
    }
    fn parse_first_rust(src: &[u8]) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_rust::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        (tree, src.to_vec())
    }
    fn run_case(src: &[u8]) -> Vec<(String, usize)> {
        let (tree, bytes) = parse_first_rust(src);
        let pat = first_tuple_pattern(tree.root_node()).expect("tuple_pattern in fixture");
        collect_array_pattern_bindings_indexed(pat, &bytes)
            .into_iter()
            .collect()
    }
    assert_eq!(
        run_case(b"fn f() { let (a, b) = (1, 2); }"),
        vec![("a".into(), 0), ("b".into(), 1)],
    );
    assert_eq!(
        run_case(b"fn f() { let (_, b) = (1, 2); }"),
        vec![("b".into(), 1)],
    );
    assert_eq!(
        run_case(b"fn f() { let (a, _) = (1, 2); }"),
        vec![("a".into(), 0)],
    );
    assert_eq!(
        run_case(b"fn f() { let (a, _, c) = (1, 2, 3); }"),
        vec![("a".into(), 0), ("c".into(), 2)],
    );
}

/// Python `pattern_list` (bare `a, b = ...`) and `tuple_pattern`
/// (parenthesised `(a, b) = ...`) share the helper.  Python's `_` is
/// a normal identifier binding (not a wildcard), so every identifier
/// child emits a `(name, position)` entry — `_` lands at its source
/// position alongside any other names.  `list_splat_pattern`
/// (`a, *rest`) bails to empty so callers fall back to scalar union.
#[test]
fn pattern_list_indexed_bindings_recognise_python_destructure() {
    use super::helpers::collect_array_pattern_bindings_indexed;
    fn first_pattern<'t>(
        n: tree_sitter::Node<'t>,
        kinds: &[&str],
    ) -> Option<tree_sitter::Node<'t>> {
        if kinds.contains(&n.kind()) {
            return Some(n);
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            if let Some(found) = first_pattern(child, kinds) {
                return Some(found);
            }
        }
        None
    }
    fn parse_first_python(src: &[u8]) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        (tree, src.to_vec())
    }
    fn run_case(src: &[u8], kinds: &[&str]) -> Vec<(String, usize)> {
        let (tree, bytes) = parse_first_python(src);
        let pat = first_pattern(tree.root_node(), kinds)
            .unwrap_or_else(|| panic!("no {kinds:?} in fixture"));
        collect_array_pattern_bindings_indexed(pat, &bytes)
            .into_iter()
            .collect()
    }
    // Bare comma-list `a, b = ...` is `pattern_list`.
    assert_eq!(
        run_case(b"a, b = (1, 2)\n", &["pattern_list"]),
        vec![("a".into(), 0), ("b".into(), 1)],
    );
    // Three-binding bare comma list.
    assert_eq!(
        run_case(b"a, b, c = (1, 2, 3)\n", &["pattern_list"]),
        vec![("a".into(), 0), ("b".into(), 1), ("c".into(), 2)],
    );
    // Underscore is a regular identifier binding in Python.
    assert_eq!(
        run_case(b"_, b = (1, 2)\n", &["pattern_list"]),
        vec![("_".into(), 0), ("b".into(), 1)],
    );
    assert_eq!(
        run_case(b"a, _ = (1, 2)\n", &["pattern_list"]),
        vec![("a".into(), 0), ("_".into(), 1)],
    );
    // Parenthesised destructure surfaces as `tuple_pattern`.
    assert_eq!(
        run_case(b"(a, b) = (1, 2)\n", &["tuple_pattern"]),
        vec![("a".into(), 0), ("b".into(), 1)],
    );
    // Splat / rest bindings bail because positional mapping breaks.
    assert!(run_case(b"a, *rest = (1, 2, 3)\n", &["pattern_list"]).is_empty());
    // Nested destructure bails — recogniser doesn't recurse into
    // sub-patterns to preserve flat-binding-only semantics.
    assert!(run_case(b"(a, b), c = ((1, 2), 3)\n", &["pattern_list"]).is_empty());
}

/// Ruby `left_assignment_list` is the LHS node tree-sitter-ruby produces
/// for `a, b = ...`.  The helper walks comma-separated identifier
/// children in source order, emitting `(name, position)` for each.
/// Ruby `_` is a normal identifier (matches Python convention).
/// `rest_assignment` (`*rest`) and `destructured_left_assignment`
/// (parenthesised nested destructure) hit the bail branch so callers
/// fall back to scalar union for those advanced shapes.
#[test]
fn left_assignment_list_indexed_bindings_recognise_ruby_destructure() {
    use super::helpers::collect_array_pattern_bindings_indexed;
    fn first_left_assignment_list<'t>(n: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        if n.kind() == "left_assignment_list" {
            return Some(n);
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            if let Some(found) = first_left_assignment_list(child) {
                return Some(found);
            }
        }
        None
    }
    fn parse_first_ruby(src: &[u8]) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_ruby::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        (tree, src.to_vec())
    }
    fn run_case(src: &[u8]) -> Vec<(String, usize)> {
        let (tree, bytes) = parse_first_ruby(src);
        let pat =
            first_left_assignment_list(tree.root_node()).expect("left_assignment_list in fixture");
        collect_array_pattern_bindings_indexed(pat, &bytes)
            .into_iter()
            .collect()
    }
    assert_eq!(
        run_case(b"a, b = [x, y]\n"),
        vec![("a".into(), 0), ("b".into(), 1)],
    );
    assert_eq!(
        run_case(b"a, b, c = [x, y, z]\n"),
        vec![("a".into(), 0), ("b".into(), 1), ("c".into(), 2)],
    );
    // Underscore is a regular identifier binding in Ruby (idiomatic
    // "unused" marker, but still resolvable in scope).
    assert_eq!(
        run_case(b"_, b = [x, y]\n"),
        vec![("_".into(), 0), ("b".into(), 1)],
    );
    assert_eq!(
        run_case(b"a, _ = [x, y]\n"),
        vec![("a".into(), 0), ("_".into(), 1)],
    );
    // Call return value, helper walks LHS regardless of RHS shape.
    assert_eq!(
        run_case(b"a, b = func()\n"),
        vec![("a".into(), 0), ("b".into(), 1)],
    );
    // Splat tail bails because rest_assignment is a complex sub-pattern.
    assert!(run_case(b"a, *rest = [x, y, z]\n").is_empty());
    // Parenthesised nested destructure bails because
    // destructured_left_assignment isn't in the simple-identifier
    // whitelist.
    assert!(run_case(b"(a, b) = [x, y]\n").is_empty());
}

/// Helper for `src/ssa/lower.rs` bare-array destructure rewrite.
/// Walks the RHS of a destructure assignment and emits one slot per
/// source-order element. Each slot is `Ident(name)`, `Literal`, or
/// `Complex(inner_uses)`. Bails (empty) on shapes that shift index
/// alignment (spread / list splat).
#[test]
fn rhs_array_literal_elements_recognise_per_language_shapes() {
    use super::RhsArraySlot;
    use super::helpers::collect_rhs_array_literal_elements;

    fn parse(lang_label: &str, src: &[u8]) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        let lang = match lang_label {
            "javascript" => Language::from(tree_sitter_javascript::LANGUAGE),
            "typescript" => Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
            "python" => Language::from(tree_sitter_python::LANGUAGE),
            "ruby" => Language::from(tree_sitter_ruby::LANGUAGE),
            "rust" => Language::from(tree_sitter_rust::LANGUAGE),
            other => panic!("unsupported lang: {}", other),
        };
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        (tree, src.to_vec())
    }

    fn find_first<'t>(n: tree_sitter::Node<'t>, kinds: &[&str]) -> Option<tree_sitter::Node<'t>> {
        if kinds.iter().any(|k| *k == n.kind()) {
            return Some(n);
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            if let Some(found) = find_first(child, kinds) {
                return Some(found);
            }
        }
        None
    }

    fn run(lang: &str, src: &[u8], rhs_kinds: &[&str]) -> Vec<RhsArraySlot> {
        let (tree, bytes) = parse(lang, src);
        let rhs = find_first(tree.root_node(), rhs_kinds).expect("rhs in fixture");
        collect_rhs_array_literal_elements(rhs, lang, &bytes, None)
            .into_iter()
            .collect()
    }

    fn ident(name: &str) -> RhsArraySlot {
        RhsArraySlot::Ident(name.to_string())
    }
    fn complex(uses: &[&str]) -> RhsArraySlot {
        RhsArraySlot::Complex {
            uses: uses.iter().map(|s| s.to_string()).collect(),
            source_cap: crate::labels::Cap::empty(),
        }
    }
    fn complex_source(uses: &[&str]) -> RhsArraySlot {
        RhsArraySlot::Complex {
            uses: uses.iter().map(|s| s.to_string()).collect(),
            source_cap: crate::labels::Cap::all(),
        }
    }

    // JS/TS `array` literal: two bare idents.
    assert_eq!(
        run("javascript", b"const _ = [safe, tainted];\n", &["array"]),
        vec![ident("safe"), ident("tainted")],
    );
    // JS/TS `array` mixed ident + string literal.
    assert_eq!(
        run("javascript", b"const _ = [tainted, \"ok\"];\n", &["array"]),
        vec![ident("tainted"), RhsArraySlot::Literal],
    );
    // JS/TS now classifies a call as `Complex` carrying inner idents
    // rather than bailing. `collect_idents_with_paths` lifts both paths
    // and bare idents, so a member access surfaces as the dotted path
    // (e.g. `req.query.x`) followed by its component idents.
    assert_eq!(
        run("javascript", b"const _ = [fn(x), 'lit'];\n", &["array"]),
        vec![complex(&["fn", "x"]), RhsArraySlot::Literal],
    );
    // JS/TS member access becomes Complex; dotted path + component idents.
    // Per-slot Source classification fires when the slot's subtree carries
    // a member-expression that strip-and-retry-classifies as Source
    // (`req.query.x` → strip `.x` → `req.query` matches the JS Source rule).
    assert_eq!(
        run(
            "javascript",
            b"const _ = [req.query.x, 'lit'];\n",
            &["array"],
        ),
        vec![
            complex_source(&["req.query.x", "req", "query", "x"]),
            RhsArraySlot::Literal,
        ],
    );
    // Sibling-precision: a Source-classified Complex slot ALONGSIDE a
    // Complex slot whose subtree does NOT classify as Source. Pre-session
    // 0047 every Complex slot was conservatively re-emitted as Source by
    // the outer-node fallback in `src/ssa/lower.rs`; with per-slot
    // classification the safe sibling stays empty so the SSA lowering can
    // emit `Assign(safe)` instead.
    assert_eq!(
        run(
            "javascript",
            b"const _ = [process.env.X, helper(local)];\n",
            &["array"],
        ),
        vec![
            complex_source(&["process.env.X", "process", "env", "X"]),
            complex(&["helper", "local"]),
        ],
    );
    // JS/TS spread bails entirely (index alignment shifts).
    assert!(run("javascript", b"const _ = [...arr, b];\n", &["array"]).is_empty());
    // JS/TS binary expression becomes Complex with the inner ident.
    assert_eq!(
        run(
            "javascript",
            b"const _ = ['log-' + x, 'lit'];\n",
            &["array"],
        ),
        vec![complex(&["x"]), RhsArraySlot::Literal],
    );

    // Python `list` shape.
    assert_eq!(
        run("python", b"a = [safe, tainted]\n", &["list"]),
        vec![ident("safe"), ident("tainted")],
    );
    // Python `expression_list` (bare commas RHS in `a, b = x, y`).
    assert_eq!(
        run("python", b"a, b = safe, tainted\n", &["expression_list"]),
        vec![ident("safe"), ident("tainted")],
    );
    // Python `tuple` (parenthesised).
    assert_eq!(
        run("python", b"x = (safe, 42)\n", &["tuple"]),
        vec![ident("safe"), RhsArraySlot::Literal],
    );
    // Python list-splat bails.
    assert!(run("python", b"x = [*a, b]\n", &["list"]).is_empty());

    // Ruby `array`.
    assert_eq!(
        run("ruby", b"a, b = [safe, tainted]\n", &["array"]),
        vec![ident("safe"), ident("tainted")],
    );
    // Ruby `array` with literal + ident.
    assert_eq!(
        run("ruby", b"a, b = [tainted, \"safe\"]\n", &["array"]),
        vec![ident("tainted"), RhsArraySlot::Literal],
    );

    // Rust `tuple_expression`.
    assert_eq!(
        run(
            "rust",
            b"fn f(safe: &str, tainted: &str) { let _ = (safe, tainted); }\n",
            &["tuple_expression"]
        ),
        vec![ident("safe"), ident("tainted")],
    );

    // Non-array-shape node returns empty (defensive guard).
    assert!(run("javascript", b"const x = tainted;\n", &["identifier"]).is_empty());
}

/// `CalleeSite.span` should carry the 1-based (line, col) of each call's
/// node span so downstream consumers (surface map, datastore/external
/// detectors) can render real coordinates instead of `line: 0`.
#[test]
fn callee_site_span_carries_line_and_column() {
    // Three calls on three different lines.  The leading newline puts
    // line 1 at the blank line; `helper(x, y);` is on line 3, etc.
    let src = b"
function outer(obj, x, y) {
    helper(x, y);
    obj.method(x);
}
";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let (_key, outer) = file_cfg
        .summaries
        .iter()
        .find(|(k, _)| k.name == "outer")
        .expect("outer summary should exist");

    let helper_site = outer
        .callees
        .iter()
        .find(|c| c.name == "helper")
        .expect("helper call should be recorded");
    let (line, col) = helper_site.span.expect("span populated at CFG-build time");
    assert_eq!(line, 3, "helper(...) sits on the 3rd source line");
    assert!(col >= 5, "indented 4 spaces — column is 1-based and > 4");

    let method_site = outer
        .callees
        .iter()
        .find(|c| c.name.ends_with("method"))
        .expect("method call should be recorded");
    let (mline, _) = method_site.span.expect("method span populated");
    assert_eq!(mline, 4, "obj.method(x) on line 4");
}

//  Constant-branch fold: CondArith capture + evaluation

/// `CondArith::eval`/`eval_bool` must fold the two OWASP-Benchmark
/// arithmetic guard shapes to a definite boolean, using integer
/// (truncating) division, and must return `None` — never a wrong fold —
/// for any undefined operation or unresolved variable.
#[test]
fn cond_arith_eval_is_sound() {
    use crate::cfg::{BinOp, CondArith, CondVal};
    let lit = |n| Box::new(CondArith::Lit(n));
    let var = |s: &str| Box::new(CondArith::Var(s.to_string()));
    let bin = |op, l, r| Box::new(CondArith::Bin(op, l, r));

    // num = 86 resolver.
    let r86 = |name: &str| if name == "num" { Some(86) } else { None };
    // (7*42) - num > 200  →  208 > 200  →  true.
    let shape1 = CondArith::Bin(
        BinOp::Gt,
        bin(BinOp::Sub, bin(BinOp::Mul, lit(7), lit(42)), var("num")),
        lit(200),
    );
    assert_eq!(shape1.eval_bool(&r86), Some(true));

    // (500/42) + num > 200  →  11 + 196 = 207 > 200  →  true (integer div).
    let r196 = |name: &str| if name == "num" { Some(196) } else { None };
    let shape2 = CondArith::Bin(
        BinOp::Gt,
        bin(BinOp::Add, bin(BinOp::Div, lit(500), lit(42)), var("num")),
        lit(200),
    );
    assert_eq!(shape2.eval_bool(&r196), Some(true));
    // Integer division truncates toward zero (500/42 == 11, not ~11.9).
    assert_eq!(
        CondArith::Bin(BinOp::Div, lit(500), lit(42)).eval(&r86),
        Some(CondVal::Int(11))
    );

    // Unresolved variable → None (no prune).
    let none = |_: &str| None;
    assert_eq!(shape1.eval_bool(&none), None);

    // Division / modulo by zero → None (never a wrong fold).
    assert_eq!(CondArith::Bin(BinOp::Div, lit(1), lit(0)).eval(&r86), None);
    assert_eq!(CondArith::Bin(BinOp::Mod, lit(1), lit(0)).eval(&r86), None);

    // Arithmetic overflow → None.
    assert_eq!(
        CondArith::Bin(BinOp::Mul, lit(i64::MAX), lit(2)).eval(&r86),
        None
    );

    // Bare integer at the top level is not a branch condition → eval_bool None.
    assert_eq!(CondArith::Lit(1).eval_bool(&r86), None);

    // Comparing a boolean sub-result as an integer operand → None.
    let cmp = bin(BinOp::Gt, lit(2), lit(1)); // yields Bool
    assert_eq!(CondArith::Bin(BinOp::Add, cmp, lit(1)).eval(&r86), None);
}

/// The CFG builder must capture a pure integer-arithmetic comparison as a
/// `CondArith` on the `If` node, and must refuse (None) any condition that
/// touches a call / field access / string.
#[test]
fn build_cond_arith_captures_pure_int_comparison() {
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let src = br#"
class C {
  void m(int num, String s) {
    if ((7 * 42) - num > 200) { foo(); }
    if (s.length() > 200) { bar(); }
  }
}
"#;
    let (cfg, _entry) = parse_and_build(src, "java", ts_lang);
    let ifs = if_nodes(&cfg);
    let arith: Vec<_> = ifs
        .iter()
        .filter_map(|&n| cfg[n].cond_arith.clone())
        .collect();

    // Exactly one If condition is a pure int-arith comparison; the
    // `s.length() > 200` one must NOT be captured (it contains a call).
    assert_eq!(
        arith.len(),
        1,
        "only the pure int comparison should yield a CondArith, got {arith:?}"
    );
    // It folds to a definite bool once `num` is known constant.
    let r = |name: &str| if name == "num" { Some(86) } else { None };
    assert_eq!(arith[0].eval_bool(&r), Some(true));
}

// ── rhs_object_literal (JS/TS object-literal property shape) ──────────────

fn object_literal_of<'a>(cfg: &'a Cfg, name: &str) -> Option<&'a crate::cfg::RhsObjectLiteral> {
    cfg.node_indices()
        .map(|i| &cfg[i])
        .find(|n| n.taint.defines.as_deref() == Some(name))
        .and_then(|n| n.taint.rhs_object_literal.as_deref())
}

#[test]
fn rhs_object_literal_records_property_shape() {
    use crate::cfg::RhsObjectSlot;
    let src = b"function f(req) {\n\
        const a = { k: 'v', \"q\": 1, n: null, t: `x`, i: req.query.x, s, id: other, o: { p: 'c' } };\n\
        const b = { ...req.body, safe: 'x' };\n\
        const c = { [req.query.k]: 1 };\n\
        const d = ({ m() { return 1; } });\n\
        const e = req.body;\n\
        const g = { u: `a${req.query.x}` }, h = { v: 1 };\n\
    }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);

    let a = object_literal_of(&cfg, "a").expect("`a` binds an object literal");
    assert!(!a.open);
    let slot = |k: &str| {
        a.fields
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, s)| s.clone())
    };
    assert_eq!(slot("k"), Some(RhsObjectSlot::Literal));
    assert_eq!(
        slot("q"),
        Some(RhsObjectSlot::Literal),
        "quoted key is unquoted"
    );
    assert_eq!(slot("n"), Some(RhsObjectSlot::Literal));
    assert_eq!(
        slot("t"),
        Some(RhsObjectSlot::Literal),
        "template without substitutions"
    );
    assert_eq!(slot("i"), Some(RhsObjectSlot::Complex));
    assert_eq!(
        slot("s"),
        Some(RhsObjectSlot::Ident("s".into())),
        "shorthand"
    );
    assert_eq!(slot("id"), Some(RhsObjectSlot::Ident("other".into())));
    match slot("o") {
        Some(RhsObjectSlot::Object(inner)) => {
            assert_eq!(inner.fields.len(), 1);
            assert_eq!(inner.fields[0], ("p".into(), RhsObjectSlot::Literal));
        }
        other => panic!("nested literal expected, got {other:?}"),
    }

    assert!(object_literal_of(&cfg, "b").expect("spread literal").open);
    assert!(
        object_literal_of(&cfg, "c")
            .expect("computed key literal")
            .open
    );
    assert!(
        object_literal_of(&cfg, "d")
            .expect("parenthesised literal")
            .open
    );
    assert!(object_literal_of(&cfg, "e").is_none(), "non-literal RHS");
    assert!(
        object_literal_of(&cfg, "g").is_none() && object_literal_of(&cfg, "h").is_none(),
        "multi-declarator statements are not single bindings"
    );
}

#[test]
fn rhs_object_literal_unwraps_ts_assertions() {
    let src = b"function f(req: any) {\n\
        const a = { k: 'v' } as const;\n\
        const b = { k: req.query.x } satisfies Record<string, unknown>;\n\
        let c: any;\n\
        c = { k: 1 };\n\
    }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let (cfg, _entry) = parse_and_build(src, "typescript", ts_lang);
    assert!(object_literal_of(&cfg, "a").is_some(), "`as const` literal");
    assert!(
        object_literal_of(&cfg, "b").is_some(),
        "`satisfies` literal"
    );
    assert!(object_literal_of(&cfg, "c").is_some(), "plain assignment");
}

// ── numeric_confined_uses (inline numeric-chain confinement) ──────────────

/// Find the sink node carrying a non-empty `numeric_confined_uses`, plus the
/// node whose callee contains `needle` (the collapsed sink chain text).
fn confined_uses_of<'a>(cfg: &'a Cfg, needle: &str) -> Option<&'a Vec<String>> {
    cfg.node_indices()
        .map(|i| &cfg[i])
        .find(|n| n.call.callee.as_deref().is_some_and(|c| c.contains(needle)))
        .map(|n| &n.numeric_confined_uses)
}

#[test]
fn numeric_confined_inline_parse_chain_into_shell_arg() {
    // `Command::new("nc").arg(e.parse::<u16>().unwrap().to_string())` — the
    // tainted leaf `e` is consumed only by a numeric parse, so it must be
    // recorded as numeric-confined on the sink node.
    let src = b"fn f() { let e = std::env::var(\"P\").unwrap_or_default(); \
                let _ = std::process::Command::new(\"nc\").arg(e.parse::<u16>().unwrap().to_string()).output(); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "Command").expect("sink node present");
    assert!(
        confined.iter().any(|u| u == "e"),
        "expected `e` numeric-confined; got {confined:?}"
    );
}

#[test]
fn numeric_confined_skips_string_tostring_receiver() {
    // `Command::new("nc").arg(e.to_string())` where `e` is a String — the
    // receiver of `.to_string()` is not numeric, so `e` must NOT be confined
    // (the command injection must still fire).
    let src = b"fn f() { let e = std::env::var(\"P\").unwrap_or_default(); \
                let _ = std::process::Command::new(\"nc\").arg(e.to_string()).output(); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "Command").expect("sink node present");
    assert!(
        !confined.iter().any(|u| u == "e"),
        "`e.to_string()` on a String must not be numeric-confined; got {confined:?}"
    );
}

#[test]
fn numeric_confined_blocked_by_raw_occurrence() {
    // Same leaf used raw AND parsed: `Command::new(e.clone()).arg(e.parse::<u16>()…)`
    // — the raw `e.clone()` occurrence (receiver of a non-numeric call) must
    // block confinement so the real injection still fires.  Soundness guard.
    let src = b"fn f() { let e = std::env::var(\"P\").unwrap_or_default(); \
                let _ = std::process::Command::new(e.clone()).arg(e.parse::<u16>().unwrap().to_string()).output(); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "Command").expect("sink node present");
    assert!(
        !confined.iter().any(|u| u == "e"),
        "raw `e.clone()` occurrence must block confinement of `e`; got {confined:?}"
    );
}

#[test]
fn numeric_confined_only_on_sink_nodes() {
    // A non-sink node (`let n = e.parse::<u16>()` with no sink label) must not
    // carry confinement entries — the field is gated to Sink nodes.
    let src = b"fn f() { let e = std::env::var(\"P\").unwrap_or_default(); \
                let n = e.parse::<u16>().unwrap(); let _ = n; }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    for i in cfg.node_indices() {
        assert!(
            cfg[i].numeric_confined_uses.is_empty(),
            "non-sink node carried confinement entries: {:?}",
            cfg[i].numeric_confined_uses
        );
    }
}

#[test]
fn numeric_confined_js_parse_method_is_not_numeric() {
    // Outside Rust a `.parse` method returns an object (`url.parse`,
    // `JSON.parse`), so `x` inside `url.parse(x)` must not be confined, while
    // `parseInt(y)` still confines `y`.
    let src = b"var fs = require('fs'); function h(req) { var x = req.query.a; \
                var y = req.query.b; fs.readFile(url.parse(x).pathname); \
                fs.readFile('/d/' + parseInt(y)); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let confined: Vec<&String> = cfg
        .node_indices()
        .flat_map(|i| cfg[i].numeric_confined_uses.iter())
        .collect();
    assert!(
        !confined.iter().any(|u| *u == "x"),
        "`url.parse(x)` must not numeric-confine `x`; got {confined:?}"
    );
    assert!(
        confined.iter().any(|u| *u == "y"),
        "`parseInt(y)` must numeric-confine `y`; got {confined:?}"
    );
}

#[test]
fn numeric_confined_format_macro_parse_chain() {
    // `fs::read(format!("/d/{}", g.parse::<u32>().unwrap()))` — tree-sitter
    // flattens the macro body to a token_tree, so `g` is recovered as confined
    // only by re-parsing the interpolated argument expression.
    let src = b"fn f() { let g = std::env::var(\"ID\").unwrap(); \
                let _ = std::fs::read(format!(\"/d/{}\", g.parse::<u32>().unwrap())); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "fs::read").expect("sink node present");
    assert!(
        confined.iter().any(|u| u == "g"),
        "expected `g` numeric-confined inside format!; got {confined:?}"
    );
}

#[test]
fn numeric_confined_format_macro_mixed_idents() {
    // `format!("/d/{}/{}", h, g.parse::<u32>())` — `g` is numeric-confined but
    // the raw `h` interpolation must NOT be, so the path traversal via `h`
    // still fires.
    let src = b"fn f() { let h = std::env::var(\"A\").unwrap(); \
                let g = std::env::var(\"B\").unwrap(); \
                let _ = std::fs::read(format!(\"/d/{}/{}\", h, g.parse::<u32>().unwrap())); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "fs::read").expect("sink node present");
    assert!(
        confined.iter().any(|u| u == "g"),
        "expected `g` confined; got {confined:?}"
    );
    assert!(
        !confined.iter().any(|u| u == "h"),
        "raw `h` interpolation must not be confined; got {confined:?}"
    );
}

#[test]
fn numeric_confined_format_macro_pathbuf_turbofish_not_confined() {
    // `format!("/d/{}", p.parse::<PathBuf>())` — a non-numeric explicit
    // turbofish target proves the value is NOT an integer, so `p` must stay
    // un-confined and the FILE_IO flow fires.
    let src = b"fn f() { let p = std::env::var(\"C\").unwrap(); \
                let _ = std::fs::read(format!(\"/d/{}\", p.parse::<std::path::PathBuf>().unwrap())); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "fs::read").expect("sink node present");
    assert!(
        !confined.iter().any(|u| u == "p"),
        "`parse::<PathBuf>()` must not be numeric-confined; got {confined:?}"
    );
}

#[test]
fn numeric_confined_format_macro_blocked_by_raw_occurrence() {
    // Same leaf raw AND parsed inside one format!: `format!("/d/{}/{}", v,
    // v.parse::<u32>())` — the raw `v` occurrence blocks confinement.
    let src = b"fn f() { let v = std::env::var(\"E\").unwrap(); \
                let _ = std::fs::read(format!(\"/d/{}/{}\", v, v.parse::<u32>().unwrap())); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let confined = confined_uses_of(&cfg, "fs::read").expect("sink node present");
    assert!(
        !confined.iter().any(|u| u == "v"),
        "raw `v` occurrence must block confinement; got {confined:?}"
    );
}

#[test]
fn numeric_confined_shares_enclosing_call_verdict_across_callbacks() {
    // Sink argument is a chained call whose callee text carries a whole
    // callback body.  Each identifier is judged by its nearest enclosing
    // call: `n` and `m` only ever feed `parseInt`, so they are confined
    // (both occurrences of `m`); `x` and `items` feed `filter` and stay raw.
    let src = b"function h(req, res) { \
                res.send(items.filter(function (x) { return parseInt(n + m) > x; }).size(), parseInt(m)); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let confined = confined_uses_of(&cfg, "res.send").expect("sink node present");
    let mut got: Vec<&str> = confined.iter().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, ["m", "n"], "confined idents");
}

#[test]
fn numeric_confined_raw_occurrence_inside_callback_blocks() {
    // `n` feeds `parseInt` in the outer argument but appears raw (argument
    // of the non-numeric `log`) inside the callback, so it is not confined.
    let src = b"function h(req, res) { \
                res.send(items.map(function (y) { log(n); return y; }).size(), parseInt(n)); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "javascript", ts_lang);
    let confined = confined_uses_of(&cfg, "res.send").expect("sink node present");
    assert!(
        !confined.iter().any(|u| u == "n"),
        "raw `log(n)` occurrence must block confinement; got {confined:?}"
    );
}

#[test]
fn format_macro_method_idents_records_machinery() {
    // The phantom method/macro-name tokens (`format`, `parse`, `unwrap`) of a
    // confined format! interpolation are recorded so the structural confinement
    // check can skip the SSA Param operands they lower to.
    let src = b"fn f() { let g = std::env::var(\"ID\").unwrap(); \
                let _ = std::fs::read(format!(\"/d/{}\", g.parse::<u32>().unwrap())); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "rust", ts_lang);
    let sink = cfg
        .node_indices()
        .map(|i| &cfg[i])
        .find(|n| {
            n.call
                .callee
                .as_deref()
                .is_some_and(|c| c.contains("fs::read"))
        })
        .expect("sink node present");
    for name in ["format", "parse", "unwrap"] {
        assert!(
            sink.format_macro_method_idents.iter().any(|m| m == name),
            "expected `{name}` in format_macro_method_idents; got {:?}",
            sink.format_macro_method_idents
        );
    }
    // The confined value leaf `g` is a real value, not machinery.
    assert!(
        !sink.format_macro_method_idents.iter().any(|m| m == "g"),
        "value leaf `g` must not be machinery; got {:?}",
        sink.format_macro_method_idents
    );
}

// ── Java borrowed-vs-owned JDBC connection classification ───────────────
// Pins `NodeInfo.borrowed_resource`, set at CFG build by receiver-type
// discrimination (`java_getconnection_receiver_is_borrowed`).  A connection
// borrowed from a managed session / DB abstraction (Liquibase `Database`,
// Hibernate `Session`, MyBatis `SqlSession`, JPA `EntityManager`) is closed
// by its owner, so leak-at-exit on the borrower is a false positive; an
// OWNED `DataSource` / static `DriverManager` connection stays a real leak.

fn java_any_borrowed_resource(src: &[u8]) -> bool {
    let ts_lang = Language::from(tree_sitter_java::LANGUAGE);
    let (cfg, _entry) = parse_and_build(src, "java", ts_lang);
    cfg.node_weights().any(|n| n.borrowed_resource)
}

#[test]
fn java_borrowed_connection_from_liquibase_database_param_is_flagged() {
    // openmrs Liquibase changeset shape: `database` is a `Database` parameter
    // whose connection Liquibase owns and closes.
    let src = br#"class C {
  public void execute(Database database) throws Exception {
    JdbcConnection connection = (JdbcConnection) database.getConnection();
    connection.prepareStatement("x");
  }
}"#;
    assert!(java_any_borrowed_resource(src));
}

#[test]
fn java_borrowed_connection_from_hibernate_local_session_is_flagged() {
    // A local `Session` (Hibernate) owns its JDBC connection.
    let src = br#"class C {
  void run(SessionFactory sf) {
    Session s = sf.openSession();
    java.sql.Connection c = s.getConnection();
    c.prepareStatement("x");
  }
}"#;
    assert!(java_any_borrowed_resource(src));
}

#[test]
fn java_borrowed_connection_from_mybatis_field_is_flagged() {
    // A `SqlSession` (MyBatis) class field owns its connection.
    let src = br#"class Dao {
  private SqlSession dbSession;
  void run() {
    java.sql.Connection c = dbSession.getConnection();
    c.prepareStatement("x");
  }
}"#;
    assert!(java_any_borrowed_resource(src));
}

#[test]
fn java_owned_connection_from_driver_manager_static_is_not_flagged() {
    // `DriverManager.getConnection(...)` returns an OWNED connection: the
    // receiver `DriverManager` resolves to no local / param / field, so the
    // leak stays a true positive.
    let src = br#"class C {
  void run(String url) throws Exception {
    java.sql.Connection c = java.sql.DriverManager.getConnection(url);
    c.prepareStatement("x");
  }
}"#;
    assert!(!java_any_borrowed_resource(src));
}

#[test]
fn java_owned_connection_from_datasource_is_not_flagged() {
    // A `DataSource` connection is OWNED by the caller (must close).
    let src = br#"class C {
  private javax.sql.DataSource ds;
  void run() throws Exception {
    java.sql.Connection c = ds.getConnection();
    c.prepareStatement("x");
  }
}"#;
    assert!(!java_any_borrowed_resource(src));
}

#[test]
fn java_bare_getconnection_call_is_not_flagged() {
    // A bare `getConnection()` (self / static helper, no receiver) has no
    // receiver type to discriminate → stays a real leak.
    let src = br#"class C {
  void run() throws Exception {
    java.sql.Connection c = getConnection();
    c.prepareStatement("x");
  }
}"#;
    assert!(!java_any_borrowed_resource(src));
}

#[test]
fn java_borrowed_owner_type_classifier_and_leaf() {
    assert_eq!(
        super::java_type_leaf("liquibase.database.Database"),
        "Database"
    );
    assert_eq!(super::java_type_leaf("org.hibernate.Session"), "Session");
    assert_eq!(super::java_type_leaf("List<Session>"), "List");
    assert_eq!(super::java_type_leaf("Foo[]"), "Foo");
    assert!(super::is_java_borrowed_connection_owner("Database"));
    assert!(super::is_java_borrowed_connection_owner(
        "org.hibernate.Session"
    ));
    assert!(super::is_java_borrowed_connection_owner("SqlSession"));
    assert!(super::is_java_borrowed_connection_owner(
        "javax.persistence.EntityManager"
    ));
    // `*Session` suffix generalises across frameworks (sonarqube `DbSession`
    // extends MyBatis `SqlSession`; Hibernate `StatelessSession`).
    assert!(super::is_java_borrowed_connection_owner(
        "org.sonar.db.DbSession"
    ));
    assert!(super::is_java_borrowed_connection_owner("StatelessSession"));
    // OWNED-connection receivers must NOT be borrowed owners (recall).
    assert!(!super::is_java_borrowed_connection_owner(
        "javax.sql.DataSource"
    ));
    assert!(!super::is_java_borrowed_connection_owner("DriverManager"));
    assert!(!super::is_java_borrowed_connection_owner("Connection"));
    assert!(!super::is_java_borrowed_connection_owner("BasicDataSource"));
}

/// `sequelize.transaction(async (t) => { sequelize.query(`const`, {t}) })`:
/// `first_member_label` hoists the inner query SQL_QUERY Sink onto the outer
/// `.transaction` wrapper node.  The wrapper must carry `HoistedSink`
/// provenance recording the INNER call's own payload-arg positions ([0], from
/// the sequelize.query gate) and per-argument string literals (arg0 = the
/// constant SQL template), so the cfg-unguarded-sink layer can prove the inner
/// payload constant and suppress the phantom wrapper finding.
#[test]
fn transaction_wrapper_records_hoisted_sink_const_payload() {
    let src = br#"module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.sequelize.query(`DROP VIEW x`, { transaction });
    });
  },
};
"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let fc = parse_to_file_cfg(src, "javascript", ts_lang);
    let wrapper = fc
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .find(|n| n.call.callee.as_deref() == Some("queryInterface.sequelize.transaction"))
        .expect("transaction wrapper node");
    let h = wrapper
        .call
        .hoisted_sink
        .as_ref()
        .expect("wrapper carries HoistedSink provenance from the callback body");
    assert_eq!(h.payload_args.as_deref(), Some(&[0usize][..]));
    assert_eq!(
        h.arg_string_literals.first(),
        Some(&Some("DROP VIEW x".to_string()))
    );
}

/// Interpolated inner SQL: the same wrapper shape but the inner query payload
/// is a `${…}` template (non-const).  The recorded `HoistedSink` must leave
/// payload position 0 non-literal so the syntactic payload-const suppression
/// does NOT fire and a tainted inner flow still reports.
#[test]
fn transaction_wrapper_hoisted_sink_interpolated_payload_not_literal() {
    let src = br#"async function h(name) {
  await sequelize.transaction(async (transaction) => {
    await sequelize.query(`SELECT * FROM u WHERE n = '${name}'`, { transaction });
  });
}
"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let fc = parse_to_file_cfg(src, "javascript", ts_lang);
    let wrapper = fc
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .find(|n| n.call.callee.as_deref() == Some("sequelize.transaction"))
        .expect("transaction wrapper node");
    let h = wrapper
        .call
        .hoisted_sink
        .as_ref()
        .expect("wrapper carries HoistedSink provenance");
    assert_eq!(h.payload_args.as_deref(), Some(&[0usize][..]));
    // Interpolated template => no captured literal at the payload position.
    assert_eq!(h.arg_string_literals.first(), Some(&None));
}

/// Ordinary member-source-on-wrapper hoist (no callback body) must NOT be
/// treated as a hoisted callback sink: `storeInto(req.query.input, items)`
/// hoists the `req.query.input` Source onto the wrapper, which is not a
/// callback-nested Sink, so `hoisted_sink` stays `None`.
#[test]
fn member_source_wrapper_has_no_hoisted_sink() {
    let src = b"function h(req, items) { storeInto(req.query.input, items); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let fc = parse_to_file_cfg(src, "javascript", ts_lang);
    for b in &fc.bodies {
        for i in b.graph.node_indices() {
            assert!(
                b.graph[i].call.hoisted_sink.is_none(),
                "no callback sink hoist expected for a member-source wrapper"
            );
        }
    }
}

/// A chained call must not inherit `HoistedSink` provenance from a sink nested
/// in its RECEIVER's callback.  In
/// `http.get(target, res => { res.send('ok') }).on('error', cb)` the `.on` node
/// owns only `'error'` and `cb`; `res.send('ok')` belongs to the `http.get`
/// receiver.  Recording it made the unrelated `'ok'` literal look like a
/// constant payload for the `.on` node, and `sink_payload_args_syntactic_const`
/// then suppressed a real SSRF finding (benchmark case `js-ssrf-003`).
#[test]
fn chained_call_takes_no_hoisted_sink_from_receiver_callback() {
    let src = br#"const http = require('http');
app.get('/probe', (req, res) => {
    const target = req.query.url;
    http.get(target, response => {
        res.send('ok');
    }).on('error', e => {
        res.status(500).send(e.message);
    });
});
"#;
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let fc = parse_to_file_cfg(src, "javascript", ts_lang);
    let on_node = fc
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .find(|n| {
            n.call
                .outer_callee
                .as_deref()
                .is_some_and(|c| c.ends_with(".on"))
        });
    if let Some(n) = on_node {
        // Provenance may be absent, or present only from the `.on` node's own
        // argument callback (`res.status(500).send(e.message)`), whose payload
        // is NOT a literal.  What must never happen is inheriting the
        // receiver's constant `'ok'`.
        if let Some(h) = &n.call.hoisted_sink {
            assert!(
                !h.arg_string_literals
                    .iter()
                    .any(|l| l.as_deref() == Some("ok")),
                "chained `.on` node inherited `'ok'` from the receiver's callback: {h:?}"
            );
        }
    }
}

fn file_cfg_nodes(file_cfg: &FileCfg) -> Vec<&NodeInfo> {
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .collect()
}

#[test]
fn js_sink_assignment_member_source_is_pre_emitted() {
    let src = b"function f() {\n\
                  const el = document.getElementById('a');\n\
                  el.innerHTML = '<b>' + location.hash + '</b>';\n\
                  el.textContent = location.hash;\n\
                  el.innerHTML = DOMPurify.sanitize(location.search);\n\
                }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let nodes = file_cfg_nodes(&file_cfg);
    let synth: Vec<&&NodeInfo> = nodes
        .iter()
        .filter(|n| {
            n.taint
                .defines
                .as_deref()
                .is_some_and(|d| d.starts_with("__nyx_src_") && d.contains("_rhs"))
        })
        .collect();
    // Only the concatenation written into `innerHTML` gets one: `textContent`
    // is not a sink and the sanitizer call's argument is left to the call.
    assert_eq!(synth.len(), 1, "{synth:?}");
    assert!(
        synth[0]
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_)))
    );
    let name = synth[0].taint.defines.clone().unwrap();
    let sink = nodes
        .iter()
        .find(|n| n.taint.uses.contains(&name))
        .expect("the assignment uses the synthetic source");
    assert!(has_sink(sink, Cap::HTML_ESCAPE));
}

#[test]
fn js_for_of_over_source_field_is_a_source() {
    let src = b"function h(req, config) {\n\
                  for (const f of req.body.items) { run(f); }\n\
                  for (const g of config.items) { run(g); }\n\
                }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let loop_sources: Vec<String> = file_cfg_nodes(&file_cfg)
        .into_iter()
        .filter(|n| {
            n.taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)))
        })
        .filter_map(|n| n.call.callee.clone())
        .collect();
    assert!(
        loop_sources.iter().any(|c| c == "req.body.items"),
        "{loop_sources:?}"
    );
    assert!(!loop_sources.iter().any(|c| c.contains("config")));
}

#[test]
fn ts_sql_tagged_templates_bind_substitutions() {
    let src = b"import { sql } from 'drizzle-orm';\n\
                import { Prisma } from '@prisma/client';\n\
                async function h(prisma, db, name, col) {\n\
                  await prisma.$queryRaw`SELECT * FROM t WHERE n = ${name}`;\n\
                  await prisma.$queryRaw`SELECT ${Prisma.raw(col)} FROM t WHERE n = ${name}`;\n\
                  await db.execute(sql`select * from t where n = ${name}`);\n\
                  const q = sql`select * from t where n = ${name}`;\n\
                }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
    let raws = js_call_nodes(&file_cfg, "prisma.$queryRaw");
    assert_eq!(raws.len(), 2);
    // Plain substitutions are parameters: no SQL sink.
    assert!(!has_sink(raws[0], Cap::SQL_QUERY));
    // The raw splice is the only payload: `${Prisma.raw(col)}` is the
    // template's second named child.
    assert!(has_sink(raws[1], Cap::SQL_QUERY));
    assert_eq!(
        raws[1].call.sink_payload_args.as_deref(),
        Some(&[1usize][..])
    );
    // A SQL executor fed a parameterized tag is not a sink either.
    let execs = js_call_nodes(&file_cfg, "db.execute");
    assert_eq!(execs.len(), 1);
    assert!(!has_sink(execs[0], Cap::SQL_QUERY));
    // The builder's result is SQL-safe.
    let builder = file_cfg_nodes(&file_cfg)
        .into_iter()
        .find(|n| n.taint.defines.as_deref() == Some("q"))
        .unwrap();
    assert!(
        builder
            .taint
            .labels
            .contains(&DataLabel::Sanitizer(Cap::SQL_QUERY))
    );
}

#[test]
fn ts_query_builder_chain_condition_is_a_sql_sink() {
    let src = b"async function h(repo, name) {\n\
                  await repo.createQueryBuilder('u').leftJoin('u.p', 'p').where(`u.name = '${name}'`).getMany();\n\
                  await repo.createQueryBuilder('u').where({ name }).getMany();\n\
                }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
    let wheres = js_call_nodes(&file_cfg, "QueryBuilder.where");
    assert_eq!(wheres.len(), 2, "both chains rebind to their where link");
    assert!(has_sink(wheres[0], Cap::SQL_QUERY));
    assert_eq!(
        wheres[0].call.sink_payload_args.as_deref(),
        Some(&[0usize][..])
    );
    // An object condition is bound by the ORM.
    assert!(!has_sink(wheres[1], Cap::SQL_QUERY));
}

#[test]
fn ts_query_builder_object_argument_is_bound_only_for_conditions() {
    let src = b"async function h(repo, col, name, dir) {\n\
                  await repo.createQueryBuilder('u').orderBy({ [col]: 'ASC' }).getMany();\n\
                  await repo.createQueryBuilder('u').orderBy({ 'u.name': 'ASC' }).getMany();\n\
                  await repo.createQueryBuilder('u').orderBy({ ...col }).getMany();\n\
                  await repo.createQueryBuilder('u').orderBy({ 'u.name': dir }).getMany();\n\
                  await repo.createQueryBuilder('u').orderBy({ 'u.id': { order: 'DESC', nulls: 'NULLS LAST' } }).getMany();\n\
                  await repo.createQueryBuilder('u').groupBy(new String(col)).getMany();\n\
                  await repo.createQueryBuilder('u').where(new Brackets(q => q.where('a = 1'))).getMany();\n\
                  await repo.createQueryBuilder('u').where(new String(name)).getMany();\n\
                }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
    let order = js_call_nodes(&file_cfg, "QueryBuilder.orderBy");
    assert_eq!(order.len(), 5);
    // A computed key or a spread puts an attacker-chosen column into SQL.
    assert!(has_sink(order[0], Cap::SQL_QUERY));
    assert!(!has_sink(order[1], Cap::SQL_QUERY));
    assert!(has_sink(order[2], Cap::SQL_QUERY));
    // The direction is written into SQL too, so it has to be static.
    assert!(has_sink(order[3], Cap::SQL_QUERY));
    assert!(!has_sink(order[4], Cap::SQL_QUERY));
    let group = js_call_nodes(&file_cfg, "QueryBuilder.groupBy");
    assert!(has_sink(group[0], Cap::SQL_QUERY));
    let wheres = js_call_nodes(&file_cfg, "QueryBuilder.where");
    assert!(
        wheres
            .iter()
            .any(|w| w.call.arg_uses[0].iter().any(|u| u == "name") && has_sink(w, Cap::SQL_QUERY)),
        "where(new String(name)) is not a Brackets group"
    );
    assert!(wheres.iter().any(|w| !has_sink(w, Cap::SQL_QUERY)));
}

#[test]
fn ts_reexported_sql_tag_and_client_values_are_parameterized() {
    // A tag re-exported by a project module, or a client built by a call, is
    // a library tag; only a function the file defines itself is not.
    for src in [
        &b"import { sql } from '@/db';\n\
           async function h(db, name) {\n\
             await db.execute(sql`select * from t where n = ${name}`);\n\
           }"[..],
        &b"import postgres from 'postgres';\n\
           export const sql = postgres(process.env.DB_URL);\n\
           async function h(db, name) {\n\
             await db.execute(sql`select * from t where n = ${name}`);\n\
           }"[..],
    ] {
        let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
        let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
        let execs = js_call_nodes(&file_cfg, "db.execute");
        assert_eq!(execs.len(), 1);
        assert!(
            !has_sink(execs[0], Cap::SQL_QUERY),
            "{}",
            String::from_utf8_lossy(src)
        );
    }
    // An arrow function the file defines is its own tag.
    let src = b"const sql = (s, ...v) => s.join('');\n\
                async function h(db, name) {\n\
                  await db.execute(sql`select * from t where n = ${name}`);\n\
                }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
    let execs = js_call_nodes(&file_cfg, "db.execute");
    assert!(has_sink(execs[0], Cap::SQL_QUERY));
}

#[test]
fn ts_user_defined_sql_tag_is_not_parameterized() {
    // Same shapes as the drizzle test, with no SQL library import: the tag
    // and the `raw` helper are the file's own functions.
    let src = b"function sql(s, ...v) { return s.join(''); }\n\
                async function h(db, name) {\n\
                  await db.execute(sql`select * from t where n = ${name}`);\n\
                }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
    let execs = js_call_nodes(&file_cfg, "db.execute");
    assert_eq!(execs.len(), 1);
    assert!(has_sink(execs[0], Cap::SQL_QUERY));
    let builder = file_cfg_nodes(&file_cfg)
        .into_iter()
        .find(|n| n.call.callee.as_deref() == Some("sql"));
    assert!(builder.is_none_or(|b| {
        !b.taint
            .labels
            .contains(&DataLabel::Sanitizer(Cap::SQL_QUERY))
    }));
}

#[test]
fn ts_query_builder_chain_binds_an_inline_member_source() {
    let src = b"async function h(repo, req) {\n\
                  await repo.createQueryBuilder('u').where(`u.name = '${req.query.name}'`).getMany();\n\
                }";
    let ts_lang = Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    let file_cfg = parse_to_file_cfg(src, "typescript", ts_lang);
    let wheres = js_call_nodes(&file_cfg, "QueryBuilder.where");
    assert_eq!(wheres.len(), 1, "the chain rebinds to its where link");
    assert!(has_sink(wheres[0], Cap::SQL_QUERY));
    // The inline `req.query.name` is bound to the where condition's argument.
    assert!(
        wheres[0].call.arg_uses[0]
            .iter()
            .any(|u| u.starts_with("__nyx_src_")),
        "{:?}",
        wheres[0].call.arg_uses
    );
}

#[test]
fn js_sink_assignment_from_source_receiver_call_keeps_the_sink() {
    let src = b"function f() {\n\
                  location.href = location.hash.substring(1);\n\
                }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let nodes = file_cfg_nodes(&file_cfg);
    let synth = nodes
        .iter()
        .find(|n| {
            n.taint
                .defines
                .as_deref()
                .is_some_and(|d| d.contains("_rhs"))
        })
        .expect("location.hash is pre-emitted");
    let name = synth.taint.defines.clone().unwrap();
    let sink = nodes
        .iter()
        .find(|n| n.taint.uses.contains(&name))
        .unwrap_or_else(|| panic!("no node uses {name}: {nodes:#?}"));
    assert!(
        sink.taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(_))),
        "{sink:#?}"
    );
}

/// The page's own origin parts are not attacker input: same-origin
/// navigation built from them gets no pre-emitted Source, while the path or
/// query of the location still does.
#[test]
fn js_sink_assignment_from_own_origin_has_no_source() {
    let count = |body: &str| {
        let src = format!("function f(name) {{\n  {body}\n}}");
        let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
        let file_cfg = parse_to_file_cfg(src.as_bytes(), "javascript", ts_lang);
        file_cfg_nodes(&file_cfg)
            .iter()
            .filter(|n| {
                n.taint
                    .defines
                    .as_deref()
                    .is_some_and(|d| d.starts_with("__nyx_src_") && d.contains("_rhs"))
            })
            .count()
    };
    assert_eq!(
        count("window.location.href = window.location.origin + window.location.pathname;"),
        0
    );
    assert_eq!(
        count("window.location.href = `/auth/${name}?host=${window.location.host}`;"),
        0
    );
    assert_eq!(
        count("window.location.href = window.location.origin + window.location.search;"),
        1
    );
    assert_eq!(
        count("window.location.href = window.location.hash.slice(1);"),
        1
    );
}

// ── Read-modify-write assignments (`x += y`, `x ||= y`) ─────────────────

fn rmw_all_nodes(src: &[u8], lang_str: &str, ts_lang: Language) -> Vec<NodeInfo> {
    let fc = parse_to_file_cfg(src, lang_str, ts_lang);
    fc.bodies
        .iter()
        .flat_map(|b| b.graph.node_weights().cloned().collect::<Vec<_>>())
        .collect()
}

/// The single node that defines `var` from a read-modify-write.
fn rmw_def_node(nodes: &[NodeInfo], var: &str) -> NodeInfo {
    let defs: Vec<&NodeInfo> = nodes
        .iter()
        .filter(|n| n.rmw_assign && n.taint.defines.as_deref() == Some(var))
        .collect();
    assert_eq!(
        defs.len(),
        1,
        "expected one read-modify-write def of `{var}`, got {defs:#?}"
    );
    defs[0].clone()
}

fn assert_compound_reads_target(src: &[u8], lang_str: &str, ts_lang: Language) {
    let nodes = rmw_all_nodes(src, lang_str, ts_lang);
    let n = rmw_def_node(&nodes, "x");
    assert_eq!(
        n.taint.uses.first().map(String::as_str),
        Some("x"),
        "{lang_str}: the target must be the first use: {:?}",
        n.taint.uses
    );
    assert!(
        n.taint.uses.iter().any(|u| u == "y"),
        "{lang_str}: the right-hand side must stay a use: {:?}",
        n.taint.uses
    );
    assert!(
        n.taint.const_text.is_none(),
        "{lang_str}: a compound assignment is not a literal def"
    );
}

#[test]
fn compound_assign_reads_target_javascript() {
    assert_compound_reads_target(
        b"function f(y) { let x = 'a'; x += y; return x; }",
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_typescript() {
    assert_compound_reads_target(
        b"function f(y: string) { let x = 'a'; x ??= y; return x; }",
        "typescript",
        Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
    );
}

#[test]
fn compound_assign_reads_target_python() {
    assert_compound_reads_target(
        b"def f(y):\n    x = 'a'\n    x += y\n    return x\n",
        "python",
        Language::from(tree_sitter_python::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_php() {
    assert_compound_reads_target(
        b"<?php function f($y) { $x = 'a'; $x .= $y; return $x; }",
        "php",
        Language::from(tree_sitter_php::LANGUAGE_PHP),
    );
}

#[test]
fn compound_assign_reads_target_rust() {
    assert_compound_reads_target(
        b"fn f(y: &str) -> String { let mut x = String::new(); x += y; x }",
        "rust",
        Language::from(tree_sitter_rust::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_java() {
    assert_compound_reads_target(
        b"class A { String f(String y) { String x = \"a\"; x += y; return x; } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_go() {
    assert_compound_reads_target(
        b"package main\nfunc f(y string) string {\n\tx := \"a\"\n\tx += y\n\treturn x\n}\n",
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_c() {
    assert_compound_reads_target(
        b"int f(int y) { int x = 1; x += y; return x; }",
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_cpp() {
    assert_compound_reads_target(
        b"int f(int y) { int x = 1; x <<= y; return x; }",
        "cpp",
        Language::from(tree_sitter_cpp::LANGUAGE),
    );
}

#[test]
fn compound_assign_reads_target_ruby() {
    assert_compound_reads_target(
        b"def f(y)\n  x = 'a'\n  x ||= y\n  x\nend\n",
        "ruby",
        Language::from(tree_sitter_ruby::LANGUAGE),
    );
}

/// A plain `x = y` must not start reading its own target.
#[test]
fn plain_assign_does_not_read_target() {
    let nodes = rmw_all_nodes(
        b"package main\nfunc f(y string) string {\n\tx := \"a\"\n\tx = y\n\treturn x\n}\n",
        "go",
        Language::from(tree_sitter_go::LANGUAGE),
    );
    let n = nodes
        .iter()
        .find(|n| n.taint.defines.as_deref() == Some("x") && n.taint.uses == ["y"])
        .expect("`x = y` should define x from y alone");
    assert!(!n.rmw_assign);
}

/// `n += 1` keeps its literal operand as an Add, so SSA lowering builds
/// `n' = n + 1` instead of a stale copy or the constant `1`.
#[test]
fn compound_assign_literal_operand_is_bin_op() {
    let nodes = rmw_all_nodes(
        b"class A { void f(int n) { n += 1; g(n); } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
    );
    let n = rmw_def_node(&nodes, "n");
    assert_eq!(n.taint.uses, vec!["n".to_string()]);
    assert_eq!(n.bin_op, Some(BinOp::Add));
    assert_eq!(n.bin_op_const, Some(1));
    assert!(n.taint.const_text.is_none());
}

/// The operator comes from the compound token, not from a binary
/// expression inside the right-hand side.
#[test]
fn compound_assign_bin_op_ignores_rhs_operator() {
    let nodes = rmw_all_nodes(
        b"class A { String f(String s, int a, int b) { s += a - b; return s; } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
    );
    assert_eq!(rmw_def_node(&nodes, "s").bin_op, Some(BinOp::Add));
}

/// Python `*=` / `%=` / `/=` work on strings and paths, so they must not
/// type the result as an integer.
#[test]
fn compound_assign_python_overloaded_ops_have_no_bin_op() {
    for op in ["*=", "%=", "/=", "|="] {
        let src = format!("def f(s, y):\n    s {op} y\n    return s\n");
        let nodes = rmw_all_nodes(
            src.as_bytes(),
            "python",
            Language::from(tree_sitter_python::LANGUAGE),
        );
        assert_eq!(rmw_def_node(&nodes, "s").bin_op, None, "python `{op}`");
    }
}

/// A member target reads its own dotted path only, never the receiver:
/// `el.innerHTML += "<b>"` does not read `el` as a value.
#[test]
fn compound_assign_member_target_reads_path_only() {
    let nodes = rmw_all_nodes(
        b"function f(el) { el.innerHTML += '<b>x</b>'; }",
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let n = rmw_def_node(&nodes, "el.innerHTML");
    assert_eq!(n.taint.uses, vec!["el.innerHTML".to_string()]);
}

/// `q += fmt(x)` splits into the call (which neither reads nor defines
/// `q`) and an unlabelled combine node `q = q + <call>` fed by the call.
#[test]
fn compound_assign_call_rhs_splits_off_combine_node() {
    let src = b"function f(x) { let q = 'a'; q += fmt(x); return q; }";
    let fc = parse_to_file_cfg(
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let body = &fc.bodies[1];
    let g = &body.graph;
    let call = g
        .node_indices()
        .find(|&i| g[i].call.callee.as_deref() == Some("fmt"))
        .expect("call node for fmt");
    assert!(g[call].taint.defines.is_none());
    assert!(!g[call].taint.uses.iter().any(|u| u == "q"));
    let succs: Vec<_> = g.neighbors(call).collect();
    assert_eq!(
        succs.len(),
        1,
        "call should flow only into the combine node"
    );
    let combine = &g[succs[0]];
    assert!(combine.rmw_assign && combine.rmw_rhs_from_pred);
    assert_eq!(combine.taint.defines.as_deref(), Some("q"));
    assert_eq!(combine.taint.uses, vec!["q".to_string()]);
    assert!(combine.taint.labels.is_empty());
    assert_eq!(combine.bin_op, Some(BinOp::Add));
}

/// `conn ||= Conn.new(..)` stays a single node that defines the target, so
/// the memoised-acquire idiom keeps its type and resource tracking.
#[test]
fn logical_assign_call_rhs_is_not_split() {
    let nodes = rmw_all_nodes(
        b"def f(dsn)\n  conn ||= PG::Connection.new(dsn)\n  conn\nend\n",
        "ruby",
        Language::from(tree_sitter_ruby::LANGUAGE),
    );
    let n = rmw_def_node(&nodes, "conn");
    assert_eq!(n.kind, StmtKind::Call);
    assert!(!n.rmw_rhs_from_pred);
}

/// Java `x += c ? a : b` must not take the ternary diamond, which rebinds
/// the target as a plain overwrite.
#[test]
fn compound_assign_ternary_rhs_keeps_target() {
    let nodes = rmw_all_nodes(
        b"class A { String f(String x, boolean c, String a, String b) { x += c ? a : b; return x; } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
    );
    let n = rmw_def_node(&nodes, "x");
    assert_eq!(n.taint.uses.first().map(String::as_str), Some("x"));
    assert!(n.taint.uses.iter().any(|u| u == "a"));
    assert!(n.taint.uses.iter().any(|u| u == "b"));
}

/// `counts[k] += 1` updates an existing slot; it is not a
/// prototype-pollution write even with an attacker-chosen key.
#[test]
fn compound_subscript_write_is_not_prototype_pollution_sink() {
    let nodes = rmw_all_nodes(
        b"function f(req) { const counts = {}; counts[req.query.k] += 1; }",
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    assert!(
        !nodes.iter().any(|n| n
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::PROTOTYPE_POLLUTION)))),
        "compound subscript store must not carry a PROTOTYPE_POLLUTION sink"
    );
}

/// `i++` / `--i` define their operand from its old value plus one, so SSA
/// lowering builds `i' = i + 1` instead of leaving `i` unchanged.
fn assert_update_defines_operand(
    src: &[u8],
    lang_str: &str,
    ts_lang: Language,
    var: &str,
    op: BinOp,
) {
    let nodes = rmw_all_nodes(src, lang_str, ts_lang);
    let n = rmw_def_node(&nodes, var);
    assert_eq!(n.taint.uses, vec![var.to_string()], "{lang_str}");
    assert_eq!(n.bin_op, Some(op), "{lang_str}");
    assert_eq!(n.bin_op_const, Some(1), "{lang_str}");
    assert!(n.taint.const_text.is_none(), "{lang_str}");
}

#[test]
fn update_expr_defines_operand_javascript() {
    assert_update_defines_operand(
        b"function f() { let i = 0; i++; return i; }",
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
        "i",
        BinOp::Add,
    );
}

#[test]
fn update_expr_defines_operand_typescript() {
    assert_update_defines_operand(
        b"function f(): number { let i = 0; --i; return i; }",
        "typescript",
        Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        "i",
        BinOp::Sub,
    );
}

#[test]
fn update_expr_defines_operand_java() {
    assert_update_defines_operand(
        b"class A { int f() { int i = 0; i++; return i; } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
        "i",
        BinOp::Add,
    );
}

#[test]
fn update_expr_defines_operand_c() {
    assert_update_defines_operand(
        b"char *f(char *p) { ++p; return p; }",
        "c",
        Language::from(tree_sitter_c::LANGUAGE),
        "p",
        BinOp::Add,
    );
}

#[test]
fn update_expr_defines_operand_cpp() {
    assert_update_defines_operand(
        b"int f() { int n = 3; n--; return n; }",
        "cpp",
        Language::from(tree_sitter_cpp::LANGUAGE),
        "n",
        BinOp::Sub,
    );
}

#[test]
fn update_expr_defines_operand_php() {
    assert_update_defines_operand(
        b"<?php function f() { $i = 0; $i++; return $i; }",
        "php",
        Language::from(tree_sitter_php::LANGUAGE_PHP),
        "i",
        BinOp::Add,
    );
}

#[test]
fn update_expr_defines_operand_go() {
    for (stmt, op) in [("i++", BinOp::Add), ("i--", BinOp::Sub)] {
        let src = format!("package main\nfunc f() int {{\n\ti := 0\n\t{stmt}\n\treturn i\n}}\n");
        assert_update_defines_operand(
            src.as_bytes(),
            "go",
            Language::from(tree_sitter_go::LANGUAGE),
            "i",
            op,
        );
    }
}

/// The `for` update clause is a real definition, so the loop header gets a
/// phi joining the initial value and the incremented one.
#[test]
fn for_update_clause_defines_counter() {
    let nodes = rmw_all_nodes(
        b"function f(xs) { for (let i = 0; i < xs.length; i++) { g(xs[i]); } }",
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let n = rmw_def_node(&nodes, "i");
    assert_eq!(n.bin_op, Some(BinOp::Add));
}

//   Multi-way branches: match / select / case / arrow switch

/// The Call node whose callee is exactly `callee`.
fn call_named(cfg: &Cfg, callee: &str) -> NodeIndex {
    cfg.node_indices()
        .find(|&n| cfg[n].call.callee.as_deref() == Some(callee))
        .unwrap_or_else(|| panic!("expected a Call node for `{callee}`"))
}

/// Nodes reachable from `from` over forward (Seq/True/False) edges,
/// skipping `blocked` nodes.
fn forward_reach(
    cfg: &Cfg,
    from: NodeIndex,
    blocked: &[NodeIndex],
) -> std::collections::HashSet<NodeIndex> {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![from];
    while let Some(n) = stack.pop() {
        if blocked.contains(&n) || !seen.insert(n) {
            continue;
        }
        for e in cfg.edges(n) {
            if matches!(e.weight(), EdgeKind::Seq | EdgeKind::True | EdgeKind::False) {
                stack.push(e.target());
            }
        }
    }
    seen
}

fn rust_cfg(src: &[u8]) -> (Cfg, NodeIndex) {
    parse_and_build(src, "rust", Language::from(tree_sitter_rust::LANGUAGE))
}

fn go_cfg(src: &[u8]) -> (Cfg, NodeIndex) {
    parse_and_build(src, "go", Language::from(tree_sitter_go::LANGUAGE))
}

fn java_cfg(src: &[u8]) -> (Cfg, NodeIndex) {
    parse_and_build(src, "java", Language::from(tree_sitter_java::LANGUAGE))
}

/// Go cases never fall through on their own: case 1's exits leave the
/// switch instead of entering case 2's body.
#[test]
fn go_switch_cases_do_not_fall_through() {
    let (cfg, _) = go_cfg(
        b"package p\nfunc f(x int) {\n\tswitch x {\n\tcase 1:\n\t\ta()\n\tcase 2:\n\t\tb()\n\t}\n\tafter()\n}\n",
    );
    let a = call_named(&cfg, "a");
    let reach = forward_reach(&cfg, a, &[]);
    assert!(
        !reach.contains(&call_named(&cfg, "b")),
        "case 1 must not fall into case 2"
    );
    assert!(
        reach.contains(&call_named(&cfg, "after")),
        "case 1 must exit the switch"
    );
}

/// An explicit `fallthrough` still chains into the next case body.
#[test]
fn go_switch_explicit_fallthrough_chains_next_case() {
    let (cfg, _) = go_cfg(
        b"package p\nfunc f(x int) {\n\tswitch x {\n\tcase 1:\n\t\ta()\n\t\tfallthrough\n\tcase 2:\n\t\tb()\n\t}\n}\n",
    );
    let reach = forward_reach(&cfg, call_named(&cfg, "a"), &[]);
    assert!(reach.contains(&call_named(&cfg, "b")));
}

/// `fallthrough` into a default that sits mid-switch: the default keeps its
/// source position, is entered from case 1 and on no-match, and does not
/// fall into the case after it.
#[test]
fn go_switch_explicit_fallthrough_into_mid_default() {
    let (cfg, entry) = go_cfg(
        b"package p\nfunc f(x int) {\n\tswitch x {\n\tcase 1:\n\t\ta()\n\t\tfallthrough\n\tdefault:\n\t\td()\n\tcase 2:\n\t\tb()\n\t}\n}\n",
    );
    let (a, b, d) = (
        call_named(&cfg, "a"),
        call_named(&cfg, "b"),
        call_named(&cfg, "d"),
    );
    assert!(forward_reach(&cfg, a, &[]).contains(&d));
    assert!(!forward_reach(&cfg, d, &[]).contains(&b));
    assert!(
        forward_reach(&cfg, entry, &[a]).contains(&d),
        "default must be reachable on the no-match path"
    );
}

/// `select` runs exactly one case: a returning case does not make the code
/// after the select unreachable, and cases do not flow into each other.
#[test]
fn go_select_cases_are_exclusive() {
    let (cfg, entry) = go_cfg(
        b"package p\nfunc f(ch chan int, done chan bool) {\n\tselect {\n\tcase <-done:\n\t\treturn\n\tcase <-ch:\n\t\ta()\n\t}\n\tafter()\n}\n",
    );
    let after = call_named(&cfg, "after");
    assert!(forward_reach(&cfg, entry, &[]).contains(&after));
    assert!(forward_reach(&cfg, call_named(&cfg, "a"), &[]).contains(&after));
    // The last case is the fallback, so the only dispatch test is case 1's.
    assert_eq!(if_nodes(&cfg).len(), 1);
}

/// The Go switch initializer and a call in the tag expression both get
/// CFG nodes ahead of the dispatch.
#[test]
fn go_switch_init_and_call_tag_are_lowered() {
    let (cfg, _) =
        go_cfg(b"package p\nfunc f() {\n\tswitch x := g(); h(x) {\n\tcase 1:\n\t\ta()\n\t}\n}\n");
    let g_node = call_named(&cfg, "g");
    assert_eq!(cfg[g_node].taint.defines.as_deref(), Some("x"));
    let h = call_named(&cfg, "h");
    assert!(forward_reach(&cfg, g_node, &[]).contains(&h));
    assert!(forward_reach(&cfg, h, &[]).contains(&call_named(&cfg, "a")));
}

/// `switch t := v.(type)` binds `t` from `v` for every clause.
#[test]
fn go_type_switch_alias_is_bound() {
    let (cfg, _) = go_cfg(
        b"package p\nfunc f(v interface{}) {\n\tswitch t := v.(type) {\n\tcase string:\n\t\tuse(t)\n\t}\n}\n",
    );
    let bind = find_node_defining(&cfg, "t").expect("alias binding node");
    assert_eq!(bind.taint.uses, vec!["v".to_string()]);
}

/// A statement-level `match` lowers to one dispatch header per non-default
/// arm, every arm body gets its own nodes, and arms do not flow into each
/// other.
#[test]
fn rust_match_stmt_builds_dispatch_cascade() {
    let (cfg, _) = rust_cfg(
        b"fn f(m: u8) {\n    match m {\n        1 => a(),\n        2 => { b(); }\n        _ => c(),\n    }\n    after();\n}\n",
    );
    assert_eq!(if_nodes(&cfg).len(), 2);
    let a = call_named(&cfg, "a");
    let reach = forward_reach(&cfg, a, &[]);
    assert!(!reach.contains(&call_named(&cfg, "b")));
    assert!(!reach.contains(&call_named(&cfg, "c")));
    assert!(reach.contains(&call_named(&cfg, "after")));
    let conds: Vec<_> = if_nodes(&cfg)
        .into_iter()
        .filter_map(|n| cfg[n].condition_text.clone())
        .collect();
    assert!(conds.contains(&"m == 1".to_string()), "got {conds:?}");
}

/// `match` is exhaustive: the last arm is the fallback, so control cannot
/// reach the code after the match without running one of the arms.
#[test]
fn rust_match_last_arm_is_default() {
    let (cfg, entry) = rust_cfg(
        b"fn f(r: Result<u8, u8>) {\n    match r {\n        Ok(v) => a(v),\n        Err(e) => b(e),\n    }\n    after();\n}\n",
    );
    let (a, b) = (call_named(&cfg, "a"), call_named(&cfg, "b"));
    assert!(forward_reach(&cfg, entry, &[]).contains(&call_named(&cfg, "after")));
    assert!(
        !forward_reach(&cfg, entry, &[a, b]).contains(&call_named(&cfg, "after")),
        "no no-match path may skip both arms"
    );
}

/// Pattern bindings are defined from the scrutinee at the start of the arm.
#[test]
fn rust_match_arm_binding_defines_from_scrutinee() {
    let (cfg, _) = rust_cfg(
        b"fn f(r: Result<String, E>) {\n    match r {\n        Ok(Foo { x, y: z }) => sink(x, z),\n        _ => {}\n    }\n}\n",
    );
    let bind = find_node_defining(&cfg, "x").expect("binding node for x");
    assert_eq!(bind.taint.extra_defines, vec!["z".to_string()]);
    assert_eq!(bind.taint.uses, vec!["r".to_string()]);
    let sink = call_named(&cfg, "sink");
    let bind_idx = cfg
        .node_indices()
        .find(|&n| cfg[n].taint.defines.as_deref() == Some("x"))
        .unwrap();
    assert!(forward_reach(&cfg, bind_idx, &[]).contains(&sink));
}

/// A call scrutinee gets its own Call node, and its value reaches the arm
/// bindings through a synthetic name.
#[test]
fn rust_match_call_scrutinee_gets_own_node() {
    let (cfg, _) = rust_cfg(
        b"fn f() {\n    match env::var(\"X\") {\n        Ok(v) => run(v),\n        Err(_) => {}\n    }\n}\n",
    );
    let scrut = cfg
        .node_indices()
        .find(|&n| {
            cfg[n].kind == StmtKind::Call
                && cfg[n]
                    .call
                    .callee
                    .as_deref()
                    .is_some_and(|c| c.contains("env::var"))
        })
        .expect("scrutinee Call node");
    let synth = cfg[scrut].taint.defines.clone().expect("synthetic define");
    assert!(synth.starts_with("__nyx_scrut_"));
    let bind = find_node_defining(&cfg, "v").expect("binding node for v");
    assert_eq!(bind.taint.uses, vec![synth]);
}

/// A guarded arm is a second test: its guard header carries the guard as
/// its condition, and the guard's False edge continues the dispatch.
#[test]
fn rust_match_guard_gets_its_own_branch() {
    let (cfg, _) = rust_cfg(
        b"fn f(x: Option<String>) {\n    match x {\n        Some(v) if ok(&v) => a(v),\n        _ => b(),\n    }\n}\n",
    );
    let guard = if_nodes(&cfg)
        .into_iter()
        .find(|&n| cfg[n].condition_text.as_deref() == Some("ok(&v)"))
        .expect("guard header");
    let a = call_named(&cfg, "a");
    let b = call_named(&cfg, "b");
    assert!(
        cfg.edges(guard)
            .any(|e| matches!(e.weight(), EdgeKind::False))
    );
    assert!(forward_reach(&cfg, guard, &[a]).contains(&b));
    // The binding runs before the guard reads it.
    let bind = cfg
        .node_indices()
        .find(|&n| cfg[n].taint.defines.as_deref() == Some("v"))
        .expect("binding node");
    assert!(forward_reach(&cfg, bind, &[]).contains(&guard));
}

/// `break` inside a match arm leaves the enclosing loop, not the match.
#[test]
fn rust_match_break_in_arm_targets_loop_exit() {
    let (cfg, _) = rust_cfg(
        b"fn f(rx: R) {\n    loop {\n        match rx.recv() {\n            Ok(m) => h(m),\n            Err(_) => break,\n        }\n        tick();\n    }\n    after();\n}\n",
    );
    let brk = cfg
        .node_indices()
        .find(|&n| cfg[n].kind == StmtKind::Break)
        .expect("break node");
    let reach = forward_reach(&cfg, brk, &[]);
    assert!(reach.contains(&call_named(&cfg, "after")));
    assert!(
        !reach.contains(&call_named(&cfg, "tick")),
        "break must skip the rest of the loop body"
    );
}

/// `let y = match ..` keeps its single-node lowering.
#[test]
fn rust_let_match_stays_single_node() {
    let (cfg, _) = rust_cfg(b"fn f(m: u8) {\n    let y = match m { 1 => a(), _ => b() };\n}\n");
    assert!(if_nodes(&cfg).is_empty());
    assert!(find_node_defining(&cfg, "y").is_some());
}

/// Statement-level `unsafe { .. }` and bare `{ .. }` blocks are walked, so
/// the calls inside them get their own nodes.
#[test]
fn rust_stmt_unsafe_and_bare_blocks_are_walked() {
    let (cfg, _) = rust_cfg(b"fn f() {\n    unsafe { a(); }\n    { b(); }\n}\n");
    let a = call_named(&cfg, "a");
    assert!(forward_reach(&cfg, a, &[]).contains(&call_named(&cfg, "b")));
}

/// An arm that emits no node still gets a branch target, so the header keeps
/// distinct True and False successors.
#[test]
fn empty_match_arm_keeps_branch_labels() {
    let (cfg, _) = rust_cfg(
        b"fn f(m: &str) {\n    match m {\n        \"q\" => return,\n        _ => {}\n    }\n    after();\n}\n",
    );
    let [header] = if_nodes(&cfg)[..] else {
        panic!("expected one dispatch header");
    };
    let true_tgt = cfg
        .edges(header)
        .find(|e| matches!(e.weight(), EdgeKind::True))
        .map(|e| e.target());
    let false_tgt = cfg
        .edges(header)
        .find(|e| matches!(e.weight(), EdgeKind::False))
        .map(|e| e.target());
    assert!(true_tgt.is_some() && false_tgt.is_some() && true_tgt != false_tgt);
    assert!(forward_reach(&cfg, false_tgt.unwrap(), &[]).contains(&call_named(&cfg, "after")));
}

/// Python `match`: cases are exclusive, `case _` is the default, and a
/// capture pattern binds from the subject.
#[test]
fn python_match_cases_exclusive_with_bindings() {
    let src = b"def f(m, d):\n    match m:\n        case \"a\":\n            x = 1\n        case str(v):\n            run(v)\n        case _:\n            other()\n    after()\n";
    let (cfg, _) = parse_and_build(src, "python", Language::from(tree_sitter_python::LANGUAGE));
    assert_eq!(if_nodes(&cfg).len(), 2);
    let x_def = cfg
        .node_indices()
        .find(|&n| cfg[n].taint.defines.as_deref() == Some("x"))
        .expect("x = 1");
    let reach = forward_reach(&cfg, x_def, &[]);
    assert!(!reach.contains(&call_named(&cfg, "run")));
    assert!(!reach.contains(&call_named(&cfg, "other")));
    assert!(reach.contains(&call_named(&cfg, "after")));
    let bind = find_node_defining(&cfg, "v").expect("capture binding");
    assert_eq!(bind.taint.uses, vec!["m".to_string()]);
}

/// Ruby `case`/`when`/`else`: `else` is the default arm and `when` arms
/// are exclusive.
#[test]
fn ruby_case_when_else_is_default() {
    let src = b"def f(m)\n  case m\n  when \"a\" then a()\n  when \"b\" then b()\n  else c()\n  end\n  after()\nend\n";
    let (cfg, _) = parse_and_build(src, "ruby", Language::from(tree_sitter_ruby::LANGUAGE));
    assert_eq!(if_nodes(&cfg).len(), 2);
    let reach = forward_reach(&cfg, call_named(&cfg, "a"), &[]);
    assert!(!reach.contains(&call_named(&cfg, "b")));
    assert!(!reach.contains(&call_named(&cfg, "c")));
    assert!(reach.contains(&call_named(&cfg, "after")));
}

/// Java arrow rules are recognised as cases: their bodies are lowered
/// statement by statement and do not fall into the next rule.
#[test]
fn java_arrow_switch_rule_bodies_lowered() {
    let src = b"class S { void m(String m, String p) {\n  switch (m) {\n    case \"a\" -> Runtime.getRuntime().exec(p);\n    case \"b\" -> { x = 1; foo(x); }\n    default -> bar();\n  }\n} }\n";
    let (cfg, _) = java_cfg(src);
    assert_eq!(if_nodes(&cfg).len(), 2);
    let exec = cfg
        .node_indices()
        .find(|&n| {
            cfg[n]
                .call
                .callee
                .as_deref()
                .is_some_and(|c| c.contains("exec"))
        })
        .expect("exec Call node");
    let reach = forward_reach(&cfg, exec, &[]);
    assert!(!reach.contains(&call_named(&cfg, "foo")));
    assert!(!reach.contains(&call_named(&cfg, "bar")));
    let conds: Vec<_> = if_nodes(&cfg)
        .into_iter()
        .filter_map(|n| cfg[n].condition_text.clone())
        .collect();
    assert!(conds.contains(&"m == \"a\"".to_string()), "got {conds:?}");
}

/// Java's `default` sits inside the `switch_label`; the colon form must
/// still treat it as the default arm (no dispatch header of its own).
#[test]
fn java_colon_switch_default_detected() {
    let (cfg, _) =
        java_cfg(b"class S { void m(int x) { switch (x) { case 1: a(); break; default: c(); } } }");
    assert_eq!(if_nodes(&cfg).len(), 1);
}

/// `case String s ->` binds `s` and synthesizes no `==` condition.
#[test]
fn java_type_pattern_case_binds_without_condition() {
    let (cfg, _) = java_cfg(
        b"class S { void m(Object o) { switch (o) { case String s -> use(s); default -> {} } } }",
    );
    let bind = find_node_defining(&cfg, "s").expect("pattern binding");
    assert_eq!(bind.taint.uses, vec!["o".to_string()]);
    assert!(
        if_nodes(&cfg)
            .iter()
            .all(|&n| cfg[n].condition_text.is_none())
    );
}

/// `outer: for (..) { .. }` walks the labeled loop.
#[test]
fn java_labeled_for_walks_body() {
    let (cfg, _) = java_cfg(
        b"class S { void m(String[] ids) { outer: for (String id : ids) { st.executeUpdate(id); } } }",
    );
    assert!(cfg.node_indices().any(|n| {
        cfg[n]
            .call
            .callee
            .as_deref()
            .is_some_and(|c| c.contains("executeUpdate"))
    }));
}

/// A call in a JS switch discriminant gets its own Call node.
#[test]
fn js_switch_call_discriminant_lowered() {
    let (cfg, _) = parse_and_build(
        b"function f(x) { switch (g(x)) { case 1: a(); } }",
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    let g_node = call_named(&cfg, "g");
    assert!(forward_reach(&cfg, g_node, &[]).contains(&call_named(&cfg, "a")));
}

//   Branch and loop headers: classified from the condition only

fn lang_cfg(lang: &str, src: &[u8]) -> (Cfg, NodeIndex) {
    let ts_lang = match lang {
        "javascript" => Language::from(tree_sitter_javascript::LANGUAGE),
        "python" => Language::from(tree_sitter_python::LANGUAGE),
        "ruby" => Language::from(tree_sitter_ruby::LANGUAGE),
        "rust" => Language::from(tree_sitter_rust::LANGUAGE),
        "go" => Language::from(tree_sitter_go::LANGUAGE),
        "java" => Language::from(tree_sitter_java::LANGUAGE),
        "c" => Language::from(tree_sitter_c::LANGUAGE),
        "php" => Language::from(tree_sitter_php::LANGUAGE_PHP),
        other => panic!("unsupported test language {other}"),
    };
    parse_and_build(src, lang, ts_lang)
}

fn header_nodes(cfg: &Cfg) -> Vec<NodeIndex> {
    cfg.node_indices()
        .filter(|&n| matches!(cfg[n].kind, StmtKind::If | StmtKind::Loop))
        .collect()
}

fn has_any_sink(info: &NodeInfo) -> bool {
    info.taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(_)))
}

/// A loop over a member read whose prefix is a Source is itself a read of
/// that Source, so its header carries the Source label.  Nothing of the loop
/// body (here a gated sink call) reaches the header.
#[test]
fn for_of_header_over_a_source_field_takes_only_that_source() {
    let src = b"function h(req) { for (const id of req.body.ids) { fetch(\"https://x\"); } }";
    let (cfg, _) = lang_cfg("javascript", src);
    let headers = header_nodes(&cfg);
    assert!(!headers.is_empty());
    for h in headers {
        let info = &cfg[h];
        assert!(
            !info.taint.labels.is_empty()
                && info
                    .taint
                    .labels
                    .iter()
                    .all(|l| matches!(l, DataLabel::Source(_))),
            "{:?}",
            info.taint.labels
        );
        assert!(info.call.sink_payload_args.is_none());
    }
}

/// A sink call in a branch or loop body labels its own node, never the
/// header: neither the gated-sink walk nor the statement text may reach
/// into the body.
#[test]
fn header_nodes_do_not_take_labels_from_the_body() {
    let cases: &[(&str, &[u8], &str)] = &[
        (
            "javascript",
            b"function h(req, db) { const f = req.query.f; if (f === \"y\") { db.query(\"SELECT 1\"); } }",
            "db.query",
        ),
        (
            "javascript",
            b"function h(req) { let n = req.query.n; while (n > 0) { fetch(\"https://x\"); n--; } }",
            "fetch",
        ),
        (
            "javascript",
            b"function h(req, cp) { const flag = req.query.f; do { cp.exec(\"ls\"); } while (flag); }",
            "cp.exec",
        ),
        (
            "javascript",
            b"function h(req, pool) { const id = req.query.id; for (let i = 0; i < id.length; i++) { pool.query(\"SELECT now()\"); } }",
            "pool.query",
        ),
        (
            "javascript",
            b"function h(ids) { for (const id of ids) { fetch(\"https://x\"); } }",
            "fetch",
        ),
        (
            "javascript",
            b"function h(req, exec) { const c = req.query.c; if (c) exec(\"ls\"); }",
            "exec",
        ),
        (
            "python",
            b"def h(self, flag):\n    if flag:\n        self.cursor.execute(\"select 1\")\n",
            "self.cursor.execute",
        ),
        (
            "python",
            b"def h(event):\n    if event == \"a\":\n        pass\n    elif event == \"push\":\n        requests.post(\"https://h\", json={})\n",
            "requests.post",
        ),
        (
            "python",
            b"def h(cmd):\n    while cmd:\n        subprocess.run(cmd, shell=True)\n        break\n",
            "subprocess.run",
        ),
        (
            "ruby",
            b"def h(mode)\n  if mode == \"x\"\n    User.connection.execute(\"SELECT 1\")\n  end\nend\n",
            "execute",
        ),
        (
            "ruby",
            b"def h(payload)\n  unless payload =~ /a/\n    x = 1\n  else\n    STDOUT.print(payload)\n  end\nend\n",
            "STDOUT.print",
        ),
        (
            "rust",
            b"fn h(p: &str, flag: bool) { if flag { std::fs::remove_file(p).unwrap(); } }",
            "std::fs::remove_file",
        ),
        (
            "c",
            b"int main(int argc, char **argv) { if (argc > 1) { execv(\"/bin/ls\", argv); } return 0; }",
            "execv",
        ),
        (
            "go",
            b"package main\nfunc h(flag bool) {\n\tif flag {\n\t\texec.Command(\"ls\").Run()\n\t}\n}\n",
            "exec.Command",
        ),
    ];
    for (lang, src, body_callee) in cases {
        let (cfg, _) = lang_cfg(lang, src);
        let headers = header_nodes(&cfg);
        assert!(!headers.is_empty(), "{lang}: no header node");
        for h in headers {
            let info = &cfg[h];
            assert!(
                info.taint.labels.is_empty(),
                "{lang}: header took labels {:?} from its body",
                info.taint.labels
            );
            assert!(info.call.callee.is_none(), "{lang}: {:?}", info.call.callee);
            assert!(info.call.sink_payload_args.is_none(), "{lang}");
            assert!(info.call.gate_filters.is_empty(), "{lang}");
        }
        assert!(
            cfg.node_indices().any(|n| cfg[n]
                .call
                .callee
                .as_deref()
                .is_some_and(|c| c.contains(body_callee))),
            "{lang}: the body call `{body_callee}` lost its node"
        );
    }
}

/// A Rust `loop {}` header evaluates nothing: no uses, no labels.
#[test]
fn rust_loop_header_is_empty() {
    let (cfg, _) = rust_cfg(
        b"fn h(name: String) { loop { std::process::Command::new(\"ls\").status().unwrap(); println!(\"{}\", name); break; } }",
    );
    let headers = header_nodes(&cfg);
    assert_eq!(headers.len(), 1);
    let info = &cfg[headers[0]];
    assert!(info.taint.uses.is_empty(), "{:?}", info.taint.uses);
    assert!(info.taint.labels.is_empty());
}

/// Header uses are the condition's identifiers.  A C-style `for` keeps its
/// init / update clauses (Go and Java do not lower them separately) but
/// never the body.
#[test]
fn header_uses_come_from_the_condition() {
    let (cfg, _) = lang_cfg(
        "javascript",
        b"function h(f, q, db) { if (f === \"y\") { db.query(q); } }",
    );
    let h = header_nodes(&cfg)[0];
    assert_eq!(cfg[h].taint.uses, vec!["f".to_string()]);

    let (cfg, _) = lang_cfg(
        "python",
        b"def h(a, mode, payload):\n    if a:\n        pass\n    elif mode == \"x\":\n        send(payload)\n",
    );
    for h in header_nodes(&cfg) {
        assert!(
            !cfg[h].taint.uses.contains(&"payload".to_string()),
            "{:?}",
            cfg[h].taint.uses
        );
    }

    let (cfg, _) = go_cfg(
        b"package main\nfunc h(n int, body string) {\n\tfor i := 0; i < n; i++ {\n\t\tuse(body)\n\t}\n}\n",
    );
    let h = header_nodes(&cfg)[0];
    let uses = &cfg[h].taint.uses;
    assert!(uses.contains(&"i".to_string()) && uses.contains(&"n".to_string()));
    assert!(!uses.contains(&"body".to_string()), "{uses:?}");
}

/// Header work is proportional to the condition, not the nested body: the
/// uses summed over a long else-if chain stay linear in its length.
#[test]
fn else_if_chain_header_uses_are_linear() {
    let mut src = String::from("function h(x, y) {\n");
    for i in 0..20 {
        let kw = if i == 0 { "if" } else { "} else if" };
        src.push_str(&format!("  {kw} (x === {i}) {{\n    y = g{i}(y);\n"));
    }
    src.push_str("  }\n}\n");
    let (cfg, _) = lang_cfg("javascript", src.as_bytes());
    let headers: Vec<_> = if_nodes(&cfg);
    assert_eq!(headers.len(), 20);
    let total: usize = headers.iter().map(|&h| cfg[h].taint.uses.len()).sum();
    assert_eq!(total, 20, "each header reads only `x`");
}

/// Calls in the condition still classify the header: an output-parameter
/// source (`fgets`) in `if`, `while`, `do .. while` and a C-style `for`, a
/// bare call condition (Python, Ruby), an elif condition, and an `if let`
/// value.
#[test]
fn header_condition_calls_still_classify() {
    let cases: &[(&str, &[u8])] = &[
        (
            "c",
            b"void f(void) { char buf[10]; if (!fgets(buf, 10, stdin)) return; system(buf); }",
        ),
        (
            "c",
            b"void f(void) { char buf[10]; while (fgets(buf, 10, stdin)) { system(buf); } }",
        ),
        (
            "c",
            b"void f(void) { char buf[10]; do { puts(\"x\"); } while (!fgets(buf, 10, stdin)); }",
        ),
        (
            "c",
            b"void f(void) { char buf[10]; for (; fgets(buf, 10, stdin); ) { system(buf); } }",
        ),
        ("python", b"def h(cmd):\n    if os.system(cmd):\n        pass\n"),
        (
            "python",
            b"def h(cmd):\n    if cmd == \"a\":\n        pass\n    elif os.system(cmd):\n        pass\n",
        ),
        ("ruby", b"def h(cmd)\n  if system(cmd)\n    x = 1\n  end\nend\n"),
        (
            "rust",
            b"fn h() { if let Ok(c) = std::env::var(\"X\") { run(c); } }",
        ),
    ];
    for (lang, src) in cases {
        let (cfg, _) = lang_cfg(lang, src);
        assert!(
            header_nodes(&cfg)
                .iter()
                .any(|&h| !cfg[h].taint.labels.is_empty()),
            "{lang}: condition call lost its label:\n{}",
            String::from_utf8_lossy(src)
        );
    }
}

/// A gated sink in the condition (`await axios.get(url)`) gates on the
/// condition call itself, with its own argument positions.
#[test]
fn header_condition_gated_sink_uses_condition_call() {
    let (cfg, _) = lang_cfg(
        "javascript",
        b"async function h(url) { if (await axios.get(url)) { log(1); } }",
    );
    let h = header_nodes(&cfg)[0];
    assert!(has_any_sink(&cfg[h]), "{:?}", cfg[h].taint.labels);
    assert_eq!(cfg[h].call.callee.as_deref(), Some("axios.get"));
    assert_eq!(cfg[h].call.arg_uses, vec![vec!["url".to_string()]]);
}

/// A for-each header classifies on its iterable, in every language.
#[test]
fn for_each_header_classifies_iterable() {
    let (cfg, _) = lang_cfg(
        "javascript",
        b"function h(req) { for (const x of req.body) { use(x); } }",
    );
    let h = header_nodes(&cfg)[0];
    assert!(
        cfg[h]
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_))),
        "{:?}",
        cfg[h].taint.labels
    );

    // Go: the iterable is `range_clause.right`; an index iterable
    // classifies on its base call.
    let (cfg, _) = go_cfg(
        b"package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tfor _, v := range r.URL.Query()[\"c\"] {\n\t\tuse(v)\n\t}\n}\n",
    );
    let h = header_nodes(&cfg)[0];
    assert!(
        cfg[h]
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_))),
        "{:?}",
        cfg[h].taint.labels
    );
    let info = &cfg[h];
    assert!(
        info.taint.defines.as_deref() == Some("v")
            || info.taint.extra_defines.contains(&"v".into())
    );
}

//   try / finally and begin / ensure on early exits

fn exit_node(cfg: &Cfg) -> NodeIndex {
    cfg.node_indices()
        .find(|&n| cfg[n].kind == StmtKind::Exit)
        .expect("function body has an Exit node")
}

fn return_nodes(cfg: &Cfg) -> Vec<NodeIndex> {
    cfg.node_indices()
        .filter(|&n| cfg[n].kind == StmtKind::Return)
        .collect()
}

fn calls_named(cfg: &Cfg, callee: &str) -> Vec<NodeIndex> {
    cfg.node_indices()
        .filter(|&n| cfg[n].call.callee.as_deref() == Some(callee))
        .collect()
}

fn reachable_from_entry(cfg: &Cfg, entry: NodeIndex) -> usize {
    let mut bfs = petgraph::visit::Bfs::new(cfg, entry);
    let mut n = 0;
    while bfs.next(cfg).is_some() {
        n += 1;
    }
    n
}

/// `return` in the try body runs the finally clause before leaving: the
/// clause is reachable (it used to be an orphan when every path returned),
/// the return reaches the exit only through it, and the clause is lowered
/// once, not once per path.
#[test]
fn return_in_try_runs_finally_in_every_language() {
    let cases: &[(&str, &[u8])] = &[
        (
            "javascript",
            b"function f() { try { return a(); } finally { cleanup(); } }",
        ),
        (
            "java",
            b"class C { int f() { try { return a(); } finally { cleanup(); } } }",
        ),
        (
            "python",
            b"def f():\n    try:\n        return a()\n    finally:\n        cleanup()\n",
        ),
        (
            "php",
            b"<?php function f() { try { return a(); } finally { cleanup(); } }",
        ),
        (
            "ruby",
            b"def f\n  begin\n    return a()\n  ensure\n    cleanup()\n  end\nend\n",
        ),
        // Method-level `ensure` without a `begin`.
        ("ruby", b"def f\n  return a()\nensure\n  cleanup()\nend\n"),
    ];
    for (lang, src) in cases {
        let (cfg, entry) = lang_cfg(lang, src);
        let src_text = String::from_utf8_lossy(src);
        assert_eq!(
            reachable_from_entry(&cfg, entry),
            cfg.node_count(),
            "{lang}: orphan node:\n{src_text}"
        );
        let cleanup = calls_named(&cfg, "cleanup");
        assert_eq!(cleanup.len(), 1, "{lang}: finally lowered once\n{src_text}");
        let cleanup = cleanup[0];

        let exit = exit_node(&cfg);
        let (tails, real): (Vec<NodeIndex>, Vec<NodeIndex>) = return_nodes(&cfg)
            .into_iter()
            .partition(|&r| cfg[r].finally_tail);
        assert_eq!((real.len(), tails.len()), (1, 1), "{lang}\n{src_text}");
        let (ret, tail) = (real[0], tails[0]);
        assert!(cfg[ret].finally_return, "{lang}");
        assert!(
            !cfg.contains_edge(ret, exit),
            "{lang}: the return left the function without running the finally clause"
        );
        assert!(
            forward_reach(&cfg, ret, &[]).contains(&cleanup),
            "{lang}: the return does not reach the finally clause"
        );
        assert!(
            forward_reach(&cfg, cleanup, &[]).contains(&tail),
            "{lang}: the finally clause does not reach the tail"
        );
        assert!(
            cfg.contains_edge(tail, exit),
            "{lang}: tail must reach Exit"
        );
    }
}

/// A return in a catch handler runs the clause too, and with every path
/// returning there is no normal-path copy left over.
#[test]
fn return_in_catch_runs_finally_once() {
    let (cfg, entry) = lang_cfg(
        "javascript",
        b"function f() { try { return a(); } catch (e) { return b(); } finally { c(); } }",
    );
    assert_eq!(reachable_from_entry(&cfg, entry), cfg.node_count());
    assert_eq!(calls_named(&cfg, "c").len(), 1);
    let exit = exit_node(&cfg);
    let c = calls_named(&cfg, "c")[0];
    let rerouted: Vec<_> = return_nodes(&cfg)
        .into_iter()
        .filter(|&r| cfg[r].finally_return)
        .collect();
    assert_eq!(rerouted.len(), 2);
    for r in rerouted {
        assert!(!cfg.contains_edge(r, exit));
        assert!(forward_reach(&cfg, r, &[]).contains(&c));
    }
}

/// A return on only some paths: the clause exists on the normal path and on
/// the return path, and both reach the exit.
#[test]
fn partial_return_runs_finally_on_both_paths() {
    let (cfg, entry) = lang_cfg(
        "javascript",
        b"function f(x) { try { if (x) { return a(); } b(); } finally { c(); } d(); }",
    );
    assert_eq!(reachable_from_entry(&cfg, entry), cfg.node_count());
    let copies = calls_named(&cfg, "c");
    assert_eq!(copies.len(), 2, "normal-path copy and early-exit copy");
    let exit = exit_node(&cfg);
    let ret = return_nodes(&cfg)
        .into_iter()
        .find(|&r| cfg[r].finally_return)
        .expect("the return is rerouted");
    let reached_from_ret = forward_reach(&cfg, ret, &[]);
    let early = copies
        .iter()
        .copied()
        .find(|c| reached_from_ret.contains(c))
        .unwrap();
    let normal = copies.iter().copied().find(|&c| c != early).unwrap();
    // The code after the try follows the normal copy only.
    let d = call_named(&cfg, "d");
    assert!(forward_reach(&cfg, normal, &[]).contains(&d));
    assert!(!forward_reach(&cfg, early, &[]).contains(&d));
    assert!(forward_reach(&cfg, early, &[]).contains(&exit));
}

/// The inner clause runs before the outer one on the return path.
#[test]
fn nested_finally_runs_inner_before_outer() {
    let (cfg, entry) = lang_cfg(
        "javascript",
        b"function f() { try { try { return a(); } finally { inner(); } } finally { outer(); } }",
    );
    assert_eq!(reachable_from_entry(&cfg, entry), cfg.node_count());
    let (inner, outer) = (call_named(&cfg, "inner"), call_named(&cfg, "outer"));
    let ret = return_nodes(&cfg)
        .into_iter()
        .find(|&r| cfg[r].finally_return)
        .unwrap();
    assert!(forward_reach(&cfg, ret, &[]).contains(&inner));
    assert!(
        !forward_reach(&cfg, ret, &[inner]).contains(&outer),
        "the outer clause ran without the inner one"
    );
    assert!(forward_reach(&cfg, inner, &[]).contains(&outer));
    // Only the outermost tail is a Return: the inner tail flows on.
    let tails: Vec<_> = return_nodes(&cfg)
        .into_iter()
        .filter(|&r| cfg[r].finally_tail)
        .collect();
    assert_eq!(tails.len(), 1);
    assert!(forward_reach(&cfg, outer, &[]).contains(&tails[0]));
}

/// A return inside the clause is the clause's own and is not rerouted
/// through the clause it sits in.
#[test]
fn return_inside_finally_is_not_rerouted() {
    let (cfg, entry) = lang_cfg(
        "javascript",
        b"function f() { try { return a(); } finally { return b(); } }",
    );
    assert_eq!(reachable_from_entry(&cfg, entry), cfg.node_count());
    let exit = exit_node(&cfg);
    let own: Vec<_> = return_nodes(&cfg)
        .into_iter()
        .filter(|&r| !cfg[r].finally_return && !cfg[r].finally_tail)
        .collect();
    assert!(!own.is_empty());
    for r in own {
        assert!(cfg.contains_edge(r, exit));
    }
}

/// Without a finally clause nothing changes: the return goes to the exit.
#[test]
fn return_without_finally_keeps_exit_edge() {
    let (cfg, _) = lang_cfg(
        "javascript",
        b"function f() { try { return a(); } catch (e) { b(); } }",
    );
    let exit = exit_node(&cfg);
    for r in return_nodes(&cfg) {
        assert!(!cfg[r].finally_return && !cfg[r].finally_tail);
        assert!(cfg.contains_edge(r, exit));
    }
}

/// The tail returns what the original returns returned, so ownership of a
/// returned resource still reads as handed to the caller.
#[test]
fn finally_tail_carries_the_returned_names() {
    let (cfg, _) = lang_cfg(
        "javascript",
        b"function f(r) { try { if (r) { return r; } return s; } finally { audit(); } }",
    );
    let tail = return_nodes(&cfg)
        .into_iter()
        .find(|&r| cfg[r].finally_tail)
        .unwrap();
    let mut uses = cfg[tail].taint.uses.clone();
    uses.sort();
    assert_eq!(uses, vec!["r".to_string(), "s".to_string()]);
}

/// A function declared in the clause is registered once even though the
/// clause is lowered for two paths.
#[test]
fn closure_in_duplicated_finally_has_one_body() {
    let src = b"function f(x) { try { if (x) { return a(); } b(); } finally { run(function () { inner(); }); } }";
    let file_cfg = parse_to_file_cfg(
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    // top level, f, and the closure
    assert_eq!(file_cfg.bodies.len(), 3);
    let spans: std::collections::HashSet<_> = file_cfg
        .bodies
        .iter()
        .skip(1)
        .map(|b| b.meta.span)
        .collect();
    assert_eq!(spans.len(), 2, "no body is registered twice");
}

/// With every path returning there is no normal-path copy, so a closure in
/// the clause is still registered by the early-exit copy.
#[test]
fn closure_in_only_finally_copy_is_registered() {
    let src = b"function f() { try { return a(); } finally { run(function () { inner(); }); } }";
    let file_cfg = parse_to_file_cfg(
        src,
        "javascript",
        Language::from(tree_sitter_javascript::LANGUAGE),
    );
    assert_eq!(file_cfg.bodies.len(), 3);
}

// ── nested_calls (per-operand call nesting) ──────────────────────────────

/// The nested-call record of the first node whose callee is `callee`.
fn nested_calls_of<'a>(cfg: &'a Cfg, callee: &str) -> Option<&'a NestedCallTree> {
    cfg.node_indices()
        .map(|i| &cfg[i])
        .find(|n| n.call.callee.as_deref() == Some(callee))
        .and_then(|n| n.call.nested_calls.as_deref())
}

fn occ<'a>(tree: &'a NestedCallTree, text: &'a str) -> Vec<&'a NestedUse> {
    tree.uses_of(text).collect()
}

#[test]
fn nested_calls_separates_sanitized_and_sibling_operands() {
    let src =
        b"function f(name, bio) { const html = \"<p>\" + escapeHtml(name) + \"</p>\" + bio; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let tree = nested_calls_of(&cfg, "escapeHtml").expect("record for a call beside an operand");
    assert_eq!(tree.calls.len(), 1);
    assert_eq!(tree.anchor, Some(0));
    let name = occ(tree, "name");
    assert_eq!(name.len(), 1);
    assert_eq!((name[0].call, name[0].slot), (Some(0), CallSlot::Arg(0)));
    let bio = occ(tree, "bio");
    assert_eq!(bio.len(), 1);
    assert_eq!(bio[0].call, None, "`bio` sits outside every call");
    assert!(
        occ(tree, "html").is_empty(),
        "the declared name is written, not read"
    );
}

#[test]
fn nested_calls_absent_for_a_single_call_statement() {
    let src = b"function f(x) { const y = g(x); h(y.a, y); return k(x); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    for i in cfg.node_indices() {
        assert!(
            cfg[i].call.nested_calls.is_none(),
            "single-call node {:?} must not carry a record",
            cfg[i].call.callee
        );
    }
}

#[test]
fn nested_calls_records_wrapper_argument_positions_go() {
    let src = b"package main\nfunc h(w W, f string, a string, b string) { fmt.Fprintf(w, f, html.EscapeString(a), b) }\n";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "go", ts_lang);
    let tree = nested_calls_of(&cfg, "fmt.Fprintf").expect("record for a nested call");
    let anchor = tree.anchor.expect("anchor is the Fprintf call") as usize;
    assert_eq!(tree.calls[anchor].callee, "fmt.Fprintf");
    assert_eq!(tree.calls[anchor].arity, Some(4));
    let esc = tree
        .calls
        .iter()
        .position(|c| c.callee == "html.EscapeString")
        .expect("inner call recorded");
    assert_eq!(tree.calls[esc].parent, Some(anchor as u16));
    assert_eq!(tree.calls[esc].slot, CallSlot::Arg(2));
    let a = occ(tree, "a");
    assert_eq!((a[0].call, a[0].slot), (Some(esc as u16), CallSlot::Arg(0)));
    let b = occ(tree, "b");
    assert_eq!(
        (b[0].call, b[0].slot),
        (Some(anchor as u16), CallSlot::Arg(3))
    );
}

#[test]
fn nested_calls_template_substitution_operand_is_a_sibling() {
    let src = b"function f(n, bio) { const h = `<p>${escapeHtml(n)}</p>${bio}`; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let tree = nested_calls_of(&cfg, "escapeHtml").expect("record");
    assert_eq!(occ(tree, "bio")[0].call, None);
    assert_eq!(occ(tree, "n")[0].call, Some(0));
}

#[test]
fn nested_calls_compound_assignment_reads_its_target() {
    let src = b"function f(html, n) { html += escapeHtml(n); return html; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let tree = nested_calls_of(&cfg, "escapeHtml").expect("record");
    let html = occ(tree, "html");
    assert_eq!(html.len(), 1, "`+=` reads the target");
    assert_eq!(html[0].call, None);
}

#[test]
fn nested_calls_plain_assignment_skips_member_target() {
    // `alias.data = sanitize(alias.data)`: the written target must not count
    // as an operand beside the sanitizer call.
    let src = b"function f(alias) { alias.data = DOMPurify.sanitize(alias.data) + x; }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let tree = nested_calls_of(&cfg, "DOMPurify.sanitize").expect("record");
    let data = occ(tree, "alias.data");
    assert_eq!(data.len(), 1, "only the read inside the call: {data:?}");
    assert_eq!(data[0].call, Some(0));
}

#[test]
fn nested_calls_receiver_and_member_path() {
    let src = b"function f(req, y) { const s = req.query.name.trim() + escape(y); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let tree = nested_calls_of(&cfg, "req.trim").or_else(|| {
        cfg.node_indices()
            .find_map(|i| cfg[i].call.nested_calls.as_deref())
    });
    let tree = tree.expect("record");
    let path = occ(tree, "req.query.name");
    assert_eq!(path.len(), 1);
    assert_eq!(path[0].slot, CallSlot::Receiver);
    let trim = path[0].call.expect("inside the trim call") as usize;
    assert!(tree.calls[trim].callee.ends_with("trim"));
}

#[test]
fn nested_calls_python_keyword_value_and_positions() {
    let src = b"def f(a, b):\n    subprocess.run(quote(a), shell=b)\n";
    let ts_lang = Language::from(tree_sitter_python::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "python", ts_lang);
    let tree = nested_calls_of(&cfg, "subprocess.run").expect("record");
    let anchor = tree.anchor.expect("anchor");
    assert_eq!(
        tree.calls[anchor as usize].arity,
        Some(1),
        "keyword args are not positional"
    );
    let b = occ(tree, "b");
    assert_eq!((b[0].call, b[0].slot), (Some(anchor), CallSlot::Other));
    assert!(occ(tree, "shell").is_empty(), "keyword names are not reads");
}

#[test]
fn nested_calls_rust_macro_has_no_record() {
    let src = b"fn f(a: String, b: String) { let s = format!(\"{}{}\", esc(&a), b); run(s); }";
    let ts_lang = Language::from(tree_sitter_rust::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "rust", ts_lang);
    for i in cfg.node_indices() {
        if cfg[i]
            .call
            .callee
            .as_deref()
            .is_some_and(|c| c.contains("format"))
        {
            assert!(cfg[i].call.nested_calls.is_none());
        }
    }
}

#[test]
fn nested_calls_marks_whole_argument_calls() {
    let src =
        b"function f(res, n, x) { res.setHeader('X', String(n)); res.send('a' + String(x)); }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let (cfg, _) = parse_and_build(src, "javascript", ts_lang);
    let exact = nested_calls_of(&cfg, "res.setHeader").expect("record");
    let inner = exact
        .calls
        .iter()
        .find(|c| c.callee == "String")
        .expect("inner call");
    assert!(inner.exact_arg, "String(n) is the whole argument");
    let concat = nested_calls_of(&cfg, "res.send").expect("record");
    let inner = concat
        .calls
        .iter()
        .find(|c| c.callee == "String")
        .expect("inner call");
    assert!(!inner.exact_arg, "String(x) is one operand of the argument");
}

/// Outgoing non-exception edge count of the first Call node whose callee is
/// `callee`, across every body of `src`.
fn call_fallthrough_count(src: &[u8], lang: &str, ts_lang: Language, callee: &str) -> usize {
    let fc = parse_to_file_cfg(src, lang, ts_lang);
    for body in &fc.bodies {
        let g = &body.graph;
        if let Some(n) = g
            .node_indices()
            .find(|&i| g[i].kind == StmtKind::Call && g[i].call.callee.as_deref() == Some(callee))
        {
            return g
                .edges(n)
                .filter(|e| !matches!(e.weight(), EdgeKind::Exception))
                .count();
        }
    }
    panic!("no call to {callee}");
}

#[test]
fn python_flask_abort_import_dead_ends_the_call() {
    let ts = || Language::from(tree_sitter_python::LANGUAGE);
    let src = b"from flask import request, abort\ndef h():\n    x = request.args.get('x')\n    if x not in A:\n        abort(400)\n    run(x)\n";
    assert_eq!(call_fallthrough_count(src, "python", ts(), "abort"), 0);

    let aliased = b"from werkzeug.exceptions import abort as deny\ndef h(x):\n    if x not in A:\n        deny(400)\n    run(x)\n";
    assert_eq!(call_fallthrough_count(aliased, "python", ts(), "deny"), 0);

    let qualified =
        b"import flask\ndef h(x):\n    if x not in A:\n        flask.abort(400)\n    run(x)\n";
    assert_eq!(
        call_fallthrough_count(qualified, "python", ts(), "flask.abort"),
        0
    );
}

#[test]
fn python_local_abort_without_framework_import_falls_through() {
    let ts = Language::from(tree_sitter_python::LANGUAGE);
    let src = b"def abort(c):\n    print(c)\ndef h(x):\n    if x not in A:\n        abort(400)\n    run(x)\n";
    assert_eq!(call_fallthrough_count(src, "python", ts, "abort"), 1);
}

#[test]
fn php_wp_die_and_namespaced_abort_dead_end() {
    let ts = || Language::from(tree_sitter_php::LANGUAGE_PHP);
    let src = b"<?php\nfunction h($c) {\n  if (!in_array($c, ['a'], true)) { wp_die('bad'); }\n  system($c);\n}\n";
    assert_eq!(call_fallthrough_count(src, "php", ts(), "wp_die"), 0);
    let ns = b"<?php\nnamespace App;\nfunction h($c) {\n  if (!in_array($c, ['a'], true)) { \\abort(403); }\n  system($c);\n}\n";
    let fc = parse_to_file_cfg(ns, "php", ts());
    let callee = fc
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .filter_map(|n| n.call.callee.clone())
        .find(|c| c.ends_with("abort"))
        .expect("abort call");
    assert_eq!(call_fallthrough_count(ns, "php", ts(), &callee), 0);
}

#[test]
fn koa_ctx_throw_dead_ends_the_call() {
    let ts = Language::from(tree_sitter_javascript::LANGUAGE);
    let src = b"async function h(ctx) {\n  const c = ctx.query.c;\n  if (!A.includes(c)) { ctx.throw(400, 'bad'); }\n  run(c);\n}\n";
    assert_eq!(
        call_fallthrough_count(src, "javascript", ts, "ctx.throw"),
        0
    );
}

/// Condition texts of every `If` node in `src`, across all bodies.
fn if_condition_texts(src: &[u8], lang: &str, ts_lang: Language) -> Vec<String> {
    let fc = parse_to_file_cfg(src, lang, ts_lang);
    fc.bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .filter(|n| n.kind == StmtKind::If)
        .filter_map(|n| n.condition_text.clone())
        .collect()
}

#[test]
fn conditional_expression_assignments_lower_to_a_diamond() {
    let py = b"def h(s):\n    sort = s if s in SORTABLE else 'name'\n    run(sort)\n";
    let conds = if_condition_texts(py, "python", Language::from(tree_sitter_python::LANGUAGE));
    assert!(
        conds.iter().any(|c| c == "s in SORTABLE"),
        "python: {conds:?}"
    );

    let rb = b"def h\n  sort = SORTABLE.include?(params[:sort]) ? params[:sort] : 'created_at'\n  run(sort)\nend\n";
    let conds = if_condition_texts(rb, "ruby", Language::from(tree_sitter_ruby::LANGUAGE));
    assert!(
        conds.iter().any(|c| c.starts_with("SORTABLE.include?")),
        "ruby: {conds:?}"
    );

    let php = b"<?php\nfunction h($a) {\n  $sort = in_array($_GET['s'], $a, true) ? $_GET['s'] : 'name';\n  run($sort);\n}\n";
    let conds = if_condition_texts(php, "php", Language::from(tree_sitter_php::LANGUAGE_PHP));
    assert!(
        conds.iter().any(|c| c.starts_with("in_array(")),
        "php: {conds:?}"
    );

    // PHP `a ?: b` has no separate consequence and stays a plain assignment.
    let short = b"<?php\nfunction h() {\n  $sort = $_GET['s'] ?: 'name';\n  run($sort);\n}\n";
    let conds = if_condition_texts(short, "php", Language::from(tree_sitter_php::LANGUAGE_PHP));
    assert!(conds.is_empty(), "php short ternary: {conds:?}");
    let fc = parse_to_file_cfg(short, "php", Language::from(tree_sitter_php::LANGUAGE_PHP));
    let defines_sort = fc
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .any(|n| n.taint.defines.as_deref() == Some("sort"));
    assert!(defines_sort, "php short ternary assignment was dropped");
}
#[test]
fn js_object_assign_pollutes_only_a_prototype_target() {
    let src = b"function h(body) {\n\
                  Object.assign({}, body);\n\
                  Object.assign(Session.prototype, body);\n\
                }";
    let ts_lang = Language::from(tree_sitter_javascript::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "javascript", ts_lang);
    let assigns = js_call_nodes(&file_cfg, "Object.assign");
    assert_eq!(assigns.len(), 2);
    assert!(!has_sink(assigns[0], Cap::PROTOTYPE_POLLUTION));
    assert!(has_sink(assigns[1], Cap::PROTOTYPE_POLLUTION));
}

/// Go request formals are classified by declared type: `req *http.Request`
/// reads are sources under any binding name, an inner closure formal of an
/// unrelated type shadows the outer one, and the alias stack is empty again
/// once the CFG is built.
#[test]
fn go_request_typed_formal_classifies_as_source() {
    fn source_callees(cfg: &Cfg) -> Vec<String> {
        cfg.node_indices()
            .filter(|&n| {
                cfg[n]
                    .taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Source(_)))
            })
            .filter_map(|n| cfg[n].call.callee.clone())
            .collect()
    }
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);

    let src = b"package main\nfunc h(w http.ResponseWriter, req *http.Request) {\n\tx := req.Header.Get(\"a\")\n\t_ = x\n}\n";
    let (cfg, _) = parse_and_build(src, "go", ts_lang.clone());
    assert!(
        source_callees(&cfg).iter().any(|c| c == "req.Header.Get"),
        "req.Header.Get on a *http.Request formal must be a Source; got {:?}",
        source_callees(&cfg)
    );

    let src = b"package main\nfunc h(c *gin.Context) {\n\tx := c.ShouldBindJSON(&in)\n\t_ = x\n}\n";
    let (cfg, _) = parse_and_build(src, "go", ts_lang.clone());
    assert!(
        source_callees(&cfg).iter().any(|c| c == "c.ShouldBindJSON"),
        "gin binder on a *gin.Context formal must be a Source; got {:?}",
        source_callees(&cfg)
    );

    let src = b"package main\nfunc h(w http.ResponseWriter, req *http.Request) {\n\tf := func(req *Spec) {\n\t\tx := req.Header.Get(\"a\")\n\t\t_ = x\n\t}\n\t_ = f\n}\n";
    let file_cfg = parse_to_file_cfg(src, "go", ts_lang);
    let inner_sources: Vec<String> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| source_callees(&b.graph))
        .collect();
    assert!(
        inner_sources.is_empty(),
        "the closure's own `req *Spec` formal shadows the request; got {inner_sources:?}"
    );
    assert!(
        crate::labels::classify("go", "req.Header.Get", None).is_none(),
        "receiver aliases must not outlive build_cfg"
    );
}

/// Callee text and `all_args_literal` of every call node with a callee in a
/// Java snippet's method body.
fn java_call_literal_flags(src: &[u8]) -> Vec<(String, bool)> {
    let (cfg, _) = parse_and_build(src, "java", Language::from(tree_sitter_java::LANGUAGE));
    cfg.node_indices()
        .filter_map(|n| {
            let callee = cfg[n].call.callee.clone()?;
            Some((callee, cfg[n].all_args_literal))
        })
        .collect()
}

#[test]
fn java_chained_literal_call_is_all_literal_despite_zero_arg_inner_call() {
    let literal = java_call_literal_flags(
        b"class T { void f(String p) throws Exception { Runtime.getRuntime().exec(\"uptime\"); } }",
    );
    assert!(
        literal.iter().any(|(c, lit)| c.ends_with("exec") && *lit),
        "a literal argument on the exec call makes the chain literal, got {literal:?}"
    );

    let variable = java_call_literal_flags(
        b"class T { void f(String p) throws Exception { Runtime.getRuntime().exec(p); } }",
    );
    assert!(
        variable.iter().any(|(c, lit)| c.ends_with("exec") && !*lit),
        "a variable argument keeps the call non-literal, got {variable:?}"
    );

    // The zero-argument guard still applies to the call that is the sink
    // itself: `ois.readObject()` has no arguments to prove safe.
    let receiver_sink =
        java_call_literal_flags(b"class T { Object f(ObjectInputStream ois) throws Exception { return ois.readObject(); } }");
    assert!(
        receiver_sink
            .iter()
            .any(|(c, lit)| c.ends_with("readObject") && !*lit),
        "a zero-arg outer call is not literal, got {receiver_sink:?}"
    );

    // An inner call that takes a variable still rejects the chain.
    let inner_variable = java_call_literal_flags(
        b"class T { void f(String p) throws Exception { a.b(p).c(\"lit\"); } }",
    );
    assert!(
        inner_variable
            .iter()
            .any(|(c, lit)| c.ends_with('c') && !*lit),
        "a variable argument on an inner chain call rejects the chain, got {inner_variable:?}"
    );
}

/// Declared receiver type recorded on the Java call nodes of a snippet,
/// keyed by callee text.
fn java_receiver_decl_types(src: &[u8]) -> Vec<(String, Option<crate::ssa::type_facts::TypeKind>)> {
    let file_cfg = parse_to_file_cfg(src, "java", Language::from(tree_sitter_java::LANGUAGE));
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| {
            b.graph
                .node_indices()
                .filter_map(|n| {
                    let callee = b.graph[n].call.callee.clone()?;
                    Some((callee, b.graph[n].call.receiver_decl_type.clone()))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn java_receiver_decl_type_follows_the_declaration() {
    use crate::ssa::type_facts::TypeKind;
    let src = br#"
import org.springframework.jdbc.core.JdbcTemplate;
class T {
    private JdbcTemplate jdbc;
    private final javax.naming.directory.DirContext dirCtx;
    private Object other;
    void field(String q) { jdbc.queryForList(q); }
    void thisField(String q) { this.jdbc.update(q); }
    void formal(DirContext dc, String q) throws Exception { dc.search("", q, null); }
    void local(String q) { EntityManager mgr = lookup(); mgr.createQuery(q); }
    void catchBound() { try { run(); } catch (Exception jdbc) { jdbc.getMessage(); } }
    void lambdaShadow() { run(jdbc -> jdbc.update("x")); }
    void unrelated(String q) { other.update(q); }
    void staticCall(String q) { Files.readString(q); }
}
"#;
    let types = java_receiver_decl_types(src);
    let kind_of = |callee: &str| {
        types
            .iter()
            .find(|(c, _)| c == callee)
            .unwrap_or_else(|| panic!("no call node for {callee}: {types:?}"))
            .1
            .clone()
    };
    assert_eq!(kind_of("jdbc.queryForList"), Some(TypeKind::JdbcTemplate));
    assert_eq!(kind_of("this.jdbc.update"), Some(TypeKind::JdbcTemplate));
    assert_eq!(kind_of("dc.search"), Some(TypeKind::LdapClient));
    assert_eq!(kind_of("mgr.createQuery"), Some(TypeKind::HibernateSession));
    assert_eq!(
        kind_of("jdbc.getMessage"),
        None,
        "a catch parameter shadows the field of the same name"
    );
    assert_eq!(
        kind_of("jdbc.update"),
        None,
        "an untyped lambda formal shadows the field of the same name"
    );
    assert_eq!(kind_of("other.update"), None);
    assert_eq!(kind_of("Files.readString"), None);
}

#[test]
fn java_response_write_sink_keeps_declared_stream_type() {
    use crate::ssa::type_facts::TypeKind;
    let src = br#"
import java.io.FileWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
class T {
    FileWriter log;
    PrintStream err;
    PrintWriter out;
    void f(String m, java.io.DataOutputStream peer, StringWriter buf) throws Exception {
        log.write(m);
        buf.write(m);
        err.println(m);
        out.println(m);
        peer.write(m.getBytes());
    }
}
"#;
    let types = java_receiver_decl_types(src);
    let kind_of = |callee: &str| {
        types
            .iter()
            .find(|(c, _)| c == callee)
            .unwrap_or_else(|| panic!("no call node for {callee}: {types:?}"))
            .1
            .clone()
    };
    // File and memory writers can never be the servlet response.
    assert_eq!(kind_of("log.write"), Some(TypeKind::FileHandle));
    assert_eq!(kind_of("buf.write"), Some(TypeKind::FileHandle));
    // Wrapping streams can sit on the response
    // (`new PrintStream(resp.getOutputStream())`), and a PrintWriter is the
    // servlet response writer type, so none of them drops the sink.
    assert_eq!(kind_of("err.println"), None);
    assert_eq!(kind_of("peer.write"), None);
    assert_eq!(
        kind_of("out.println"),
        None,
        "a PrintWriter is the servlet response writer type"
    );
}

#[test]
fn java_stream_resource_println_keeps_declared_type() {
    use crate::ssa::type_facts::TypeKind;
    let src = br#"
import java.io.*;
class T {
    void copy(File out, File f, String header) throws Exception {
        try (PrintStream ps = new PrintStream(new FileOutputStream(out));
             BufferedReader br = new BufferedReader(new FileReader(f))) {
            for (String l = br.readLine(); l != null; l = br.readLine()) {
                ps.println(l);
            }
            ps.print(header);
        }
    }
}
"#;
    let types = java_receiver_decl_types(src);
    for callee in ["ps.println", "ps.print"] {
        let kind = types
            .iter()
            .find(|(c, _)| c == callee)
            .unwrap_or_else(|| panic!("no call node for {callee}: {types:?}"))
            .1
            .clone();
        assert_eq!(kind, Some(TypeKind::FileHandle), "{callee}");
    }
}

#[test]
fn java_wrapping_stream_on_response_or_reassigned_keeps_no_type() {
    let src = br#"
import java.io.*;
class T {
    void a(javax.servlet.http.HttpServletResponse resp, String m) throws Exception {
        PrintStream ps = new PrintStream(resp.getOutputStream());
        ps.println(m);
    }
    void b(javax.servlet.http.HttpServletResponse resp, File f, String m) throws Exception {
        PrintStream qs = new PrintStream(new FileOutputStream(f));
        qs = new PrintStream(resp.getOutputStream());
        qs.println(m);
    }
    void c(PrintWriter w, String m) {
        PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter("log")));
        pw.println(m);
        w.println(m);
    }
}
"#;
    let types = java_receiver_decl_types(src);
    let kind_of = |callee: &str| {
        types
            .iter()
            .find(|(c, _)| c == callee)
            .unwrap_or_else(|| panic!("no call node for {callee}: {types:?}"))
            .1
            .clone()
    };
    assert_eq!(kind_of("ps.println"), None, "wraps the servlet response");
    assert_eq!(kind_of("qs.println"), None, "reassigned to the response");
    assert_eq!(kind_of("w.println"), None, "a PrintWriter formal");
    assert_eq!(
        kind_of("pw.println"),
        Some(crate::ssa::type_facts::TypeKind::FileHandle),
        "nested wrappers over a FileWriter"
    );
}

/// Callee text of every Java call node that carries a `Source` label.
fn java_source_callees(src: &[u8]) -> Vec<String> {
    let file_cfg = parse_to_file_cfg(src, "java", Language::from(tree_sitter_java::LANGUAGE));
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| {
            b.graph
                .node_indices()
                .filter(|&n| {
                    b.graph[n]
                        .taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
                })
                .filter_map(|n| b.graph[n].call.callee.clone())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn java_process_and_resource_streams_are_not_sources() {
    // Child-process output, through a declared `Process`, a chained
    // `exec(..)`, or a `ProcessBuilder.start()`.
    for body in [
        "Process p = Runtime.getRuntime().exec(cmd); InputStream in = p.getInputStream();",
        "Process p = new ProcessBuilder(cmd).start(); BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream())); String l = r.readLine();",
        "InputStream in = Runtime.getRuntime().exec(cmd).getInputStream();",
        "String l = new BufferedReader(new InputStreamReader(proc.getInputStream())).readLine();",
        // Classpath and zip entries ship with the application.
        "InputStream in = new ClassPathResource(\"app.properties\").getInputStream();",
        "InputStream in = zip.getInputStream(entry);",
    ] {
        let src = format!(
            "class T {{ void f(String cmd, Process proc, java.util.zip.ZipFile zip, Object entry) throws Exception {{ {body} }} }}"
        );
        assert_eq!(
            java_source_callees(src.as_bytes()),
            Vec::<String>::new(),
            "no source expected in: {body}"
        );
    }
}

#[test]
fn java_request_and_unresolved_streams_stay_sources() {
    let sources = |body: &str| {
        java_source_callees(
            format!(
                "class T {{ void f(HttpServletRequest req, Socket sock, Stream unknown) throws Exception {{ {body} }} }}"
            )
            .as_bytes(),
        )
    };
    assert_eq!(
        sources("InputStream in = req.getInputStream();"),
        vec!["req.getInputStream"]
    );
    assert_eq!(
        sources("BufferedReader r = req.getReader();"),
        vec!["req.getReader"]
    );
    // A socket, and a receiver the method does not declare, are not ruled out.
    assert_eq!(
        sources("InputStream in = sock.getInputStream();"),
        vec!["sock.getInputStream"]
    );
    assert_eq!(
        sources("InputStream in = unknown.getInputStream();"),
        vec!["unknown.getInputStream"]
    );
    assert_eq!(
        sources("InputStream in = other().getInputStream();"),
        vec!["other().getInputStream"],
        "a computed receiver is not ruled out"
    );
}

#[test]
fn java_read_line_source_follows_the_reader_root() {
    let sources = |body: &str| {
        java_source_callees(
            format!(
                "class T {{ void f(HttpServletRequest req, Process p) throws Exception {{ {body} }} }}"
            )
            .as_bytes(),
        )
    };
    // A file reader keeps the engine's file-content source.
    assert_eq!(
        sources(
            "BufferedReader br = new BufferedReader(new FileReader(\"/etc/app/hosts\")); String h = br.readLine();"
        ),
        vec!["br.readLine"]
    );
    // Stdin and an undeclared reader keep it too.
    assert_eq!(
        sources(
            "BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); String h = br.readLine();"
        ),
        vec!["br.readLine"]
    );
    // Over the request the getInputStream / getReader source is the origin,
    // and readLine is not a second one.
    assert_eq!(
        sources(
            "BufferedReader r = new BufferedReader(new InputStreamReader(req.getInputStream())); String l = r.readLine();"
        ),
        vec!["req.getInputStream"]
    );
    assert_eq!(
        sources("BufferedReader r = req.getReader(); String l = r.readLine();"),
        vec!["req.getReader"]
    );
}

#[test]
fn java_get_method_sink_needs_a_class_receiver_and_a_name() {
    // Callee text of every call node carrying a CODE_EXEC sink.
    let sinks = |body: &str| -> Vec<String> {
        let src = format!(
            "class T {{ void f(Class<?> cls, ZipEntry entry, String n, HttpServletRequest req) throws Exception {{ {body} }} }}"
        );
        let file_cfg = parse_to_file_cfg(
            src.as_bytes(),
            "java",
            Language::from(tree_sitter_java::LANGUAGE),
        );
        file_cfg
            .bodies
            .iter()
            .flat_map(|b| {
                b.graph
                    .node_indices()
                    .filter(|&i| {
                        b.graph[i].taint.labels.iter().any(|l| {
                            matches!(l, crate::labels::DataLabel::Sink(c) if c.contains(crate::labels::Cap::CODE_EXEC))
                        })
                    })
                    .filter_map(|i| b.graph[i].call.callee.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    // A computed name on a Class-typed or unresolved receiver is a sink.
    assert_eq!(sinks("cls.getMethod(n);"), vec!["cls.getMethod"]);
    assert_eq!(
        sinks("cls.getDeclaredMethod(n, String.class);"),
        vec!["cls.getDeclaredMethod"]
    );
    assert_eq!(sinks("this.getClass().getMethod(n);").len(), 1);
    assert_eq!(sinks("Object m = Foo.class.getMethod(n);").len(), 1);
    assert_eq!(
        sinks("Object m = other.getMethod(n);").len(),
        1,
        "undeclared receiver is not ruled out"
    );
    // A literal name, no name at all, another declared type, a bare class
    // name and an unqualified or this-call are not.
    assert!(sinks("cls.getMethod(\"run\");").is_empty());
    assert!(sinks("String v = req.getMethod();").is_empty());
    assert!(sinks("int m = entry.getMethod();").is_empty());
    assert!(sinks("Object m = entry.getMethod(n);").is_empty());
    assert!(sinks("Object m = Util.getMethod(cls, n);").is_empty());
    assert!(sinks("Object m = getMethod(cls, n);").is_empty());
    assert!(sinks("Object m = this.getMethod(cls, n);").is_empty());
    assert!(sinks("int m = (entry.getMethod() != 8) ? 1 : build(n);").is_empty());
}

// ── NullCheck extraction (resource null / failure guards) ───────────────

/// `(var, null_on_true)` of the single null-check `If` node built from
/// `src`, or `None` when no `If` node carries one.
fn null_checks(src: &[u8], lang: &str, ts_lang: Language) -> Vec<(String, bool)> {
    let fc = parse_to_file_cfg(src, lang, ts_lang);
    fc.bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .filter(|n| n.kind == StmtKind::If)
        .filter_map(|n| n.null_check.as_ref())
        .map(|nc| (nc.var.clone(), nc.null_on_true))
        .collect()
}

fn one_null_check(src: &[u8], lang: &str, ts_lang: Language) -> Option<(String, bool)> {
    let all = null_checks(src, lang, ts_lang);
    assert!(
        all.len() <= 1,
        "expected at most one null check, got {all:?}"
    );
    all.into_iter().next()
}

#[test]
fn null_check_c_shapes() {
    let c = || Language::from(tree_sitter_c::LANGUAGE);
    let case = |cond: &str| {
        let src = format!("void g(void) {{ if ({cond}) {{ h(); }} }}");
        one_null_check(src.as_bytes(), "c", c())
    };
    assert_eq!(case("f"), Some(("f".into(), false)));
    assert_eq!(case("!f"), Some(("f".into(), true)));
    assert_eq!(case("!(f)"), Some(("f".into(), true)));
    assert_eq!(case("f == NULL"), Some(("f".into(), true)));
    assert_eq!(case("NULL == f"), Some(("f".into(), true)));
    assert_eq!(case("f != NULL"), Some(("f".into(), false)));
    assert_eq!(case("NULL != f"), Some(("f".into(), false)));
    assert_eq!(case("!(f == NULL)"), Some(("f".into(), false)));
    assert_eq!(case("fd < 0"), Some(("fd".into(), true)));
    assert_eq!(case("fd == -1"), Some(("fd".into(), true)));
    assert_eq!(case("fd >= 0"), Some(("fd".into(), false)));
    assert_eq!(case("0 > fd"), Some(("fd".into(), true)));
    // Not a failure test: descriptor 0 is valid, and these are not
    // single-variable null tests at all.
    assert_eq!(case("fd == 0"), None);
    assert_eq!(case("f == g"), None);
    assert_eq!(case("x == 1"), None);
    assert_eq!(case("f->ok"), None);
    assert_eq!(case("valid(f)"), None);
}

#[test]
fn null_check_cpp_nullptr() {
    let src = b"int g() { FILE* fp = fopen(p, \"r\"); if (fp == nullptr) return -1; return 0; }";
    assert_eq!(
        one_null_check(src, "cpp", Language::from(tree_sitter_cpp::LANGUAGE)),
        Some(("fp".into(), true))
    );
}

#[test]
fn null_check_short_circuit_operand() {
    // `if (f && g)` is decomposed into one If node per operand; each bare
    // operand carries its own null check.
    let src = b"void g(void) { if (f && g) { h(); } }";
    let mut got = null_checks(src, "c", Language::from(tree_sitter_c::LANGUAGE));
    got.sort();
    assert_eq!(got, vec![("f".into(), false), ("g".into(), false)]);
}

#[test]
fn null_check_python_shapes() {
    let py = || Language::from(tree_sitter_python::LANGUAGE);
    let case = |cond: &str| {
        let src = format!("def g(f):\n    if {cond}:\n        h()\n");
        one_null_check(src.as_bytes(), "python", py())
    };
    assert_eq!(case("not f"), Some(("f".into(), true)));
    assert_eq!(case("f is None"), Some(("f".into(), true)));
    assert_eq!(case("f is not None"), Some(("f".into(), false)));
    assert_eq!(case("f"), Some(("f".into(), false)));
    assert_eq!(case("f.closed"), None);
}

#[test]
fn null_check_php_js_java_go_shapes() {
    let php = b"<?php function g($p) { $fh = fopen($p, 'r'); if ($fh === false) { return null; } }";
    assert_eq!(
        one_null_check(php, "php", Language::from(tree_sitter_php::LANGUAGE_PHP)),
        Some(("fh".into(), true))
    );
    let php_not = b"<?php function g($p) { $fh = fopen($p, 'r'); if (!$fh) { return null; } }";
    assert_eq!(
        one_null_check(
            php_not,
            "php",
            Language::from(tree_sitter_php::LANGUAGE_PHP)
        ),
        Some(("fh".into(), true))
    );
    let js = b"function g(p) { const fd = open(p); if (fd === null) { return -1; } }";
    assert_eq!(
        one_null_check(
            js,
            "javascript",
            Language::from(tree_sitter_javascript::LANGUAGE)
        ),
        Some(("fd".into(), true))
    );
    let java = b"class A { void g() { if (s != null) { s.close(); } } }";
    assert_eq!(
        one_null_check(java, "java", Language::from(tree_sitter_java::LANGUAGE)),
        Some(("s".into(), false))
    );
    let go = b"package m\nfunc g() error { f, err := os.Open(p)\n if err != nil { return err }\n return f.Close() }";
    assert_eq!(
        one_null_check(go, "go", Language::from(tree_sitter_go::LANGUAGE)),
        Some(("err".into(), false))
    );
}

// ── Return escapes (ownership handed to the caller) ─────────────────────

fn return_escapes(src: &[u8], lang: &str, ts_lang: Language) -> Vec<(Vec<String>, Vec<String>)> {
    let fc = parse_to_file_cfg(src, lang, ts_lang);
    fc.bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .filter(|n| n.kind == StmtKind::Return)
        .map(|n| (n.returned_idents.clone(), n.returned_call_callees.clone()))
        .collect()
}

#[test]
fn return_escapes_go_shapes() {
    let go = |body: &str| {
        let src = format!("package m\nfunc g() {{ {body} }}");
        return_escapes(
            src.as_bytes(),
            "go",
            Language::from(tree_sitter_go::LANGUAGE),
        )
    };
    assert_eq!(go("return f, nil"), vec![(vec!["f".to_string()], vec![])]);
    assert_eq!(go("return &W{f: f}"), vec![(vec!["f".to_string()], vec![])]);
    assert_eq!(go("return W{f}"), vec![(vec!["f".to_string()], vec![])]);
    assert_eq!(
        go("return os.Open(p)"),
        vec![(vec![], vec!["os.Open".to_string()])]
    );
    // The handle is an argument of a plain call: it does not escape.
    assert_eq!(
        go("return io.ReadAll(f)"),
        vec![(vec![], vec!["io.ReadAll".to_string()])]
    );
    let (idents, _) = &go("return f.Name()")[0];
    assert!(
        idents.is_empty(),
        "method receiver does not escape: {idents:?}"
    );
}

#[test]
fn return_escapes_python_java_c_shapes() {
    let py = |body: &str| {
        let src = format!("def g(p):\n    {body}\n");
        return_escapes(
            src.as_bytes(),
            "python",
            Language::from(tree_sitter_python::LANGUAGE),
        )
    };
    assert_eq!(py("return f")[0].0, vec!["f".to_string()]);
    assert_eq!(py("return f, 1")[0].0, vec!["f".to_string()]);
    assert_eq!(py("return {'h': f}")[0].0, vec!["f".to_string()]);
    assert!(py("return f.read()")[0].0.is_empty());
    assert_eq!(py("return open(p)")[0].1, vec!["open".to_string()]);
    assert_eq!(py("return self.conn")[0].0, vec!["self.conn".to_string()]);

    let java = b"class A { Reader g(InputStream in) { return new BufferedReader(new InputStreamReader(in)); } }";
    let got = return_escapes(java, "java", Language::from(tree_sitter_java::LANGUAGE));
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].0,
        vec!["in".to_string()],
        "a wrapped stream escapes with its wrapper"
    );
    assert!(got[0].1.iter().any(|c| c.contains("BufferedReader")));

    let c = b"char *g(void) { char *b = malloc(4); return (char *)b; }";
    let got = return_escapes(c, "c", Language::from(tree_sitter_c::LANGUAGE));
    assert_eq!(got[0].0, vec!["b".to_string()]);
}

// ── Stores that leave the body, constructor ownership ───────────────────

fn all_nodes(src: &[u8], lang: &str, ts_lang: Language) -> Vec<NodeInfo> {
    let fc = parse_to_file_cfg(src, lang, ts_lang);
    fc.bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| b.graph[i].clone()))
        .collect()
}

fn escaping_defines(src: &[u8], lang: &str, ts_lang: Language) -> Vec<String> {
    let mut out: Vec<String> = all_nodes(src, lang, ts_lang)
        .into_iter()
        .filter(|n| n.escaping_store)
        .filter_map(|n| n.taint.defines.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[test]
fn escaping_store_c_deref_global_and_static() {
    let c = || Language::from(tree_sitter_c::LANGUAGE);
    let src = b"static char *g;\n\
        int out_param(char **out) { char *b = malloc(4); *out = b; return 0; }\n\
        void global(void) { g = malloc(4); }\n\
        void keep(void) { static char *s; s = malloc(4); }\n\
        void late_local(void) { char *p; p = malloc(4); }\n";
    assert_eq!(
        escaping_defines(src, "c", c()),
        vec!["g".to_string(), "out".to_string(), "s".to_string()],
        "`p` is a plain local and must stay tracked"
    );
}

#[test]
fn escaping_store_java_unqualified_field_only() {
    let src = b"class A {\n  java.io.InputStream in;\n\
        void field(String p) throws Exception { in = new java.io.FileInputStream(p); }\n\
        void local(String p) throws Exception { java.io.InputStream s; s = new java.io.FileInputStream(p); }\n}\n";
    assert_eq!(
        escaping_defines(src, "java", Language::from(tree_sitter_java::LANGUAGE)),
        vec!["in".to_string()]
    );
}

#[test]
fn escaping_store_go_package_var() {
    let src = b"package m\nvar logFile *os.File\nfunc init() {\n\tvar err error\n\tlogFile, err = os.Create(\"x\")\n\t_ = err\n}\nfunc local() {\n\tf, err := os.Create(\"y\")\n\t_, _ = f, err\n}\n";
    assert_eq!(
        escaping_defines(src, "go", Language::from(tree_sitter_go::LANGUAGE)),
        vec!["logFile".to_string()]
    );
}

#[test]
fn ctor_owned_args_java_wrappers() {
    let src = b"class A { void m(java.io.InputStream in) throws Exception {\n\
        java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));\n\
        Object o = new Object();\n} }\n";
    let owned: Vec<Vec<String>> =
        all_nodes(src, "java", Language::from(tree_sitter_java::LANGUAGE))
            .into_iter()
            .map(|n| n.call.ctor_owned_args)
            .filter(|a| !a.is_empty())
            .collect();
    assert_eq!(owned, vec![vec!["in".to_string()]]);
}

#[test]
fn cpp_smart_pointer_declarations() {
    let cpp = || Language::from(tree_sitter_cpp::LANGUAGE);
    let src = b"struct Foo { int x; };\n\
        void a() { std::unique_ptr<Foo> p(new Foo()); }\n\
        void b(Foo *raw) { std::unique_ptr<Foo> q(raw); }\n\
        void c() { Foo *plain = new Foo(); }\n";
    let nodes = all_nodes(src, "cpp", cpp());
    let news: Vec<bool> = nodes
        .iter()
        .filter(|n| n.call.callee.as_deref() == Some("new"))
        .map(|n| n.managed_resource)
        .collect();
    assert_eq!(
        news,
        vec![true, false],
        "only the smart-pointer `new` is managed"
    );
    assert!(
        nodes
            .iter()
            .any(|n| n.call.ctor_owned_args == vec!["raw".to_string()]),
        "`std::unique_ptr<Foo> q(raw)` adopts raw"
    );
}

// ── Assignment targets for Java / PHP member LHS ────────────────────────

fn defines_of(src: &[u8], lang: &str, ts_lang: Language) -> Vec<(Option<String>, Vec<String>)> {
    all_nodes(src, lang, ts_lang)
        .into_iter()
        .filter(|n| n.taint.defines.is_some())
        .map(|n| (n.taint.defines.clone(), n.taint.extra_defines.clone()))
        .collect()
}

#[test]
fn java_php_member_lhs_defines_whole_path() {
    let java = defines_of(
        b"class A { String cmd; void f(A o, String x) { o.cmd = x; this.cmd = x; } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
    );
    assert_eq!(
        java,
        vec![
            (Some("o.cmd".to_string()), vec![]),
            (Some("cmd".to_string()), vec![])
        ],
        "Java `this.f` keeps the bare field name, and `cmd` is not an extra define"
    );

    let php = defines_of(
        b"<?php class A { function f($p) { $this->fh = fopen($p, 'r'); } }",
        "php",
        Language::from(tree_sitter_php::LANGUAGE_PHP),
    );
    assert_eq!(php, vec![(Some("this.fh".to_string()), vec![])]);

    let java_arr = defines_of(
        b"class A { void f(String[] arr, int i, String v) { arr[i] = v; } }",
        "java",
        Language::from(tree_sitter_java::LANGUAGE),
    );
    assert_eq!(
        java_arr,
        vec![(Some("arr".to_string()), vec![])],
        "the index is read, not assigned"
    );
}

// ── URL string prefixes ─────────────────────────────────────────────────────

/// `string_prefix` of the first node (any body) whose callee ends with
/// `callee_suffix`, or of the node that defines `defines`.
fn url_prefix_of(
    src: &str,
    lang_str: &str,
    ts_lang: Language,
    callee_suffix: Option<&str>,
    defines: Option<&str>,
) -> Option<String> {
    let file_cfg = parse_to_file_cfg(src.as_bytes(), lang_str, ts_lang);
    for body in &file_cfg.bodies {
        for idx in body.graph.node_indices() {
            let info = &body.graph[idx];
            let by_callee = callee_suffix
                .is_some_and(|s| info.call.callee.as_deref().is_some_and(|c| c.ends_with(s)));
            let by_def = defines.is_some_and(|d| info.taint.defines.as_deref() == Some(d));
            if (by_callee || by_def) && info.string_prefix.is_some() {
                return info.string_prefix.clone();
            }
        }
    }
    None
}

#[test]
fn url_prefix_reads_the_left_spine_of_a_concat_chain() {
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "function h(id) { axios.get('https://h.example/items/' + id + '/details'); }",
            "javascript",
            js,
            Some("get"),
            None
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
    let go = Language::from(tree_sitter_go::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "package p\nfunc h(id string) { url := \"https://h.example/items/\" + id + \"/d\"; http.Get(url) }",
            "go",
            go,
            None,
            Some("url")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
}

#[test]
fn url_prefix_reads_go_var_and_const_declarations() {
    let go = Language::from(tree_sitter_go::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "package p\nfunc h(id string) { var url = \"https://h.example/items/\" + id; http.Get(url) }",
            "go",
            go,
            None,
            Some("url")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
}

#[test]
fn url_prefix_reads_the_url_argument_not_the_first() {
    let go = Language::from(tree_sitter_go::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "package p\nfunc h(id string) { req, _ := http.NewRequest(\"GET\", \"https://h.example/items/\"+id, nil); _ = req }",
            "go",
            go,
            Some("NewRequest"),
            None
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
}

#[test]
fn url_prefix_reads_format_calls() {
    let go = Language::from(tree_sitter_go::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "package p\nfunc h(id string) { url := fmt.Sprintf(\"https://h.example/items/%s\", id); _ = url }",
            "go",
            go,
            None,
            Some("url")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
    let py = Language::from(tree_sitter_python::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "def h(i):\n    u = 'https://h.example/items/{}'.format(i)\n",
            "python",
            py.clone(),
            None,
            Some("u")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
    assert_eq!(
        url_prefix_of(
            "def h(i):\n    u = 'https://h.example/items/%s' % i\n",
            "python",
            py.clone(),
            None,
            Some("u")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
    assert_eq!(
        url_prefix_of(
            "def h(i):\n    u = f'https://h.example/items/{i}'\n",
            "python",
            py,
            None,
            Some("u")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
    let java = Language::from(tree_sitter_java::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "class A { void h(String id) { String u = String.format(\"https://h.example/items/%s\", id); } }",
            "java",
            java,
            None,
            Some("u")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
}

#[test]
fn url_prefix_reads_php_call_arguments_and_interpolation() {
    let php = Language::from(tree_sitter_php::LANGUAGE_PHP);
    assert_eq!(
        url_prefix_of(
            "<?php function h($c) { file_get_contents('https://h.example/w?city=' . $c); }",
            "php",
            php.clone(),
            Some("file_get_contents"),
            None
        )
        .as_deref(),
        Some("https://h.example/w?city=")
    );
    assert_eq!(
        url_prefix_of(
            "<?php function h($id) { $u = \"https://h.example/items/{$id}\"; }",
            "php",
            php,
            None,
            Some("u")
        )
        .as_deref(),
        Some("https://h.example/items/")
    );
}

#[test]
fn url_prefix_does_not_read_interpolated_hosts() {
    let py = Language::from(tree_sitter_python::LANGUAGE);
    // The host is interpolated: the literal head is only the scheme.
    let p = url_prefix_of(
        "def h(host):\n    u = f'https://{host}/x/'\n",
        "python",
        py,
        None,
        Some("u"),
    );
    assert_eq!(p.as_deref(), Some("https://"));
}

#[test]
fn url_prefix_resolves_module_level_string_constants() {
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    let src = |body: &str| {
        format!("const API = 'https://api.example.com/';\nfunction h(p) {{ {body} }}\n")
    };
    assert_eq!(
        url_prefix_of(
            &src("axios.get(API + p);"),
            "javascript",
            js.clone(),
            Some("get"),
            None
        )
        .as_deref(),
        Some("https://api.example.com/")
    );
    assert_eq!(
        url_prefix_of(
            &src("axios.get(`${API}users/${p}`);"),
            "javascript",
            js.clone(),
            Some("get"),
            None
        )
        .as_deref(),
        Some("https://api.example.com/users/")
    );
    assert_eq!(
        url_prefix_of(
            &src("const url = API + p;"),
            "javascript",
            js.clone(),
            None,
            Some("url")
        )
        .as_deref(),
        Some("https://api.example.com/")
    );
    // A URL sink takes the bare constant itself.
    assert_eq!(
        url_prefix_of(&src("axios.get(API);"), "javascript", js, Some("get"), None).as_deref(),
        Some("https://api.example.com/")
    );
}

#[test]
fn url_prefix_ignores_constants_that_are_not_unique_definitions() {
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    // Reassigned at module level.
    assert_eq!(
        url_prefix_of(
            "let API = 'https://api.example.com/';\nAPI = process.argv[2];\nfunction h(p) { axios.get(API + p); }",
            "javascript",
            js.clone(),
            Some("get"),
            None
        ),
        None
    );
    // Shadowed by a local of the same name.
    assert_eq!(
        url_prefix_of(
            "const API = 'https://api.example.com/';\nfunction h(p) { const API = p; axios.get(API + p); }",
            "javascript",
            js.clone(),
            Some("get"),
            None
        ),
        None
    );
    // Shadowed by a parameter.
    assert_eq!(
        url_prefix_of(
            "const API = 'https://api.example.com/';\nfunction h(API, p) { axios.get(API + p); }",
            "javascript",
            js.clone(),
            Some("get"),
            None
        ),
        None
    );
    // Not a string literal.
    assert_eq!(
        url_prefix_of(
            "const API = process.env.API;\nfunction h(p) { axios.get(API + p); }",
            "javascript",
            js,
            Some("get"),
            None
        ),
        None
    );
}

#[test]
fn url_prefix_resolves_python_and_go_module_constants() {
    let py = Language::from(tree_sitter_python::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "API = 'https://api.example.com/v1/'\ndef h(c):\n    requests.get(API + c)\n",
            "python",
            py.clone(),
            Some("get"),
            None
        )
        .as_deref(),
        Some("https://api.example.com/v1/")
    );
    assert_eq!(
        url_prefix_of(
            "API = 'https://api.example.com/v1/'\ndef h(c):\n    u = f'{API}city/{c}'\n",
            "python",
            py,
            None,
            Some("u")
        )
        .as_deref(),
        Some("https://api.example.com/v1/city/")
    );
    let go = Language::from(tree_sitter_go::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "package p\nconst apiBase = \"https://api.example.com/\"\nfunc h(id string) { http.Get(apiBase + id) }",
            "go",
            go,
            Some("Get"),
            None
        )
        .as_deref(),
        Some("https://api.example.com/")
    );
}

#[test]
fn url_prefix_does_not_read_through_a_call_inside_a_concatenation() {
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    // `wrap` can return any string, so its argument's head is not the head of
    // the concatenation.
    assert_eq!(
        url_prefix_of(
            "function h(p) { axios.get(wrap('https://h.example/') + p); }",
            "javascript",
            js.clone(),
            Some("get"),
            None
        ),
        None
    );
    // A format call is read: its result starts with the format's head.
    let go = Language::from(tree_sitter_go::LANGUAGE);
    assert_eq!(
        url_prefix_of(
            "package p\nfunc h(id string) { http.Get(fmt.Sprintf(\"https://h.example/%s\", id) + \"/d\") }",
            "go",
            go,
            Some("Get"),
            None
        )
        .as_deref(),
        Some("https://h.example/")
    );
}

#[test]
fn ruby_file_level_local_is_not_a_module_prefix() {
    let rb = Language::from(tree_sitter_ruby::LANGUAGE);
    // A file-level local is not visible inside `def`: there `api` is a
    // method call, so it says nothing about the URL.
    assert_eq!(
        url_prefix_of(
            "api = 'https://api.example.com/'\ndef h(id)\n  u = api + id\nend\n",
            "ruby",
            rb,
            None,
            Some("u")
        ),
        None
    );
}

#[test]
fn arg_bare_names_marks_name_arguments_only() {
    let mask_of = |src: &str, lang_str: &str, ts_lang: Language, callee_suffix: &str| {
        let file_cfg = parse_to_file_cfg(src.as_bytes(), lang_str, ts_lang);
        file_cfg
            .bodies
            .iter()
            .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
            .find(|n| {
                n.call
                    .callee
                    .as_deref()
                    .is_some_and(|c| c.ends_with(callee_suffix))
            })
            .map(|n| n.call.arg_bare_names)
            .expect("call node")
    };
    let go = Language::from(tree_sitter_go::LANGUAGE);
    // "/var/data" (literal), c (name), cfg.Dir (member path), c + "/x"
    // (expression), p[1:] (slice).
    assert_eq!(
        mask_of(
            "package p\nfunc h(c string, p string) { filepath.Join(\"/var/data\", c, cfg.Dir, c + \"/x\", p[1:]) }",
            "go",
            go,
            "Join"
        ),
        0b00110
    );
    let py = Language::from(tree_sitter_python::LANGUAGE);
    // Keyword arguments do not take a position.
    assert_eq!(
        mask_of(
            "def h(base, p):\n    urljoin(base, (p), timeout=t)\n",
            "python",
            py,
            "urljoin"
        ),
        0b11
    );
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    assert_eq!(
        mask_of(
            "function h(p) { new URL(p.slice(1), base); }",
            "javascript",
            js,
            "URL"
        ),
        0b10
    );
}

#[test]
fn nested_sanitizer_does_not_replace_a_gated_sink_callee() {
    let py = Language::from(tree_sitter_python::LANGUAGE);
    let src = "import subprocess, html\ndef h(name):\n    subprocess.Popen(['sh', '-c', html.escape(name)])\n";
    let file_cfg = parse_to_file_cfg(src.as_bytes(), "python", py);
    let node = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_indices().map(move |i| &b.graph[i]))
        .find(|n| {
            n.call
                .outer_callee
                .as_deref()
                .or(n.call.callee.as_deref())
                .is_some_and(|c| c.ends_with("Popen"))
        })
        .expect("Popen call node");
    // The gated sink keeps its callee, so its gate still classifies it.
    assert_eq!(node.call.callee.as_deref(), Some("subprocess.Popen"));
    assert!(
        node.taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SHELL_ESCAPE))),
        "{:?}",
        node.taint.labels
    );
}

/// Callee text and `all_args_literal` of every Rust call node.
fn rust_call_literal_flags(src: &[u8]) -> Vec<(String, bool)> {
    let (cfg, _) = rust_cfg(src);
    cfg.node_indices()
        .filter_map(|n| {
            let info = &cfg[n];
            Some((info.call.callee.clone()?, info.all_args_literal))
        })
        .collect()
}

/// `.unwrap()` is rebound to the call underneath for gate payload positions,
/// but the literal-argument check never sees the receiver of that call.  A
/// literal argument list on a possibly tainted receiver must not read as
/// "all arguments literal", or the sink would be suppressed.
#[test]
fn rust_unwrap_rebind_never_counts_as_all_literal() {
    let flags = rust_call_literal_flags(
        b"fn f(h: Handle) { h.run(\"literal\").unwrap(); h.run(\"literal\"); }",
    );
    let unwrapped = flags
        .iter()
        .find(|(c, _)| c.contains("unwrap"))
        .expect("unwrap call node");
    assert!(!unwrapped.1, "peeled call must stay not-all-literal");
}

/// Whether the first prefix-test condition in the file was flagged as having a
/// root that provably lacks a trailing separator.
fn first_prefix_test_root_unterminated(src: &[u8], lang: &str, ts_lang: Language) -> bool {
    let file_cfg = parse_to_file_cfg(src, lang, ts_lang);
    for body in &file_cfg.bodies {
        for n in body.graph.node_indices() {
            let info = &body.graph[n];
            if info.condition_text.as_deref().is_some_and(|t| {
                crate::abstract_interp::path_domain::starts_with_root_arg(t).is_some()
            }) {
                return info.root_unterminated;
            }
        }
    }
    panic!("no prefix-test condition in source");
}

#[test]
fn js_root_constant_without_trailing_separator_is_flagged() {
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    let flagged = |root: &str| {
        let src = format!(
            "const path = require('path');\nconst ROOT = {root};\n\
             function f(p) {{ if (!p.startsWith(ROOT)) {{ return; }} use(p); }}"
        );
        first_prefix_test_root_unterminated(src.as_bytes(), "javascript", js.clone())
    };
    // path.resolve strips a trailing separator; a bare literal has none.
    assert!(flagged("path.resolve('/srv/files')"));
    assert!(flagged("'/srv/files'"));
    // A separator at the end of the literal, or appended to the call, makes
    // the root a directory prefix.
    assert!(!flagged("'/srv/files/'"));
    assert!(!flagged("path.resolve('/srv/files') + path.sep"));
    assert!(!flagged("path.resolve('/srv/files') + '/'"));
    // An opaque value is not resolved, so the lock stays accepted.
    assert!(!flagged("loadRoot()"));
    assert!(!flagged("process.env.ROOT"));
}

#[test]
fn root_constant_rebound_or_shadowed_is_not_flagged() {
    let js = Language::from(tree_sitter_javascript::LANGUAGE);
    // Two definitions: the value at the test is unknown.
    let rebound = b"let ROOT = '/srv/files';\nROOT = loadRoot();\n\
                    function f(p) { if (!p.startsWith(ROOT)) { return; } use(p); }";
    assert!(!first_prefix_test_root_unterminated(
        rebound,
        "javascript",
        js.clone()
    ));
    // A parameter named like the constant shadows it.
    let shadowed = b"const ROOT = '/srv/files';\n\
                     function f(p, ROOT) { if (!p.startsWith(ROOT)) { return; } use(p); }";
    assert!(!first_prefix_test_root_unterminated(
        shadowed,
        "javascript",
        js
    ));
}

#[test]
fn python_root_constant_without_trailing_separator_is_flagged() {
    let py = Language::from(tree_sitter_python::LANGUAGE);
    let flagged = |root: &str| {
        let src = format!(
            "import os\nROOT = {root}\n\
             def f(p):\n    if not p.startswith(ROOT):\n        return\n    use(p)\n"
        );
        first_prefix_test_root_unterminated(src.as_bytes(), "python", py.clone())
    };
    assert!(flagged("'/srv/files'"));
    assert!(flagged("os.path.abspath('/srv/files')"));
    assert!(flagged("os.path.realpath(BASE)"));
    assert!(!flagged("'/srv/files/'"));
    assert!(!flagged("os.path.abspath('/srv/files') + os.sep"));
    assert!(!flagged("os.path.join(BASE, '')"));
    assert!(!flagged("load_root()"));
}

#[test]
fn java_and_rust_root_constants_are_not_resolved() {
    // `startsWith` / `starts_with` may be component-wise `Path` methods there.
    let java = Language::from(tree_sitter_java::LANGUAGE);
    let src = b"class C { static final String ROOT = \"/srv/files\";\n\
                void f(String p) { if (!p.startsWith(ROOT)) { return; } use(p); } }";
    assert!(!first_prefix_test_root_unterminated(src, "java", java));
}

/// Whether any node of the snippet carries a DESERIALIZE sink label.
fn rust_has_deserialize_sink(src: &[u8]) -> bool {
    let file_cfg = parse_to_file_cfg(src, "rust", Language::from(tree_sitter_rust::LANGUAGE));
    file_cfg.bodies.iter().any(|b| {
        b.graph.node_indices().any(|n| {
            b.graph[n]
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::DESERIALIZE)))
        })
    })
}

#[test]
fn rust_dyn_let_annotation_makes_toml_decode_a_sink() {
    assert!(rust_has_deserialize_sink(
        b"fn f(s: &str) { let v: Box<dyn P> = toml::from_str(s).unwrap(); }"
    ));
    assert!(rust_has_deserialize_sink(
        b"fn f(s: &str) -> R { let v: Box<dyn P> = ron::from_str(s).map_err(e)?; Ok(()) }"
    ));
    assert!(!rust_has_deserialize_sink(
        b"fn f(s: &str) { let v: Config = toml::from_str(s).unwrap(); }"
    ));
    assert!(!rust_has_deserialize_sink(
        b"fn f(s: &str) { let v: Box<Config> = toml::from_str(s).unwrap(); }"
    ));
    assert!(!rust_has_deserialize_sink(
        b"fn f(s: &str) { let v: Result<Config, Box<dyn Error>> = toml::from_str(s); }"
    ));
    assert!(rust_has_deserialize_sink(
        b"fn f(s: &str) { let v: Result<Box<dyn P>, E> = toml::from_str(s); }"
    ));
    assert!(
        !rust_has_deserialize_sink(
            b"fn f(s: &str) { let (a, b): (Box<dyn P>, X) = (build(), toml::from_str(s)?); }"
        ),
        "a dyn annotation that is not the decode target must not label it"
    );
}

/// Whether any node of the Ruby snippet carries a sink label with `cap`.
fn ruby_has_sink(src: &[u8], cap: Cap) -> bool {
    let file_cfg = parse_to_file_cfg(src, "ruby", Language::from(tree_sitter_ruby::LANGUAGE));
    file_cfg.bodies.iter().any(|b| {
        b.graph.node_indices().any(|n| {
            b.graph[n]
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(cap)))
        })
    })
}

#[test]
fn ruby_connection_chain_keeps_the_connection_segment() {
    for src in [
        &b"def f(q)\n  ActiveRecord::Base.connection.execute(q)\nend"[..],
        b"def f(q)\n  Report.connection.execute(\n    \"S\" + q\n  )\nend",
        b"def f(q)\n  Report.lease_connection.execute(q)\nend",
    ] {
        assert!(
            ruby_has_sink(src, Cap::SQL_QUERY),
            "{}",
            String::from_utf8_lossy(src)
        );
    }
    assert!(!ruby_has_sink(
        b"def f(q)\n  Report.execute(q)\nend",
        Cap::SQL_QUERY
    ));
    assert!(!ruby_has_sink(
        b"def f(q)\n  Report.connection.reload(q)\nend",
        Cap::SQL_QUERY
    ));
}

/// Declared receiver type recorded on the Rust call nodes of a snippet, keyed
/// by callee text.
fn rust_receiver_decl_types(src: &[u8]) -> Vec<(String, Option<crate::ssa::type_facts::TypeKind>)> {
    let file_cfg = parse_to_file_cfg(src, "rust", Language::from(tree_sitter_rust::LANGUAGE));
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| {
            b.graph
                .node_indices()
                .filter_map(|n| {
                    let callee = b.graph[n].call.callee.clone()?;
                    Some((callee, b.graph[n].call.receiver_decl_type.clone()))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn rust_receiver_decl_type_follows_the_declaration() {
    use crate::ssa::type_facts::TypeKind;
    let src = br#"
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
struct Store { conn: Connection, pool: Arc<Mutex<Connection>>, log: Vec<String>, other: Other }
struct Other { n: u32 }
impl Store {
    fn field(&self) { self.conn.execute("a", []); }
    fn field_chain(&self) { self.conn.execute("b", []).unwrap(); }
    fn locked(&self) { let c = self.pool.lock().unwrap(); c.execute("c", []); }
    fn not_conn(&self) { self.log.push(1); self.other.touch(); }
    fn no_self() { self.conn.execute("d", []); }
    fn shadowed(&self) { let c = self.pool.lock().unwrap(); let c = make(); c.run_it(); }
    fn closure_shadow(&self) { let c = self.pool.lock().unwrap(); items.iter().for_each(|c| c.visit_it()); }
}
fn annotated() { let c: Connection = open_db(); c.execute("e", []); }
fn formal(pool: &Arc<Mutex<Connection>>) { let g = pool.lock().unwrap(); g.execute("f", []); }
fn pool_formal(pool: &Pool) { let g = pool.get().unwrap(); g.execute("g", []); }
fn plain_formal(conn: &Connection) { conn.execute("h", []); }
"#;
    let types = rust_receiver_decl_types(src);
    let kind_of = |callee_part: &str| {
        types
            .iter()
            .find(|(c, _)| c.contains(callee_part))
            .unwrap_or_else(|| panic!("no call node for {callee_part}: {types:?}"))
            .1
            .clone()
    };
    let conn = Some(TypeKind::DatabaseConnection);
    assert_eq!(kind_of("self.conn.execute"), conn, "{types:?}");
    assert_eq!(kind_of("c.execute"), conn);
    assert_eq!(kind_of("g.execute"), conn);
    assert_eq!(kind_of("self.log.push"), None);
    assert_eq!(kind_of("self.other.touch"), None);
    assert_eq!(kind_of("c.run_it"), None, "a later let shadows the guard");
    assert_eq!(
        kind_of("c.visit_it"),
        None,
        "a closure formal shadows the guard"
    );
    let no_self: Vec<_> = types
        .iter()
        .filter(|(c, _)| c.contains("self.conn.execute(\"d\""))
        .collect();
    assert!(no_self.iter().all(|(_, k)| k.is_none()), "{no_self:?}");
    let pool_get: Vec<_> = types
        .iter()
        .filter(|(c, _)| c.starts_with("g.execute(\"g\""))
        .collect();
    assert!(pool_get.iter().all(|(_, k)| k.is_none()), "{pool_get:?}");
}

/// Callee texts of the nested-call tree of the Ruby call node `callee`.
fn ruby_nested_callees(src: &[u8], callee: &str) -> Option<Vec<String>> {
    let file_cfg = parse_to_file_cfg(src, "ruby", Language::from(tree_sitter_ruby::LANGUAGE));
    for b in &file_cfg.bodies {
        for n in b.graph.node_indices() {
            let info = &b.graph[n];
            if info.call.callee.as_deref() == Some(callee) {
                return Some(
                    info.call
                        .nested_calls
                        .as_deref()
                        .map(|t| t.calls.iter().map(|c| c.callee.clone()).collect())
                        .unwrap_or_default(),
                );
            }
        }
    }
    None
}

#[test]
fn ruby_bare_identifier_argument_is_an_implicit_call_unless_bound() {
    let calls = |body: &str| {
        let src = format!("class C\n  def a(formal)\n{body}\n  end\nend\n");
        ruby_nested_callees(src.as_bytes(), "redirect_to")
            .unwrap_or_else(|| panic!("no redirect_to node in {src}"))
    };
    assert_eq!(calls("    redirect_to helper"), ["redirect_to", "helper"]);
    assert_eq!(calls("    redirect_to helper()"), ["redirect_to", "helper"]);
    // Locals, formals and block parameters are variables.
    assert!(
        calls("    helper = 1\n    redirect_to helper")
            .iter()
            .all(|c| c != "helper")
    );
    assert!(
        calls("    redirect_to formal")
            .iter()
            .all(|c| c != "formal")
    );
    assert!(
        calls("    [1].each { |helper| redirect_to helper }")
            .iter()
            .all(|c| c != "helper")
    );
    assert!(
        calls("    a, helper = pair\n    redirect_to helper")
            .iter()
            .all(|c| c != "helper")
    );
    assert!(
        calls("    for helper in list\n      redirect_to helper\n    end")
            .iter()
            .all(|c| c != "helper")
    );
    assert!(
        calls("    begin\n      go\n    rescue => helper\n      redirect_to helper\n    end")
            .iter()
            .all(|c| c != "helper")
    );
    // A name bound later in the method is still a variable: nothing is
    // guessed about control flow.
    assert!(
        calls("    redirect_to helper\n    helper = 1")
            .iter()
            .all(|c| c != "helper")
    );
    // A name that carries a label keeps its label handling.
    assert!(
        calls("    redirect_to params")
            .iter()
            .all(|c| c != "params")
    );
}

#[test]
fn c_short_circuit_condition_assignment_is_a_source_node() {
    let src = b"void f(void) {\n char *x;\n if ((x = getenv(\"T\")) == NULL || strlen(x) > 5) return;\n system(x);\n}\n";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let (g, _entry) = parse_and_build(src, "c", ts_lang);
    let n = g
        .node_indices()
        .find(|&i| g[i].taint.defines.as_deref() == Some("x") && g[i].kind == StmtKind::If)
        .expect("the assigning operand defines x");
    assert_eq!(g[n].call.callee.as_deref(), Some("getenv"));
    assert!(
        g[n].taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_)))
    );
}

#[test]
fn c_condition_assignment_target_is_not_a_read() {
    let src =
        b"void f(void) {\n char *cmd = getenv(\"X\");\n if ((cmd = safe) == NULL) return;\n}\n";
    let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
    let (g, _entry) = parse_and_build(src, "c", ts_lang);
    let n = g
        .node_indices()
        .find(|&i| g[i].taint.defines.as_deref() == Some("cmd") && g[i].kind == StmtKind::If)
        .expect("the condition defines cmd");
    assert_eq!(g[n].taint.uses, vec!["safe".to_string()]);
}

#[test]
fn c_call_through_a_local_function_pointer_has_no_function_callee() {
    // `cmp` is a variable here, so the call must not resolve to a function
    // that shares the name in this or another file.
    let callees_of = |src: &[u8]| -> Vec<String> {
        let ts_lang = Language::from(tree_sitter_c::LANGUAGE);
        let (g, _entry) = parse_and_build(src, "c", ts_lang);
        g.node_indices()
            .filter_map(|i| g[i].call.callee.clone())
            .collect()
    };
    let local = callees_of(
        b"int f(int (*pick)(const char *, const char *), const char *s) {\n int (*cmp)(const char *, const char *) = pick;\n int a = cmp(s, s);\n int b = pick(s, s);\n return a + b;\n}\n",
    );
    assert!(local.iter().any(|c| c == "(*cmp)"), "{local:?}");
    assert!(local.iter().any(|c| c == "(*pick)"), "{local:?}");
    let global = callees_of(b"int g(const char *s) { return cmp(s, s); }\n");
    assert!(global.iter().any(|c| c == "cmp"), "{global:?}");
}

fn ruby_call_node(file_cfg: &FileCfg, body: usize, callee_suffix: &str) -> NodeInfo {
    file_cfg.bodies[body]
        .graph
        .node_weights()
        .find(|n| {
            n.kind == StmtKind::Call
                && n.call
                    .callee
                    .as_deref()
                    .is_some_and(|c| c.ends_with(callee_suffix))
        })
        .unwrap_or_else(|| panic!("call to {callee_suffix} should exist"))
        .clone()
}

/// A block argument (`&blk`) is not a positional argument, so it must not
/// change the call's arity or add an `arg_uses` group.
#[test]
fn ruby_block_argument_is_not_positional() {
    let src = b"
def outer(p, blk)
  inner(p, &blk)
end
";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "ruby", ts_lang);
    let call = ruby_call_node(&file_cfg, 1, "inner");
    assert_eq!(call.call.arg_uses, vec![vec!["p".to_string()]]);
}

/// Keyword arguments aimed at a same-file method move to the slot of the
/// parameter of that name; omitted parameters leave an empty slot.
#[test]
fn ruby_keyword_args_follow_callee_parameter_order() {
    let src = b"
def target(a, dir: '.', name: 'x')
  use(a, dir, name)
end
def outer(p, q)
  target(p, name: q)
end
";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "ruby", ts_lang);
    let call = ruby_call_node(&file_cfg, 2, "target");
    assert_eq!(
        call.call.arg_uses,
        vec![vec!["p".to_string()], vec![], vec!["q".to_string()]]
    );
}

/// A keyword the callee does not declare leaves the call in syntactic order.
#[test]
fn ruby_unknown_keyword_keeps_syntactic_order() {
    let src = b"
def target(a, dir: '.')
  use(a, dir)
end
def outer(p, q)
  target(p, other: q)
end
";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "ruby", ts_lang);
    let call = ruby_call_node(&file_cfg, 2, "target");
    assert_eq!(
        call.call.arg_uses,
        vec![vec!["p".to_string()], vec!["q".to_string()]]
    );
}

/// Optional and keyword parameters count as parameters; splat and block
/// parameters do not.
#[test]
fn ruby_param_kinds_cover_optional_and_keyword() {
    let src = b"
def target(a, b = 1, *rest, c:, d: 2, &blk)
  use(a)
end
";
    let ts_lang = Language::from(tree_sitter_ruby::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "ruby", ts_lang);
    let names: Vec<_> = file_cfg
        .summaries
        .iter()
        .find(|(k, _)| k.name == "target")
        .map(|(_, s)| s.param_names.clone())
        .expect("summary for target");
    assert_eq!(names, vec!["a", "b", "c", "d"]);
}

#[cfg(test)]
mod popen_shell_shape_tests {
    use super::super::literals::extract_shell_array_payload_idents;
    use tree_sitter::Parser;

    fn matches(src: &str) -> usize {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let stmt = tree.root_node().named_child(0).unwrap();
        let call = stmt.named_child(0).unwrap();
        extract_shell_array_payload_idents(call, src.as_bytes()).len()
    }

    #[test]
    fn popen_shapes_that_run_code() {
        for src in [
            r#"Popen(["bash", "-lc", x])"#,
            r#"Popen(("bash", "-c", x))"#,
            r#"Popen(["env", "bash", "-c", x])"#,
            r#"Popen(["sudo", "-u", "root", "sh", "-c", x])"#,
            r#"Popen(["python", "-c", x])"#,
            r#"Popen(args=["bash", "-c", f"echo {x}"])"#,
            r#"Popen([x, "a"])"#,
            r#"Popen(args=[x, "a"])"#,
            r#"Popen(["bash", "-c", x], **opts)"#,
        ] {
            assert_eq!(matches(src), 1, "{src}");
        }
    }

    #[test]
    fn popen_shapes_that_do_not() {
        for src in [
            r#"Popen(["git", "log", x])"#,
            r#"Popen(["bash", "run.sh", x])"#,
            r#"Popen(["bash", "-c", "ls"])"#,
            r#"Popen(args=["git", "log", x])"#,
            r#"Popen(x)"#,
            r#"other([x, "a"])"#,
        ] {
            assert_eq!(matches(src), 0, "{src}");
        }
    }
}

fn go_elem_reads_of(src: &[u8]) -> Vec<Vec<String>> {
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "go", ts_lang);
    file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter(|n| !n.elem_reads.is_empty())
        // The synthetic element read of a call argument is not a statement.
        .filter(|n| n.call.callee.as_deref() != Some("__index_get__"))
        .map(|n| n.elem_reads.iter().map(|e| e.to_string()).collect())
        .collect()
}

/// Whether the node reading `parts[0]` in `src` is marked unstable.
fn go_elem_base_unstable_in(src: &str) -> bool {
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src.as_bytes(), "go", ts_lang);
    let nodes: Vec<_> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter(|n| !n.elem_reads.is_empty())
        .collect();
    assert!(!nodes.is_empty(), "no element read in {src}");
    nodes.iter().any(|n| n.elem_base_unstable)
}

#[test]
fn go_elem_base_with_other_write_routes_is_unstable() {
    let wrap = |mid: &str| {
        format!(
            "package p\nfunc f(s string) {{\n  parts := strings.Split(s, \" \")\n  {mid}\n  use(parts[0])\n}}"
        )
    };
    for mid in [
        "sort.Strings(parts)",
        "copy(parts, other)",
        "fill(parts)",
        "p := &parts; (*p)[0] = s",
        "q := parts; q[0] = s",
        "parts[0] = s",
        "set := func() { parts[0] = s }; set()",
        "r := parts[1:]; r[0] = s",
        "parts = append(parts, s)",
    ] {
        assert!(go_elem_base_unstable_in(&wrap(mid)), "{mid}");
    }
    for mid in [
        "n := len(parts)",
        "i := 1; _ = parts[i]",
        "for _, p := range parts { use(p) }",
        "parts = strings.Split(s, \",\")",
        "",
    ] {
        assert!(!go_elem_base_unstable_in(&wrap(mid)), "{mid}");
    }
}

#[test]
fn go_constant_index_reads_are_recorded() {
    let src = b"package p\n\
        func f(s string) {\n\
          parts := strings.Split(s, \" \")\n\
          x := parts[0]\n\
          y := parts[i]\n\
          if parts[1] != \"asc\" { return }\n\
          parts[2] = s\n\
          z := parts[0] + parts[1]\n\
          w := strings.Join(parts, parts[0])\n\
        }";
    let reads = go_elem_reads_of(src);
    assert!(reads.contains(&vec!["parts[0]".to_string()]), "{reads:?}");
    assert!(reads.contains(&vec!["parts[1]".to_string()]), "{reads:?}");
    assert!(
        reads.contains(&vec!["parts[0]".to_string(), "parts[1]".to_string()]),
        "{reads:?}"
    );
    // Variable index, an element store, and a base that is also read whole
    // record nothing.
    assert!(
        reads
            .iter()
            .flatten()
            .all(|e| e != "parts[2]" && e != "parts[i]"),
        "{reads:?}"
    );
    assert_eq!(reads.len(), 3, "{reads:?}");
}

#[test]
fn go_membership_lookup_accepts_constant_index_key() {
    let src = b"package p\n\
        func f(parts []string, m map[string]bool) {\n\
          _, ok := m[parts[0]]\n\
          _, ok2 := m[parts[i]]\n\
        }";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "go", ts_lang);
    let lookups: Vec<_> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .filter_map(|n| n.membership_lookup.as_ref())
        .collect();
    assert_eq!(lookups.len(), 1);
    assert_eq!(lookups[0].key, "parts[0]");
    assert_eq!(lookups[0].base, "m");
}

#[test]
fn go_map_stores_record_key_identifiers() {
    let src = b"package p\n\
        func f(cols []string) {\n\
          m := map[string]bool{}\n\
          n := map[string]bool{k: true, \"lit\": true}\n\
          for _, c := range cols { m[c] = true }\n\
          m[\"fixed\"] = true\n\
        }";
    let ts_lang = Language::from(tree_sitter_go::LANGUAGE);
    let file_cfg = parse_to_file_cfg(src, "go", ts_lang);
    let stores: Vec<_> = file_cfg
        .bodies
        .iter()
        .flat_map(|b| b.graph.node_weights())
        .flat_map(|n| n.map_stores.iter())
        .map(|s| (s.base.as_str(), s.key_idents.join(",")))
        .collect();
    assert!(stores.contains(&("m", "c".to_string())), "{stores:?}");
    assert!(stores.contains(&("n", "k".to_string())), "{stores:?}");
    assert!(stores.contains(&("m", String::new())), "{stores:?}");
}

#[test]
fn go_address_prefilter_sees_unary_address_of_names_only() {
    use super::go_body_takes_address_of_name as f;
    assert!(f(b"func f() { p := 1; g(&p) }"));
    assert!(f(b"func f() *T { var t T; return &t }"));
    assert!(f(b"func f() { x := &s.field }"));
    assert!(f(b"func f() { y = &(z) }"));
    assert!(!f(b"func f() { if a && b { g() } }"));
    assert!(!f(b"func f() { x := a & b; y &= 3; z := a &^ b }"));
    assert!(!f(b"func f() *T { return &T{A: 1} }"));
    assert!(!f(b"func f() { m := &pkg.Config{} }"));
}

#[test]
fn call_arg_nesting_descent_matches_the_bottom_up_walk() {
    use super::{call_arg_nesting_for_test, call_arg_nesting_reference};
    let cases: [(&[u8], Language); 4] = [
        (
            b"const r = rq(fs.createReadStream(p), { s: [open(q)], t: f(g(h())) });\nfoo(`a${b(c)}`);\nnew X(y(z), [w(v)]);",
            Language::from(tree_sitter_javascript::LANGUAGE),
        ),
        (
            b"x = json.load(open(p))\ny = f({'a': g(h)}, [k(m)], *args, n=o(p))\nz = sum(t(i) for i in r)\n",
            Language::from(tree_sitter_python::LANGUAGE),
        ),
        (
            b"package m\nfunc f() { a := g(h(i), []int{j(k)}, T{L: m(n)}); defer o(p(q)) }\n",
            Language::from(tree_sitter_go::LANGUAGE),
        ),
        (
            b"fn f() { let a = g(h(i), vec![j(k)], S { l: m(n) }); o(&[p(q)]); }",
            Language::from(tree_sitter_rust::LANGUAGE),
        ),
    ];
    for (src, lang) in cases {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let root = tree.root_node();
        // Every node as the target, under every ancestor as the root.
        let mut stack = vec![root];
        let mut checked = 0;
        while let Some(n) = stack.pop() {
            let mut anc = Some(n);
            while let Some(r) = anc {
                let span = (n.start_byte(), n.end_byte());
                assert_eq!(
                    call_arg_nesting_for_test(r, span),
                    call_arg_nesting_reference(r, span),
                    "root {} target {} ({:?})",
                    r.kind(),
                    n.kind(),
                    std::str::from_utf8(&src[span.0..span.1]).unwrap_or("")
                );
                checked += 1;
                anc = r.parent();
            }
            let mut c = n.walk();
            stack.extend(n.children(&mut c));
        }
        assert!(checked > 50);
    }
}

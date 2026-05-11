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

// ─────────────────────────────────────────────────────────────────
//  Ruby begin/rescue/ensure tests
// ─────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────
//  Short-circuit evaluation tests
// ─────────────────────────────────────────────────────────────────

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
            kwargs: vec![("shell".into(), vec!["True".into()])],
            arg_string_literals: vec![Some("lit".into())],
            destination_uses: None,
            gate_filters: Vec::new(),
            is_constructor: false,
            produces_null_proto: false,
        },
        taint: TaintMeta {
            labels: {
                let mut v = SmallVec::new();
                v.push(crate::labels::DataLabel::Source(crate::labels::Cap::all()));
                v
            },
            const_text: Some("42".into()),
            defines: Some("r".into()),
            uses: vec!["a".into(), "b".into()],
            extra_defines: vec!["c".into()],
            array_pattern_indices: smallvec::SmallVec::new(),
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
    assert_eq!(cloned.call.kwargs, original.call.kwargs);
    assert_eq!(cloned.taint.labels.len(), original.taint.labels.len());
    assert_eq!(cloned.taint.const_text, original.taint.const_text);
    assert_eq!(cloned.taint.defines, original.taint.defines);
    assert_eq!(cloned.taint.uses, original.taint.uses);
    assert_eq!(cloned.taint.extra_defines, original.taint.extra_defines);
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

// ─────────────────────────────────────────────────────────────────────
//  Anonymous function body naming via syntactic context
//  (derive_anon_fn_name_from_context coverage)
// ─────────────────────────────────────────────────────────────────────

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
    let node = find_node_with_callee(&cfg, "userDb.Raw")
        .expect("go: userDb.Raw node should be present");
    assert_eq!(node.call.receiver.as_deref(), Some("userDb"));
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

// ─────────────────────────────────────────────────────────────────
//   Gap-filling: switch / for / do-while / nested loops / re-throw
// ─────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────
//  Loop CFG structure: every loop variant must produce a Loop header
//  with at least one Back edge that targets that header. Without these
//  invariants the SSA loop-induction-variable phi placement is wrong
//  and the abstract-interp widening points are missed.
// ─────────────────────────────────────────────────────────────────────

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
    use std::collections::HashSet;
    use petgraph::visit::Bfs;
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
    parser.set_language(&Language::from(tree_sitter_java::LANGUAGE)).unwrap();
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
    parser.set_language(&Language::from(tree_sitter_java::LANGUAGE)).unwrap();
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

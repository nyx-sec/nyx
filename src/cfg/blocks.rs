use super::conditions::push_condition_node;
use super::{
    AstMeta, BodyCfg, BodyId, CallMeta, Cfg, EdgeKind, FuncSummaries, NodeInfo, StmtKind,
    TaintMeta, build_sub, collect_idents, collect_idents_with_paths, connect_all, emit_call_node,
    first_member_label, has_call_descendant, push_node, text_of, unwrap_parens,
};
use crate::cfg::fast_kind::{FastKind, lookup_node};
use crate::labels::{DataLabel, Kind, LangAnalysisRules};
use petgraph::graph::NodeIndex;
use tree_sitter::Node;

/// True when the language's multi-way branch never falls through from one
/// case into the next: Rust `match`, Go `switch` / `select`, Python `match`
/// and Ruby `case`.  Classic C/C++/JS/TS/PHP switches and Java colon-form
/// switches fall through; Java mixes both shapes, so it is decided per switch
/// in [`switch_is_exclusive`].
fn lang_has_exclusive_cases(lang: &str) -> bool {
    matches!(lang, "rust" | "go" | "python" | "ruby")
}

/// True when *this specific switch* has guaranteed-exclusive (non-fall-through)
/// cases, so it is safe to reorder the `default` arm to the cascade tail and
/// to send each case's exits straight past the switch.
///
/// Rust `match`, Go `switch` / `select`, Python `match` and Ruby `case` are
/// always exclusive. Java mixes shapes: the arrow form (`switch_rule` cases,
/// `case x -> ...`) is exclusive, but the classic colon form
/// (`switch_block_statement_group`, `case x:` with implicit fall-through) is
/// NOT. C/C++/JS/TS/PHP classic switches fall through and are never
/// exclusive. Reordering `default` to the tail is only correct for the
/// exclusive shapes; doing it for fall-through switches connects the wrong
/// case bodies in the source-order fall-through chain (both missed and phantom
/// taint flows).
fn switch_is_exclusive(lang: &str, cases: &[(Node<'_>, bool)]) -> bool {
    if lang_has_exclusive_cases(lang) {
        return true;
    }
    if lang == "java" {
        // Arrow-switch when every case is the arrow `switch_rule` shape.
        return cases.iter().all(|(c, _)| c.fkind() == "switch_rule");
    }
    false
}

/// True when `break` inside a case leaves the construct itself.  Rust
/// `match`, Python `match` and Ruby `case` have no `break` of their own: a
/// `break` in one of their arms leaves the enclosing loop.
fn switch_owns_break(lang: &str) -> bool {
    !matches!(lang, "rust" | "python" | "ruby")
}

/// True when the construct always runs exactly one of its arms, so the last
/// arm doubles as the default and no no-match path leads past it.  Rust
/// `match` is exhaustive, and Go `select` blocks until one case is ready.
fn switch_is_exhaustive(ast: Node<'_>, lang: &str) -> bool {
    matches!(
        (lang, ast.fkind()),
        ("rust", "match_expression") | ("go", "select_statement")
    )
}

/// The scrutinee expression of a switch-like node, with grouping parentheses
/// stripped.  `None` when the construct has none (Go `select`, Ruby's
/// subject-less `case`, unsupported grammars).
fn extract_scrutinee_node<'a>(ast: Node<'a>, lang: &str) -> Option<Node<'a>> {
    let field = match lang {
        "rust" | "go" | "javascript" | "typescript" | "tsx" | "ruby" => "value",
        "python" => "subject",
        "java" | "c" | "cpp" | "php" => "condition",
        _ => return None,
    };
    ast.child_by_field_name(field).map(unwrap_parens)
}

/// Extract a single literal/path text from a case AST when the case is a
/// plain mutually-exclusive literal pattern. Returns `None` for non-literal
/// patterns (wildcards, bindings, OR-patterns, range patterns, type patterns,
/// guards) and for fall-through-shaped Java cases.
fn extract_case_literal_text<'a>(case: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    let kind = case.fkind();
    match (lang, kind) {
        ("rust", "match_arm") => {
            // Reject guarded arms, `match x { y if cond => ... }`; the guard
            // is the `condition` field of the `match_pattern`.
            if case_guard(case, lang).is_some() {
                return None;
            }
            let pattern = case.child_by_field_name("pattern")?;
            // `match_pattern` wraps the real pattern as its first named
            // child.  A wildcard `_` has no named child at all.
            let inner = {
                let mut cursor = pattern.walk();
                pattern.named_children(&mut cursor).next()?
            };
            // Only plain literals and enum/const paths compare with `==`.
            // A bare identifier is a binding (or a unit const we cannot tell
            // apart from one), never a literal.
            if !matches!(
                inner.fkind(),
                "string_literal"
                    | "raw_string_literal"
                    | "char_literal"
                    | "integer_literal"
                    | "negative_literal"
                    | "boolean_literal"
                    | "scoped_identifier"
            ) {
                return None;
            }
            text_of(inner, code)
        }
        ("go", "expression_case") => {
            // Go case `case v1, v2: ...`, only handle exactly one expression.
            let value = case.child_by_field_name("value")?;
            let mut named_children: Vec<Node> = Vec::new();
            let mut cursor = value.walk();
            for child in value.children(&mut cursor) {
                if child.is_named() {
                    named_children.push(child);
                }
            }
            if named_children.len() == 1 {
                text_of(named_children[0], code)
            } else {
                None
            }
        }
        ("java", "switch_rule") => {
            // Java arrow-switch (no fall-through). Look for a switch_label
            // child whose contents are a single case value.
            let mut cursor = case.walk();
            for child in case.children(&mut cursor) {
                if child.fkind() != "switch_label" {
                    continue;
                }
                let mut named_values: Vec<Node> = Vec::new();
                let mut sl_cursor = child.walk();
                let mut saw_default = false;
                for sl_child in child.children(&mut sl_cursor) {
                    let k = sl_child.fkind();
                    if k == "default" || k == "default_label" {
                        saw_default = true;
                        break;
                    }
                    if k == "case" || k == ":" || k == "->" || k == "," {
                        continue;
                    }
                    if sl_child.is_named() {
                        named_values.push(sl_child);
                    }
                }
                if saw_default || named_values.len() != 1 {
                    return None;
                }
                // `case String s ->` is a type pattern, not a value.
                let value = named_values[0];
                if value.fkind() == "pattern" || value.fkind().ends_with("_pattern") {
                    return None;
                }
                return text_of(value, code);
            }
            None
        }
        _ => None,
    }
}

/// The part of a case that runs when the case is chosen.  Rust arms,
/// Python `case` clauses and Java arrow rules expose their body separately
/// from the pattern; every other case kind is walked whole (its label nodes
/// are harmless leaves).
fn case_body<'a>(case: Node<'a>, lang: &str) -> Node<'a> {
    let body = match (lang, case.fkind()) {
        ("rust", "match_arm") => case.child_by_field_name("value"),
        ("python", "case_clause") => case.child_by_field_name("consequence"),
        ("java", "switch_rule") => {
            let mut cursor = case.walk();
            case.named_children(&mut cursor)
                .last()
                .filter(|n| n.fkind() != "switch_label")
        }
        _ => None,
    };
    body.unwrap_or(case)
}

/// The guard expression of a case (`Some(x) if x > 0 =>`, `case x if x:`,
/// `case String s when s.isEmpty() ->`), if any.
fn case_guard<'a>(case: Node<'a>, lang: &str) -> Option<Node<'a>> {
    match (lang, case.fkind()) {
        ("rust", "match_arm") => case
            .child_by_field_name("pattern")?
            .child_by_field_name("condition"),
        ("python", "case_clause") => case.child_by_field_name("guard")?.named_child(0),
        ("java", "switch_rule") => {
            let mut cursor = case.walk();
            let label = case
                .children(&mut cursor)
                .find(|c| c.fkind() == "switch_label")?;
            let mut label_cursor = label.walk();
            let guard = label
                .children(&mut label_cursor)
                .find(|c| c.fkind() == "guard")?;
            guard.named_child(0)
        }
        _ => None,
    }
}

/// Names a case pattern binds from the scrutinee (`Ok(v)`, `case [a, *rest]`,
/// `case String s ->`), in source order without duplicates.
fn case_bindings(case: Node<'_>, lang: &str, code: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    match (lang, case.fkind()) {
        ("rust", "match_arm") => {
            if let Some(pattern) = case.child_by_field_name("pattern") {
                collect_rust_pattern_bindings(pattern, code, &mut out);
            }
        }
        ("python", "case_clause") => {
            let mut cursor = case.walk();
            for child in case.children(&mut cursor) {
                if child.fkind() == "case_pattern" {
                    collect_python_pattern_bindings(child, code, &mut out);
                }
            }
        }
        ("java", "switch_rule") => {
            let mut cursor = case.walk();
            if let Some(label) = case
                .children(&mut cursor)
                .find(|c| c.fkind() == "switch_label")
            {
                let mut label_cursor = label.walk();
                for child in label.children(&mut label_cursor) {
                    if child.fkind() == "pattern" {
                        collect_java_pattern_bindings(child, code, &mut out);
                    }
                }
            }
        }
        _ => {}
    }
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|name| seen.insert(name.clone()));
    out
}

/// A bare identifier in a Rust pattern binds a new name unless it starts with
/// an upper-case letter, which by convention is a unit variant or constant
/// (`None`, `MAX`) matched against.
fn is_rust_binding_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_lowercase() || c == '_')
}

/// Binding identifiers of a Rust pattern.  Paths, struct/variant names,
/// field names, range bounds and the arm guard never bind.
fn collect_rust_pattern_bindings(n: Node<'_>, code: &[u8], out: &mut Vec<String>) {
    match n.fkind() {
        "identifier" => {
            if let Some(name) = text_of(n, code)
                && is_rust_binding_name(&name)
                && name != "_"
            {
                out.push(name);
            }
        }
        "shorthand_field_identifier" => {
            if let Some(name) = text_of(n, code) {
                out.push(name);
            }
        }
        "scoped_identifier"
        | "scoped_type_identifier"
        | "type_identifier"
        | "field_identifier"
        | "range_pattern"
        | "generic_type"
        | "macro_invocation" => {}
        _ => {
            let mut cursor = n.walk();
            for (i, child) in n.children(&mut cursor).enumerate() {
                if matches!(
                    n.field_name_for_child(i as u32),
                    Some("type") | Some("condition")
                ) {
                    continue;
                }
                collect_rust_pattern_bindings(child, code, out);
            }
        }
    }
}

/// Capture names of a Python `case` pattern.  A bare name captures; a dotted
/// name (`Color.RED`), a class name, a keyword name and a mapping key are
/// matched against, never bound.
fn collect_python_pattern_bindings(n: Node<'_>, code: &[u8], out: &mut Vec<String>) {
    match n.fkind() {
        "dotted_name" => {
            if n.named_child_count() == 1
                && let Some(id) = n.named_child(0)
                && let Some(name) = text_of(id, code)
            {
                out.push(name);
            }
        }
        "identifier" => {
            // `*rest`, `**kw` and the alias of `pattern as name`.
            if let Some(name) = text_of(n, code)
                && name != "_"
            {
                out.push(name);
            }
        }
        "class_pattern" => {
            // `Point(x=0, y=yy)`: the class name is a direct `dotted_name`.
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                if child.fkind() != "dotted_name" {
                    collect_python_pattern_bindings(child, code, out);
                }
            }
        }
        "keyword_pattern" => {
            // `y=yy`: the keyword is a direct `identifier`.
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                if child.fkind() != "identifier" {
                    collect_python_pattern_bindings(child, code, out);
                }
            }
        }
        "dict_pattern" => {
            let mut cursor = n.walk();
            for (i, child) in n.children(&mut cursor).enumerate() {
                if n.field_name_for_child(i as u32) == Some("key") {
                    continue;
                }
                collect_python_pattern_bindings(child, code, out);
            }
        }
        _ => {
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                collect_python_pattern_bindings(child, code, out);
            }
        }
    }
}

/// Variables a Java type or record pattern declares (`String s`,
/// `Point(int x, var y)`).
fn collect_java_pattern_bindings(n: Node<'_>, code: &[u8], out: &mut Vec<String>) {
    if matches!(n.fkind(), "type_pattern" | "record_pattern_component") {
        let mut cursor = n.walk();
        if let Some(name) = n
            .named_children(&mut cursor)
            .last()
            .filter(|c| c.fkind() == "identifier")
            .and_then(|c| text_of(c, code))
        {
            out.push(name);
            return;
        }
    }
    let mut cursor = n.walk();
    for child in n.named_children(&mut cursor) {
        collect_java_pattern_bindings(child, code, out);
    }
}

//    Exception-source detection for try/catch wiring

/// Returns true if this CFG node can implicitly raise an exception (calls).
/// Explicit throws are collected separately via `throw_targets`.
pub(super) fn is_exception_source(info: &NodeInfo) -> bool {
    matches!(info.kind, StmtKind::Call)
}

/// Extract the catch parameter name from a catch clause AST node.
///
/// Returns `None` for parameter-less catch (`catch {}` in JS) or
/// catch-all (`catch(...)` in C++).
pub(super) fn extract_catch_param_name<'a>(
    catch_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Option<String> {
    match lang {
        "javascript" | "js" | "typescript" | "ts" | "tsx" => {
            // JS/TS: catch_clause has a "parameter" field
            let param = catch_node.child_by_field_name("parameter")?;
            text_of(param, code)
        }
        "java" => {
            // Java: catch_clause → catch_formal_parameter → field "name"
            let mut cursor = catch_node.walk();
            for child in catch_node.children(&mut cursor) {
                if child.fkind() == "catch_formal_parameter" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        return text_of(name_node, code);
                    }
                }
            }
            None
        }
        "php" => {
            // PHP: catch_clause has a "name" field, strip $ prefix
            let name_node = catch_node.child_by_field_name("name")?;
            text_of(name_node, code).map(|s| s.trim_start_matches('$').to_string())
        }
        "cpp" | "c++" => {
            // C++: catch_clause has a "parameters" field → collect idents → last
            let params = catch_node.child_by_field_name("parameters")?;
            let mut idents = Vec::new();
            collect_idents(params, code, &mut idents);
            idents.pop()
        }
        "python" | "py" => {
            // Python: except_clause has an "alias" field for `except Exception as e`
            let alias = catch_node.child_by_field_name("alias")?;
            text_of(alias, code)
        }
        "ruby" | "rb" => {
            // Ruby: rescue StandardError => e  →  exception_variable → identifier
            let var_node = catch_node.child_by_field_name("variable")?;
            let mut cursor = var_node.walk();
            for child in var_node.children(&mut cursor) {
                if child.fkind() == "identifier" {
                    return text_of(child, code);
                }
            }
            None
        }
        _ => None,
    }
}

//    finally / ensure on early exits

thread_local! {
    /// Nesting depth of early-exit `finally` copies being lowered next to a
    /// normal-completion copy (see [`build_finally_paths`]).  The Function
    /// arm of `build_sub` reads it through [`in_duplicate_finally_copy`].
    static DUPLICATE_FINALLY_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// True while the second copy of a `finally` / `ensure` clause is being
/// lowered.  A function or closure declared in the clause was already
/// registered by the first copy, so its second declaration site gets only a
/// placeholder node and no body of its own.
pub(super) fn in_duplicate_finally_copy() -> bool {
    DUPLICATE_FINALLY_DEPTH.with(|d| d.get() > 0)
}

struct DuplicateFinallyCopy;

impl DuplicateFinallyCopy {
    fn enter() -> Self {
        DUPLICATE_FINALLY_DEPTH.with(|d| d.set(d.get() + 1));
        DuplicateFinallyCopy
    }
}

impl Drop for DuplicateFinallyCopy {
    fn drop(&mut self) {
        DUPLICATE_FINALLY_DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Return nodes at or after node index `first` that nothing leaves yet: the
/// early exits of the try / catch bodies built since `first`.
///
/// A return rerouted through an inner `finally` already has its edge into
/// that clause, so it is not collected again.  The inner clause's tail
/// stands in for it (see [`build_finally_paths`]).
fn collect_abrupt_returns(g: &Cfg, first: usize, enclosing_func: Option<&str>) -> Vec<NodeIndex> {
    (first..g.node_count())
        .map(NodeIndex::new)
        .filter(|&idx| {
            g[idx].kind == StmtKind::Return
                && g[idx].ast.enclosing_func.as_deref() == enclosing_func
                && g.neighbors(idx).next().is_none()
        })
        .collect()
}

/// Lower a `finally` / `ensure` clause on the paths that reach it.
///
/// Control reaches the clause by falling out of the try and catch bodies
/// (`normal_preds`) and by returning from them.  `build_sub` ends a return's
/// path, so without more work a return never ran the clause: its releases
/// were invisible on the return path (resource-leak false positives), and a
/// clause every path returns through had no predecessor at all (its sinks
/// read as unreachable and were never analysed).
///
/// The clause is lowered once for the normal path, from `normal_preds`, and
/// once more for the early exits, from the Return nodes built since
/// `body_first_idx`.  Each such Return is marked `finally_return` and keeps
/// one edge into the second copy, which ends in a synthetic `finally_tail`
/// Return that carries the union of the returns' uses.  Nested clauses
/// compose: the inner tail is collected by the outer clause as one more
/// early exit, so inner cleanup runs before outer cleanup.
///
/// The first copy is skipped when nothing falls out of the bodies and some
/// path returns, so no orphan copy is left behind.  Break, continue and
/// throw leave a try without running its finally clause.
///
/// Returns the exits of the normal-path copy.
#[allow(clippy::too_many_arguments)]
fn build_finally_paths<'a>(
    clause: Node<'a>,
    normal_preds: &[NodeIndex],
    body_first_idx: usize,
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
    file_path: &str,
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
    break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
    throw_targets: &mut Vec<NodeIndex>,
    bodies: &mut Vec<BodyCfg>,
    next_body_id: &mut u32,
    current_body_id: BodyId,
) -> Vec<NodeIndex> {
    // Collect before either copy exists, so a return inside the clause itself
    // is not rerouted through the clause it sits in.
    let abrupt = collect_abrupt_returns(g, body_first_idx, enclosing_func);
    let normal_copy_built = abrupt.is_empty() || !normal_preds.is_empty();

    let normal_exits = if normal_copy_built {
        build_sub(
            clause,
            normal_preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        )
    } else {
        Vec::new()
    };
    if abrupt.is_empty() {
        return normal_exits;
    }

    let mut tail_uses: Vec<String> = Vec::new();
    let mut tail_returned: Vec<String> = Vec::new();
    for &ret in &abrupt {
        for u in &g[ret].taint.uses {
            if !tail_uses.contains(u) {
                tail_uses.push(u.clone());
            }
        }
        for n in &g[ret].returned_idents {
            if !tail_returned.contains(n) {
                tail_returned.push(n.clone());
            }
        }
        if g[ret].finally_tail {
            // The inner clause's tail is an early exit of this clause too:
            // it flows on into the copy below instead of returning.
            g[ret].kind = StmtKind::Seq;
            g[ret].finally_tail = false;
            g[ret].taint.uses.clear();
            g[ret].returned_idents.clear();
        } else {
            g[ret].finally_return = true;
        }
    }

    let copy_exits = {
        let _guard = normal_copy_built.then(DuplicateFinallyCopy::enter);
        build_sub(
            clause,
            &abrupt,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        )
    };
    if !copy_exits.is_empty() {
        let tail = g.add_node(NodeInfo {
            kind: StmtKind::Return,
            ast: AstMeta {
                span: (clause.end_byte(), clause.end_byte()),
                enclosing_func: enclosing_func.map(|s| s.to_string()),
            },
            taint: TaintMeta {
                uses: tail_uses,
                ..Default::default()
            },
            returned_idents: tail_returned,
            finally_tail: true,
            ..Default::default()
        });
        connect_all(g, &copy_exits, tail, EdgeKind::Seq);
    }
    normal_exits
}

//    Ruby begin/rescue/ensure handler

/// Builds CFG for Ruby's `begin`/`rescue`/`ensure` blocks (and `body_statement`
/// with inline rescue).  Ruby's `begin` has no `body` field, the try-body
/// statements are direct children before `rescue`/`else`/`ensure` nodes.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_begin_rescue<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
    file_path: &str,
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
    break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
    throw_targets: &mut Vec<NodeIndex>,
    bodies: &mut Vec<BodyCfg>,
    next_body_id: &mut u32,
    current_body_id: BodyId,
) -> Vec<NodeIndex> {
    // 1. Partition children into body / rescue / else / ensure
    let mut body_children: Vec<Node<'a>> = Vec::new();
    let mut rescue_clauses: Vec<Node<'a>> = Vec::new();
    let mut else_clause: Option<Node<'a>> = None;
    let mut ensure_clause: Option<Node<'a>> = None;

    let mut cursor = ast.walk();
    for child in ast.children(&mut cursor) {
        match child.fkind() {
            "rescue" => rescue_clauses.push(child),
            "else" => else_clause = Some(child),
            "ensure" => ensure_clause = Some(child),
            _ if lookup_node(lang, child) == Kind::Trivia => {}
            // Keywords like "begin", "end" appear as anonymous children
            "begin" | "end" => {}
            _ => body_children.push(child),
        }
    }

    // 2. Build try body sub-CFG (sequential, like Block handler)
    let try_body_first_idx = g.node_count();
    let mut try_throw_targets = Vec::new();
    let mut frontier = preds.to_vec();
    for child in &body_children {
        frontier = build_sub(
            *child,
            &frontier,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            &mut try_throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        );
    }
    let try_exits = frontier;
    let try_body_last_idx = g.node_count();

    // 3. Collect exception sources: implicit (calls) + explicit (throws)
    let mut exception_sources: Vec<NodeIndex> = Vec::new();
    for raw in try_body_first_idx..try_body_last_idx {
        let idx = NodeIndex::new(raw);
        if is_exception_source(&g[idx]) {
            exception_sources.push(idx);
        }
    }
    exception_sources.extend(&try_throw_targets);

    // 4. Build each rescue clause and wire exception edges
    let mut all_catch_exits: Vec<NodeIndex> = Vec::new();

    for rescue_node in &rescue_clauses {
        let param_name = extract_catch_param_name(*rescue_node, lang, code);

        // If the rescue has a named variable (=> e), inject a synthetic catch-param node
        let catch_preds = if let Some(ref name) = param_name {
            let synth = g.add_node(NodeInfo {
                kind: StmtKind::Seq,
                ast: AstMeta {
                    span: (rescue_node.start_byte(), rescue_node.start_byte()),
                    enclosing_func: enclosing_func.map(|s| s.to_string()),
                },
                taint: TaintMeta {
                    defines: Some(name.clone()),
                    ..Default::default()
                },
                call: CallMeta {
                    callee: Some(format!("catch({name})")),
                    ..Default::default()
                },
                catch_param: true,
                ..Default::default()
            });

            // Wire exception edges from every exception source → synthetic node
            for &src in &exception_sources {
                g.add_edge(src, synth, EdgeKind::Exception);
            }

            vec![synth]
        } else {
            // No param name, will wire exception edges to first rescue body node
            Vec::new()
        };

        // Build rescue body.  The rescue node's body may be in a "body" field
        // (a "then" node), or the statements may be direct children.
        let catch_first_idx = NodeIndex::new(g.node_count());
        let rescue_body = rescue_node.child_by_field_name("body");
        let catch_exits = if let Some(body_node) = rescue_body {
            build_sub(
                body_node,
                &catch_preds,
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                break_targets,
                continue_targets,
                throw_targets,
                bodies,
                next_body_id,
                current_body_id,
            )
        } else {
            // No body field, build rescue node itself as a block.
            // Filter out meta-children (exceptions, exception_variable) by
            // iterating and building only statement children.
            let mut rescue_cursor = rescue_node.walk();
            let mut rf = catch_preds.clone();
            for child in rescue_node.children(&mut rescue_cursor) {
                match child.fkind() {
                    "exceptions" | "exception_variable" => {}
                    _ if lookup_node(lang, child) == Kind::Trivia => {}
                    "=>" | "rescue" => {}
                    _ => {
                        rf = build_sub(
                            child,
                            &rf,
                            g,
                            lang,
                            code,
                            summaries,
                            file_path,
                            enclosing_func,
                            call_ordinal,
                            analysis_rules,
                            break_targets,
                            continue_targets,
                            throw_targets,
                            bodies,
                            next_body_id,
                            current_body_id,
                        );
                    }
                }
            }
            rf
        };

        // If no param name, wire exception edges to the first rescue body node
        if param_name.is_none() {
            let catch_entry = if catch_first_idx.index() < g.node_count() {
                catch_first_idx
            } else {
                continue;
            };
            for &src in &exception_sources {
                g.add_edge(src, catch_entry, EdgeKind::Exception);
            }
        }

        all_catch_exits.extend(catch_exits);
    }

    // 5. Build else clause (runs when no exception was raised)
    let normal_exits = if let Some(else_node) = else_clause {
        build_sub(
            else_node,
            &try_exits,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        )
    } else {
        try_exits
    };

    // 6. Build ensure clause (Ruby's finally, always runs)
    if let Some(ensure_node) = ensure_clause {
        let mut ensure_preds: Vec<NodeIndex> = Vec::new();
        ensure_preds.extend(&normal_exits);
        ensure_preds.extend(&all_catch_exits);
        if rescue_clauses.is_empty() {
            ensure_preds.extend(&try_throw_targets);
        }

        build_finally_paths(
            ensure_node,
            &ensure_preds,
            try_body_first_idx,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        )
    } else {
        // No ensure: return normal exits + catch exits
        let mut exits = normal_exits;
        exits.extend(all_catch_exits);
        exits
    }
}

//    switch handler, multi-way dispatch with fallthrough

/// True for AST kinds that wrap a single switch case body.
pub(super) fn is_switch_case_kind(lang: &str, kind: &str) -> bool {
    match lang {
        "rust" => kind == "match_arm",
        "python" => kind == "case_clause",
        // Only consulted for direct children of a `case`, where `else` is the
        // default arm.
        "ruby" => matches!(kind, "when" | "else"),
        "java" => matches!(kind, "switch_block_statement_group" | "switch_rule"),
        _ => matches!(
            kind,
            "switch_case"
                | "switch_default"
                | "case_statement"
                | "default_statement"
                | "expression_case"
                | "default_case"
                | "type_case"
                | "type_switch_case"
                | "communication_case"
        ),
    }
}

/// True for AST kinds that always represent the switch's `default` arm.
/// For C/C++/Java, default is encoded as a child label inside a generic case
/// kind; those are detected via `case_has_default_label` below.
pub(super) fn is_default_case_kind(kind: &str) -> bool {
    matches!(
        kind,
        "switch_default" | "default_statement" | "default_case"
    )
}

/// Detect a `default` label in a case-like AST node.  C/C++ put the keyword
/// among the case's own children; Java nests it in the `switch_label` child,
/// and parses the `default` of `case null, default ->` as an identifier.
pub(super) fn case_has_default_label(case: Node<'_>, code: &[u8]) -> bool {
    let mut cursor = case.walk();
    for child in case.children(&mut cursor) {
        let k = child.fkind();
        if k == "default" || k == "default_label" {
            return true;
        }
        if k == "switch_label" {
            let mut label_cursor = child.walk();
            let labelled_default = child.children(&mut label_cursor).any(|part| {
                part.fkind() == "default"
                    || (part.fkind() == "identifier"
                        && part.utf8_text(code).is_ok_and(|t| t == "default"))
            });
            if labelled_default {
                return true;
            }
        }
    }
    false
}

/// True when `case` is the arm taken when no other arm matches: an explicit
/// `default`, Ruby `else`, or an unguarded catch-all pattern (Rust `_` /
/// `name =>`, Python `case _:` / `case name:`).
fn is_default_case(lang: &str, case: Node<'_>, code: &[u8]) -> bool {
    match (lang, case.fkind()) {
        ("ruby", "else") => true,
        ("rust", "match_arm") => {
            case_guard(case, lang).is_none()
                && case.child_by_field_name("pattern").is_some_and(|p| {
                    let mut cursor = p.walk();
                    let named: Vec<Node> = p.named_children(&mut cursor).collect();
                    match named.as_slice() {
                        // `_` is an anonymous token.
                        [] => true,
                        [only] => {
                            only.fkind() == "identifier"
                                && text_of(*only, code).is_some_and(|t| is_rust_binding_name(&t))
                        }
                        _ => false,
                    }
                })
        }
        ("python", "case_clause") => {
            if case_guard(case, lang).is_some() {
                return false;
            }
            let mut cursor = case.walk();
            let patterns: Vec<Node> = case
                .children(&mut cursor)
                .filter(|c| c.fkind() == "case_pattern")
                .collect();
            let [pattern] = patterns.as_slice() else {
                return false;
            };
            let mut pattern_cursor = pattern.walk();
            let named: Vec<Node> = pattern.named_children(&mut pattern_cursor).collect();
            match named.as_slice() {
                [] => true,
                [only] => only.fkind() == "dotted_name" && only.named_child_count() == 1,
                _ => false,
            }
        }
        _ => is_default_case_kind(case.fkind()) || case_has_default_label(case, code),
    }
}

/// Go case whose last statement is `fallthrough`: control continues into the
/// next case body even though Go cases are otherwise exclusive.
fn case_ends_with_fallthrough(case: Node<'_>, lang: &str) -> bool {
    fn last_stmt(n: Node<'_>) -> Option<Node<'_>> {
        let mut cursor = n.walk();
        n.named_children(&mut cursor)
            .filter(|c| c.fkind() != "comment")
            .last()
    }
    if lang != "go" {
        return false;
    }
    let list = {
        let mut cursor = case.walk();
        case.children(&mut cursor)
            .find(|c| c.fkind() == "statement_list")
    };
    let mut last = list.and_then(last_stmt);
    while let Some(n) = last
        && n.fkind() == "labeled_statement"
    {
        last = last_stmt(n);
    }
    last.is_some_and(|n| n.fkind() == "fallthrough_statement")
}

/// Node that binds a case pattern's names from the scrutinee value, emitted
/// as the first node of the case.
fn push_binding_node(
    g: &mut Cfg,
    span: (usize, usize),
    names: Vec<String>,
    uses: Vec<String>,
    enclosing_func: Option<&str>,
) -> NodeIndex {
    let mut names = names.into_iter();
    let defines = names.next();
    g.add_node(NodeInfo {
        kind: StmtKind::Seq,
        taint: TaintMeta {
            defines,
            extra_defines: names.collect(),
            uses,
            ..Default::default()
        },
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    })
}

/// Synthetic pass-through node giving a branch edge a concrete target.
fn push_pass_node(g: &mut Cfg, at: usize, enclosing_func: Option<&str>) -> NodeIndex {
    g.add_node(NodeInfo {
        kind: StmtKind::Seq,
        ast: AstMeta {
            span: (at, at),
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    })
}

/// Build CFG for a multi-way branch: C/C++/JS/TS/PHP/Java/Go `switch`, Go
/// `select`, Rust `match`, Python `match` and Ruby `case`.
///
/// The scrutinee runs first and gets its own Call node when it contains a
/// call (a Go `switch init; x` initializer runs before it).  The dispatch is
/// then decomposed into a chain of binary `StmtKind::If` headers, one per
/// non-default case, because the SSA terminator only models 0/1/2
/// successors. A monolithic N-way header would otherwise be collapsed to
/// `Goto(first)` and silently drop every other case. Each header's True edge
/// reaches its case; the False edge falls through to the next header (or the
/// default body, if present, or the post-switch code).  A case whose pattern
/// binds names (`Ok(v)`, `case [a, b]`, `case String s`) starts with a node
/// defining them from the scrutinee, and a guarded case gets a second header
/// for its guard whose False edge also continues the dispatch.
///
/// In a fall-through switch (C/C++/JS/TS/PHP, Java colon form) the previous
/// case's exits are chained as additional predecessors of the next case's
/// first node.  In an exclusive one every case leaves the switch directly,
/// except a Go case ending in `fallthrough`.  `break` inside a case targets a
/// fresh switch-scoped break list, except in Rust/Python/Ruby where it
/// belongs to the enclosing loop.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_switch<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
    file_path: &str,
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
    break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
    throw_targets: &mut Vec<NodeIndex>,
    bodies: &mut Vec<BodyCfg>,
    next_body_id: &mut u32,
    current_body_id: BodyId,
) -> Vec<NodeIndex> {
    // Locate the case container. Most grammars expose it as field "body"
    // (JS/TS, Java, C, C++, Rust, Python); Go puts cases as direct children
    // of the switch, and Ruby `case` / Go `select` have no body at all.
    //
    // Per-language gotcha: Go's `expression_case` / `default_case` /
    // `type_case` / `communication_case` map to `Kind::Block` (so the case
    // body is iterated by the Block handler), so a naive "first Block
    // child" fallback latches onto the FIRST case as the container, then
    // walks the case's interior looking for case-like children, finds none,
    // and falls through to the empty-cases early return (CFG dead-end:
    // dispatch If has no False edge, every post-switch statement becomes
    // unreachable).  Skip case-kind nodes when picking the container so
    // Go's flat "cases-as-direct-children" shape uses `ast` itself.  Ruby's
    // `else` arm is a Block too, so `case` skips the fallback entirely.
    let body = if matches!(
        (lang, ast.fkind()),
        ("ruby", "case") | ("go", "select_statement")
    ) {
        None
    } else {
        ast.child_by_field_name("body").or_else(|| {
            let mut c = ast.walk();
            ast.children(&mut c).find(|n| {
                matches!(lookup_node(lang, n), Kind::Block) && !is_switch_case_kind(lang, n.fkind())
            })
        })
    };
    let container = body.unwrap_or(ast);

    // Collect case-like children in source order. Default goes through the
    // same path as other cases but is tracked separately so the dispatch
    // chain's tail can fall into it instead of past the switch.
    let mut cases: Vec<(Node<'a>, bool)> = Vec::new();
    {
        let mut cursor = container.walk();
        for case in container.children(&mut cursor) {
            if !is_switch_case_kind(lang, case.fkind()) {
                continue;
            }
            cases.push((case, is_default_case(lang, case, code)));
        }
    }

    // `break` inside a case: a switch-scoped list, or the enclosing loop's.
    let owns_break = switch_owns_break(lang);
    let mut switch_breaks: Vec<NodeIndex> = Vec::new();

    // Everything that runs before the dispatch: Go's `switch init; x`
    // initializer, then the scrutinee.  A scrutinee with a call is lowered
    // as its own Call node, so a source or sink in `match f(x)` or
    // `switch (exec(x))` is analysed like any other call; a bare scrutinee
    // only contributes its identifiers to the arms' pattern bindings.
    let mut dispatch_preds: Vec<NodeIndex> = preds.to_vec();
    if lang == "go"
        && let Some(init) = ast.child_by_field_name("initializer")
    {
        dispatch_preds = build_sub(
            init,
            &dispatch_preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            if owns_break {
                &mut switch_breaks
            } else {
                &mut *break_targets
            },
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        );
    }
    let scrutinee = extract_scrutinee_node(ast, lang);
    // Go `switch t := v.(type)` binds `t` in every clause.
    let go_alias: Vec<String> = if lang == "go" && ast.fkind() == "type_switch_statement" {
        let mut names = Vec::new();
        if let Some(alias) = ast.child_by_field_name("alias") {
            collect_idents(alias, code, &mut names);
        }
        names
    } else {
        Vec::new()
    };
    let needs_scrutinee_value = !go_alias.is_empty()
        || cases
            .iter()
            .any(|(c, _)| !case_bindings(*c, lang, code).is_empty());
    let mut scrutinee_uses: Vec<String> = Vec::new();
    if let Some(scrut) = scrutinee {
        // A scrutinee that reads a source member (`request.args.get("x")`,
        // `request.json`) is a Source the same way that expression is on
        // the right of an assignment.
        let member_source = first_member_label(
            scrut,
            lang,
            code,
            analysis_rules.map(|r| r.extra_labels.as_slice()),
        )
        .filter(|l| matches!(l, DataLabel::Source(_)));
        let scrut_is_call = matches!(
            lookup_node(lang, scrut),
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro
        );
        if scrut_is_call || has_call_descendant(scrut, lang) {
            let (n, _) = emit_call_node(
                scrut,
                &dispatch_preds,
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                if owns_break {
                    &mut switch_breaks
                } else {
                    &mut *break_targets
                },
                continue_targets,
                throw_targets,
                bodies,
                next_body_id,
                current_body_id,
            );
            if g[n].taint.labels.is_empty()
                && let Some(label) = member_source
            {
                g[n].taint.labels.push(label);
            }
            // The bindings need a name for the scrutinee's value.
            if let Some(def) = g[n].taint.defines.clone() {
                scrutinee_uses.push(def);
            } else if needs_scrutinee_value {
                let synth = format!("__nyx_scrut_{}", n.index());
                g[n].taint.defines = Some(synth.clone());
                scrutinee_uses.push(synth);
            }
            dispatch_preds = vec![n];
        } else {
            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(scrut, code, &mut idents, &mut paths);
            scrutinee_uses.extend(paths);
            scrutinee_uses.extend(idents);
            // A source member scrutinee gets a value node of its own so the
            // bindings read a Source-labelled definition.
            if needs_scrutinee_value && let Some(label) = member_source {
                let synth = format!("__nyx_scrut_{}", g.node_count());
                let n = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    call: CallMeta {
                        callee: text_of(scrut, code),
                        ..Default::default()
                    },
                    taint: TaintMeta {
                        labels: std::iter::once(label).collect(),
                        defines: Some(synth.clone()),
                        uses: std::mem::take(&mut scrutinee_uses),
                        ..Default::default()
                    },
                    ast: AstMeta {
                        span: (scrut.start_byte(), scrut.end_byte()),
                        enclosing_func: enclosing_func.map(|s| s.to_string()),
                    },
                    ..Default::default()
                });
                connect_all(g, &dispatch_preds, n, EdgeKind::Seq);
                dispatch_preds = vec![n];
                scrutinee_uses = vec![synth];
            }
        }
    }
    if !go_alias.is_empty() {
        let span = ast
            .child_by_field_name("alias")
            .map(|a| (a.start_byte(), a.end_byte()))
            .unwrap_or((ast.start_byte(), ast.start_byte()));
        let n = push_binding_node(g, span, go_alias, scrutinee_uses.clone(), enclosing_func);
        connect_all(g, &dispatch_preds, n, EdgeKind::Seq);
        dispatch_preds = vec![n];
    }

    // Grammar didn't expose recognisable case nodes, fall back to a single
    // header + Block-style walk so nodes still get linked.
    if cases.is_empty() {
        let header = push_node(
            g,
            StmtKind::If,
            ast,
            lang,
            code,
            enclosing_func,
            0,
            analysis_rules,
        );
        connect_all(g, &dispatch_preds, header, EdgeKind::Seq);
        let mut frontier = vec![header];
        let mut cursor = container.walk();
        for child in container.children(&mut cursor) {
            frontier = build_sub(
                child,
                &frontier,
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                if owns_break {
                    &mut switch_breaks
                } else {
                    &mut *break_targets
                },
                continue_targets,
                throw_targets,
                bodies,
                next_body_id,
                current_body_id,
            );
        }
        let mut exits = switch_breaks;
        exits.extend(frontier);
        return exits;
    }

    // Rust `match` and Go `select` always take one arm: with no explicit
    // default, the last (unguarded) arm is the fallback, so no no-match path
    // escapes past the construct.
    if switch_is_exhaustive(ast, lang)
        && !cases.iter().any(|(_, d)| *d)
        && let Some(last) = cases.last_mut()
        && case_guard(last.0, lang).is_none()
    {
        last.1 = true;
    }

    // Whether this switch's cases are mutually exclusive (no fall-through).
    // Only exclusive switches may have `default` reordered to the cascade
    // tail, and only while no Go case falls through explicitly (that keeps
    // the source order load-bearing).
    let is_exclusive = switch_is_exclusive(lang, &cases);
    let any_explicit_fallthrough = cases
        .iter()
        .any(|(c, _)| case_ends_with_fallthrough(*c, lang));
    let reorder_default = is_exclusive && !any_explicit_fallthrough;

    // Reorder so the default arm (if any) sits at the tail of the cascade.
    // Reordering case dispatch is semantically harmless ONLY for mutually
    // exclusive pattern matches (Rust match, Go switch, Java arrow-switch); it
    // keeps the chain a clean Branch(True→case, False→next). For classic
    // fall-through switches (C/C++/JS/TS/PHP, Java colon-switch) a mid-chain
    // `default:` can fall into the following case and a preceding case can fall
    // into it, so the source order MUST be preserved — reordering there breaks
    // the fall-through Seq layer and produces both missed and phantom flows.
    let default_pos = cases.iter().position(|(_, d)| *d);
    if reorder_default
        && let Some(pos) = default_pos
        && pos != cases.len() - 1
    {
        let default_pair = cases.remove(pos);
        cases.push(default_pair);
    }

    // For mutually-exclusive switch shapes (Rust match, Go switch, Java
    // arrow-switch), pre-extract the scrutinee text + idents so the synthetic
    // dispatch headers can carry a `<scrutinee> == <case_literal>` condition.
    // Falls back to `None` when the scrutinee is structurally complex (calls,
    // member chains, parenthesized expressions in Go), the existing first-
    // reachable behavior remains correct in that case.
    let supports_exclusive_cases = lang_has_exclusive_cases(lang) || lang == "java";
    let (scrutinee_text, scrutinee_idents) = if supports_exclusive_cases {
        match scrutinee {
            Some(scrut) => {
                let mut idents = Vec::new();
                collect_idents(scrut, code, &mut idents);
                idents.sort();
                idents.dedup();
                let text = text_of(scrut, code).map(|s| s.trim().to_string());
                // Keep only when the scrutinee is a single bare identifier;
                // anything more complex falls back to no condition_text. This
                // prevents synthesizing nonsense like `f(x) == 200`.
                let single_ident =
                    matches!((&text, idents.as_slice()), (Some(t), [name]) if t == name);
                if single_ident {
                    (text, idents)
                } else {
                    (None, Vec::new())
                }
            }
            None => (None, Vec::new()),
        }
    } else {
        (None, Vec::new())
    };

    let mut fallthrough_exits: Vec<NodeIndex> = Vec::new();
    let mut exclusive_exits: Vec<NodeIndex> = Vec::new();
    // Nodes whose "no case matched yet" path continues to the next dispatch
    // target (Seq edges), and the subset of them that are branch headers and
    // also need a False edge there.
    let mut chain_preds: Vec<NodeIndex> = dispatch_preds;
    let mut false_srcs: Vec<NodeIndex> = Vec::new();
    // Set once a tail default has taken over the no-match path.
    let mut no_match_consumed = false;
    // First node of the `default` body for a fall-through switch where the
    // default is NOT at the tail. The cumulative no-match path (the last
    // non-default header's False edge) is wired into it after the loop, so the
    // default stays in its source position for the fall-through Seq layer while
    // still being reachable when no case matches.
    let mut pending_default_no_match: Option<NodeIndex> = None;

    for (idx, (case, is_default)) in cases.iter().copied().enumerate() {
        let is_last = idx + 1 == cases.len();

        // A `default` arm carries no discriminant test, so it never gets its
        // own dispatch If. For exclusive switches it has been reordered to the
        // tail (`is_last`); for fall-through switches it stays in source
        // position and is wired into the Seq fall-through chain instead of
        // acting as a conditional branch.
        let default_no_dispatch = is_default && (is_last || !reorder_default);

        // Predecessors of the case's first node, the header whose True edge
        // enters it, and the headers whose False edge does (tail default).
        let mut entry: Vec<NodeIndex>;
        let mut true_src: Option<NodeIndex> = None;
        let mut false_into_case: Vec<NodeIndex> = Vec::new();
        if default_no_dispatch {
            // Body entry = fall-through from the preceding case body.
            entry = std::mem::take(&mut fallthrough_exits);
            if is_last {
                // Tail default: the no-match path lands here.
                entry.append(&mut chain_preds);
                false_into_case = std::mem::take(&mut false_srcs);
                no_match_consumed = true;
            }
            // For a non-tail (fall-through) default the dispatch chain must
            // continue PAST it, so the chain is left untouched and the next
            // case's dispatch header still receives the previous header's
            // False edge. The cumulative no-match entry is recorded below once
            // the body's first node is known.
        } else {
            // Normal case: synthesize a per-case dispatch header. We tie it
            // to the case AST so the node carries a useful span.
            let header = push_node(
                g,
                StmtKind::If,
                case,
                lang,
                code,
                enclosing_func,
                0,
                analysis_rules,
            );
            // The dispatch header is purely structural (it stands in for the
            // discriminant comparison). It must not inherit Sink/Source labels
            // from the case body's text, push_node uses `text_of(ast)` for
            // non-call kinds, which would let the body text drive classification.
            g[header].taint.labels.clear();
            g[header].call.callee = None;
            g[header].call.sink_payload_args = None;
            g[header].call.destination_uses = None;
            g[header].call.gate_filters.clear();
            // For mutually-exclusive switch shapes with a single-ident
            // scrutinee, synthesize a `<scrutinee> == <case_literal>`
            // structured condition on the dispatch header so SSA lowering
            // builds a concrete `Comparison` ConditionExpr. The existing
            // executor Branch arm then forks per-case with the right path
            // refinement. Skipped for non-literal patterns (OR-patterns,
            // ranges, guards), which fall back to the legacy behavior.
            if let Some(scrut_text) = scrutinee_text.as_ref() {
                if let Some(case_lit) = extract_case_literal_text(case, lang, code) {
                    g[header].condition_text = Some(format!("{} == {}", scrut_text, case_lit));
                    g[header].condition_vars = scrutinee_idents.clone();
                    g[header].condition_negated = false;
                }
            }
            connect_all(g, &chain_preds, header, EdgeKind::Seq);
            // The previous headers' False edges land on this header.
            for &prev in &false_srcs {
                g.add_edge(prev, header, EdgeKind::False);
            }
            entry = vec![header];
            entry.append(&mut fallthrough_exits);
            chain_preds = vec![header];
            false_srcs = vec![header];
            true_src = Some(header);
        }

        // Snapshot the next node index so we can attach the True edge to
        // the case's first emitted node.
        let case_first_idx = NodeIndex::new(g.node_count());

        // Pattern bindings run as soon as the arm is chosen, before its guard.
        let bindings = case_bindings(case, lang, code);
        if !bindings.is_empty() {
            let pattern = case.child_by_field_name("pattern").or_else(|| {
                let mut cursor = case.walk();
                case.children(&mut cursor)
                    .find(|c| matches!(c.fkind(), "case_pattern" | "switch_label"))
            });
            let span = pattern
                .map(|p| (p.start_byte(), p.end_byte()))
                .unwrap_or((case.start_byte(), case.start_byte()));
            let b = push_binding_node(g, span, bindings, scrutinee_uses.clone(), enclosing_func);
            connect_all(g, &entry, b, EdgeKind::Seq);
            entry = vec![b];
        }

        // A guarded case is a second test: guard False continues the dispatch.
        let guard_header = case_guard(case, lang).map(|guard| {
            let gh = push_condition_node(
                g,
                guard,
                lang,
                code,
                enclosing_func,
                call_ordinal,
                analysis_rules,
            );
            connect_all(g, &entry, gh, EdgeKind::Seq);
            gh
        });
        if let Some(gh) = guard_header {
            entry = vec![gh];
            chain_preds.push(gh);
            false_srcs.push(gh);
        }

        let body_first_idx = NodeIndex::new(g.node_count());
        let exits = build_sub(
            case_body(case, lang),
            &entry,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            if owns_break {
                &mut switch_breaks
            } else {
                &mut *break_targets
            },
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        );
        // A case that emits no node (`_ => {}`, `case 1:` with an empty
        // body) still needs a concrete branch target: without one the
        // header's True/False labelling is lost and SSA folds both of its
        // successors into one.  Same synthetic pass-through node the `if`
        // lowering uses for a missing else.
        let exits = if body_first_idx.index() == g.node_count() && exits == entry {
            let pass = push_pass_node(g, case.end_byte(), enclosing_func);
            connect_all(g, &entry, pass, EdgeKind::Seq);
            vec![pass]
        } else {
            exits
        };

        // Wire the dispatch True edge from this header (or the False edges of
        // the previous headers for a tail default) to the case's first node.
        if case_first_idx.index() < g.node_count() {
            if let Some(h) = true_src {
                g.add_edge(h, case_first_idx, EdgeKind::True);
            } else if is_last && default_no_dispatch {
                // Tail default: the previous headers already reach it via the
                // Seq edges from `entry`; the False edges let SSA label the
                // branch.
                for prev in false_into_case {
                    g.add_edge(prev, case_first_idx, EdgeKind::False);
                }
            } else {
                // Non-tail fall-through default: defer wiring the no-match
                // entry until the last non-default header's False edge is
                // known (after the loop). The body's only in-edge for now
                // is the source-order fall-through from the preceding case.
                pending_default_no_match = Some(case_first_idx);
            }
        }
        if let Some(gh) = guard_header
            && body_first_idx.index() < g.node_count()
        {
            g.add_edge(gh, body_first_idx, EdgeKind::True);
        }

        // An exclusive case leaves the switch; a fall-through one continues
        // into the next case body.
        if is_exclusive && !case_ends_with_fallthrough(case, lang) {
            exclusive_exits.extend(exits);
        } else {
            fallthrough_exits = exits;
        }
    }

    // Resolve the cumulative no-match path (the last headers' False edges):
    //   - If the `default` arm sits mid-chain (fall-through switch), the
    //     no-match path enters the default body: wire the deferred False
    //     edges into it. The default stayed in source position for the
    //     fall-through Seq layer, so these are the only edges making it
    //     reachable on no-match.
    //   - Otherwise, unless a tail default already took it over, the
    //     no-match path escapes to the post-switch frontier.
    let mut exits: Vec<NodeIndex> = switch_breaks;
    exits.append(&mut exclusive_exits);
    exits.append(&mut fallthrough_exits);
    if let Some(default_first) = pending_default_no_match {
        for &prev in &false_srcs {
            g.add_edge(prev, default_first, EdgeKind::False);
        }
    } else if !no_match_consumed {
        let pass = push_pass_node(g, ast.end_byte(), enclosing_func);
        for &prev in &chain_preds {
            let kind = if false_srcs.contains(&prev) {
                EdgeKind::False
            } else {
                EdgeKind::Seq
            };
            g.add_edge(prev, pass, kind);
        }
        exits.push(pass);
    }
    exits
}

//    try/catch/finally handler

#[allow(clippy::too_many_arguments)]
pub(super) fn build_try<'a>(
    ast: Node<'a>,
    preds: &[NodeIndex],
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    summaries: &mut FuncSummaries,
    file_path: &str,
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
    break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
    throw_targets: &mut Vec<NodeIndex>,
    bodies: &mut Vec<BodyCfg>,
    next_body_id: &mut u32,
    current_body_id: BodyId,
) -> Vec<NodeIndex> {
    // Ruby begin/rescue/ensure: no "body" field, has "rescue" or "ensure" children.
    // Delegate to the dedicated handler.
    if ast.child_by_field_name("body").is_none() {
        let mut cursor = ast.walk();
        let has_rescue_or_ensure = ast
            .children(&mut cursor)
            .any(|c| c.fkind() == "rescue" || c.fkind() == "ensure");
        if has_rescue_or_ensure {
            return build_begin_rescue(
                ast,
                preds,
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                break_targets,
                continue_targets,
                throw_targets,
                bodies,
                next_body_id,
                current_body_id,
            );
        }
    }

    // 1. Extract child AST nodes (language-aware field lookup)
    let try_body = ast.child_by_field_name("body");

    // Catch clauses: JS/TS use "handler" field, Java uses positional "catch_clause" children
    let catch_clauses: Vec<Node<'a>> = {
        let mut clauses = Vec::new();
        if let Some(handler) = ast.child_by_field_name("handler") {
            clauses.push(handler);
        }
        // Also collect positional catch_clause children (Java, PHP, C++)
        let mut cursor = ast.walk();
        for child in ast.children(&mut cursor) {
            if (child.fkind() == "catch_clause" || child.fkind() == "except_clause")
                && !clauses.iter().any(|c| c.id() == child.id())
            {
                clauses.push(child);
            }
        }
        clauses
    };

    // Finally: JS/TS use "finalizer" field, Java/PHP use positional "finally_clause" child
    let finally_clause = ast.child_by_field_name("finalizer").or_else(|| {
        let mut cursor = ast.walk();
        ast.children(&mut cursor)
            .find(|child| child.fkind() == "finally_clause")
    });

    // For Java try-with-resources: build resources as sequential predecessors
    let try_preds = if let Some(resources) = ast.child_by_field_name("resources") {
        let first_resource_idx = g.node_count();
        let result = build_sub(
            resources,
            preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        );
        // Mark actual resource acquisition nodes (Call + defines) as managed.
        // Java try-with-resources guarantees AutoCloseable.close() is called.
        for raw in first_resource_idx..g.node_count() {
            let idx = NodeIndex::new(raw);
            if g[idx].kind == StmtKind::Call && g[idx].taint.defines.is_some() {
                g[idx].managed_resource = true;
            }
        }
        result
    } else {
        preds.to_vec()
    };

    // 2. Build try body sub-CFG
    let try_body_first_idx = g.node_count();
    let mut try_throw_targets = Vec::new();
    let try_exits = if let Some(body) = try_body {
        build_sub(
            body,
            &try_preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            &mut try_throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        )
    } else {
        try_preds
    };
    let try_body_last_idx = g.node_count();

    // 3. Collect exception sources: implicit (calls) + explicit (throws)
    let mut exception_sources: Vec<NodeIndex> = Vec::new();
    for raw in try_body_first_idx..try_body_last_idx {
        let idx = NodeIndex::new(raw);
        if is_exception_source(&g[idx]) {
            exception_sources.push(idx);
        }
    }
    exception_sources.extend(&try_throw_targets);

    // 4. Build each catch clause and wire exception edges
    let mut all_catch_exits: Vec<NodeIndex> = Vec::new();

    if catch_clauses.is_empty() {
        // try/finally without catch: throws propagate outward after finally
        // (handled below in the finally section)
    } else {
        for catch_node in &catch_clauses {
            let param_name = extract_catch_param_name(*catch_node, lang, code);

            // If the catch has a named parameter, inject a synthetic node that
            // defines it.  The taint transfer function will conservatively
            // taint this variable (catch_param = true).
            let catch_preds = if let Some(ref name) = param_name {
                let synth = g.add_node(NodeInfo {
                    kind: StmtKind::Seq,
                    ast: AstMeta {
                        span: (catch_node.start_byte(), catch_node.start_byte()),
                        enclosing_func: enclosing_func.map(|s| s.to_string()),
                    },
                    taint: TaintMeta {
                        defines: Some(name.clone()),
                        ..Default::default()
                    },
                    call: CallMeta {
                        callee: Some(format!("catch({name})")),
                        ..Default::default()
                    },
                    catch_param: true,
                    ..Default::default()
                });

                // Wire exception edges from every exception source → synthetic node
                for &src in &exception_sources {
                    g.add_edge(src, synth, EdgeKind::Exception);
                }

                vec![synth]
            } else {
                // No param name, wire exception edges directly to first catch body node
                Vec::new()
            };

            let catch_first_idx = NodeIndex::new(g.node_count());
            // Pass outer throw_targets so throws in catch propagate to enclosing try
            let catch_exits = build_sub(
                *catch_node,
                &catch_preds,
                g,
                lang,
                code,
                summaries,
                file_path,
                enclosing_func,
                call_ordinal,
                analysis_rules,
                break_targets,
                continue_targets,
                throw_targets,
                bodies,
                next_body_id,
                current_body_id,
            );

            // If no param name, wire exception edges to the first catch body node
            if param_name.is_none() {
                let catch_entry = if catch_first_idx.index() < g.node_count() {
                    catch_first_idx
                } else {
                    continue;
                };
                for &src in &exception_sources {
                    g.add_edge(src, catch_entry, EdgeKind::Exception);
                }
            }

            all_catch_exits.extend(catch_exits);
        }
    }

    // 5. Build finally clause (if present)
    if let Some(finally_node) = finally_clause {
        // Finally predecessors = try normal exits + catch exits
        // For try/finally without catch, also include throw targets from try body
        let mut finally_preds: Vec<NodeIndex> = Vec::new();
        finally_preds.extend(&try_exits);
        finally_preds.extend(&all_catch_exits);
        if catch_clauses.is_empty() {
            finally_preds.extend(&try_throw_targets);
        }

        build_finally_paths(
            finally_node,
            &finally_preds,
            try_body_first_idx,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            break_targets,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        )
    } else {
        // No finally: return try normal exits + catch exits
        let mut exits = try_exits;
        exits.extend(all_catch_exits);
        exits
    }
}

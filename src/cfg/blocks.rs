use super::{
    AstMeta, BodyCfg, BodyId, CallMeta, Cfg, EdgeKind, FuncSummaries, NodeInfo, StmtKind,
    TaintMeta, build_sub, collect_idents, connect_all, push_node, text_of,
};
use crate::labels::{Kind, LangAnalysisRules, lookup};
use petgraph::graph::NodeIndex;
use tree_sitter::Node;

/// True when the language has guaranteed-exclusive (non-fall-through) cases
/// at the *case-level* shape `build_switch` sees here. Rust `match`, Go
/// `switch`, and Java arrow-switches qualify; classic Java/C/C++/JS switches
/// with fall-through do not. The check is per-language because Java mixes
/// arrow and classic shapes, that's handled by inspecting the case kind in
/// [`extract_case_literal_text`].
fn lang_has_exclusive_cases(lang: &str) -> bool {
    matches!(lang, "rust" | "go")
}

/// True when *this specific switch* has guaranteed-exclusive (non-fall-through)
/// cases, so it is safe to reorder the `default` arm to the cascade tail.
///
/// Rust `match` and Go `switch` are always exclusive. Java mixes shapes: the
/// arrow form (`switch_rule` cases, `case x -> ...`) is exclusive, but the
/// classic colon form (`switch_block_statement_group`, `case x:` with implicit
/// fall-through) is NOT. C/C++/JS/TS/PHP classic switches fall through and are
/// never exclusive. Reordering `default` to the tail is only correct for the
/// exclusive shapes; doing it for fall-through switches connects the wrong
/// case bodies in the source-order fall-through chain (both missed and phantom
/// taint flows).
fn switch_is_exclusive(lang: &str, cases: &[(Node<'_>, bool)]) -> bool {
    if lang_has_exclusive_cases(lang) {
        return true;
    }
    if lang == "java" {
        // Arrow-switch when every case is the arrow `switch_rule` shape.
        return cases.iter().all(|(c, _)| c.kind() == "switch_rule");
    }
    false
}

/// Extract the scrutinee subtree from a switch-like AST node.
///
/// Returns the AST node referenced by the language's scrutinee field. Only
/// fires for Rust `match`, Go `switch`, and Java `switch` statements, other
/// languages return `None` so [`build_switch`] keeps its legacy behavior.
fn extract_scrutinee_node<'a>(ast: Node<'a>, lang: &str) -> Option<Node<'a>> {
    let field = match lang {
        "rust" => "value",
        "go" => "value",
        "java" => "condition",
        _ => return None,
    };
    ast.child_by_field_name(field)
}

/// Extract a single literal/path text from a case AST when the case is a
/// plain mutually-exclusive literal pattern. Returns `None` for non-literal
/// patterns (wildcards, OR-patterns, range patterns, guards) and for
/// fall-through-shaped Java cases.
fn extract_case_literal_text<'a>(case: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    let kind = case.kind();
    match (lang, kind) {
        ("rust", "match_arm") => {
            // Reject guarded arms, `match x { y if cond => ... }`.
            if case.child_by_field_name("guard").is_some() {
                return None;
            }
            let pattern = case.child_by_field_name("pattern")?;
            // `match_pattern` wraps the real pattern as a child.
            let inner = {
                let mut cursor = pattern.walk();
                pattern
                    .children(&mut cursor)
                    .find(|c| c.is_named())
                    .unwrap_or(pattern)
            };
            // Reject patterns that are not plain literals/paths.
            if matches!(
                inner.kind(),
                "_" | "wildcard"
                    | "range_pattern"
                    | "or_pattern"
                    | "tuple_struct_pattern"
                    | "struct_pattern"
                    | "ref_pattern"
                    | "tuple_pattern"
                    | "slice_pattern"
                    | "captured_pattern"
                    | "binding_pattern"
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
                if child.kind() != "switch_label" {
                    continue;
                }
                let mut named_values: Vec<Node> = Vec::new();
                let mut sl_cursor = child.walk();
                let mut saw_default = false;
                for sl_child in child.children(&mut sl_cursor) {
                    let k = sl_child.kind();
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
                return text_of(named_values[0], code);
            }
            None
        }
        _ => None,
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
                if child.kind() == "catch_formal_parameter" {
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
                if child.kind() == "identifier" {
                    return text_of(child, code);
                }
            }
            None
        }
        _ => None,
    }
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
        match child.kind() {
            "rescue" => rescue_clauses.push(child),
            "else" => else_clause = Some(child),
            "ensure" => ensure_clause = Some(child),
            _ if lookup(lang, child.kind()) == Kind::Trivia => {}
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
                match child.kind() {
                    "exceptions" | "exception_variable" => {}
                    _ if lookup(lang, child.kind()) == Kind::Trivia => {}
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

        build_sub(
            ensure_node,
            &ensure_preds,
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
pub(super) fn is_switch_case_kind(kind: &str) -> bool {
    matches!(
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
            | "switch_block_statement_group"
    )
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

/// Detect a `default` keyword among the immediate children of a case-like AST
/// node. Used for grammars (C/C++/Java) where `default:` is encoded as a child
/// label of an otherwise generic `case_statement` / `switch_block_statement_group`.
pub(super) fn case_has_default_label(case: Node<'_>) -> bool {
    let mut cursor = case.walk();
    for child in case.children(&mut cursor) {
        let k = child.kind();
        if k == "default" || k == "default_label" {
            return true;
        }
    }
    false
}

/// Build CFG for a switch statement.
///
/// The dispatch is decomposed into a chain of binary `StmtKind::If` headers
///, one per non-default case, because the SSA terminator only models 0/1/2
/// successors. A monolithic N-way header would otherwise be collapsed to
/// `Goto(first)` and silently drop every other case. Each header's True edge
/// reaches its case body; the False edge falls through to the next header (or
/// the default body, if present, or the post-switch code).
///
/// Fall-through between adjacent case bodies (e.g. C/C++/Java/JS without
/// `break`) is preserved by chaining the previous case's exits as additional
/// predecessors of the next case's first node. `break` inside a case targets
/// a fresh switch-scoped break list rather than the surrounding loop.
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
    _break_targets: &mut Vec<NodeIndex>,
    continue_targets: &mut Vec<NodeIndex>,
    throw_targets: &mut Vec<NodeIndex>,
    bodies: &mut Vec<BodyCfg>,
    next_body_id: &mut u32,
    current_body_id: BodyId,
) -> Vec<NodeIndex> {
    // Locate the case container. Most grammars expose it as field "body"
    // (JS/TS, Java, C, C++); Go puts cases as direct children of the switch.
    //
    // Per-language gotcha: Go's `expression_case` / `default_case` /
    // `type_case` / `communication_case` map to `Kind::Block` (so the case
    // body is iterated by the Block handler), so a naive "first Block
    // child" fallback latches onto the FIRST case as the container, then
    // walks the case's interior looking for case-like children, finds none,
    // and falls through to the empty-cases early return (CFG dead-end:
    // dispatch If has no False edge, every post-switch statement becomes
    // unreachable).  Skip case-kind nodes when picking the container so
    // Go's flat "cases-as-direct-children" shape uses `ast` itself.
    let body = ast.child_by_field_name("body").or_else(|| {
        let mut c = ast.walk();
        ast.children(&mut c).find(|n| {
            matches!(lookup(lang, n.kind()), Kind::Block) && !is_switch_case_kind(n.kind())
        })
    });
    let container = body.unwrap_or(ast);

    // Collect case-like children in source order. Default goes through the
    // same path as other cases but is tracked separately so the dispatch
    // chain's tail can fall into it instead of past the switch.
    let mut cases: Vec<(Node<'a>, bool)> = Vec::new();
    {
        let mut cursor = container.walk();
        for case in container.children(&mut cursor) {
            let k = case.kind();
            if !is_switch_case_kind(k) {
                continue;
            }
            let is_default = is_default_case_kind(k) || case_has_default_label(case);
            cases.push((case, is_default));
        }
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
        connect_all(g, preds, header, EdgeKind::Seq);
        let mut switch_breaks: Vec<NodeIndex> = Vec::new();
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
                &mut switch_breaks,
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

    // Whether this switch's cases are mutually exclusive (no fall-through).
    // Only exclusive switches may have `default` reordered to the cascade tail.
    let is_exclusive = switch_is_exclusive(lang, &cases);

    // Reorder so the default arm (if any) sits at the tail of the cascade.
    // Reordering case dispatch is semantically harmless ONLY for mutually
    // exclusive pattern matches (Rust match, Go switch, Java arrow-switch); it
    // keeps the chain a clean Branch(True→case, False→next). For classic
    // fall-through switches (C/C++/JS/TS/PHP, Java colon-switch) a mid-chain
    // `default:` can fall into the following case and a preceding case can fall
    // into it, so the source order MUST be preserved — reordering there breaks
    // the fall-through Seq layer and produces both missed and phantom flows.
    let default_pos = cases.iter().position(|(_, d)| *d);
    if is_exclusive
        && let Some(pos) = default_pos
        && pos != cases.len() - 1
    {
        let default_pair = cases.remove(pos);
        cases.push(default_pair);
    }
    let has_default = default_pos.is_some();

    // For mutually-exclusive switch shapes (Rust match, Go switch, Java
    // arrow-switch), pre-extract the scrutinee text + idents so the synthetic
    // dispatch headers can carry a `<scrutinee> == <case_literal>` condition.
    // Falls back to `None` when the scrutinee is structurally complex (calls,
    // member chains, parenthesized expressions in Go), the existing first-
    // reachable behavior remains correct in that case.
    let supports_exclusive_cases = lang_has_exclusive_cases(lang) || lang == "java";
    let (scrutinee_text, scrutinee_idents) = if supports_exclusive_cases {
        match extract_scrutinee_node(ast, lang) {
            Some(scrut) => {
                let mut idents = Vec::new();
                collect_idents(scrut, code, &mut idents);
                idents.sort();
                idents.dedup();
                let text = text_of(scrut, code).map(|s| {
                    // Java's `condition` field includes the surrounding parens.
                    let trimmed = s.trim();
                    if trimmed.starts_with('(') && trimmed.ends_with(')') {
                        trimmed[1..trimmed.len() - 1].trim().to_string()
                    } else {
                        trimmed.to_string()
                    }
                });
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

    let mut switch_breaks: Vec<NodeIndex> = Vec::new();
    let mut fallthrough_exits: Vec<NodeIndex> = Vec::new();
    let mut last_header_false: Option<NodeIndex> = None;
    let mut chain_preds: Vec<NodeIndex> = preds.to_vec();
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
        // position (`!is_exclusive`) and is wired into the Seq fall-through
        // chain instead of acting as a conditional branch.
        let default_no_dispatch = is_default && (is_last || !is_exclusive);

        // Default at the chain tail doesn't get its own dispatch If, the
        // previous header's False edge already targets it directly.
        let case_first_preds: Vec<NodeIndex> = if default_no_dispatch {
            // Body entry = fall-through from the preceding case body.
            let mut p = std::mem::take(&mut fallthrough_exits);
            if is_last {
                // Tail default: the previous header's False branch also lands
                // here directly (legacy behavior preserved for exclusive
                // switches and tail defaults).
                p.extend(chain_preds.iter().copied());
                last_header_false = chain_preds.first().copied();
            }
            // For a non-tail (fall-through) default the dispatch chain must
            // continue PAST it, so `chain_preds` / `last_header_false` are left
            // untouched and the next case's dispatch header still receives the
            // previous header's False edge. The cumulative no-match entry is
            // recorded below once the body's first node is known.
            p
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
            // If there was a previous header in the chain, that header's
            // False edge needs to land on this header.
            if let Some(prev) = last_header_false {
                g.add_edge(prev, header, EdgeKind::False);
            }

            let mut p = vec![header];
            p.append(&mut fallthrough_exits);
            last_header_false = Some(header);
            chain_preds = vec![header];
            p
        };

        // Snapshot the next node index so we can attach the True edge to
        // the case body's first emitted node.
        let body_first_idx = NodeIndex::new(g.node_count());

        let exits = build_sub(
            case,
            &case_first_preds,
            g,
            lang,
            code,
            summaries,
            file_path,
            enclosing_func,
            call_ordinal,
            analysis_rules,
            &mut switch_breaks,
            continue_targets,
            throw_targets,
            bodies,
            next_body_id,
            current_body_id,
        );

        // Wire the dispatch True edge from this header (or from the previous
        // header for a tail-default) to the first node of the case body.
        if body_first_idx.index() < g.node_count() {
            let header_for_true = if default_no_dispatch {
                if is_last {
                    // Tail default: the previous header's False already lands
                    // here via the EdgeKind::Seq inside `case_first_preds`; we
                    // additionally emit a False edge directly so SSA labels the
                    // branch.
                    if let Some(prev) = last_header_false {
                        g.add_edge(prev, body_first_idx, EdgeKind::False);
                    }
                } else {
                    // Non-tail fall-through default: defer wiring the no-match
                    // entry until the last non-default header's False edge is
                    // known (after the loop). The body's only in-edge for now
                    // is the source-order fall-through from the preceding case.
                    pending_default_no_match = Some(body_first_idx);
                }
                None
            } else {
                // Last header in chain_preds is the only entry.
                chain_preds.first().copied()
            };
            if let Some(h) = header_for_true {
                g.add_edge(h, body_first_idx, EdgeKind::True);
            }
        }

        fallthrough_exits = exits;
        let _ = is_default;
    }

    // Resolve the cumulative no-match (the last non-default header's False
    // edge):
    //   - If the `default` arm sits mid-chain (fall-through switch), the
    //     no-match path enters the default body — wire the deferred False edge
    //     into it. The default stayed in source position for the fall-through
    //     Seq layer, so this is the only edge making it reachable on no-match.
    //   - Otherwise, with no reachable default (no default arm, or it was the
    //     tail and already consumed the False edge), the no-match path escapes
    //     to the post-switch frontier.
    let mut exits: Vec<NodeIndex> = switch_breaks;
    exits.append(&mut fallthrough_exits);
    if let Some(default_first) = pending_default_no_match {
        if let Some(prev) = last_header_false {
            g.add_edge(prev, default_first, EdgeKind::False);
        }
    } else if !has_default {
        if let Some(prev) = last_header_false {
            exits.push(prev);
        }
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
            .any(|c| c.kind() == "rescue" || c.kind() == "ensure");
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
            if (child.kind() == "catch_clause" || child.kind() == "except_clause")
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
            .find(|child| child.kind() == "finally_clause")
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

        let finally_exits = build_sub(
            finally_node,
            &finally_preds,
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
        finally_exits
    } else {
        // No finally: return try normal exits + catch exits
        let mut exits = try_exits;
        exits.extend(all_catch_exits);
        exits
    }
}

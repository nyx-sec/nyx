use super::helpers::first_member_label;
use super::{
    AstMeta, Cfg, EdgeKind, MAX_COND_VARS, MAX_CONDITION_TEXT_LEN, NodeInfo, StmtKind,
    build_cond_arith, collect_idents, connect_all, detect_eq_with_const, detect_negation,
    has_call_descendant, member_expr_text, push_node, text_of, try_lower_jsx_dangerous_html,
};
use crate::labels::{DataLabel, LangAnalysisRules, classify};
use crate::utils::snippet::truncate_at_char_boundary;
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use tree_sitter::Node;

//    Short-circuit boolean operator helpers

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum BoolOp {
    And,
    Or,
}

/// Check if an AST node is a boolean operator (`&&`/`||`/`and`/`or`).
pub(super) fn is_boolean_operator(node: Node) -> Option<BoolOp> {
    match node.kind() {
        "binary_expression" | "boolean_operator" | "binary" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "&&" | "and" => return Some(BoolOp::And),
                    "||" | "or" => return Some(BoolOp::Or),
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

/// Strip parenthesized_expression wrappers.
pub(super) fn unwrap_parens(node: Node) -> Node {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return unwrap_parens(inner);
        }
    }
    node
}

/// Extract `left` and `right` operands from a binary boolean node.
pub(super) fn get_boolean_operands<'a>(node: Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    // Field-based (all supported grammars)
    if let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        return Some((left, right));
    }
    // Positional fallback (safety net)
    let mut cursor = node.walk();
    let named: Vec<_> = node.named_children(&mut cursor).collect();
    if named.len() >= 2 {
        return Some((named[0], named[named.len() - 1]));
    }
    None
}

/// Create a lightweight `StmtKind::If` node for a sub-condition in a boolean chain.
pub(super) fn push_condition_node<'a>(
    g: &mut Cfg,
    cond_ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
) -> NodeIndex {
    // Pass cond_ast as both args, sub-conditions are never `unless` nodes
    let (inner, negated) = detect_negation(cond_ast, cond_ast, lang);
    let mut vars = Vec::new();
    collect_idents(inner, code, &mut vars);
    vars.sort();
    vars.dedup();
    vars.truncate(MAX_COND_VARS);
    let text = text_of(cond_ast, code)
        .map(|t| truncate_at_char_boundary(&t, MAX_CONDITION_TEXT_LEN).to_string());
    let span = (cond_ast.start_byte(), cond_ast.end_byte());
    // Mirror condition variables into `taint.uses` so the per-body
    // `SymbolInterner::from_cfg` pass interns them.  Without this,
    // `apply_branch_predicates` (which calls `interner.get(var)` to
    // look up a Symbol id) silently no-ops on short-circuit branch
    // condition nodes — they have no `taint.uses` even though
    // `condition_vars` carries the variable names.  Surfaced by
    // GHSA-h8cj-hpmg-636v: a `||`-decomposed validator like
    // `if (x == null || !regex.matcher(x).matches()) throw;` failed
    // to mark `x` as `validated_must` on the surviving branch
    // because the per-disjunct cond nodes (built via
    // `build_condition_chain`) didn't populate `taint.uses`.
    let uses_for_taint: Vec<String> = vars.clone();
    g.add_node(NodeInfo {
        kind: StmtKind::If,
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        condition_text: text,
        condition_vars: vars,
        condition_negated: negated,
        taint: crate::cfg::TaintMeta {
            uses: uses_for_taint,
            ..Default::default()
        },
        ..Default::default()
    })
}

/// For a Rust `let <pattern> = match <scrutinee> { <arm> if <guard> => .., ... }`,
/// find the first guarded `match_arm` and return the guard expression node plus
/// the primary let-binding name.  Returns `None` when the let-value is not a
/// `match_expression` or no arm has a guard.
///
/// The guard lives on the tree-sitter `match_pattern` node as the field
/// `condition` (present whenever the pattern is followed by `if <expr>`).
pub(super) fn detect_rust_let_match_guard<'a>(
    ast: Node<'a>,
    code: &[u8],
) -> Option<(Node<'a>, String)> {
    if ast.kind() != "let_declaration" {
        return None;
    }
    let value = ast.child_by_field_name("value")?;
    if value.kind() != "match_expression" {
        return None;
    }
    let body = value.child_by_field_name("body")?;

    let mut cursor = body.walk();
    let guard = body.children(&mut cursor).find_map(|arm| {
        if !matches!(arm.kind(), "match_arm" | "last_match_arm") {
            return None;
        }
        let pattern = arm.child_by_field_name("pattern")?;
        pattern.child_by_field_name("condition")
    })?;

    let pat = ast.child_by_field_name("pattern")?;
    let mut idents = Vec::new();
    collect_idents(pat, code, &mut idents);
    let name = idents.into_iter().next()?;

    Some((guard, name))
}

/// Synthesize a `StmtKind::If` CFG node carrying a Rust match-arm guard's
/// condition text and vars.  The let-binding name is added to `condition_vars`
/// so `apply_branch_predicates` narrows validation to that specific variable
///, the variable that receives the arm's value and flows to downstream sinks.
pub(super) fn emit_rust_match_guard_if<'a>(
    g: &mut Cfg,
    guard: Node<'a>,
    let_name: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
) -> NodeIndex {
    let mut vars = Vec::new();
    collect_idents(guard, code, &mut vars);
    vars.push(let_name.to_string());
    vars.sort();
    vars.dedup();
    vars.truncate(MAX_COND_VARS);
    let text = text_of(guard, code)
        .map(|t| truncate_at_char_boundary(&t, MAX_CONDITION_TEXT_LEN).to_string());
    let span = (guard.start_byte(), guard.end_byte());
    g.add_node(NodeInfo {
        kind: StmtKind::If,
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        condition_text: text,
        condition_vars: vars,
        condition_negated: false,
        ..Default::default()
    })
}

/// Decompose an assignment whose RHS is a ternary (`lhs = cond ? a : b`) into
/// a proper diamond CFG: cond → {true_branch | false_branch} → join. Each
/// branch defines `lhs_text` from its own operand's identifiers; a phi for
/// `lhs_text` is then synthesised by SSA lowering at the join.
///
/// The condition's identifiers live on the If node's `condition_vars`, **not**
/// on the branch `uses`. This is the whole point of the split, cond is control
/// flow, branches are data flow.
///
/// Returns the exit frontier for downstream statement chaining (a single-element
/// vec containing the join node).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_ternary_diamond<'a>(
    lhs_text: String,
    lhs_labels: SmallVec<[DataLabel; 2]>,
    ternary_ast: Node<'a>,
    preds: &[NodeIndex],
    pred_edge: EdgeKind,
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> Vec<NodeIndex> {
    let (Some(cond_field), Some(cons_field), Some(alt_field)) = (
        ternary_ast.child_by_field_name("condition"),
        ternary_ast.child_by_field_name("consequence"),
        ternary_ast.child_by_field_name("alternative"),
    ) else {
        // Grammar mismatch: caller will fall through to the non-split path.
        return preds.to_vec();
    };
    let cond_ast = unwrap_parens(cond_field);
    let cons_ast = unwrap_parens(cons_field);
    let alt_ast = unwrap_parens(alt_field);

    // 1. Condition header. `push_condition_node` sets span/text/vars/negated
    //    but leaves `is_eq_with_const` default; stamp it explicitly so the
    //    taint engine's equality-narrowing fires for `x === 'literal' ? …`.
    let cond_if = push_condition_node(g, cond_ast, lang, code, enclosing_func);
    g[cond_if].is_eq_with_const = detect_eq_with_const(cond_ast, lang);
    // Capture the pure int-arith + comparison tree so `fold_constant_branches`
    // can prune a dead constant-condition arm of the ternary (e.g. Java
    // `(7*18)+num > 200 ? "const" : param` with `num` a known int constant),
    // exactly as it does for the if-form.  `build_cond_arith` is conservative
    // (returns None for any call/field/string/`&&`/`||`/`!` shape) so this is
    // sound for every language the diamond fires on.
    g[cond_if].cond_arith = build_cond_arith(cond_ast, lang, code, 0);
    connect_all(g, preds, cond_if, pred_edge);

    // 2. Branches. Each branch produces its own exit frontier (≥ 1 node) ,
    //    a nested ternary recurses and returns its own join node.
    let true_exits = lower_ternary_branch(
        cons_ast,
        &[cond_if],
        EdgeKind::True,
        &lhs_text,
        &lhs_labels,
        g,
        lang,
        code,
        enclosing_func,
        call_ordinal,
        analysis_rules,
    );
    let false_exits = lower_ternary_branch(
        alt_ast,
        &[cond_if],
        EdgeKind::False,
        &lhs_text,
        &lhs_labels,
        g,
        lang,
        code,
        enclosing_func,
        call_ordinal,
        analysis_rules,
    );

    // 3. Join: a zero-width Seq node placed at the ternary's end. Phi insertion
    //    via Cytron will synthesise `lhs_text = phi(true_def, false_def)` here
    //    because both branches define `lhs_text` and this is their dominance
    //    frontier.
    let join_pos = ternary_ast.end_byte();
    let join = g.add_node(NodeInfo {
        kind: StmtKind::Seq,
        ast: AstMeta {
            span: (join_pos, join_pos),
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        ..Default::default()
    });
    connect_all(g, &true_exits, join, EdgeKind::Seq);
    connect_all(g, &false_exits, join, EdgeKind::Seq);

    vec![join]
}

/// Emit the CFG shape for a single ternary branch. Three cases:
///
/// 1. Branch is itself a ternary → recurse via `build_ternary_diamond` so nested
///    conditions also split cleanly (no `cond2` leakage into uses).
/// 2. Branch contains a call → emit as `StmtKind::Call` via `push_node` so inner
///    source/sanitizer/sink classification is preserved, then rewrite `defines`
///    to the outer LHS and union in the LHS's sink labels.
/// 3. Otherwise → emit as `StmtKind::Seq`, same override.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_ternary_branch<'a>(
    branch_ast: Node<'a>,
    preds: &[NodeIndex],
    pred_edge: EdgeKind,
    lhs_text: &str,
    lhs_labels: &SmallVec<[DataLabel; 2]>,
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> Vec<NodeIndex> {
    // Case 1: nested ternary.
    if branch_ast.kind() == "ternary_expression" {
        return build_ternary_diamond(
            lhs_text.to_string(),
            lhs_labels.clone(),
            branch_ast,
            preds,
            pred_edge,
            g,
            lang,
            code,
            enclosing_func,
            call_ordinal,
            analysis_rules,
        );
    }

    // Cases 2 and 3: leaf branch expression.
    let has_call = has_call_descendant(branch_ast, lang);
    let kind = if has_call {
        StmtKind::Call
    } else {
        StmtKind::Seq
    };
    let ord = if kind == StmtKind::Call {
        let o = *call_ordinal;
        *call_ordinal += 1;
        o
    } else {
        0
    };

    let node = push_node(
        g,
        kind,
        branch_ast,
        lang,
        code,
        enclosing_func,
        ord,
        analysis_rules,
    );

    // The branch expression's own `defines` (if any, typically None for a
    // pure value expression) is replaced with the outer LHS so that both
    // branches agree on the target, driving phi insertion at the join.
    g[node].taint.defines = Some(lhs_text.to_string());
    for label in lhs_labels {
        if !g[node].taint.labels.contains(label) {
            g[node].taint.labels.push(*label);
        }
    }

    // Bridge source recognition to ternary branches.  push_node only does
    // suffix/prefix matching on the branch text, so a source-shaped member
    // expression like `req.query.lng` doesn't classify (the rule matcher
    // is `req.query`, which neither suffix-matches nor prefix-matches
    // `req.query.lng`).  Run the segment-strip-and-retry classifier on
    // the branch AST to recover the source label, mirroring what
    // `pre_emit_arg_source_nodes` does for call arguments and what the
    // `Kind::CallWrapper | Kind::Assignment` gate at push_node:1827 does
    // for whole declarations.  Without this, `let arr = cond ? req.query.lng
    // : "";` lowers each branch to a labelless Assign-with-empty-uses, the
    // join phi sees no taint, and downstream sinks miss the flow.
    if !g[node]
        .taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Source(_)))
    {
        let extra = analysis_rules
            .map(|r| r.extra_labels.as_slice())
            .filter(|s| !s.is_empty());
        if let Some(found @ DataLabel::Source(_)) =
            first_member_label(branch_ast, lang, code, extra)
        {
            g[node].taint.labels.push(found);
        }
    }

    connect_all(g, preds, node, pred_edge);

    // React JSX `dangerouslySetInnerHTML={{__html: x}}` synthesis when the
    // branch expression is itself a JSX element (or contains one as a
    // descendant).  Without this, `cond ? <div dangerouslySetInnerHTML=...
    // /> : null` and similar ternary-RHS shapes never reach the
    // `Kind::Return` / `Kind::Assignment` arms that own the synthesis hook,
    // because `build_ternary_diamond` lowers each branch directly.
    let post_jsx = try_lower_jsx_dangerous_html(
        branch_ast,
        &[node],
        g,
        lang,
        code,
        enclosing_func,
        call_ordinal,
        analysis_rules,
    );
    post_jsx
}

/// Extract `(lhs_ast, ternary_ast)` when `outer_ast` is an expression-statement
/// or declaration whose single assignment/declarator's RHS is a ternary.
/// Returns `None` for multi-declarator forms, for missing fields, and for
/// any RHS that isn't a `ternary_expression` after `unwrap_parens`.
pub(super) fn find_ternary_rhs_wrapper<'a>(outer_ast: Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    let mut cursor = outer_ast.walk();
    let mut declarator_count = 0usize;
    let mut found: Option<(Node<'a>, Node<'a>)> = None;

    for child in outer_ast.children(&mut cursor) {
        match child.kind() {
            "variable_declarator" => {
                declarator_count += 1;
                if declarator_count > 1 {
                    return None;
                }
                let (Some(name), Some(value)) = (
                    child.child_by_field_name("name"),
                    child.child_by_field_name("value"),
                ) else {
                    continue;
                };
                let rhs = unwrap_parens(value);
                if rhs.kind() == "ternary_expression" {
                    found = Some((name, rhs));
                }
            }
            "assignment_expression" => {
                let (Some(left), Some(right)) = (
                    child.child_by_field_name("left"),
                    child.child_by_field_name("right"),
                ) else {
                    continue;
                };
                let rhs = unwrap_parens(right);
                if rhs.kind() == "ternary_expression" {
                    return Some((left, rhs));
                }
            }
            _ => {}
        }
    }
    found
}

/// Classify the LHS of a ternary-split assignment. Returns `(lhs_text, labels)`
/// where `labels` are any sink labels that belong to the LHS itself (e.g.
/// `innerHTML`, `document.cookie`). These are applied to **each branch** so
/// the sink fires on whichever branch carries tainted data.
pub(super) fn classify_ternary_lhs(
    lhs_ast: Node,
    lang: &str,
    code: &[u8],
    analysis_rules: Option<&LangAnalysisRules>,
) -> (String, SmallVec<[DataLabel; 2]>) {
    let extra = analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut labels: SmallVec<[DataLabel; 2]> = SmallVec::new();

    // Prefer full member-expression path; fall back to raw text.
    let lhs_text = member_expr_text(lhs_ast, code)
        .or_else(|| text_of(lhs_ast, code))
        .unwrap_or_default();

    // Try the full dotted path first (e.g. "document.cookie"), then fall back
    // to the property alone (e.g. "innerHTML"), mirrors the LHS classification
    // already performed in `push_node` for non-split assignments.
    if let Some(l) = classify(lang, &lhs_text, extra) {
        labels.push(l);
    }
    if labels.is_empty()
        && let Some(prop) = lhs_ast.child_by_field_name("property")
        && let Some(prop_text) = text_of(prop, code)
        && let Some(l) = classify(lang, &prop_text, extra)
    {
        labels.push(l);
    }

    (lhs_text, labels)
}

/// Recursively decompose a boolean condition into a chain of `StmtKind::If` nodes
/// with short-circuit edges.
///
/// Returns `(true_exits, false_exits)`, the sets of nodes from which True/False
/// edges should connect to the then/else branches.
pub(super) fn build_condition_chain<'a>(
    cond_ast: Node<'a>,
    preds: &[NodeIndex],
    pred_edge: EdgeKind,
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let inner = unwrap_parens(cond_ast);

    match is_boolean_operator(inner) {
        Some(BoolOp::And) => {
            if let Some((left, right)) = get_boolean_operands(inner) {
                // Left operand with current preds
                let (left_true, left_false) =
                    build_condition_chain(left, preds, pred_edge, g, lang, code, enclosing_func);
                // Right operand only evaluated when left is true
                let (right_true, right_false) = build_condition_chain(
                    right,
                    &left_true,
                    EdgeKind::True,
                    g,
                    lang,
                    code,
                    enclosing_func,
                );
                // AND: true only when both true; false when either false
                let mut false_exits = left_false;
                false_exits.extend(right_false);
                (right_true, false_exits)
            } else {
                // Safety fallback: treat as leaf
                let node = push_condition_node(g, inner, lang, code, enclosing_func);
                connect_all(g, preds, node, pred_edge);
                (vec![node], vec![node])
            }
        }
        Some(BoolOp::Or) => {
            if let Some((left, right)) = get_boolean_operands(inner) {
                // Left operand with current preds
                let (left_true, left_false) =
                    build_condition_chain(left, preds, pred_edge, g, lang, code, enclosing_func);
                // Right operand only evaluated when left is false
                let (right_true, right_false) = build_condition_chain(
                    right,
                    &left_false,
                    EdgeKind::False,
                    g,
                    lang,
                    code,
                    enclosing_func,
                );
                // OR: true when either true; false only when both false
                let mut true_exits = left_true;
                true_exits.extend(right_true);
                (true_exits, right_false)
            } else {
                // Safety fallback: treat as leaf
                let node = push_condition_node(g, inner, lang, code, enclosing_func);
                connect_all(g, preds, node, pred_edge);
                (vec![node], vec![node])
            }
        }
        None => {
            // Leaf: single condition node
            let node = push_condition_node(g, inner, lang, code, enclosing_func);
            connect_all(g, preds, node, pred_edge);
            (vec![node], vec![node])
        }
    }
}

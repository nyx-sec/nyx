use super::helpers::first_member_label;
use super::{
    AstMeta, Cfg, EdgeKind, MAX_COND_VARS, MAX_CONDITION_TEXT_LEN, NodeInfo, NullCheck, StmtKind,
    build_cond_arith, collect_idents, connect_all, detect_eq_with_const, detect_negation,
    has_call_descendant, member_expr_text, push_node, rmw_assignment, text_of,
    try_lower_jsx_dangerous_html,
};
use crate::cfg::fast_kind::FastKind;
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
    match node.fkind() {
        "binary_expression" | "boolean_operator" | "binary" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.fkind() {
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
    if node.fkind() == "parenthesized_expression" {
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

/// Peel one logical-not wrapper (`!x`, `not x`), returning its operand.
fn peel_logical_not(node: Node) -> Option<Node> {
    if !matches!(
        node.fkind(),
        "unary_expression"
            | "not_operator"
            | "prefix_unary_expression"
            | "unary_not"
            | "unary_op_expression"
            | "unary"
    ) {
        return None;
    }
    let mut cursor = node.walk();
    let is_not = node
        .children(&mut cursor)
        .any(|c| !c.is_named() && matches!(c.fkind(), "!" | "not"));
    if !is_not {
        return None;
    }
    node.child_by_field_name("argument")
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).last()
        })
}

/// Name of a bare variable operand, spelled the way `collect_idents` spells
/// it so it matches `taint.defines` (PHP `$fh` becomes `fh`).
fn null_check_operand_name(node: Node, code: &[u8]) -> Option<String> {
    match node.fkind() {
        "identifier" => text_of(node, code),
        "variable_name" => text_of(node, code).map(|t| t.trim_start_matches('$').to_string()),
        _ => None,
    }
}

/// True for a literal that means "no handle": `NULL` / `nullptr` / `null` /
/// `nil` / `None` / `undefined`, plus PHP `false` (what `fopen` and friends
/// return on failure).
fn is_null_like_literal(node: Node, lang: &str, code: &[u8]) -> bool {
    match node.fkind() {
        "null" | "nullptr" | "null_literal" | "nil" | "none" | "undefined" => true,
        // Older C/C++ grammar shapes and macro spellings surface as a plain
        // identifier.
        "identifier" if matches!(lang, "c" | "cpp") => {
            matches!(text_of(node, code).as_deref(), Some("NULL" | "nullptr"))
        }
        "boolean" if lang == "php" => {
            text_of(node, code).is_some_and(|t| t.eq_ignore_ascii_case("false"))
        }
        _ => false,
    }
}

/// Integer value of a C/C++ literal operand (`0`, `-1`, `- 1`).
fn c_int_literal(node: Node, code: &[u8]) -> Option<i64> {
    match node.fkind() {
        "number_literal" => text_of(node, code)?.trim().parse().ok(),
        "unary_expression" => {
            let op = node.child_by_field_name("operator")?;
            let arg = node.child_by_field_name("argument")?;
            if op.fkind() != "-" || arg.fkind() != "number_literal" {
                return None;
            }
            text_of(arg, code)?.trim().parse::<i64>().ok().map(|v| -v)
        }
        _ => None,
    }
}

/// Split a two-operand comparison into `(left, operator, right)`.  Covers
/// `binary_expression` (C-family, Go, Java, JS/TS, PHP, Rust), Ruby
/// `binary`, and a single Python `comparison_operator` (`f is None`;
/// chained `a < b < c` is rejected).
fn comparison_parts<'a>(node: Node<'a>, code: &[u8]) -> Option<(Node<'a>, String, Node<'a>)> {
    match node.fkind() {
        "binary_expression" | "binary" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let op = node.child_by_field_name("operator")?;
            Some((left, text_of(op, code)?, right))
        }
        "comparison_operator" => {
            let mut cursor = node.walk();
            let operands: Vec<Node> = node.named_children(&mut cursor).collect();
            if operands.len() != 2 {
                return None;
            }
            let mut cursor = node.walk();
            let ops: Vec<Node> = node
                .children_by_field_name("operators", &mut cursor)
                .collect();
            if ops.len() != 1 {
                return None;
            }
            Some((operands[0], text_of(ops[0], code)?, operands[1]))
        }
        _ => None,
    }
}

/// Recognise a single-variable null / failure test in a branch condition.
///
/// Peels parentheses and logical-not (each `!` / `not` flips polarity), then
/// accepts:
///   * a bare variable: `if (f)`, `if not conn` (null when false);
///   * `v ==/===/is <null>` (null when true) or `v !=/!==/is not <null>`
///     (null when false), with the literal on either side;
///   * C/C++ only, the integer failure sentinel of `open` / `socket` /
///     `accept` / `dup`: `fd < 0`, `fd <= -1`, `fd == -1` (failure when true)
///     and `fd >= 0`, `fd > -1`, `fd != -1` (failure when false).  A bare
///     `== 0` is not a failure test (descriptor 0 is valid), so it is
///     rejected.
///
/// Everything else (calls, field access, `&&` / `||`, `a == b`) yields
/// `None`.
pub(super) fn extract_null_check(cond: Node, lang: &str, code: &[u8]) -> Option<NullCheck> {
    let mut node = cond;
    let mut flip = false;
    // Bounded: real conditions nest a handful of parens / nots at most.
    for _ in 0..16 {
        if node.fkind() == "parenthesized_expression" {
            node = node.named_child(0)?;
            continue;
        }
        // C++ wraps the condition as `condition_clause` (`if (init; value)`).
        if node.fkind() == "condition_clause" {
            node = node.child_by_field_name("value")?;
            continue;
        }
        if let Some(inner) = peel_logical_not(node) {
            node = inner;
            flip = !flip;
            continue;
        }
        break;
    }

    let (var, null_on_true) = if let Some(var) = null_check_operand_name(node, code) {
        (var, false)
    } else {
        let (left, op, right) = comparison_parts(node, code)?;
        let (mut left, mut right) = (unwrap_parens(left), unwrap_parens(right));
        let mut op = op.split_whitespace().collect::<Vec<_>>().join(" ");
        let c_family = matches!(lang, "c" | "cpp");
        let right_is_lit = is_null_like_literal(right, lang, code)
            || (c_family && c_int_literal(right, code).is_some());
        if !right_is_lit {
            // Literal on the left (`NULL == f`, `0 > fd`): swap operands and
            // mirror the ordering operators.
            std::mem::swap(&mut left, &mut right);
            op = match op.as_str() {
                "<" => ">".into(),
                ">" => "<".into(),
                "<=" => ">=".into(),
                ">=" => "<=".into(),
                _ => op,
            };
        }
        let var = null_check_operand_name(left, code)?;
        let null_on_true = if is_null_like_literal(right, lang, code) {
            match op.as_str() {
                "==" | "===" | "is" => true,
                "!=" | "!==" | "is not" | "<>" => false,
                _ => return None,
            }
        } else if c_family {
            match (op.as_str(), c_int_literal(right, code)?) {
                ("<", 0) | ("<=", -1) | ("==", -1) => true,
                (">=", 0) | (">", -1) | ("!=", -1) => false,
                _ => return None,
            }
        } else {
            return None;
        };
        (var, null_on_true)
    };

    Some(NullCheck {
        var,
        null_on_true: null_on_true ^ flip,
    })
}

/// Create a `StmtKind::If` node for a sub-condition in a boolean chain.
///
/// When the operand contains a classifiable call (`if (flag && cp.execSync(x))`),
/// the node is built via [`push_node`] so the inner source/sink/sanitizer
/// classification — callee, labels, arg-uses, gated sinks — is preserved, then
/// the branch-condition metadata is overlaid on top.  Without this, a sink or
/// source CALL inside a short-circuited operand was dropped entirely (the bare
/// node only carried `condition_vars`, no callee or labels), so the
/// `if (flag && sink(x))` form missed flows that the un-decomposed
/// `if (sink(x))` form catches via the mod.rs condition-call fallback.  This
/// mirrors `lower_ternary_branch`, which already uses `push_node` for the same
/// reason.  Non-call operands keep the original lightweight shape.
pub(super) fn push_condition_node<'a>(
    g: &mut Cfg,
    cond_ast: Node<'a>,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> NodeIndex {
    // Pass cond_ast as both args, sub-conditions are never `unless` nodes
    let (inner, negated) = detect_negation(cond_ast, cond_ast, lang);
    let mut vars = Vec::new();
    collect_idents(inner, code, &mut vars);
    vars.sort();
    vars.dedup();
    vars.truncate(MAX_COND_VARS);
    let elem_reads = if lang == "go" {
        super::go_const_index_reads(inner, code)
    } else {
        Vec::new()
    };
    vars.extend(elem_reads.iter().map(|e| e.to_string()));
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

    // Operand containing a call → route through `push_node` for full
    // source/sink/sanitizer classification, then overlay branch metadata.
    if has_call_descendant(inner, lang) {
        let ord = *call_ordinal;
        *call_ordinal += 1;
        let node = push_node(
            g,
            StmtKind::If,
            inner,
            lang,
            code,
            enclosing_func,
            ord,
            analysis_rules,
        );
        // Overlay the branch-condition metadata that the chain wiring depends
        // on.  `push_node` set `defines`/`uses`/`labels`/`callee` from the call;
        // keep those, but ensure the condition fields and the interned
        // condition vars (for `apply_branch_predicates`) are present, and the
        // span/enclosing_func point at the operand expression.
        let info = &mut g[node];
        info.kind = StmtKind::If;
        info.ast.span = span;
        info.ast.enclosing_func = enclosing_func.map(|s| s.to_string());
        info.condition_text = text;
        info.condition_vars = vars;
        info.elem_reads = elem_reads;
        info.condition_negated = negated;
        info.null_check = extract_null_check(cond_ast, lang, code);
        // Union the condition idents into `taint.uses` so branch-predicate
        // lookup keeps working without clobbering the call's own arg uses.
        // The target of a C / C++ condition assignment is overwritten here,
        // so it is not a read of the node.
        let overwritten = if matches!(lang, "c" | "cpp") {
            info.taint.defines.clone()
        } else {
            None
        };
        for v in &uses_for_taint {
            if overwritten.as_deref() == Some(v.as_str()) {
                continue;
            }
            if !info.taint.uses.contains(v) {
                info.taint.uses.push(v.clone());
            }
        }
        return node;
    }

    g.add_node(NodeInfo {
        kind: StmtKind::If,
        ast: AstMeta {
            span,
            enclosing_func: enclosing_func.map(|s| s.to_string()),
        },
        condition_text: text,
        condition_vars: vars,
        elem_reads,
        condition_negated: negated,
        null_check: extract_null_check(cond_ast, lang, code),
        taint: crate::cfg::TaintMeta {
            uses: uses_for_taint,
            ..Default::default()
        },
        ..Default::default()
    })
}

/// For a Rust `let <pattern> = match <scrutinee> { <arm> if <guard> => .., ... }`,
/// find the first guarded `match_arm` and return the guard expression node, the
/// primary let-binding name, and whether every *other* arm diverges.  Returns
/// `None` when the let-value is not a `match_expression` or no arm has a guard.
///
/// The guard lives on the tree-sitter `match_pattern` node as the field
/// `condition` (present whenever the pattern is followed by `if <expr>`).
///
/// The third element answers "can the code after the `match` be reached without
/// the guard holding?".  When every arm other than the guarded one diverges
/// (`_ => return`, `_ => panic!(…)`), the binding downstream can only carry the
/// guarded arm's value, so the caller drops the guard-false gate from the
/// statement frontier rather than handing the join a predecessor on which the
/// binding was never validated.
pub(super) fn detect_rust_let_match_guard<'a>(
    ast: Node<'a>,
    code: &[u8],
) -> Option<(Node<'a>, String, bool)> {
    if ast.fkind() != "let_declaration" {
        return None;
    }
    let value = ast.child_by_field_name("value")?;
    if value.fkind() != "match_expression" {
        return None;
    }
    let body = value.child_by_field_name("body")?;

    let mut cursor = body.walk();
    let arms: Vec<Node<'a>> = body
        .children(&mut cursor)
        .filter(|arm| matches!(arm.fkind(), "match_arm" | "last_match_arm"))
        .collect();

    // The guarded arm the synthetic If node stands for: the same "first arm
    // carrying a guard" rule the CFG synthesis is built around.
    let guarded_idx = arms.iter().position(|arm| {
        arm.child_by_field_name("pattern")
            .and_then(|p| p.child_by_field_name("condition"))
            .is_some()
    })?;
    let guard = arms[guarded_idx]
        .child_by_field_name("pattern")?
        .child_by_field_name("condition")?;

    // Every arm except the guarded one has to leave the function for the
    // guard-false path to be unreachable downstream.  An arm that yields a
    // value (including a second guarded arm) keeps the frontier conservative.
    let alternatives_diverge = arms
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != guarded_idx)
        .all(|(_, arm)| {
            arm.child_by_field_name("value")
                .is_some_and(|v| rust_expr_diverges(v, code))
        });

    let pat = ast.child_by_field_name("pattern")?;
    let mut idents = Vec::new();
    collect_idents(pat, code, &mut idents);
    let name = idents.into_iter().next()?;

    Some((guard, name, alternatives_diverge))
}

/// Does this Rust expression leave the enclosing function instead of producing
/// a value?
///
/// Recognises an explicit `return`, the diverging std macros / process
/// terminators, and a block whose last statement does one of those.  Anything
/// else is assumed to fall through, so the caller stays conservative.
///
/// The name list mirrors the Rust arm of `params::is_builtin_terminator`, but
/// the test cannot be shared: that recogniser answers "does this CFG *node*
/// end the block?", while a `let … = match …` collapses into a single Call
/// node whose arm bodies never become CFG nodes at all, so the arms have to be
/// judged on the AST.  `break` / `continue` are deliberately not claimed: they
/// leave a loop rather than the function, and the match-guard synthesis does
/// not model the surrounding loop edges.
fn rust_expr_diverges(node: Node, code: &[u8]) -> bool {
    // Macro callees are written without the trailing `!`, matching the way
    // the CFG records them.
    fn is_diverging_callee(name: &str) -> bool {
        matches!(
            name,
            "panic"
                | "unreachable"
                | "todo"
                | "unimplemented"
                | "process::exit"
                | "std::process::exit"
                | "process::abort"
                | "std::process::abort"
        )
    }

    match node.fkind() {
        "return_expression" => true,
        "macro_invocation" => node
            .child_by_field_name("macro")
            .and_then(|m| text_of(m, code))
            .is_some_and(|name| is_diverging_callee(&name)),
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|f| text_of(f, code))
            .is_some_and(|name| is_diverging_callee(&name)),
        // `_ => { return; }` and friends: the arm's value is a block, so the
        // decision rests on its last statement.  Comments are skipped so a
        // trailing `// unreachable` note cannot hide the terminator.
        "block" => {
            let mut cursor = node.walk();
            let mut last: Option<Node> = None;
            for child in node.named_children(&mut cursor) {
                if !matches!(child.fkind(), "line_comment" | "block_comment") {
                    last = Some(child);
                }
            }
            last.is_some_and(|stmt| {
                let inner = if stmt.fkind() == "expression_statement" {
                    stmt.named_child(0).unwrap_or(stmt)
                } else {
                    stmt
                };
                rust_expr_diverges(inner, code)
            })
        }
        _ => false,
    }
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
    let Some((cond_field, cons_field, alt_field)) = ternary_parts(ternary_ast) else {
        // Grammar mismatch (or PHP's `a ?: b` short form, which has no
        // separate consequence): caller will fall through to the non-split
        // path.
        return preds.to_vec();
    };
    let cond_ast = unwrap_parens(cond_field);
    let cons_ast = unwrap_parens(cons_field);
    let alt_ast = unwrap_parens(alt_field);

    // 1. Condition header. `push_condition_node` sets span/text/vars/negated
    //    but leaves `is_eq_with_const` default; stamp it explicitly so the
    //    taint engine's equality-narrowing fires for `x === 'literal' ? …`.
    let cond_if = push_condition_node(
        g,
        cond_ast,
        lang,
        code,
        enclosing_func,
        call_ordinal,
        analysis_rules,
    );
    g[cond_if].is_eq_with_const = detect_eq_with_const(cond_ast, lang);
    g[cond_if].is_ternary_condition = true;
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
    if ternary_parts(branch_ast).is_some() {
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

/// Conditional-expression node kinds lowered as a diamond: JS/TS/Java
/// `ternary_expression`, Python / PHP `conditional_expression`, Ruby
/// `conditional`.  Callers go through [`ternary_parts`], which also rejects
/// the PHP `a ?: b` short form.
fn is_ternary_node(node: Node) -> bool {
    matches!(
        node.fkind(),
        "ternary_expression" | "conditional_expression" | "conditional"
    )
}

/// `(condition, consequence, alternative)` of a conditional expression.
///
/// * JS/TS/Java `ternary_expression` and Ruby `conditional`: `condition` /
///   `consequence` / `alternative` fields.
/// * PHP `conditional_expression`: `condition` / `body` / `alternative`;
///   the `a ?: b` short form has no body and returns `None`.
/// * Python `conditional_expression` (`a if c else b`) has no fields: the
///   three named children are body, condition, alternative.
pub(super) fn ternary_parts(node: Node) -> Option<(Node, Node, Node)> {
    if !is_ternary_node(node) {
        return None;
    }
    if let Some(cond) = node.child_by_field_name("condition") {
        let cons = node
            .child_by_field_name("consequence")
            .or_else(|| node.child_by_field_name("body"))?;
        let alt = node.child_by_field_name("alternative")?;
        return Some((cond, cons, alt));
    }
    if node.fkind() != "conditional_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let parts: Vec<Node> = node
        .named_children(&mut cursor)
        .filter(|c| c.fkind() != "comment")
        .collect();
    match parts.as_slice() {
        [body, cond, alt] => Some((*cond, *body, *alt)),
        _ => None,
    }
}

/// Extract `(lhs_ast, ternary_ast)` when `outer_ast` is an expression-statement
/// or declaration whose single assignment/declarator's RHS is a conditional
/// expression with all three parts ([`ternary_parts`]).  Returns `None` for
/// multi-declarator forms, for missing fields, for the PHP `a ?: b` short
/// form, and for any other RHS after `unwrap_parens`.
pub(super) fn find_ternary_rhs_wrapper<'a>(outer_ast: Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    let mut cursor = outer_ast.walk();
    let mut declarator_count = 0usize;
    let mut found: Option<(Node<'a>, Node<'a>)> = None;

    for child in outer_ast.children(&mut cursor) {
        match child.fkind() {
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
                if ternary_parts(rhs).is_some() {
                    found = Some((name, rhs));
                }
            }
            // JS/TS/Java/PHP `assignment_expression`, Python `assignment`.
            // `x += c ? a : b` reads `x`; the diamond would rebind it as a
            // plain `x = a | b`.
            "assignment_expression" | "assignment" if rmw_assignment(child).is_none() => {
                let (Some(left), Some(right)) = (
                    child.child_by_field_name("left"),
                    child.child_by_field_name("right"),
                ) else {
                    continue;
                };
                let rhs = unwrap_parens(right);
                if ternary_parts(rhs).is_some() {
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

    // Prefer full member-expression path; fall back to raw text.  A PHP
    // `$name` binds the SSA variable `name` (see `collect_idents`).
    let lhs_text = member_expr_text(lhs_ast, code)
        .or_else(|| text_of(lhs_ast, code))
        .unwrap_or_default();
    let lhs_text = if lhs_ast.fkind() == "variable_name" {
        lhs_text.trim_start_matches('$').to_string()
    } else {
        lhs_text
    };

    // A Python / Ruby / PHP local (`query`, `@replies`, `$query`) is never
    // a sink, whatever its name; only member targets (`self.headers[..]`)
    // are worth classifying.  JS keeps bare names: `location = c ? a : b`
    // navigates.
    if matches!(lang, "python" | "ruby" | "php")
        && matches!(
            lhs_ast.fkind(),
            "identifier"
                | "variable_name"
                | "instance_variable"
                | "class_variable"
                | "global_variable"
        )
    {
        return (lhs_text, labels);
    }

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
#[allow(clippy::too_many_arguments)]
pub(super) fn build_condition_chain<'a>(
    cond_ast: Node<'a>,
    preds: &[NodeIndex],
    pred_edge: EdgeKind,
    g: &mut Cfg,
    lang: &str,
    code: &'a [u8],
    enclosing_func: Option<&str>,
    call_ordinal: &mut u32,
    analysis_rules: Option<&LangAnalysisRules>,
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let inner = unwrap_parens(cond_ast);

    match is_boolean_operator(inner) {
        Some(BoolOp::And) => {
            if let Some((left, right)) = get_boolean_operands(inner) {
                // Left operand with current preds
                let (left_true, left_false) = build_condition_chain(
                    left,
                    preds,
                    pred_edge,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                // Right operand only evaluated when left is true
                let (right_true, right_false) = build_condition_chain(
                    right,
                    &left_true,
                    EdgeKind::True,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                // AND: true only when both true; false when either false
                let mut false_exits = left_false;
                false_exits.extend(right_false);
                (right_true, false_exits)
            } else {
                // Safety fallback: treat as leaf
                let node = push_condition_node(
                    g,
                    inner,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                connect_all(g, preds, node, pred_edge);
                (vec![node], vec![node])
            }
        }
        Some(BoolOp::Or) => {
            if let Some((left, right)) = get_boolean_operands(inner) {
                // Left operand with current preds
                let (left_true, left_false) = build_condition_chain(
                    left,
                    preds,
                    pred_edge,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                // Right operand only evaluated when left is false
                let (right_true, right_false) = build_condition_chain(
                    right,
                    &left_false,
                    EdgeKind::False,
                    g,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                // OR: true when either true; false only when both false
                let mut true_exits = left_true;
                true_exits.extend(right_true);
                (true_exits, right_false)
            } else {
                // Safety fallback: treat as leaf
                let node = push_condition_node(
                    g,
                    inner,
                    lang,
                    code,
                    enclosing_func,
                    call_ordinal,
                    analysis_rules,
                );
                connect_all(g, preds, node, pred_edge);
                (vec![node], vec![node])
            }
        }
        None => {
            // Leaf: single condition node
            let node = push_condition_node(
                g,
                inner,
                lang,
                code,
                enclosing_func,
                call_ordinal,
                analysis_rules,
            );
            connect_all(g, preds, node, pred_edge);
            (vec![node], vec![node])
        }
    }
}

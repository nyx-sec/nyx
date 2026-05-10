#![allow(clippy::collapsible_if)]

use super::dominators::{self, dominates};
use super::rules;
use super::{
    AnalysisContext, BodyConstFacts, CfgAnalysis, CfgFinding, Confidence, is_entry_point_func,
};
use crate::callgraph::callee_leaf_name;
use crate::cfg::StmtKind;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule};
use crate::patterns::Severity;
use crate::ssa::const_prop::ConstLattice;
use crate::symbol::Lang;
use crate::ssa::type_facts::TypeFactResult;
use crate::ssa::{SsaOp, SsaValue};
use crate::taint::path_state::{PredicateKind, classify_condition};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::HashSet;

pub struct UnguardedSink;

/// Check whether **all** arguments to the sink are constants (no taint-capable
/// variable flows).  Extends the inline callee-part check by tracing one hop
/// through the CFG: if a used variable is defined by a node that itself has
/// empty `uses` and no Source label, the definition is treated as a constant
/// binding (e.g. `let cmd = "git"; Command::new(cmd)`).  When SSA
/// [`BodyConstFacts`] are available, falls back to walking the sink's
/// `SsaOp::Call` operands and consulting `OptimizeResult.const_values` for
/// any operand the syntactic trace can't classify (e.g. a chained method-call
/// receiver recorded as a compound identifier rather than a named binding).
fn is_all_args_constant(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    // Fast path: syntactic literal detection from CFG construction.
    // Strictly weaker than the one-hop trace below, serves as an
    // optimization for the common case of inline literal arguments.
    if ctx.cfg[sink].all_args_literal {
        return true;
    }
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    // Split callee description into parts and strip parenthesized arg portions.
    // e.g. `exec.Command("echo", "health-ok").Run` → ["exec", "Command", "Run"]
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    // When the callee was overridden by an inner call (e.g. `db.query` inside
    // `Promise.all([db.query(...)])`), the outer callee's parts (e.g. "Promise",
    // "all") also belong to the callee machinery, not to arguments.
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    sink_info.taint.uses.iter().all(|u| {
        // Part of the callee name itself → not an argument, skip
        // Check both individual parts and the full dotted callee path
        if callee_parts.contains(&u.as_str())
            || u == callee_desc
            || outer_parts.contains(&u.as_str())
        {
            return true;
        }
        // One-hop trace: find the defining node in the same function
        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];
            if info.ast.enclosing_func.as_deref() != sink_func {
                continue;
            }
            if info.taint.defines.as_deref() == Some(u.as_str()) {
                // If the defining node has no uses (pure constant) and is not
                // a Source, the variable is constant.
                if info.taint.uses.is_empty()
                    && !info
                        .taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, DataLabel::Source(_)))
                {
                    return true;
                }
            }
        }
        // Class-level constant scalar: Java `static final TYPE NAME = LIT;`
        // field references are compile-time constants that the per-function
        // CFG one-hop trace can't see (fields live outside any function
        // body) and that SSA const-prop doesn't surface either (the per-
        // function lowering treats the cross-scope reference as a free
        // identifier).
        if let Some(map) = ctx.class_constant_scalars
            && map.contains_key(u.as_str())
        {
            return true;
        }
        false
    }) || ssa_all_sink_operands_constant(ctx, sink, callee_desc, &callee_parts, &outer_parts)
}

/// SSA-backed fallback for `is_all_args_constant`.  Looks up the sink CFG
/// node in `cfg_node_map`, expects an `SsaOp::Call`, and checks that every
/// operand (positional args and receiver) either names a callee fragment or
/// resolves to a concrete `ConstLattice` literal.
fn ssa_all_sink_operands_constant(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    callee_desc: &str,
    callee_parts: &[&str],
    outer_parts: &[&str],
) -> bool {
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    let operand_const = |v: SsaValue| -> bool {
        ssa_operand_constant(v, facts, callee_desc, callee_parts, outer_parts)
    };
    let args_ok = args
        .iter()
        .all(|group| group.iter().all(|v| operand_const(*v)));
    let receiver_ok = receiver.is_none_or(operand_const);
    args_ok && receiver_ok
}

/// SSA-backed reassign-aware safety probe: every operand of the sink
/// resolves to a constant, callee fragment, OR a function parameter that
/// is not itself a Source.  Used at the cfg-unguarded-sink site under
/// `!has_taint`, the taint engine has already proved no source-tainted
/// data reaches the sink, so a non-source Param at operand position is
/// inert payload-wise (e.g. HTTP writer in `Fprintf(w, "<h1>", "Guest")`).
///
/// Gated on the function body actually exhibiting the reassign-to-constant
/// signature, at least one named SSA def whose RHS is a literal Const
/// (`name = "Guest"`).  In a thin wrapper without a same-block named
/// const assignment (`fn wrap(p) { sink(p) }`, or C `popen(buf, "r")` where
/// `buf` is filled in-place by `sprintf` with no Const Assign on `buf`),
/// the bare Param at operand position IS the payload and the suppression's
/// rationale does not apply, `cfg-unguarded-sink` must still fire.
fn ssa_all_sink_operands_const_or_param(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    if !func_body_has_named_const_assign(facts) {
        return false;
    }

    let operand_safe = |v: SsaValue| -> bool { ssa_operand_const_or_param(v, facts, ctx.cfg) };
    let args_ok = args
        .iter()
        .all(|group| group.iter().all(|v| operand_safe(*v)));
    let receiver_ok = receiver.is_none_or(operand_safe);
    args_ok && receiver_ok
}

/// Return true if the SSA body contains a *named* variable whose definition
/// is a constant, the SSA signature of an explicit `name = "literal"`
/// reassignment.  Used as the gate for the broader operand-Param suppression:
/// the suppression's purpose is the reassign-to-constant idiom, which by
/// definition has at least one named const assignment.  In a thin wrapper
/// (`fn wrap(p) { sink(p) }` or `popen(buf, "r")` where `buf` is filled by
/// `sprintf`), no such named const assignment exists and the suppression's
/// rationale doesn't apply, so the bare-Param structural finding fires.
fn func_body_has_named_const_assign(facts: &BodyConstFacts) -> bool {
    for block in &facts.ssa.blocks {
        for inst in &block.body {
            if inst.var_name.is_none() {
                continue;
            }
            let rhs_const = match &inst.op {
                SsaOp::Const(_) => true,
                SsaOp::Assign(vals) => vals.iter().all(|v| {
                    matches!(
                        facts.const_values.get(v),
                        Some(
                            ConstLattice::Str(_)
                                | ConstLattice::Int(_)
                                | ConstLattice::Bool(_)
                                | ConstLattice::Null
                        )
                    )
                }),
                _ => false,
            };
            if rhs_const {
                return true;
            }
        }
    }
    false
}

/// Variant of [`ssa_operand_constant`] that also accepts non-Source Params.
/// Stricter than `ssa_operand_constant` on Source (always false) but
/// looser on bare Params (always true unless they are Source-labeled).
fn ssa_operand_const_or_param(
    root: SsaValue,
    facts: &BodyConstFacts,
    cfg: &crate::cfg::Cfg,
) -> bool {
    let mut visited: HashSet<SsaValue> = HashSet::new();
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        if !visited.insert(v) {
            continue;
        }
        match facts.const_values.get(&v) {
            Some(ConstLattice::Str(_))
            | Some(ConstLattice::Int(_))
            | Some(ConstLattice::Bool(_))
            | Some(ConstLattice::Null) => continue,
            _ => {}
        }
        let Some(inst) = find_inst(&facts.ssa, v) else {
            return false;
        };
        // CFG-node-level Source label: when an SSA `Call` corresponds to a
        // Source-labeled CFG node (e.g. `env::var(...)` whose callee
        // matches a `LabelRule` Source matcher), the call's result is
        // tainted user input, refuse, regardless of how the SSA
        // happened to lower.  Catches the `SsaOp::Call` lowering of
        // labeled Source functions, which the `SsaOp::Source` arm only
        // sees for callee-less pure sources like PHP `$_GET`.
        let cfg_node = inst.cfg_node;
        if cfg
            .node_weight(cfg_node)
            .map(|info| {
                info.taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Source(_)))
            })
            .unwrap_or(false)
        {
            return false;
        }
        match &inst.op {
            SsaOp::Const(_) => {}
            SsaOp::Assign(vals) => stack.extend(vals.iter().copied()),
            SsaOp::Phi(ops) => stack.extend(ops.iter().map(|(_, v)| *v)),
            SsaOp::Call { args, receiver, .. } => {
                for group in args {
                    stack.extend(group.iter().copied());
                }
                if let Some(r) = receiver {
                    stack.push(*r);
                }
            }
            SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam => {
                // Bare parameters are accepted: at the call site the
                // taint engine has already concluded no source data
                // reaches this sink (`!has_taint` gate).  A Param that
                // is not source-tainted contributes only its caller-
                // bound value, which the gate above already filtered.
            }
            SsaOp::Source => return false,
            SsaOp::Nop | SsaOp::Undef => {}
            // FieldProj: walk the receiver, `obj.f` is constant iff `obj`
            // is constant under the same definition.  The field name itself
            // is structural and adds no runtime value.
            SsaOp::FieldProj { receiver, .. } => stack.push(*receiver),
        }
    }
    true
}

/// Return true if this SSA operand is a compile-time-known literal, a callee
/// fragment pseudo-use (not a real runtime value), or transitively composed
/// of such operands.  Returns false for sources, parameters with non-callee
/// names, `Varying` const-prop facts, and any unresolved definition.
fn ssa_operand_constant(
    root: SsaValue,
    facts: &BodyConstFacts,
    callee_desc: &str,
    callee_parts: &[&str],
    outer_parts: &[&str],
) -> bool {
    let mut visited: HashSet<SsaValue> = HashSet::new();
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        if !visited.insert(v) {
            continue;
        }
        match facts.const_values.get(&v) {
            Some(ConstLattice::Str(_))
            | Some(ConstLattice::Int(_))
            | Some(ConstLattice::Bool(_))
            | Some(ConstLattice::Null) => continue,
            Some(ConstLattice::Varying) => {
                // Fall through: a Varying lattice entry may still correspond
                // to a callee-fragment pseudo-name that the SSA models as a
                // Param.  The per-op check below filters those out.
            }
            _ => {}
        }
        let Some(inst) = find_inst(&facts.ssa, v) else {
            return false;
        };
        match &inst.op {
            SsaOp::Const(_) => {}
            SsaOp::Assign(vals) => stack.extend(vals.iter().copied()),
            SsaOp::Phi(ops) => stack.extend(ops.iter().map(|(_, v)| *v)),
            SsaOp::Call { args, receiver, .. } => {
                for group in args {
                    stack.extend(group.iter().copied());
                }
                if let Some(r) = receiver {
                    stack.push(*r);
                }
            }
            SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam | SsaOp::Source => {
                // Only acceptable when the param's `var_name` is a callee
                // fragment, i.e. an identifier that only appears because
                // the CFG recorded name components of the dotted/chained
                // callee as uses.  Real parameters and sources are dynamic.
                let name = inst.var_name.as_deref().unwrap_or("");
                if matches!(inst.op, SsaOp::Source) {
                    return false;
                }
                if !is_callee_fragment(name, callee_desc, callee_parts, outer_parts) {
                    return false;
                }
            }
            SsaOp::Nop => {}
            // Undef is a non-user, non-dynamic sentinel, treat like Const
            // (no additional operands to trace).
            SsaOp::Undef => {}
            // FieldProj: structural field read; constness reduces to the
            // receiver's constness.
            SsaOp::FieldProj { receiver, .. } => stack.push(*receiver),
        }
    }
    true
}

fn is_callee_fragment(
    name: &str,
    callee_desc: &str,
    callee_parts: &[&str],
    outer_parts: &[&str],
) -> bool {
    if name.is_empty() {
        return true;
    }
    if callee_parts.contains(&name) || outer_parts.contains(&name) || name == callee_desc {
        return true;
    }
    // Chained-receiver prefix: the name is a strict prefix of `callee_desc`
    // terminating at a `.` or `::` boundary (e.g. name =
    // `Command::new("sh").arg("-c").arg(cmd)` for callee_desc ending in
    // `.status().unwrap`).  These are the outer callee's receiver chain,
    // not user-supplied arguments.
    if callee_desc.len() > name.len() && callee_desc.starts_with(name) {
        let rest = &callee_desc[name.len()..];
        if rest.starts_with('.') || rest.starts_with("::") {
            return true;
        }
    }
    false
}

fn find_inst(ssa: &crate::ssa::SsaBody, v: SsaValue) -> Option<&crate::ssa::SsaInst> {
    let def = ssa.value_defs.get(v.0 as usize)?;
    let block = ssa.blocks.get(def.block.0 as usize)?;
    block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|inst| inst.value == v)
}

/// Check whether every operand SSA value of the sink's Call instruction is
/// proven by type-fact analysis to be non-injectable for `sink_caps`.
///
/// Used to suppress `cfg-unguarded-sink` when all arguments are typed safe
/// (e.g. Rust `port: u16` flowing into `Command::new(…).arg(port.to_string())`).
/// Returns `false` when any required fact is missing so the structural finding
/// is preserved whenever typing is ambiguous.
fn sink_args_typed_safe(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(type_facts) = ctx.type_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    // Chained Rust/JS calls record the whole dotted path as a single Call node.
    // Its SSA operands include pseudo-uses for every identifier segment of the
    // callee (e.g. `Command`, `new`, `arg`, `status`, `unwrap`) plus string
    // literal arguments to intermediate calls.  Filter those out so the
    // is-Int check runs only against real argument values.
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();

    let is_real_arg = |v: SsaValue| -> bool {
        let Some(def) = find_inst(&facts.ssa, v) else {
            return true;
        };
        // Callee-fragment pseudo-uses appear as `Param { .. }` with a
        // var_name that is a segment of the callee text.  SelfParam and
        // CatchParam cover `self`/exception bindings that cannot be the
        // implicit callee chain.
        match &def.op {
            SsaOp::Param { .. } => {
                let name = def.var_name.as_deref().unwrap_or("");
                !is_callee_fragment(name, callee_desc, &callee_parts, &outer_parts)
            }
            // Constant string literals used as inline args (e.g. `"listener"`,
            // `"-c"`) are not user-controlled, treat as non-real for the
            // "all int-typed" test so they don't block suppression.
            SsaOp::Const(_) => false,
            _ => true,
        }
    };

    let mut values: Vec<SsaValue> = Vec::new();
    if let Some(r) = receiver {
        if is_real_arg(*r) {
            values.push(*r);
        }
    }
    for group in args {
        for v in group.iter() {
            if is_real_arg(*v) {
                values.push(*v);
            }
        }
    }
    type_facts_suppress(&values, sink_caps, type_facts)
}

/// Suppress a `cfg-unguarded-sink` SQL_QUERY finding when any positional
/// argument to the sink Call is provably a JPA / Hibernate Criteria query
/// object ([`crate::ssa::type_facts::TypeKind::JpaCriteriaQuery`]).
///
/// Receiver values are deliberately excluded, the receiver of a JPA
/// query method (`session.createQuery(cq)`, `em.createQuery(cq)`,
/// `session.executeUpdate(cq)`) is the connection / EntityManager
/// channel, never the SQL payload.  Including the receiver in the type
/// check would make this suppression unreachable since `Session` /
/// `EntityManager` values are typed `Object` / `Unknown` and never
/// `JpaCriteriaQuery` themselves.
///
/// Closes the dominant FP cluster across openmrs (169 of 216
/// cfg-unguarded-sink), xwiki, and keycloak: Hibernate DAO methods
/// build a `CriteriaQuery<Foo>` via `cb.createQuery(Foo.class)` +
/// `Root` / `Predicate` API, then hand the query object to
/// `session.createQuery(cq)` for execution.  No string concatenation
/// happens, JPA emits parameterized SQL by construction.
fn sink_args_jpa_criteria_query_safe(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    sink_caps: Cap,
) -> bool {
    if !sink_caps.intersects(Cap::SQL_QUERY) {
        return false;
    }
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(type_facts) = ctx.type_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, .. } = &inst.op else {
        return false;
    };
    let mut values: Vec<SsaValue> = Vec::new();
    for group in args {
        for v in group.iter() {
            values.push(*v);
        }
    }
    crate::ssa::type_facts::is_safe_query_object_arg(&values, sink_caps, type_facts)
}

/// Suppress a `cfg-unguarded-sink` SQL_QUERY finding when the call site is
/// a zero-positional-argument query-builder execute / create verb.
///
/// Doctrine DBAL `QueryBuilder` (`$qb->select(...)->from(...)->executeQuery()`),
/// JPA / Hibernate `CriteriaBuilder` (`cb.createQuery()` returning the
/// query-object factory), and any chained-builder pattern share the shape:
/// the SQL string is bound earlier on the receiver chain via parameterized
/// API calls (`->select`, `->from`, `->where(... param ...)`), and the
/// terminal verb that fires on the sink list (`executeQuery`,
/// `executeStatement`, `executeUpdate`, `createQuery`, `createNativeQuery`)
/// takes zero positional args, no SQL string ever flows through the call
/// site itself.
///
/// vs. the dangerous flat shape:
/// `$conn->executeQuery($sql, $params)` — arg 0 carries the SQL string,
/// the structural finding is correctly preserved.
///
/// Restricted to verb names where JDBC / Doctrine / JPA expose a
/// receiver-built (zero-arg) overload.  PHP `stmt.execute` is excluded
/// because PDOStatement::execute() can be reached via a tainted
/// `prepare($sql)` chain where the SQL was already built unsafely;
/// the receiver-side taint check is the only thing that fires there.
fn sink_is_zero_arg_query_builder(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.intersects(Cap::SQL_QUERY) {
        return false;
    }
    // Only suppress when the sink's caps are SQL_QUERY-only.  Multi-cap
    // sinks may carry a non-SQL injection vector through the same call.
    if sink_caps != Cap::SQL_QUERY {
        return false;
    }
    // Restrict to PHP.  Java / Kotlin / JVM langs already cover the
    // safe prepared-statement shape via the `prepareStatement` Sanitizer
    // rule that dominates `pstmt.executeUpdate()` / `pstmt.executeQuery()`
    // at the structural finding site.  PHP's Doctrine DBAL `QueryBuilder`
    // and Drupal `Connection::prepareStatement` shapes need explicit
    // structural support because the receiver isn't always sanitized in
    // a way the dominator-Sanitizer scan recognises (chain receiver,
    // closure-captured helper, etc.).
    if ctx.lang != Lang::Php {
        return false;
    }
    let info = &ctx.cfg[sink];
    let callee = match info.call.callee.as_deref() {
        Some(c) => c,
        None => return false,
    };
    let suffix = callee.rsplit('.').next().unwrap_or(callee);
    let is_builder_verb =
        matches!(suffix, "executeQuery" | "executeStatement" | "createQuery");
    if !is_builder_verb {
        return false;
    }
    // Restrict to receivers that name a known query-builder.  The
    // root-receiver text is the leftmost segment of the callee chain;
    // for `$qb->...->executeQuery()` the root is `qb`, for
    // `$deleteQuery->executeStatement()` it is `deleteQuery`, etc.
    // Patterns canvassed from Doctrine DBAL / Drupal Database / Nextcloud
    // dav / lib idioms:
    //   * canonical names: qb, query, queryBuilder, builder, q
    //   * verb-bound builders: deleteQuery, insertQuery, selectTagQuery,
    //     calendarObjectIdQuery, deleteQb, qbDeleteCalendarObjectProps
    //   * action-named builders: insert, update, delete, select, upsert,
    //     forUpdate, restoreUpdate
    // Receivers named after the SQL connection (`conn`, `connection`,
    // `dbc`, `db`) or entity-manager (`em`, `entityManager`) are
    // excluded since their `executeQuery` / `executeStatement` overloads
    // accept a SQL string arg.
    let root_receiver = match callee.split('.').next() {
        Some(r) if !r.is_empty() => r,
        _ => return false,
    };
    let receiver_lower = root_receiver.to_ascii_lowercase();
    let is_builder_receiver_by_name = receiver_lower == "qb"
        || receiver_lower == "q"
        || receiver_lower == "query"
        || receiver_lower == "querybuilder"
        || receiver_lower == "builder"
        || receiver_lower == "insert"
        || receiver_lower == "update"
        || receiver_lower == "delete"
        || receiver_lower == "select"
        || receiver_lower == "upsert"
        || receiver_lower.starts_with("qb")
        || receiver_lower.starts_with("querybuilder")
        || receiver_lower.ends_with("qb")
        || receiver_lower.ends_with("query")
        || receiver_lower.ends_with("builder");
    let is_builder_receiver_by_def =
        receiver_defined_by_builder_factory(ctx, sink, root_receiver);
    if !is_builder_receiver_by_name && !is_builder_receiver_by_def {
        return false;
    }
    // Once the receiver is proven to be a builder via def-call lookup, the
    // call is the builder-variant of `executeQuery` / `executeStatement`
    // regardless of argument count (Doctrine DBAL `QueryBuilder::executeQuery`
    // accepts only an optional `?Connection`, never a SQL string).  When the
    // receiver was identified solely by its NAME, fall back to the byte-level
    // zero-arg check that guards the closure-captured shape so an unfamiliar
    // verb-named local (`$insert = "DROP TABLE..."`-bound mistake) doesn't
    // unconditionally suppress.
    if !is_builder_receiver_by_def && !callee_span_has_zero_args(info, ctx.source_bytes) {
        return false;
    }
    true
}

/// Suppress a `cfg-unguarded-sink` SQL_QUERY finding when the sink call's first
/// positional argument is the result of a Doctrine DBAL safe-SQL accessor —
/// either `<builder>.getSQL()` (parameterised SQL from a QueryBuilder chain)
/// or a `Platform::get*SQL(...)` factory (`getTruncateTableSQL`,
/// `getCreateTableSQL`, etc., which return DDL with no user-controlled bytes).
///
/// Two paths:
///  1. Direct arg: `arg_callees[0]` names a recognised accessor.  Catches
///     `$conn->executeStatement($builder->getSQL(), ...)` and
///     `$conn->executeStatement($platform->getTruncateTableSQL('t', false))`.
///  2. Indirect via local var: the arg is a bare identifier `$sql` whose
///     most-recent same-function defining Call has a recognised accessor as
///     its callee.  Catches the migration shape
///     `$sql = $this->dbc->getDatabasePlatform()->getTruncateTableSQL(...);
///      $this->dbc->executeStatement($sql);`
///
/// PHP-only: other languages have their own builder conventions (Java JPA's
/// `CriteriaQuery` is already covered by `sink_args_jpa_criteria_query_safe`).
fn sink_first_arg_is_builder_get_sql(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    sink_caps: Cap,
) -> bool {
    if !sink_caps.intersects(Cap::SQL_QUERY) {
        return false;
    }
    if sink_caps != Cap::SQL_QUERY {
        return false;
    }
    if ctx.lang != Lang::Php {
        return false;
    }
    let info = &ctx.cfg[sink];

    // Path 1: direct method-call arg.
    if let Some(Some(arg_callee)) = info.arg_callees.first() {
        let suffix = arg_callee.rsplit('.').next().unwrap_or(arg_callee);
        if is_dbal_safe_sql_accessor(suffix) {
            return true;
        }
    }

    // Path 2: bare-identifier arg defined earlier by a recognised accessor.
    // Use `arg_uses[0]` (the first positional argument's identifier set) to
    // pick the candidate variable name.  When `arg_uses` is empty (e.g. the
    // arg is a literal, an arithmetic expression, or a complex chain), no
    // back-walk is performed.
    let first_arg_use = info
        .call
        .arg_uses
        .first()
        .and_then(|grp| grp.first())
        .map(|s| s.as_str());
    let var_name = match first_arg_use {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };
    let sink_func = info.ast.enclosing_func.as_deref();
    let sink_span_start = info.ast.span.0;
    let mut best: Option<(usize, String)> = None;
    for nidx in ctx.cfg.node_indices() {
        let n = &ctx.cfg[nidx];
        if n.kind != crate::cfg::StmtKind::Call {
            continue;
        }
        if n.taint.defines.as_deref() != Some(var_name) {
            continue;
        }
        if n.ast.enclosing_func.as_deref() != sink_func {
            continue;
        }
        let span_start = n.ast.span.0;
        if span_start >= sink_span_start {
            continue;
        }
        let Some(callee) = n.call.callee.as_deref() else {
            continue;
        };
        match best {
            Some((s, _)) if s >= span_start => {}
            _ => best = Some((span_start, callee.to_string())),
        }
    }
    if let Some((_, callee)) = best {
        let suffix = callee.rsplit('.').next().unwrap_or(&callee);
        if is_dbal_safe_sql_accessor(suffix) {
            return true;
        }
    }
    false
}

/// Recognise method names that Doctrine DBAL exposes as safe-SQL accessors.
/// `getSQL` is the QueryBuilder accessor; `get*SQL` (case-sensitive `SQL`
/// suffix) is the Platform-specific DDL builder convention used across the
/// `Doctrine\DBAL\Platforms\*` hierarchy (`getTruncateTableSQL`,
/// `getCreateTableSQL`, `getDropTableSQL`, etc.).  All such methods receive
/// schema identifiers and emit DBMS-specific DDL, never weaving user payload.
fn is_dbal_safe_sql_accessor(name: &str) -> bool {
    if name == "getSQL" {
        return true;
    }
    name.starts_with("get")
        && name.len() > 5
        && name.ends_with("SQL")
}

/// Suppress a `cfg-unguarded-sink` SQL_QUERY finding when the sink's first
/// positional argument *composes* a Doctrine DBAL safe-SQL accessor with
/// constant string-shaping ops.  Two real-world shapes from nextcloud:
///   (a) `$conn->executeStatement(preg_replace('/^INSERT/i', 'INSERT IGNORE',
///        $builder->getSQL()), ...)`
///   (b) `$conn->executeStatement($builder->getSQL() . ' ON CONFLICT DO
///        NOTHING', ...)`
///
/// Strategy (byte-level, conservative):
///   1. Lang-gate to PHP.  Cap-gate to SQL_QUERY-only.
///   2. Extract the sink's first-positional-arg source bytes by balanced-paren
///      walk inside the call's `ast.span`, with single/double-quoted-string
///      awareness.
///   3. Scan arg-0 bytes for every PHP variable token `$<name>`.  Every var
///      must be bound by a query-builder factory (`getQueryBuilder` /
///      `createQueryBuilder` / `*queryBuilder`).  Bypasses `arg_uses` because
///      `collect_idents_with_paths` also surfaces method names (`getSQL`,
///      `getParameters`) that are not variable references in PHP.
///   4. At least one var must appear in arg-0 bytes as the receiver of a DBAL
///      safe-SQL accessor call (`$<recv>->getSQL(` or `$<recv>->get*SQL(`).
///
/// The taint engine has already cleared this flow (gate is `!has_taint`),
/// so the suppression's job is to silence the structural cfg-unguarded-sink
/// over-fire on builder-composed SQL.  PHP-only.
fn sink_first_arg_composes_safe_dbal_sql(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    sink_caps: Cap,
) -> bool {
    if sink_caps != Cap::SQL_QUERY {
        return false;
    }
    if ctx.lang != Lang::Php {
        return false;
    }
    let info = &ctx.cfg[sink];
    let Some(arg0_bytes) = first_positional_arg_bytes(info, ctx.source_bytes) else {
        return false;
    };
    if arg0_bytes.is_empty() {
        return false;
    }
    let vars = extract_php_variables(arg0_bytes);
    if vars.is_empty() {
        return false;
    }
    let mut accessor_seen = false;
    for name in &vars {
        if !receiver_defined_by_builder_factory(ctx, sink, name) {
            return false;
        }
        if arg_bytes_call_dbal_accessor_on(arg0_bytes, name) {
            accessor_seen = true;
        }
    }
    accessor_seen
}

/// Extract the unique PHP variable identifiers appearing as `$<name>` tokens
/// in `bytes`.  Skips the `$` sigil; variables tokens are alphanumeric +
/// underscore.  Order-stable (insertion order, with deduplication), so the
/// caller's any-failure-bails loop deterministically rejects the first
/// non-builder-bound var.
fn extract_php_variables(bytes: &[u8]) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let mut e = i + 1;
        while e < bytes.len() && (bytes[e].is_ascii_alphanumeric() || bytes[e] == b'_') {
            e += 1;
        }
        if e > i + 1 {
            if let Ok(name) = std::str::from_utf8(&bytes[i + 1..e]) {
                if !result.iter().any(|n| n == name) {
                    result.push(name.to_string());
                }
            }
        }
        i = e.max(i + 1);
    }
    result
}

/// Extract the source bytes of the sink call's first positional argument.
///
/// Scans `info.ast.span` for the first `(` (outer args opener), then
/// balance-walks parens with single/double-quoted-string awareness, returning
/// the slice up to the first depth-1 `,` or the matching closing `)`.
/// PHP-shaped: handles `'...'` and `"..."` with backslash escapes; ignores
/// heredoc/nowdoc, which don't appear inside DBAL call-site argument lists
/// in practice.  `callee_span` is intentionally ignored because the upstream
/// CFG narrowing path may set it to the *whole* call span (e.g. when a
/// `return $this->conn->executeStatement(...)` is lowered: `inner_text_span`
/// records the call's span via `first_call_ident_with_span`).  Searching
/// from `ast.span.0` and matching the first `(` is robust across both
/// direct-call and statement-wrapped shapes.
///
/// Returns `None` if no `(` is found or the walk runs off the end of
/// `ast.span` without closing.
fn first_positional_arg_bytes<'a>(
    info: &crate::cfg::NodeInfo,
    bytes: &'a [u8],
) -> Option<&'a [u8]> {
    let span = info.ast.span;
    if span.1 > bytes.len() || span.0 >= span.1 {
        return None;
    }
    let mut i = span.0;
    while i < span.1 && bytes[i] != b'(' {
        i += 1;
    }
    if i >= span.1 {
        return None;
    }
    let arg_start = i + 1;
    let mut j = arg_start;
    let mut depth: i32 = 1;
    let mut quote: Option<u8> = None;
    while j < span.1 {
        let b = bytes[j];
        if let Some(q) = quote {
            if b == b'\\' && j + 1 < span.1 {
                j += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => {
                quote = Some(b);
                j += 1;
            }
            b'(' => {
                depth += 1;
                j += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&bytes[arg_start..j]);
                }
                j += 1;
            }
            b',' if depth == 1 => {
                return Some(&bytes[arg_start..j]);
            }
            _ => j += 1,
        }
    }
    None
}

/// Return true if `arg0` contains a method-call against `recv_name` whose
/// method matches [`is_dbal_safe_sql_accessor`].  Recognises the PHP
/// member-access shape `$<recv>-><method>(`.  The backward walk stops at
/// the first non-identifier byte; the immediately preceding byte must be
/// the `$` sigil so `mybuilder->getSQL` does not match `recv = "builder"`.
fn arg_bytes_call_dbal_accessor_on(arg0: &[u8], recv_name: &str) -> bool {
    if recv_name.is_empty() {
        return false;
    }
    let recv_bytes = recv_name.as_bytes();
    let mut i = 0usize;
    while i + 1 < arg0.len() {
        if arg0[i] != b'-' || arg0[i + 1] != b'>' {
            i += 1;
            continue;
        }
        // Walk backward to capture the receiver identifier ending at i.
        let mut s = i;
        while s > 0 {
            let c = arg0[s - 1];
            if c.is_ascii_alphanumeric() || c == b'_' {
                s -= 1;
            } else {
                break;
            }
        }
        if s == i || s == 0 || arg0[s - 1] != b'$' || &arg0[s..i] != recv_bytes {
            i += 2;
            continue;
        }
        // Walk forward to capture the method identifier following `->`.
        let mut e = i + 2;
        while e < arg0.len() {
            let c = arg0[e];
            if c.is_ascii_alphanumeric() || c == b'_' {
                e += 1;
            } else {
                break;
            }
        }
        // Must be followed by `(`.
        if e < arg0.len() && arg0[e] == b'(' {
            if let Ok(method) = std::str::from_utf8(&arg0[i + 2..e]) {
                if is_dbal_safe_sql_accessor(method) {
                    return true;
                }
            }
        }
        i += 2;
    }
    false
}

/// Suppress a `cfg-unguarded-sink` SQL_QUERY finding when the sink's first
/// positional argument interpolates only PHP variables that are bound by a
/// `foreach` over a literal-keyed array within the same function body.
/// Real-world shape from nextcloud `lib/private/DB/MySqlTools.php:27`:
///   ```php
///   $variables = ['innodb_file_per_table' => 'ON'];
///   if (...) { $variables['innodb_file_format'] = 'Barracuda'; }
///   foreach ($variables as $var => $val) {
///       $connection->executeQuery("SHOW VARIABLES LIKE '$var'");
///   }
///   ```
/// The foreach-key `$var` ranges over `{innodb_file_per_table,
/// innodb_file_format, innodb_large_prefix}`, all metachar-free, so the
/// interpolated SQL is bounded.
///
/// Strategy (byte-level, conservative):
///   1. Lang-gate to PHP.  Cap-gate to SQL_QUERY-only.
///   2. Extract the sink's first-positional-arg source bytes; collect every
///      `$<name>` interpolation token.
///   3. For every var, walk the enclosing function bytes.  Find the
///      innermost `foreach ($X as $name => $...)` or `foreach ($X as $name)`
///      pattern whose body contains the sink span, with `$name` matching
///      the use site.
///   4. Find every assignment of `$X` in the function body.  Each must be
///      either an array literal `['LIT' => 'LIT', ...]` (key-arrow form) or
///      a subscript-set `$X['LIT'] = 'LIT';`.  Every key/value involved
///      must be metachar-free (alphanumeric + `_`, `-`, `.`).
///   5. Whether the use site reads the foreach-key (`$key` slot) or
///      foreach-value (`$val` slot), the corresponding literal set must be
///      proven safe.
///
/// PHP-only.  Limited to the simple foreach + literal-array shape; bare-
/// reference / by-reference foreach variants and dynamic array sources
/// fall through to the structural finding.
fn sink_arg_uses_safe_foreach_key(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    sink_caps: Cap,
) -> bool {
    if sink_caps != Cap::SQL_QUERY {
        return false;
    }
    if ctx.lang != Lang::Php {
        return false;
    }
    let info = &ctx.cfg[sink];
    let Some(arg0_bytes) = first_positional_arg_bytes(info, ctx.source_bytes) else {
        return false;
    };
    if arg0_bytes.is_empty() {
        return false;
    }
    let vars = extract_php_variables(arg0_bytes);
    if vars.is_empty() {
        return false;
    }
    let Some(func_scope) = enclosing_func_byte_scope(ctx, sink) else {
        return false;
    };
    for name in &vars {
        if !php_var_safe_via_foreach_literal_array(
            ctx.source_bytes,
            func_scope,
            info.ast.span.0,
            name,
        ) {
            return false;
        }
    }
    true
}

/// Extent of the enclosing function body.  Returns `None` when the sink
/// has no `enclosing_func` (e.g. file-level top-level statement) or no
/// matching CFG nodes.  The byte range is `(min_span.0, max_span.1)` over
/// the function's CFG nodes, conservative against multi-statement bodies.
fn enclosing_func_byte_scope(
    ctx: &AnalysisContext,
    sink: NodeIndex,
) -> Option<(usize, usize)> {
    let sink_func = ctx.cfg[sink].ast.enclosing_func.as_deref()?;
    let mut lo = usize::MAX;
    let mut hi = 0usize;
    for n in ctx.cfg.node_indices() {
        let info = &ctx.cfg[n];
        if info.ast.enclosing_func.as_deref() != Some(sink_func) {
            continue;
        }
        if info.ast.span.0 < lo {
            lo = info.ast.span.0;
        }
        if info.ast.span.1 > hi {
            hi = info.ast.span.1;
        }
    }
    if lo == usize::MAX || hi == 0 || lo >= hi {
        return None;
    }
    Some((lo, hi))
}

/// Walk `source[func_scope]` for `foreach (...)` blocks containing
/// `sink_span_start` in their body.  Match the iteration pattern shape and
/// (when found) verify every assignment of the iterated identifier in the
/// function body is a literal-keyed array or a subscript-set with literal
/// key, with all keys/values metachar-free.  Returns true only when *every*
/// candidate foreach proves safe; bails (returns false) on the first
/// failure to keep the suppression conservative.
fn php_var_safe_via_foreach_literal_array(
    source: &[u8],
    func_scope: (usize, usize),
    sink_span_start: usize,
    name: &str,
) -> bool {
    if name.is_empty() {
        return false;
    }
    if func_scope.0 >= func_scope.1 || func_scope.1 > source.len() {
        return false;
    }
    let scope = &source[func_scope.0..func_scope.1];
    let sink_offset = if sink_span_start >= func_scope.0 {
        sink_span_start - func_scope.0
    } else {
        return false;
    };
    let needle = b"foreach";
    let mut cursor = 0usize;
    let mut matched_any = false;
    while cursor + needle.len() <= scope.len() {
        let Some(rel) = find_subslice(&scope[cursor..], needle) else {
            break;
        };
        let pos = cursor + rel;
        cursor = pos + needle.len();
        // Require word boundary: prev byte (if any) must not be alnum/`_`.
        if pos > 0 {
            let prev = scope[pos - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }
        // Skip whitespace; require `(`.
        let mut p = pos + needle.len();
        while p < scope.len() && matches!(scope[p], b' ' | b'\t' | b'\n' | b'\r') {
            p += 1;
        }
        if p >= scope.len() || scope[p] != b'(' {
            continue;
        }
        // Balanced walk to closing `)`.
        let header_open = p;
        let mut depth = 1i32;
        let mut q = p + 1;
        let mut quote: Option<u8> = None;
        while q < scope.len() && depth > 0 {
            let b = scope[q];
            if let Some(c) = quote {
                if b == b'\\' && q + 1 < scope.len() {
                    q += 2;
                    continue;
                }
                if b == c {
                    quote = None;
                }
                q += 1;
                continue;
            }
            match b {
                b'\'' | b'"' => quote = Some(b),
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            q += 1;
        }
        if depth != 0 {
            continue;
        }
        let header_close = q - 1;
        // Skip whitespace; require `{`.
        let mut bp = header_close + 1;
        while bp < scope.len() && matches!(scope[bp], b' ' | b'\t' | b'\n' | b'\r') {
            bp += 1;
        }
        if bp >= scope.len() || scope[bp] != b'{' {
            continue;
        }
        // Balanced walk to closing `}`.
        let body_open = bp;
        let mut bdepth = 1i32;
        let mut bq = bp + 1;
        let mut bquote: Option<u8> = None;
        while bq < scope.len() && bdepth > 0 {
            let b = scope[bq];
            if let Some(c) = bquote {
                if b == b'\\' && bq + 1 < scope.len() {
                    bq += 2;
                    continue;
                }
                if b == c {
                    bquote = None;
                }
                bq += 1;
                continue;
            }
            match b {
                b'\'' | b'"' => bquote = Some(b),
                b'{' => bdepth += 1,
                b'}' => bdepth -= 1,
                _ => {}
            }
            bq += 1;
        }
        if bdepth != 0 {
            continue;
        }
        let body_end = bq - 1;
        // Sink position must lie inside the body.
        if sink_offset < body_open || sink_offset > body_end {
            continue;
        }
        let header = &scope[header_open + 1..header_close];
        let Some((iter_var, key_var, val_var)) = parse_foreach_header(header) else {
            return false;
        };
        let used_as_key = key_var.as_deref() == Some(name);
        let used_as_val = val_var.as_str() == name;
        if !used_as_key && !used_as_val {
            // The use site references some other variable; not bound by
            // this foreach.  Continue scanning (might be a nested foreach).
            continue;
        }
        if !php_iter_var_assigns_safe_literals(scope, &iter_var, used_as_key, used_as_val) {
            return false;
        }
        matched_any = true;
    }
    matched_any
}

/// Parse a foreach header text (the bytes between `(` and `)`).  Returns
/// `(iter_var, key_var, value_var)`.  Recognises `$X as $V` and
/// `$X as $K => $V` shapes; bails (returns `None`) on by-reference
/// (`& $V`), expressions (`call() as $V`), or any unexpected token.
fn parse_foreach_header(header: &[u8]) -> Option<(String, Option<String>, String)> {
    let text = std::str::from_utf8(header).ok()?.trim();
    let lower = text;
    let as_pos = find_word(lower.as_bytes(), b"as")?;
    let iter_part = lower[..as_pos].trim();
    let body_part = lower[as_pos + 2..].trim();
    let iter_var = parse_simple_var(iter_part)?;
    if body_part.contains("=>") {
        let mut split = body_part.splitn(2, "=>");
        let k = split.next()?.trim();
        let v = split.next()?.trim();
        let key_var = parse_simple_var(k)?;
        let val_var = parse_simple_var(v)?;
        Some((iter_var, Some(key_var), val_var))
    } else {
        let val_var = parse_simple_var(body_part)?;
        Some((iter_var, None, val_var))
    }
}

/// Parse a `$<name>` token, rejecting any extra tokens (whitespace OK).
/// By-reference (`&$x`), splat (`...$x`), or list-destructuring shapes
/// produce `None` so the suppression bails conservatively.
fn parse_simple_var(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let bytes = trimmed.as_bytes();
    if bytes.first() != Some(&b'$') {
        return None;
    }
    let rest = &trimmed[1..];
    if rest.is_empty() {
        return None;
    }
    if !rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    Some(rest.to_string())
}

/// Find a whole-word match of `word` inside `text`.  Word boundaries are
/// non-alnum/non-`_` bytes (or the buffer edges).  Returns the byte offset
/// of the first match.
fn find_word(text: &[u8], word: &[u8]) -> Option<usize> {
    let mut cursor = 0usize;
    while cursor + word.len() <= text.len() {
        let rel = find_subslice(&text[cursor..], word)?;
        let pos = cursor + rel;
        let prev_ok = pos == 0 || {
            let p = text[pos - 1];
            !(p.is_ascii_alphanumeric() || p == b'_')
        };
        let next = pos + word.len();
        let next_ok = next == text.len() || {
            let p = text[next];
            !(p.is_ascii_alphanumeric() || p == b'_')
        };
        if prev_ok && next_ok {
            return Some(pos);
        }
        cursor = pos + 1;
    }
    None
}

/// For every assignment of `$<iter_var>` inside `scope` (the enclosing
/// function bytes), require every key/value referenced is a metachar-free
/// string literal (alphanumeric, `_`, `-`, `.`, space).  Recognises:
///   * `$<iter_var> = ['LIT' => 'LIT', ...];` (key-arrow array literal)
///   * `$<iter_var>['LIT'] = 'LIT';` (subscript-set with literal key)
///
/// Conservative: any other assignment shape, missing literals, or empty
/// array set returns false.  When `used_as_key` is true, the literal keys
/// must be safe; when `used_as_val` is true, the literal values must be
/// safe; both flags can be true at once.
fn php_iter_var_assigns_safe_literals(
    scope: &[u8],
    iter_var: &str,
    used_as_key: bool,
    used_as_val: bool,
) -> bool {
    if iter_var.is_empty() {
        return false;
    }
    let needle: Vec<u8> = std::iter::once(b'$')
        .chain(iter_var.bytes())
        .collect();
    let mut cursor = 0usize;
    let mut saw_init = false;
    while cursor + needle.len() <= scope.len() {
        let Some(rel) = find_subslice(&scope[cursor..], &needle) else {
            break;
        };
        let pos = cursor + rel;
        cursor = pos + 1;
        // Word-boundary on the trailing side: the next byte must not be
        // alnum/`_` (no `$variables_extra`).
        let after = pos + needle.len();
        if after < scope.len() {
            let b = scope[after];
            if b.is_ascii_alphanumeric() || b == b'_' {
                continue;
            }
        }
        // Skip trailing whitespace.
        let mut p = after;
        while p < scope.len() && matches!(scope[p], b' ' | b'\t' | b'\n' | b'\r') {
            p += 1;
        }
        if p >= scope.len() {
            continue;
        }
        match scope[p] {
            b'=' => {
                // Direct assignment: `$X = ['k' => 'v', ...];`
                if p + 1 < scope.len() && scope[p + 1] == b'=' {
                    continue; // comparison
                }
                if !php_check_array_literal_assignment(scope, p + 1, used_as_key, used_as_val) {
                    return false;
                }
                saw_init = true;
            }
            b'[' => {
                // Subscript-set: `$X['LIT'] = 'LIT';`
                if !php_check_subscript_set(scope, p, used_as_key, used_as_val) {
                    return false;
                }
            }
            _ => {
                // Other usage (foreach iter, function arg, member access).
                // Doesn't add to the literal set; allowed as long as no
                // unrecognised assignment shape appears.
            }
        }
    }
    saw_init
}

/// Validate an array-literal assignment after `$X =` (cursor points at
/// the byte just after `=`).  Allowed: optional whitespace, then `[ ... ];`
/// where every element is `'LIT' => 'LIT'` with metachar-free literals.
fn php_check_array_literal_assignment(
    scope: &[u8],
    after_eq: usize,
    used_as_key: bool,
    used_as_val: bool,
) -> bool {
    let mut p = after_eq;
    while p < scope.len() && matches!(scope[p], b' ' | b'\t' | b'\n' | b'\r') {
        p += 1;
    }
    if p >= scope.len() || scope[p] != b'[' {
        return false;
    }
    let body_open = p + 1;
    let mut depth = 1i32;
    let mut q = body_open;
    let mut quote: Option<u8> = None;
    while q < scope.len() && depth > 0 {
        let b = scope[q];
        if let Some(c) = quote {
            if b == b'\\' && q + 1 < scope.len() {
                q += 2;
                continue;
            }
            if b == c {
                quote = None;
            }
            q += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'[' => depth += 1,
            b']' => depth -= 1,
            _ => {}
        }
        q += 1;
    }
    if depth != 0 {
        return false;
    }
    let body_close = q - 1;
    let elements = &scope[body_open..body_close];
    php_check_kv_array_literal(elements, used_as_key, used_as_val)
}

/// Walk an array-literal body (between `[` and `]`).  Each element must
/// be `'LIT' => 'LIT'`.  All keys/values used by the consumer must be
/// metachar-free.
fn php_check_kv_array_literal(elements: &[u8], used_as_key: bool, used_as_val: bool) -> bool {
    if elements.iter().all(|b| b.is_ascii_whitespace()) {
        return false;
    }
    // Split by `,` at depth 0.
    let mut start = 0usize;
    let mut quote: Option<u8> = None;
    let mut depth = 0i32;
    let mut any_pair = false;
    let mut i = 0usize;
    while i < elements.len() {
        let b = elements[i];
        if let Some(c) = quote {
            if b == b'\\' && i + 1 < elements.len() {
                i += 2;
                continue;
            }
            if b == c {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'[' | b'(' => depth += 1,
            b']' | b')' => depth -= 1,
            b',' if depth == 0 => {
                if !php_check_arrow_pair(&elements[start..i], used_as_key, used_as_val) {
                    return false;
                }
                any_pair = true;
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = &elements[start..];
    if tail.iter().any(|b| !b.is_ascii_whitespace()) {
        if !php_check_arrow_pair(tail, used_as_key, used_as_val) {
            return false;
        }
        any_pair = true;
    }
    any_pair
}

/// Validate one `'LIT' => 'LIT'` pair.  Both literals must be string
/// literals (`'...'` or `"..."`) with metachar-free contents per
/// `is_metachar_free_literal`.
fn php_check_arrow_pair(pair: &[u8], used_as_key: bool, used_as_val: bool) -> bool {
    let text = std::str::from_utf8(pair).map(str::trim).unwrap_or("");
    let mut split = text.splitn(2, "=>");
    let k = match split.next() {
        Some(s) => s.trim(),
        None => return false,
    };
    let v = match split.next() {
        Some(s) => s.trim(),
        None => return false,
    };
    if used_as_key && !is_metachar_free_string_literal(k.as_bytes()) {
        return false;
    }
    if used_as_val && !is_metachar_free_string_literal(v.as_bytes()) {
        return false;
    }
    true
}

/// Validate a subscript-set assignment `$X[...] = ...;` starting at the
/// `[` byte.  Both the subscript key (when `used_as_key`) and the
/// assigned value (when `used_as_val`) must be metachar-free string
/// literals.
fn php_check_subscript_set(
    scope: &[u8],
    open_bracket: usize,
    used_as_key: bool,
    used_as_val: bool,
) -> bool {
    let mut depth = 1i32;
    let mut q = open_bracket + 1;
    let mut quote: Option<u8> = None;
    while q < scope.len() && depth > 0 {
        let b = scope[q];
        if let Some(c) = quote {
            if b == b'\\' && q + 1 < scope.len() {
                q += 2;
                continue;
            }
            if b == c {
                quote = None;
            }
            q += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'[' => depth += 1,
            b']' => depth -= 1,
            _ => {}
        }
        q += 1;
    }
    if depth != 0 {
        return false;
    }
    let close_bracket = q - 1;
    let key_bytes = &scope[open_bracket + 1..close_bracket];
    if used_as_key && !is_metachar_free_string_literal(key_bytes.trim_ascii()) {
        return false;
    }
    // Skip whitespace; require `=`, not `==`.
    let mut p = close_bracket + 1;
    while p < scope.len() && matches!(scope[p], b' ' | b'\t' | b'\n' | b'\r') {
        p += 1;
    }
    if p >= scope.len() || scope[p] != b'=' {
        return false;
    }
    if p + 1 < scope.len() && scope[p + 1] == b'=' {
        return false;
    }
    // Read the RHS up to the next `;` at depth 0 (no string awareness needed
    // beyond `;` because PHP statement separator).
    let mut q = p + 1;
    let mut quote: Option<u8> = None;
    let mut depth = 0i32;
    while q < scope.len() {
        let b = scope[q];
        if let Some(c) = quote {
            if b == b'\\' && q + 1 < scope.len() {
                q += 2;
                continue;
            }
            if b == c {
                quote = None;
            }
            q += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => break,
            _ => {}
        }
        q += 1;
    }
    let rhs = &scope[p + 1..q];
    if used_as_val && !is_metachar_free_string_literal(rhs.trim_ascii()) {
        return false;
    }
    true
}

/// `true` when `bytes` form a single-quoted or double-quoted string
/// literal whose contents are alphanumeric, `_`, `-`, `.`, or space —
/// safe for SQL pattern literal interpolation.  Rejects empty string,
/// any escape sequences, control characters, quotes, semicolons, or
/// shell/SQL metacharacters.
fn is_metachar_free_string_literal(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if first != last || (first != b'\'' && first != b'"') {
        return false;
    }
    let inner = &bytes[1..bytes.len() - 1];
    if inner.is_empty() {
        return false;
    }
    inner
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b' '))
}

/// Check whether the source bytes inside the sink's `callee_span` end with a
/// zero-argument call form: trailing `)` preceded by `(` with only whitespace
/// in between.  Used to identify `qb.executeQuery()` / `qb.executeStatement()`
/// where the SQL was bound earlier on the receiver chain.
fn callee_span_has_zero_args(info: &crate::cfg::NodeInfo, bytes: &[u8]) -> bool {
    let span = info.call.callee_span.unwrap_or(info.ast.span);
    if span.0 >= span.1 || span.1 > bytes.len() {
        return false;
    }
    let slice = &bytes[span.0..span.1];
    let mut end = slice.len();
    while end > 0 && matches!(slice[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
        end -= 1;
    }
    if end == 0 || slice[end - 1] != b')' {
        return false;
    }
    end -= 1;
    while end > 0 && matches!(slice[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
        end -= 1;
    }
    end > 0 && slice[end - 1] == b'('
}

/// Detect that `receiver_name` was bound earlier in the same function by a
/// query-builder factory call.  Two paths:
///  1. CFG def-call: a same-function Call node defines `receiver_name` with a
///     callee ending in `getQueryBuilder` / `createQueryBuilder`.
///  2. Source-text scan: between the enclosing function's first byte and the
///     sink's byte offset, the source contains
///     `$<receiver_name> = ... ->getQueryBuilder(...)` (or `createQueryBuilder`).
///     Picks up assignment nodes whose CFG kind/callee text doesn't surface a
///     leaf factory name (multi-line chains, `for`/`try` block nesting,
///     unusual lowering paths).
fn receiver_defined_by_builder_factory(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    receiver_name: &str,
) -> bool {
    if receiver_name.is_empty() {
        return false;
    }
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.ast.enclosing_func.as_deref();
    let sink_span_start = sink_info.ast.span.0;

    // Path 1: CFG-level def lookup.
    let mut best: Option<(usize, String)> = None;
    for nidx in ctx.cfg.node_indices() {
        let n = &ctx.cfg[nidx];
        if n.kind != crate::cfg::StmtKind::Call {
            continue;
        }
        if n.taint.defines.as_deref() != Some(receiver_name) {
            continue;
        }
        if n.ast.enclosing_func.as_deref() != sink_func {
            continue;
        }
        let span_start = n.ast.span.0;
        if span_start >= sink_span_start {
            continue;
        }
        let Some(callee) = n.call.callee.as_deref() else {
            continue;
        };
        match best {
            Some((s, _)) if s >= span_start => {}
            _ => best = Some((span_start, callee.to_string())),
        }
    }
    if let Some((_, callee)) = best {
        let suffix = callee.rsplit('.').next().unwrap_or(&callee);
        let suffix_lower = suffix.to_ascii_lowercase();
        if matches!(
            suffix_lower.as_str(),
            "getquerybuilder" | "createquerybuilder" | "getqb" | "createqb"
        ) || suffix_lower.ends_with("querybuilder")
        {
            return true;
        }
    }

    // Path 2: source-text scan over the enclosing function's body.  Some
    // builder assignments (multi-line chains, deeply nested in `try`/`for`
    // bodies) bind `defines` to a synthesised name that doesn't match
    // `receiver_name` exactly.  A direct byte scan for an assignment shape
    // catches these without depending on CFG synthesis details.
    let func_start = ctx
        .cfg
        .node_indices()
        .filter_map(|i| {
            let n = &ctx.cfg[i];
            if n.ast.enclosing_func.as_deref() == sink_func {
                Some(n.ast.span.0)
            } else {
                None
            }
        })
        .min()
        .unwrap_or(0);
    let bytes = ctx.source_bytes;
    let lo = func_start.min(bytes.len());
    let hi = sink_span_start.min(bytes.len());
    if lo >= hi {
        return false;
    }
    let scope = &bytes[lo..hi];
    text_contains_builder_factory_assignment(scope, receiver_name)
}

/// Search `scope` for `$<name> = ... <factory>(...)` where `<factory>` ends
/// with `getQueryBuilder` / `createQueryBuilder` (case-insensitive).  Used as a
/// byte-level fallback for CFG def-lookup that misses multi-line chained
/// assignments inside nested `try` / `for` bodies.
fn text_contains_builder_factory_assignment(scope: &[u8], name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let needle: Vec<u8> = std::iter::once(b'$')
        .chain(name.bytes())
        .collect();
    let mut start = 0usize;
    while start + needle.len() <= scope.len() {
        let Some(rel) = find_subslice(&scope[start..], &needle) else {
            return false;
        };
        let mut cursor = start + rel + needle.len();
        // Require an immediate `=` (allow whitespace before).
        while cursor < scope.len() && matches!(scope[cursor], b' ' | b'\t' | b'\n' | b'\r') {
            cursor += 1;
        }
        if cursor < scope.len() && scope[cursor] == b'=' && (cursor + 1 == scope.len() || scope[cursor + 1] != b'=') {
            // Find the next `;` (statement terminator) without crossing a
            // closing brace boundary, the assignment expression spans up to it.
            let mut end = cursor + 1;
            while end < scope.len() {
                let b = scope[end];
                if b == b';' || b == b'\n' && end + 1 < scope.len() && scope[end + 1] == b'\n' {
                    break;
                }
                end += 1;
            }
            let rhs_lower: Vec<u8> = scope[cursor + 1..end]
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            if find_subslice(&rhs_lower, b"getquerybuilder").is_some()
                || find_subslice(&rhs_lower, b"createquerybuilder").is_some()
            {
                return true;
            }
        }
        start = start + rel + 1;
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Walk the sink's Call SSA arguments and check whether every real argument
/// resolves through a defining `SsaOp::Call` whose callee carries an SSA
/// summary with `validated_params_to_return` covering every propagating
/// parameter slot the caller's argument flows into.  When that holds, the
/// helper validates each argument on every taint-carrying return path, and
/// the call result is structurally validated even though no syntactic guard
/// dominates the sink in the caller's body.
///
/// Conservative: returns `false` whenever any required fact is missing,
/// any operand is non-Call-defined and not a constant/parameter, or any
/// callee summary lacks the validated transform.  Real arguments only —
/// the same `is_real_arg` filter as `sink_args_typed_safe` skips
/// callee-fragment pseudo-uses and SSA constants.
fn sink_args_summary_validated_safe(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    // Per-file SSA summary map carries the augment + rerun-pass merges
    // that GlobalSummaries may not yet reflect on single-file scans;
    // fall back to GlobalSummaries when the per-file map isn't threaded
    // through (legacy callers).
    let local_map = ctx.ssa_summaries;
    let global_map = ctx.global_summaries.map(|g| g.snapshot_ssa());
    if local_map.is_none() && global_map.is_none() {
        return false;
    }

    let sink_info = &ctx.cfg[sink];
    use crate::cfg::StmtKind;

    // Collect per-arg use names.  Prefer `call.arg_uses` (positional, tighter
    // scope), fall back to `taint.uses` minus callee-fragment names when
    // `arg_uses` wasn't extracted (e.g. `await db.execute(sql)` where the
    // CFG saw the await wrapper rather than the underlying call_expression).
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();

    let mut arg_use_names: Vec<String> = Vec::new();
    if !sink_info.call.arg_uses.is_empty() {
        for group in &sink_info.call.arg_uses {
            for u in group {
                if !arg_use_names.iter().any(|n| n == u) {
                    arg_use_names.push(u.clone());
                }
            }
        }
    }
    if arg_use_names.is_empty() {
        for u in &sink_info.taint.uses {
            if is_callee_fragment(u, callee_desc, &callee_parts, &outer_parts) {
                continue;
            }
            if !arg_use_names.iter().any(|n| n == u) {
                arg_use_names.push(u.clone());
            }
        }
    }
    if arg_use_names.is_empty() {
        return false;
    }

    // Match callee text against any SSA summary key registered in
    // GlobalSummaries by leaf name.  Conservative: require an exact
    // single-match so ambiguous overloads fall through to the default
    // structural-finding path.
    let lookup_validated = |callee_text: &str| -> Option<bool> {
        let leaf = callee_leaf_name(callee_text);
        let mut matches: Vec<&crate::summary::ssa_summary::SsaFuncSummary> = Vec::new();
        if let Some(map) = local_map {
            for (key, sum) in map {
                if key.name == leaf || key.name == callee_text {
                    matches.push(sum);
                }
            }
        }
        if matches.is_empty() {
            if let Some(map) = global_map {
                for (key, sum) in map {
                    if key.name == leaf || key.name == callee_text {
                        matches.push(sum);
                    }
                }
            }
        }
        if matches.len() != 1 {
            return None;
        }
        let sum = matches[0];
        if sum.validated_params_to_return.is_empty() {
            return Some(false);
        }
        // Every propagating parameter must be in validated_params_to_return.
        // When the callee doesn't propagate taint at all, the call result
        // cannot carry caller-side taint, so a non-empty validation set is
        // sufficient.
        let propagates = sum
            .param_to_return
            .iter()
            .map(|(idx, _)| *idx)
            .collect::<Vec<usize>>();
        if propagates.is_empty() {
            return Some(true);
        }
        let all_validated = propagates
            .iter()
            .all(|p| sum.validated_params_to_return.contains(p));
        Some(all_validated)
    };

    // Walk CFG predecessors of `sink` looking for nodes that define an
    // arg-use name via a Call to an in-file helper.  Conservative
    // traversal: stops at the body entry, follows Seq/Branch edges,
    // bails out on join/branch back-edges (loops) to keep the analysis
    // bounded.
    let mut to_validate: Vec<String> = arg_use_names.clone();
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    let mut frontier: Vec<NodeIndex> = ctx
        .cfg
        .neighbors_directed(sink, petgraph::Direction::Incoming)
        .collect();
    let mut iter_budget = 256usize;
    while let Some(n) = frontier.pop() {
        if iter_budget == 0 {
            return false;
        }
        iter_budget -= 1;
        if !visited.insert(n) {
            continue;
        }
        let info = &ctx.cfg[n];
        if info.kind == StmtKind::Call {
            if let Some(def_name) = info.taint.defines.as_deref() {
                if let Some(pos) = to_validate.iter().position(|u| u == def_name) {
                    let callee = info.call.callee.as_deref().unwrap_or("");
                    if !matches!(lookup_validated(callee), Some(true)) {
                        return false;
                    }
                    to_validate.remove(pos);
                    if to_validate.is_empty() {
                        return true;
                    }
                }
            }
        }
        for pred in ctx.cfg.neighbors_directed(n, petgraph::Direction::Incoming) {
            frontier.push(pred);
        }
    }
    // Some arg-use names didn't map to an in-body Call definition (e.g.
    // they bind to a function parameter, an import, or a literal).
    // Only suppress when EVERY tainted-shaped arg has been validated by
    // an in-file helper summary; otherwise fall through.
    to_validate.is_empty()
}

/// Thin wrapper around [`crate::ssa::type_facts::is_type_safe_for_sink`] kept
/// local so the unit tests here can exercise the exact predicate used at the
/// `cfg-unguarded-sink` emission site.
fn type_facts_suppress(values: &[SsaValue], sink_caps: Cap, type_facts: &TypeFactResult) -> bool {
    crate::ssa::type_facts::is_type_safe_for_sink(values, sink_caps, type_facts)
}

/// Suppress a `cfg-unguarded-sink` finding when every real argument SSA
/// value resolves to a finite set of metacharacter-free literals, as proved
/// by the static-map analysis.  Runs in lock-step with the SSA taint
/// suppression so both findings paths agree on when a provably-bounded
/// lookup idiom (e.g. `map.get(x).unwrap_or("safe")` over literal inserts)
/// should clear a command-injection sink.
///
/// Only fires for `Cap::SHELL_ESCAPE`, SQL / path suppression from this
/// domain would require stronger reasoning (literal keys can still carry
/// SQL tokens if the inserts themselves contain them).
fn sink_args_static_map_safe(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.intersects(Cap::SHELL_ESCAPE) {
        return false;
    }
    let Some(facts) = ctx.body_const_facts else {
        return false;
    };
    let Some(&sink_val) = facts.ssa.cfg_node_map.get(&sink) else {
        return false;
    };
    let Some(inst) = find_inst(&facts.ssa, sink_val) else {
        return false;
    };
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };

    let sm =
        crate::ssa::static_map::analyze(&facts.ssa, ctx.cfg, Some(ctx.lang), &facts.const_values);
    if sm.is_empty() {
        return false;
    }

    // Skip callee-fragment pseudo-uses the same way `sink_args_typed_safe`
    // does so only real runtime arg values participate in the check.
    let sink_info = &ctx.cfg[sink];
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    let callee_parts: Vec<&str> = callee_desc
        .split(['.', ':'])
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect();
    let outer_parts: Vec<&str> = sink_info
        .call
        .outer_callee
        .as_deref()
        .map(|oc| {
            oc.split(['.', ':'])
                .map(|p| p.split('(').next().unwrap_or(p))
                .collect()
        })
        .unwrap_or_default();

    let is_real_arg = |v: SsaValue| -> bool {
        let Some(def) = find_inst(&facts.ssa, v) else {
            return true;
        };
        match &def.op {
            SsaOp::Param { .. } => {
                let name = def.var_name.as_deref().unwrap_or("");
                !is_callee_fragment(name, callee_desc, &callee_parts, &outer_parts)
            }
            SsaOp::Const(_) => false,
            _ => true,
        }
    };

    let mut values: Vec<SsaValue> = Vec::new();
    if let Some(r) = receiver {
        if is_real_arg(*r) {
            values.push(*r);
        }
    }
    for group in args {
        for v in group.iter() {
            if is_real_arg(*v) {
                values.push(*v);
            }
        }
    }
    if values.is_empty() {
        return false;
    }
    values.iter().all(|v| match sm.finite_string_values.get(v) {
        Some(set) if !set.is_empty() => set
            .iter()
            .all(|s| crate::abstract_interp::string_domain::is_shell_safe_literal(s)),
        _ => false,
    })
}

/// Check if a callee matches any of the runtime label rules that are sanitizers.
fn match_config_sanitizer(callee: &str, extra: &[RuntimeLabelRule]) -> Option<Cap> {
    // Lazily compute lowercased callee only when a case-insensitive rule is hit.
    let mut callee_lower: Option<String> = None;

    for rule in extra {
        let cap = match rule.label {
            DataLabel::Sanitizer(c) => c,
            _ => continue,
        };
        for m in &rule.matchers {
            if rule.case_sensitive {
                if m.ends_with('_') {
                    if callee.starts_with(m.as_str()) {
                        return Some(cap);
                    }
                } else if callee.ends_with(m.as_str()) {
                    return Some(cap);
                }
            } else {
                let cl = callee_lower.get_or_insert_with(|| callee.to_ascii_lowercase());
                let ml = m.to_ascii_lowercase();
                if ml.ends_with('_') {
                    if cl.starts_with(&ml) {
                        return Some(cap);
                    }
                } else if cl.ends_with(&ml) {
                    return Some(cap);
                }
            }
        }
    }
    None
}

/// Resolve the `if (X)` / `if (!X)` indirect-validator pattern: the
/// condition has exactly one bare-identifier variable whose defining
/// CFG node is a [`StmtKind::Call`] whose `defines` is the same name
/// and whose `callee` is recognised by
/// [`crate::ssa::type_facts::classify_input_validator_callee`].
///
/// Returns the validator callee name when the pattern matches, `None`
/// otherwise.  Conservative: bails when the condition has zero or more
/// than one variable, when no defining call is found, or when the
/// callee doesn't match a validator pattern.  Mirrors the SSA
/// branch-narrowing layer
/// ([`crate::taint::ssa_transfer::apply_input_validator_branch_narrowing`])
/// so the structural `cfg-unguarded-sink` suppression matches the
/// taint engine's validator recognition.
///
/// Driven off CFG `TaintMeta.defines` rather than the per-body SSA
/// value-defs because nested arrow-function bodies are sometimes
/// lowered with empty SSA in the cfg-analysis context, but the CFG
/// nodes themselves carry `defines` in every body.
fn cond_indirect_validator_callee(
    info: &crate::cfg::NodeInfo,
    ctx: &AnalysisContext,
) -> Option<String> {
    if info.condition_vars.len() != 1 {
        return None;
    }
    let var_name = info.condition_vars[0].as_str();
    let cond_func = info.ast.enclosing_func.as_deref();
    let cond_span_start = info.ast.span.0;

    // Walk the CFG for any node that DEFINES `var_name` via a Call
    // expression.  Same-function only, and only consider definitions
    // textually before the condition: a reassignment after the `if`
    // cannot be the def reaching it.  Among the eligible defs, take
    // the textually-last one (highest span start), a conservative
    // latest-def proxy without paying for full dominator analysis.
    let mut best: Option<(usize, &str)> = None;
    for nidx in ctx.cfg.node_indices() {
        let n = &ctx.cfg[nidx];
        if n.kind != crate::cfg::StmtKind::Call {
            continue;
        }
        if n.taint.defines.as_deref() != Some(var_name) {
            continue;
        }
        if n.ast.enclosing_func.as_deref() != cond_func {
            continue;
        }
        let span_start = n.ast.span.0;
        if span_start >= cond_span_start {
            continue;
        }
        let Some(callee) = n.call.callee.as_deref() else {
            continue;
        };
        match best {
            Some((s, _)) if s >= span_start => {}
            _ => best = Some((span_start, callee)),
        }
    }
    let (_, callee) = best?;

    crate::ssa::type_facts::classify_input_validator_callee(callee).map(|_| callee.to_string())
}

/// Find all nodes in the CFG that are calls to guard functions.
fn find_guard_nodes(ctx: &AnalysisContext) -> Vec<(NodeIndex, Cap)> {
    let guard_rules = rules::guard_rules(ctx.lang);
    let config_rules = ctx
        .analysis_rules
        .map(|r| r.extra_labels.as_slice())
        .unwrap_or(&[]);
    let mut result = Vec::new();

    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];

        // If-condition guards: allowlist checks, type checks, validation
        // calls, shell-metachar rejections, and bounded-length checks in
        // branch conditions act as guards for downstream sinks.
        if info.kind == StmtKind::If {
            if let Some(cond_text) = &info.condition_text {
                let kind = classify_condition(cond_text);
                // For `AllowlistCheck`, also confirm a target identifier was
                // extractable.  When the receiver-method form carries a
                // string-literal arg (`filePath.includes("/")`,
                // `path.contains("..")`), `extract_allowlist_target` returns
                // `None` because the argument isn't an identifier.  Those
                // shapes are presence-checks, not real allowlist tests against
                // a collection variable, and shouldn't dominate every
                // downstream sink as a structural guard with `Cap::all()`.
                // `classify_condition` itself stays unchanged (an existing
                // test locks in its broad return for the receiver-method form,
                // and the SSA branch-narrowing layer reads the kind for its
                // own purposes).
                let allowlist_has_target = if kind == PredicateKind::AllowlistCheck {
                    crate::taint::path_state::classify_condition_with_target(cond_text)
                        .1
                        .is_some()
                } else {
                    true
                };
                if matches!(
                    kind,
                    PredicateKind::TypeCheck | PredicateKind::ValidationCall,
                ) || (kind == PredicateKind::AllowlistCheck && allowlist_has_target)
                {
                    result.push((idx, Cap::all()));
                } else if cond_indirect_validator_callee(info, ctx).is_some() {
                    // Indirect-validator pattern:
                    //   const err = validate(x); if (err) throw …;
                    //   const ok = isValid(x);   if (!ok) throw …;
                    // The classifier returns Unknown / NullCheck / ErrorCheck
                    // because the if-condition is a bare result variable, not
                    // a direct call expression. `cond_indirect_validator_callee`
                    // handles that by scanning the CFG for nodes whose
                    // `TaintMeta.defines` matches the condition variable and
                    // checking whether any defining Call has an
                    // `is_input_validator_callee`-recognised callee. This keeps
                    // cfg-unguarded-sink suppression aligned with the same
                    // structural validator recognition the SSA branch-narrowing
                    // layer uses, without requiring the condition itself to be
                    // a direct call expression.
                    //
                    // Motivated by Novu CVE GHSA-4x48-cgf9-q33f.
                    result.push((idx, Cap::all()));
                } else if matches!(
                    kind,
                    PredicateKind::ShellMetaValidated | PredicateKind::BoundedLength
                ) {
                    // Shell-metachar rejection and bounded-length checks only
                    // guard shell-family sinks.  Keep scope tight so unrelated
                    // sinks (SQL, XSS) aren't silenced when a shell gate
                    // happens to sit upstream.
                    result.push((idx, Cap::SHELL_ESCAPE | Cap::CODE_EXEC));
                } else {
                    // Path-traversal rejection guard.  When the condition
                    // matches a path-rejection idiom recognised by
                    // `classify_path_rejection_axes` (`strstr(p, "..")`
                    // / `.contains("..")` / `strings.Contains(p, "..")`
                    // / `p[0] == '/'` / `path.is_absolute()` / etc.),
                    // it acts as a guard for FILE_IO sinks.  Catches
                    // the C/C++ `if (strstr(p, "..") != NULL)` shape
                    // whose `!= NULL` wrapper otherwise falls through
                    // to NullCheck classification and never registers
                    // as a guard.  Scope kept to FILE_IO so unrelated
                    // sinks aren't silenced.
                    let axes = crate::abstract_interp::path_domain::classify_path_rejection_axes(
                        cond_text,
                    );
                    if !axes.is_empty() {
                        result.push((idx, Cap::FILE_IO));
                    }
                }
            }
        }

        if info.kind != StmtKind::Call {
            continue;
        }
        if let Some(callee) = &info.call.callee {
            // Check config sanitizer rules first
            if let Some(cap) = match_config_sanitizer(callee, config_rules) {
                result.push((idx, cap));
                continue;
            }

            // Then check built-in guard rules
            let callee_lower = callee.to_ascii_lowercase();
            for rule in guard_rules {
                let matched = rule.matchers.iter().any(|m| {
                    let ml = m.to_ascii_lowercase();
                    if ml.ends_with('_') {
                        callee_lower.starts_with(&ml)
                    } else {
                        callee_lower.ends_with(&ml)
                    }
                });
                if matched {
                    result.push((idx, rule.applies_to_sink_caps));
                    break;
                }
            }
        }
    }

    result
}

/// Check whether taint analysis confirmed unsanitized flow to this sink node.
fn taint_confirms_sink(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    ctx.taint_findings.iter().any(|f| f.sink == sink)
}

/// Check whether any variable used by the sink is directly derived from a
/// Source node in the same function (via simple def-use chain).
fn sink_arg_is_source_derived(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    // Collect all variables the sink reads
    let sink_uses = &sink_info.taint.uses;
    if sink_uses.is_empty() {
        return false;
    }

    // Walk all nodes in the same function looking for Source nodes that define
    // one of the variables the sink uses.
    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.ast.enclosing_func.as_deref() != sink_func {
            continue;
        }
        if !info
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_)))
        {
            continue;
        }
        // Source node defines a variable that the sink reads → source-derived
        if let Some(def) = &info.taint.defines
            && sink_uses.iter().any(|u| u == def)
        {
            return true;
        }
    }
    false
}

/// Check whether the sink's arguments are *only* function parameters
/// (i.e. this function is a thin wrapper around the sink).
fn sink_arg_is_parameter_only(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    let sink_uses = &sink_info.taint.uses;
    if sink_uses.is_empty() {
        // No identifiable arguments, could be a constant call like Command::new("ls")
        return true; // treat as non-dangerous (constant arg)
    }

    // Collect parameter names for the enclosing function from FuncSummaries
    let param_names: Vec<&str> = ctx
        .func_summaries
        .values()
        .filter(|s| {
            // Match by function entry being in the same function
            ctx.cfg[s.entry].ast.enclosing_func.as_deref() == sink_func
        })
        .flat_map(|s| s.param_names.iter().map(|p| p.as_str()))
        .collect();

    if param_names.is_empty() {
        return false; // can't determine params
    }

    // The sink's `taint.uses` includes pseudo-uses for callee-chain segments
    // when the chain is rooted at a self-pseudo-receiver (`this`, `self`,
    // `static`, `parent`).  In that case every segment of the chain is part
    // of the dotted callee path that tree-sitter records as identifier
    // children of the call expression, not a real argument.  This shape
    // covers thin method wrappers like
    // `function wrap($sql) { return $this->inner->execute($sql); }` so the
    // sink is recognised as parameter-only despite `this` / `inner` /
    // `execute` showing up in `taint.uses`.
    //
    // For other callee chains (e.g. Python `cursor.execute(name)` where
    // `cursor` is a local variable from `connection.cursor()`), only the
    // method name itself (`execute`) is filtered.  `cursor` is a real
    // identifier value — a non-param local — and must not be filtered,
    // otherwise wrappers around external receivers get suppressed
    // incorrectly.
    //
    // PHP variable receivers carry a leading `$` (`$this->inner->execute`)
    // and use `->` between the receiver and member, so split on the full
    // set of separators and strip a leading `$` so identifier-shaped
    // fragments line up with bare identifier names in `taint.uses`.
    //
    // Each segment carries an `is_call` flag so chain pieces that are
    // themselves method invocations (`getSession()` in
    // `getSession().createQuery(qs)`) can be recognised as pseudo-uses
    // alongside the terminal method name.  Variable-receiver chains like
    // `cursor.execute(name)` keep `cursor` as a real identifier and stay
    // out of the param-only filter.
    let callee_desc = sink_info.call.callee.as_deref().unwrap_or("");
    let outer_callee = sink_info.call.outer_callee.as_deref().unwrap_or("");
    fn split_chain_with_flags(s: &str) -> SmallVec<[(&str, bool); 8]> {
        let mut out: SmallVec<[(&str, bool); 8]> = SmallVec::new();
        for piece in s.split(['.', ':', '>', '-']) {
            let stripped = piece.trim_start_matches('$').trim();
            if stripped.is_empty() {
                continue;
            }
            let (name, is_call) = match stripped.find('(') {
                Some(idx) => (stripped[..idx].trim(), true),
                None => (stripped, false),
            };
            if !name.is_empty() {
                out.push((name, is_call));
            }
        }
        out
    }
    fn is_self_root(seg: &str) -> bool {
        matches!(seg, "this" | "self" | "static" | "parent" | "cls")
    }
    let mut callee_fragments: SmallVec<[&str; 8]> = SmallVec::new();
    for src in [callee_desc, outer_callee] {
        let segs = split_chain_with_flags(src);
        let Some(&(first_name, _)) = segs.first() else {
            continue;
        };
        let last_idx = segs.len() - 1;
        if is_self_root(first_name) {
            // Whole chain is callee path: `$this->inner->execute` →
            // every segment is a pseudo-use.
            for &(name, _) in &segs {
                if !callee_fragments.contains(&name) {
                    callee_fragments.push(name);
                }
            }
        } else {
            // The terminal method name is a pseudo-use.  Any non-last
            // segment that is itself a method call (`getSession()` in
            // `getSession().createQuery(qs)`) is also a pseudo-use, since
            // the segment text in the chain refers to a method name, not
            // a local variable.  Bare-identifier receivers like `cursor`
            // in `cursor.execute(name)` carry no `(` and stay as real
            // local-variable values.
            for (i, &(name, is_call)) in segs.iter().enumerate() {
                if (is_call || i == last_idx) && !callee_fragments.contains(&name) {
                    callee_fragments.push(name);
                }
            }
        }
    }

    // Source-text scan: `callee_desc` collapses chains via `root_receiver_text`,
    // so `getSession().getCriteriaBuilder().createQuery(qs)` reduces to
    // `"getSession().createQuery"` and the intermediate `getCriteriaBuilder`
    // is missing.  Walk the sink's source bytes up to the outermost args
    // opener and lift every `IDENT(` pattern as a method-call pseudo-use.
    // Identifiers nested inside earlier `()` groups (which open at depth 0
    // for sibling method calls in a chain) are picked up too, so every
    // chain hop contributes its method name.
    let span = sink_info.classification_span();
    let (start, end) = span;
    if start < ctx.source_bytes.len() && end <= ctx.source_bytes.len() && start < end {
        let span_bytes = &ctx.source_bytes[start..end];
        if let Ok(span_text) = std::str::from_utf8(span_bytes) {
            let bytes = span_text.as_bytes();
            // Find the outermost args-opener: the last `(` at depth 0.
            let mut depth: i32 = 0;
            let mut last_open_at_zero: Option<usize> = None;
            for (i, &b) in bytes.iter().enumerate() {
                match b {
                    b'(' => {
                        if depth == 0 {
                            last_open_at_zero = Some(i);
                        }
                        depth += 1;
                    }
                    b')' => {
                        depth = depth.saturating_sub(1);
                    }
                    _ => {}
                }
            }
            let chain_end = last_open_at_zero.unwrap_or(bytes.len());
            // Walk the chain prefix and lift every identifier directly followed
            // by `(` as a method-call pseudo-use.
            let mut i = 0;
            while i < chain_end {
                let b = bytes[i];
                let is_ident_start = b.is_ascii_alphabetic() || b == b'_';
                if !is_ident_start {
                    i += 1;
                    continue;
                }
                let id_start = i;
                while i < chain_end {
                    let c = bytes[i];
                    if c.is_ascii_alphanumeric() || c == b'_' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                if i < chain_end && bytes[i] == b'(' {
                    let name = &span_text[id_start..i];
                    if !callee_fragments.contains(&name) {
                        callee_fragments.push(name);
                    }
                }
            }
        }
    }

    sink_uses.iter().all(|u| {
        if callee_fragments.contains(&u.as_str()) || u == callee_desc {
            return true;
        }
        param_names.contains(&u.as_str())
    })
}

/// Check if the source bytes at a given span contain a redirect call whose
/// argument starts with a path prefix (`/...`), indicating a server-relative
/// path rather than an attacker-controlled URL.
///
/// Reused by both `cfg-unguarded-sink` suppression and taint finding filtering.
pub(crate) fn has_redirect_path_prefix(source_bytes: &[u8], span: (usize, usize)) -> bool {
    let (start, end) = span;
    if start >= source_bytes.len() || end > source_bytes.len() {
        return false;
    }
    let text = &source_bytes[start..end];
    // Search for the argument portion after the first '('
    if let Some(paren_pos) = text.iter().position(|&b| b == b'(') {
        let after_paren = &text[paren_pos + 1..];
        let trimmed = after_paren
            .iter()
            .skip_while(|&&b| b == b' ' || b == b'\n' || b == b'\t')
            .copied()
            .collect::<Vec<_>>();
        // Template literal: `/ ...
        if trimmed.starts_with(b"`/") {
            return true;
        }
        // String literal: "/ ... or '/ ...
        if trimmed.starts_with(b"\"/") || trimmed.starts_with(b"'/") {
            return true;
        }
    }
    false
}

/// Check if this sink is an internal redirect, a `res.redirect` (SSRF sink)
/// whose argument is a template literal or string starting with `/`, indicating
/// a server-relative path rather than an attacker-controlled URL.
fn is_internal_redirect(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.contains(Cap::SSRF) {
        return false;
    }
    let sink_info = &ctx.cfg[sink];
    let callee = match &sink_info.call.callee {
        Some(c) => c.as_str(),
        None => return false,
    };
    // Only applies to redirect calls
    if !callee.ends_with("redirect") && !callee.ends_with("Redirect") {
        return false;
    }
    has_redirect_path_prefix(ctx.source_bytes, sink_info.ast.span)
}

/// Check if the enclosing function qualifies as an entrypoint.
fn sink_in_entrypoint(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    if let Some(func_name) = &sink_info.ast.enclosing_func {
        is_entry_point_func(func_name, ctx.lang)
    } else {
        false
    }
}

impl CfgAnalysis for UnguardedSink {
    fn name(&self) -> &'static str {
        "unguarded-sink"
    }

    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let doms = dominators::compute_dominators(ctx.cfg, ctx.entry);
        let sink_nodes = dominators::find_sink_nodes(ctx.cfg);
        let guard_nodes = find_guard_nodes(ctx);

        let mut findings = Vec::new();

        for sink in &sink_nodes {
            let sink_info = &ctx.cfg[*sink];
            let sink_caps = sink_info.taint.labels.iter().fold(Cap::empty(), |acc, l| {
                if let DataLabel::Sink(caps) = l {
                    acc | *caps
                } else {
                    acc
                }
            });
            if sink_caps.is_empty() {
                continue;
            }

            let sink_func = sink_info.ast.enclosing_func.as_deref();

            // Check: does any applicable guard dominate this sink?
            // Guards must be in the same function to be relevant.
            let is_guarded = guard_nodes.iter().any(|(guard_idx, guard_caps)| {
                let guard_func = ctx.cfg[*guard_idx].ast.enclosing_func.as_deref();
                (*guard_caps & sink_caps) != Cap::empty()
                    && guard_func == sink_func
                    && dominates(&doms, *guard_idx, *sink)
            });

            // Also check if an inline sanitizer dominates this sink (same function).
            let has_sanitizer = ctx.cfg.node_indices().any(|idx| {
                let node_func = ctx.cfg[idx].ast.enclosing_func.as_deref();
                ctx.cfg[idx].taint.labels.iter().any(|l| {
                    if let DataLabel::Sanitizer(san_caps) = l {
                        (*san_caps & sink_caps) != Cap::empty()
                            && node_func == sink_func
                            && dominates(&doms, idx, *sink)
                    } else {
                        false
                    }
                })
            });

            // Interprocedural sanitizer: check if any arg_callee resolves to a
            // function with sanitizer caps that cover this sink's caps.
            let has_interprocedural_sanitizer = sink_info.arg_callees.iter().any(|mc| {
                if let Some(callee) = mc {
                    let leaf = callee_leaf_name(callee);
                    // Check local function summaries
                    ctx.func_summaries.iter().any(|(k, s)| {
                        k.name == leaf && (s.sanitizer_caps & sink_caps) != Cap::empty()
                    })
                } else {
                    false
                }
            });

            if is_guarded || has_sanitizer || has_interprocedural_sanitizer {
                continue;
            }

            let callee_desc = sink_info.call.callee.as_deref().unwrap_or("(unknown sink)");

            // ── Severity classification ───────────────────────────────
            //
            // HIGH: taint confirms flow OR source directly feeds sink
            // MEDIUM: structural finding without taint confirmation
            // LOW: wrapper function (param-only, non-entrypoint)

            let has_taint = taint_confirms_sink(ctx, *sink);
            let source_derived = sink_arg_is_source_derived(ctx, *sink);

            // If sink args are all constants (including one-hop constant bindings)
            // and taint didn't confirm, this is a false positive, skip it.
            if is_all_args_constant(ctx, *sink) && !has_taint {
                continue;
            }

            // SSA latest-def suppression: when the taint engine has already
            // proved no source-tainted data reaches this sink (`!has_taint`)
            // and every SSA operand resolves to a constant, callee-fragment
            // pseudo-name, OR a function parameter that is not a Source ,
            // the sink's actual arguments cannot carry an injection payload.
            // Catches the reassign-to-constant idiom (`name := req.x; name =
            // "Guest"; sink(name)`) where the latest SSA def is a literal
            // and a non-payload parameter (e.g. an HTTP writer / receiver)
            // is the only other operand.  The simpler `is_all_args_constant`
            // check above rejects that mixed shape because it forbids real
            // parameters in operand position.
            //
            // Exemption: shell-array gate filters.  The
            // `extract_shell_array_payload_idents` detector recognises
            // `[<shell>, "-c", <payload>]` arrays at any call site and emits a
            // `Sink(SHELL_ESCAPE)` label with `destination_uses` narrowed to
            // the payload-element idents.  When the array shape itself is the
            // gate, an unrelated reassign-to-const elsewhere in the body
            // (`const flag = true; if (flag) {}`) does not erase the
            // shell-exec intent — the construction of `[bash, -c, x]` is by
            // itself the dangerous operation.  Skip this suppression so the
            // structural finding survives in closed-world contexts where no
            // taint source has been resolved yet.
            let has_shell_array_gate = sink_info.call.gate_filters.iter().any(|gf| {
                gf.label_caps.contains(Cap::SHELL_ESCAPE) && gf.destination_uses.is_some()
            });
            if !has_taint
                && !has_shell_array_gate
                && ssa_all_sink_operands_const_or_param(ctx, *sink)
            {
                continue;
            }

            // Type-aware suppression: when all SSA operand values of the sink
            // are proven to carry non-injectable types (e.g. integers parsed
            // from a raw source), the arguments cannot form a payload for
            // SHELL/SQL/FILE sinks.  Skip the structural finding, the taint
            // engine already covers the source→sink flow via type-aware
            // suppression.  Unknown-typed or mixed operands fall through.
            if !has_taint && sink_args_typed_safe(ctx, *sink, sink_caps) {
                continue;
            }

            // JPA / Hibernate Criteria-query suppression: receiver-call SQL
            // sinks like `session.createQuery(cq)` / `em.executeUpdate(cq)`
            // are safe by construction when arg 0 is a structural Criteria
            // object built via `CriteriaBuilder` (returns parameterized
            // SQL).  Receiver excluded from the check, the receiver is
            // never the payload.  Closes openmrs / xwiki / keycloak
            // Hibernate-DAO FP cluster.
            if !has_taint && sink_args_jpa_criteria_query_safe(ctx, *sink, sink_caps) {
                continue;
            }

            // Zero-arg query-builder verbs: Doctrine DBAL `QueryBuilder`,
            // JPA `CriteriaBuilder`, and similar chain-builder shapes
            // execute a query that was bound earlier on the receiver via
            // parameterised API calls.  No SQL string is concatenated at
            // the terminal call site.  Closes the nextcloud apps/dav and
            // lib/private/DB cluster (`$qb->executeQuery()` /
            // `$qb->executeStatement()` after `select`/`from`/`where`/
            // `setParameter` chains).
            if !has_taint && sink_is_zero_arg_query_builder(ctx, *sink, sink_caps) {
                continue;
            }

            // Builder.getSQL() arg suppression: the dangerous flat shape is
            // `$conn->executeStatement($sql)` where `$sql` is user-controlled
            // SQL.  When `$sql` is itself the return of `<builder>.getSQL()`,
            // the SQL is parameterised by construction (Doctrine DBAL),
            // independent of which receiver fires the terminal verb.
            if !has_taint && sink_first_arg_is_builder_get_sql(ctx, *sink, sink_caps) {
                continue;
            }

            // Composition: `<builder>.getSQL()` wrapped by string-shaping ops
            // (`preg_replace('/^INSERT/i', 'INSERT IGNORE', $b->getSQL())`,
            // `$b->getSQL() . ' ON CONFLICT DO NOTHING'`).  Closes the
            // remaining nextcloud `AdapterMySQL.php` / `AdapterSqlite.php`
            // FPs after the direct accessor recognition above.
            if !has_taint && sink_first_arg_composes_safe_dbal_sql(ctx, *sink, sink_caps) {
                continue;
            }

            // PHP foreach-key string interpolation: arg-0 is a SQL string
            // whose interpolated `$<var>` is bound by a `foreach ($X as $var)`
            // (or `as $key => $var`) over a literal-keyed array assigned
            // earlier in the same function.  The literal set is finite and
            // metachar-free, so the interpolated SQL is bounded.  Closes the
            // nextcloud `lib/private/DB/MySqlTools.php:27` FP.
            if !has_taint && sink_arg_uses_safe_foreach_key(ctx, *sink, sink_caps) {
                continue;
            }

            // Static-map suppression: the SSA value flowing into the sink is
            // proved by the static-HashMap-lookup idiom detector to be a
            // finite set of literals free of shell metacharacters.  Mirrors
            // the SSA-taint finite-domain suppression so both paths agree.
            if !has_taint && sink_args_static_map_safe(ctx, *sink, sink_caps) {
                continue;
            }

            // Summary-validated suppression: when the SSA value flowing into
            // the sink is the return of a callee whose summary records a
            // `validated_params_to_return` covering every propagating
            // parameter, the helper validates its inputs on every taint-
            // carrying return path (regex allowlist, type check, validation
            // call, …).  The SSA taint engine already cleared this flow via
            // `propagate_validated_params_to_return`, so the structural
            // finding is noise.  Closes the patched-counterpart noise for
            // CVE-2026-25544 (Payload `sanitizeValue` → `createJSONQuery`
            // → `db.execute`).
            if !has_taint && sink_args_summary_validated_safe(ctx, *sink) {
                continue;
            }

            // Parameterized SQL queries: arg 0 is a string literal with
            // placeholders ($1, ?, %s, :name) and a params argument exists.
            // These are safe by construction, the driver handles escaping.
            if sink_info.parameterized_query {
                continue;
            }

            // Internal redirects: res.redirect(`/path/...`) with a path-prefix
            // argument are server-relative, not attacker-controlled URLs.
            if is_internal_redirect(ctx, *sink, sink_caps) {
                continue;
            }

            let param_only = sink_arg_is_parameter_only(ctx, *sink);
            let in_entrypoint = sink_in_entrypoint(ctx, *sink);

            let (severity, confidence) = if has_taint || source_derived {
                (Severity::High, Confidence::High)
            } else if param_only && !in_entrypoint {
                // Wrapper function with param-only args, zero signal. Suppress.
                continue;
            } else if !ctx.taint_active {
                // AST-only / cfg-only mode, preserve as LOW (unchanged)
                (Severity::Low, Confidence::Low)
            } else {
                // taint_active=true but found nothing.
                // Keep high-risk sinks (SHELL_ESCAPE, CODE_EXEC, SQL_QUERY, DESERIALIZE)
                // as structural backup. Suppress low-risk sinks (FILE_IO, SSRF, etc.).
                let high_risk =
                    Cap::SHELL_ESCAPE | Cap::CODE_EXEC | Cap::SQL_QUERY | Cap::DESERIALIZE;
                if (sink_caps & high_risk).is_empty() {
                    continue; // FILE_IO, SSRF, FMT_STRING etc. without taint → noise
                }
                // If the function containing the sink has no Source-labeled
                // nodes AND no parameters (through which taint could flow
                // from callers), taint ran and found nothing because there
                // is nothing to find.  Suppress, the structural finding
                // is noise.
                let sink_func = sink_info.ast.enclosing_func.as_deref();
                let has_sources = ctx.cfg.node_indices().any(|n| {
                    let info = &ctx.cfg[n];
                    info.ast.enclosing_func.as_deref() == sink_func
                        && info
                            .taint
                            .labels
                            .iter()
                            .any(|l| matches!(l, DataLabel::Source(_)))
                });
                let has_params = ctx.func_summaries.values().any(|s| {
                    s.entry.index() < ctx.cfg.node_count()
                        && ctx.cfg[s.entry].ast.enclosing_func.as_deref() == sink_func
                        && !s.param_names.is_empty()
                });
                if !has_sources && !has_params {
                    continue; // No sources or params in scope → noise
                }
                (Severity::Medium, Confidence::Medium)
            };

            findings.push(CfgFinding {
                rule_id: "cfg-unguarded-sink".to_string(),
                title: "Unguarded sink".to_string(),
                severity,
                confidence,
                span: sink_info.ast.span,
                message: format!("Sink `{callee_desc}` has no dominating guard or sanitizer"),
                evidence: vec![*sink],
                score: None,
            });
        }

        findings
    }
}

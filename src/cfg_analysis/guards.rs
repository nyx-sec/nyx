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
use crate::ssa::type_facts::TypeFactResult;
use crate::ssa::{SsaOp, SsaValue};
use crate::taint::path_state::{PredicateKind, classify_condition};
use petgraph::graph::NodeIndex;
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

    // Check if ALL sink uses are parameters
    sink_uses.iter().all(|u| param_names.contains(&u.as_str()))
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

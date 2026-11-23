//! Unguarded-sink detection via CFG dominator analysis.
//!
//! Flags dangerous sinks that are not dominated by an appropriate guard
//! (validation or auth check) on every path from an entry point.

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
use crate::symbol::Lang;
use crate::taint::path_state::{PredicateKind, classify_condition};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::HashSet;

pub struct UnguardedSink;

/// True when this CFG node introduces untrusted data into the structural
/// analysis.
///
/// A [`DataLabel::Source`] label is the base signal, minus the hardcoded
/// network-fetch exemption the SSA taint engine already applies
/// (`file_get_contents("https://api.example.com/health")`): a network-fetch
/// primitive is a source only because it reaches out over the network, so
/// when its endpoint is pinned by a literal URL the response is
/// developer-chosen and the result is as constant as the URL that produced
/// it.  Without the mirror the taint engine stays silent on such a flow
/// while the structural rule still treats the fetch result as a source,
/// which both defeats the constant-argument suppressions below and promotes
/// the finding to High via `sink_arg_is_source_derived`.
fn node_introduces_untrusted_data(info: &crate::cfg::NodeInfo) -> bool {
    info.taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Source(_)))
        && !crate::taint::ssa_transfer::node_is_hardcoded_network_fetch_source(info)
}

/// Check whether **all** arguments to the sink are constants (no taint-capable
/// variable flows).  Extends the inline callee-part check by tracing one hop
/// through the CFG: if a used variable is defined by a node that itself has
/// empty `uses` and no Source label, the definition is treated as a constant
/// binding (e.g. `let cmd = "git"; Command::new(cmd)`).  When SSA
/// [`BodyConstFacts`] are available, falls back to walking the sink's
/// `SsaOp::Call` operands and consulting `OptimizeResult.const_values` for
/// any operand the syntactic trace can't classify (e.g. a chained method-call
/// receiver recorded as a compound identifier rather than a named binding).
pub(super) fn is_all_args_constant(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
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
                if info.taint.uses.is_empty() && !node_introduces_untrusted_data(info) {
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
        // File-scope constant the body neither assigns nor shadows with a
        // parameter (`const CMD = 'ls'` at module level).
        ident_bound_to_constant(ctx, sink_func, u)
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
        ssa_operand_constant(v, facts, ctx.cfg, callee_desc, callee_parts, outer_parts)
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

/// Suppress a `cfg-unguarded-sink` finding when the sink restricts its
/// injection payload to specific argument positions (`sink_payload_args`)
/// and every operand at those positions resolves to a concrete constant.
///
/// The flat [`is_all_args_constant`] check inspects *every* operand, so a
/// safe parameterised call like Go's
/// `db.QueryContext(context.Background(), "SELECT … $1", bind)` is wrongly
/// rejected: only arg 1 (the SQL string, `payload_args = [1]`) can carry an
/// injection, yet the non-payload `context.Background()` call and the
/// positional bind value are non-constant operands that defeat the
/// all-operands test.  The taint engine already honours the payload-arg
/// gate (no `taint-unsanitised-flow` fires), so under `!has_taint` a sink
/// whose payload positions are all literals is safe by construction.
fn sink_payload_args_const(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let payload_positions = match &ctx.cfg[sink].call.sink_payload_args {
        Some(p) if !p.is_empty() => p,
        _ => return false,
    };
    let Some(facts) = ctx.body_const_facts else {
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
    // Every payload-position operand must resolve to a concrete literal.  A
    // payload position outside the call's positional arguments cannot be
    // proven safe, except in Go (see `payload_position_absent`).  The SSA
    // argument list can end with an implicit-uses group, so the positional
    // arity comes from the CFG node.
    let arity = ctx.cfg[sink].call.arg_uses.len();
    payload_positions.iter().all(|&pos| match args.get(pos) {
        _ if payload_position_absent(ctx.lang, pos, arity) => true,
        Some(group) => group.iter().all(|v| {
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
        None => false,
    })
}

/// True when a gated sink's payload position lies past the end of the call's
/// positional arguments and so cannot carry anything.  Only Go qualifies: it
/// has no keyword arguments, and a spread `xs...` is always the last
/// positional argument, so it sits at a position the check already covers.
/// Variadic sinks (`exec.CommandContext(ctx, name, args...)`) list more
/// payload positions than a typical call passes.  Elsewhere a short
/// positional list can hide a keyword or splat payload, so the position
/// stays unproven.
fn payload_position_absent(lang: Lang, pos: usize, arity: usize) -> bool {
    lang == Lang::Go && arity > 0 && pos >= arity
}

/// CFG-syntactic variant of [`sink_payload_args_const`]: suppress a
/// `cfg-unguarded-sink` finding when every operand at the sink's
/// `sink_payload_args` positions is a constant literal recorded on the call
/// node at CFG-build time (`arg_string_literals`).
///
/// Unlike the SSA-backed [`sink_payload_args_const`], this reads the
/// per-argument literals captured directly from the AST during CFG
/// construction, so it holds even when the sink lives inside a nested callback
/// body whose statements the per-function SSA const-facts do not cover.  This
/// is the dominant real-repo shape for raw-SQL migrations (outline
/// `server/migrations/*.js`):
///
/// ```text
/// queryInterface.sequelize.transaction(async (transaction) => {
///   queryInterface.sequelize.query(`ALTER TABLE …`, { transaction });
/// });
/// ```
///
/// The SQL template (payload arg 0) is a constant, but the sink node is inside
/// the arrow callback, so `sink_payload_args_const` cannot find its SSA `Call`
/// inst, and the `{ transaction }` options object (arg 1) defeats the
/// whole-call `is_all_args_constant`.  A constant payload provably carries no
/// injection regardless of the non-payload options object, so this is sound
/// independent of `has_taint`.
/// Return true when every payload position of a sink call resolves to a
/// captured constant string literal.
///
/// `payload_args = Some(non-empty)` (a gated sink, e.g. `sequelize.query` with
/// `payload_args = [0]`): each listed position must be a `Some(literal)`.
/// `payload_args = None`/empty (an unrestricted sink, every argument is a
/// payload): every recorded argument must be a `Some(literal)` — mirroring
/// `is_all_args_constant` — and there must be at least one recorded argument
/// (an empty list is unproven → not suppressed).
pub(crate) fn payload_positions_all_literal(
    payload_args: &Option<Vec<usize>>,
    lits: &[Option<String>],
) -> bool {
    match payload_args {
        Some(p) if !p.is_empty() => p.iter().all(|&pos| matches!(lits.get(pos), Some(Some(_)))),
        _ => !lits.is_empty() && lits.iter().all(|l| l.is_some()),
    }
}

pub(super) fn sink_payload_args_syntactic_const(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let info = &ctx.cfg[sink];

    // Hoisted-callback sink: the `Sink` label on this wrapper node was hoisted
    // from an inner call nested inside a callback-argument function literal
    // (`sequelize.transaction(async (t) => { sequelize.query(`…const…`, {t}) })`).
    // The wrapper's own arguments are the callback, not the SQL payload, so the
    // syntactic-const check below (keyed on the wrapper's `sink_payload_args` /
    // `arg_string_literals`) can never see the constant.  Consult the recorded
    // INNER sink call's payload positions + literals instead.  Sound regardless
    // of `has_taint`: a syntactic literal at the inner payload position cannot
    // carry taint, and a tainted inner payload leaves that position non-literal
    // so the wrapper finding still fires.  (The inner sink call also has its own
    // CFG node in the nested-callback body, so real detection is never lost.)
    if let Some(h) = &info.call.hoisted_sink {
        return payload_positions_all_literal(&h.payload_args, &h.arg_string_literals);
    }

    let payload_positions = match &info.call.sink_payload_args {
        Some(p) if !p.is_empty() => p,
        _ => return false,
    };
    // Only trust the syntactic literals when the sink's callee identity was
    // NOT overridden by an inner-nested / chained-call rebind.  When
    // `outer_callee` is set (e.g. `http.get(target, cb).on('error', cb2)`,
    // where the SSRF sink is rebound to the inner `http.get` but the node's
    // `arg_string_literals` still reflect the outer `.on('error', …)` call),
    // `sink_payload_args` and `arg_string_literals` come from DIFFERENT call
    // nodes and are no longer positionally aligned — the `'error'` string
    // literal at the `.on` arg 0 would masquerade as a constant SSRF payload.
    // A direct raw-SQL sink (`sequelize.query(`…`, opts)`) has no override, so
    // this preserves the migration suppression while refusing the misaligned
    // rebind case.
    if info
        .call
        .outer_callee
        .as_deref()
        .is_some_and(|outer| info.call.callee.as_deref() != Some(outer))
    {
        return false;
    }
    // Destination-narrowed gates whose object-literal destination fields hold
    // no identifier (`pool.query({ text: 'SELECT ... $1', values: [id] })`,
    // Apollo `client.query({ query, variables })`, which has no SQL text field
    // at all) read nothing at their payload positions.  Every sink cap on the
    // node must belong to such a gate.
    let filters = &info.call.gate_filters;
    if !filters.is_empty()
        && filters
            .iter()
            .all(|f| f.destination_uses.as_ref().is_some_and(|u| u.is_empty()))
    {
        let gated = filters
            .iter()
            .fold(crate::labels::Cap::empty(), |acc, f| acc | f.label_caps);
        let sink_caps =
            info.taint
                .labels
                .iter()
                .fold(crate::labels::Cap::empty(), |acc, l| match l {
                    crate::labels::DataLabel::Sink(c) => acc | *c,
                    _ => acc,
                });
        if gated.contains(sink_caps) {
            return true;
        }
    }
    // `arg_string_literals` is aligned with positional arguments (keyword /
    // named args are skipped during extraction), matching the positional
    // indices carried in `sink_payload_args`.  Every payload position must
    // resolve to a captured literal; a position outside the recorded arg list
    // (empty vec on splat args, arity mismatch) is left unproven → not
    // suppressed.
    //
    // A payload argument built only from file-level constants
    // (`cur.execute(BASE_Q + " WHERE id = ?", (uid,))`, with `BASE_Q` a
    // module-level string) is constant too: its only identifiers are in the
    // file's constant scalar table, which the per-function CFG cannot see.
    let lits = &info.call.arg_string_literals;
    let arg_uses = &info.call.arg_uses;
    payload_positions.iter().all(|&pos| match lits.get(pos) {
        Some(Some(_)) => true,
        Some(None) => ctx.class_constant_scalars.is_some_and(|consts| {
            arg_uses
                .get(pos)
                .is_some_and(|uses| !uses.is_empty() && uses.iter().all(|u| consts.contains_key(u)))
        }),
        None => payload_position_absent(ctx.lang, pos, lits.len()),
    })
}

/// True when the base argument of a URL builder call is an absolute URL
/// (`scheme://host`) given either as a string literal at the call or as a
/// local whose every definition in the function is such a literal
/// (`const base = "https://api.example.com"; new URL(path, base)`).
fn builder_base_is_absolute_literal(
    ctx: &AnalysisContext,
    builder: NodeIndex,
    base_idx: usize,
) -> bool {
    let info = &ctx.cfg[builder];
    let pins_origin = |base: &str| {
        crate::abstract_interp::string_domain::prefix_locks_origin(&format!(
            "{}/",
            base.trim_end_matches('/')
        ))
    };
    if let Some(lit) = info
        .call
        .arg_string_literals
        .get(base_idx)
        .and_then(|s| s.as_deref())
    {
        return pins_origin(lit);
    }
    let Some([name]) = info.call.arg_uses.get(base_idx).map(|u| u.as_slice()) else {
        return false;
    };
    let func = info.ast.enclosing_func.as_deref();
    let defs: Vec<NodeIndex> = ctx
        .cfg
        .node_indices()
        .filter(|&i| {
            ctx.cfg[i].taint.defines.as_deref() == Some(name.as_str())
                && ctx.cfg[i].ast.enclosing_func.as_deref() == func
        })
        .collect();
    let all_literal = defs.iter().all(|&i| {
        ctx.cfg[i].taint.const_text.as_deref().is_some_and(|text| {
            let t = text.trim();
            t.len() >= 2
                && matches!(t.as_bytes()[0], b'"' | b'\'' | b'`')
                && t.as_bytes()[0] == t.as_bytes()[t.len() - 1]
                && pins_origin(&t[1..t.len() - 1])
        })
    });
    all_literal && defs_cover_every_path(ctx, &defs, builder)
}

/// True when every path from the entry to `use_node` passes through one of
/// `defs`.  A name that is also a parameter, or that is only re-bound under a
/// condition (`if (!url) { url = "https://h/" + id }`), has a path on which
/// the caller's value reaches the use without meeting a definition, so an
/// "every definition is locked" check proves nothing without this.
fn defs_cover_every_path(ctx: &AnalysisContext, defs: &[NodeIndex], use_node: NodeIndex) -> bool {
    if defs.is_empty() {
        return false;
    }
    let blocked: HashSet<NodeIndex> = defs.iter().copied().collect();
    if blocked.contains(&ctx.entry) {
        return true;
    }
    let mut seen: HashSet<NodeIndex> = HashSet::new();
    let mut stack = vec![ctx.entry];
    while let Some(n) = stack.pop() {
        if n == use_node {
            return false;
        }
        if !seen.insert(n) {
            continue;
        }
        stack.extend(ctx.cfg.neighbors(n).filter(|m| !blocked.contains(m)));
    }
    true
}

/// Suppress a `cfg-unguarded-sink` SSRF finding when the sink's URL operand
/// is origin-locked: it is the result of a `new URL(path, base)` /
/// `urljoin(base, path)` / `url.JoinPath(base, …)` builder whose base
/// argument pins the scheme+host, so the (attacker-controlled) path
/// component cannot redirect the request off the locked origin.
///
/// Mirrors the taint engine's `StringFact::from_url_with_base` prefix-lock
/// (`url_builder_arg_indices` + `is_string_safe_for_ssrf`): the taint engine
/// stays silent on this shape, so the parallel structural finding is a false
/// positive.  Like the taint side, a resolving builder (everything except Go
/// `JoinPath`) locks only when the path argument is provably a relative
/// reference.  The base is recognised as either a string literal recorded on
/// the builder node (`arg_string_literals[base_idx]`) or a const-bound
/// identifier whose SSA operand resolves to a concrete string.
fn sink_url_origin_locked(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.contains(Cap::SSRF) {
        return false;
    }
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.ast.enclosing_func.as_deref();
    // CFG one-hop trace (mirrors `is_all_args_constant`): the SSA
    // `cfg_node_map` only covers the body whose facts are attached to `ctx`,
    // so for a sink inside a nested function (e.g. an Express arrow handler)
    // the SSA path misses it.  Walk the CFG instead: for every variable the
    // sink uses, find its defining node in the same function and test whether
    // that definition is an origin-locking URL builder.
    sink_info.taint.uses.iter().any(|u| {
        ctx.cfg.node_indices().any(|idx| {
            let info = &ctx.cfg[idx];
            if info.ast.enclosing_func.as_deref() != sink_func {
                return false;
            }
            if info.taint.defines.as_deref() != Some(u.as_str()) {
                return false;
            }
            // `info` defines `u`.  Is it `new URL(path, base)` / `urljoin` /
            // `JoinPath` with a string-literal base pinning scheme+host?
            let Some(callee) = info.call.callee.as_deref() else {
                return false;
            };
            let Some((path_idx, base_idx)) = crate::ssa::type_facts::url_builder_arg_indices(
                ctx.lang,
                callee,
                info.call.outer_callee.as_deref(),
                info.call.is_constructor,
            ) else {
                return false;
            };
            if !builder_base_is_absolute_literal(ctx, idx, base_idx) {
                return false;
            }
            if crate::ssa::type_facts::url_builder_appends_path(ctx.lang) {
                return true;
            }
            // Reference resolution: the base's host survives only a path
            // that is provably a relative reference, so a bare tainted path
            // (`new URL(req.query.p, BASE)`) stays unlocked.
            use crate::abstract_interp::string_domain::{
                exact_is_host_preserving_reference, prefix_is_host_preserving_reference,
            };
            match info
                .call
                .arg_string_literals
                .get(path_idx)
                .and_then(|s| s.as_deref())
            {
                Some(lit) => exact_is_host_preserving_reference(lit),
                None => info
                    .call
                    .arg_string_prefixes
                    .get(path_idx)
                    .and_then(|s| s.as_deref())
                    .is_some_and(prefix_is_host_preserving_reference),
            }
        })
    })
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
            .map(node_introduces_untrusted_data)
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
    cfg: &crate::cfg::Cfg,
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
        // CFG-node-level Source label: a `SsaOp::Call` can be the lowering
        // of a Source-labeled CFG node (`file_get_contents`, `env::var`,
        // `readline`, …).  Such a call's result is tainted user input, not a
        // constant, even when its own arguments are constant (or it is a
        // zero-arg source).  Mirror the refusal in the sibling
        // `ssa_operand_const_or_param` so a source-fed sink is never proven
        // "all args constant" and silently dropped.
        let cfg_node = inst.cfg_node;
        if cfg
            .node_weight(cfg_node)
            .map(node_introduces_untrusted_data)
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

/// True when every real operand of the sink call is a number the language
/// produced by a numeric cast or arithmetic assignment (PHP `$pid = (int)
/// $raw;`).  The taint engine clears all capabilities at such an assignment
/// (`NodeInfo::yields_number`), so the structural rule must not keep
/// treating the variable as source-derived through its earlier definition:
/// `passthru('kill -9 ' . $pid)` after `$pid = (int) fread(..)`.
///
/// Reads the SSA definition chain, so a cast on only one path (a phi with a
/// non-numeric operand) does not count.
fn sink_args_numeric_assigned(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
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

    fn numeric(ctx: &AnalysisContext, ssa: &crate::ssa::SsaBody, v: SsaValue, depth: u8) -> bool {
        if depth > 8 {
            return false;
        }
        let Some(def) = find_inst(ssa, v) else {
            return false;
        };
        match &def.op {
            SsaOp::Phi(ops) => ops.iter().all(|(_, o)| numeric(ctx, ssa, *o, depth + 1)),
            SsaOp::Const(_) => true,
            _ => ctx.cfg[def.cfg_node].yields_number,
        }
    }

    let mut saw_cast = false;
    let mut check = |v: SsaValue| -> bool {
        let Some(def) = find_inst(&facts.ssa, v) else {
            return true;
        };
        match &def.op {
            SsaOp::Const(_) => return true,
            SsaOp::Param { .. } => {
                let name = def.var_name.as_deref().unwrap_or("");
                if is_callee_fragment(name, callee_desc, &callee_parts, &outer_parts) {
                    return true;
                }
            }
            _ => {}
        }
        if numeric(ctx, &facts.ssa, v, 0) {
            saw_cast = true;
            true
        } else {
            false
        }
    };
    if let Some(r) = receiver
        && !check(*r)
    {
        return false;
    }
    for group in args {
        for v in group.iter() {
            if !check(*v) {
                return false;
            }
        }
    }
    saw_cast
}

/// Whether the file defines a class deriving from `ActiveRecord::Migration`.
fn source_declares_rails_migration(src: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"ActiveRecord::Migration";
    src.windows(NEEDLE.len()).any(|w| w == NEEDLE)
}

/// Whether the sink sits in a block, lambda or other anonymous function body.
fn sink_in_closure(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    ctx.cfg[sink]
        .ast
        .enclosing_func
        .as_deref()
        .is_some_and(crate::cfg::is_anon_fn_name)
        || !ctx.captured_params.is_empty()
}

/// Whether any identifier the sink reads is a parameter in scope, or a local assigned from an expression that reads one.
/// Closure over the body's assignments, so `o = [a, opts[:x]]; q.order(o)`
/// reaches `opts` while `q.order(sort_clause)` does not.
fn sink_operands_reach_param(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.ast.enclosing_func.as_deref();
    let mut reach: HashSet<&str> = ctx.scope_param_names().collect();
    if reach.is_empty() {
        return false;
    }
    loop {
        let before = reach.len();
        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];
            if info.ast.enclosing_func.as_deref() != sink_func {
                continue;
            }
            if !info.taint.uses.iter().any(|u| reach.contains(u.as_str())) {
                continue;
            }
            if let Some(d) = info.taint.defines.as_deref() {
                reach.insert(d);
            }
            for d in &info.taint.extra_defines {
                reach.insert(d.as_str());
            }
        }
        if reach.len() == before {
            break;
        }
    }
    sink_info
        .taint
        .uses
        .iter()
        .any(|u| reach.contains(u.as_str()))
}

/// Suppress a Go `cfg-unguarded-sink` reflected-XSS finding on
/// `fmt.Fprint*` / `io.WriteString` when the writer (positional arg 0) is
/// provably not an `http.ResponseWriter`: an in-memory `*bytes.Buffer`, an
/// `*os.File`, a `bufio.Writer`, an `io.Writer` parameter, and similar
/// non-response byte sinks.  (`os.Stderr` and typed writer formals lose the
/// sink label at CFG construction.)
///
/// Mirrors the SSA taint engine's Go printf writer gate
/// ([`crate::ssa::type_facts::go_writer_is_non_response`]) so the two rules
/// agree: the taint engine already strips `HTML_ESCAPE` when the writer is a
/// non-response type, which leaves the sink unconfirmed (`!has_taint`) and
/// re-opens the structural finding on the identical call.  gitea
/// `models/unittest/mock_http.go:103` (`fmt.Fprintf(out, "%s: %s\n", …)`
/// where `out := os.Create(…)`) and `temp_repo.go:152`
/// (`fmt.Fprintf(stdIn, …)` where `stdIn := new(bytes.Buffer)`) are the
/// motivating shapes.
fn go_fprintf_writer_non_response(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    if !sink_caps.contains(Cap::HTML_ESCAPE) {
        return false;
    }
    let sink_info = &ctx.cfg[sink];
    let callee = sink_info.call.callee.as_deref().unwrap_or("");
    if !crate::ssa::type_facts::is_go_writer_sink_callee(callee) {
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
    let Some(&first_val) = args.first().and_then(|g| g.first()) else {
        return false;
    };
    type_facts
        .get_type(first_val)
        .is_some_and(crate::ssa::type_facts::go_writer_is_non_response)
}

/// True when every cap on the sink is response-only and the call's receiver is
/// declared as a type that cannot be an HTTP response
/// ([`crate::cfg::NodeInfo::call`] `receiver_decl_type`).  Mirrors the taint
/// engine's declared-receiver strip so the structural rule agrees with it.
fn java_receiver_declared_non_response(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    sink_caps: Cap,
) -> bool {
    ctx.cfg[sink]
        .call
        .receiver_decl_type
        .as_ref()
        .is_some_and(|kind| {
            crate::taint::ssa_transfer::receiver_incompatible_sink_caps(kind, sink_caps)
                .contains(sink_caps)
        })
}

/// Suppress a `cfg-unguarded-sink` finding when every real argument to the
/// sink is a value-use identifier proven *numeric-confined* by the CFG-level
/// AST walk ([`crate::cfg::NodeInfo::numeric_confined_uses`]): each occurrence
/// of the identifier in the sink node is consumed by a numeric / safe-string
/// producer (`x.parse::<u16>().unwrap().to_string()`, `parseInt(x)`, …), so it
/// reaches the sink only as a number.  The structural analogue of the SSA
/// taint engine's `numeric_confined_uses` drop, kept in lock-step so both
/// findings paths agree (an inline numeric chain never lowers to its own SSA
/// value, so the value-level `type_facts_suppress` above cannot reach it).
///
/// Gated to fully-type-suppressible sinks (a number can still be an IDOR /
/// `UNAUTHORIZED_ID` payload, so confinement must not silence those).
fn sink_args_numeric_confined(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    let type_suppressible = Cap::SQL_QUERY
        | Cap::FILE_IO
        | Cap::SHELL_ESCAPE
        | Cap::HTML_ESCAPE
        | Cap::SSRF
        | Cap::DATA_EXFIL
        | Cap::HEADER_INJECTION
        | Cap::OPEN_REDIRECT;
    if sink_caps.is_empty() || !(sink_caps & !type_suppressible).is_empty() {
        return false;
    }
    let sink_info = &ctx.cfg[sink];
    if sink_info.numeric_confined_uses.is_empty() {
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

    // A "real" arg is a non-constant, non-callee-fragment SSA value.  Its
    // var_name must be listed in `numeric_confined_uses`; otherwise the sink
    // carries an un-confined operand and the finding is preserved.
    let mut saw_real = false;
    let mut all_confined = true;
    let mut check = |v: SsaValue| {
        let Some(def) = find_inst(&facts.ssa, v) else {
            return;
        };
        if matches!(def.op, SsaOp::Const(_)) {
            return;
        }
        let name = def.var_name.as_deref().unwrap_or("");
        if matches!(def.op, SsaOp::Param { .. })
            && (is_callee_fragment(name, callee_desc, &callee_parts, &outer_parts)
                || sink_info
                    .format_macro_method_idents
                    .iter()
                    .any(|m| m == name))
        {
            // Callee receiver-chain fragments and Rust `format!`-macro phantom
            // method/macro-name tokens (`format`, `parse`, `unwrap`) are
            // syntactic machinery flattened into the use set, not real values.
            return;
        }
        saw_real = true;
        if !sink_info.numeric_confined_uses.iter().any(|n| n == name) {
            all_confined = false;
        }
    };
    if let Some(r) = receiver {
        check(*r);
    }
    for group in args {
        for v in group.iter() {
            check(*v);
        }
    }
    saw_real && all_confined
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
    // Restrict to PHP.  On Java the zero-arg `pstmt.executeUpdate()` /
    // `pstmt.executeQuery()` has only its receiver as an operand, which
    // `is_all_args_constant` already treats as part of the callee, and
    // the chained literal shape gets a synthesized sanitizer at CFG
    // build.  PHP's Doctrine DBAL `QueryBuilder`
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
    let is_builder_verb = matches!(suffix, "executeQuery" | "executeStatement" | "createQuery");
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
    let is_builder_receiver_by_def = receiver_defined_by_builder_factory(ctx, sink, root_receiver);
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
    name.starts_with("get") && name.len() > 5 && name.ends_with("SQL")
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
fn sink_arg_uses_safe_foreach_key(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
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
fn enclosing_func_byte_scope(ctx: &AnalysisContext, sink: NodeIndex) -> Option<(usize, usize)> {
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
    if !rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
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
    let needle: Vec<u8> = std::iter::once(b'$').chain(iter_var.bytes()).collect();
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
            b'['
                // Subscript-set: `$X['LIT'] = 'LIT';`
                if !php_check_subscript_set(scope, p, used_as_key, used_as_val) =>
            {
                return false;
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
    !used_as_val || is_metachar_free_string_literal(rhs.trim_ascii())
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
    let needle: Vec<u8> = std::iter::once(b'$').chain(name.bytes()).collect();
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
        if cursor < scope.len()
            && scope[cursor] == b'='
            && (cursor + 1 == scope.len() || scope[cursor + 1] != b'=')
        {
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
    haystack.windows(needle.len()).position(|w| w == needle)
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
    let global = ctx.global_summaries;
    if local_map.is_none() && global.is_none() {
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
        if matches.is_empty()
            && let Some(g) = global
        {
            matches.extend(g.ssa_named(leaf));
            if callee_text != leaf {
                matches.extend(g.ssa_named(callee_text));
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

/// Behaviour-based path-confinement guard recognition for
/// `cfg-unguarded-sink`.
///
/// Returns `true` when the `if`-condition gates on a helper whose SSA
/// summary records a constant-prefix path-confinement predicate
/// ([`crate::summary::ssa_summary::SsaFuncSummary::confines_path_params`]),
/// mirroring the taint engine's `apply_summary_confinement_narrowing` so the
/// structural and taint layers agree on this validator shape.  Recognises
/// both the inline (`if (!isOptimizedDepFile(p))`) and two-statement
/// (`const ok = isOptimizedDepFile(p); if (!ok)`) forms.  The caller scopes
/// the registered guard to `Cap::FILE_IO`, matching the confinement
/// semantics.
///
/// Name-based confinement helpers (`isValid…` / `isSafe…`) are already
/// recognised via [`classify_condition`] / [`cond_indirect_validator_callee`];
/// this closes the gap for behaviour-recognised helpers whose names carry no
/// validator marker.  Motivated by CVE-2026-39365 (Vite sourcemap traversal).
fn cond_confinement_helper(info: &crate::cfg::NodeInfo, ctx: &AnalysisContext) -> bool {
    let Some(ssa_summaries) = ctx.ssa_summaries else {
        return false;
    };
    let confines = |name: &str| -> bool {
        ssa_summaries.iter().any(|(k, s)| {
            k.lang == ctx.lang && k.name == name && !s.confines_path_params.is_empty()
        })
    };

    // Inline call form: `if (!helper(p))`.
    if let Some(cond_text) = info.condition_text.as_deref()
        && !cond_text.contains("&&")
        && !cond_text.contains("||")
    {
        let trimmed = cond_text.trim_start_matches(['(', '!', ' ', '\t']);
        let trimmed = trimmed.strip_prefix("not ").unwrap_or(trimmed).trim();
        if trimmed.contains('(') {
            let callee_part = trimmed.split('(').next().unwrap_or("");
            let bare = callee_part
                .rsplit(['.', ':'])
                .next()
                .unwrap_or(callee_part)
                .trim();
            if !bare.is_empty() && confines(bare) {
                return true;
            }
        }
    }

    // Two-statement form: condition var is defined by a Call to the helper.
    // Mirrors `cond_indirect_validator_callee`'s CFG scan, gated on the
    // confinement summary instead of the validator-name classifier.
    if info.condition_vars.len() == 1 {
        let var_name = info.condition_vars[0].as_str();
        let cond_func = info.ast.enclosing_func.as_deref();
        let cond_span_start = info.ast.span.0;
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
        if let Some((_, callee)) = best {
            let bare = crate::labels::bare_method_name(callee);
            if confines(bare) {
                return true;
            }
        }
    }

    false
}

/// Whether the `if`-condition at `info` gates a redirect on the result of a
/// recognised relative-URL confiner
/// ([`crate::summary::ssa_summary::SsaFuncSummary::sanitizes_open_redirect_return`]),
/// e.g. `const dest = normalize_relative_url(...); if (dest !== null) res.redirect(dest);`.
///
/// Mirrors the taint layer's OPEN_REDIRECT strip (the `outer_callee`-aware
/// confiner check in `transfer_inst`) so `cfg-unguarded-sink` agrees the
/// redirect is guarded.  The confining call is recorded either as the defining
/// node's `callee` or — when it wraps a nested source expression — as its
/// `outer_callee`.  Scoped by the caller to `Cap::OPEN_REDIRECT`.  Motivated
/// by CVE-2026-42259 (Saltcorn login open redirect).
fn cond_open_redirect_confiner(info: &crate::cfg::NodeInfo, ctx: &AnalysisContext) -> bool {
    let Some(ssa_summaries) = ctx.ssa_summaries else {
        return false;
    };
    let confines = |name: &str| -> bool {
        ssa_summaries
            .iter()
            .any(|(k, s)| k.lang == ctx.lang && k.name == name && s.sanitizes_open_redirect_return)
    };

    // Inline form: `if (helper(x) !== null)` / `if (!helper(x))`.
    if let Some(cond_text) = info.condition_text.as_deref()
        && !cond_text.contains("&&")
        && !cond_text.contains("||")
    {
        let trimmed = cond_text.trim_start_matches(['(', '!', ' ', '\t']);
        if trimmed.contains('(') {
            let callee_part = trimmed.split('(').next().unwrap_or("");
            let bare = callee_part
                .rsplit(['.', ':'])
                .next()
                .unwrap_or(callee_part)
                .trim();
            if !bare.is_empty() && confines(bare) {
                return true;
            }
        }
    }

    // Two-statement form: `const dest = normalize_relative_url(...); if (dest ...)`.
    cond_open_redirect_confiner_two_statement(info, ctx)
}

/// Whether a Call node's argument expression wraps the redirect target in an
/// open-redirect confiner, without an intervening `if` guard, e.g.
/// `return redirect(get_safe_redirect(next_url))` (Flask-AppBuilder
/// CVE-2022-24776).  The wrapper survives in [`CallMeta::arg_uses`] (or, for a
/// `find_classifiable_inner_call` override, `outer_callee`), and its SSA summary
/// records [`SsaFuncSummary::sanitizes_open_redirect_return`].  Mirrors the taint
/// layer's nested-sink OPEN_REDIRECT strip so `cfg-unguarded-sink` agrees the
/// redirect is same-origin.  Registered as a guard on the node itself
/// (dominance is reflexive).
fn call_arg_open_redirect_confiner(info: &crate::cfg::NodeInfo, ctx: &AnalysisContext) -> bool {
    let Some(ssa_summaries) = ctx.ssa_summaries else {
        return false;
    };
    let confines = |name: &str| -> bool {
        ssa_summaries
            .iter()
            .any(|(k, s)| k.lang == ctx.lang && k.name == name && s.sanitizes_open_redirect_return)
    };
    info.call
        .arg_uses
        .iter()
        .flatten()
        .chain(info.call.outer_callee.as_ref())
        .any(|id| confines(crate::labels::bare_method_name(id)))
}

/// Two-statement form of [`cond_open_redirect_confiner`]:
/// `const dest = normalize_relative_url(...); if (dest !== null) res.redirect(dest);`.
fn cond_open_redirect_confiner_two_statement(
    info: &crate::cfg::NodeInfo,
    ctx: &AnalysisContext,
) -> bool {
    let Some(ssa_summaries) = ctx.ssa_summaries else {
        return false;
    };
    let confines = |name: &str| -> bool {
        ssa_summaries
            .iter()
            .any(|(k, s)| k.lang == ctx.lang && k.name == name && s.sanitizes_open_redirect_return)
    };

    if info.condition_vars.len() == 1 {
        let var_name = info.condition_vars[0].as_str();
        let cond_func = info.ast.enclosing_func.as_deref();
        let cond_span_start = info.ast.span.0;
        let mut best: Option<(usize, NodeIndex)> = None;
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
            match best {
                Some((s, _)) if s >= span_start => {}
                _ => best = Some((span_start, nidx)),
            }
        }
        if let Some((_, nidx)) = best {
            let n = &ctx.cfg[nidx];
            let matches = |c: &str| confines(crate::labels::bare_method_name(c));
            if n.call.callee.as_deref().is_some_and(matches)
                || n.call.outer_callee.as_deref().is_some_and(matches)
            {
                return true;
            }
        }
    }

    false
}

/// Match a guard suffix matcher against a callee, requiring the suffix to
/// begin on a *leaf-name boundary* rather than mid-identifier.
///
/// A bare `callee_lower.ends_with(suffix)` over-matches: `invalidate` ends
/// with `validate` (the `Cap::all()` guard) and `unquote` ends with `quote`
/// (the SHELL_ESCAPE guard), so cache-invalidation and URL-decoding calls
/// would register as dominating guards and silently suppress every
/// downstream `cfg-unguarded-sink` in the function.  Require that the
/// character preceding the matched suffix is a name separator (`.`, `_`, or
/// `:` from `::`) or that the suffix sits at the start of the callee.  This
/// mirrors the existing prefix-anchor convention (a trailing `_` on the
/// matcher anchors at the start).
pub(super) fn suffix_matches_at_leaf_boundary(callee_lower: &str, suffix: &str) -> bool {
    if !callee_lower.ends_with(suffix) {
        return false;
    }
    let prefix_len = callee_lower.len() - suffix.len();
    if prefix_len == 0 {
        // Suffix is the whole callee (or its leaf with nothing before it).
        return true;
    }
    // The byte immediately before the suffix must be a leaf-name separator.
    let prev = callee_lower.as_bytes()[prefix_len - 1];
    matches!(prev, b'.' | b'_' | b':')
}

/// Branch conditions that pin one variable to a fixed set of values, with
/// the variables they pin:
///
/// * an equality test against a literal (`dir === 'asc'`, part of a
///   `dir === 'asc' || dir === 'desc'` chain);
/// * the presence result of a Go map lookup (`_, ok := allowed[cmd]; if
///   !ok`), which pins the key and the value binding.
///
/// Unlike [`find_guard_nodes`] these only guard a sink that reads one of the
/// pinned variables, so an unrelated `if (mode === 'debug')` above a sink
/// does not hide it.  The returned node is the first node on the pinning
/// edge (the equal / present side), and only when every way into it is a
/// pinning edge for the same variable: the body of `a === 'x' || a === 'y'`
/// qualifies, the body of `a === 'x' || flag` and the code after
/// `if (a === 'x') log()` do not.
fn find_value_pinning_guards(ctx: &AnalysisContext) -> Vec<(NodeIndex, SmallVec<[String; 2]>)> {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;

    let pins: Vec<(NodeIndex, SmallVec<[String; 2]>, NodeIndex)> = ctx
        .cfg
        .node_indices()
        .filter_map(|idx| {
            let (vars, on_true) = pinned_edge(idx, ctx)?;
            Some((idx, vars, branch_successor(idx, on_true, ctx)?))
        })
        .collect();
    let mut out = Vec::new();
    for (_, vars, succ) in &pins {
        let only_pinned_entries = ctx.cfg.edges_directed(*succ, Direction::Incoming).all(|e| {
            pins.iter().any(|(p, pv, ps)| {
                *p == e.source() && ps == succ && pv.iter().any(|v| vars.contains(v))
            })
        });
        if only_pinned_entries && !out.iter().any(|(n, _)| n == succ) {
            out.push((*succ, vars.clone()));
        }
    }
    out
}

/// The node an `If` node's TRUE (or FALSE) branch starts at.  The builder
/// marks the then-branch with an explicit TRUE edge; the other side is a
/// FALSE edge or, for an `if` without `else`, the plain fall-through to the
/// next statement.  `None` when the other side is ambiguous.
fn branch_successor(cond: NodeIndex, on_true: bool, ctx: &AnalysisContext) -> Option<NodeIndex> {
    use crate::cfg::EdgeKind;
    use petgraph::visit::EdgeRef;
    let target_of = |kind: EdgeKind| {
        ctx.cfg
            .edges(cond)
            .find(|e| *e.weight() == kind)
            .map(|e| e.target())
    };
    let true_succ = target_of(EdgeKind::True);
    if on_true {
        return true_succ;
    }
    if let Some(f) = target_of(EdgeKind::False) {
        return Some(f);
    }
    let mut others = ctx
        .cfg
        .edges(cond)
        .filter(|e| *e.weight() == EdgeKind::Seq)
        .map(|e| e.target())
        .filter(|t| Some(*t) != true_succ);
    let first = others.next()?;
    others.all(|t| t == first).then_some(first)
}

/// The variables an `If` node pins and whether they are pinned on its TRUE
/// branch: the equal side of `x == 'lit'`, the present side of a Go
/// comma-ok lookup.
fn pinned_edge(idx: NodeIndex, ctx: &AnalysisContext) -> Option<(SmallVec<[String; 2]>, bool)> {
    let info = &ctx.cfg[idx];
    if info.kind != StmtKind::If {
        return None;
    }
    let cond_text = info.condition_text.as_deref()?;
    if classify_condition(cond_text) == PredicateKind::Comparison
        && let Some((target, op_is_eq)) =
            crate::taint::path_state::equality_literal_guard(cond_text)
        && info.condition_vars.contains(&target)
    {
        return Some((
            SmallVec::from_elem(target, 1),
            op_is_eq != info.condition_negated,
        ));
    }
    let lookup = cond_membership_lookup(idx, ctx)?;
    let mut vars: SmallVec<[String; 2]> = SmallVec::new();
    vars.push(lookup.key.clone());
    vars.extend(lookup.value_var.clone());
    Some((vars, !info.condition_negated))
}

/// The map lookup whose presence result is this condition's single
/// variable (`ok` in `_, ok := allowed[cmd]; if !ok`).  Same-function
/// definitions textually before the condition, or the `if` statement's own
/// initializer (a direct CFG predecessor inside its span), taking the last
/// one, like [`cond_indirect_validator_callee`].
fn cond_membership_lookup<'c>(
    cond: NodeIndex,
    ctx: &'c AnalysisContext,
) -> Option<&'c crate::cfg::MembershipLookup> {
    let info = &ctx.cfg[cond];
    let [var_name] = info.condition_vars.as_slice() else {
        return None;
    };
    let cond_func = info.ast.enclosing_func.as_deref();
    let mut best: Option<(usize, &crate::cfg::MembershipLookup)> = None;
    for nidx in ctx.cfg.node_indices() {
        let n = &ctx.cfg[nidx];
        let Some(lookup) = n.membership_lookup.as_ref() else {
            continue;
        };
        let before_cond = n.ast.span.0 < info.ast.span.0 || ctx.cfg.find_edge(nidx, cond).is_some();
        if lookup.result_var != *var_name
            || n.ast.enclosing_func.as_deref() != cond_func
            || !before_cond
        {
            continue;
        }
        if best.is_none_or(|(s, _)| n.ast.span.0 > s) {
            best = Some((n.ast.span.0, lookup));
        }
    }
    best.map(|(_, l)| l)
}

/// The node `cond`'s TRUE (or FALSE) branch starts at, when `cond` is its
/// only way in.
fn sole_successor_on_edge(
    cond: NodeIndex,
    on_true: bool,
    ctx: &AnalysisContext,
) -> Option<NodeIndex> {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    let succ = branch_successor(cond, on_true, ctx)?;
    ctx.cfg
        .edges_directed(succ, Direction::Incoming)
        .all(|e| e.source() == cond)
        .then_some(succ)
}

/// True when the `//` test at `cond` has a leading-`/` test on the same
/// value elsewhere in the same function (the other half of the inline
/// relative-URL check).
fn has_leading_slash_partner(cond: NodeIndex, ctx: &AnalysisContext) -> bool {
    use crate::taint::path_state::classify_condition_with_target;
    let info = &ctx.cfg[cond];
    let Some((_, Some(target))) = info
        .condition_text
        .as_deref()
        .map(classify_condition_with_target)
    else {
        return false;
    };
    let func = info.ast.enclosing_func.as_deref();
    ctx.cfg.node_indices().any(|i| {
        let n = &ctx.cfg[i];
        n.kind == StmtKind::If
            && n.ast.enclosing_func.as_deref() == func
            && n.condition_text.as_deref().is_some_and(|t| {
                classify_condition_with_target(t)
                    == (PredicateKind::LeadingSlashCheck, Some(target.clone()))
            })
    })
}

/// `if (u.host === Y)` where `u` was bound by `new URL(..)` in the same
/// function and `Y` is not attacker data.  Returns whether the guarded code
/// sits on the TRUE edge.
///
/// `Y` counts as attacker data when any dotted path in it classifies as a
/// source, or when a variable in it is defined by a source-labelled node.
fn cond_url_host_guard(info: &crate::cfg::NodeInfo, ctx: &AnalysisContext) -> Option<bool> {
    let hc = crate::taint::path_state::url_host_compare(info.condition_text.as_deref()?)?;
    let cond_func = info.ast.enclosing_func.as_deref();
    let cond_start = info.ast.span.0;
    let defined_in_func = |n: &crate::cfg::NodeInfo, name: &str| {
        n.taint.defines.as_deref() == Some(name) && n.ast.enclosing_func.as_deref() == cond_func
    };

    // The subject's latest definition before the condition must be `new URL(..)`.
    let mut best: Option<(usize, &str)> = None;
    for nidx in ctx.cfg.node_indices() {
        let n = &ctx.cfg[nidx];
        if n.kind != StmtKind::Call
            || !defined_in_func(n, &hc.subject)
            || n.ast.span.0 >= cond_start
        {
            continue;
        }
        if let Some(callee) = n.call.callee.as_deref()
            && best.is_none_or(|(s, _)| n.ast.span.0 > s)
        {
            best = Some((n.ast.span.0, callee));
        }
    }
    if !matches!(
        best?.1,
        "URL" | "new URL" | "window.URL" | "globalThis.URL" | "self.URL" | "URL.parse"
    ) {
        return None;
    }

    let extra = ctx.analysis_rules.map(|r| r.extra_labels.as_slice());
    let lang = ctx.lang.as_str();
    for word in hc
        .rhs
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.')))
        .filter(|w| !w.is_empty())
    {
        let mut candidate = word;
        loop {
            if matches!(
                crate::labels::classify(lang, candidate, extra),
                Some(DataLabel::Source(_))
            ) {
                return None;
            }
            match candidate.rsplit_once('.') {
                Some((prefix, _)) => candidate = prefix,
                None => break,
            }
        }
        let root = word.split('.').next().unwrap_or(word);
        let source_defined = ctx.cfg.node_indices().any(|nidx| {
            let n = &ctx.cfg[nidx];
            defined_in_func(n, root) && node_introduces_untrusted_data(n)
        });
        if source_defined {
            return None;
        }
    }
    Some(hc.is_eq != info.condition_negated)
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

        // Nested-expression open-redirect confiner guard (CVE-2022-24776):
        //   return redirect(get_safe_redirect(next_url))
        // The redirect target is wrapped by a same-origin confiner in one
        // nested expression with no `if` guard; the wrapper name survives in the
        // sink node's `arg_uses`.  Register the node itself as an OPEN_REDIRECT
        // guard (dominance is reflexive) so `cfg-unguarded-sink` agrees the
        // validated redirect is same-origin.  Mirrors the taint-layer strip.
        if call_arg_open_redirect_confiner(info, ctx) {
            result.push((idx, Cap::OPEN_REDIRECT));
        }

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
                } else if kind == PredicateKind::RedirectValidator {
                    result.push((idx, Cap::OPEN_REDIRECT));
                } else if kind == PredicateKind::HostDenylistRejected {
                    result.push((idx, Cap::SSRF));
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
                } else if cond_confinement_helper(info, ctx) {
                    // Behaviour-based path-confinement helper guard:
                    //   if (!isOptimizedDepFile(p)) return next();
                    // The helper's name carries no validator marker, but its
                    // SSA summary records a constant-prefix path-confinement
                    // predicate.  Scope to FILE_IO (confinement only proves
                    // path safety).  Motivated by CVE-2026-39365 (Vite).
                    result.push((idx, Cap::FILE_IO));
                } else if cond_open_redirect_confiner(info, ctx) {
                    // Behaviour-based relative-URL confiner guard:
                    //   const dest = normalize_relative_url(x);
                    //   if (dest !== null) res.redirect(dest);
                    // The helper's SSA summary records an OPEN_REDIRECT
                    // confinement (rejects `//` + `scheme:`), so a redirect
                    // gated on its non-null result is same-origin.  Scope to
                    // OPEN_REDIRECT.  Motivated by CVE-2026-42259 (Saltcorn).
                    result.push((idx, Cap::OPEN_REDIRECT));
                } else if kind == PredicateKind::RelativeUrlValidated
                    || (kind == PredicateKind::ProtocolRelativeCheck
                        && has_leading_slash_partner(idx, ctx))
                {
                    // Inline relative-URL check: a leading `/` plus a
                    // rejection of protocol-relative `//host` keeps a
                    // redirect on-site.  The split form registers on the
                    // `//` test when the same function also tests the same
                    // value for a leading `/`.  The guard is the first node
                    // on the passing edge (TRUE for the conjunction, FALSE
                    // for a `//` test), so a redirect inside the reject
                    // branch stays unguarded.
                    let passes_on_true =
                        (kind == PredicateKind::RelativeUrlValidated) != info.condition_negated;
                    if let Some(succ) = sole_successor_on_edge(idx, passes_on_true, ctx) {
                        result.push((succ, Cap::OPEN_REDIRECT));
                    }
                } else if let Some(passes_on_true) = cond_url_host_guard(info, ctx) {
                    // `const u = new URL(x, base); if (u.host === TRUSTED)`:
                    // on the passing edge the parsed URL, and the string it
                    // was parsed from, stay on the trusted host.  Mirrors the
                    // taint layer's `apply_url_host_compare_narrowing`.
                    if let Some(succ) = sole_successor_on_edge(idx, passes_on_true, ctx) {
                        result.push((succ, Cap::OPEN_REDIRECT | Cap::SSRF));
                    }
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
                        suffix_matches_at_leaf_boundary(&callee_lower, &ml)
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

/// Sanitizer caps that label rules (built-in and `nyx.conf`) give the calls
/// wrapping the sink's arguments.  Mirrors the fallback in the taint
/// engine's arg-callee sanitizer subtraction: a callee with a same-file
/// summary is answered by that summary (the `has_interprocedural_sanitizer`
/// check), every other callee by its labels, which is how library
/// sanitizers such as `escapeHtml` or `DOMPurify.sanitize` count.
fn arg_callee_label_sanitizer_caps(ctx: &AnalysisContext, sink: NodeIndex) -> Cap {
    let extra = ctx.analysis_rules.map(|r| r.extra_labels.as_slice());
    let mut caps = Cap::empty();
    for callee in ctx.cfg[sink].arg_callees.iter().flatten() {
        let leaf = callee_leaf_name(callee);
        if ctx.func_summaries.keys().any(|k| k.name == leaf) {
            continue;
        }
        for label in crate::labels::classify_all(ctx.lang.as_str(), callee, extra) {
            if let DataLabel::Sanitizer(c) = label {
                caps |= c;
            }
        }
    }
    caps
}

/// Whether the receiver of `callee` is known to be an instance of a project
/// class: `self` / `this` / `cls`, or a local bound to a constructor call of a
/// class the project defines.  Any other receiver (a parameter, an attribute,
/// an import) may be a library object such as a DataFrame.
fn receiver_is_project_object(ctx: &AnalysisContext, callee: &str, leaf: &str) -> bool {
    let recv = callee[..callee.len() - leaf.len()].trim_end_matches(['.', ':']);
    if matches!(recv, "self" | "this" | "cls") {
        return true;
    }
    if recv.is_empty() || recv.contains(['.', ':', '(']) {
        return false;
    }
    let is_project_class = |name: &str| {
        ctx.func_summaries
            .keys()
            .any(|k| k.container.rsplit("::").next() == Some(name))
            || ctx.global_summaries.is_some_and(|g| {
                g.lookup_same_lang(ctx.lang, "__init__")
                    .into_iter()
                    .any(|(k, _)| k.container.rsplit("::").next() == Some(name))
            })
    };
    ctx.cfg.node_weights().any(|info| {
        info.taint.defines.as_deref() == Some(recv)
            && info
                .call
                .callee
                .as_deref()
                .is_some_and(|c| is_project_class(callee_leaf_name(c)))
    })
}

/// Whether a receiver-qualified sink call is a name collision with a
/// project-defined method rather than a call to the library API the sink
/// label models.
///
/// Suffix sink matchers (Python `eval`, which exists for `df.eval` and
/// `redis.eval`) match any `recv.<name>` call.  When the project defines
/// methods with that name, the call usually targets one of them.  The call is
/// treated as such a collision only when every project function of that name
/// is known not to contain the sink: no sink caps overlapping `sink_caps`, or
/// the overlap is explained entirely by receiver-qualified calls of the same
/// name (a wrapper that forwards to another method called `eval`).  Any
/// unqualified call of the name, or another sink-labelled call, in a
/// candidate keeps the finding.  Callers apply this only to findings the
/// taint engine did not confirm.
fn sink_is_project_method_name_collision(
    ctx: &AnalysisContext,
    sink: NodeIndex,
    sink_caps: Cap,
) -> bool {
    let Some(callee) = ctx.cfg[sink].call.callee.as_deref() else {
        return false;
    };
    let leaf = callee_leaf_name(callee);
    // Only receiver-qualified calls: a bare `eval(x)` is the builtin.
    if leaf == callee {
        return false;
    }
    if !receiver_is_project_object(ctx, callee, leaf) {
        return false;
    }
    let lang = ctx.lang.as_str();
    let extra = ctx.analysis_rules.map(|r| r.extra_labels.as_slice());
    let sink_overlaps = |text: &str| {
        crate::labels::classify_all(lang, text, extra)
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.intersects(sink_caps)))
    };
    // The label must be name-based: the bare leaf alone already classifies.
    if !sink_overlaps(leaf) {
        return false;
    }

    let candidate_is_clean = |name_caps: Cap, callees: &[crate::summary::CalleeSite]| {
        if !name_caps.intersects(sink_caps) {
            return true;
        }
        let mut explained = false;
        for site in callees {
            let full = match site.receiver.as_deref() {
                Some(r) if !site.name.contains('.') => format!("{r}.{}", site.name),
                _ => site.name.clone(),
            };
            if !sink_overlaps(&full) {
                continue;
            }
            let qualified = site.receiver.is_some() || site.name.contains('.');
            if callee_leaf_name(&site.name) == leaf && qualified {
                explained = true;
            } else {
                return false;
            }
        }
        explained
    };

    let mut any = false;
    for (k, s) in ctx.func_summaries.iter() {
        if k.name == leaf {
            any = true;
            if !candidate_is_clean(s.sink_caps, &s.callees) {
                return false;
            }
        }
    }
    if let Some(g) = ctx.global_summaries {
        for (_, s) in g.lookup_same_lang(ctx.lang, leaf) {
            any = true;
            if !candidate_is_clean(Cap::from_bits_truncate(s.sink_caps), &s.callees) {
                return false;
            }
        }
    }
    any
}

/// Check whether taint analysis confirmed unsanitized flow to this sink node.
pub(super) fn taint_confirms_sink(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    ctx.taint_findings.iter().any(|f| f.sink == sink)
}

/// Identifiers that can carry the sink's injection payload, mirroring the
/// taint engine's sink filter: a gated sink takes its payload only from its
/// payload positions (per gate when the call carries several, narrowed to
/// the destination-field identifiers when the gate names them).  The bind
/// array of `pool.query(SQL, [req.query.email])` or the body sent to a fixed
/// URL is not the payload.  `None` when every use counts: an ungated sink,
/// a call whose argument boundaries are unknown, or one whose payload
/// positions may index a different call (see [`payload_positions_aligned`]).
fn sink_payload_uses(lang: Lang, info: &crate::cfg::NodeInfo) -> Option<SmallVec<[&str; 8]>> {
    let arg_uses = &info.call.arg_uses;
    if arg_uses.is_empty() || !payload_positions_aligned(lang, info) {
        return None;
    }
    let mut out: SmallVec<[&str; 8]> = SmallVec::new();
    let mut add = |positions: &[usize], dest: Option<&[String]>| -> Option<()> {
        for &pos in positions {
            for u in arg_uses.get(pos)? {
                if dest.is_none_or(|names| names.contains(u)) && !out.contains(&u.as_str()) {
                    out.push(u.as_str());
                }
            }
        }
        Some(())
    };
    if info.call.gate_filters.len() > 1 {
        for gate in &info.call.gate_filters {
            add(&gate.payload_args, gate.destination_uses.as_deref())?;
        }
    } else {
        match info.call.sink_payload_args.as_deref() {
            Some(positions) if !positions.is_empty() => {
                add(positions, info.call.destination_uses.as_deref())?
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Whether the sink's payload positions index the arguments recorded on the
/// node.  The positions come from the gate that matched the sink callee, and
/// `arg_uses` / `arg_string_literals` from the statement's own call.  When the
/// callee was rebound to an inner call (`http.get(target, cb).on('error', ..)`
/// keeps the `.on` arguments while the SSRF gate is `http.get`'s), the two
/// only line up if the outer call is itself the gated sink (`fetch(url, {body:
/// JSON.stringify(..)})`).  A hoisted callback sink keeps its own positions.
fn payload_positions_aligned(lang: Lang, info: &crate::cfg::NodeInfo) -> bool {
    if info.call.hoisted_sink.is_some() {
        return false;
    }
    match info.call.outer_callee.as_deref() {
        None => true,
        Some(outer) => {
            !crate::labels::classify_gated_sink(lang.as_str(), outer, |_| None, |_| None, |_| true)
                .is_empty()
        }
    }
}

/// Check whether any variable that reaches the sink's payload is directly
/// derived from a Source node in the same function (via simple def-use
/// chain).
fn sink_arg_is_source_derived(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    let sink_info = &ctx.cfg[sink];
    let sink_func = sink_info.ast.enclosing_func.as_deref();

    // Collect the variables the sink reads at its payload positions.
    let payload_uses = sink_payload_uses(ctx.lang, sink_info);
    let reaches_payload = |name: &str| match &payload_uses {
        Some(uses) => uses.contains(&name),
        None => sink_info.taint.uses.iter().any(|u| u == name),
    };

    // Walk all nodes in the same function looking for Source nodes that define
    // one of the variables the sink uses.
    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.ast.enclosing_func.as_deref() != sink_func {
            continue;
        }
        if !node_introduces_untrusted_data(info) {
            continue;
        }
        // A source that carries none of the sink's capabilities (the page's
        // own `window.location.origin` read by a redirect sink) is not data
        // the sink can be attacked through.
        if !sink_caps.is_empty()
            && !info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(bits) if bits.intersects(sink_caps)))
        {
            continue;
        }
        // Source node defines a variable that the sink reads → source-derived
        if let Some(def) = &info.taint.defines
            && reaches_payload(def)
        {
            return true;
        }
    }
    false
}

/// Whether `info` is a loop header that binds its variable from a file-scope
/// literal collection (`for (const n of NAMES)` with `const NAMES = ["a",
/// "b"]`), so the variable only ever holds one of those literals.  The
/// collection name must not be shadowed or taken as a parameter in the body.
fn loop_binds_literal_collection(
    ctx: &AnalysisContext,
    sink_func: Option<&str>,
    info: &crate::cfg::NodeInfo,
) -> bool {
    let (crate::cfg::StmtKind::Loop, [iterable]) = (info.kind, info.taint.uses.as_slice()) else {
        return false;
    };
    ctx.module_constant_collections
        .is_some_and(|m| m.contains(iterable.as_str()))
        && !ctx.scope_param_names().any(|p| p == iterable)
        && !ctx.cfg.node_indices().map(|i| &ctx.cfg[i]).any(|n| {
            n.ast.enclosing_func.as_deref() == sink_func
                && (n.taint.defines.as_deref() == Some(iterable.as_str())
                    || n.taint.extra_defines.iter().any(|d| d == iterable))
        })
}

/// Whether `name`, read in the body under analysis, is bound to a literal:
/// every assignment of it in this body is a constant (and there is at least
/// one), or the body neither assigns it nor takes it as a parameter and it is
/// a file-scope constant (`module_constants`, Java `static final` scalars).
fn ident_bound_to_constant(ctx: &AnalysisContext, sink_func: Option<&str>, name: &str) -> bool {
    let mut local_defs = ctx.cfg.node_indices().map(|i| &ctx.cfg[i]).filter(|info| {
        info.ast.enclosing_func.as_deref() == sink_func
            && (info.taint.defines.as_deref() == Some(name)
                || info.taint.extra_defines.iter().any(|d| d == name))
    });
    let mut any_local = false;
    for info in local_defs.by_ref() {
        any_local = true;
        let constant = info.taint.defines.as_deref() == Some(name)
            && ((info.taint.uses.is_empty() && !node_introduces_untrusted_data(info))
                || loop_binds_literal_collection(ctx, sink_func, info));
        if !constant {
            return false;
        }
    }
    if any_local {
        return true;
    }
    if ctx.scope_param_names().any(|p| p == name) {
        return false;
    }
    ctx.module_constants.is_some_and(|m| m.contains(name))
        || ctx
            .class_constant_scalars
            .is_some_and(|m| m.contains_key(name))
}

/// CFG-level twin of [`sink_payload_args_const`]: a gated sink whose
/// payload positions only hold literals or identifiers bound to literals
/// ([`ident_bound_to_constant`]).  Covers the named-query idiom
/// `pool.query(FIND_USER, [req.query.email])` / `cursor.execute(QUERY,
/// params)`, where the SQL lives in a local or file-scope constant that the
/// per-body SSA facts do not resolve, and the bind values sit outside the
/// payload.
fn sink_payload_uses_constant(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    let info = &ctx.cfg[sink];
    let positions = match info.call.sink_payload_args.as_deref() {
        Some(p) if !p.is_empty() && payload_positions_aligned(ctx.lang, info) => p,
        _ => return false,
    };
    let sink_func = info.ast.enclosing_func.as_deref();
    positions.iter().all(|&pos| {
        let literal = matches!(info.call.arg_string_literals.get(pos), Some(Some(_)));
        match info.call.arg_uses.get(pos) {
            Some(uses) if !uses.is_empty() => uses
                .iter()
                .all(|u| ident_bound_to_constant(ctx, sink_func, u)),
            Some(_) => literal,
            None => false,
        }
    })
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

    // Parameters in scope for this body (its own plus the ones a closure
    // captures from the functions around it).
    let param_names: SmallVec<[&str; 8]> = ctx.scope_param_names().collect();

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

    // Callback arguments are code, not data: the names read inside a function
    // literal passed to the sink (`exec(cmd, (error, stdout) => { ... })`)
    // and the name of a file-level function passed by reference
    // (`exec(cmd, done)`) never reach the sink's payload.  A name that also
    // appears in a non-callback argument keeps counting there.
    let mut callback_only: SmallVec<[&str; 8]> = SmallVec::new();
    for (pos, callee) in sink_info.arg_callees.iter().enumerate() {
        if callee.as_deref().is_some_and(crate::cfg::is_anon_fn_name)
            && let Some(uses) = sink_info.call.arg_uses.get(pos)
        {
            for u in uses {
                let elsewhere = sink_info
                    .call
                    .arg_uses
                    .iter()
                    .enumerate()
                    .any(|(i, us)| i != pos && us.contains(u));
                if !elsewhere && !callback_only.contains(&u.as_str()) {
                    callback_only.push(u.as_str());
                }
            }
        }
    }
    let names_file_function = |u: &str| {
        !param_names.contains(&u)
            && ctx.func_summaries.keys().any(|k| k.name == u)
            && !ctx.cfg.node_indices().any(|i| {
                let n = &ctx.cfg[i];
                n.ast.enclosing_func.as_deref() == sink_func
                    && (n.taint.defines.as_deref() == Some(u)
                        || n.taint.extra_defines.iter().any(|d| d == u))
            })
    };

    sink_uses.iter().all(|u| {
        if callee_fragments.contains(&u.as_str()) || u == callee_desc {
            return true;
        }
        if param_names.contains(&u.as_str()) {
            return true;
        }
        if callback_only.contains(&u.as_str()) || names_file_function(u) {
            return true;
        }
        // One-hop transitive local trace: when a sink use names a body
        // local whose every definition resolves to parameter-derived
        // data (e.g. `Statement stmt = connection.createStatement();
        // stmt.executeQuery(sql);` where `connection` is a param), the
        // local is wrapper plumbing.  Receiver-variable shapes whose
        // definitions reach a free (non-param, non-local) identifier or
        // a Source label fail the trace and keep the structural finding.
        let mut seen: SmallVec<[&str; 4]> = SmallVec::new();
        local_is_param_derived(
            ctx,
            sink_func,
            &param_names,
            &callee_fragments,
            u.as_str(),
            3,
            &mut seen,
        )
    })
}

/// Recursive trace, return true iff every definition of `name` inside
/// `sink_func` has its right-hand-side fully resolvable to parameter
/// names, callee fragments, or other already-cleared body locals.  Bounded
/// by `depth` to prevent runaway on pathological CFGs and uses `seen` to
/// short-circuit cycles (a local whose definition mentions itself does
/// not clear).  Called from `sink_arg_is_parameter_only` once the simple
/// param / callee-fragment / source-text check has failed.
fn local_is_param_derived<'a>(
    ctx: &'a AnalysisContext,
    sink_func: Option<&str>,
    param_names: &[&'a str],
    callee_fragments: &[&'a str],
    name: &'a str,
    depth: u8,
    seen: &mut SmallVec<[&'a str; 4]>,
) -> bool {
    if depth == 0 || seen.contains(&name) {
        return false;
    }
    seen.push(name);
    let mut found_def = false;
    let mut all_def_clear = true;
    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.ast.enclosing_func.as_deref() != sink_func {
            continue;
        }
        if info.taint.defines.as_deref() != Some(name) {
            continue;
        }
        found_def = true;
        // A `foreach` / `for-each` loop binding iterates collection
        // *elements*, not a direct parameter pass-through.  Even when the
        // iterable is a bare parameter (`foreach ($param as $v)`), the
        // per-element values are not simple wrapper plumbing, so do not
        // clear them as parameter-derived — keep the structural finding
        // for `foreach ($param as $v) { sink($v) }` shapes (literal-keyed
        // arrays are already suppressed earlier by
        // `sink_arg_uses_safe_foreach_key`).
        if info.kind == StmtKind::Loop {
            all_def_clear = false;
            break;
        }
        if info
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(_)))
        {
            all_def_clear = false;
            break;
        }
        // Compute the defining node's own callee fragments so method-name
        // segments (e.g. `createStatement` in `statement =
        // connection.createStatement();`) are recognised as pseudo-uses
        // alongside the receiver variable.  Without this, the trace
        // wrongly rejects every chained method initialisation.  The
        // source-text scan below also lifts intermediate method calls
        // (`unwrap` in `connection.unwrap().createStatement`) that the
        // collapsed `info.call.callee` drops.
        let def_fragments = chain_callee_fragments_with_text(
            info.call.callee.as_deref().unwrap_or(""),
            info.call.outer_callee.as_deref().unwrap_or(""),
            ctx.source_bytes,
            info.classification_span(),
        );
        let clear = info.taint.uses.iter().all(|u| {
            param_names.contains(&u.as_str())
                || callee_fragments.contains(&u.as_str())
                || def_fragments.contains(&u.as_str())
                || local_is_param_derived(
                    ctx,
                    sink_func,
                    param_names,
                    callee_fragments,
                    u.as_str(),
                    depth - 1,
                    seen,
                )
        });
        if !clear {
            all_def_clear = false;
            break;
        }
    }
    seen.pop();
    found_def && all_def_clear
}

/// Split a callee chain like `getSession().createQuery` or
/// `connection.createStatement` into method-name segments treated as
/// pseudo-uses.  Also walks `source_bytes[span]` up to the outermost
/// args-opener and lifts every `IDENT(` pattern, recovering intermediate
/// method-call segments that the collapsed `info.call.callee` text drops
/// (e.g. `unwrap` in `connection.unwrap().createStatement()`).  Mirrors
/// the in-place chain split inside `sink_arg_is_parameter_only` so trace
/// nodes get the same recognition as the sink itself.  Self-rooted
/// chains (`this->...`, `self.foo`) surface every segment; other chains
/// surface only the terminal method name plus any inner method-call
/// segments.
fn chain_callee_fragments_with_text<'a>(
    callee: &'a str,
    outer: &'a str,
    source_bytes: &'a [u8],
    span: (usize, usize),
) -> SmallVec<[&'a str; 8]> {
    fn split_chain<'b>(s: &'b str) -> SmallVec<[(&'b str, bool); 8]> {
        let mut out: SmallVec<[(&'b str, bool); 8]> = SmallVec::new();
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
    let mut frags: SmallVec<[&str; 8]> = SmallVec::new();
    for src in [callee, outer] {
        let segs = split_chain(src);
        let Some(&(first_name, _)) = segs.first() else {
            continue;
        };
        let last_idx = segs.len() - 1;
        if is_self_root(first_name) {
            for &(name, _) in &segs {
                if !frags.contains(&name) {
                    frags.push(name);
                }
            }
        } else {
            for (i, &(name, is_call)) in segs.iter().enumerate() {
                if (is_call || i == last_idx) && !frags.contains(&name) {
                    frags.push(name);
                }
            }
        }
    }
    let (start, end) = span;
    if start < source_bytes.len() && end <= source_bytes.len() && start < end {
        let span_bytes = &source_bytes[start..end];
        if let Ok(span_text) = std::str::from_utf8(span_bytes) {
            let bytes = span_text.as_bytes();
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
                    let abs_start = start + id_start;
                    let abs_end = start + i;
                    if abs_start < source_bytes.len() && abs_end <= source_bytes.len() {
                        let name_slice =
                            std::str::from_utf8(&source_bytes[abs_start..abs_end]).unwrap_or(name);
                        if !frags.contains(&name_slice) {
                            frags.push(name_slice);
                        }
                    }
                }
            }
        }
    }
    frags
}

/// True when a redirect-style sink's target is a plain string literal, or
/// starts with a constant prefix that pins the origin
/// (`res.redirect(`/users/${id}`)`, `redirect_to "/users/#{id}"`,
/// `redirect("https://app.example/" + p)`).  The prefix is the AST-derived
/// [`crate::cfg::NodeInfo::string_prefix`], so a bare `"/" + next` (which
/// `next = "/evil.com"` turns into `//evil.com`) does not count.
///
/// Reused by both `cfg-unguarded-sink` suppression and taint finding filtering.
pub(crate) fn redirect_target_origin_locked(info: &crate::cfg::NodeInfo, src: &[u8]) -> bool {
    info.call.callee.as_deref().is_some_and(|c| {
        let c = c.to_ascii_lowercase();
        c.ends_with("redirect") || c.ends_with("redirect_to")
    }) && (redirect_url_arg_is_literal(info, src)
        || info
            .string_prefix
            .as_deref()
            .is_some_and(crate::abstract_interp::string_domain::prefix_locks_origin))
}

/// The URL argument of a redirect call is a plain quoted string: the first
/// argument, or the second after a numeric status (`res.redirect(301,
/// '/home')`).  A literal target is chosen by the developer, whatever taint
/// the receiver carries.  Read from the call's own source text: f-strings,
/// template literals and double-quoted text with `#{..}` / `$` interpolation
/// are not literals, and a callee that is an inner call of the statement
/// (`get '/x', to: redirect { .. }`) does not count.
fn redirect_url_arg_is_literal(info: &crate::cfg::NodeInfo, src: &[u8]) -> bool {
    if info.call.outer_callee.is_some() {
        return false;
    }
    let (start, end) = info.call.callee_span.unwrap_or(info.ast.span);
    let Some(text) = src.get(start..end) else {
        return false;
    };
    let Some(open) = text.iter().position(|&b| b == b'(') else {
        return false;
    };
    let mut rest = text[open + 1..].trim_ascii_start();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits > 0 {
        let after = rest[digits..].trim_ascii_start();
        let Some(after_comma) = after.strip_prefix(b",") else {
            return false;
        };
        rest = after_comma.trim_ascii_start();
    }
    let Some(&quote) = rest.first() else {
        return false;
    };
    if quote != b'"' && quote != b'\'' {
        return false;
    }
    let mut i = 1;
    while i < rest.len() && rest[i] != quote {
        i += if rest[i] == b'\\' { 2 } else { 1 };
    }
    if i >= rest.len() {
        return false;
    }
    let content = &rest[1..i];
    let interpolated =
        quote == b'"' && (content.windows(2).any(|w| w == b"#{") || content.contains(&b'$'));
    !interpolated
        && matches!(
            rest[i + 1..].trim_ascii_start().first(),
            Some(b',') | Some(b')')
        )
}

/// Check if this sink's URL is pinned to a fixed origin: a redirect call whose
/// target is server-relative or literal, or an outbound request whose URL
/// starts with a constant `scheme://host/` (or `/path`) prefix.  The URL may
/// be inline or a variable whose every same-function definition before the
/// sink carries such a prefix (`const target = `/users/${id}`;
/// res.redirect(target)`, `url := "https://h/items/" + id; http.Get(url)`).
///
/// Mirrors the taint engine's `is_string_safe_for_ssrf` prefix-lock, so the
/// structural finding does not outlive the taint finding it duplicates.  The
/// URL argument is the sink's lowest payload position (`http.NewRequest`
/// takes it second), else the first argument that holds an identifier.
fn url_target_origin_locked(ctx: &AnalysisContext, sink: NodeIndex, sink_caps: Cap) -> bool {
    let url_caps = Cap::SSRF | Cap::OPEN_REDIRECT;
    // A sink that carries another cap as well (a request body is DATA_EXFIL)
    // keeps its structural finding: the URL lock says nothing about the body.
    if !sink_caps.intersects(url_caps) || !sink_caps.difference(url_caps).is_empty() {
        return false;
    }
    let info = &ctx.cfg[sink];
    if redirect_target_origin_locked(info, ctx.source_bytes) {
        return true;
    }
    let callee = info.call.callee.as_deref();
    let locks = |prefix: &str| {
        crate::abstract_interp::string_domain::prefix_locks_origin_for(callee, prefix)
    };
    if info.string_prefix.as_deref().is_some_and(locks) {
        return true;
    }
    let url_idx = info
        .call
        .sink_payload_args
        .as_deref()
        .and_then(|p| p.iter().copied().filter(|&i| i != usize::MAX).min())
        .or_else(|| info.call.arg_uses.iter().position(|uses| !uses.is_empty()));
    let Some([url_var]) = url_idx
        .and_then(|i| info.call.arg_uses.get(i))
        .map(|uses| uses.as_slice())
    else {
        return false;
    };
    let sink_func = info.ast.enclosing_func.as_deref();
    let defs: Vec<NodeIndex> = ctx
        .cfg
        .node_indices()
        .filter(|&i| {
            let n = &ctx.cfg[i];
            n.taint.defines.as_deref() == Some(url_var.as_str())
                && n.ast.enclosing_func.as_deref() == sink_func
                && n.ast.span.0 < info.ast.span.0
        })
        .collect();
    if defs
        .iter()
        .all(|&i| ctx.cfg[i].string_prefix.as_deref().is_some_and(locks))
        && defs_cover_every_path(ctx, &defs, sink)
    {
        return true;
    }
    // The taint engine locks the target from the abstract string facts as
    // well (`"/" + strings.Trim(p, "/\\")` keeps the origin), which no single
    // definition's literal prefix shows.
    ctx.body_const_facts.is_some_and(|facts| {
        crate::taint::ssa_transfer::url_sink_origin_locked_by_facts(
            &facts.ssa,
            ctx.cfg,
            ctx.lang,
            sink,
            node_introduces_untrusted_data,
        )
    })
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

/// Whether the sink reads the constant-index element `v` (`parts[0]`) of a
/// base that is defined once and has no write route besides redefinition, so a guard on that element names the same value the sink reads.
fn elem_read_pinned(cfg: &crate::cfg::Cfg, sink_info: &crate::cfg::NodeInfo, v: &str) -> bool {
    if !sink_info.elem_reads.iter().any(|e| &**e == v) {
        return false;
    }
    let Some((base, _)) = v.split_once('[') else {
        return false;
    };
    let defs = crate::cfg::go_base_def_count(cfg, sink_info.ast.enclosing_func.as_deref(), base);
    !sink_info.elem_base_unstable && defs <= 1
}

impl CfgAnalysis for UnguardedSink {
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let doms = dominators::compute_dominators(ctx.cfg, ctx.entry);
        let sink_nodes = dominators::find_sink_nodes(ctx.cfg);
        let guard_nodes = find_guard_nodes(ctx);
        let pinning_guards = find_value_pinning_guards(ctx);

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
            }) || pinning_guards.iter().any(|(guard_idx, vars)| {
                ctx.cfg[*guard_idx].ast.enclosing_func.as_deref() == sink_func
                    && vars.iter().any(|v| {
                        sink_info.taint.uses.iter().any(|u| u == v)
                            || elem_read_pinned(ctx.cfg, sink_info, v)
                    })
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

            // Library sanitizer wrapping an argument (`res.send(escapeHtml(x))`,
            // `shell_exec('wc -l ' . escapeshellarg($f))`): the taint engine
            // strips the sanitizer's caps from the sink, so do the same.
            let wrapped_by_label_sanitizer =
                (sink_caps & !arg_callee_label_sanitizer_caps(ctx, *sink)).is_empty();

            if is_guarded
                || has_sanitizer
                || has_interprocedural_sanitizer
                || wrapped_by_label_sanitizer
            {
                continue;
            }

            let callee_desc = sink_info.call.callee.as_deref().unwrap_or("(unknown sink)");

            // ── Severity classification ───────────────────────────────
            //
            // HIGH: taint confirms flow OR source directly feeds sink
            // MEDIUM: structural finding without taint confirmation
            // LOW: wrapper function (param-only, non-entrypoint)

            let has_taint = taint_confirms_sink(ctx, *sink);
            let source_derived = sink_arg_is_source_derived(ctx, *sink, sink_caps);

            // If sink args are all constants (including one-hop constant bindings)
            // and taint didn't confirm, this is a false positive, skip it.
            if is_all_args_constant(ctx, *sink) && !has_taint {
                continue;
            }

            // Name-based sink label on a call that resolves to project
            // methods of that name (`cond.eval(data)` on a project class).
            if !has_taint && sink_is_project_method_name_collision(ctx, *sink, sink_caps) {
                continue;
            }

            // Syntactic payload-const suppression (scope-robust): when every
            // operand at the sink's `sink_payload_args` positions is a constant
            // literal captured on the call node at CFG-build time, the injection
            // vector is provably non-attacker-controlled.  Unlike the SSA-backed
            // check below, this holds even when the sink lives inside a nested
            // callback body the per-function SSA const-facts don't cover — the
            // dominant raw-SQL migration idiom
            // `sequelize.transaction(async (t) => { sequelize.query(`…DDL…`, { transaction: t }) })`.
            // Sound regardless of `has_taint`: a syntactic literal at a payload
            // position cannot itself carry taint.
            if sink_payload_args_syntactic_const(ctx, *sink) {
                continue;
            }

            // Payload-arg-gated sinks (e.g. Go `db.QueryContext(ctx, sql,
            // ...binds)`, `payload_args = [1]`): only the payload positions can
            // carry an injection.  When the taint engine is already silent
            // (`!has_taint`) and every payload-position operand is a constant
            // literal, the non-payload operands (a `context.Context`, bind
            // values) cannot make the call dangerous, so the structural finding
            // is a false positive even though `is_all_args_constant` rejects it.
            if !has_taint && sink_payload_args_const(ctx, *sink) {
                continue;
            }
            // Same, resolved on the CFG: the payload positions hold literals
            // or names bound to literals in this body or at file scope
            // (`pool.query(FIND_USER, [req.query.email])`).
            if !has_taint && sink_payload_uses_constant(ctx, *sink) {
                continue;
            }

            // Origin-locked URL SSRF sinks (`fetch(new URL(path, "https://…"))`):
            // the builder's literal base pins scheme+host, so the
            // attacker-controlled path cannot redirect off-origin.  The taint
            // engine already suppresses this via the abstract prefix-lock, so
            // the parallel structural finding is a false positive.  NOT gated
            // on `!has_taint`: the origin lock holds precisely *because* the
            // tainted path reaches the builder — the host stays fixed — so the
            // syntactic taint-reaches signal must not re-open the finding.
            if sink_url_origin_locked(ctx, *sink, sink_caps) {
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

            // Numeric cast / arithmetic assignment (`$pid = (int) $raw`):
            // the taint engine clears every capability at that assignment.
            if !has_taint && sink_args_numeric_assigned(ctx, *sink) {
                continue;
            }

            // Go `fmt.Fprint*` reflected-XSS onto a non-response writer
            // (`*bytes.Buffer`, `*os.File`, `bufio.Writer`, `io.Writer`
            // param): the taint engine strips `HTML_ESCAPE` for the same
            // writer type, so the flow is not confirmed here (`!has_taint`)
            // and the structural finding would be a twin false positive.
            if !has_taint && go_fprintf_writer_non_response(ctx, *sink, sink_caps) {
                continue;
            }

            // A response-write sink (`println` / `write`) on a receiver whose
            // declared type is not an HTTP response (a `PrintStream` field):
            // the taint engine strips the cap for the same receiver.
            if !has_taint && java_receiver_declared_non_response(ctx, *sink, sink_caps) {
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

            // Interpolated query text with a params argument
            // (`f"... ORDER BY {sort} LIMIT ?", (n,)`): the bound values are
            // not the injection vector, so only a taint-confirmed flow into
            // the query text is reported.  Without this the structural rule
            // would read the bind value as a source-derived operand.
            if sink_info.parameterized_query_interpolated && !has_taint {
                continue;
            }

            // Numeric-confinement: every real argument to the sink is an
            // inline numeric call-chain (`Command::arg(s.parse::<u16>()
            // .unwrap().to_string())`) whose source leaf reaches the sink only
            // as a number.  Fires regardless of `has_taint` — the SSA taint
            // engine drops the same flow via `numeric_confined_uses`, so the
            // structural finding must clear in lock-step.
            if sink_args_numeric_confined(ctx, *sink, sink_caps) {
                continue;
            }

            // Fixed-origin URLs: res.redirect(`/path/...`) is server-relative,
            // and a request to `https://host/...${x}` cannot leave the host.
            if url_target_origin_locked(ctx, *sink, sink_caps) {
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
                let has_params = ctx.scope_param_names().next().is_some();
                if !has_sources && !has_params {
                    continue; // No sources or params in scope → noise
                }
                // Rails migration: one-off DDL run by a developer, its block
                // parameters come from rows the migration just selected.
                if !has_sources
                    && ctx.lang == Lang::Ruby
                    && source_declares_rails_migration(ctx.source_bytes)
                {
                    continue;
                }
                // Ruby block / lambda body: a closure that merely has
                // parameters in scope is not a signal.  The sink must read
                // one of them, directly or through locals
                // (`lambda { order(configuration[:order]) }` reads none).
                if !has_sources
                    && ctx.lang == Lang::Ruby
                    && sink_in_closure(ctx, *sink)
                    && !sink_operands_reach_param(ctx, *sink)
                {
                    continue;
                }
                (Severity::Medium, Confidence::Medium)
            };

            findings.push(CfgFinding {
                rule_id: "cfg-unguarded-sink".to_string(),
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

#[cfg(test)]
mod chain_fragments_tests {
    use super::chain_callee_fragments_with_text;

    fn frags(callee: &str, outer: &str, source: &str) -> Vec<String> {
        chain_callee_fragments_with_text(callee, outer, source.as_bytes(), (0, source.len()))
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    #[test]
    fn java_chained_init_lifts_inner_call() {
        // `Statement stmt = connection.unwrap().createStatement();`
        // The collapsed `info.call.callee` drops the inner method call,
        // so the source-text scan has to recover `unwrap` on top of the
        // structural split's `createStatement`.
        let src = "Statement stmt = connection.unwrap().createStatement()";
        let got = frags("connection.createStatement", "", src);
        assert!(got.contains(&"createStatement".to_string()));
        assert!(got.contains(&"unwrap".to_string()));
        assert!(!got.contains(&"connection".to_string()));
        assert!(!got.contains(&"stmt".to_string()));
    }

    #[test]
    fn flat_method_invocation_terminal_only() {
        // `connection.createStatement()` — receiver `connection` stays a
        // real local-variable use, only the terminal method counts as a
        // pseudo-use.
        let src = "connection.createStatement()";
        let got = frags("connection.createStatement", "", src);
        assert!(got.contains(&"createStatement".to_string()));
        assert!(!got.contains(&"connection".to_string()));
    }

    #[test]
    fn self_rooted_chain_lifts_every_segment() {
        // `$this->inner->execute($sql)` — every chain segment belongs to
        // the callee path because the chain is rooted at a self
        // pseudo-receiver.
        let src = "$this->inner->execute($sql)";
        let got = frags("this->inner->execute", "", src);
        assert!(got.contains(&"this".to_string()));
        assert!(got.contains(&"inner".to_string()));
        assert!(got.contains(&"execute".to_string()));
    }

    #[test]
    fn source_scan_skips_inside_args() {
        // The scan stops at the outermost args opener, so identifiers
        // nested inside the arguments are NOT lifted as pseudo-uses.
        // `db.exec(transform(raw))` still treats `transform` as a real
        // local reference, not a chain segment.
        let src = "db.exec(transform(raw))";
        let got = frags("db.exec", "", src);
        assert!(got.contains(&"exec".to_string()));
        assert!(!got.contains(&"transform".to_string()));
        assert!(!got.contains(&"raw".to_string()));
    }
}

#[cfg(test)]
mod guard_suffix_boundary_tests {
    use super::suffix_matches_at_leaf_boundary;

    #[test]
    fn rejects_mid_identifier_suffixes() {
        // The whole point of the fix: these must NOT register as guards.
        assert!(!suffix_matches_at_leaf_boundary("invalidate", "validate"));
        assert!(!suffix_matches_at_leaf_boundary(
            "cache.invalidate",
            "validate"
        ));
        assert!(!suffix_matches_at_leaf_boundary("unquote", "quote"));
        assert!(!suffix_matches_at_leaf_boundary(
            "urllib.parse.unquote",
            "quote"
        ));
    }

    #[test]
    fn accepts_leaf_boundary_suffixes() {
        // Suffix at a real leaf-name boundary stays a valid guard match.
        assert!(suffix_matches_at_leaf_boundary("validate", "validate"));
        assert!(suffix_matches_at_leaf_boundary("shlex.quote", "quote"));
        assert!(suffix_matches_at_leaf_boundary(
            "urllib.parse.quote",
            "quote"
        ));
        // `_` and `::` separators also count as leaf boundaries.
        assert!(suffix_matches_at_leaf_boundary("my_validate", "validate"));
        assert!(suffix_matches_at_leaf_boundary(
            "std::shell_escape",
            "shell_escape"
        ));
    }

    #[test]
    fn rejects_non_suffix() {
        assert!(!suffix_matches_at_leaf_boundary(
            "validate_input",
            "validate"
        ));
        assert!(!suffix_matches_at_leaf_boundary("os.system", "quote"));
    }
}

#[cfg(test)]
mod hoisted_payload_tests {
    use super::payload_positions_all_literal;

    #[test]
    fn gated_payload_all_literal_suppresses() {
        // `sequelize.query(`const DDL`, { transaction })` — gated payload_args=[0],
        // arg 0 literal, arg 1 non-literal options object. Only position 0 counts.
        let lits = vec![Some("DROP VIEW x".to_string()), None];
        assert!(payload_positions_all_literal(&Some(vec![0]), &lits));
    }

    #[test]
    fn gated_payload_non_literal_position_does_not_suppress() {
        // Interpolated inner SQL: payload position 0 is a non-const template.
        let lits = vec![None, None];
        assert!(!payload_positions_all_literal(&Some(vec![0]), &lits));
    }

    #[test]
    fn gated_payload_position_out_of_range_does_not_suppress() {
        let lits = vec![Some("x".to_string())];
        assert!(!payload_positions_all_literal(&Some(vec![1]), &lits));
    }

    #[test]
    fn unrestricted_sink_requires_every_arg_literal() {
        // No gate: every recorded argument must be a constant literal.
        assert!(payload_positions_all_literal(
            &None,
            &[Some("a".to_string()), Some("b".to_string())]
        ));
        assert!(!payload_positions_all_literal(
            &None,
            &[Some("a".to_string()), None]
        ));
    }

    #[test]
    fn unrestricted_sink_empty_args_unproven() {
        // Empty literal list is unproven → not suppressed (conservative).
        assert!(!payload_positions_all_literal(&None, &[]));
        assert!(!payload_positions_all_literal(&Some(vec![]), &[]));
    }
}

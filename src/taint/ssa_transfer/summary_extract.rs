//! SSA function-summary and container-flow extraction.
//!
//! Extracted from the monolithic `ssa_transfer.rs`.  Contains:
//! * [`extract_ssa_func_summary`], runs per-parameter taint probes and
//!   synthesises an [`crate::summary::ssa_summary::SsaFuncSummary`] with
//!   source caps, return transforms, per-path transforms, and sink site
//!   attribution.
//! * [`extract_container_flow_summary`], structural scan for
//!   `param_container_to_return` + `param_to_container_store` pairs.
//! * Private helpers for predicate-hash summarisation, abstract-transfer
//!   derivation, callback source detection, and return-type inference.

use super::events::extract_sink_arg_positions;
use super::state::{BindingKey, SsaTaintState};
use super::{
    SsaTaintEvent, SsaTaintTransfer, detect_variant_inner_fact, op_for_value, run_ssa_taint_full,
    transfer_block, transfer_inst,
};
use crate::taint::path_state::is_redirect_safety_predicate_name;

use crate::cfg::{BodyId, Cfg, FuncSummaries};
use crate::labels::{Cap, SourceKind};
use crate::ssa::ir::{SsaBody, SsaOp, SsaValue, Terminator};
use crate::ssa::type_facts::{TypeFactResult, TypeKind, analyze_types_with_param_types};
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use crate::taint::domain::{TaintOrigin, VarTaint};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};

/// Maximum number of parameters to probe for summary extraction.
/// Functions with more params fall back to legacy `FuncSummary`.
pub(crate) const MAX_PROBE_PARAMS: usize = 8;

/// Whether return value `v` provably evaluates to a compile-time constant —
/// its def is a `Const`, or an `Assign`/`Phi` whose every operand traces
/// (transitively) to a constant.  A value that hits a parameter, a call, or any
/// other op is *not* provably constant (return `false`, conservative).
///
/// Used by `run_probe` to recognise a clean, param-free return so the
/// param-taint fallback does not attribute the seeded parameter's `Cap::all`
/// to a return that cannot reach it (the dead-branch-folded
/// `return v; v = Assign([phi([const])])` shape).  Bounded depth.
fn rv_traces_to_constant(
    ssa: &SsaBody,
    v: SsaValue,
    all_param_values: &HashSet<SsaValue>,
    depth: u32,
    budget: &mut u32,
) -> bool {
    // Node budget caps total work so a wide phi/assign DAG (shared
    // sub-expressions are re-visited without memoisation) cannot blow up;
    // exhausting it returns the conservative `false`.
    if depth > 16 || *budget == 0 || all_param_values.contains(&v) {
        return false;
    }
    *budget -= 1;
    match op_for_value(ssa, v) {
        Some(SsaOp::Const(_)) => true,
        Some(SsaOp::Assign(uses)) => {
            !uses.is_empty()
                && uses
                    .iter()
                    .all(|&u| rv_traces_to_constant(ssa, u, all_param_values, depth + 1, budget))
        }
        Some(SsaOp::Phi(operands)) => {
            !operands.is_empty()
                && operands.iter().all(|(_, u)| {
                    rv_traces_to_constant(ssa, *u, all_param_values, depth + 1, budget)
                })
        }
        _ => false,
    }
}

/// True when the value returned on one path can hold data that came into the
/// function: it depends on a parameter, or it already carries source taint.
///
/// A return that depends on neither (a failure sentinel such as `null` or
/// `None`, `errors.New("bad")`) holds nothing a caller's taint can flow into,
/// so having no abstract fact for it does not make the fact joined over the
/// other returns wrong.  An exhausted node budget answers `true`.
fn return_carries_input(
    ssa: &SsaBody,
    rv: SsaValue,
    all_param_values: &HashSet<SsaValue>,
    derived_caps: Cap,
) -> bool {
    if !derived_caps.is_empty() {
        return true;
    }
    let params: HashMap<SsaValue, usize> = all_param_values.iter().map(|&v| (v, 0)).collect();
    let mut seen = HashSet::new();
    let mut found: SmallVec<[usize; 2]> = SmallVec::new();
    let mut budget = 256u32;
    collect_reaching_params(ssa, rv, &params, &mut seen, &mut found, &mut budget);
    !found.is_empty() || budget == 0
}

/// Walk the def-use closure of `v`, collecting the set of formal-parameter
/// indices it depends on.
///
/// Traces through `Assign`/`Phi` operands, `Call` receiver + args (so a
/// path-normalising wrapper like `normalizePath(id)` still reaches the
/// underlying `id` parameter), and `FieldProj` receivers.  A value found in
/// `param_index_of` is a leaf (its def is the `Param` op).  Bounded by a
/// shared node `budget` and a `seen` set so a wide/cyclic SSA DAG cannot
/// blow up.
fn collect_reaching_params(
    ssa: &SsaBody,
    v: SsaValue,
    param_index_of: &HashMap<SsaValue, usize>,
    seen: &mut HashSet<SsaValue>,
    out: &mut SmallVec<[usize; 2]>,
    budget: &mut u32,
) {
    if *budget == 0 || !seen.insert(v) {
        return;
    }
    *budget -= 1;
    if let Some(&idx) = param_index_of.get(&v) {
        if !out.contains(&idx) {
            out.push(idx);
        }
        return;
    }
    match op_for_value(ssa, v) {
        Some(SsaOp::Assign(uses)) => {
            for &u in uses {
                collect_reaching_params(ssa, u, param_index_of, seen, out, budget);
            }
        }
        Some(SsaOp::Phi(operands)) => {
            for &(_, u) in operands {
                collect_reaching_params(ssa, u, param_index_of, seen, out, budget);
            }
        }
        Some(SsaOp::Call { receiver, args, .. }) => {
            if let Some(r) = receiver {
                collect_reaching_params(ssa, *r, param_index_of, seen, out, budget);
            }
            for group in args {
                for &u in group {
                    collect_reaching_params(ssa, u, param_index_of, seen, out, budget);
                }
            }
        }
        Some(SsaOp::FieldProj { receiver, .. }) => {
            collect_reaching_params(ssa, *receiver, param_index_of, seen, out, budget);
        }
        _ => {}
    }
}

/// What a return block's value depends on, as two walks of its def-use
/// closure (see [`return_reaching_param_values`]).  `None` means the walk ran
/// out of budget.
struct ReturnReach {
    /// Parameters reached without crossing a sanitizer call.
    direct: Option<HashSet<SsaValue>>,
    /// Parameters reached at all.
    through_sanitizers: Option<HashSet<SsaValue>>,
}

/// Node budget for [`return_reaching_param_values`].
const RETURN_REACH_BUDGET: u32 = 512;

/// Parameter values that can influence the returned value `rv`.
///
/// The per-parameter summary probe runs with one parameter seeded.  When `rv`
/// still comes out untainted, either the seeded parameter does not reach it
/// (`first(a, b) { return a }` probed for `b`), or a sanitizer or numeric
/// conversion on the way killed the taint (`return Number(s)`), or the SSA
/// lacks an edge for a side effect the function really has.  Only the last
/// case should keep the parameter's caps on the return, and that case is
/// exactly "the parameter is in the def-use closure of `rv` without a
/// sanitizer in between".
///
/// The walk follows `Assign` and `Phi` operands, `FieldProj` receivers and
/// `Call` receiver plus arguments.  It does not descend through a call whose
/// CFG node carries a `Sanitizer` label: that call is a deliberate kill, the
/// same one the intra-procedural transfer applies.  Two edges SSA does not
/// carry as operands are added: a call made on a reached value as its receiver
/// (`sb.append(tail)` then `sb.toString()`, `lst.append(x)` then `lst`), and
/// the prior object of a synthetic field-write base update (`obj.f = v` then
/// `return obj`).
///
/// With `stop_at_sanitizers` off the walk crosses sanitizer calls too, giving
/// every parameter the value is built from at all.  The difference between the
/// two walks is the set of parameters that reach the return only through a
/// sanitizer.
///
/// Returns `None` when the node budget runs out, meaning "unknown": the
/// caller keeps the legacy all-parameters fallback.
fn return_reaching_param_values(
    ssa: &SsaBody,
    cfg: &Cfg,
    rv: SsaValue,
    all_param_values: &HashSet<SsaValue>,
    calls_by_receiver: &HashMap<SsaValue, SmallVec<[SsaValue; 2]>>,
    stop_at_sanitizers: bool,
) -> Option<HashSet<SsaValue>> {
    let mut reached: HashSet<SsaValue> = HashSet::new();
    let mut seen: HashSet<SsaValue> = HashSet::new();
    let mut work: Vec<SsaValue> = vec![rv];
    let mut budget = RETURN_REACH_BUDGET;
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        if budget == 0 {
            return None;
        }
        budget -= 1;
        if all_param_values.contains(&v) {
            reached.insert(v);
        }
        let op = op_for_value(ssa, v);
        // A phi sits on whichever CFG node starts its block, so only the
        // value-producing ops can be the sanitizing call.
        let killed_by_sanitizer = matches!(op, Some(SsaOp::Call { .. } | SsaOp::Assign(_)))
            && ssa.value_defs.get(v.0 as usize).is_some_and(|vd| {
                cfg.node_weight(vd.cfg_node).is_some_and(|n| {
                    n.taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, crate::labels::DataLabel::Sanitizer(_)))
                })
            });
        if killed_by_sanitizer && stop_at_sanitizers {
            continue;
        }
        match op {
            Some(SsaOp::Assign(uses)) => work.extend(uses.iter().copied()),
            Some(SsaOp::Phi(operands)) => work.extend(operands.iter().map(|&(_, u)| u)),
            Some(SsaOp::FieldProj { receiver, .. }) => work.push(*receiver),
            Some(SsaOp::Call { receiver, args, .. }) => {
                work.extend(receiver.iter().copied());
                work.extend(args.iter().flatten().copied());
            }
            _ => {}
        }
        if let Some((prior, _)) = ssa.field_writes.get(&v) {
            work.push(*prior);
        }
        if let Some(calls) = calls_by_receiver.get(&v) {
            work.extend(calls.iter().copied());
        }
    }
    Some(reached)
}

/// Whether `param` is one of the values some return is built from, and every
/// way it gets there crosses a sanitizer call.
fn reaches_return_only_through_sanitizers(
    param: SsaValue,
    reach_by_block: &HashMap<usize, ReturnReach>,
) -> bool {
    let mut through = false;
    for reach in reach_by_block.values() {
        let (Some(direct), Some(all)) = (&reach.direct, &reach.through_sanitizers) else {
            return false;
        };
        if direct.contains(&param) {
            return false;
        }
        through |= all.contains(&param);
    }
    through
}

/// Detect parameters confined by a boolean path-prefix predicate.
///
/// Recognises the behaviour-based path-confinement helper shape: a function
/// whose return value is a constant-prefix containment check on a parameter,
/// e.g.
///
/// ```text
/// const isOptimizedDepFile = (id: string): boolean =>
///   normalizePath(id).startsWith(`${depsCacheDir}/`)   // JS/TS
/// func isSafe(p string) bool { return strings.HasPrefix(p, "/safe") }  // Go
/// def is_safe(p): return p.startswith("/safe")          // Python
/// def safe?(p); p.start_with?("/safe"); end             // Ruby
/// ```
///
/// For each `return <call>` block, follows single-operand `Assign` copies to
/// the real defining op, requires it to be a prefix-containment call
/// (`startsWith` / `startswith` / `start_with?` method forms, or Go's
/// `strings.HasPrefix(subject, prefix)` function form), then:
///
///  * the **subject** (method receiver, or `HasPrefix` arg 0) must trace back
///    to a formal parameter — that parameter is the one being confined;
///  * the **prefix** (method arg 0, or `HasPrefix` arg 1) must be a *fixed*
///    value: a string constant, or at minimum not derived from any parameter,
///    so a caller cannot influence the safe-prefix the subject is checked
///    against.
///
/// The recognised predicate is `BooleanTrueIsValid` (a `true` result proves
/// containment).  Callers consume the returned indices in
/// `apply_summary_confinement_narrowing` to strip `Cap::FILE_IO` from the
/// matching argument on the surviving branch of a downstream truthiness gate.
///
/// Conservative by construction: a negated/rejection form (`!…startsWith` /
/// `.contains("..")`) is *not* recognised here (opposite polarity), nor is a
/// `path.relative(base, p)` not-`..` shape — both are documented follow-ups.
/// Motivated by CVE-2026-39365 (Vite dev-server sourcemap path traversal).
fn detect_path_confining_predicate_params(
    ssa: &SsaBody,
    consts: &crate::ssa::const_prop::ConstValues,
    param_index_of: &HashMap<SsaValue, usize>,
) -> SmallVec<[usize; 2]> {
    let mut result: SmallVec<[usize; 2]> = SmallVec::new();
    if param_index_of.is_empty() {
        return result;
    }

    for block in &ssa.blocks {
        let Terminator::Return(Some(rv)) = &block.terminator else {
            continue;
        };

        // Follow single-operand Assign copies to the real defining op
        // (`return t; t = recv.startsWith(p)` lowers `rv` to a copy of the
        // call value on some paths).
        let mut cur = *rv;
        let mut hops = 0;
        let def = loop {
            match op_for_value(ssa, cur) {
                Some(SsaOp::Assign(uses)) if uses.len() == 1 && hops < 8 => {
                    cur = uses[0];
                    hops += 1;
                }
                other => break other,
            }
        };
        let Some(SsaOp::Call {
            callee,
            callee_text,
            args,
            receiver,
        }) = def
        else {
            continue;
        };

        for p in prefix_confinement_params(
            ssa,
            consts,
            param_index_of,
            callee.as_str(),
            callee_text.as_deref(),
            *receiver,
            args,
        ) {
            if !result.contains(&p) {
                result.push(p);
            }
        }
    }

    result
}

/// Subject/prefix analysis for a resolved prefix-containment call
/// (`recv.startsWith(prefix)`, `strings.HasPrefix(subject, prefix)`, Python
/// `.startswith`, Ruby `.start_with?`).  Returns the formal-parameter indices a
/// `true` result confines: params reaching the *subject* side, provided the
/// *prefix* operand is a fixed value (a string constant, or not reachable from
/// any formal parameter).  Empty when the call is not a fixed-prefix
/// containment check.  Shared by the return-value confiner detector
/// ([`detect_path_confining_predicate_params`]) and the assert-guard detector
/// ([`detect_assert_path_confined_params`]).
fn prefix_confinement_params(
    ssa: &SsaBody,
    consts: &crate::ssa::const_prop::ConstValues,
    param_index_of: &HashMap<SsaValue, usize>,
    callee: &str,
    callee_text: Option<&str>,
    receiver: Option<SsaValue>,
    args: &[SmallVec<[SsaValue; 2]>],
) -> SmallVec<[usize; 2]> {
    use crate::ssa::const_prop::ConstLattice;
    let mut result: SmallVec<[usize; 2]> = SmallVec::new();

    let method = crate::labels::bare_method_name(callee_text.unwrap_or(callee));
    let mlow = method.to_ascii_lowercase();
    if !matches!(mlow.as_str(), "startswith" | "start_with?" | "hasprefix") {
        return result;
    }

    // Resolve (subject operands, prefix value) per call form.
    //
    // Method form (`receiver.startsWith(prefix)`): SSA lowering of a
    // chained-receiver method call puts the *explicit* arguments first
    // and *appends* the chain's implicit-use operands (the free
    // identifiers and the real subject param) as later arg groups
    // (`build_call_args`).  So `args[0]` is the prefix and the subject
    // param hides in `receiver` + `args[1..]` as an implicit use — the
    // textual receiver (`normalizePath(id)`) is itself collapsed to a
    // free-var Param, so the real `id` param is only observable through
    // those implicit uses.
    //
    // Go function form (`strings.HasPrefix(subject, prefix)`): no
    // receiver, `args[0]` is the subject and `args[1]` the prefix.
    let (subject_vals, prefix): (SmallVec<[SsaValue; 4]>, Option<SsaValue>) =
        if let Some(r) = receiver {
            let prefix = args.first().and_then(|g| g.first()).copied();
            let mut subs: SmallVec<[SsaValue; 4]> = SmallVec::new();
            subs.push(r);
            for g in args.iter().skip(1) {
                subs.extend(g.iter().copied());
            }
            (subs, prefix)
        } else if mlow == "hasprefix" {
            let prefix = args.get(1).and_then(|g| g.first()).copied();
            let subs: SmallVec<[SsaValue; 4]> = args
                .first()
                .map(|g| g.iter().copied().collect())
                .unwrap_or_default();
            (subs, prefix)
        } else {
            (SmallVec::new(), None)
        };
    let Some(prefix) = prefix else {
        return result;
    };

    // Prefix must be a fixed value: a string constant, or not reachable
    // from any *formal* parameter.  Captured module-scope values
    // (`depsCacheDir`) appear as free-var Params with no formal index,
    // so they read as fixed; a real param-derived prefix is
    // attacker-influenced and proves no confinement.
    let prefix_is_const = matches!(consts.get(&prefix), Some(ConstLattice::Str(_)));
    let mut budget = 512u32;
    let mut prefix_params: SmallVec<[usize; 2]> = SmallVec::new();
    if !prefix_is_const {
        let mut pseen = HashSet::new();
        collect_reaching_params(
            ssa,
            prefix,
            param_index_of,
            &mut pseen,
            &mut prefix_params,
            &mut budget,
        );
        if !prefix_params.is_empty() {
            return result;
        }
    }

    // A formal parameter flowing into the subject side of the prefix
    // check is confined: a `true` result constrains it to start with the
    // fixed prefix.
    let mut subj_params: SmallVec<[usize; 2]> = SmallVec::new();
    for sv in subject_vals {
        let mut sseen = HashSet::new();
        collect_reaching_params(
            ssa,
            sv,
            param_index_of,
            &mut sseen,
            &mut subj_params,
            &mut budget,
        );
    }
    for p in subj_params {
        if !prefix_params.contains(&p) && !result.contains(&p) {
            result.push(p);
        }
    }
    result
}

/// Whether a callee (by lowercased bare name) is a *throw-if-false* assertion
/// helper: any normal return after it proves its boolean argument held.
/// Spring `Assert.isTrue`, commons-lang `Validate.isTrue`, Guava
/// `Preconditions.checkArgument` / `checkState`, Node `assert(...)`.  Bounded
/// to this small set so a non-guard call whose first argument happens to be a
/// `startsWith` result cannot mint a spurious confinement.
fn is_assert_true_callee(bare_lower: &str) -> bool {
    matches!(
        bare_lower,
        "istrue" | "checkargument" | "checkstate" | "require" | "assert"
    )
}

/// Detect the *assert-guard* path-confinement form: a guard method whose body
/// asserts a fixed-prefix containment on a parameter and throws otherwise
/// (`Assert.isTrue(canonical.startsWith(base), msg)`,
/// `Preconditions.checkArgument(p.startsWith(dir))`).  Any normal return from
/// such a method is a post-condition that the checked parameter is confined
/// under the fixed prefix, so a *call* to it (no caller branch needed) clears
/// `Cap::FILE_IO` from the confined arguments.  Distinct from
/// [`detect_path_confining_predicate_params`], which recognises a *return-value*
/// boolean confiner the caller must branch on.
///
/// The confinement is sound only when the assertion throws on a `false`
/// containment: the recognised callees are all throw-if-false asserts, and the
/// asserted operand must reduce to a prefix-containment check.  Two shapes:
///   * Case A (collapsed method form, the dominant Java/Spring shape) — the
///     chained `x.startsWith(y)` flattens into the assert's arg0 group with the
///     `startsWith` method name surviving only as a synthetic-param leaf, split
///     by [`confined_params_from_collapsed_assert_group`].
///   * Case B (clean Call form, e.g. Go `strings.HasPrefix`) — arg0's def is a
///     distinct `startsWith`/`hasPrefix` Call, resolved by
///     [`prefix_confinement_params`].
///
/// A negated `Assert.isTrue(!x.startsWith(p))` (assert-NOT-contained) is not a
/// real containment guard; in Case B its def is a unary-not op, not a
/// `startsWith` Call, so it is naturally excluded.  This over-recognition is
/// conservative-to-suppress only in the (non-idiomatic) collapsed-negated
/// shape, and only ever clears `Cap::FILE_IO`.
///
/// Motivated by CVE-2021-21234 (spring-boot-actuator-logview path traversal).
fn detect_assert_path_confined_params(
    ssa: &SsaBody,
    consts: &crate::ssa::const_prop::ConstValues,
    param_index_of: &HashMap<SsaValue, usize>,
) -> SmallVec<[usize; 2]> {
    let mut result: SmallVec<[usize; 2]> = SmallVec::new();
    if param_index_of.is_empty() {
        return result;
    }

    for block in &ssa.blocks {
        for inst in &block.body {
            let SsaOp::Call {
                callee,
                callee_text,
                args,
                ..
            } = &inst.op
            else {
                continue;
            };
            let assert_name =
                crate::labels::bare_method_name(callee_text.as_deref().unwrap_or(callee.as_str()))
                    .to_ascii_lowercase();
            if !is_assert_true_callee(&assert_name) {
                continue;
            }

            // The asserted boolean is the assert call's first argument group.
            let Some(group) = args.first() else {
                continue;
            };

            // Case A — collapsed method form (`Assert.isTrue(x.startsWith(dir))`).
            // SSA lowering flattens the chained receiver-method call into this
            // arg group: the receiver, the `startsWith` method name (surviving
            // only as a synthetic-param leaf), and the prefix argument all
            // appear as ordered leaves.  Split at the method phantom.  This is
            // the dominant Java/Spring shape; the `startsWith` never survives
            // as a distinct SSA Call op.
            let confined =
                confined_params_from_collapsed_assert_group(ssa, consts, param_index_of, group);
            if !confined.is_empty() {
                for p in confined {
                    if !result.contains(&p) {
                        result.push(p);
                    }
                }
                continue;
            }

            // Case B — clean Call form (function-style, e.g. Go
            // `strings.HasPrefix(p, dir)`): arg0's def is a distinct
            // startsWith/hasPrefix Call.  Follow single-operand Assign copies
            // to it, exactly as the return-value detector follows a return.
            let Some(&cond_v) = group.first() else {
                continue;
            };
            let mut cur = cond_v;
            let mut hops = 0;
            let def = loop {
                match op_for_value(ssa, cur) {
                    Some(SsaOp::Assign(uses)) if uses.len() == 1 && hops < 8 => {
                        cur = uses[0];
                        hops += 1;
                    }
                    other => break other,
                }
            };
            let Some(SsaOp::Call {
                callee: c2,
                callee_text: ct2,
                args: a2,
                receiver: r2,
            }) = def
            else {
                continue;
            };
            for p in prefix_confinement_params(
                ssa,
                consts,
                param_index_of,
                c2.as_str(),
                ct2.as_deref(),
                *r2,
                a2,
            ) {
                if !result.contains(&p) {
                    result.push(p);
                }
            }
        }
    }

    result
}

/// Detect a `Result`-returning *rejection-guard* and the formal parameters it
/// rejects: parameters that reach an `Err(...)` construction in the body.  Such
/// a function returns `Err` on (rather than transforms) its argument, so any
/// *normal* completion of a call to it proves the argument satisfied the
/// guard.  Recorded name-independently in
/// [`SsaFuncSummary::result_reject_guard_params`].
///
/// Path-specificity is applied later, at the call site, by
/// `apply_path_validator_confinement`: only a callee whose bare name matches
/// the path-safety-validator grammar (`ensure_safe_path_component`,
/// `validate_safe_path`, …) confines `Cap::FILE_IO` on the rejected argument.
/// This split is forced by SSA reality — the path-traversal sentinels the guard
/// rejects (`".."`, `'/'`, `'\\'`) are collapsed out of the SSA body by
/// boolean-expression lowering (a `component == ".." || component.chars().any(
/// |c| matches!(c, '/' | '\\'))` guard lowers to a single aggregate `Call` with
/// no surviving string/char constants), and the branch condition text is only
/// the bound flag (`is_unsafe`), so no structural path token survives.  The
/// `?`-guarded call (`ensure_safe_path_component(&segment)?`) also never becomes
/// a branch condition (`?` lowers to a discarded `Call`), so the
/// `classify_condition` `ValidationCall` machinery never engages.
///
/// Motivated by CVE-2026-53956 (rattler package-cache path traversal).
fn detect_result_reject_guard_params(
    ssa: &SsaBody,
    param_index_of: &HashMap<SsaValue, usize>,
) -> SmallVec<[usize; 2]> {
    let mut result: SmallVec<[usize; 2]> = SmallVec::new();
    if param_index_of.is_empty() {
        return result;
    }

    let mut budget = 512u32;
    let mut constructs_err = false;
    for block in &ssa.blocks {
        for inst in &block.body {
            let SsaOp::Call {
                callee,
                callee_text,
                args,
                ..
            } = &inst.op
            else {
                continue;
            };
            if crate::labels::bare_method_name(callee_text.as_deref().unwrap_or(callee.as_str()))
                != "Err"
            {
                continue;
            }
            constructs_err = true;
            // Params reaching the rejected error's operands are the rejected
            // parameters (`Err(InvalidPathComponentError { value: component
            // .to_string() })` carries `component`).
            for group in args {
                for &u in group {
                    let mut seen = HashSet::new();
                    collect_reaching_params(
                        ssa,
                        u,
                        param_index_of,
                        &mut seen,
                        &mut result,
                        &mut budget,
                    );
                }
            }
        }
    }

    // A single-parameter rejection guard whose `Err` does not carry the
    // parameter (`Err("bad component")`) still rejects that sole parameter.
    if constructs_err && result.is_empty() && param_index_of.len() == 1 {
        if let Some(&idx) = param_index_of.values().next() {
            result.push(idx);
        }
    }

    result
}

/// Whether a callee bare name matches the *path-safety-validator* grammar: a
/// function whose name declares it checks a value is a safe path / path
/// component / filename (`ensure_safe_path_component`, `validate_safe_path`,
/// `is_safe_filename`, `check_path_component`, …).  Snake-cased and matched on
/// token co-occurrence, not a per-callee list, so it generalises across the
/// naming conventions real path validators use.  Consumed by
/// `apply_path_validator_confinement`.
pub(crate) fn is_path_safety_validator_name(bare: &str) -> bool {
    let snake = crate::taint::path_state::to_snake_lower(bare);
    // Explicit compound tokens that are unambiguously path-safety validators.
    if snake.contains("safe_path")
        || snake.contains("path_component")
        || snake.contains("safe_component")
        || snake.contains("safe_filename")
        || snake.contains("safe_file_name")
        || snake.contains("safe_segment")
        || snake.contains("no_traversal")
        || snake.contains("reject_traversal")
        || snake.contains("path_traversal")
    {
        return true;
    }
    // Co-occurrence: a "safe"/validation verb together with a path noun.
    let has_safe_verb = snake.contains("safe")
        || snake.contains("valid")
        || snake.contains("ensure")
        || snake.contains("check")
        || snake.contains("sanit");
    let has_path_noun = snake.contains("path")
        || snake.contains("component")
        || snake.contains("filename")
        || snake.contains("file_name")
        || snake.contains("basename")
        || snake.contains("dirname")
        || snake.contains("segment");
    // Require a *safe* signal for the noun co-occurrence form: a bare
    // `validate_component` (no safety word) is too weak, but `safe` + noun, or
    // `ensure`/`check`/`sanit` + `path`-family noun, is a real validator idiom.
    has_safe_verb
        && has_path_noun
        && (snake.contains("safe") || snake.contains("path") || snake.contains("sanit"))
}

/// Reconstruct the confined formal-parameter indices from a *collapsed*
/// prefix-containment assertion argument group.
///
/// When `Assert.isTrue(subject.startsWith(prefix), msg)` lowers, the chained
/// `subject.startsWith(prefix)` receiver-method call flattens into the assert
/// call's first argument group as ordered leaves — the subject receiver's
/// operands, then the `startsWith` method name (as a synthetic-param leaf),
/// then the prefix operands — with no surviving `startsWith` SSA Call.  Split
/// the group at the method-name phantom: leaves before it are the *subject*,
/// leaves after are the *prefix*.  A `true` result confines the formal params
/// reaching the subject, provided the prefix is fixed (reaches no formal param
/// — a param-derived prefix is attacker-influenced and proves nothing).
///
/// Returns the confined subject params, or empty when the group is not a
/// collapsed prefix-containment check or the prefix is param-derived.
fn confined_params_from_collapsed_assert_group(
    ssa: &SsaBody,
    consts: &crate::ssa::const_prop::ConstValues,
    param_index_of: &HashMap<SsaValue, usize>,
    group: &[SsaValue],
) -> SmallVec<[usize; 2]> {
    use crate::ssa::const_prop::ConstLattice;
    let mut result: SmallVec<[usize; 2]> = SmallVec::new();

    // Locate the (last) prefix-containment method-name phantom leaf.
    let is_prefix_method = |v: SsaValue| -> bool {
        ssa.value_defs
            .get(v.0 as usize)
            .and_then(|vd| vd.var_name.as_deref())
            .map(|n| {
                matches!(
                    n.to_ascii_lowercase().as_str(),
                    "startswith" | "start_with?" | "hasprefix"
                )
            })
            .unwrap_or(false)
    };
    let Some(mi) = group.iter().rposition(|&v| is_prefix_method(v)) else {
        return result;
    };
    let subject_vals = &group[..mi];
    let prefix_vals = &group[mi + 1..];

    let mut budget = 512u32;

    // Prefix must be fixed: no non-const prefix leaf reaches a formal param.
    let mut prefix_params: SmallVec<[usize; 2]> = SmallVec::new();
    for &pv in prefix_vals {
        if matches!(consts.get(&pv), Some(ConstLattice::Str(_))) {
            continue;
        }
        let mut seen = HashSet::new();
        collect_reaching_params(
            ssa,
            pv,
            param_index_of,
            &mut seen,
            &mut prefix_params,
            &mut budget,
        );
    }
    if !prefix_params.is_empty() {
        return result;
    }

    // Subject formal params are confined by a `true` result.
    let mut subj_params: SmallVec<[usize; 2]> = SmallVec::new();
    for &sv in subject_vals {
        if is_prefix_method(sv) {
            continue;
        }
        let mut seen = HashSet::new();
        collect_reaching_params(
            ssa,
            sv,
            param_index_of,
            &mut seen,
            &mut subj_params,
            &mut budget,
        );
    }
    for p in subj_params {
        if !prefix_params.contains(&p) && !result.contains(&p) {
            result.push(p);
        }
    }
    result
}

/// Detect a *return-value path-prefix confiner* (CVE-2020-5221, uftpd).
///
/// Recognises a function whose *every* non-null return is guarded by a C
/// prefix-containment check (`strncmp(rv, prefix, strlen(prefix))`) on the
/// *returned* value, so any non-null path it returns is provably contained
/// under a fixed directory prefix.  Consumed at the call site by
/// `apply_call_return_confinement`, which clears [`Cap::FILE_IO`] from the
/// call result.
///
/// This is the interprocedural analogue of the intra-function
/// [`crate::taint::path_state::PredicateKind::PathPrefixConfined`] narrowing.
/// The runtime narrowing clears `FILE_IO` from the confined *value* on the
/// surviving branch, but in the uftpd shape the returned `rpath` is a `static`
/// buffer written by a condition-embedded `realpath(dir, rpath)` — which lowers
/// to a `nop`, so `rpath` never joins the tainted-parameter SSA chain.  The
/// summary's return-caps then come from the param-taint fallback (the source
/// parameter's `Cap::all`, re-attributed to the return), which the branch
/// narrowing on `rpath` never touches.  Recording the confinement as a summary
/// post-condition carries it across the return into the caller.
///
/// The vulnerable uftpd form `strncmp(dir, home, …)` confines a *different* var
/// (`dir`) than the returned `rpath`, so `subject != return-value name` and
/// this returns `false` — the exact bug/fix discriminator.  Conservative: a
/// single non-null return that is not confined means the function can leak an
/// unconfined path, so it is not a confiner.
///
/// A second, *transitive* case handles the thin-wrapper hop the uftpd flow
/// routes through (`compose_abspath` just `return compose_path(...)`): a
/// non-null return whose value is a call to a callee that itself
/// `confines_path_return` is also confined.  This case fires only in the
/// augmented re-extraction pass (where `ssa_summaries` carries the callee's
/// first-pass flag); the merge back into the persisted summary is via
/// `merge_sink_fields`.
pub(crate) fn detect_path_confined_return(
    ssa: &SsaBody,
    cfg: &Cfg,
    ssa_summaries: Option<
        &HashMap<crate::symbol::FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    lang: Lang,
) -> bool {
    use crate::taint::path_state::{PredicateKind, classify_condition_with_target};

    // Confined edges: for each `PathPrefixConfined` branch, the block reached
    // when the prefix check *passes* (`strncmp == 0`), paired with the confined
    // subject name.  The passing edge is the FALSE block (the reject sits in the
    // `if (strncmp(...)) return NULL;` body), inverted under a leading `!`
    // (`condition_negated`) — mirroring the runtime `apply_branch_predicates`
    // polarity for `PredicateKind::PathPrefixConfined`.
    let mut confined_edges: SmallVec<[(crate::ssa::ir::BlockId, String); 4]> = SmallVec::new();
    for block in &ssa.blocks {
        let Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            ..
        } = &block.terminator
        else {
            continue;
        };
        let Some(cond_info) = cfg.node_weight(*cond) else {
            continue;
        };
        let Some(text) = cond_info.condition_text.as_deref() else {
            continue;
        };
        let (kind, target) = classify_condition_with_target(text);
        if kind != PredicateKind::PathPrefixConfined {
            continue;
        }
        let Some(subject) = target else {
            continue;
        };
        let confined_blk = if cond_info.condition_negated {
            *true_blk
        } else {
            *false_blk
        };
        confined_edges.push((confined_blk, subject));
    }

    // NB: do not early-return when `confined_edges` is empty — a thin wrapper
    // (`return compose_path(...)`) has no `strncmp` branch of its own yet is
    // still a confiner via the transitive passthrough case below.

    let mut confined_any = false;
    for block in &ssa.blocks {
        let Terminator::Return(Some(rv)) = &block.terminator else {
            continue;
        };
        // NULL / constant rejection returns carry no path taint — skip.
        if rv_traces_to_constant(ssa, *rv, &HashSet::new(), 0, &mut 256) {
            continue;
        }
        // Transitive passthrough: `return confining_helper(...)`.
        if return_block_is_confining_passthrough(ssa, block, *rv, ssa_summaries, lang) {
            confined_any = true;
            continue;
        }
        let Some(name) = return_value_subject_name(ssa, *rv) else {
            return false;
        };
        let confined = confined_edges
            .iter()
            .any(|(blk, subj)| *blk == block.id && *subj == name);
        if !confined {
            return false;
        }
        confined_any = true;
    }
    confined_any
}

/// Whether a return block is a thin-wrapper passthrough of a
/// `confines_path_return` helper (`return compose_path(...)`), resolved against
/// the intra-file `ssa_summaries` map by same-language bare callee name.  Fires
/// only in the augmented re-extraction pass (`ssa_summaries` present).
///
/// Two forms:
///  1. the return value traces (through single-operand `Assign` copies) to a
///     `Call` op — the clean, pre-optimisation shape; and
///  2. the return value is a disconnected `Nop` (the SSA optimiser rewrites
///     `v = assign(call_result); return v` to `v = nop; return v`, severing the
///     use-def link to the call), in which case the return block's body is
///     scanned for a confining `Call`.  Sound because it always resolves the
///     *callee's* `confines_path_return` flag: a wrapper of a non-confiner (the
///     vulnerable uftpd form where `compose_path` confines `dir`, not the
///     returned `rpath`) stays unconfined.
fn return_block_is_confining_passthrough(
    ssa: &SsaBody,
    block: &crate::ssa::ir::SsaBlock,
    rv: SsaValue,
    ssa_summaries: Option<
        &HashMap<crate::symbol::FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    lang: Lang,
) -> bool {
    let Some(map) = ssa_summaries else {
        return false;
    };
    let callee_confines = |callee: &str, callee_text: Option<&str>| -> bool {
        let bare = crate::labels::bare_method_name(callee_text.unwrap_or(callee));
        map.iter()
            .any(|(key, sum)| key.lang == lang && key.name == bare && sum.confines_path_return)
    };

    // Form 1: return value traces to a Call.
    let mut cur = rv;
    let mut hops = 0;
    loop {
        match op_for_value(ssa, cur) {
            Some(SsaOp::Assign(uses)) if uses.len() == 1 && hops < 8 => {
                cur = uses[0];
                hops += 1;
            }
            Some(SsaOp::Call {
                callee,
                callee_text,
                ..
            }) => {
                return callee_confines(callee, callee_text.as_deref());
            }
            // Form 2: the return value is a disconnected `Nop` (optimiser
            // artifact).  Scan this block's body for a confining Call.
            Some(SsaOp::Nop) | None => {
                return block.body.iter().any(|inst| {
                    if let SsaOp::Call {
                        callee,
                        callee_text,
                        ..
                    } = &inst.op
                    {
                        callee_confines(callee, callee_text.as_deref())
                    } else {
                        false
                    }
                });
            }
            _ => return false,
        }
    }
}

/// Trace a return value through single-operand `Assign` copies to the name of
/// the returned storage.  `return rpath` lowers to `Assign(rpath_val)` where
/// the `rpath` name lives on the copied value, so the first hop reveals it.
/// Returns the first `var_name` found, or `None` for a bare temporary /
/// constant return with no name.
fn return_value_subject_name(ssa: &SsaBody, rv: SsaValue) -> Option<String> {
    let mut cur = rv;
    let mut hops = 0;
    loop {
        if let Some(name) = ssa
            .value_defs
            .get(cur.0 as usize)
            .and_then(|vd| vd.var_name.as_deref())
        {
            return Some(name.to_string());
        }
        match op_for_value(ssa, cur) {
            Some(SsaOp::Assign(uses)) if uses.len() == 1 && hops < 8 => {
                cur = uses[0];
                hops += 1;
            }
            _ => return None,
        }
    }
}

/// Detect a *relative-URL confiner*: a helper whose return value is provably a
/// same-origin (relative) URL, so redirecting to it cannot leave the trusted
/// origin.
///
/// Recognises the WHATWG-correct confinement shape as three co-occurring
/// behaviours in the function body, plus a parameter-derived return:
///
/// ```text
/// const normalize_relative_url = (url) => {
///   if (typeof url !== "string") return null;
///   const normalised = url.replace(/\\/g, "/").trimStart();   // (1) normalise `\`->`/`
///   if (normalised.startsWith("//")) return null;             // (2) reject protocol-relative
///   if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(normalised)) return null;  // (3) reject scheme:
///   return normalised;                                        // param-derived return
/// };
/// ```
///
///  1. a `.replace(...)` normalisation call (backslash-to-slash rewriting is
///     what defeats the `/\evil.com` bypass — required for soundness, since a
///     confiner that skips it still leaks through a browser `\`->`/` rewrite),
///  2. a `startsWith("//")` protocol-relative rejection (const `"//"` arg), and
///  3. a scheme rejection expressed as a regex `.test(...)` call.
///
/// All three together, with at least one return path carrying a
/// parameter-derived value, mark the return as OPEN_REDIRECT-confined.
///
/// Conservative by construction: the *weak* validator
/// `!url.includes("//") && !url.includes(":/")` matches none of these — it uses
/// `.includes` (substring, not prefix) and never normalises backslashes — so a
/// redirect gated only by it still fires.  Motivated by CVE-2026-42259
/// (Saltcorn login open redirect): the patched `normalize_relative_url` is
/// recognised here and stops the patched code from false-positiving.
fn detect_open_redirect_normalizer(
    ssa: &SsaBody,
    cfg: &Cfg,
    param_index_of: &HashMap<SsaValue, usize>,
) -> bool {
    if param_index_of.is_empty() {
        return false;
    }

    let mut has_normalize_replace = false;
    let mut has_protocol_relative_reject = false;
    let mut has_scheme_reject = false;

    // (1) Backslash-normalisation `.replace(...)` — appears as an SSA Call
    // whose textual callee carries the `.replace(` chain segment (the outer
    // `.trimStart()` swallows the method name, so match on the callee string
    // rather than the bare terminal method).
    for block in &ssa.blocks {
        for inst in &block.body {
            let SsaOp::Call {
                callee,
                callee_text,
                ..
            } = &inst.op
            else {
                continue;
            };
            let text = callee_text.as_deref().unwrap_or(callee.as_str());
            if text.to_ascii_lowercase().contains(".replace(") {
                has_normalize_replace = true;
            }
        }
    }

    // (2)+(3) Protocol-relative and scheme rejections live in `if (...)`
    // conditions (`Branch` terminators), whose text the CFG node carries in
    // `condition_text`.
    for block in &ssa.blocks {
        let Terminator::Branch { cond, .. } = &block.terminator else {
            continue;
        };
        let Some(text) = cfg
            .node_weight(*cond)
            .and_then(|n| n.condition_text.as_deref())
        else {
            continue;
        };
        let lower = text.to_ascii_lowercase();
        // Prefix-based protocol-relative rejection: `x.startsWith("//")`
        // (NOT the weak `.includes("//")` substring form).
        if lower.contains("startswith(\"//\")") || lower.contains("startswith('//')") {
            has_protocol_relative_reject = true;
        }
        // Scheme rejection: a regex `.test(...)` whose pattern pins a
        // `scheme:` (the `:` marker distinguishes it from an unrelated regex).
        if lower.contains(".test(") && lower.contains(':') {
            has_scheme_reject = true;
        }
    }

    if !(has_normalize_replace && has_protocol_relative_reject && has_scheme_reject) {
        return false;
    }

    // At least one return path must carry a parameter-derived (normalised)
    // value — the confined result the caller redirects to.  Pure-`null`
    // reject returns don't count.
    let mut budget = 512u32;
    for block in &ssa.blocks {
        let Terminator::Return(Some(rv)) = &block.terminator else {
            continue;
        };
        let mut seen = HashSet::new();
        let mut params: SmallVec<[usize; 2]> = SmallVec::new();
        collect_reaching_params(
            ssa,
            *rv,
            param_index_of,
            &mut seen,
            &mut params,
            &mut budget,
        );
        if !params.is_empty() {
            return true;
        }
    }

    false
}

/// True when a branch `condition_text` invokes an open-redirect URL-safety
/// validator (`is_safe_redirect_url(url)`,
/// `url_has_allowed_host_and_scheme(url=next, ...)`).  Scans every `<ident>(`
/// call head and tests its leaf name against
/// [`is_open_redirect_validator_name`].
fn condition_calls_open_redirect_validator(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'(' {
            continue;
        }
        let mut j = i;
        while j > 0 {
            let c = bytes[j - 1];
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
                j -= 1;
            } else {
                break;
            }
        }
        if j < i && is_redirect_safety_predicate_name(&text[j..i]) {
            return true;
        }
    }
    false
}

/// Whether the branch condition is a leading negation (`not X` / `!X`), which
/// flips which successor edge is the validated one.
fn condition_is_leading_negation(text: &str) -> bool {
    let t = text.trim_start();
    t.strip_prefix("not ").is_some() || t.strip_prefix('!').is_some_and(|r| !r.starts_with('='))
}

/// Whether block `r` is dominated by block `t` in `ssa` — every path from the
/// entry block to `r` passes through `t`.  Computed as: `r` is unreachable from
/// the entry once `t` is deleted from the block graph.  Operates on
/// [`crate::ssa::ir::BlockId`] values verbatim (which are not assumed equal to
/// `Vec` positions).
fn block_dominated_by(ssa: &SsaBody, r: u32, t: u32) -> bool {
    if r == t {
        return true;
    }
    let Some(entry) = ssa.blocks.first().map(|b| b.id.0) else {
        return false;
    };
    if r == entry {
        return false;
    }
    let mut visited: HashSet<u32> = HashSet::new();
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        if b == t || !visited.insert(b) {
            continue;
        }
        if let Some(blk) = ssa.blocks.iter().find(|x| x.id.0 == b) {
            for s in &blk.succs {
                stack.push(s.0);
            }
        }
    }
    !visited.contains(&r)
}

/// Detect a *guarded-passthrough open-redirect confiner*: a helper that returns
/// its URL parameter only on the validated branch of a URL-safety guard, and a
/// constant otherwise.
///
/// Shape (Flask-AppBuilder CVE-2022-24776 `get_safe_redirect`):
///
/// ```python
/// def get_safe_redirect(url):
///     if url and is_safe_redirect_url(url):   # URL-safety guard
///         return url                          # param-derived return
///     return "/"                              # constant fallback
/// ```
///
/// Every param-derived return block must be **dominated by the validated edge**
/// of a guard whose condition calls a recognised open-redirect validator
/// ([`is_open_redirect_validator_name`]) and mentions the returned parameter, so
/// the parameter can only escape after passing validation — the return is
/// provably OPEN_REDIRECT-safe.  Sound by construction: an unguarded return of
/// the parameter (dominance fails) or a guard on an unrelated variable (name tie
/// fails) leaves the confiner unrecognised, so the redirect still fires.
///
/// Complements [`detect_open_redirect_normalizer`] (the JS backslash-normalise /
/// protocol-relative-reject shape, CVE-2026-42259): this recognises the
/// validate-then-passthrough shape common to Python/Flask/Django redirect
/// wrappers.  Motivated by CVE-2022-24776.
fn detect_open_redirect_guarded_passthrough(
    ssa: &SsaBody,
    cfg: &Cfg,
    param_index_of: &HashMap<SsaValue, usize>,
) -> bool {
    if param_index_of.is_empty() {
        return false;
    }

    // Map param index -> source-level name (to tie a guard to the return it
    // protects).
    let mut param_name: HashMap<usize, String> = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = inst.op {
                if let Some(n) = &inst.var_name {
                    param_name.entry(index).or_insert_with(|| n.clone());
                }
            }
        }
    }

    // (1) Param-derived return blocks + the param indices they carry.
    let mut param_returns: SmallVec<[(u32, SmallVec<[usize; 2]>); 2]> = SmallVec::new();
    let mut budget = 512u32;
    for block in &ssa.blocks {
        let Terminator::Return(Some(rv)) = &block.terminator else {
            continue;
        };
        let mut seen = HashSet::new();
        let mut params: SmallVec<[usize; 2]> = SmallVec::new();
        collect_reaching_params(
            ssa,
            *rv,
            param_index_of,
            &mut seen,
            &mut params,
            &mut budget,
        );
        if !params.is_empty() {
            param_returns.push((block.id.0, params));
        }
    }
    if param_returns.is_empty() {
        return false;
    }

    // (2) URL-safety guard branches -> (validated-edge block id, condition text).
    let mut guards: SmallVec<[(u32, String); 2]> = SmallVec::new();
    for block in &ssa.blocks {
        let Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            ..
        } = &block.terminator
        else {
            continue;
        };
        let Some(text) = cfg
            .node_weight(*cond)
            .and_then(|n| n.condition_text.as_deref())
        else {
            continue;
        };
        if condition_calls_open_redirect_validator(text) {
            let validated = if condition_is_leading_negation(text) {
                false_blk
            } else {
                true_blk
            };
            guards.push((validated.0, text.to_string()));
        }
    }
    if guards.is_empty() {
        return false;
    }

    // (3) Every param-derived return must be dominated by the validated edge of
    //     some guard whose condition names one of the returned params.
    for (rblk, params) in &param_returns {
        let names: SmallVec<[&str; 2]> = params
            .iter()
            .filter_map(|i| param_name.get(i).map(String::as_str))
            .collect();
        let confined = guards.iter().any(|(vblk, gtext)| {
            let ties = names.is_empty() || names.iter().any(|n| gtext.contains(n));
            ties && block_dominated_by(ssa, *rblk, *vblk)
        });
        if !confined {
            return false;
        }
    }
    true
}

/// Extract a precise per-parameter `SsaFuncSummary` from an already-lowered SSA body.
///
/// For each parameter (up to `MAX_PROBE_PARAMS`), runs a taint probe by seeding
/// that parameter with `Cap::all()` via `global_seed` and observing what caps
/// survive to return positions and which sinks fire.  A final probe with no params
/// tainted detects intrinsic source caps.
#[allow(clippy::too_many_arguments)]
pub fn extract_ssa_func_summary(
    ssa: &SsaBody,
    cfg: &Cfg,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    lang: Lang,
    namespace: &str,
    interner: &crate::state::symbol::SymbolInterner,
    param_count: usize,
    module_aliases: Option<&HashMap<SsaValue, SmallVec<[String; 2]>>>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
    formal_param_names: Option<&[String]>,
    formal_destructured_fields: Option<&[Vec<String>]>,
    param_types: Option<&[Option<TypeKind>]>,
) -> crate::summary::ssa_summary::SsaFuncSummary {
    extract_ssa_func_summary_full(
        ssa,
        cfg,
        local_summaries,
        global_summaries,
        lang,
        namespace,
        interner,
        param_count,
        module_aliases,
        locator,
        formal_param_names,
        None,
        formal_destructured_fields,
        param_types,
        None,
    )
}

/// Like [`extract_ssa_func_summary`] but allows passing an in-progress
/// `ssa_summaries` map so the per-parameter probes can resolve callee
/// SSA summaries via step 0 of `resolve_callee_full`.
///
/// This enables transitive cross-function summary propagation: when a
/// caller's body references a callee whose summary was just augmented
/// by the closure-capture lift pass, the caller's probe sees the
/// augmented `param_to_sink` and can propagate it onto the caller's
/// own summary. Used by `lower_all_functions_from_bodies`'s second
/// extraction pass after `augment_summaries_with_child_sinks`.
#[allow(clippy::too_many_arguments)]
pub fn extract_ssa_func_summary_full(
    ssa: &SsaBody,
    cfg: &Cfg,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    lang: Lang,
    namespace: &str,
    interner: &crate::state::symbol::SymbolInterner,
    param_count: usize,
    module_aliases: Option<&HashMap<SsaValue, SmallVec<[String; 2]>>>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
    formal_param_names: Option<&[String]>,
    ssa_summaries: Option<
        &HashMap<crate::symbol::FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    // Per-parameter destructured-binding sibling names.  Entry `i` is
    // the list of field names destructured by the same call-site arg
    // slot as the primary `formal_param_names[i]`, excluding the
    // primary name.  Empty vec for non-destructured params; `None` for
    // callers that don't carry destructure info (legacy / test paths).
    // Drives the destructured-arg expansion in the per-param probe so
    // taint flow through sibling bindings is visible to summary
    // extraction (CVE-2026-25544 / @payloadcms/drizzle SQLi).
    formal_destructured_fields: Option<&[Vec<String>]>,
    // BodyMeta.param_types parallel-vec.  When supplied, drives a local
    // `analyze_types_with_param_types` pass so the per-parameter probe's
    // `SsaTaintTransfer.type_facts` is populated.  Without this, helper
    // bodies whose sinks are recognised only via type-qualified callee
    // resolution (`receiver_type.label_prefix() + "." + method`, e.g.
    // `DatabaseConnection.execute` for JDBC `Statement.execute`) silently
    // drop the sink during summary extraction even though the same
    // callee is correctly classified by the post-optimise transfer in
    // `transfer_inst`.  Surfaced by GHSA-h8cj-hpmg-636v (Appsmith
    // FilterDataServiceCE.dropTable: helper `executeDbQuery(query)`
    // routes the SQL string through `statement.execute(query)` whose
    // SQL_QUERY caps were invisible to the param-1 probe).  `None` for
    // legacy / test paths preserves prior behaviour.
    param_types: Option<&[Option<TypeKind>]>,
    base_aliases: Option<&crate::ssa::alias::BaseAliasResult>,
) -> crate::summary::ssa_summary::SsaFuncSummary {
    // The baseline probe and one probe per parameter all consult the same
    // summary map; let them share one scan of it.
    let _confinement = super::ConfinementGatesScope::enter(ssa_summaries, lang);

    // Pre-compute type facts on the un-optimised SSA body so the per-param
    // probe can resolve sinks that depend on receiver-type inference.
    // Empty const_values: this runs *before* the optimiser, so const-prop
    // refinements aren't available yet, but the pass-1 instruction-shape
    // typing (Source/Param/Call→constructor_type) and the second-pass
    // Assign/Phi propagation are sufficient for the JDBC chain
    // `Statement s = conn.createStatement(); s.execute(q);` to type `s`
    // as `DatabaseConnection`.
    let local_type_facts: Option<TypeFactResult> = param_types.map(|pt| {
        let empty_consts = crate::ssa::const_prop::ConstValues::default();
        analyze_types_with_param_types(ssa, cfg, &empty_consts, Some(lang), pt)
    });
    let local_type_facts_ref: Option<&TypeFactResult> = local_type_facts.as_ref();
    let probe_const_values = crate::ssa::const_prop::const_propagate(ssa).values;
    let probe_points_to = crate::ssa::heap::analyze_points_to(ssa, cfg, Some(lang));
    use crate::summary::SinkSite;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let effective_params = param_count.min(MAX_PROBE_PARAMS);

    // Collect (param_index, var_name, ssa_value) from the SSA body
    let mut param_info: Vec<(usize, String, SsaValue)> = Vec::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = &inst.op {
                if *index < effective_params {
                    if let Some(name) = inst.var_name.as_ref() {
                        param_info.push((*index, name.clone(), inst.value));
                    }
                }
            }
        }
    }

    // Identify return-reaching blocks
    let return_blocks: Vec<usize> = ssa
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b.terminator, Terminator::Return(_)))
        .map(|(i, _)| i)
        .collect();

    // Collect all param SSA values to exclude from return cap collection.
    // Param values persist with their seeded taint throughout the function ,
    // we only want caps on derived values (call results, assigns) at return.
    let all_param_values: std::collections::HashSet<SsaValue> =
        param_info.iter().map(|(_, _, v)| *v).collect();

    // For each return block whose returned value is not itself a parameter:
    // the parameters that value depends on (see
    // [`return_reaching_param_values`]), first stopping at sanitizer calls and
    // then crossing them.  Independent of the probe seed, so computed once.
    // `None` for a walk means it ran out of budget.
    let reach_by_block: HashMap<usize, ReturnReach> = {
        let mut calls_by_receiver: HashMap<SsaValue, SmallVec<[SsaValue; 2]>> = HashMap::new();
        for block in &ssa.blocks {
            for inst in &block.body {
                if let SsaOp::Call {
                    receiver: Some(r), ..
                } = &inst.op
                {
                    calls_by_receiver.entry(*r).or_default().push(inst.value);
                }
            }
        }
        return_blocks
            .iter()
            .filter_map(|&bid| match &ssa.blocks[bid].terminator {
                Terminator::Return(Some(rv)) if !all_param_values.contains(rv) => {
                    let walk = |stop| {
                        return_reaching_param_values(
                            ssa,
                            cfg,
                            *rv,
                            &all_param_values,
                            &calls_by_receiver,
                            stop,
                        )
                    };
                    Some((
                        bid,
                        ReturnReach {
                            direct: walk(true),
                            through_sanitizers: walk(false),
                        },
                    ))
                }
                _ => None,
            })
            .collect()
    };

    // Per-return-block observation captured alongside the aggregate return
    // caps.  Each entry records one return block's exit state, caps
    // contributed on that path, path-predicate hash, known_true/false bits,
    // and the return SSA value's abstract fact, so the per-param loop can
    // emit one [`ReturnPathTransform`] per distinct predicate gate.
    struct ReturnBlockObs {
        /// Caps at the return SSA value (or joined live values for
        /// implicit returns) on this block's exit.
        derived_caps: Cap,
        /// Caps collected from parameter values reaching this return
        /// (passthrough fallback).
        param_caps: Cap,
        /// Deterministic hash of the predicate gate at this return.
        /// `0` means "no predicate gate", an unguarded return.
        predicate_hash: u64,
        /// `PredicateSummary::known_true` bits intersected across all
        /// tracked variables at this return.  Encoded via
        /// [`crate::taint::domain::predicate_kind_bit`].
        known_true: u8,
        /// `PredicateSummary::known_false` bits at this return.
        known_false: u8,
        /// Abstract fact on the return SSA value at this return (None
        /// when Top or abstract interp disabled).
        abstract_value: Option<crate::abstract_interp::AbstractValue>,
        /// [`crate::abstract_interp::PathFact`] on the return SSA value
        /// at this block's exit.  Top when abstract interp is disabled
        /// or no narrowing was proved on this path.
        path_fact: crate::abstract_interp::PathFact,
        /// Inner [`PathFact`] when the rv on this path is a one-arg
        /// variant constructor; [`None`] otherwise.
        variant_inner_fact: Option<crate::abstract_interp::PathFact>,
        /// `true` when the per-param probe's seeded parameter var_name
        /// is in this return block's exit `validated_must`.  `false`
        /// for the baseline (no-seed) probe and for params not
        /// validated on this path.  Drives
        /// `validated_params_to_return` summary extraction.
        param_validated_must: bool,
    }

    // Helper: run a taint probe with a given global_seed and return
    // the aggregate return caps, sink events, joined return abstract,
    // and the per-return-block observation list used to derive
    // per-return-path transforms.
    //
    // `probe_param_names` lists the seeded parameter's `var_name`
    // plus any destructured-binding siblings sharing the slot
    // (`None` for the baseline source-caps probe).  When non-empty,
    // each return-block observation records whether ANY of those
    // names is in the exit state's `validated_must`, which feeds
    // `validated_params_to_return` summary extraction below.  The
    // any-name semantics matches the slot-wide model: a destructured
    // formal `({ a, b, c })` represents one call-site slot, and any
    // sibling reaching `validated_must` proves the slot's caps were
    // narrowed before reaching the return.
    let run_probe = |seed: HashMap<BindingKey, VarTaint>,
                     probe_param_names: Option<&[&str]>|
     -> (
        Cap,
        Vec<SsaTaintEvent>,
        Option<crate::abstract_interp::AbstractValue>,
        Vec<ReturnBlockObs>,
    ) {
        let seed_ref = if seed.is_empty() { None } else { Some(&seed) };
        let dynamic_pts = std::cell::RefCell::new(std::collections::HashMap::new());
        let transfer = SsaTaintTransfer {
            lang,
            namespace,
            interner,
            local_summaries,
            global_summaries,
            interop_edges: &[],
            owner_body_id: BodyId(0),
            parent_body_id: None,
            global_seed: seed_ref,
            param_seed: None,
            receiver_seed: None,
            const_values: Some(&probe_const_values),
            type_facts: local_type_facts_ref,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries,
            extra_labels: None,
            base_aliases,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: Some(&probe_points_to),
            dynamic_pts: Some(&dynamic_pts),
            import_bindings: None,
            promisify_aliases: None,
            module_aliases,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
            cross_package_imports: None,
            entry_kind: None,
            param_route_capture: None,
            recording_summary: true,
        };

        let (events, block_states) = run_ssa_taint_full(ssa, cfg, &transfer);

        // Collect surviving caps at return blocks.
        // Separate param values from derived values: derived values give
        // more precise transforms (they reflect function-internal sanitization).
        // If only param values reach return → pure passthrough (Identity).
        let mut total_derived_caps = Cap::empty();
        let mut total_param_caps = Cap::empty();
        // Extract abstract value of the return SSA value.
        let mut return_abstract: Option<crate::abstract_interp::AbstractValue> = None;
        // Cleared when any reached return path yields no abstract fact (a
        // pass-through `return p` is Top).  The join over the remaining paths
        // would then describe only some returns, so the summary claims none.
        let mut every_return_has_abstract = true;
        // Per-return-block observations for per-path transforms.
        let mut per_return: Vec<ReturnBlockObs> = Vec::with_capacity(return_blocks.len());
        let confinement = crate::taint::ssa_transfer::compute_confinement_gates(&transfer);
        for &bid in &return_blocks {
            if let Some(entry) = &block_states[bid] {
                let empty_induction = HashSet::new();
                let exit = transfer_block(
                    &ssa.blocks[bid],
                    cfg,
                    ssa,
                    &transfer,
                    entry.clone(),
                    &empty_induction,
                    None,
                    confinement,
                );

                let ret_val = match &ssa.blocks[bid].terminator {
                    Terminator::Return(rv) => rv.as_ref().copied(),
                    _ => None,
                };

                let mut block_derived_caps = Cap::empty();
                let mut block_param_caps = Cap::empty();

                if let Some(rv) = ret_val {
                    // Explicit return value: use only its taint for derived_caps.
                    // If rv has no taint entry, this block contributes no derived caps.
                    if let Some(taint) = exit.get(rv) {
                        if all_param_values.contains(&rv) {
                            block_param_caps |= taint.caps;
                        } else {
                            block_derived_caps |= taint.caps;
                        }
                    }
                    // When rv is not a param value, also collect the caps of
                    // the parameters it depends on, tainted or not.  The SSA
                    // can lack an edge for a side effect the function really
                    // has (`lst.push(x); return lst`), so a parameter in rv's
                    // def-use closure keeps its caps.  A parameter outside it
                    // (`first(a, b) { return a }` probed for `b`) or one cut
                    // off by a sanitizer call (`return parseInt(s)`)
                    // contributes nothing.  When the closure walk ran out of
                    // budget, fall back to every live parameter, minus
                    // returns that trace only to constants.
                    match reach_by_block.get(&bid).map(|r| &r.direct) {
                        Some(Some(reaching)) => {
                            for (val, taint) in &exit.values {
                                if reaching.contains(val) {
                                    block_param_caps |= taint.caps;
                                }
                            }
                        }
                        Some(None)
                            if !rv_traces_to_constant(ssa, rv, &all_param_values, 0, &mut 256) =>
                        {
                            for (val, taint) in &exit.values {
                                if all_param_values.contains(val) {
                                    block_param_caps |= taint.caps;
                                }
                            }
                        }
                        _ => {}
                    }
                } else {
                    // Return(None): implicit return, fall back to all live values.
                    for (val, taint) in &exit.values {
                        if all_param_values.contains(val) {
                            block_param_caps |= taint.caps;
                        } else {
                            block_derived_caps |= taint.caps;
                        }
                    }
                }

                total_derived_caps |= block_derived_caps;
                total_param_caps |= block_param_caps;

                // Abstract return: use terminator's return value when available,
                // fall back to last instruction heuristic for Return(None).
                let mut block_abs: Option<crate::abstract_interp::AbstractValue> = None;
                let mut block_path_fact = crate::abstract_interp::PathFact::top();
                let mut block_variant_inner: Option<crate::abstract_interp::PathFact> = None;
                if let Some(ref abs) = exit.abstract_state {
                    let abs_rv = ret_val.or_else(|| {
                        ssa.blocks[bid]
                            .body
                            .last()
                            .or_else(|| ssa.blocks[bid].phis.last())
                            .map(|inst| inst.value)
                    });
                    if let Some(rv) = abs_rv {
                        let av = abs.get(rv);
                        block_path_fact = av.path.clone();
                        if !av.is_top() {
                            block_abs = Some(av.clone());
                            return_abstract = Some(match return_abstract {
                                None => av,
                                Some(prev) => prev.join(&av),
                            });
                        } else if return_carries_input(
                            ssa,
                            rv,
                            &all_param_values,
                            block_derived_caps,
                        ) {
                            // A return that can hold caller data has no fact,
                            // so the join over the other returns would not
                            // describe it.
                            every_return_has_abstract = false;
                        }
                        block_variant_inner = detect_variant_inner_fact(rv, ssa, &exit);
                    } else {
                        every_return_has_abstract = false;
                    }
                } else {
                    every_return_has_abstract = false;
                }

                // Derive a predicate hash + known-true/false
                // intersection across tracked variables at this return.
                // The hash is stable across runs for a given predicate
                // shape so call sites can compare paths deterministically.
                let (predicate_hash, known_true, known_false) = summarise_return_predicates(&exit);
                let param_validated_must = match probe_param_names {
                    Some(names) => names.iter().any(|name| match interner.get(name) {
                        Some(sym) => exit.validated_must.contains(sym),
                        None => false,
                    }),
                    None => false,
                };
                per_return.push(ReturnBlockObs {
                    derived_caps: block_derived_caps,
                    param_caps: block_param_caps,
                    predicate_hash,
                    known_true,
                    known_false,
                    abstract_value: block_abs,
                    path_fact: block_path_fact,
                    variant_inner_fact: block_variant_inner,
                    param_validated_must,
                });
            }
        }

        // Prefer derived caps; fall back to param caps for passthrough functions
        let return_caps = if !total_derived_caps.is_empty() {
            total_derived_caps
        } else {
            total_param_caps
        };

        // Drop return_abstract if it joined to Top, or if some return path
        // contributed nothing to the join.
        let return_abstract = return_abstract.filter(|v| every_return_has_abstract && !v.is_top());

        (return_caps, events, return_abstract, per_return)
    };

    // Probe with no params tainted → detect source_caps + return abstract.
    // Abstract values don't depend on taint seeding, so the baseline probe
    // captures the function's intrinsic abstract return value.
    let (baseline_return_caps, _baseline_events, return_abstract, baseline_obs) =
        run_probe(HashMap::new(), None);
    let source_caps = baseline_return_caps;

    // Per-return-path PathFact decomposition derived from the baseline
    // probe (no seeded taint).  Abstract facts on the return rv are
    // independent of taint seeding, they describe the function's
    // intrinsic narrowing, so the baseline run captures them without
    // per-param noise.
    //
    // Emitted only when ≥2 return-block entries have distinct predicate
    // hashes *and* at least one entry carries non-Top signal (fact or
    // variant_inner_fact).  A uniform all-Top list adds bytes without
    // helping any caller.
    let mut return_path_facts: SmallVec<[crate::summary::ssa_summary::PathFactReturnEntry; 2]> =
        SmallVec::new();
    if baseline_obs.len() >= 2 {
        let mut merged: SmallVec<[crate::summary::ssa_summary::PathFactReturnEntry; 2]> =
            SmallVec::new();
        for obs in &baseline_obs {
            let entry = crate::summary::ssa_summary::PathFactReturnEntry {
                predicate_hash: obs.predicate_hash,
                known_true: obs.known_true,
                known_false: obs.known_false,
                path_fact: obs.path_fact.clone(),
                variant_inner_fact: obs.variant_inner_fact.clone(),
            };
            crate::summary::ssa_summary::merge_path_fact_return_paths(&mut merged, &[entry]);
        }
        let distinct_hashes = merged
            .iter()
            .map(|e| e.predicate_hash)
            .collect::<std::collections::HashSet<_>>();
        let has_signal = merged
            .iter()
            .any(|e| !e.path_fact.is_top() || e.variant_inner_fact.is_some());
        if distinct_hashes.len() >= 2 && has_signal {
            return_path_facts = merged;
        }
    }

    // Probe each param
    let mut param_to_return = Vec::new();
    let mut param_to_sink: Vec<(usize, SmallVec<[SinkSite; 1]>)> = Vec::new();
    let mut param_to_sink_param = Vec::new();
    // Per-param gate-filter cap masks lifted from inner multi-gate sink calls.
    // Populated when the per-param probe reaches a sink whose CFG node carries
    // [`crate::cfg::CallMeta::gate_filters`] with more than one entry, the
    // multi-gate dispatch in `collect_block_events` has already cap-narrowed
    // `event.sink_caps` to the matching gate's `label_caps`, so we record the
    // pair as-is.  Cross-file callers consume this list to preserve per-position
    // cap attribution through wrapper functions like
    // `fn forward(url, body) { fetch(url, {body}) }`.
    let mut param_to_gate_filters: Vec<(usize, Cap)> = Vec::new();
    // Per-param return-path decomposition.  Populated only when the param
    // has ≥2 distinct return-block predicate hashes, a single-return-path
    // callee is already precise via `param_to_return`.
    let mut param_return_paths: Vec<(
        usize,
        SmallVec<[crate::summary::ssa_summary::ReturnPathTransform; 2]>,
    )> = Vec::new();
    // Parameter indices whose taint flow to the return is fully
    // validated by a dominating predicate on every return path.
    // Populated below by checking each per-param probe's return-block
    // exit states for `validated_must` containing the param's
    // var_name.  Empty when no parameter is validated.
    let mut validated_params_to_return: SmallVec<[usize; 2]> = SmallVec::new();

    for &(idx, ref var_name, param_val) in &param_info {
        let mut seed = HashMap::new();
        let origin = TaintOrigin {
            node: NodeIndex::new(0), // synthetic origin for probing
            source_kind: SourceKind::UserInput,
            source_span: None,
        };
        let probe_taint = VarTaint {
            caps: Cap::all(),
            origins: SmallVec::from_elem(origin, 1),
            uses_summary: false,
        };
        seed.insert(
            BindingKey::new(var_name.as_str(), BodyId(0)),
            probe_taint.clone(),
        );

        // Destructured-arg sibling expansion.  When the formal at slot
        // `idx` destructures an object pattern (`({ column, operator,
        // value })`), the SSA body emits a separate [`SsaOp::Param`]
        // for every destructured binding (sequential indices > slot
        // count, since the closure-capture pass treats them as
        // free-identifier reads).  The call-site only passes ONE arg
        // for the slot, so the engine never seeds the sibling Param
        // ops at runtime — but the per-parameter SUMMARY probe must
        // model "if this slot is tainted then every binding it
        // produced is tainted too".  Seed each sibling's `var_name`
        // with the same caps the primary received.  The probe-level
        // `validated_must` check below treats the slot as validated
        // when ANY sibling lands in `validated_must` on a return path.
        //
        // Closes the residual gap behind CVE-2026-25544 (PayloadCMS
        // `@payloadcms/drizzle` SQLi via `createJSONQuery({ value })`):
        // the validator helper `sanitizeValue(value, operator)` lives
        // inside the body and the probe needs to see `value` flow
        // through the `validated_params_to_return` channel before
        // suppressing the caller's sink.
        let slot_siblings: &[String] = formal_destructured_fields
            .and_then(|d| d.get(idx))
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        for sib in slot_siblings {
            seed.insert(
                BindingKey::new(sib.as_str(), BodyId(0)),
                probe_taint.clone(),
            );
        }

        // Phantom-Param prefix seeding.  SSA lowering of arrow / nested
        // function bodies often exposes free-identifier member-access
        // expressions (e.g. `file._source.uri`) as their own
        // [`SsaOp::Param`] ops with composite `var_name`s like
        // `"file._source.uri"`.  These phantom Params are the values
        // actually used as call arguments, not the formal-param SSA
        // value the seed targets.  Without this, the per-param probe
        // misses cross-call sinks because the call's arg SSA value is
        // a phantom Param with no seed entry, so `transfer_inst::Param`
        // leaves it untainted and `collect_tainted_sink_values`
        // observes empty caps despite the formal param being seeded.
        //
        // Seed every phantom Param whose `var_name` begins with
        // `formal_var_name + "."` with the same caps the formal param
        // received: semantically "if `file` is tainted, then every
        // observable field path on `file` is tainted too".  Bounded
        // by SSA size; cap-equivalent to direct seeding.  Mirror this
        // for each destructured sibling (`value.foo` / `column.name`
        // member-projections inside the body).
        let prefixes: Vec<String> = std::iter::once(var_name.clone())
            .chain(slot_siblings.iter().cloned())
            .map(|n| format!("{}.", n))
            .collect();
        for block in &ssa.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if let SsaOp::Param { .. } = &inst.op {
                    if let Some(name) = inst.var_name.as_ref() {
                        if prefixes.iter().any(|p| name.starts_with(p)) {
                            seed.insert(
                                BindingKey::new(name.as_str(), BodyId(0)),
                                probe_taint.clone(),
                            );
                        }
                    }
                }
            }
        }

        // Build slot-wide name list for the validated_must check.
        // Primary first, then siblings, then heap-allocated owned
        // copies — `run_probe` only borrows for its inner loop.
        let mut slot_names: Vec<&str> = Vec::with_capacity(1 + slot_siblings.len());
        slot_names.push(var_name.as_str());
        for sib in slot_siblings {
            slot_names.push(sib.as_str());
        }
        let (return_caps, events, _, per_return_obs) = run_probe(seed, Some(slot_names.as_slice()));

        // Subtract baseline source_caps, we only want param-contributed caps
        let param_return_caps = return_caps & !source_caps;

        if !param_return_caps.is_empty() {
            let stripped = Cap::all() & !param_return_caps;
            let transform = if stripped.is_empty() {
                TaintTransform::Identity
            } else {
                TaintTransform::StripBits(stripped)
            };
            param_to_return.push((idx, transform));
        } else if reaches_return_only_through_sanitizers(param_val, &reach_by_block) {
            // `return parseInt(s)`: the parameter does flow to the return, and
            // a full sanitizer clears it.  Say so, rather than leave the edge
            // out, so a caller that passes the call's source inline
            // (`wrap(req.query.x)`) sees a sanitizing wrapper and not an
            // unrelated one.
            param_to_return.push((idx, TaintTransform::StripBits(Cap::all())));
        }

        // Validated-param-to-return detection.
        //
        // When the per-param probe shows that the parameter's
        // `var_name` is in `validated_must` on every return path that
        // *carries the parameter's contributed caps*, record the
        // parameter as validated.  The caller will mark each tainted
        // argument passed to this position — and the call's own
        // return value — as `validated_must` / `validated_may`, the
        // same way an inline `if (!regex.test(x)) throw` would
        // validate the surviving branch.
        //
        // Conservative gating:
        //   * Skip when the param contributes no caps to the return,
        //     a degenerate "validated but irrelevant" record.
        //   * Skip when no return block was observed (probes that
        //     diverged or hit `MAX_PROBE_PARAMS`).
        //   * Require validation on every return path that *carries
        //     param caps to the return*.  Branches that return
        //     constants (e.g. `if (x === null) return 'NULL'`) carry
        //     no param taint and don't need a validation predicate.
        //   * Require ≥1 path that actually validates the param.
        if !param_return_caps.is_empty() && !per_return_obs.is_empty() {
            let mut any_carrying_path = false;
            let all_carrying_validated = per_return_obs.iter().all(|obs| {
                let carries = !(obs.derived_caps & !source_caps).is_empty()
                    || !(obs.param_caps & !source_caps).is_empty();
                if carries {
                    any_carrying_path = true;
                    obs.param_validated_must
                } else {
                    true
                }
            });
            if any_carrying_path && all_carrying_validated {
                validated_params_to_return.push(idx);
            }
            if std::env::var("NYX_DBG_VPR2").is_ok() {
                eprintln!(
                    "VPR2 fp={:?} idx={} name={} any_carry={} all_validated={}",
                    formal_param_names, idx, var_name, any_carrying_path, all_carrying_validated
                );
                for (i, obs) in per_return_obs.iter().enumerate() {
                    eprintln!(
                        "  ret[{}] derived={:?} param={:?} validated_must={}",
                        i, obs.derived_caps, obs.param_caps, obs.param_validated_must
                    );
                }
            }
        }

        // Derive per-return-path decomposition.  For each
        // observed return block, derive a `ReturnPathTransform` mirroring
        // the aggregate logic (prefer derived caps, fall back to param
        // caps, strip baseline source caps).  Only emit when ≥2 distinct
        // predicate hashes are present, a single-hash summary adds no
        // signal over the aggregate `param_to_return`.
        if per_return_obs.len() >= 2 {
            let mut per_path: SmallVec<[crate::summary::ssa_summary::ReturnPathTransform; 2]> =
                SmallVec::new();
            for obs in &per_return_obs {
                let block_return_caps = if !obs.derived_caps.is_empty() {
                    obs.derived_caps
                } else {
                    obs.param_caps
                };
                let block_contributed = block_return_caps & !source_caps;
                let transform_kind = if block_contributed.is_empty() {
                    // No caps on this path, param does not reach return
                    // under this predicate.  A `StripBits(all)` records
                    // "all bits cleared" so downstream join preserves the
                    // disparity with other paths.
                    TaintTransform::StripBits(Cap::all())
                } else {
                    let stripped = Cap::all() & !block_contributed;
                    if stripped.is_empty() {
                        TaintTransform::Identity
                    } else {
                        TaintTransform::StripBits(stripped)
                    }
                };
                crate::summary::ssa_summary::merge_return_paths(
                    &mut per_path,
                    &[crate::summary::ssa_summary::ReturnPathTransform {
                        transform: transform_kind,
                        path_predicate_hash: obs.predicate_hash,
                        known_true: obs.known_true,
                        known_false: obs.known_false,
                        abstract_contribution: obs.abstract_value.clone(),
                    }],
                );
            }
            // Only record when ≥2 distinct predicate gates survived
            // the dedup (a single-entry vector is no finer than the
            // aggregate `param_to_return` and wastes bytes on disk).
            let distinct_hashes = per_path
                .iter()
                .map(|e| e.path_predicate_hash)
                .collect::<std::collections::HashSet<_>>();
            if distinct_hashes.len() >= 2 {
                param_return_paths.push((idx, per_path));
            }
        }

        // Collect sink caps + primary-location sites from events + per-arg-position detail.
        //
        // Skip events flagged `all_validated`: every tainted SSA value
        // that reached the sink was already proved validated by a
        // dominating predicate (AllowlistCheck / TypeCheck /
        // ValidationCall, including the indirect-validator branch
        // narrowing for `validate*` / `is_valid*` callees).  Those
        // events would have been dropped by `ssa_events_to_findings` at
        // the per-file finding step; carrying them into
        // `param_to_sink` / `param_to_sink_param` re-publishes a sink
        // attribution callers can no longer suppress, because the
        // caller can't see the validator that lives inside the
        // callee body.
        //
        // Strict-additive: `all_validated` is set only when every
        // tainted operand at the sink has its `var_name` in
        // `state.validated_may`, single-path single-validator helpers
        // cleanly skip; mixed-tainted-with-some-unvalidated events
        // still propagate.  Closes the helper-summary precision gap
        // surfaced by Novu CVE GHSA-4x48-cgf9-q33f.
        let mut param_sites: SmallVec<[SinkSite; 1]> = SmallVec::new();
        for event in &events {
            if event.all_validated {
                continue;
            }
            for pos in extract_sink_arg_positions(event, ssa) {
                param_to_sink_param.push((idx, pos, event.sink_caps));
            }
            // Per-position gate-filter cap lifting.
            //
            // When the sink callee carries multiple gate filters (e.g. `fetch`
            // is both an SSRF gate on the URL arg and a `DATA_EXFIL` gate on
            // the body arg), the multi-gate dispatch has already filtered
            // `event.sink_caps` down to the specific gate's `label_caps` for
            // this probe.  Recording `(idx, event.sink_caps)` preserves that
            // narrowing across the function-summary boundary so a caller of
            // the wrapper splits SSRF from DATA_EXFIL findings instead of
            // joining them under a single union.
            //
            // Single-gate / no-gate sinks are skipped, the existing
            // `param_to_sink` machinery already records those without
            // per-position cap conflict.
            if !event.sink_caps.is_empty()
                && cfg[event.sink_node].call.gate_filters.len() > 1
                && !param_to_gate_filters
                    .iter()
                    .any(|&(i, c)| i == idx && c == event.sink_caps)
            {
                param_to_gate_filters.push((idx, event.sink_caps));
            }
            if event.sink_caps.is_empty() {
                continue;
            }
            // Preserve the deepest sink attribution across multi-hop summaries.
            // When `event.primary_sink_site` is populated, the upstream
            // resolver already pierced through a callee summary to the
            // dangerous instruction's coordinates; promoting it here means a
            // grandparent caller of this function sees `line N` of the
            // innermost helper rather than `line M` of *this* function's
            // call site to its child.  Mark `from_chain = true` so pass-2
            // emission can distinguish multi-hop chain markers (always
            // promote into `Finding.primary_location`) from this body's own
            // locator-resolved sink (only promote across file boundaries).
            // Falls back to locator-based call-site attribution when the
            // event is intra-procedural.
            let site = match event.primary_sink_site.as_ref() {
                Some(s) => {
                    let mut s = s.clone();
                    s.from_chain = true;
                    s
                }
                None => match locator {
                    Some(loc) => loc
                        .site_for_span(cfg[event.sink_node].classification_span(), event.sink_caps),
                    None => SinkSite::cap_only(event.sink_caps),
                },
            };
            let key = site.dedup_key();
            if let Some(existing) = param_sites.iter_mut().find(|s| s.dedup_key() == key) {
                if site.from_chain && !existing.from_chain {
                    existing.from_chain = true;
                }
            } else {
                param_sites.push(site);
            }
        }
        if !param_sites.is_empty() {
            param_to_sink.push((idx, param_sites));
        }
    }

    let (param_container_to_return, param_to_container_store) =
        extract_container_flow_summary(ssa, lang, effective_params);

    // Parameter-granularity points-to summary.
    let points_to = crate::ssa::param_points_to::analyse_param_points_to(
        ssa,
        &param_info,
        effective_params,
        formal_param_names,
        Some(lang),
    );

    // Infer return type: scan return-reaching blocks for constructor calls.
    let return_type = infer_summary_return_type(ssa, lang);

    // Detect source_to_callback: internal source taint flowing to calls of
    // parameter functions (e.g., `fn apply(f) { let x = source(); f(x); }`).
    // Re-runs the baseline probe internally to get accurate taint state.
    let source_to_callback = if !source_caps.is_empty() && !param_info.is_empty() {
        let baseline_transfer = SsaTaintTransfer {
            lang,
            namespace,
            interner,
            local_summaries,
            global_summaries,
            interop_edges: &[],
            owner_body_id: BodyId(0),
            parent_body_id: None,
            global_seed: None,
            param_seed: None,
            receiver_seed: None,
            const_values: None,
            type_facts: local_type_facts_ref,
            xml_parser_config: None,
            xpath_config: None,
            ssa_summaries,
            extra_labels: None,
            base_aliases,
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
            recording_summary: true,
        };
        detect_source_to_callback_from_states(
            ssa,
            cfg,
            source_caps,
            &param_info,
            &baseline_transfer,
        )
    } else {
        vec![]
    };

    // Per-parameter abstract-domain transfers.
    //
    // Derived structurally from the SSA body, no additional taint probes.
    // Three-step inference per parameter:
    //   1. Identity: return SSA value at every return block traces back to
    //      this parameter (possibly through assigns / phi merges all feeding
    //      from the same param).
    //   2. Callee-intrinsic bound: baseline `return_abstract` carries a
    //      concrete fact (bounded interval or known prefix) that holds
    //      regardless of caller input, record it once per parameter as
    //      `Clamped` / `LiteralPrefix` so the caller sees the bound even
    //      when it has no abstract info on its own argument.
    //   3. Top: default; the entry is omitted (empty transfer is meaningless).
    let abstract_transfer = derive_abstract_transfer(ssa, &param_info, return_abstract.as_ref());

    // Behaviour-based path-confinement predicate detection (CVE-2026-39365).
    // Independent of the per-param taint probes above: a structural scan of
    // the return-block call shapes for `<param>.startsWith(const)`-style
    // confinement, keyed by the formal-param SSA value.
    let param_index_of: HashMap<SsaValue, usize> =
        param_info.iter().map(|(idx, _, v)| (*v, *idx)).collect();
    let confines_path_params =
        detect_path_confining_predicate_params(ssa, &probe_const_values, &param_index_of);

    // Assert-guard path confinement (CVE-2021-21234): a `void` guard method
    // that `Assert.isTrue(p.startsWith(base))`-throws unless its path arg is
    // contained under a fixed prefix.  Consumed unconditionally at the call
    // site by `apply_call_post_confinement`.
    let asserts_path_confined_params =
        detect_assert_path_confined_params(ssa, &probe_const_values, &param_index_of);
    // `Result`-returning rejection-guard parameters (`ensure_safe_path_component(
    // x)?` returning `Err` — rattler CVE-2026-53956).  Kept separate from the
    // self-proving assert guards above because the confinement is applied only
    // at a *path-safety-validator-named* call site (`apply_path_validator_
    // confinement`), not unconditionally.
    let result_reject_guard_params = detect_result_reject_guard_params(ssa, &param_index_of);

    // Behaviour-based open-redirect confiner detection.  Two shapes mark the
    // return as OPEN_REDIRECT-clean:
    //   * `detect_open_redirect_normalizer` (CVE-2026-42259): normalise the
    //     input then reject protocol-relative (`//`) and `scheme:` URLs before
    //     returning the confined value (JS `normalize_relative_url`).
    //   * `detect_open_redirect_guarded_passthrough` (CVE-2022-24776): return
    //     the URL parameter only on the validated branch of a URL-safety guard
    //     (`get_safe_redirect` -> `is_safe_redirect_url` /
    //     `url_has_allowed_host_and_scheme`).
    let sanitizes_open_redirect_return = detect_open_redirect_normalizer(ssa, cfg, &param_index_of)
        || detect_open_redirect_guarded_passthrough(ssa, cfg, &param_index_of);

    // Return-value path-prefix confinement (CVE-2020-5221, uftpd): a function
    // whose every non-null return is guarded by `strncmp(rv, prefix,
    // strlen(prefix))` on the *returned* value.  Carries the intra-function
    // `PathPrefixConfined` narrowing across the interprocedural return the
    // static-buffer/param-fallback shape otherwise defeats.
    let confines_path_return = detect_path_confined_return(ssa, cfg, ssa_summaries, lang);

    // A C++ method that returns `*this` / `this` hands back the receiver, which
    // now holds whatever the parameters were stored into (`host_ = h`).  The
    // probe cannot see object state, so record every parameter as flowing to
    // the return, as a call on an unsummarised fluent method would.
    if lang == Lang::Cpp
        && ssa.blocks.iter().any(|b| {
            matches!(b.terminator, Terminator::Return(_))
                && b.body
                    .iter()
                    .any(|i| cfg[i.cfg_node].returned_idents.iter().any(|r| r == "this"))
        })
    {
        for &(idx, _, _) in &param_info {
            if !param_to_return.iter().any(|(i, _)| *i == idx) {
                param_to_return.push((idx, TaintTransform::Identity));
            }
        }
    }

    SsaFuncSummary {
        param_to_return,
        param_to_sink,
        source_caps,
        param_to_sink_param,
        param_to_gate_filters,
        param_container_to_return,
        param_to_container_store,
        return_type,
        return_abstract,
        source_to_callback,
        receiver_to_return: None,
        receiver_to_sink: Cap::empty(),
        abstract_transfer,
        param_return_paths,
        return_path_facts,
        points_to,
        // extension, empty until the field-granularity
        // extractor is wired (`NYX_POINTER_ANALYSIS=1` only).  Default
        // path stays bit-identical to today.
        field_points_to: crate::summary::points_to::FieldPointsToSummary::empty(),
        // Populated post-extraction in
        // `taint::lower_all_functions_from_bodies` once SSA optimisation
        // has computed `opt.type_facts`.  Empty here means the
        // extractor itself doesn't carry receiver-type info, the
        // caller patches it in.
        typed_call_receivers: Vec::new(),
        validated_params_to_return,
        confines_path_params,
        asserts_path_confined_params,
        result_reject_guard_params,
        sanitizes_open_redirect_return,
        confines_path_return,
        // Phase-10 entry-point classification is attached post-extraction
        // by `taint::lower_all_functions_from_bodies` (which has access
        // to `FileCfg::entry_kinds`).  Empty here means the extractor
        // itself does not carry the tag.
        entry_kind: None,
    }
}

/// Derive a deterministic predicate-hash + known-true/false intersection
/// for a return-block exit state.
///
/// The hash combines the sorted `(SymbolId, known_true, known_false)` tuples
/// from the state's `predicates` list with the validated_must bitmask.  Two
/// return blocks whose predicate gates are observationally identical produce
/// the same hash; the intersection of known_true/false gives the bits that
/// hold on every path into each return block.
///
/// Returns `(0, 0, 0)` for a Top state (no predicates tracked).
pub(super) fn summarise_return_predicates(state: &SsaTaintState) -> (u64, u8, u8) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use crate::taint::domain::INTERPROC_PREDICATE_BITS;

    // URL-shape bits stay inside the body (see `INTERPROC_PREDICATE_BITS`);
    // a variable that only carries those is not tracked here.
    let interproc = |kt: u8, kf: u8| {
        let (mkt, mkf) = (kt & INTERPROC_PREDICATE_BITS, kf & INTERPROC_PREDICATE_BITS);
        ((mkt | mkf) != 0 || (kt | kf) == 0).then_some((mkt, mkf))
    };
    if state
        .predicates
        .iter()
        .all(|(_, s)| interproc(s.known_true, s.known_false).is_none())
        && state.validated_must.is_empty()
    {
        return (0, 0, 0);
    }

    let mut h = DefaultHasher::new();
    // Validated-must contributes deterministically via bits().
    state.validated_must.bits().hash(&mut h);
    // Sort by SymbolId (predicates list is already sorted by SsaTaintState
    // invariants, but hash-input stability matters here).
    let mut sorted: smallvec::SmallVec<[(u32, u8, u8); 4]> = state
        .predicates
        .iter()
        .filter_map(|(id, s)| interproc(s.known_true, s.known_false).map(|(kt, kf)| (id.0, kt, kf)))
        .collect();
    sorted.sort_by_key(|(id, _, _)| *id);
    for (id, kt, kf) in &sorted {
        id.hash(&mut h);
        kt.hash(&mut h);
        kf.hash(&mut h);
    }
    let hash = h.finish();
    // Intersect known_true / known_false across all tracked variables:
    // the bits that hold for EVERY predicate-tracked var at this return.
    //
    // When `sorted` is empty (a return path guarded only by
    // ValidationCall/AllowlistCheck/TypeCheck, which populate `validated_must`
    // but never the `predicates` list because `predicate_kind_bit` returns
    // `None` for those kinds), the fold's `u8::MAX` identity would yield
    // `0xFF`/`0xFF`, claiming every predicate kind is simultaneously known-true
    // AND known-false on this path, a contradiction.  The consumer
    // (`effective_param_sanitizer`) then prunes this validated path from the
    // compatible set whenever the caller tracks any predicate bit, over-broadly
    // clearing taint.  No tracked predicate means no bit is known either way,
    // so the correct identity on the empty list is `0` (matching the Top-state
    // convention returned above).
    let known_true = if sorted.is_empty() {
        0
    } else {
        sorted
            .iter()
            .map(|(_, kt, _)| *kt)
            .fold(u8::MAX, |a, b| a & b)
    };
    let known_false = if sorted.is_empty() {
        0
    } else {
        sorted
            .iter()
            .map(|(_, _, kf)| *kf)
            .fold(u8::MAX, |a, b| a & b)
    };
    // Use `1` for the "no predicates but validated_must non-empty" case to
    // avoid colliding with the unguarded sentinel (0).
    let hash = if hash == 0 { 1 } else { hash };
    (hash, known_true, known_false)
}

/// Derive per-parameter [`AbstractTransfer`] entries for a function's SSA
/// body.
///
/// `return_abstract` is the callee's intrinsic baseline (from the no-seed
/// probe).  When present, it describes a fact that holds for the return
/// regardless of parameter input, so it can be attached as a
/// `Clamped` / `LiteralPrefix` transform to every parameter that flows to
/// the return.
///
/// Identity detection is structural: walk the return values back through
/// [`SsaOp::Assign`] / [`SsaOp::Phi`] chains (bounded) and check whether
/// every leaf resolves to the same [`SsaOp::Param`].  The trace is cheap
/// and can only produce `Identity` for passthrough callees, anything
/// more complex degrades to the baseline fact or `Top`.
fn derive_abstract_transfer(
    ssa: &SsaBody,
    param_info: &[(usize, String, SsaValue)],
    return_abstract: Option<&crate::abstract_interp::AbstractValue>,
) -> Vec<(usize, crate::abstract_interp::AbstractTransfer)> {
    use crate::abstract_interp::{AbstractTransfer, IntervalTransfer, StringTransfer};

    if param_info.is_empty() {
        return Vec::new();
    }

    // Build a lookup from SsaValue → defining op by scanning the body once.
    let mut defs: HashMap<SsaValue, &SsaOp> = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            defs.insert(inst.value, &inst.op);
        }
    }

    // Trace an SSA value backwards to the single source parameter index it
    // resolves to, if any.  Returns `None` when the trace diverges, hits a
    // non-pass-through op, or exceeds the depth bound.
    fn trace_to_param(
        v: SsaValue,
        defs: &HashMap<SsaValue, &SsaOp>,
        depth: usize,
    ) -> Option<usize> {
        const MAX_DEPTH: usize = 8;
        if depth > MAX_DEPTH {
            return None;
        }
        match defs.get(&v)? {
            SsaOp::Param { index } => Some(*index),
            SsaOp::Assign(ops) if ops.len() == 1 => trace_to_param(ops[0], defs, depth + 1),
            SsaOp::Phi(preds) => {
                let mut result: Option<usize> = None;
                for (_, pv) in preds {
                    let p = trace_to_param(*pv, defs, depth + 1)?;
                    match result {
                        None => result = Some(p),
                        Some(existing) if existing == p => {}
                        Some(_) => return None,
                    }
                }
                result
            }
            _ => None,
        }
    }

    // For every return block, trace its return value and record which
    // parameter (if any) it resolves to.  If all return blocks agree on the
    // same parameter index, that parameter has `Identity`.  If they disagree
    // (or some don't resolve), no parameter gets `Identity` and we fall
    // back to baseline-derived forms.
    let mut identity_param: Option<usize> = None;
    let mut identity_consistent = true;
    for block in &ssa.blocks {
        if let Terminator::Return(Some(rv)) = &block.terminator {
            let traced = trace_to_param(*rv, &defs, 0);
            match (identity_param, traced) {
                (None, Some(p)) => identity_param = Some(p),
                (Some(existing), Some(p)) if existing == p => {}
                _ => {
                    identity_consistent = false;
                    break;
                }
            }
        }
    }

    // Derive a baseline-invariant transform from `return_abstract`.  This is
    // the "callee intrinsic" fact that always holds, each parameter that
    // flows to the return gets it attached as the conservative transfer.
    let baseline_invariant: Option<AbstractTransfer> = return_abstract.map(|av| {
        let interval = match (av.interval.lo, av.interval.hi) {
            (Some(lo), Some(hi)) if lo <= hi => IntervalTransfer::Clamped { lo, hi },
            _ => IntervalTransfer::Top,
        };
        let string = match &av.string.prefix {
            Some(p) if !p.is_empty() => StringTransfer::literal_prefix(p),
            _ => StringTransfer::Unknown,
        };
        AbstractTransfer { interval, string }
    });

    let mut result: Vec<(usize, AbstractTransfer)> = Vec::new();

    for (idx, _, _) in param_info {
        let mut transfer = AbstractTransfer::top();

        if identity_consistent && identity_param == Some(*idx) {
            transfer.interval = IntervalTransfer::Identity;
            transfer.string = StringTransfer::Identity;
        } else if let Some(base) = baseline_invariant.as_ref() {
            // Baseline intrinsic bound applies to every parameter that could
            // reach the return.  We conservatively attach it to all params
            //, at apply time the caller meets it with the real return
            // abstract (also from this same summary), so double-counting
            // would collapse to the tighter of the two.
            transfer = base.clone();
        }

        if !transfer.is_top() {
            result.push((*idx, transfer));
        }
    }

    result
}

/// Detect callback patterns where internal source taint flows to a call of a
/// parameter function. Re-runs the baseline probe internally to get accurate
/// taint state at each instruction point.
///
/// Returns `(param_index_of_callee, source_caps)` pairs.
fn detect_source_to_callback_from_states(
    ssa: &SsaBody,
    cfg: &Cfg,
    source_caps: Cap,
    param_info: &[(usize, String, SsaValue)],
    transfer: &SsaTaintTransfer,
) -> Vec<(usize, Cap)> {
    use crate::ssa::ir::SsaOp;

    // Map param var_name → param_index
    let param_name_to_index: HashMap<&str, usize> = param_info
        .iter()
        .map(|(idx, name, _)| (name.as_str(), *idx))
        .collect();

    // Run taint analysis to get converged block states
    let (_events, block_states) = run_ssa_taint_full(ssa, cfg, transfer);

    let mut result: Vec<(usize, Cap)> = vec![];
    for (bid, block) in ssa.blocks.iter().enumerate() {
        let Some(entry_state) = &block_states[bid] else {
            continue;
        };
        // Replay block transfer to get accurate taint state at each instruction
        let mut state = entry_state.clone();
        for inst in &block.body {
            // Apply transfer for this instruction to advance state
            transfer_inst(inst, cfg, ssa, transfer, &mut state);

            // After transfer: check if this is a call to a param with tainted args
            if let SsaOp::Call { callee, args, .. } = &inst.op {
                if let Some(&param_idx) = param_name_to_index.get(callee.as_str()) {
                    let any_arg_tainted = args.iter().any(|arg_vals| {
                        arg_vals
                            .iter()
                            .any(|v| state.get(*v).is_some_and(|t| !t.caps.is_empty()))
                    });
                    if any_arg_tainted && !result.iter().any(|(idx, _)| *idx == param_idx) {
                        result.push((param_idx, source_caps));
                    }
                }
            }
        }
    }

    result
}

/// Infer the return type of a function from its SSA body by checking whether
/// return-reaching blocks produce values from known constructor/factory calls.
fn infer_summary_return_type(
    ssa: &SsaBody,
    lang: Lang,
) -> Option<crate::ssa::type_facts::TypeKind> {
    // Find blocks with Return terminators, then look at the last defined value
    // in those blocks, if it's a Call with a known constructor, that's our type.
    for block in &ssa.blocks {
        if !matches!(block.terminator, Terminator::Return(_)) {
            continue;
        }
        // Only inspect the very last instruction in the returning block.
        // Mirror the CFG-level `outer_callee` fallback (Phase 08 audit) so a
        // CFG-rewritten callee (e.g. `req.body.path` displacing `URL` on
        // `new URL(req.body.path, base)`) still resolves to the original
        // constructor identifier preserved in `callee_text`.
        if let Some(inst) = block.body.last()
            && let SsaOp::Call {
                callee,
                callee_text,
                ..
            } = &inst.op
        {
            if let Some(ty) = crate::ssa::type_facts::constructor_type(lang, callee) {
                return Some(ty);
            }
            if let Some(orig) = callee_text.as_deref()
                && let Some(ty) = crate::ssa::type_facts::constructor_type(lang, orig)
            {
                return Some(ty);
            }
        }
    }
    None
}

// ── Inter-procedural container flow detection (structural SSA analysis) ──

/// Build a map from SsaValue to its defining instruction.
fn build_inst_map(ssa: &SsaBody) -> HashMap<SsaValue, (SsaOp, Option<SsaValue>)> {
    let mut map = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            // Store the op and optionally the receiver for calls
            map.insert(inst.value, (inst.op.clone(), None));
        }
    }
    map
}

/// Trace an SSA value back through Assign/Phi chains to find if it originates
/// from a `Param { index }`. Returns `Some(index)` if a param is found.
/// Does NOT trace through Call, Const, Source, or other non-identity ops.
fn trace_to_param(
    v: SsaValue,
    ssa: &SsaBody,
    inst_map: &HashMap<SsaValue, (SsaOp, Option<SsaValue>)>,
    visited: &mut HashSet<SsaValue>,
) -> Option<usize> {
    if !visited.insert(v) {
        return None;
    }
    let (op, _) = inst_map.get(&v)?;
    match op {
        SsaOp::Param { index } => Some(*index),
        SsaOp::Assign(uses) => {
            for u in uses {
                if let Some(idx) = trace_to_param(*u, ssa, inst_map, visited) {
                    return Some(idx);
                }
            }
            None
        }
        SsaOp::Phi(operands) => {
            for (_, op_val) in operands {
                if let Some(idx) = trace_to_param(*op_val, ssa, inst_map, visited) {
                    return Some(idx);
                }
            }
            None
        }
        // Don't trace through Call (new identity), Const, Source, Nop, CatchParam
        _ => None,
    }
}

/// Detect inter-procedural container flow patterns from SSA structure:
/// - `param_container_to_return`: params whose container identity flows to return
/// - `param_to_container_store`: (src_param, container_param) pairs where src taint
///   is stored into container_param's contents
pub(crate) fn extract_container_flow_summary(
    ssa: &SsaBody,
    lang: Lang,
    formal_param_count: usize,
) -> (Vec<usize>, Vec<(usize, usize)>) {
    use crate::ssa::pointsto::{ContainerOp, classify_container_op};

    let inst_map = build_inst_map(ssa);
    let mut container_to_return: HashSet<usize> = HashSet::new();
    let mut container_store: Vec<(usize, usize)> = Vec::new();

    // 1. param_container_to_return: trace Assign/Phi ops in return blocks to params.
    //
    // `trace_to_param` will happily return any `SsaOp::Param { index }`, but
    // scoped lowering synthesises `Param` ops for external captures (module
    // imports, free identifiers) at indices beyond the formal parameter count.
    // Those must not enter the summary, the key's arity only covers formal
    // params, and an out-of-range index trips `ssa_summary_fits_arity`, forcing
    // the reconciliation probe to generate a synthetic disambiguator that no
    // caller will ever look up.
    for block in &ssa.blocks {
        if !matches!(block.terminator, Terminator::Return(_)) {
            continue;
        }
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                // Only trace identity-preserving ops (Assign, Phi).
                // Skip Param (would cause false positives in single-block functions),
                // Call (new identity), Const, Source, Nop, CatchParam.
                SsaOp::Assign(_) | SsaOp::Phi(_) => {
                    if let Some(idx) =
                        trace_to_param(inst.value, ssa, &inst_map, &mut HashSet::new())
                        && idx < formal_param_count
                    {
                        container_to_return.insert(idx);
                    }
                }
                _ => {}
            }
        }
    }

    // 2. param_to_container_store: find container Store calls, trace args to params
    for block in &ssa.blocks {
        for inst in block.body.iter() {
            if let SsaOp::Call {
                callee,
                args,
                receiver,
                ..
            } = &inst.op
            {
                let op = match classify_container_op(callee, lang) {
                    Some(ContainerOp::Store { value_args, .. }) => value_args,
                    _ => continue,
                };

                // Resolve container SSA value.  With the new call ABI, the
                // receiver is a separate channel and `args` contains only
                // positional arguments.  For Go, container ops are plain
                // function calls (no receiver), so args[0] is the container.
                let container_val = if let Some(v) = *receiver {
                    Some(v)
                } else if lang == Lang::Go {
                    args.first().and_then(|a| a.first().copied())
                } else if let Some(dot_pos) = callee.rfind('.') {
                    let receiver_name = &callee[..dot_pos];
                    args.iter()
                        .flat_map(|a| a.iter())
                        .find(|&&v| {
                            ssa.value_defs
                                .get(v.0 as usize)
                                .and_then(|d| d.var_name.as_deref())
                                == Some(receiver_name)
                        })
                        .copied()
                } else {
                    None
                };

                let container_val = match container_val {
                    Some(v) => v,
                    None => continue,
                };

                // Trace container to positional param (SelfParam → None, so
                // when the container is the receiver we skip, the caller
                // tracks that via `receiver_to_container_store` if needed).
                // Same arity filter as above: reject synthetic Param ops that
                // were injected for free captures.
                let container_param =
                    match trace_to_param(container_val, ssa, &inst_map, &mut HashSet::new()) {
                        Some(idx) if idx < formal_param_count => idx,
                        _ => continue,
                    };

                // Go container ops are plain function calls with the container
                // at args[0]; value args start at args[1].  Other languages
                // place the container on the receiver channel so args holds
                // only value args starting at index 0.
                let arg_offset = if lang == Lang::Go && receiver.is_none() {
                    1usize
                } else {
                    0
                };

                // Trace each value arg to param (same arity filter as above).
                for &va_idx in &op {
                    let effective_idx = va_idx + arg_offset;
                    if let Some(arg_vals) = args.get(effective_idx) {
                        for &av in arg_vals {
                            if let Some(src_param) =
                                trace_to_param(av, ssa, &inst_map, &mut HashSet::new())
                                && src_param < formal_param_count
                                && src_param != container_param
                                && !container_store.contains(&(src_param, container_param))
                            {
                                container_store.push((src_param, container_param));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut ctr: Vec<usize> = container_to_return.into_iter().collect();
    ctr.sort();
    container_store.sort();
    (ctr, container_store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::symbol::SymbolId;
    use crate::taint::domain::PredicateSummary;

    /// The path-safety-validator name grammar recognises the real path
    /// validator idioms and rejects non-path validators (CVE-2026-53956).
    #[test]
    fn is_path_safety_validator_name_grammar() {
        // Positive: path-safety validator idioms (snake + camel).
        for n in [
            "ensure_safe_path_component",
            "validate_safe_path",
            "is_safe_filename",
            "check_path_component",
            "sanitize_path",
            "ensureSafePathComponent",
            "assert_no_traversal",
            "reject_path_traversal",
        ] {
            assert!(
                is_path_safety_validator_name(n),
                "expected path-safety: {n}"
            );
        }
        // Negative: non-path validators and unrelated calls must not match.
        for n in [
            "ensure_valid_email",
            "is_authenticated",
            "validate_component", // has a path noun but no safe/path/sanit signal
            "check_length",
            "to_path_buf", // a path *noun* but not a validator verb
            "join",
            "format",
        ] {
            assert!(
                !is_path_safety_validator_name(n),
                "expected NOT path-safety: {n}"
            );
        }
    }

    /// Top state (no predicates, no validated_must) → all-zero sentinel.
    #[test]
    fn summarise_return_predicates_top_is_zero() {
        let state = SsaTaintState::initial();
        assert_eq!(summarise_return_predicates(&state), (0, 0, 0));
    }

    /// A return path guarded only by a ValidationCall/AllowlistCheck/TypeCheck
    /// populates `validated_must` but leaves `predicates` empty.  The
    /// known-true / known-false fields MUST be 0 (no tracked predicate ⇒ no bit
    /// known either way), not the `u8::MAX` fold identity, which would claim
    /// every predicate kind is simultaneously known-true AND known-false and
    /// cause the consumer to over-prune the validated path.
    #[test]
    fn summarise_return_predicates_validated_only_path_has_zero_bits() {
        let mut state = SsaTaintState::initial();
        state.validated_must.insert(SymbolId(3));
        let (hash, kt, kf) = summarise_return_predicates(&state);
        // Non-zero hash (validated_must is non-empty → distinct from unguarded).
        assert_ne!(
            hash, 0,
            "validated path must hash distinctly from unguarded"
        );
        assert_eq!(
            kt, 0,
            "no tracked predicate ⇒ known_true must be 0, not 0xFF"
        );
        assert_eq!(
            kf, 0,
            "no tracked predicate ⇒ known_false must be 0, not 0xFF"
        );
        // The result must not be a self-contradiction.
        assert_eq!(kt & kf, 0, "known_true & known_false contradiction");
    }

    /// When predicates ARE tracked, the intersection still reflects the
    /// actual per-var bits (regression guard that the empty-list special case
    /// did not disturb the populated path).
    #[test]
    fn summarise_return_predicates_tracked_bits_intersect() {
        let mut state = SsaTaintState::initial();
        state.predicates.push((
            SymbolId(1),
            PredicateSummary {
                known_true: 0b0000_0011,
                known_false: 0b0000_0100,
            },
        ));
        state.predicates.push((
            SymbolId(2),
            PredicateSummary {
                known_true: 0b0000_0001,
                known_false: 0b0000_1100,
            },
        ));
        let (_hash, kt, kf) = summarise_return_predicates(&state);
        // Intersection of known_true: 0b011 & 0b001 = 0b001.
        assert_eq!(kt, 0b0000_0001);
        // Intersection of known_false: 0b100 & 0b1100 = 0b100.
        assert_eq!(kf, 0b0000_0100);
    }

    /// The URL-shape bits (leading slash / protocol-relative) only pair up
    /// inside one body; they stay out of return-path summaries.
    #[test]
    fn summarise_return_predicates_masks_url_shape_bits() {
        let url_only = PredicateSummary {
            known_true: 1 << crate::taint::domain::PRED_BIT_LEADING_SLASH,
            known_false: 1 << crate::taint::domain::PRED_BIT_PROTOCOL_RELATIVE,
        };
        let mut state = SsaTaintState::initial();
        state.predicates.push((SymbolId(1), url_only));
        assert_eq!(summarise_return_predicates(&state), (0, 0, 0));

        let mut mixed = SsaTaintState::initial();
        mixed.predicates.push((
            SymbolId(1),
            PredicateSummary {
                known_true: 0b0000_0001,
                known_false: 0,
            },
        ));
        let baseline = summarise_return_predicates(&mixed);
        mixed.predicates.push((SymbolId(2), url_only));
        assert_eq!(summarise_return_predicates(&mixed), baseline);
    }
}

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
    SsaTaintEvent, SsaTaintTransfer, detect_variant_inner_fact, run_ssa_taint_full, transfer_block,
    transfer_inst,
};

use crate::cfg::{BodyId, Cfg, FuncSummaries};
use crate::labels::{Cap, SourceKind};
use crate::ssa::ir::{SsaBody, SsaOp, SsaValue, Terminator};
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use crate::taint::domain::{TaintOrigin, VarTaint};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};

/// Maximum number of parameters to probe for summary extraction.
/// Functions with more params fall back to legacy `FuncSummary`.
const MAX_PROBE_PARAMS: usize = 8;

/// Extract a precise per-parameter `SsaFuncSummary` from an already-lowered SSA body.
///
/// For each parameter (up to [`MAX_PROBE_PARAMS`]), runs a taint probe by seeding
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
) -> crate::summary::ssa_summary::SsaFuncSummary {
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
    }

    // Helper: run a taint probe with a given global_seed and return
    // the aggregate return caps, sink events, joined return abstract,
    // and the per-return-block observation list used to derive
    // per-return-path transforms.
    let run_probe = |seed: HashMap<BindingKey, VarTaint>| -> (
        Cap,
        Vec<SsaTaintEvent>,
        Option<crate::abstract_interp::AbstractValue>,
        Vec<ReturnBlockObs>,
    ) {
        let seed_ref = if seed.is_empty() { None } else { Some(&seed) };
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
            const_values: None,
            type_facts: None,
            ssa_summaries,
            extra_labels: None,
            base_aliases: None,
            callee_bodies: None,
            inline_cache: None,
            context_depth: 0,
            callback_bindings: None,
            points_to: None,
            dynamic_pts: None,
            import_bindings: None,
            promisify_aliases: None,
            module_aliases,
            static_map: None,
            auto_seed_handler_params: false,
            cross_file_bodies: None,
            pointer_facts: None,
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
        // Per-return-block observations for per-path transforms.
        let mut per_return: Vec<ReturnBlockObs> = Vec::with_capacity(return_blocks.len());
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
                    // When rv is not a param value, also collect param taint as a
                    // fallback. The SSA terminator's rv may point to the last body
                    // instruction (e.g. push/append result) rather than the actual
                    // return expression (the container parameter itself). This fires
                    // both when rv is tainted (derived) and when rv is untainted
                    // (the push result may have no taint but the param does).
                    // Skip when rv IS a param (already handled above) or when rv is
                    // a Const (provably untainted constant return).
                    let rv_is_const = ssa.blocks[bid]
                        .body
                        .iter()
                        .chain(ssa.blocks[bid].phis.iter())
                        .any(|inst| inst.value == rv && matches!(inst.op, SsaOp::Const(_)));
                    if !all_param_values.contains(&rv) && !rv_is_const {
                        for (val, taint) in &exit.values {
                            if all_param_values.contains(val) {
                                block_param_caps |= taint.caps;
                            }
                        }
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
                        }
                        block_variant_inner = detect_variant_inner_fact(rv, ssa, &exit);
                    }
                }

                // Derive a predicate hash + known-true/false
                // intersection across tracked variables at this return.
                // The hash is stable across runs for a given predicate
                // shape so call sites can compare paths deterministically.
                let (predicate_hash, known_true, known_false) = summarise_return_predicates(&exit);
                per_return.push(ReturnBlockObs {
                    derived_caps: block_derived_caps,
                    param_caps: block_param_caps,
                    predicate_hash,
                    known_true,
                    known_false,
                    abstract_value: block_abs,
                    path_fact: block_path_fact,
                    variant_inner_fact: block_variant_inner,
                });
            }
        }

        // Prefer derived caps; fall back to param caps for passthrough functions
        let return_caps = if !total_derived_caps.is_empty() {
            total_derived_caps
        } else {
            total_param_caps
        };

        // Drop return_abstract if it joined to Top
        let return_abstract = return_abstract.filter(|v| !v.is_top());

        (return_caps, events, return_abstract, per_return)
    };

    // Probe with no params tainted → detect source_caps + return abstract.
    // Abstract values don't depend on taint seeding, so the baseline probe
    // captures the function's intrinsic abstract return value.
    let (baseline_return_caps, _baseline_events, return_abstract, baseline_obs) =
        run_probe(HashMap::new());
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

    for &(idx, ref var_name, _ssa_val) in &param_info {
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
        // by SSA size; cap-equivalent to direct seeding.
        let prefix = format!("{}.", var_name);
        for block in &ssa.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if let SsaOp::Param { .. } = &inst.op {
                    if let Some(name) = inst.var_name.as_ref() {
                        if name.starts_with(&prefix) {
                            seed.insert(
                                BindingKey::new(name.as_str(), BodyId(0)),
                                probe_taint.clone(),
                            );
                        }
                    }
                }
            }
        }

        let (return_caps, events, _, per_return_obs) = run_probe(seed);

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
            let site = match locator {
                Some(loc) => {
                    loc.site_for_span(cfg[event.sink_node].classification_span(), event.sink_caps)
                }
                None => SinkSite::cap_only(event.sink_caps),
            };
            let key = site.dedup_key();
            if !param_sites.iter().any(|s| s.dedup_key() == key) {
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
            type_facts: None,
            ssa_summaries,
            extra_labels: None,
            base_aliases: None,
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

    if state.predicates.is_empty() && state.validated_must.is_empty() {
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
        .map(|(id, s)| (id.0, s.known_true, s.known_false))
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
    let known_true = sorted
        .iter()
        .map(|(_, kt, _)| *kt)
        .fold(u8::MAX, |a, b| a & b);
    let known_false = sorted
        .iter()
        .map(|(_, _, kf)| *kf)
        .fold(u8::MAX, |a, b| a & b);
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
        if let Some(inst) = block.body.last()
            && let SsaOp::Call { callee, .. } = &inst.op
            && let Some(ty) = crate::ssa::type_facts::constructor_type(lang, callee)
        {
            return Some(ty);
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

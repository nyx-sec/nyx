//! Taint event emission and conversion to [`crate::taint::Finding`].
//!
//! Extracted from the monolithic `ssa_transfer.rs`.  Contains:
//! * [`SsaTaintEvent`], the raw event struct produced by the block-level
//!   worklist each time a tainted value reaches a sink.
//! * [`ssa_events_to_findings`], event → `Finding` conversion with the
//!   `primary_location` invariant and dedup.
//! * Flow-path reconstruction helpers ([`reconstruct_flow_path`] and
//!   operand pickers).
//! * Small post-hoc utilities ([`block_distance`],
//!   [`extract_sink_arg_positions`], [`compute_path_hash`]).

use crate::cfg::Cfg;
use crate::labels::Cap;
use crate::ssa::ir::{SsaBody, SsaOp, SsaValue};
use crate::summary::SinkSite;
use crate::taint::domain::TaintOrigin;
use crate::taint::path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::{HashSet, VecDeque};

/// Event emitted when taint reaches a sink in SSA analysis.
#[derive(Clone, Debug)]
pub struct SsaTaintEvent {
    pub sink_node: NodeIndex,
    pub tainted_values: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    pub sink_caps: Cap,
    pub all_validated: bool,
    pub guard_kind: Option<PredicateKind>,
    /// Whether any callee in this event's taint path was resolved via a
    /// function summary (SSA, local, or global) rather than direct label.
    pub uses_summary: bool,
    /// Primary (callee-internal) sink location for cross-file attribution.
    ///
    /// Populated when this event was emitted via summary resolution and the
    /// callee summary carried a [`SinkSite`] whose `cap` intersects
    /// `sink_caps`.  When multiple [`SinkSite`]s for the same `(param_idx,
    /// cap mask)` match, the emission site produces one event per
    /// [`SinkSite`] so each downstream [`crate::taint::Finding`] carries a
    /// single primary attribution, the multi-primary case collapses to
    /// multiple single-primary events.
    ///
    /// `None` for:
    /// * intra-procedural sinks (`uses_summary == false`), where the
    ///   caller's sink span already names the dangerous instruction;
    /// * summary-resolved sinks whose callee summary carried only cap-only
    ///   [`SinkSite`]s (no source coordinates, e.g. pass-2 transient
    ///   summaries or local `LocalFuncSummary`-only callees).
    pub primary_sink_site: Option<SinkSite>,
}

pub(super) fn block_distance(ssa: &SsaBody, source_node: NodeIndex, sink_node: NodeIndex) -> u16 {
    let src_block = match ssa.cfg_node_map.get(&source_node) {
        Some(v) => ssa.def_of(*v).block,
        None => return 0,
    };
    let sink_block = match ssa.cfg_node_map.get(&sink_node) {
        Some(v) => ssa.def_of(*v).block,
        None => return 0,
    };
    if src_block == sink_block {
        return 0;
    }

    // BFS from src_block to sink_block
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(src_block);
    queue.push_back((src_block, 0u16));

    while let Some((blk, dist)) = queue.pop_front() {
        for &succ in &ssa.block(blk).succs {
            if succ == sink_block {
                return (dist + 1).min(255);
            }
            if visited.insert(succ) && dist + 1 < 255 {
                queue.push_back((succ, dist + 1));
            }
        }
    }
    0 // unreachable or not connected, conservative default
}

// ── Flow Path Reconstruction ─────────────────────────────────────────────

/// Reconstruct the taint flow path from source to sink by walking backward
/// through the SSA def-use chain.
///
/// Returns steps in source→sink order.
pub(super) fn reconstruct_flow_path(
    tainted_val: SsaValue,
    origin: &crate::taint::domain::TaintOrigin,
    sink_node: NodeIndex,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Vec<crate::taint::FlowStepRaw> {
    use crate::evidence::FlowStepKind;
    use crate::taint::FlowStepRaw;

    const MAX_STEPS: usize = 64;

    let mut steps = Vec::new();
    let mut visited = HashSet::new();

    // 1. Add sink step
    steps.push(FlowStepRaw {
        cfg_node: sink_node,
        var_name: cfg
            .node_weight(sink_node)
            .and_then(|n| n.call.callee.clone()),
        op_kind: FlowStepKind::Sink,
    });

    // 2. Walk backward from tainted_val
    let mut current = tainted_val;
    for _ in 0..MAX_STEPS {
        if !visited.insert(current) {
            break;
        }

        let def = ssa.def_of(current);
        let block = ssa.block(def.block);

        // Find the instruction for this value
        let inst = block
            .phis
            .iter()
            .chain(block.body.iter())
            .find(|i| i.value == current);

        let inst = match inst {
            Some(i) => i,
            None => break,
        };

        // Skip if same cfg_node as previous step (dedup consecutive same-line)
        if let Some(prev) = steps.last() {
            if prev.cfg_node == inst.cfg_node {
                // Still follow the chain, just don't add a duplicate step
                match &inst.op {
                    SsaOp::Source | SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam => {
                        break;
                    }
                    SsaOp::Assign(uses) => {
                        current = pick_tainted_operand(uses, origin, ssa);
                        continue;
                    }
                    SsaOp::Call { args, receiver, .. } => {
                        current = pick_tainted_operand_call(args, receiver, origin, ssa);
                        continue;
                    }
                    SsaOp::Phi(operands) => {
                        let vals: SmallVec<[SsaValue; 4]> =
                            operands.iter().map(|(_, v)| *v).collect();
                        current = pick_tainted_operand(&vals, origin, ssa);
                        continue;
                    }
                    _ => break,
                }
            }
        }

        match &inst.op {
            SsaOp::Source | SsaOp::Param { .. } | SsaOp::SelfParam | SsaOp::CatchParam => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Source,
                });
                break;
            }
            SsaOp::Assign(uses) => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Assignment,
                });
                if uses.is_empty() {
                    break;
                }
                current = pick_tainted_operand(uses, origin, ssa);
            }
            SsaOp::Call { args, receiver, .. } => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Call,
                });
                current = pick_tainted_operand_call(args, receiver, origin, ssa);
            }
            SsaOp::Phi(operands) => {
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Phi,
                });
                let vals: SmallVec<[SsaValue; 4]> = operands.iter().map(|(_, v)| *v).collect();
                if vals.is_empty() {
                    break;
                }
                current = pick_tainted_operand(&vals, origin, ssa);
            }
            SsaOp::FieldProj { receiver, .. } => {
                // Treat field projection as a one-step assignment for
                // flow-step reconstruction: taint reaching `obj.f` came
                // from `obj`.  the analysis may refine the witness rendering
                // to include the field name in the step.
                steps.push(FlowStepRaw {
                    cfg_node: inst.cfg_node,
                    var_name: inst.var_name.clone(),
                    op_kind: FlowStepKind::Assignment,
                });
                let single: SmallVec<[SsaValue; 4]> = smallvec::smallvec![*receiver];
                current = pick_tainted_operand(&single, origin, ssa);
            }
            SsaOp::Const(_) | SsaOp::Nop | SsaOp::Undef => break,
        }
    }

    // 3. Reverse: was built sink→source, need source→sink
    steps.reverse();
    steps
}

/// Pick the operand whose definition is closest to the origin node (direct match preferred).
fn pick_tainted_operand(
    operands: &[SsaValue],
    origin: &crate::taint::domain::TaintOrigin,
    ssa: &SsaBody,
) -> SsaValue {
    // Prefer operand defined at the origin node
    for &op in operands {
        if ssa.def_of(op).cfg_node == origin.node {
            return op;
        }
    }
    // Fallback: pick first (heuristic)
    operands.first().copied().unwrap_or(SsaValue(0))
}

/// Pick tainted operand for Call instructions (flatten args + receiver).
fn pick_tainted_operand_call(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    origin: &crate::taint::domain::TaintOrigin,
    ssa: &SsaBody,
) -> SsaValue {
    let mut all_vals: SmallVec<[SsaValue; 8]> = SmallVec::new();
    for arg in args {
        all_vals.extend_from_slice(arg);
    }
    if let Some(r) = receiver {
        all_vals.push(*r);
    }
    pick_tainted_operand(&all_vals, origin, ssa)
}

/// Convert SSA taint events to the standard Finding struct.
///
/// # Invariants enforced by debug_assert!
///
/// The `primary_location` field carries the primary sink-location
/// attribution.  One invariant must hold across every emitted Finding:
///
/// * A populated `primary_location` implies the attribution came from a
///   [`SinkSite`] with resolved coordinates (`line != 0` AND `file_rel`
///   non-empty).  Cap-only sites are filtered to `None` here; they never
///   reach downstream formatters claiming a `(0, 0)` origin.
///
/// Note: this invariant is intentionally independent of `uses_summary`.
/// The taint-chain flag tracks summary-propagated *taint*, not summary-
/// resolved *sinks*, a local source can reach a cross-file sink, so
/// `primary_location.is_some()` does not imply `uses_summary == true`.
pub fn ssa_events_to_findings(
    events: &[SsaTaintEvent],
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Vec<crate::taint::Finding> {
    // The dedup key includes `cap_bits` so the multi-gate dispatch can
    // co-emit separate findings for distinct capabilities at the same
    // (origin, sink) pair (e.g. PHP `header("Location: " . $url)` fires
    // both HEADER_INJECTION and OPEN_REDIRECT, attributed by the gate
    // filters' per-cap masks).  Single-cap call sites are unaffected:
    // every event in that case carries the same `sink_caps`, so the key
    // collapses identically with or without the extra component.
    type FindingDedupKey = (usize, usize, Option<(String, u32, u32)>, u32);
    let mut findings = Vec::new();
    let mut seen: HashSet<FindingDedupKey> = HashSet::new();

    for event in events {
        // Suppress findings where all tainted variables were validated
        // (passed through an allowlist, type-check, or validation branch).
        if event.all_validated {
            let span = cfg[event.sink_node].ast.span;
            // Cap-agnostic: record the validated sink span so the
            // AST-pattern suppression gate (`TaintSuppressionCtx`) has
            // positive evidence that the SSA engine reached this sink
            // and proved safety.  Without this, validation/dominator/
            // early-return-style safe code is indistinguishable from
            // silent engine failure when the function emitted no
            // findings and contains no labelled Sanitizer.
            crate::taint::ssa_transfer::state::record_all_validated_span(span);

            // Mirror the path-safety pathway: when the SSA engine has
            // already proved every tainted input to a privileged sink
            // passed through validation, publish the sink span so the
            // state-analysis pass suppresses `state-unauthed-access`
            // on the same span.  Trust here matches the trust the
            // engine already extends when dropping the taint flow
            // finding.  Covers the privileged sink classes
            // [`is_privileged_sink`] keys on (FILE_IO + SHELL_ESCAPE);
            // broadening past those would stretch the validator-trust
            // heuristic into unrelated finding classes.
            if event.sink_caps.intersects(Cap::FILE_IO | Cap::SHELL_ESCAPE) {
                crate::taint::ssa_transfer::state::record_path_safe_suppressed_span(span);
            }
            continue;
        }

        let primary_location = event.primary_sink_site.as_ref().and_then(|s| {
            // Only promote to a Finding.primary_location when the site has
            // resolved coordinates (cap-only sites at (0, 0) carry no
            // attribution and would just add noise).
            if s.line == 0 {
                None
            } else {
                Some(crate::taint::SinkLocation {
                    file_rel: s.file_rel.clone(),
                    line: s.line,
                    col: s.col,
                    snippet: s.snippet.clone(),
                })
            }
        });

        // Data-integrity invariant: a populated primary_location must at least
        // carry resolved line coordinates.  `file_rel` may legitimately be
        // empty, when the scan root is the caller file itself (single-file
        // scans), every namespace normalizes to `""` and the callee's site
        // inherits that empty path; consumers resolve it against the file
        // under analysis.  Line==0 is the only filter-worthy invariant.
        debug_assert!(
            primary_location.as_ref().is_none_or(|l| l.line != 0),
            "primary_location must carry a resolved line coordinate",
        );

        // Dedup key includes primary location so multi-site events that
        // share a single (source, sink) pair still produce distinct findings
        //, one per resolved callee-internal site.
        let loc_key = primary_location
            .as_ref()
            .map(|l| (l.file_rel.clone(), l.line, l.col));
        for (val, caps, origins) in &event.tainted_values {
            let effective_caps = event.sink_caps & *caps;
            let cap_specificity = effective_caps.bits().count_ones() as u8;
            for origin in origins {
                if seen.insert((
                    origin.node.index(),
                    event.sink_node.index(),
                    loc_key.clone(),
                    effective_caps.bits(),
                )) {
                    let hop_count = block_distance(ssa, origin.node, event.sink_node);
                    let flow_steps = reconstruct_flow_path(*val, origin, event.sink_node, ssa, cfg);
                    let path_hash = compute_path_hash(&flow_steps);
                    findings.push(crate::taint::Finding {
                        body_id: crate::cfg::BodyId(0), // set by caller
                        sink: event.sink_node,
                        source: origin.node,
                        path: vec![origin.node, event.sink_node],
                        source_kind: origin.source_kind,
                        path_validated: event.all_validated,
                        guard_kind: event.guard_kind,
                        hop_count,
                        cap_specificity,
                        uses_summary: event.uses_summary,
                        flow_steps,
                        symbolic: None,
                        source_span: origin.source_span.map(|(start, _)| start),
                        primary_location: primary_location.clone(),
                        engine_notes: smallvec::SmallVec::new(),
                        path_hash,
                        finding_id: String::new(),
                        alternative_finding_ids: smallvec::SmallVec::new(),
                        // Per-event mask from the multi-gate dispatch, picks
                        // exactly the cap that fired (e.g. `Cap::DATA_EXFIL`
                        // for a `fetch` body-flow finding versus `Cap::SSRF`
                        // for a URL-flow finding on the same call).
                        effective_sink_caps: event.sink_caps & *caps,
                    });
                }
            }
        }
    }

    findings
}

/// Compute a stable hash over the sequence of intermediate CFG nodes
/// that a tainted value traversed from source to sink.  Used as part of
/// the dedup key so two flows that share `(body_id, sink, source)` but
/// cross different intermediate variables are preserved as distinct
/// findings rather than collapsed to one.
///
/// Hashes the `(cfg_node.index(), op_kind-tag, var_name)` tuple per
/// step.  `op_kind` is captured as a small integer tag so changes in
/// enum encoding do not silently alter the hash; `var_name` is included
/// because two flows may touch the same cfg_node via different phi
/// operands (same node, different variable).
fn compute_path_hash(steps: &[crate::taint::FlowStepRaw]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    for step in steps {
        step.cfg_node.index().hash(&mut hasher);
        // Encode FlowStepKind as a stable small integer.  Using the
        // discriminant directly would tie us to enum ordering; an
        // explicit tag is more resilient to reordering.
        let kind_tag: u8 = match step.op_kind {
            crate::evidence::FlowStepKind::Source => 0,
            crate::evidence::FlowStepKind::Assignment => 1,
            crate::evidence::FlowStepKind::Call => 2,
            crate::evidence::FlowStepKind::Phi => 3,
            crate::evidence::FlowStepKind::Sink => 4,
        };
        kind_tag.hash(&mut hasher);
        step.var_name.hash(&mut hasher);
    }
    hasher.finish()
}

/// Given an SSA taint event at a sink, find which argument positions of the
/// sink call instruction were tainted.
pub(super) fn extract_sink_arg_positions(event: &SsaTaintEvent, ssa: &SsaBody) -> Vec<usize> {
    let ssa_val = match ssa.cfg_node_map.get(&event.sink_node) {
        Some(v) => *v,
        None => return vec![],
    };

    let def = ssa.def_of(ssa_val);
    let block = &ssa.blocks[def.block.0 as usize];

    let inst = block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|i| i.value == ssa_val);

    let inst = match inst {
        Some(i) => i,
        None => return vec![],
    };

    if let SsaOp::Call { args, .. } = &inst.op {
        let tainted_vals: HashSet<SsaValue> =
            event.tainted_values.iter().map(|(v, _, _)| *v).collect();

        let mut positions = Vec::new();
        for (i, arg_vals) in args.iter().enumerate() {
            if arg_vals.iter().any(|v| tainted_vals.contains(v)) {
                positions.push(i);
            }
        }
        positions
    } else {
        vec![]
    }
}

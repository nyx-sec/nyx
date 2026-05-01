//! Forward symbolic transfer over SSA instructions.
//!
//! Walks SSA blocks and builds `SymbolicValue` expression trees for each
//! defined SSA value, while eagerly propagating taint through the root-set.
//!
//! Cross-file symbolic summary modeling: when a callee has an
//! `SsaFuncSummary` available via `GlobalSummaries`, the Call instruction's
//! return value is modeled symbolically instead of being treated as opaque.
#![allow(
    clippy::collapsible_if,
    clippy::if_same_then_else,
    clippy::too_many_arguments
)]

use crate::cfg::Cfg;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::heap::PointsToResult;
use crate::ssa::ir::{BlockId, SsaBlock, SsaBody, SsaInst, SsaOp, SsaValue};
use crate::ssa::pointsto::{ContainerOp, classify_container_op};
use crate::ssa::type_facts::TypeFactResult;
use crate::summary::ssa_summary::TaintTransform;
use crate::summary::{CalleeResolution, GlobalSummaries};
use crate::symbol::Lang;

use super::heap::{self, FieldAccessRecord, FieldSlot, HeapKey};
use super::state::SymbolicState;
use super::strings::{
    StringOperandSource, TransformKind, classify_string_method, classify_transform_method,
};
use super::value::{
    Op, SymbolicValue, mk_binop, mk_call, mk_decode, mk_encode, mk_phi, mk_replace, mk_strlen,
    mk_substr, mk_to_lower, mk_to_upper, mk_trim,
};

/// Context for cross-file symbolic summary modeling during transfer.
///
/// When provided, Call instructions attempt to resolve callee behavior
/// via `SsaFuncSummary` before falling back to the opaque `mk_call`.
pub struct SymexSummaryCtx<'a> {
    pub global_summaries: &'a GlobalSummaries,
    pub lang: Lang,
    pub namespace: &'a str,
    /// Type facts for type-qualified symbolic summary resolution.
    /// When present, receiver types guide callee name qualification.
    pub type_facts: Option<&'a TypeFactResult>,
}

/// Context for field-sensitive heap operations during transfer.
///
/// When provided, Assign and Call instructions attempt store/load operations
/// through the symbolic heap using allocation-site identities from points-to.
/// `const_values` enables per-index array slot resolution.
pub struct SymexHeapCtx<'a> {
    pub points_to: &'a PointsToResult,
    pub ssa: &'a SsaBody,
    pub lang: Lang,
    pub const_values: &'a std::collections::HashMap<SsaValue, ConstLattice>,
}

/// Result of resolving a callee symbolically via its summary.
struct SymbolicCallResult {
    value: SymbolicValue,
    tainted: bool,
}

/// Transfer a single SSA instruction: set the symbolic value and propagate taint.
pub fn transfer_inst(
    state: &mut SymbolicState,
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
    interproc_ctx: Option<&super::interproc::InterprocCtx>,
    lang: Option<Lang>,
    node_meta: Option<
        &std::collections::HashMap<u32, crate::taint::ssa_transfer::CrossFileNodeMeta>,
    >,
) {
    match &inst.op {
        SsaOp::Const(text) => {
            let sym = match text {
                Some(t) => match ConstLattice::parse(t) {
                    ConstLattice::Int(n) => SymbolicValue::Concrete(n),
                    ConstLattice::Str(s) => SymbolicValue::ConcreteStr(s),
                    _ => SymbolicValue::Unknown, // Bool, Null, Top, Varying
                },
                None => SymbolicValue::Unknown,
            };
            state.set(inst.value, sym);
        }

        SsaOp::Source => {
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
            state.mark_tainted(inst.value);
        }

        SsaOp::Param { .. } => {
            // Params are symbolic inputs but NOT tainted by default.
            // Taint seeding happens via finding.flow_steps in analyse_finding_path.
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
        }

        SsaOp::SelfParam => {
            // Implicit method receiver, symbolic input, not tainted by default.
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
        }

        SsaOp::CatchParam => {
            if let Some(exc_val) = state.take_exception_context() {
                // On an exception path, seed from exception context
                // and mark tainted (matches taint engine: CatchParam gets Cap::all())
                state.set(inst.value, exc_val);
                state.mark_tainted(inst.value);
            } else {
                // Normal path or no explicit exception context, still mark tainted
                // to match taint engine behavior (ssa_transfer.rs CatchParam gets Cap::all())
                state.set(inst.value, SymbolicValue::Symbol(inst.value));
                state.mark_tainted(inst.value);
            }
        }

        SsaOp::Nop => {
            // Nop does not define a meaningful value, skip.
        }

        SsaOp::Undef => {
            // Phi-operand sentinel for edges without a reaching
            // definition. No concrete value, no taint.
            state.set(inst.value, SymbolicValue::Unknown);
        }

        SsaOp::FieldProj { receiver, .. } => {
            // Symbolic field read: model `obj.field` as an opaque value
            // tied to the projection's SsaValue, and propagate the
            // receiver's taint to the result so flat root-set tracking
            // continues to flow taint through chained accesses.
            //
            // This pass deliberately keeps the opaque-Symbol model: without
            // a field-sensitive heap, a dedicated `Field { receiver, name }`
            // SymbolicValue variant cannot soundly carry concrete reads
            // across method boundaries, the witness pipeline already
            // reconstructs `obj.field` text from `ValueDef.var_name`
            // (populated by lower.rs to `"base.f1.f2"` for chain projections).
            // The structured variant is deferred to the field-sensitive
            // pointer analysis prompt, where heap loads consume `FieldProj`
            // directly.
            state.set(inst.value, SymbolicValue::Symbol(inst.value));
            state.propagate_taint(inst.value, std::slice::from_ref(receiver));
        }

        SsaOp::Assign(uses) => {
            let uses_slice: &[_] = uses;
            match uses_slice.len() {
                0 => {
                    state.set(inst.value, SymbolicValue::Unknown);
                }
                1 => {
                    // Copy
                    let sym = state.get(uses_slice[0]);
                    state.set(inst.value, sym);
                    state.propagate_taint(inst.value, uses_slice);
                }
                2 => {
                    // Field-load pattern detection.
                    // When RHS is a member expression, SSA produces 2 uses:
                    //   uses[0] = dotted-path SSA value (e.g., v for "user.name")
                    //   uses[1] = base variable SSA value (e.g., v for "user")
                    // The first operand IS the field value, use it directly.
                    if let Some(def) = ssa.value_defs.get(uses_slice[0].0 as usize) {
                        if def.var_name.as_ref().is_some_and(|n| n.contains('.')) {
                            let sym = state.get(uses_slice[0]);
                            state.set(inst.value, sym);
                            state.propagate_taint(inst.value, uses_slice);
                            // Record heap load for cross-alias + witness
                            try_heap_load_record(state, inst, ssa, heap_ctx);
                            return;
                        }
                    }

                    // Heap-based cross-alias load fallback.
                    // If the instruction defines a dotted path but the first
                    // operand doesn't have a dotted var_name (aliased object),
                    // try loading from the symbolic heap via points-to.
                    if try_heap_alias_load(state, inst, ssa, heap_ctx) {
                        state.propagate_taint(inst.value, uses_slice);
                        return;
                    }

                    // Check for binary op metadata on the CFG node
                    let bin_op_val = if let Some(meta) = node_meta {
                        meta.get(&(inst.cfg_node.index() as u32))
                            .and_then(|m| m.info.bin_op)
                    } else {
                        cfg[inst.cfg_node].bin_op
                    };
                    if let Some(bin_op) = bin_op_val {
                        let lhs = state.get(uses_slice[0]);
                        let rhs = state.get(uses_slice[1]);
                        let sym = mk_binop(Op::from(bin_op), lhs, rhs);
                        state.set(inst.value, sym);
                    } else {
                        // No structural info, conservative Unknown
                        state.set(inst.value, SymbolicValue::Unknown);
                    }
                    state.propagate_taint(inst.value, uses_slice);
                }
                _ => {
                    // 3+ operands, complex expression
                    state.set(inst.value, SymbolicValue::Unknown);
                    state.propagate_taint(inst.value, uses_slice);
                }
            }

            // If this instruction defines a dotted path, record
            // the store in the symbolic heap for cross-alias resolution.
            try_heap_field_store(state, inst, ssa, heap_ctx);
        }

        SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } => {
            // Collect symbolic values for arguments
            let mut arg_syms: Vec<SymbolicValue> = Vec::new();
            let mut all_operands: Vec<_> = Vec::new();

            if let Some(recv) = receiver {
                arg_syms.push(state.get(*recv));
                all_operands.push(*recv);
            }

            for arg_slot in args {
                if let Some(&first_val) = arg_slot.first() {
                    arg_syms.push(state.get(first_val));
                    all_operands.push(first_val);
                }
            }

            // Container store/load via symbolic heap.
            // Resolve index_arg via const_values for per-index precision when
            // the index is a known constant.
            if let Some(hctx) = heap_ctx {
                if let Some(container_op) = classify_container_op(callee, hctx.lang) {
                    let recv_obj = receiver
                        .and_then(|rv| hctx.points_to.get(rv))
                        .filter(|pts| pts.len() == 1)
                        .and_then(|pts| pts.iter().next().copied());

                    if let Some(obj_id) = recv_obj {
                        match container_op {
                            ContainerOp::Store {
                                ref value_args,
                                index_arg,
                            } => {
                                let field = index_arg
                                    .and_then(|pos| {
                                        args.get(pos).and_then(|slot| slot.first()).map(|&v| {
                                            heap::resolve_index_slot(v, hctx.const_values)
                                        })
                                    })
                                    .unwrap_or(FieldSlot::Elements);
                                let key = HeapKey {
                                    object: obj_id,
                                    field,
                                };

                                let val_sym = value_args
                                    .first()
                                    .and_then(|&idx| args.get(idx))
                                    .and_then(|slot| slot.first())
                                    .map(|&v| state.get(v))
                                    .unwrap_or(SymbolicValue::Unknown);
                                let any_tainted = value_args.iter().any(|&idx| {
                                    args.get(idx)
                                        .and_then(|slot| slot.first())
                                        .map(|&v| state.is_tainted(v))
                                        .unwrap_or(false)
                                });
                                state.heap_mut().store(key, val_sym, any_tainted);
                                // Fall through to normal Call for return value
                            }
                            ContainerOp::Load { index_arg } => {
                                let field = index_arg
                                    .and_then(|pos| {
                                        args.get(pos).and_then(|slot| slot.first()).map(|&v| {
                                            heap::resolve_index_slot(v, hctx.const_values)
                                        })
                                    })
                                    .unwrap_or(FieldSlot::Elements);
                                let key = HeapKey {
                                    object: obj_id,
                                    field,
                                };

                                let loaded = state.heap().load(&key);
                                if !matches!(loaded, SymbolicValue::Unknown) {
                                    state.set(inst.value, loaded);
                                    if state.heap().is_tainted(&key) {
                                        state.mark_tainted(inst.value);
                                    }
                                    return;
                                }
                                // Fall through to normal Call
                            }
                            ContainerOp::Writeback { .. } => {
                                // Symex doesn't model writeback yet, taint
                                // engine handles the destination-arg taint
                                // directly. Fall through to normal Call.
                            }
                        }
                    }
                }
            }

            // String method recognition
            if let Some(result) =
                try_string_method(state, callee, receiver, &arg_syms, &all_operands, lang)
            {
                state.set(inst.value, result.value);
                if result.tainted {
                    state.mark_tainted(inst.value);
                }
                return;
            }

            // Encoding/decoding transform recognition
            if let Some(result) =
                try_transform_method(state, callee, receiver, &arg_syms, &all_operands, lang)
            {
                state.set(inst.value, result.value);
                if result.tainted {
                    state.mark_tainted(inst.value);
                }
                return;
            }

            // Interprocedural symbolic execution.
            // Execute callee body when available, full state propagation.
            if let Some(ictx) = interproc_ctx {
                let mut callee_args: Vec<(crate::ssa::ir::SsaValue, SymbolicValue, bool)> =
                    Vec::new();
                for (i, op) in all_operands.iter().enumerate() {
                    callee_args.push((
                        *op,
                        arg_syms.get(i).cloned().unwrap_or(SymbolicValue::Unknown),
                        state.is_tainted(*op),
                    ));
                }
                if let Some(outcome) = super::interproc::execute_callee(
                    ictx,
                    callee,
                    &callee_args,
                    state.heap(),
                    0, // depth: caller is at depth 0
                    &[],
                    summary_ctx,
                    heap_ctx,
                ) {
                    if !outcome.exit_states.is_empty() {
                        let policy = super::interproc::select_merge_policy(
                            outcome.exit_states.len(),
                            !outcome.cutoff_reasons.is_empty(),
                        );
                        let merged =
                            super::interproc::merge_exit_states(&outcome.exit_states, policy);
                        state.set(inst.value, merged.return_value);
                        if merged.return_tainted {
                            state.mark_tainted(inst.value);
                        }
                        // Apply heap delta: callee writes become visible to caller
                        for mutation in &merged.heap_delta {
                            state.heap_mut().store(
                                mutation.key.clone(),
                                mutation.value.clone(),
                                mutation.tainted,
                            );
                        }
                        return;
                    }
                }
            }

            // Try cross-file summary modeling before falling back to mk_call
            if let Some(ctx) = summary_ctx {
                if let Some(result) = resolve_callee_symbolically(
                    ctx,
                    callee,
                    &arg_syms,
                    &all_operands,
                    state,
                    inst.value,
                    *receiver,
                ) {
                    state.set(inst.value, result.value);
                    if result.tainted {
                        state.mark_tainted(inst.value);
                    }
                    return;
                }
            }

            // Fallback: opaque call
            let sym = mk_call(callee.clone(), arg_syms);
            state.set(inst.value, sym);
            state.propagate_taint(inst.value, &all_operands);
        }

        SsaOp::Phi(operands) => {
            let phi_ops: Vec<_> = operands
                .iter()
                .map(|(bid, v)| (*bid, state.get(*v)))
                .collect();
            let operand_vals: Vec<_> = operands.iter().map(|(_, v)| *v).collect();

            let sym = mk_phi(phi_ops);
            state.set(inst.value, sym);
            state.propagate_taint(inst.value, &operand_vals);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Heap helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Record a field store in the symbolic heap when the instruction defines
/// a dotted path (e.g., `user.name`).
fn try_heap_field_store(
    state: &mut SymbolicState,
    inst: &SsaInst,
    _ssa: &SsaBody,
    heap_ctx: Option<&SymexHeapCtx>,
) {
    let hctx = match heap_ctx {
        Some(hctx) => hctx,
        None => return,
    };
    let vn = match inst.var_name.as_deref() {
        Some(vn) => vn,
        None => return,
    };
    let (recv_name, field_name) = match heap::split_field_access(vn) {
        Some(pair) => pair,
        None => return,
    };
    let recv_ssa = match heap::resolve_receiver_ssa(recv_name, hctx.ssa, inst.value) {
        Some(v) => v,
        None => return,
    };
    let obj_id = match heap::resolve_singleton_object(recv_ssa, hctx.points_to) {
        Some(id) => id,
        None => return,
    };

    let key = HeapKey {
        object: obj_id,
        field: FieldSlot::Named(field_name.to_string()),
    };
    let sym = state.get(inst.value);
    let tainted = state.is_tainted(inst.value);
    state.heap_mut().store(key, sym, tainted);
    state.heap_mut().record_access(FieldAccessRecord {
        object_name: recv_name.to_string(),
        field_name: field_name.to_string(),
        ssa_value: inst.value,
    });
}

/// Record a field access from a successful field-load pattern.
fn try_heap_load_record(
    state: &mut SymbolicState,
    inst: &SsaInst,
    ssa: &SsaBody,
    _heap_ctx: Option<&SymexHeapCtx>,
) {
    // The uses[0] var_name has the dotted path.
    let uses = match &inst.op {
        SsaOp::Assign(u) => u,
        _ => return,
    };
    if let Some(&first) = uses.first() {
        if let Some(def) = ssa.value_defs.get(first.0 as usize) {
            if let Some(ref dotted) = def.var_name {
                if let Some((recv_name, field_name)) = heap::split_field_access(dotted) {
                    state.heap_mut().record_access(FieldAccessRecord {
                        object_name: recv_name.to_string(),
                        field_name: field_name.to_string(),
                        ssa_value: inst.value,
                    });
                }
            }
        }
    }
}

/// Try to resolve a 2-use Assign via heap cross-alias lookup.
///
/// When `inst.var_name` is a dotted path (e.g., `obj.field`) but the first
/// operand doesn't have a dotted def (the alias case), check the heap via
/// points-to resolution.  Returns `true` if the heap provided a value.
fn try_heap_alias_load(
    state: &mut SymbolicState,
    inst: &SsaInst,
    _ssa: &SsaBody,
    heap_ctx: Option<&SymexHeapCtx>,
) -> bool {
    let hctx = match heap_ctx {
        Some(hctx) => hctx,
        None => return false,
    };
    let vn = match inst.var_name.as_deref() {
        Some(vn) => vn,
        None => return false,
    };
    let (recv_name, field_name) = match heap::split_field_access(vn) {
        Some(pair) => pair,
        None => return false,
    };
    let recv_ssa = match heap::resolve_receiver_ssa(recv_name, hctx.ssa, inst.value) {
        Some(v) => v,
        None => return false,
    };
    let obj_id = match heap::resolve_singleton_object(recv_ssa, hctx.points_to) {
        Some(id) => id,
        None => return false,
    };

    let key = HeapKey {
        object: obj_id,
        field: FieldSlot::Named(field_name.to_string()),
    };
    let loaded = state.heap().load(&key);
    if matches!(loaded, SymbolicValue::Unknown) {
        return false;
    }
    state.set(inst.value, loaded);
    if state.heap().is_tainted(&key) {
        state.mark_tainted(inst.value);
    }
    state.heap_mut().record_access(FieldAccessRecord {
        object_name: recv_name.to_string(),
        field_name: field_name.to_string(),
        ssa_value: inst.value,
    });
    true
}

/// Transfer a single SSA instruction with optional predecessor context.
///
/// ONLY phi instructions use predecessor-sensitive selection, when
/// `predecessor` is `Some(bid)`, the phi resolves to the operand from
/// that specific predecessor block instead of building a `Phi(...)`
/// expression. All non-phi instructions delegate to [`transfer_inst`].
pub fn transfer_inst_with_predecessor(
    state: &mut SymbolicState,
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    predecessor: Option<BlockId>,
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
    interproc_ctx: Option<&super::interproc::InterprocCtx>,
    lang: Option<Lang>,
    node_meta: Option<
        &std::collections::HashMap<u32, crate::taint::ssa_transfer::CrossFileNodeMeta>,
    >,
) {
    match (&inst.op, predecessor) {
        (SsaOp::Phi(operands), Some(pred)) => {
            let sym = state.resolve_phi_from_predecessor(operands, pred);
            state.set(inst.value, sym);
            // Taint: propagate only from the matched predecessor operand
            for (bid, v) in operands.iter() {
                if *bid == pred {
                    state.propagate_taint(inst.value, &[*v]);
                    return;
                }
            }
            // Predecessor not found among operands, propagate from all (fallback)
            let operand_vals: Vec<_> = operands.iter().map(|(_, v)| *v).collect();
            state.propagate_taint(inst.value, &operand_vals);
        }
        _ => {
            transfer_inst(
                state,
                inst,
                cfg,
                ssa,
                summary_ctx,
                heap_ctx,
                interproc_ctx,
                lang,
                node_meta,
            );
        }
    }
}

/// Transfer all instructions in a block with predecessor context.
///
/// Phis use predecessor-aware transfer; body instructions use standard
/// [`transfer_inst`]. See [`transfer_inst_with_predecessor`] for details.
pub fn transfer_block_with_predecessor(
    state: &mut SymbolicState,
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    predecessor: Option<BlockId>,
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
    interproc_ctx: Option<&super::interproc::InterprocCtx>,
    lang: Option<Lang>,
    node_meta: Option<
        &std::collections::HashMap<u32, crate::taint::ssa_transfer::CrossFileNodeMeta>,
    >,
) {
    for inst in &block.phis {
        transfer_inst_with_predecessor(
            state,
            inst,
            cfg,
            ssa,
            predecessor,
            summary_ctx,
            heap_ctx,
            interproc_ctx,
            lang,
            node_meta,
        );
    }
    for inst in &block.body {
        transfer_inst(
            state,
            inst,
            cfg,
            ssa,
            summary_ctx,
            heap_ctx,
            interproc_ctx,
            lang,
            node_meta,
        );
    }
}

/// Transfer all instructions in a block: phis first, then body.
pub fn transfer_block(
    state: &mut SymbolicState,
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
    interproc_ctx: Option<&super::interproc::InterprocCtx>,
    lang: Option<Lang>,
) {
    for inst in &block.phis {
        transfer_inst(
            state,
            inst,
            cfg,
            ssa,
            summary_ctx,
            heap_ctx,
            interproc_ctx,
            lang,
            None,
        );
    }
    for inst in &block.body {
        transfer_inst(
            state,
            inst,
            cfg,
            ssa,
            summary_ctx,
            heap_ctx,
            interproc_ctx,
            lang,
            None,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  String method dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to model a callee as a recognized string operation.
///
/// Returns `Some(SymbolicCallResult)` if the callee is a known string method
/// with structurally-modelable arguments. Otherwise returns `None`.
fn try_string_method(
    state: &SymbolicState,
    callee: &str,
    receiver: &Option<SsaValue>,
    arg_syms: &[SymbolicValue],
    all_operands: &[SsaValue],
    lang: Option<Lang>,
) -> Option<SymbolicCallResult> {
    let lang = lang?;
    let info = classify_string_method(callee, arg_syms, lang)?;

    // Get the string operand based on the operand source
    let (string_sym, string_ssa) = match info.operand_source {
        StringOperandSource::Receiver => {
            let recv = (*receiver)?;
            (state.get(recv), recv)
        }
        StringOperandSource::FirstArg => {
            // For free functions, first arg is the string.
            // If receiver was prepended to arg_syms, it's at index 0;
            // otherwise first explicit arg is at index 0.
            if let Some(recv) = receiver {
                // Receiver was prepended, it IS the string operand
                (state.get(*recv), *recv)
            } else if let Some(&first_op) = all_operands.first() {
                (
                    arg_syms.first().cloned().unwrap_or(SymbolicValue::Unknown),
                    first_op,
                )
            } else {
                return None;
            }
        }
    };

    // Build the structured SymbolicValue via smart constructors
    let value = match info.method {
        super::strings::StringMethod::Trim => mk_trim(string_sym),
        super::strings::StringMethod::ToLower => mk_to_lower(string_sym),
        super::strings::StringMethod::ToUpper => mk_to_upper(string_sym),
        super::strings::StringMethod::Replace {
            pattern,
            replacement,
        } => mk_replace(string_sym, pattern, replacement),
        super::strings::StringMethod::Substr => {
            // Extract start and end indices from args
            let arg_offset = match info.operand_source {
                StringOperandSource::Receiver => 1, // args[0] = receiver, args[1] = start
                StringOperandSource::FirstArg => {
                    if receiver.is_some() { 1 } else { 1 } // args[0] = string, args[1] = start
                }
            };
            let start = arg_syms
                .get(arg_offset)
                .cloned()
                .unwrap_or(SymbolicValue::Concrete(0));
            let end = arg_syms.get(arg_offset + 1).cloned();
            mk_substr(string_sym, start, end)
        }
        super::strings::StringMethod::StrLen => mk_strlen(string_sym),
    };

    // Taint: string operations preserve taint from the string operand
    let tainted = state.is_tainted(string_ssa);

    Some(SymbolicCallResult { value, tainted })
}

/// Recognize encoding/decoding transforms and build structured
/// `Encode`/`Decode` nodes instead of opaque `Call`.
///
/// Taint is always propagated from the operand, encoding preserves taint
/// unconditionally. This function does NOT sanitize.
fn try_transform_method(
    state: &SymbolicState,
    callee: &str,
    receiver: &Option<SsaValue>,
    arg_syms: &[SymbolicValue],
    all_operands: &[SsaValue],
    lang: Option<Lang>,
) -> Option<SymbolicCallResult> {
    let lang = lang?;
    let info = classify_transform_method(callee, lang)?;

    // Extract the operand the same way as try_string_method
    let (operand_sym, operand_ssa) = match info.operand_source {
        StringOperandSource::Receiver => {
            let recv = (*receiver)?;
            (state.get(recv), recv)
        }
        StringOperandSource::FirstArg => {
            if let Some(recv) = receiver {
                (state.get(*recv), *recv)
            } else if let Some(&first_op) = all_operands.first() {
                (
                    arg_syms.first().cloned().unwrap_or(SymbolicValue::Unknown),
                    first_op,
                )
            } else {
                return None;
            }
        }
    };

    // Build structured Encode or Decode node via smart constructors
    let value = match info.kind {
        TransformKind::Base64Decode | TransformKind::UrlDecode => mk_decode(info.kind, operand_sym),
        _ => mk_encode(info.kind, operand_sym),
    };

    // Encoding preserves taint unconditionally
    let tainted = state.is_tainted(operand_ssa);

    Some(SymbolicCallResult { value, tainted })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cross-file symbolic summary resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Model a callee's return value from its SSA summary.
///
/// Shared by both type-qualified and bare-name resolution paths.
///
/// Resolution rules:
/// - **Exactly one `Identity`**: pass through that argument's symbolic value
/// - **Multiple `Identity` entries**: ambiguous → fall back (do NOT pick arbitrarily)
/// - **`StripBits`**: sanitizer → `Unknown`, not tainted
/// - **`AddBits` or `source_caps != empty`**: source → fresh tainted Symbol
/// - **`NotFound` / `Ambiguous`**: hard fallback to mk_call
fn model_from_summary(
    summary: &crate::summary::ssa_summary::SsaFuncSummary,
    arg_syms: &[SymbolicValue],
    all_operands: &[SsaValue],
    state: &SymbolicState,
    result_value: SsaValue,
) -> Option<SymbolicCallResult> {
    // Check for source-producing function
    if !summary.source_caps.is_empty() {
        return Some(SymbolicCallResult {
            value: SymbolicValue::Symbol(result_value),
            tainted: true,
        });
    }

    // Inspect param_to_return transforms
    if summary.param_to_return.is_empty() {
        return None;
    }

    // Collect identity mappings
    let identities: Vec<_> = summary
        .param_to_return
        .iter()
        .filter(|(_, t)| matches!(t, TaintTransform::Identity))
        .collect();

    // Check for StripBits (sanitizer)
    let has_strip = summary
        .param_to_return
        .iter()
        .any(|(_, t)| matches!(t, TaintTransform::StripBits(_)));

    // Check for AddBits (source introduction)
    let has_add = summary
        .param_to_return
        .iter()
        .any(|(_, t)| matches!(t, TaintTransform::AddBits(_)));

    if has_add {
        return Some(SymbolicCallResult {
            value: SymbolicValue::Symbol(result_value),
            tainted: true,
        });
    }

    if has_strip && identities.is_empty() {
        return Some(SymbolicCallResult {
            value: SymbolicValue::Unknown,
            tainted: false,
        });
    }

    if identities.len() == 1 {
        let (param_idx, _) = identities[0];
        if let Some(sym) = arg_syms.get(*param_idx) {
            let is_tainted = all_operands
                .get(*param_idx)
                .map(|v| state.is_tainted(*v))
                .unwrap_or(false);
            return Some(SymbolicCallResult {
                value: sym.clone(),
                tainted: is_tainted,
            });
        }
    }

    // Multiple Identity entries or other ambiguous cases: fall back
    None
}

/// Attempt to resolve a callee's return value symbolically using its
/// `SsaFuncSummary` from `GlobalSummaries`.
///
/// Returns `Some(SymbolicCallResult)` if the summary provides actionable
/// modeling. Returns `None` to fall through to the opaque `mk_call` path.
///
/// When a receiver has a known type via type facts, tries type-qualified
/// callee name (e.g., `"HttpClient.send"`) before bare-name resolution. This
/// improves summary-based modeling only, not general virtual dispatch.
fn resolve_callee_symbolically(
    ctx: &SymexSummaryCtx,
    callee: &str,
    arg_syms: &[SymbolicValue],
    all_operands: &[SsaValue],
    state: &SymbolicState,
    result_value: SsaValue,
    receiver: Option<SsaValue>,
) -> Option<SymbolicCallResult> {
    // Type-qualified symbolic resolution when receiver has a known type.
    // Improves summary-based modeling only, not general virtual dispatch.
    // Precedence: exact qualified > type-aided disambiguation > bare-name fallback.
    if let (Some(tf), Some(recv)) = (ctx.type_facts, receiver)
        && let Some(receiver_type) = tf.get_type(recv)
        && let Some(prefix) = receiver_type.label_prefix()
    {
        let method = crate::callgraph::callee_leaf_name(callee);
        let qualified = format!("{}.{}", prefix, method);

        // Attempt 1: Exact lookup under type-qualified name.
        // Arity=None to avoid receiver-in-operands vs formal-param mismatch.
        let resolution =
            ctx.global_summaries
                .resolve_callee_key(&qualified, ctx.lang, ctx.namespace, None);
        if let CalleeResolution::Resolved(key) = resolution
            && let Some(summary) = ctx.global_summaries.get_ssa(&key)
        {
            return model_from_summary(summary, arg_syms, all_operands, state, result_value);
        }

        // Attempt 2: Disambiguate among ambiguous bare-name candidates.
        // Only select when a candidate's FuncKey.name EXACTLY equals the
        // qualified name, no substring matching, never guess.
        let bare_resolution =
            ctx.global_summaries
                .resolve_callee_key(method, ctx.lang, ctx.namespace, None);
        if let CalleeResolution::Ambiguous(candidates) = bare_resolution {
            let exact_match: Vec<_> = candidates.iter().filter(|k| k.name == qualified).collect();
            if exact_match.len() == 1
                && let Some(summary) = ctx.global_summaries.get_ssa(exact_match[0])
            {
                return model_from_summary(summary, arg_syms, all_operands, state, result_value);
            }
            // >1 or 0 exact matches: do NOT guess, fall through
        }
        // Fall through to existing bare-name resolution
    }

    // Existing bare-name resolution path
    let normalized = crate::callgraph::callee_leaf_name(callee);
    let resolution = ctx.global_summaries.resolve_callee_key(
        normalized,
        ctx.lang,
        ctx.namespace,
        Some(all_operands.len()),
    );

    let key = match resolution {
        CalleeResolution::Resolved(k) => k,
        CalleeResolution::NotFound | CalleeResolution::Ambiguous(_) => return None,
    };

    let summary = ctx.global_summaries.get_ssa(&key)?;
    model_from_summary(summary, arg_syms, all_operands, state, result_value)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BinOp, Cfg, NodeInfo, StmtKind};
    use crate::ssa::ir::{BlockId, SsaBlock, SsaInst, SsaValue, Terminator};
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    /// Create a minimal Cfg with a single node that has the given bin_op.
    fn cfg_with_node(bin_op: Option<BinOp>) -> (Cfg, NodeIndex) {
        let mut cfg = Cfg::new();
        let info = NodeInfo {
            kind: StmtKind::Seq,
            bin_op,
            ..Default::default()
        };
        let idx = cfg.add_node(info);
        (cfg, idx)
    }

    fn make_inst(value: u32, op: SsaOp, cfg_node: NodeIndex) -> SsaInst {
        SsaInst {
            value: SsaValue(value),
            op,
            cfg_node,
            var_name: None,
            span: (0, 0),
        }
    }

    fn empty_ssa() -> SsaBody {
        SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        }
    }

    #[test]
    fn transfer_const_int() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("42".into())), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(42));
        assert!(!state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_const_string() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("\"hello\"".into())), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(
            state.get(SsaValue(0)),
            SymbolicValue::ConcreteStr("hello".into())
        );
    }

    #[test]
    fn transfer_const_bool_fallback() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("true".into())), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Unknown);
    }

    #[test]
    fn transfer_const_none() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(None), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Unknown);
    }

    #[test]
    fn transfer_source_tainted() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Source, node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_param_not_tainted() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Param { index: 0 }, node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(!state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_assign_copy() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Set up source value
        state.set(SsaValue(0), SymbolicValue::Concrete(7));
        state.mark_tainted(SsaValue(0));

        let inst = make_inst(1, SsaOp::Assign(smallvec![SsaValue(0)]), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Concrete(7));
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_assign_binop() {
        let (cfg, node) = cfg_with_node(Some(BinOp::Mul));
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));
        state.set(SsaValue(1), SymbolicValue::Concrete(2));

        let inst = make_inst(2, SsaOp::Assign(smallvec![SsaValue(0), SsaValue(1)]), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        let expected = SymbolicValue::BinOp(
            Op::Mul,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
            Box::new(SymbolicValue::Concrete(2)),
        );
        assert_eq!(state.get(SsaValue(2)), expected);
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_assign_no_binop_is_unknown() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.set(SsaValue(1), SymbolicValue::Concrete(2));

        let inst = make_inst(2, SsaOp::Assign(smallvec![SsaValue(0), SsaValue(1)]), node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Unknown);
    }

    #[test]
    fn transfer_call() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "parseInt".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        let expected =
            SymbolicValue::Call("parseInt".into(), vec![SymbolicValue::Symbol(SsaValue(0))]);
        assert_eq!(state.get(SsaValue(1)), expected);
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_call_with_receiver() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0))); // receiver
        state.set(SsaValue(1), SymbolicValue::Concrete(42)); // arg

        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "send".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(1)]],
                receiver: Some(SsaValue(0)),
            },
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        let expected = SymbolicValue::Call(
            "send".into(),
            vec![
                SymbolicValue::Symbol(SsaValue(0)),
                SymbolicValue::Concrete(42),
            ],
        );
        assert_eq!(state.get(SsaValue(2)), expected);
    }

    #[test]
    fn transfer_phi() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(1));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![
                (BlockId(0), SsaValue(0)),
                (BlockId(1), SsaValue(1))
            ]),
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        let expected = SymbolicValue::Phi(vec![
            (BlockId(0), SymbolicValue::Concrete(1)),
            (BlockId(1), SymbolicValue::Symbol(SsaValue(1))),
        ]);
        assert_eq!(state.get(SsaValue(2)), expected);
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn taint_propagation_chain() {
        // Build a cfg with two nodes: one plain (for source/copy/const), one with Mul
        let mut cfg = Cfg::new();
        let node_plain = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            ..Default::default()
        });
        let node_mul = cfg.add_node(NodeInfo {
            kind: StmtKind::Seq,
            bin_op: Some(BinOp::Mul),
            ..Default::default()
        });
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // v0: source (tainted)
        let i0 = make_inst(0, SsaOp::Source, node_plain);
        transfer_inst(&mut state, &i0, &cfg, &ssa, None, None, None, None, None);
        assert!(state.is_tainted(SsaValue(0)));

        // v1: copy of v0
        let i1 = make_inst(1, SsaOp::Assign(smallvec![SsaValue(0)]), node_plain);
        transfer_inst(&mut state, &i1, &cfg, &ssa, None, None, None, None, None);
        assert!(state.is_tainted(SsaValue(1)));

        // v2: constant (not tainted)
        let i2 = make_inst(2, SsaOp::Const(Some("3".into())), node_plain);
        transfer_inst(&mut state, &i2, &cfg, &ssa, None, None, None, None, None);
        assert!(!state.is_tainted(SsaValue(2)));

        // v3: v1 * v2 (tainted because v1 is tainted)
        let i3 = make_inst(
            3,
            SsaOp::Assign(smallvec![SsaValue(1), SsaValue(2)]),
            node_mul,
        );
        transfer_inst(&mut state, &i3, &cfg, &ssa, None, None, None, None, None);
        assert!(state.is_tainted(SsaValue(3)));
        let expected = SymbolicValue::BinOp(
            Op::Mul,
            Box::new(SymbolicValue::Symbol(SsaValue(0))), // v1 was a copy of v0 (Symbol)
            Box::new(SymbolicValue::Concrete(3)),
        );
        assert_eq!(state.get(SsaValue(3)), expected);

        // v4: call using v3 (still tainted)
        let i4 = make_inst(
            4,
            SsaOp::Call {
                callee: "toString".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(3)]],
                receiver: None,
            },
            node_plain,
        );
        transfer_inst(&mut state, &i4, &cfg, &ssa, None, None, None, None, None);
        assert!(state.is_tainted(SsaValue(4)));
    }

    #[test]
    fn transfer_nop_skipped() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(99));
        let inst = make_inst(0, SsaOp::Nop, node);
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        // Nop does not overwrite existing value
        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(99));
    }

    #[test]
    fn transfer_block_processes_phis_then_body() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Set up predecessor values for phi
        state.set(SsaValue(0), SymbolicValue::Concrete(1));
        state.set(SsaValue(1), SymbolicValue::Concrete(1));

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![make_inst(
                2,
                SsaOp::Phi(smallvec![
                    (BlockId(0), SsaValue(0)),
                    (BlockId(1), SsaValue(1))
                ]),
                node,
            )],
            body: vec![make_inst(3, SsaOp::Const(Some("10".into())), node)],
            terminator: Terminator::Return(None),
            preds: smallvec![],
            succs: smallvec![],
        };

        transfer_block(&mut state, &block, &cfg, &ssa, None, None, None, None);

        // Phi with all-same should fold to Concrete(1)
        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Concrete(1));
        // Body const should be set
        assert_eq!(state.get(SsaValue(3)), SymbolicValue::Concrete(10));
    }

    #[test]
    fn transfer_phi_with_predecessor_resolves_to_operand() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Set up different values for each predecessor
        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Concrete(20));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![
                (BlockId(0), SsaValue(0)),
                (BlockId(1), SsaValue(1))
            ]),
            node,
        );

        // With predecessor B1, should resolve to SsaValue(1) → Concrete(20)
        transfer_inst_with_predecessor(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(BlockId(1)),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Concrete(20));
    }

    #[test]
    fn transfer_phi_with_predecessor_taint_from_selected_only() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // B0's operand is NOT tainted, B1's operand IS tainted
        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![
                (BlockId(0), SsaValue(0)),
                (BlockId(1), SsaValue(1))
            ]),
            node,
        );

        // With predecessor B0 (untainted), result should NOT be tainted
        transfer_inst_with_predecessor(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(BlockId(0)),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_phi_with_predecessor_taint_from_tainted_pred() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![
                (BlockId(0), SsaValue(0)),
                (BlockId(1), SsaValue(1))
            ]),
            node,
        );

        // With predecessor B1 (tainted), result SHOULD be tainted
        transfer_inst_with_predecessor(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(BlockId(1)),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_phi_without_predecessor_builds_phi_expr() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Concrete(20));

        let inst = make_inst(
            2,
            SsaOp::Phi(smallvec![
                (BlockId(0), SsaValue(0)),
                (BlockId(1), SsaValue(1))
            ]),
            node,
        );

        // Without predecessor (None), falls back to Phi(...) expression
        transfer_inst_with_predecessor(
            &mut state, &inst, &cfg, &ssa, None, None, None, None, None, None,
        );
        let expected = SymbolicValue::Phi(vec![
            (BlockId(0), SymbolicValue::Concrete(10)),
            (BlockId(1), SymbolicValue::Concrete(20)),
        ]);
        assert_eq!(state.get(SsaValue(2)), expected);
    }

    #[test]
    fn transfer_non_phi_ignores_predecessor() {
        // Non-phi instructions should behave identically regardless of predecessor
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let inst = make_inst(0, SsaOp::Const(Some("42".into())), node);
        transfer_inst_with_predecessor(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(BlockId(5)),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(42));
    }

    // ─── Cross-file summary resolution tests ─────────────────────────

    use crate::labels::Cap;
    use crate::ssa::type_facts::TypeKind;
    use crate::summary::FuncSummary;
    use crate::summary::GlobalSummaries;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};
    use crate::symbol::{FuncKey, Lang};

    fn make_summary_ctx(gs: &GlobalSummaries) -> SymexSummaryCtx<'_> {
        SymexSummaryCtx {
            global_summaries: gs,
            lang: Lang::JavaScript,
            namespace: "test.js",
            type_facts: None,
        }
    }

    fn make_func_key(name: &str, arity: usize) -> FuncKey {
        FuncKey {
            lang: Lang::JavaScript,
            namespace: "helper.js".into(),
            name: name.into(),
            arity: Some(arity),
            ..Default::default()
        }
    }

    /// Insert both a regular FuncSummary (for resolve_callee_key lookup) and
    /// an SsaFuncSummary (for the actual symbolic modeling).
    fn insert_summary(gs: &mut GlobalSummaries, name: &str, arity: usize, ssa: SsaFuncSummary) {
        let key = make_func_key(name, arity);
        // Regular summary needed for by_lang_name index used by resolve_callee_key
        gs.insert(
            key.clone(),
            FuncSummary {
                name: name.into(),
                file_path: "helper.js".into(),
                lang: "javascript".into(),
                param_count: arity,
                param_names: vec![],
                source_caps: 0,
                sanitizer_caps: 0,
                sink_caps: 0,
                propagating_params: vec![],
                propagates_taint: false,
                tainted_sink_params: vec![],
                callees: vec![],
                ..Default::default()
            },
        );
        gs.insert_ssa(key, ssa);
    }

    #[test]
    fn transfer_call_identity_summary() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // Arg v0 is tainted
        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));

        // Build GlobalSummaries with exactly one Identity(param 0)
        let mut gs = GlobalSummaries::new();
        insert_summary(
            &mut gs,
            "passthrough",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        let ctx = make_summary_ctx(&gs);

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "passthrough".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            None,
            None,
        );

        // Should pass through arg's symbolic value
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_call_multiple_identity_fallback() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));
        state.set(SsaValue(1), SymbolicValue::Concrete(42));

        // Two Identity entries, should fall back to mk_call, NOT pick one
        let mut gs = GlobalSummaries::new();
        insert_summary(
            &mut gs,
            "ambig",
            2,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity), (1, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        let ctx = make_summary_ctx(&gs);

        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "ambig".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)], smallvec![SsaValue(1)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            None,
            None,
        );

        // Should fall back to Call expression, not Symbol pass-through
        match state.get(SsaValue(2)) {
            SymbolicValue::Call(name, _) => assert_eq!(name, "ambig"),
            other => panic!("expected Call fallback, got {:?}", other),
        }
    }

    #[test]
    fn transfer_call_stripbits_summary() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));

        let mut gs = GlobalSummaries::new();
        insert_summary(
            &mut gs,
            "sanitize",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::StripBits(Cap::SQL_QUERY))],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        let ctx = make_summary_ctx(&gs);

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "sanitize".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            None,
            None,
        );

        // StripBits → Unknown, not tainted
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Unknown);
        assert!(!state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_call_addbits_summary() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let mut gs = GlobalSummaries::new();
        insert_summary(
            &mut gs,
            "enrich",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::AddBits(Cap::ENV_VAR))],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        let ctx = make_summary_ctx(&gs);

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "enrich".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            None,
            None,
        );

        // AddBits → fresh Symbol, tainted
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Symbol(SsaValue(1)));
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_call_source_summary() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        let mut gs = GlobalSummaries::new();
        insert_summary(
            &mut gs,
            "readEnv",
            0,
            SsaFuncSummary {
                param_to_return: vec![],
                param_to_sink: vec![],
                source_caps: Cap::ENV_VAR,
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        let ctx = make_summary_ctx(&gs);

        let inst = make_inst(
            0,
            SsaOp::Call {
                callee: "readEnv".into(),
                callee_text: None,
                args: vec![],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            None,
            None,
        );

        // source_caps non-empty → tainted Symbol
        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(state.is_tainted(SsaValue(0)));
    }

    #[test]
    fn transfer_call_no_summary_fallback() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));

        // Empty GlobalSummaries → NotFound → mk_call fallback
        let gs = GlobalSummaries::new();
        let ctx = make_summary_ctx(&gs);

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "unknown_func".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            None,
            None,
        );

        match state.get(SsaValue(1)) {
            SymbolicValue::Call(name, _) => assert_eq!(name, "unknown_func"),
            other => panic!("expected Call fallback, got {:?}", other),
        }
    }

    #[test]
    fn transfer_call_none_summary_ctx_fallback() {
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));

        // No summary ctx at all → mk_call
        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "foo".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(&mut state, &inst, &cfg, &ssa, None, None, None, None, None);

        match state.get(SsaValue(1)) {
            SymbolicValue::Call(name, _) => assert_eq!(name, "foo"),
            other => panic!("expected Call fallback, got {:?}", other),
        }
        assert!(state.is_tainted(SsaValue(1)));
    }

    // ─── Type-qualified symbolic resolution tests ──────────

    use crate::ssa::type_facts::{TypeFact, TypeFactResult};
    use std::collections::HashMap;

    fn make_type_facts(entries: Vec<(SsaValue, TypeKind)>) -> TypeFactResult {
        let facts = entries
            .into_iter()
            .map(|(v, kind)| {
                (
                    v,
                    TypeFact {
                        kind,
                        nullable: false,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        TypeFactResult { facts }
    }

    fn insert_java_summary(
        gs: &mut GlobalSummaries,
        name: &str,
        namespace: &str,
        arity: usize,
        ssa: SsaFuncSummary,
    ) {
        let key = FuncKey {
            lang: Lang::Java,
            namespace: namespace.into(),
            name: name.into(),
            arity: Some(arity),
            ..Default::default()
        };
        gs.insert(
            key.clone(),
            FuncSummary {
                name: name.into(),
                file_path: namespace.into(),
                lang: "java".into(),
                param_count: arity,
                param_names: vec![],
                source_caps: 0,
                sanitizer_caps: 0,
                sink_caps: 0,
                propagating_params: vec![],
                propagates_taint: false,
                tainted_sink_params: vec![],
                callees: vec![],
                ..Default::default()
            },
        );
        gs.insert_ssa(key, ssa);
    }

    #[test]
    fn transfer_call_type_qualified_resolution() {
        // Receiver v1 typed as HttpClient, callee "send" → qualified "HttpClient.send"
        // Summary registered under "HttpClient.send" should be found.
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        // v0 = tainted URL argument
        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));
        // v1 = receiver (HttpClient instance)
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));

        let mut gs = GlobalSummaries::new();
        insert_java_summary(
            &mut gs,
            "HttpClient.send",
            "HttpClient.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );

        let tf = make_type_facts(vec![(SsaValue(1), TypeKind::HttpClient)]);
        let ctx = SymexSummaryCtx {
            global_summaries: &gs,
            lang: Lang::Java,
            namespace: "Caller.java",
            type_facts: Some(&tf),
        };

        // v2 = v1.send(v0)
        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "send".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: Some(SsaValue(1)),
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            Some(Lang::Java),
            None,
        );

        // Identity(0) maps to arg_syms[0] which is the receiver (prepended).
        // So return value should be the receiver's symbolic value.
        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Symbol(SsaValue(1)));
    }

    #[test]
    fn transfer_call_type_qualified_fallback_no_type() {
        // Receiver has no known type → type-qualified resolution does not fire,
        // bare-name resolution works normally.
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));

        // Register summary under bare name "passthrough" (Java, arity 1)
        let mut gs = GlobalSummaries::new();
        insert_java_summary(
            &mut gs,
            "passthrough",
            "helper.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );

        // Empty type facts, no receiver type info
        let tf = make_type_facts(vec![]);
        let ctx = SymexSummaryCtx {
            global_summaries: &gs,
            lang: Lang::Java,
            namespace: "test.java",
            type_facts: Some(&tf),
        };

        let inst = make_inst(
            1,
            SsaOp::Call {
                callee: "passthrough".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: None,
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            Some(Lang::Java),
            None,
        );

        // Bare-name resolution: Identity(0) → pass through arg
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Symbol(SsaValue(0)));
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn transfer_call_type_qualified_disambiguation() {
        // Two summaries both named "send" in different namespaces.
        // One named "HttpClient.send", type disambiguation picks it.
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.mark_tainted(SsaValue(0));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));

        let mut gs = GlobalSummaries::new();
        // First "send", generic, in ns A (Identity: passes through)
        insert_java_summary(
            &mut gs,
            "send",
            "SocketClient.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        // Second "send", in ns B, also with same arity → ambiguous bare-name
        insert_java_summary(
            &mut gs,
            "send",
            "WebSocketClient.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        // Also register the type-qualified name so Attempt 1 can find it
        insert_java_summary(
            &mut gs,
            "HttpClient.send",
            "HttpClient.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![],
                param_to_sink: vec![],
                source_caps: Cap::ENV_VAR, // Source, distinct signal
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );

        let tf = make_type_facts(vec![(SsaValue(1), TypeKind::HttpClient)]);
        let ctx = SymexSummaryCtx {
            global_summaries: &gs,
            lang: Lang::Java,
            namespace: "Caller.java",
            type_facts: Some(&tf),
        };

        // v2 = v1.send(v0), receiver v1 is HttpClient
        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "send".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: Some(SsaValue(1)),
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            Some(Lang::Java),
            None,
        );

        // Should resolve to "HttpClient.send" summary (source_caps=ENV_VAR → tainted Symbol)
        assert_eq!(state.get(SsaValue(2)), SymbolicValue::Symbol(SsaValue(2)));
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn transfer_call_type_qualified_wrong_owner() {
        // Receiver is HttpClient, but summary is registered as "DatabaseConnection.send".
        // Must NOT resolve to the wrong summary.
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));

        let mut gs = GlobalSummaries::new();
        // Summary under "DatabaseConnection.send", wrong type
        insert_java_summary(
            &mut gs,
            "DatabaseConnection.send",
            "DatabaseConnection.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![],
                param_to_sink: vec![],
                source_caps: Cap::ENV_VAR,
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );

        // Receiver typed as HttpClient, constructs "HttpClient.send", not "DatabaseConnection.send"
        let tf = make_type_facts(vec![(SsaValue(1), TypeKind::HttpClient)]);
        let ctx = SymexSummaryCtx {
            global_summaries: &gs,
            lang: Lang::Java,
            namespace: "Caller.java",
            type_facts: Some(&tf),
        };

        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "send".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: Some(SsaValue(1)),
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            Some(Lang::Java),
            None,
        );

        // "HttpClient.send" not found, bare "send" not found → opaque mk_call fallback
        match state.get(SsaValue(2)) {
            SymbolicValue::Call(name, _) => assert_eq!(name, "send"),
            other => panic!("expected Call fallback, got {:?}", other),
        }
    }

    #[test]
    fn transfer_call_type_qualified_ambiguous_no_force() {
        // Ambiguous bare-name candidates, receiver type known, but no candidate's
        // name exactly matches the qualified name → must NOT force-pick.
        let (cfg, node) = cfg_with_node(None);
        let ssa = empty_ssa();
        let mut state = SymbolicState::new();

        state.set(SsaValue(0), SymbolicValue::Symbol(SsaValue(0)));
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));

        let mut gs = GlobalSummaries::new();
        // Two "send" summaries, different namespaces → ambiguous
        insert_java_summary(
            &mut gs,
            "send",
            "ModuleA.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        insert_java_summary(
            &mut gs,
            "send",
            "ModuleB.java",
            1,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                param_to_gate_filters: vec![],
            },
        );
        // No "HttpClient.send" summary registered, disambiguation has 0 exact matches

        let tf = make_type_facts(vec![(SsaValue(1), TypeKind::HttpClient)]);
        let ctx = SymexSummaryCtx {
            global_summaries: &gs,
            lang: Lang::Java,
            namespace: "Caller.java",
            type_facts: Some(&tf),
        };

        let inst = make_inst(
            2,
            SsaOp::Call {
                callee: "send".into(),
                callee_text: None,
                args: vec![smallvec![SsaValue(0)]],
                receiver: Some(SsaValue(1)),
            },
            node,
        );
        transfer_inst(
            &mut state,
            &inst,
            &cfg,
            &ssa,
            Some(&ctx),
            None,
            None,
            Some(Lang::Java),
            None,
        );

        // Neither qualified lookup nor disambiguation found a match.
        // Bare-name path returns Ambiguous → falls through to mk_call.
        match state.get(SsaValue(2)) {
            SymbolicValue::Call(name, _) => assert_eq!(name, "send"),
            other => panic!("expected Call fallback for ambiguous case, got {:?}", other),
        }
    }
}

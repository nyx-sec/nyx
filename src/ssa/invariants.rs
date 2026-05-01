//! Structural invariant checks for SSA bodies.
//!
//! In addition to the `Vec<String>` aggregation used by
//! [`check_structural_invariants`], targeted checks that SSA *lowering* may
//! want to query directly (e.g. to decide whether to panic in debug builds
//! or warn + attach an engine note in release builds) return a
//! [`Result<(), InvariantError>`] for a more ergonomic API.
//!
//!
//! These checks prove that [`SsaBody`] instances are well-formed: single-
//! assignment holds, pred/succ edges are mutually consistent, phi operands
//! reference actual predecessors, terminators agree with the successor
//! list, and every `SsaValue` is backed by a matching `ValueDef`.
//!
//! The module is intentionally separate from the lowering code so the same
//! invariants can be exercised from tests that do not have access to the
//! private scaffolding inside [`crate::ssa::lower`].  Each function returns
//! a `Vec<String>` of violation messages rather than panicking; tests can
//! aggregate violations across an entire corpus before failing.
//!
//! Invariants are split into two groups:
//!
//! **Group A, SSA integrity (must hold unconditionally):**
//!
//! 1. `BlockId` indexing, `blocks[i].id == BlockId(i)`
//! 2. Entry block has no predecessors
//! 3. Pred/succ symmetry, `B.succs.contains(S)` ⇔ `S.preds.contains(B)`
//! 4. Phi placement, every phi appears in `block.phis` (never in body)
//! 5. Phi operand arity, ≤ `block.preds.len()`
//! 6. Phi operand sources, every `(pred_bid, _)` operand has
//!    `block.preds.contains(pred_bid)`
//! 7. Unique SSA definitions, every `SsaValue` is defined at most once
//!    across all phi + body instructions
//! 8. `value_defs` coverage, every defined `SsaValue.0` is a valid index
//!    into `value_defs`, and `value_defs[v.0].block` matches the block
//!    containing the defining instruction
//! 9. `cfg_node_map` consistency, every `(node, SsaValue)` pair points
//!    to an instruction whose `cfg_node == node`
//!
//! **Group B, terminator and reachability (loose, reflecting lowering):**
//!
//! 10. Terminator/succs agreement *subset* form:
//!     * `Goto(t)`              → `succs.contains(t)`, extras tolerated
//!       (3-successor collapse fallback)
//!     * `Branch{t, f, …}`      → `succs` contains both `t` and `f`
//!     * `Return`/`Unreachable` → no constraint on `succs` (CFG may carry
//!       finally/cleanup continuation edges that downstream analysis
//!       propagates through)
//! 11. Reachability from entry, tolerated exceptions:
//!     * blocks that appear as the `catch` side of an exception edge
//!
//! Group B is deliberately permissive: the SSA body's `succs` field is the
//! authoritative successor set for analysis (taint, abstract interp,
//! symbolic execution all enumerate `block.succs`), while the terminator
//! is a structured summary that may simplify or drop CFG-level info.
//! Regression value comes from catching *new* deviations from these
//! already-understood patterns, not from enforcing a textbook SSA shape
//! the lowering never promised.

use super::ir::*;

/// Errors returned by targeted invariant checks.
///
/// Wraps a list of human-readable violation messages, one per offending
/// block, so callers can include every failure in a single panic /
/// warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantError {
    pub messages: Vec<String>,
}

impl InvariantError {
    /// Join every message onto its own line.
    pub fn joined(&self) -> String {
        self.messages.join("\n")
    }
}

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.joined())
    }
}

impl std::error::Error for InvariantError {}

/// Aggregate invariant violations found in a single body.  An empty
/// vector means the body is structurally well-formed.
pub fn check_structural_invariants(body: &SsaBody) -> Vec<String> {
    let mut errors = Vec::new();

    check_block_ids(body, &mut errors);
    check_entry_has_no_preds(body, &mut errors);
    check_pred_succ_symmetry(body, &mut errors);
    check_terminator_succ_agreement(body, &mut errors);
    check_phi_placement_and_arity(body, &mut errors);
    check_phi_operand_sources(body, &mut errors);
    check_unique_definitions(body, &mut errors);
    check_value_def_coverage(body, &mut errors);
    check_cfg_node_map(body, &mut errors);
    check_reachability(body, &mut errors);
    if let Err(e) = check_catch_block_reachability(body) {
        errors.extend(e.messages);
    }

    errors
}

/// Every block carrying an [`SsaOp::CatchParam`], an exception-handler
/// entry, must be reachable from either the function entry (via normal
/// flow) or from at least one entry in [`SsaBody::exception_edges`].
///
/// When this fails, the CFG builder has produced an orphan catch block
/// that should have been wired up as an exception successor but was not ,
/// a real construction bug that otherwise manifests as silent false
/// negatives in resource-cleanup / exception-flow findings.
pub fn check_catch_block_reachability(body: &SsaBody) -> Result<(), InvariantError> {
    let n = body.blocks.len();
    if n == 0 {
        return Ok(());
    }

    // 1. Identify catch blocks: any block containing a CatchParam op in
    //    either its phi or body lists.
    let catch_blocks: Vec<BlockId> = body
        .blocks
        .iter()
        .filter(|b| {
            b.phis
                .iter()
                .chain(b.body.iter())
                .any(|inst| matches!(inst.op, SsaOp::CatchParam))
        })
        .map(|b| b.id)
        .collect();

    if catch_blocks.is_empty() {
        return Ok(());
    }

    // 2. BFS from entry via normal succs.
    let mut reachable = vec![false; n];
    let entry_idx = body.entry.0 as usize;
    if entry_idx < n {
        reachable[entry_idx] = true;
        let mut stack: Vec<BlockId> = vec![body.entry];
        while let Some(b) = stack.pop() {
            for &s in &body.blocks[b.0 as usize].succs {
                let sidx = s.0 as usize;
                if sidx < n && !reachable[sidx] {
                    reachable[sidx] = true;
                    stack.push(s);
                }
            }
        }
    }

    // 3. Collect exception-edge targets.
    let exception_targets: std::collections::HashSet<BlockId> = body
        .exception_edges
        .iter()
        .map(|(_, catch)| *catch)
        .collect();

    // 4. Each catch block must be normal-reachable OR an exception target.
    let mut messages = Vec::new();
    for bid in catch_blocks {
        let idx = bid.0 as usize;
        let normal = idx < n && reachable[idx];
        let via_exception = exception_targets.contains(&bid);
        if !normal && !via_exception {
            messages.push(format!(
                "catch-block orphan: block {:?} carries CatchParam but is neither \
                 reachable from entry {:?} nor a target of any exception edge",
                bid, body.entry
            ));
        }
    }

    if messages.is_empty() {
        Ok(())
    } else {
        Err(InvariantError { messages })
    }
}

// ── Individual invariant checks ─────────────────────────────────────────

fn check_block_ids(body: &SsaBody, errors: &mut Vec<String>) {
    for (i, block) in body.blocks.iter().enumerate() {
        if block.id.0 as usize != i {
            errors.push(format!(
                "block at index {i} has mismatched id {:?}",
                block.id
            ));
        }
    }
}

fn check_entry_has_no_preds(body: &SsaBody, errors: &mut Vec<String>) {
    let entry_idx = body.entry.0 as usize;
    if entry_idx >= body.blocks.len() {
        errors.push(format!("entry {:?} is out of bounds", body.entry));
        return;
    }
    let entry = &body.blocks[entry_idx];
    if !entry.preds.is_empty() {
        errors.push(format!(
            "entry block {:?} has {} predecessor(s): {:?}",
            body.entry,
            entry.preds.len(),
            entry.preds
        ));
    }
}

fn check_pred_succ_symmetry(body: &SsaBody, errors: &mut Vec<String>) {
    for block in &body.blocks {
        for &succ in &block.succs {
            let sidx = succ.0 as usize;
            if sidx >= body.blocks.len() {
                errors.push(format!(
                    "block {:?} has out-of-bounds succ {:?}",
                    block.id, succ
                ));
                continue;
            }
            if !body.blocks[sidx].preds.contains(&block.id) {
                errors.push(format!(
                    "block {:?} lists succ {:?} but {:?} does not list {:?} as pred",
                    block.id, succ, succ, block.id
                ));
            }
        }
        for &pred in &block.preds {
            let pidx = pred.0 as usize;
            if pidx >= body.blocks.len() {
                errors.push(format!(
                    "block {:?} has out-of-bounds pred {:?}",
                    block.id, pred
                ));
                continue;
            }
            if !body.blocks[pidx].succs.contains(&block.id) {
                errors.push(format!(
                    "block {:?} lists pred {:?} but {:?} does not list {:?} as succ",
                    block.id, pred, pred, block.id
                ));
            }
        }
    }
}

fn check_terminator_succ_agreement(body: &SsaBody, errors: &mut Vec<String>) {
    // Group B, loose agreement.  See module docs for rationale.
    for block in &body.blocks {
        match &block.terminator {
            Terminator::Goto(target) => {
                if !block.succs.iter().any(|s| s == target) {
                    errors.push(format!(
                        "block {:?} Goto({:?}) target not in succs {:?}",
                        block.id, target, block.succs
                    ));
                }
            }
            Terminator::Branch {
                true_blk,
                false_blk,
                ..
            } => {
                if !block.succs.iter().any(|s| s == true_blk) {
                    errors.push(format!(
                        "block {:?} Branch true target {:?} not in succs {:?}",
                        block.id, true_blk, block.succs
                    ));
                }
                if !block.succs.iter().any(|s| s == false_blk) {
                    errors.push(format!(
                        "block {:?} Branch false target {:?} not in succs {:?}",
                        block.id, false_blk, block.succs
                    ));
                }
            }
            Terminator::Switch {
                targets, default, ..
            } => {
                // Every Switch target and the default arm must be in succs.
                for t in targets {
                    if !block.succs.iter().any(|s| s == t) {
                        errors.push(format!(
                            "block {:?} Switch target {:?} not in succs {:?}",
                            block.id, t, block.succs
                        ));
                    }
                }
                if !block.succs.iter().any(|s| s == default) {
                    errors.push(format!(
                        "block {:?} Switch default {:?} not in succs {:?}",
                        block.id, default, block.succs
                    ));
                }
            }
            Terminator::Return(_) | Terminator::Unreachable => {
                // Loose by design, cleanup/finally continuation edges in
                // `succs` are expected.  Downstream consumers (taint
                // `compute_succ_states`, SCCP `process_terminator`) treat
                // `succs` as authoritative and propagate across these edges,
                // so the terminator shape must not forbid them.
            }
        }
    }
}

fn check_phi_placement_and_arity(body: &SsaBody, errors: &mut Vec<String>) {
    for block in &body.blocks {
        // Phis must not appear in body.
        for inst in &block.body {
            if matches!(inst.op, SsaOp::Phi(_)) {
                errors.push(format!(
                    "block {:?} has a Phi op in body (should be in phis): value {:?}",
                    block.id, inst.value
                ));
            }
        }
        // Every entry in `phis` must be a Phi op.
        for inst in &block.phis {
            if !matches!(inst.op, SsaOp::Phi(_)) {
                errors.push(format!(
                    "block {:?} has non-Phi op in phis slot: value {:?}",
                    block.id, inst.value
                ));
            }
            if let SsaOp::Phi(ref ops) = inst.op
                && ops.len() > block.preds.len()
            {
                errors.push(format!(
                    "block {:?} phi for {:?} has {} operand(s) > {} pred(s)",
                    block.id,
                    inst.value,
                    ops.len(),
                    block.preds.len()
                ));
            }
        }
    }
}

fn check_phi_operand_sources(body: &SsaBody, errors: &mut Vec<String>) {
    for block in &body.blocks {
        for inst in &block.phis {
            if let SsaOp::Phi(ref ops) = inst.op {
                for &(pred_bid, operand_value) in ops.iter() {
                    if !block.preds.contains(&pred_bid) {
                        errors.push(format!(
                            "block {:?} phi for {:?} references non-pred {:?} (preds: {:?})",
                            block.id, inst.value, pred_bid, block.preds
                        ));
                    }
                    // Operand value must be a valid SSA index.
                    if (operand_value.0 as usize) >= body.value_defs.len() {
                        errors.push(format!(
                            "block {:?} phi for {:?} has operand {:?} out of value_defs range",
                            block.id, inst.value, operand_value
                        ));
                    }
                }
            }
        }
    }
}

fn check_unique_definitions(body: &SsaBody, errors: &mut Vec<String>) {
    let mut seen: std::collections::HashMap<SsaValue, BlockId> =
        std::collections::HashMap::with_capacity(body.value_defs.len());
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let Some(prev) = seen.insert(inst.value, block.id) {
                errors.push(format!(
                    "SSA {:?} defined in both {:?} and {:?} — single-assignment violated",
                    inst.value, prev, block.id
                ));
            }
        }
    }
}

fn check_value_def_coverage(body: &SsaBody, errors: &mut Vec<String>) {
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let idx = inst.value.0 as usize;
            if idx >= body.value_defs.len() {
                errors.push(format!(
                    "instruction defining {:?} in block {:?} has no entry in value_defs (len {})",
                    inst.value,
                    block.id,
                    body.value_defs.len()
                ));
                continue;
            }
            let def = &body.value_defs[idx];
            if def.block != block.id {
                errors.push(format!(
                    "value_defs[{}] records block {:?} but instruction lives in block {:?}",
                    idx, def.block, block.id
                ));
            }
        }
    }
}

fn check_cfg_node_map(body: &SsaBody, errors: &mut Vec<String>) {
    for (&cfg_node, &sv) in body.cfg_node_map.iter() {
        let idx = sv.0 as usize;
        if idx >= body.value_defs.len() {
            errors.push(format!(
                "cfg_node_map points {:?} → {:?} which is out of value_defs range",
                cfg_node, sv
            ));
            continue;
        }
        let def = &body.value_defs[idx];
        if def.cfg_node != cfg_node {
            errors.push(format!(
                "cfg_node_map inconsistency: map says {:?} → {:?}, but value_defs[{}].cfg_node = {:?}",
                cfg_node, sv, idx, def.cfg_node
            ));
        }
    }
}

fn check_reachability(body: &SsaBody, errors: &mut Vec<String>) {
    let n = body.blocks.len();
    if n == 0 {
        errors.push("body has zero blocks".into());
        return;
    }
    let entry_idx = body.entry.0 as usize;
    if entry_idx >= n {
        // already reported by check_entry_has_no_preds
        return;
    }

    // Multi-root BFS: start from the entry *and* from every catch target
    // recorded in `exception_edges`.  Exception-handler blocks are reached
    // via stripped exception edges, so from the SSA body's perspective they
    // look like roots, as does anything transitively reachable from them
    // (e.g. a `finally` block chained after a `catch`).
    let mut visited = vec![false; n];
    let mut stack: Vec<BlockId> = Vec::new();
    let seed = |bid: BlockId, visited: &mut [bool], stack: &mut Vec<BlockId>| {
        let idx = bid.0 as usize;
        if idx < visited.len() && !visited[idx] {
            visited[idx] = true;
            stack.push(bid);
        }
    };
    seed(body.entry, &mut visited, &mut stack);
    for (_src, catch_target) in &body.exception_edges {
        seed(*catch_target, &mut visited, &mut stack);
    }
    while let Some(bid) = stack.pop() {
        let block = &body.blocks[bid.0 as usize];
        for &s in &block.succs {
            let sidx = s.0 as usize;
            if sidx < n && !visited[sidx] {
                visited[sidx] = true;
                stack.push(s);
            }
        }
    }

    for (i, v) in visited.iter().enumerate() {
        if !*v {
            let block = &body.blocks[i];
            errors.push(format!(
                "block {:?} is unreachable from entry {:?} or any exception-handler root",
                block.id, body.entry
            ));
        }
    }
}

// ── Optimization idempotence ─────────────────────────────────────────────

/// Compute a structural fingerprint of an [`SsaBody`] that is stable across
/// equivalent lowerings / optimisations.  Two bodies producing the same
/// fingerprint have the same block structure, terminator shape, per-block
/// phi/body instruction counts and op-kind sequences.  SsaValue numbers are
/// not part of the fingerprint, so renumbering between runs does not cause
/// spurious diffs, only shape changes do.
///
/// Phis are emitted in their natural (insertion) order.  Lowering now drives
/// phi placement through a `BTreeSet`, so that order is deterministic
/// (alphabetical by `var_name`) and any divergence between runs is a real
/// regression rather than hasher noise.
pub fn body_fingerprint(body: &SsaBody) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "entry={:?}", body.entry);
    let _ = writeln!(out, "blocks={}", body.blocks.len());
    for block in &body.blocks {
        let _ = writeln!(
            out,
            "  b{:?} preds={} succs={} phis={} body={} term={}",
            block.id,
            block.preds.len(),
            block.succs.len(),
            block.phis.len(),
            block.body.len(),
            terminator_kind(&block.terminator),
        );
        for inst in &block.phis {
            if let SsaOp::Phi(ref ops) = inst.op {
                let _ = writeln!(
                    out,
                    "    phi var={} operands={}",
                    inst.var_name.as_deref().unwrap_or(""),
                    ops.len(),
                );
            }
        }
        for inst in &block.body {
            let _ = writeln!(out, "    {}", op_kind(&inst.op));
        }
    }
    out
}

fn terminator_kind(t: &Terminator) -> &'static str {
    match t {
        Terminator::Goto(_) => "Goto",
        Terminator::Branch { .. } => "Branch",
        Terminator::Switch { .. } => "Switch",
        Terminator::Return(_) => "Return",
        Terminator::Unreachable => "Unreachable",
    }
}

fn op_kind(op: &SsaOp) -> &'static str {
    match op {
        SsaOp::Phi(_) => "Phi",
        SsaOp::Assign(_) => "Assign",
        SsaOp::Call { .. } => "Call",
        SsaOp::Source => "Source",
        SsaOp::Const(_) => "Const",
        SsaOp::Param { .. } => "Param",
        SsaOp::SelfParam => "SelfParam",
        SsaOp::CatchParam => "CatchParam",
        SsaOp::Nop => "Nop",
        SsaOp::Undef => "Undef",
        SsaOp::FieldProj { .. } => "FieldProj",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{Cfg, EdgeKind, NodeInfo, StmtKind, TaintMeta};
    use crate::ssa::lower_to_ssa;
    use petgraph::Graph;
    use petgraph::graph::NodeIndex;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    fn def(var: &str) -> NodeInfo {
        NodeInfo {
            taint: TaintMeta {
                defines: Some(var.into()),
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        }
    }

    fn use_var(var: &str) -> NodeInfo {
        NodeInfo {
            taint: TaintMeta {
                uses: vec![var.into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        }
    }

    fn assert_well_formed(body: &SsaBody) {
        let errs = check_structural_invariants(body);
        assert!(
            errs.is_empty(),
            "structural invariants failed:\n{}",
            errs.join("\n")
        );
    }

    #[test]
    fn linear_cfg_is_well_formed() {
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let n1 = cfg.add_node(def("x"));
        let n2 = cfg.add_node(use_var("x"));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, n1, EdgeKind::Seq);
        cfg.add_edge(n1, n2, EdgeKind::Seq);
        cfg.add_edge(n2, exit, EdgeKind::Seq);
        let body = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert_well_formed(&body);
    }

    #[test]
    fn diamond_cfg_is_well_formed() {
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_n = cfg.add_node(make_node(StmtKind::If));
        let t = cfg.add_node(def("x"));
        let f = cfg.add_node(def("x"));
        let join = cfg.add_node(use_var("x"));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, if_n, EdgeKind::Seq);
        cfg.add_edge(if_n, t, EdgeKind::True);
        cfg.add_edge(if_n, f, EdgeKind::False);
        cfg.add_edge(t, join, EdgeKind::Seq);
        cfg.add_edge(f, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);
        let body = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert_well_formed(&body);

        // Additionally: the join block must carry a phi whose operands come
        // from exactly its two predecessors.
        let phi_block = body
            .blocks
            .iter()
            .find(|b| !b.phis.is_empty())
            .expect("diamond should produce a phi");
        for phi in &phi_block.phis {
            if let SsaOp::Phi(ref ops) = phi.op {
                for (pred, _) in ops {
                    assert!(
                        phi_block.preds.iter().any(|p| p == pred),
                        "phi operand {pred:?} is not a pred of {:?}",
                        phi_block.id
                    );
                }
            }
        }
    }

    #[test]
    fn loop_cfg_is_well_formed() {
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let init = cfg.add_node(def("x"));
        let header = cfg.add_node(make_node(StmtKind::Loop));
        let body_n = cfg.add_node(def("x"));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, init, EdgeKind::Seq);
        cfg.add_edge(init, header, EdgeKind::Seq);
        cfg.add_edge(header, body_n, EdgeKind::True);
        cfg.add_edge(body_n, header, EdgeKind::Back);
        cfg.add_edge(header, exit, EdgeKind::False);
        let body = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert_well_formed(&body);
    }

    #[test]
    fn fingerprint_is_stable_on_double_lowering() {
        // Lowering twice on the same CFG must produce the same fingerprint.
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_n = cfg.add_node(make_node(StmtKind::If));
        let t = cfg.add_node(def("x"));
        let f = cfg.add_node(def("x"));
        let join = cfg.add_node(use_var("x"));
        let exit = cfg.add_node(make_node(StmtKind::Exit));
        cfg.add_edge(entry, if_n, EdgeKind::Seq);
        cfg.add_edge(if_n, t, EdgeKind::True);
        cfg.add_edge(if_n, f, EdgeKind::False);
        cfg.add_edge(t, join, EdgeKind::Seq);
        cfg.add_edge(f, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);
        let a = lower_to_ssa(&cfg, entry, None, true).unwrap();
        let b = lower_to_ssa(&cfg, entry, None, true).unwrap();
        assert_eq!(body_fingerprint(&a), body_fingerprint(&b));
    }

    #[test]
    fn phis_are_emitted_in_alphabetical_order() {
        // Diamond CFG with multiple variables defined on both sides:
        // Entry → If → [True: a=, b=, c=] [False: a=, b=, c=] → Join → Exit
        // Join should carry phis for a, b, and c, emitted alphabetically
        // as a consequence of the BTreeSet-backed phi_placements.
        fn defs(vars: &[&str]) -> NodeInfo {
            // Chain multiple Seq nodes; tests/fixtures route each `def(var)`
            // through its own node, so build a little sub-block here.
            // For a single NodeInfo we can only record one define; callers
            // emit one node per variable.
            NodeInfo {
                taint: TaintMeta {
                    defines: Some(vars[0].into()),
                    ..Default::default()
                },
                ..make_node(StmtKind::Seq)
            }
        }
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let if_n = cfg.add_node(make_node(StmtKind::If));

        // True branch defines c, then a, then b (intentionally non-alphabetical
        // to prove the fingerprint order is driven by lowering, not source).
        let t_c = cfg.add_node(defs(&["c"]));
        let t_a = cfg.add_node(defs(&["a"]));
        let t_b = cfg.add_node(defs(&["b"]));

        // False branch: same vars, different order to make sure neither side
        // accidentally sets the ordering downstream.
        let f_b = cfg.add_node(defs(&["b"]));
        let f_c = cfg.add_node(defs(&["c"]));
        let f_a = cfg.add_node(defs(&["a"]));

        let join = cfg.add_node(NodeInfo {
            taint: TaintMeta {
                uses: vec!["a".into(), "b".into(), "c".into()],
                ..Default::default()
            },
            ..make_node(StmtKind::Seq)
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, if_n, EdgeKind::Seq);
        cfg.add_edge(if_n, t_c, EdgeKind::True);
        cfg.add_edge(t_c, t_a, EdgeKind::Seq);
        cfg.add_edge(t_a, t_b, EdgeKind::Seq);
        cfg.add_edge(t_b, join, EdgeKind::Seq);
        cfg.add_edge(if_n, f_b, EdgeKind::False);
        cfg.add_edge(f_b, f_c, EdgeKind::Seq);
        cfg.add_edge(f_c, f_a, EdgeKind::Seq);
        cfg.add_edge(f_a, join, EdgeKind::Seq);
        cfg.add_edge(join, exit, EdgeKind::Seq);

        let body = lower_to_ssa(&cfg, entry, None, true).unwrap();
        let join_block = body
            .blocks
            .iter()
            .find(|b| b.phis.len() >= 3)
            .expect("join block should carry phis for a, b, c");
        let names: Vec<&str> = join_block
            .phis
            .iter()
            .filter_map(|inst| inst.var_name.as_deref())
            .collect();
        assert_eq!(
            names,
            vec!["a", "b", "c"],
            "phis within a block must be emitted in alphabetical var_name order"
        );
    }

    #[test]
    fn broken_pred_succ_symmetry_is_detected() {
        // Hand-craft a body with inconsistent pred/succ lists.
        use smallvec::smallvec;
        let body = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Unreachable,
                    preds: smallvec![], // Missing pred back to 0.
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let errs = check_structural_invariants(&body);
        assert!(
            errs.iter().any(|e| e.contains("does not list")),
            "expected a symmetry violation, got: {:?}",
            errs
        );
    }

    #[test]
    fn duplicate_ssa_def_is_detected() {
        use smallvec::smallvec;
        let dummy_cfg = NodeIndex::new(0);
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(None),
                        cfg_node: dummy_cfg,
                        var_name: None,
                        span: (0, 0),
                    },
                    SsaInst {
                        value: SsaValue(0), // duplicate
                        op: SsaOp::Const(None),
                        cfg_node: dummy_cfg,
                        var_name: None,
                        span: (0, 0),
                    },
                ],
                terminator: Terminator::Unreachable,
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: None,
                cfg_node: dummy_cfg,
                block: BlockId(0),
            }],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let errs = check_structural_invariants(&body);
        assert!(
            errs.iter()
                .any(|e| e.contains("single-assignment violated")),
            "expected a duplicate-def violation, got: {:?}",
            errs
        );
    }

    #[test]
    fn phi_operand_from_non_pred_is_detected() {
        use smallvec::smallvec;
        let dummy_cfg = NodeIndex::new(0);
        let body = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    // Phi claims an operand from block 2 which isn't in preds.
                    phis: vec![SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Phi(smallvec![(BlockId(2), SsaValue(0))]),
                        cfg_node: dummy_cfg,
                        var_name: Some("x".into()),
                        span: (0, 0),
                    }],
                    body: vec![],
                    terminator: Terminator::Unreachable,
                    preds: smallvec![BlockId(0)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("x".into()),
                cfg_node: dummy_cfg,
                block: BlockId(1),
            }],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let errs = check_structural_invariants(&body);
        assert!(
            errs.iter().any(|e| e.contains("references non-pred")),
            "expected a phi-operand-source violation, got: {:?}",
            errs
        );
    }

    #[test]
    fn terminator_disagreeing_with_succs_is_detected() {
        use smallvec::smallvec;
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                // Goto(1) but succs is empty.
                terminator: Terminator::Goto(BlockId(1)),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: Default::default(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let errs = check_structural_invariants(&body);
        assert!(
            errs.iter().any(|e| e.contains("Goto")),
            "expected a terminator/succ disagreement, got: {:?}",
            errs
        );
    }
}

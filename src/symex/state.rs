//! Symbolic state tracking per-SSA-value expressions and path constraints.

use std::collections::{HashMap, HashSet};

use crate::constraint::ConditionExpr;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::{BlockId, SsaBody, SsaValue};
use crate::taint::Finding;

use super::heap::SymbolicHeap;
use super::value::SymbolicValue;

/// A branch constraint collected along the path.
#[derive(Clone, Debug)]
pub struct PathConstraint {
    /// The block where this branch was taken.
    pub block: BlockId,
    /// The structured condition expression.
    pub condition: ConditionExpr,
    /// `true` = took the true branch; `false` = took the false branch.
    pub polarity: bool,
}

/// Symbolic state for a path walk through SSA blocks.
///
/// Tracks a symbolic expression tree per SSA value, branch constraints
/// collected along the path, and a flat taint root-set with eager propagation.
///
/// `Clone` is required for multi-path exploration: the executor clones the
/// state at branch forks to explore both successors independently.
#[derive(Clone)]
pub struct SymbolicState {
    /// Symbolic value for each SSA value encountered on the path.
    values: HashMap<SsaValue, SymbolicValue>,
    /// Branch constraints collected along the path.
    path_constraints: Vec<PathConstraint>,
    /// SSA values known to carry taint. Eagerly propagated during transfer ,
    /// no recursive expression-tree walking needed.
    tainted_roots: HashSet<SsaValue>,
    /// Field-sensitive symbolic heap.
    heap: SymbolicHeap,
    /// Exception context for catch-path symbolic execution.
    /// When `Some`, the next `CatchParam` instruction consumes this value and
    /// marks itself tainted. This is NOT a faithful model of the thrown value ,
    /// it is a taint carrier that signals "this CatchParam was reached via an
    /// exception edge and should be treated as tainted." The symbolic value is
    /// `Unknown` because we do not model the exception object's structure.
    exception_context: Option<SymbolicValue>,
}

impl SymbolicState {
    /// Create an empty symbolic state.
    pub fn new() -> Self {
        SymbolicState {
            values: HashMap::new(),
            path_constraints: Vec::new(),
            tainted_roots: HashSet::new(),
            heap: SymbolicHeap::new(),
            exception_context: None,
        }
    }

    /// Get the symbolic value for an SSA value.
    ///
    /// Returns a clone of the mapped value, or `Unknown` if absent.
    pub fn get(&self, v: SsaValue) -> SymbolicValue {
        self.values
            .get(&v)
            .cloned()
            .unwrap_or(SymbolicValue::Unknown)
    }

    /// Set the symbolic value for an SSA value.
    pub fn set(&mut self, v: SsaValue, val: SymbolicValue) {
        self.values.insert(v, val);
    }

    /// Record a branch constraint taken along this path.
    pub fn add_constraint(&mut self, c: PathConstraint) {
        self.path_constraints.push(c);
    }

    /// Get all path constraints accumulated on this path.
    pub fn path_constraints(&self) -> &[PathConstraint] {
        &self.path_constraints
    }

    /// Iterate over all (SsaValue, SymbolicValue) entries in the state.
    pub fn iter_values(&self) -> impl Iterator<Item = (&SsaValue, &SymbolicValue)> {
        self.values.iter()
    }

    /// Mark an SSA value as tainted (adds to the root set).
    pub fn mark_tainted(&mut self, v: SsaValue) {
        self.tainted_roots.insert(v);
    }

    /// Check if an SSA value is tainted (flat set membership).
    pub fn is_tainted(&self, v: SsaValue) -> bool {
        self.tainted_roots.contains(&v)
    }

    /// Get the set of all tainted SSA values.
    pub fn tainted_values(&self) -> &HashSet<SsaValue> {
        &self.tainted_roots
    }

    /// Set the exception context for catch-path CatchParam seeding.
    pub fn set_exception_context(&mut self, val: SymbolicValue) {
        self.exception_context = Some(val);
    }

    /// Consume the exception context. Returns `Some` exactly once per catch block.
    pub fn take_exception_context(&mut self) -> Option<SymbolicValue> {
        self.exception_context.take()
    }

    /// Propagate taint: if any operand is tainted, mark `result` as tainted.
    pub fn propagate_taint(&mut self, result: SsaValue, operands: &[SsaValue]) {
        if operands.iter().any(|op| self.tainted_roots.contains(op)) {
            self.tainted_roots.insert(result);
        }
    }

    /// Widen symbolic precision at a loop head after bounded unrolling.
    ///
    /// Sets all phi-defined values in the block to `Unknown` (we no longer
    /// know the concrete shape after arbitrary loop iterations), but
    /// **preserves taint**: if a phi value was tainted before widening, it
    /// remains tainted. `Unknown + tainted` means "shape unknown but still
    /// attacker-controlled."
    /// Get a reference to the symbolic heap.
    pub fn heap(&self) -> &SymbolicHeap {
        &self.heap
    }

    /// Get a mutable reference to the symbolic heap.
    pub fn heap_mut(&mut self) -> &mut SymbolicHeap {
        &mut self.heap
    }

    pub fn widen_at_loop_head(&mut self, block: BlockId, ssa: &SsaBody) {
        let block_data = &ssa.blocks[block.0 as usize];
        for phi in &block_data.phis {
            self.values.insert(phi.value, SymbolicValue::Unknown);
            // PRESERVE taint, do NOT remove from tainted_roots.
        }
        // Widen heap: degrade field symbolic precision, preserve taint.
        self.heap.widen();
    }

    /// Seed symbolic values from SSA constant propagation results.
    ///
    /// Maps `ConstLattice::Int(i)` to `Concrete(i)` and
    /// `ConstLattice::Str(s)` to `ConcreteStr(s)`. Other lattice values
    /// (Bool, Null, Top, Varying) are left as `Unknown` (not stored).
    pub fn seed_from_const_values(&mut self, const_values: &HashMap<SsaValue, ConstLattice>) {
        for (&v, cl) in const_values {
            match cl {
                ConstLattice::Int(i) => {
                    self.values.insert(v, SymbolicValue::Concrete(*i));
                }
                ConstLattice::Str(s) => {
                    self.values.insert(v, SymbolicValue::ConcreteStr(s.clone()));
                }
                _ => {} // Bool, Null, Top, Varying, not modeled
            }
        }
    }

    /// Resolve a phi to the operand from a specific predecessor.
    ///
    /// Returns the symbolic value for the matched predecessor's operand.
    /// Falls back to full `mk_phi(...)` only when the predecessor is genuinely
    /// not found among the phi's operands (e.g. unreachable predecessor was
    /// pruned during SSA construction).
    pub fn resolve_phi_from_predecessor(
        &self,
        operands: &[(BlockId, SsaValue)],
        predecessor: BlockId,
    ) -> SymbolicValue {
        for (bid, v) in operands {
            if *bid == predecessor {
                return self.get(*v);
            }
        }
        // Fallback: build the full phi expression
        let phi_ops: Vec<_> = operands
            .iter()
            .map(|(bid, v)| (*bid, self.get(*v)))
            .collect();
        super::value::mk_phi(phi_ops)
    }

    /// Generate a witness string for the sink value of a finding.
    ///
    /// Looks up the sink's SSA value via `cfg_node_map`, retrieves its
    /// symbolic expression, and formats it. Returns `None` if the value
    /// is `Unknown` (no useful witness).
    pub fn get_sink_witness(&self, finding: &Finding, ssa: &SsaBody) -> Option<String> {
        let ssa_val = ssa.cfg_node_map.get(&finding.sink)?;
        let sym = self.get(*ssa_val);
        if matches!(sym, SymbolicValue::Unknown) {
            return None;
        }
        Some(format!("{}", sym))
    }
}

impl Default for SymbolicState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_unknown_for_absent() {
        let state = SymbolicState::new();
        assert_eq!(state.get(SsaValue(99)), SymbolicValue::Unknown);
    }

    #[test]
    fn set_get_round_trip() {
        let mut state = SymbolicState::new();
        state.set(SsaValue(1), SymbolicValue::Concrete(42));
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Concrete(42));
    }

    #[test]
    fn set_overwrites() {
        let mut state = SymbolicState::new();
        state.set(SsaValue(1), SymbolicValue::Concrete(1));
        state.set(SsaValue(1), SymbolicValue::Concrete(2));
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Concrete(2));
    }

    #[test]
    fn mark_tainted_and_check() {
        let mut state = SymbolicState::new();
        assert!(!state.is_tainted(SsaValue(1)));
        state.mark_tainted(SsaValue(1));
        assert!(state.is_tainted(SsaValue(1)));
        assert!(!state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn propagate_taint_with_tainted_operand() {
        let mut state = SymbolicState::new();
        state.mark_tainted(SsaValue(1));
        state.propagate_taint(SsaValue(3), &[SsaValue(1), SsaValue(2)]);
        assert!(state.is_tainted(SsaValue(3)));
    }

    #[test]
    fn propagate_taint_with_no_tainted_operand() {
        let mut state = SymbolicState::new();
        state.propagate_taint(SsaValue(3), &[SsaValue(1), SsaValue(2)]);
        assert!(!state.is_tainted(SsaValue(3)));
    }

    #[test]
    fn propagate_taint_chain() {
        let mut state = SymbolicState::new();
        state.mark_tainted(SsaValue(0)); // source
        state.propagate_taint(SsaValue(1), &[SsaValue(0)]); // copy
        state.propagate_taint(SsaValue(2), &[SsaValue(1), SsaValue(99)]); // binop
        assert!(state.is_tainted(SsaValue(1)));
        assert!(state.is_tainted(SsaValue(2)));
    }

    #[test]
    fn seed_from_const_values_int() {
        let mut state = SymbolicState::new();
        let mut cv = HashMap::new();
        cv.insert(SsaValue(1), ConstLattice::Int(42));
        state.seed_from_const_values(&cv);
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Concrete(42));
    }

    #[test]
    fn seed_from_const_values_str() {
        let mut state = SymbolicState::new();
        let mut cv = HashMap::new();
        cv.insert(SsaValue(2), ConstLattice::Str("hello".into()));
        state.seed_from_const_values(&cv);
        assert_eq!(
            state.get(SsaValue(2)),
            SymbolicValue::ConcreteStr("hello".into())
        );
    }

    #[test]
    fn seed_from_const_values_bool_ignored() {
        let mut state = SymbolicState::new();
        let mut cv = HashMap::new();
        cv.insert(SsaValue(3), ConstLattice::Bool(true));
        state.seed_from_const_values(&cv);
        assert_eq!(state.get(SsaValue(3)), SymbolicValue::Unknown);
    }

    #[test]
    fn seed_from_const_values_null_ignored() {
        let mut state = SymbolicState::new();
        let mut cv = HashMap::new();
        cv.insert(SsaValue(4), ConstLattice::Null);
        state.seed_from_const_values(&cv);
        assert_eq!(state.get(SsaValue(4)), SymbolicValue::Unknown);
    }

    #[test]
    fn get_sink_witness_for_concrete() {
        let mut state = SymbolicState::new();
        state.set(
            SsaValue(5),
            SymbolicValue::ConcreteStr("SELECT * FROM t".into()),
        );

        let node = petgraph::graph::NodeIndex::new(10);
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: node,
            source: petgraph::graph::NodeIndex::new(0),
            path: vec![],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: [(node, SsaValue(5))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let witness = state.get_sink_witness(&finding, &ssa);
        assert_eq!(witness, Some("\"SELECT * FROM t\"".into()));
    }

    #[test]
    fn get_sink_witness_unknown_returns_none() {
        let state = SymbolicState::new();

        let node = petgraph::graph::NodeIndex::new(10);
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: node,
            source: petgraph::graph::NodeIndex::new(0),
            path: vec![],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: [(node, SsaValue(5))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        assert_eq!(state.get_sink_witness(&finding, &ssa), None);
    }

    #[test]
    fn get_sink_witness_unmapped_node_returns_none() {
        let state = SymbolicState::new();
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: petgraph::graph::NodeIndex::new(99), // not in cfg_node_map
            source: petgraph::graph::NodeIndex::new(0),
            path: vec![],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        assert_eq!(state.get_sink_witness(&finding, &ssa), None);
    }

    // ─── widen_at_loop_head tests ────────────────────────────────────────

    #[test]
    fn widen_at_loop_head_sets_phi_to_unknown() {
        use crate::ssa::ir::{SsaBlock, SsaInst, SsaOp, Terminator};
        use smallvec::smallvec;

        let mut state = SymbolicState::new();
        state.set(SsaValue(0), SymbolicValue::Concrete(10));
        state.set(SsaValue(1), SymbolicValue::Concrete(42));
        // v1 is defined by a phi in block 0
        let ssa = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Phi(smallvec![
                        (BlockId(0), SsaValue(0)),
                        (BlockId(1), SsaValue(0))
                    ]),
                    cfg_node: petgraph::graph::NodeIndex::new(0),
                    var_name: None,
                    span: (0, 0),
                }],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        state.widen_at_loop_head(BlockId(0), &ssa);

        // Phi value widened to Unknown
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Unknown);
        // Non-phi value preserved
        assert_eq!(state.get(SsaValue(0)), SymbolicValue::Concrete(10));
    }

    #[test]
    fn widen_at_loop_head_preserves_taint() {
        use crate::ssa::ir::{SsaBlock, SsaInst, SsaOp, Terminator};
        use smallvec::smallvec;

        let mut state = SymbolicState::new();
        state.set(SsaValue(1), SymbolicValue::Symbol(SsaValue(1)));
        state.mark_tainted(SsaValue(1));

        let ssa = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Phi(smallvec![
                        (BlockId(0), SsaValue(0)),
                        (BlockId(1), SsaValue(0))
                    ]),
                    cfg_node: petgraph::graph::NodeIndex::new(0),
                    var_name: None,
                    span: (0, 0),
                }],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        state.widen_at_loop_head(BlockId(0), &ssa);

        // Symbolic precision degraded
        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Unknown);
        // Taint PRESERVED
        assert!(state.is_tainted(SsaValue(1)));
    }

    #[test]
    fn widen_at_loop_head_untainted_stays_untainted() {
        use crate::ssa::ir::{SsaBlock, SsaInst, SsaOp, Terminator};
        use smallvec::smallvec;

        let mut state = SymbolicState::new();
        state.set(SsaValue(1), SymbolicValue::Concrete(5));
        // NOT tainted

        let ssa = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Phi(smallvec![
                        (BlockId(0), SsaValue(0)),
                        (BlockId(1), SsaValue(0))
                    ]),
                    cfg_node: petgraph::graph::NodeIndex::new(0),
                    var_name: None,
                    span: (0, 0),
                }],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: smallvec![],
                succs: smallvec![],
            }],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        state.widen_at_loop_head(BlockId(0), &ssa);

        assert_eq!(state.get(SsaValue(1)), SymbolicValue::Unknown);
        assert!(!state.is_tainted(SsaValue(1)));
    }
}

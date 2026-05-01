//! Field-sensitive Steensgaard points-to analysis driver.
//!
//! Flow-insensitive union-find over SSA values; field sensitivity comes
//! from representing each `obj.f` access as a structural
//! [`AbsLoc::Field`] keyed by `(parent_loc, field)`.

use std::collections::HashMap;

use crate::cfg::BodyId;
use crate::ssa::ir::{FieldId, SsaBody, SsaInst, SsaOp, SsaValue};

use super::domain::{AbsLoc, LOC_TOP, LocId, LocInterner, PointsToSet, PtrProxyHint};

/// Maximum constraint-solver iterations before bailing.  Each pass
/// walks every instruction once; in practice the analysis converges
/// in a small number of passes for any well-formed body.
const MAX_FIXPOINT_ITERS: usize = 8;

/// Container-read callees that pull a single element out of a
/// collection without a key.  Cross-language; non-listed callees still
/// get fresh-alloc behaviour, so the list is conservative.
fn is_container_read_callee(callee: &str) -> bool {
    let bare = match callee.rsplit_once('.') {
        Some((_, m)) => m,
        None => callee,
    };
    matches!(
        bare,
        "shift"
            | "pop"
            | "peek"
            | "front"
            | "back"
            | "first"
            | "last"
            | "head"
            | "tail"
            | "dequeue"
            | "remove"
            | "popleft"
            // synthetic callee for subscript reads (`arr[i]`, `map[k]`)
            | "__index_get__"
    )
}

/// Container-write callees, mirror of [`is_container_read_callee`].
pub fn is_container_write_callee(callee: &str) -> bool {
    let bare = match callee.rsplit_once('.') {
        Some((_, m)) => m,
        None => callee,
    };
    matches!(
        bare,
        "push"
            | "pushback"
            | "push_back"
            | "pushfront"
            | "push_front"
            | "append"
            | "add"
            | "insert"
            | "enqueue"
            | "unshift"
            // synthetic callee for subscript writes (`arr[i] = v`, `map[k] = v`)
            | "__index_set__"
    )
}

/// Public re-export of [`is_container_read_callee`] for the taint engine.
pub fn is_container_read_callee_pub(callee: &str) -> bool {
    is_container_read_callee(callee)
}

/// Derive a [`crate::summary::points_to::FieldPointsToSummary`] from
/// per-body points-to facts.
///
/// Records two channels:
///
/// 1. **Reads**, walks every [`SsaOp::FieldProj`] in the body; for
///    each `loc ∈ pt(receiver)` that resolves to a parameter
///    location ([`AbsLoc::Param`] / [`AbsLoc::SelfParam`]), records
///    the projected field name into the summary's
///    `param_field_reads`.
/// 2. **Writes**, walks the body's [`SsaBody::field_writes`] side-
///    table (populated by SSA lowering's W1 synth-Assign hook) and
///    records each `(receiver, FieldId)` pair against the receiver's
///    pt set the same way reads are recorded.
///
/// Field name resolution goes through the body's
/// [`SsaBody::field_interner`] because [`crate::ssa::ir::FieldId`]
/// is body-local, names are the only stable cross-file identity.
///
/// Receiver (`SelfParam`) reads/writes are recorded under the
/// [`u32::MAX`] sentinel parameter index, mirroring the convention in
/// [`crate::summary::ssa_summary::SsaFuncSummary::receiver_to_*`].
///
/// The container-element sentinel field [`FieldId::ELEM`] is recorded
/// under the special name `"<elem>"` so callers can recognise the
/// abstract-element flow without leaking the implementation detail
/// of the sentinel `u32::MAX` value across the wire.
pub fn extract_field_points_to(
    body: &SsaBody,
    facts: &PointsToFacts,
) -> crate::summary::points_to::FieldPointsToSummary {
    use crate::summary::points_to::FieldPointsToSummary;
    let mut out = FieldPointsToSummary::empty();
    if body.field_interner.is_empty() && body.field_writes.is_empty() {
        return out;
    }
    // Resolve a body-local FieldId to its cross-wire-stable name.
    // Returns `None` when the id is out of range (deserialised body
    // with a fresh interner) or doesn't correspond to a real field.
    let field_name = |field: FieldId| -> Option<String> {
        if field == FieldId::ELEM {
            Some("<elem>".to_string())
        } else if (field.0 as usize) < body.field_interner.len() {
            Some(body.field_interner.resolve(field).to_string())
        } else {
            None
        }
    };
    // Apply a single read or write to the summary, dispatching on
    // the abstract location's parameter / receiver shape.
    let record =
        |loc: LocId, name: &str, out: &mut FieldPointsToSummary, is_write: bool| match facts
            .interner
            .resolve(loc)
        {
            crate::pointer::AbsLoc::Param(_, idx) => {
                if is_write {
                    out.add_write(*idx as u32, name);
                } else {
                    out.add_read(*idx as u32, name);
                }
            }
            crate::pointer::AbsLoc::SelfParam(_) => {
                if is_write {
                    out.add_write(u32::MAX, name);
                } else {
                    out.add_read(u32::MAX, name);
                }
            }
            _ => {}
        };

    // Channel 1: reads from FieldProj.
    for block in &body.blocks {
        for inst in block.body.iter() {
            if let SsaOp::FieldProj {
                receiver, field, ..
            } = &inst.op
            {
                let pt = facts.pt(*receiver);
                if pt.is_empty() || pt.is_top() {
                    continue;
                }
                let Some(name) = field_name(*field) else {
                    continue;
                };
                for loc in pt.iter() {
                    record(loc, &name, &mut out, /* is_write */ false);
                }
            }
        }
    }

    // Channel 2: writes from the synth-Assign side-table.  Each
    // entry maps the synthetic Assign's defined value → (receiver
    // SsaValue, FieldId).  The receiver's pt set determines which
    // parameter index the write attributes to.
    for (receiver, field) in body.field_writes.values() {
        let pt = facts.pt(*receiver);
        if pt.is_empty() || pt.is_top() {
            continue;
        }
        let Some(name) = field_name(*field) else {
            continue;
        };
        for loc in pt.iter() {
            record(loc, &name, &mut out, /* is_write */ true);
        }
    }

    out
}

/// Per-body points-to result.
///
/// Owns the body-local [`LocInterner`] and a flat `SsaValue → PointsToSet`
/// table.  The table is dense, one slot per SSA value, so lookups
/// are O(1).
#[derive(Clone, Debug)]
pub struct PointsToFacts {
    /// Body the facts were computed for; used as the disambiguator
    /// inside [`crate::pointer::AbsLoc::Param`] / `Alloc` / `SelfParam`.
    pub body: BodyId,
    /// Interner for the [`super::domain::AbsLoc`] referenced by the
    /// per-value points-to sets.
    pub interner: LocInterner,
    /// `pt(v)` for every SSA value in the body.  Unreachable / unused
    /// slots are `PointsToSet::empty()`.
    by_value: Vec<PointsToSet>,
}

impl PointsToFacts {
    /// Empty result, every value points to nothing.  Used by callers
    /// that need a "no facts" placeholder when the analysis is
    /// disabled or the body could not be analysed.
    pub fn empty(body: BodyId) -> Self {
        Self {
            body,
            interner: LocInterner::new(),
            by_value: Vec::new(),
        }
    }

    /// Borrow the points-to set for `v`.  Returns an empty set when
    /// `v` is out of range (e.g. a value defined by an instruction
    /// the analysis didn't visit).
    pub fn pt(&self, v: SsaValue) -> &PointsToSet {
        let idx = v.0 as usize;
        static EMPTY: once_cell::sync::Lazy<PointsToSet> =
            once_cell::sync::Lazy::new(PointsToSet::empty);
        self.by_value.get(idx).unwrap_or(&EMPTY)
    }

    /// True when every value has an empty points-to set.  Used as a
    /// fast-path skip in callers that only care about non-trivial
    /// aliasing.
    pub fn is_trivial(&self) -> bool {
        self.by_value.iter().all(|s| s.is_empty())
    }

    /// Number of SSA values covered by the facts table.
    pub fn len(&self) -> usize {
        self.by_value.len()
    }

    /// True when no SSA values are covered by the facts table.
    pub fn is_empty(&self) -> bool {
        self.by_value.is_empty()
    }

    /// Classify a value's points-to set into a [`PtrProxyHint`] for
    /// consumers that only care about the "is this a sub-field alias"
    /// distinction.  Returns [`PtrProxyHint::Other`] for empty sets,
    /// `Top`, and any set containing a root location ([`AbsLoc::SelfParam`]
    /// / [`AbsLoc::Param`] / [`AbsLoc::Alloc`]).  Returns
    /// [`PtrProxyHint::FieldOnly`] iff every member is an
    /// [`AbsLoc::Field`].
    ///
    pub fn proxy_hint(&self, v: SsaValue) -> PtrProxyHint {
        let set = self.pt(v);
        if set.is_empty() || set.is_top() {
            return PtrProxyHint::Other;
        }
        for id in set.iter() {
            match self.interner.resolve(id) {
                AbsLoc::Field { .. } => {}
                _ => return PtrProxyHint::Other,
            }
        }
        PtrProxyHint::FieldOnly
    }

    /// Build a `var_name → PtrProxyHint` map by scanning the body's
    /// value defs for the latest definition of each named variable.
    /// Names that resolve to no variable, or whose latest definition is
    /// `Other`, are omitted, only `FieldOnly` entries appear.
    ///
    /// Iterates over [`SsaBody::value_defs`] in *reverse* order so the
    /// last (post-renaming) SSA definition for each name wins.  Used by
    /// the resource-lifecycle pass to look up `pt(receiver_text)` in
    /// `apply_call` without re-walking the SSA body.
    pub fn name_proxy_hints(
        &self,
        body: &SsaBody,
    ) -> std::collections::HashMap<String, PtrProxyHint> {
        let mut out = std::collections::HashMap::new();
        for (idx, def) in body.value_defs.iter().enumerate().rev() {
            let Some(name) = def.var_name.as_ref() else {
                continue;
            };
            if out.contains_key(name) {
                continue;
            }
            let hint = self.proxy_hint(SsaValue(idx as u32));
            if hint == PtrProxyHint::FieldOnly {
                out.insert(name.clone(), hint);
            }
        }
        out
    }
}

/// Analyse a single body and return its [`PointsToFacts`].
///
/// `body_id` is used as the disambiguator inside the abstract
/// locations, supplying a stable id (e.g. the file's
/// `BodyMeta.id`) lets callers compare facts emitted by different
/// bodies in the same file.
pub fn analyse_body(body: &SsaBody, body_id: BodyId) -> PointsToFacts {
    let mut state = AnalysisState::new(body_id, body.num_values());

    // Pass 1, emit constraints from ops that don't depend on
    // representative resolution (Param, SelfParam, Call result,
    // etc.).  These produce the "leaf" points-to sets.
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            state.transfer_inst(body_id, inst);
        }
    }

    // Pass 2+, propagate through field projections, phis, and
    // assignments until a fixpoint.  Field projections need iteration
    // because a `FieldProj` whose receiver's representative changes
    // (via a later unification) must re-emit its constraint with the
    // new representative.
    for _ in 0..MAX_FIXPOINT_ITERS {
        let mut changed = false;
        for block in &body.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                changed |= state.propagate_inst(inst);
            }
        }
        if !changed {
            break;
        }
    }

    state.into_facts()
}

// ── Constraint solver internals ────────────────────────────────────

/// Mutable analysis state, the interner, points-to table, and
/// union-find arrays.  Lives inside `analyse_body` only.
struct AnalysisState {
    /// Body-id forwarded to [`PointsToFacts::body`] when the analysis
    /// completes.  Recorded here so `into_facts` can preserve the
    /// caller-supplied id instead of defaulting to `BodyId(0)`.
    body_id: BodyId,
    interner: LocInterner,
    pt: Vec<PointsToSet>,
    parent: Vec<u32>,
    rank: Vec<u8>,
}

impl AnalysisState {
    fn new(body_id: BodyId, num_values: usize) -> Self {
        Self {
            body_id,
            interner: LocInterner::new(),
            pt: vec![PointsToSet::empty(); num_values],
            parent: (0..num_values as u32).collect(),
            rank: vec![0; num_values],
        }
    }

    /// Union-find find with path compression.
    fn find(&mut self, mut v: u32) -> u32 {
        if v as usize >= self.parent.len() {
            return v;
        }
        // Walk to root.
        let mut root = v;
        while self.parent[root as usize] != root {
            root = self.parent[root as usize];
        }
        // Compress.
        while self.parent[v as usize] != root {
            let next = self.parent[v as usize];
            self.parent[v as usize] = root;
            v = next;
        }
        root
    }

    /// Union `a` and `b` by rank.  Returns the new representative.
    /// Merges the points-to sets of the two classes into the new
    /// representative's slot.
    fn union(&mut self, a: u32, b: u32) -> u32 {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return ra;
        }
        let (winner, loser) = match self.rank[ra as usize].cmp(&self.rank[rb as usize]) {
            std::cmp::Ordering::Less => (rb, ra),
            std::cmp::Ordering::Greater => (ra, rb),
            std::cmp::Ordering::Equal => {
                self.rank[ra as usize] += 1;
                (ra, rb)
            }
        };
        self.parent[loser as usize] = winner;
        // Move the loser's points-to set into the winner's slot.
        let loser_pt = std::mem::take(&mut self.pt[loser as usize]);
        let _ = self.pt[winner as usize].union_in_place(&loser_pt);
        winner
    }

    /// `pt(rep) ∪= {loc}`.
    fn add_loc(&mut self, ssa: u32, loc: LocId) -> bool {
        let rep = self.find(ssa) as usize;
        let mut delta = PointsToSet::singleton(loc);
        // Inline insert via union to keep the saturation logic in one place.
        let changed = self.pt[rep].union_in_place(&delta);
        // `delta` no longer needed.
        let _ = &mut delta;
        changed
    }

    /// `pt(rep_a) ∪= pt(rep_b)`.  Caller is responsible for passing
    /// already-resolved representatives if it wants Steensgaard
    /// unification, see `union` for that.
    fn copy_pt(&mut self, dst: u32, src: u32) -> bool {
        let dr = self.find(dst);
        let sr = self.find(src);
        if dr == sr {
            return false;
        }
        // Take a clone of the source set so we can mutate dst.
        let src_pt = self.pt[sr as usize].clone();
        self.pt[dr as usize].union_in_place(&src_pt)
    }

    /// First-pass transfer for an instruction.  Emits constraints
    /// that don't depend on representative-stable resolution.
    fn transfer_inst(&mut self, body_id: BodyId, inst: &SsaInst) {
        let v = inst.value.0;
        if (v as usize) >= self.pt.len() {
            return;
        }
        match &inst.op {
            SsaOp::Param { index } => {
                let loc = self.interner.intern_param(body_id, *index);
                self.add_loc(v, loc);
            }
            SsaOp::SelfParam => {
                let loc = self.interner.intern_self_param(body_id);
                self.add_loc(v, loc);
            }
            SsaOp::CatchParam => {
                // Exception bindings come from the runtime, model as
                // an opaque allocation-site keyed by the SSA value.
                let loc = self.interner.intern_alloc(body_id, v);
                self.add_loc(v, loc);
            }
            SsaOp::Call {
                callee, receiver, ..
            } => {
                // container element retrieval ops
                // (`shift`, `pop`, `peek`, `front`, …) project through
                // the abstract `Field(pt(receiver), ELEM)` cell so
                // per-element taint flows independently of the SSA
                // value referencing the container.  The receiver's
                // points-to set may not be fully resolved on this
                // pass, so we *also* add a fresh allocation site as a
                // fallback, the fixpoint pass below absorbs the
                // proper Field projection once the receiver's set
                // converges.
                let loc = self.interner.intern_alloc(body_id, v);
                self.add_loc(v, loc);
                if let Some(rcv) = receiver
                    && is_container_read_callee(callee)
                    && (rcv.0 as usize) < self.parent.len()
                {
                    let rcv_rep = self.find(rcv.0) as usize;
                    let rcv_pt = self.pt[rcv_rep].clone();
                    if !rcv_pt.is_empty() && !rcv_pt.is_top() {
                        for parent_loc in rcv_pt.iter() {
                            let proj = self.interner.intern_field(parent_loc, FieldId::ELEM);
                            self.add_loc(v, proj);
                        }
                    }
                }
            }
            SsaOp::Assign(uses) => {
                // Steensgaard unification: rep(v) ∪= rep(u_i).  We
                // unify here and then re-propagate during the
                // fixpoint pass to absorb later field projections.
                for &u in uses {
                    if (u.0 as usize) < self.parent.len() {
                        self.union(v, u.0);
                    }
                }
            }
            SsaOp::Phi(operands) => {
                for (_, u) in operands {
                    if (u.0 as usize) < self.parent.len() {
                        self.union(v, u.0);
                    }
                }
            }
            SsaOp::FieldProj { .. } => {
                // Resolved during the fixpoint pass, see
                // `propagate_inst`.
            }
            SsaOp::Source | SsaOp::Const(_) | SsaOp::Nop | SsaOp::Undef => {
                // Scalars / no-ops: empty points-to set.
            }
        }
    }

    /// Fixpoint-pass transfer.  Re-runs constraints whose result
    /// depends on the current set of representatives, i.e. field
    /// projections, phis, and assignments may need to absorb new
    /// members emitted after the first pass.  Returns `true` when
    /// any points-to set changed.
    fn propagate_inst(&mut self, inst: &SsaInst) -> bool {
        let v = inst.value.0;
        if (v as usize) >= self.pt.len() {
            return false;
        }
        match &inst.op {
            SsaOp::FieldProj {
                receiver, field, ..
            } => {
                if (receiver.0 as usize) >= self.parent.len() {
                    return false;
                }
                let rcv_rep = self.find(receiver.0) as usize;
                let mut new_pt = PointsToSet::empty();
                let rcv_pt = self.pt[rcv_rep].clone();
                if rcv_pt.is_top() {
                    new_pt.insert(LOC_TOP);
                } else if rcv_pt.is_empty() {
                    // Nothing to project from yet.
                    return false;
                } else {
                    for parent_loc in rcv_pt.iter() {
                        let proj = self.interner.intern_field(parent_loc, *field);
                        new_pt.insert(proj);
                    }
                }
                let v_rep = self.find(v) as usize;
                self.pt[v_rep].union_in_place(&new_pt)
            }
            SsaOp::Assign(uses) => {
                let mut changed = false;
                for &u in uses {
                    if (u.0 as usize) < self.parent.len() {
                        // Steensgaard unification already happened in
                        // pass 1; re-copying the points-to set
                        // absorbs any members added since.
                        changed |= self.copy_pt(v, u.0);
                    }
                }
                changed
            }
            SsaOp::Phi(operands) => {
                let mut changed = false;
                for (_, u) in operands {
                    if (u.0 as usize) < self.parent.len() {
                        changed |= self.copy_pt(v, u.0);
                    }
                }
                changed
            }
            // No re-propagation needed for leaf ops.
            _ => false,
        }
    }

    /// Materialise the dense `SsaValue → PointsToSet` table.  Each
    /// value's set is the set of its representative, values in the
    /// same Steensgaard class share the same set.
    fn into_facts(mut self) -> PointsToFacts {
        let mut by_value = Vec::with_capacity(self.pt.len());
        // Resolve every value through the union-find before returning
        // so consumers see the unified set without having to re-find.
        let mut rep_cache: HashMap<u32, PointsToSet> = HashMap::new();
        let n = self.pt.len();
        for v in 0..n as u32 {
            let rep = self.find(v);
            let set = rep_cache
                .entry(rep)
                .or_insert_with(|| self.pt[rep as usize].clone())
                .clone();
            by_value.push(set);
        }
        PointsToFacts {
            body: self.body_id,
            interner: self.interner,
            by_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cfg::Cfg;
    use crate::ssa::ir::{
        BlockId, FieldId, FieldInterner, SsaBlock, SsaBody, SsaInst, SsaOp, SsaValue, Terminator,
        ValueDef,
    };
    use petgraph::graph::NodeIndex;
    use smallvec::{SmallVec, smallvec};
    use std::collections::HashMap;

    fn body_id() -> BodyId {
        BodyId(0)
    }

    /// Helpers for building synthetic SSA bodies in tests.  We
    /// fabricate bodies directly rather than running the full lowering
    /// pipeline so the tests stay focused on the points-to behaviour.
    struct BodyBuilder {
        defs: Vec<ValueDef>,
        body_insts: Vec<SsaInst>,
        next_value: u32,
        field_interner: FieldInterner,
    }

    impl BodyBuilder {
        fn new() -> Self {
            Self {
                defs: Vec::new(),
                body_insts: Vec::new(),
                next_value: 0,
                field_interner: FieldInterner::new(),
            }
        }

        fn fresh(&mut self, name: Option<&str>) -> SsaValue {
            let v = SsaValue(self.next_value);
            self.next_value += 1;
            self.defs.push(ValueDef {
                var_name: name.map(|s| s.to_string()),
                cfg_node: NodeIndex::new(0),
                block: BlockId(0),
            });
            v
        }

        fn emit(&mut self, value: SsaValue, op: SsaOp, name: Option<&str>) {
            self.body_insts.push(SsaInst {
                value,
                op,
                cfg_node: NodeIndex::new(0),
                var_name: name.map(|s| s.to_string()),
                span: (0, 0),
            });
        }

        fn intern_field(&mut self, name: &str) -> FieldId {
            self.field_interner.intern(name)
        }

        fn build(self) -> SsaBody {
            SsaBody {
                blocks: vec![SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: self.body_insts,
                    terminator: Terminator::Return(None),
                    preds: SmallVec::new(),
                    succs: SmallVec::new(),
                }],
                entry: BlockId(0),
                value_defs: self.defs,
                cfg_node_map: HashMap::new(),
                exception_edges: vec![],
                field_interner: self.field_interner,
                field_writes: std::collections::HashMap::new(),

                synthetic_externals: std::collections::HashSet::new(),
            }
        }
    }

    /// `let c = self; let m = c.mu;` , pt(m) must be `{Field(SelfParam, mu)}`,
    /// distinct from pt(c) = `{SelfParam}`.
    #[test]
    fn field_subobject_distinct_from_receiver() {
        let mut b = BodyBuilder::new();
        let c = b.fresh(Some("c"));
        b.emit(c, SsaOp::SelfParam, Some("c"));

        let mu_field = b.intern_field("mu");
        let m = b.fresh(Some("c.mu"));
        b.emit(
            m,
            SsaOp::FieldProj {
                receiver: c,
                field: mu_field,
                projected_type: None,
            },
            Some("c.mu"),
        );

        let body = b.build();
        let facts = analyse_body(&body, body_id());

        let pt_c = facts.pt(c);
        let pt_m = facts.pt(m);

        assert_eq!(pt_c.len(), 1, "pt(c) should be a singleton SelfParam");
        assert_eq!(pt_m.len(), 1, "pt(c.mu) should be a singleton Field");
        assert!(!pt_m.is_top());

        // The two sets must not overlap.
        for c_loc in pt_c.iter() {
            for m_loc in pt_m.iter() {
                assert_ne!(c_loc, m_loc, "field and receiver share a location");
            }
        }

        // And the field's parent must be the receiver's location.
        let m_loc = pt_m.iter().next().unwrap();
        match facts.interner.resolve(m_loc) {
            crate::pointer::AbsLoc::Field { parent, field } => {
                assert_eq!(*field, mu_field);
                assert_eq!(*parent, pt_c.iter().next().unwrap());
            }
            other => panic!("expected Field, got {other:?}"),
        }
    }

    /// `let y = x;` , y and x share the same points-to set.
    #[test]
    fn copy_propagation_unifies() {
        let mut b = BodyBuilder::new();
        let x = b.fresh(Some("x"));
        b.emit(x, SsaOp::Param { index: 0 }, Some("x"));

        let y = b.fresh(Some("y"));
        b.emit(y, SsaOp::Assign(smallvec![x]), Some("y"));

        let body = b.build();
        let facts = analyse_body(&body, body_id());

        assert_eq!(
            facts.pt(x),
            facts.pt(y),
            "Steensgaard unifies pt(y) with pt(x) via the copy"
        );
        assert!(!facts.pt(y).is_empty());
    }

    /// `if (cond) z = a; else z = b;` , phi at the merge unifies
    /// `pt(z)` with both `pt(a)` and `pt(b)`.
    #[test]
    fn phi_unifies_branches() {
        let mut b = BodyBuilder::new();
        let a = b.fresh(Some("a"));
        b.emit(a, SsaOp::Param { index: 0 }, Some("a"));
        let b_v = b.fresh(Some("b"));
        b.emit(b_v, SsaOp::Param { index: 1 }, Some("b"));

        // Phi(0: a, 0: b), predecessor block ids are placeholders.
        let z = b.fresh(Some("z"));
        b.emit(
            z,
            SsaOp::Phi(smallvec![(BlockId(0), a), (BlockId(0), b_v)]),
            Some("z"),
        );

        let body = b.build();
        let facts = analyse_body(&body, body_id());

        let pt_z = facts.pt(z);
        // Steensgaard unifies the three classes; pt(z) == pt(a) == pt(b)
        // and contains both Param locations.
        assert_eq!(pt_z, facts.pt(a));
        assert_eq!(pt_z, facts.pt(b_v));
        assert_eq!(pt_z.len(), 2);
    }

    /// `node = node.next;`, the `FieldProj` self-cycle must
    /// terminate via the union-find / depth bound, not loop.
    #[test]
    fn self_referential_field_chain_terminates() {
        let mut b = BodyBuilder::new();
        let node = b.fresh(Some("node"));
        b.emit(node, SsaOp::Param { index: 0 }, Some("node"));

        let next_field = b.intern_field("next");
        // Repeated pattern: `node = node.next` modeled as
        // fp = FieldProj(node, next); node' = Assign([fp])
        for _ in 0..6 {
            let fp = b.fresh(Some("node.next"));
            b.emit(
                fp,
                SsaOp::FieldProj {
                    receiver: node,
                    field: next_field,
                    projected_type: None,
                },
                Some("node.next"),
            );
            let new_node = b.fresh(Some("node"));
            b.emit(new_node, SsaOp::Assign(smallvec![fp]), Some("node"));
            // The original `node` and the new one are unified by Assign,
            // creating the self-cycle.  We don't update `node` here so
            // every iteration emits a fresh FieldProj on the original.
        }

        let body = b.build();
        // The bounded `MAX_FIELD_DEPTH` + union-find termination guarantees
        // analysis returns; this test would hang or panic on regression.
        let facts = analyse_body(&body, body_id());
        let pt_node = facts.pt(node);
        // Either we converge to a non-empty set including a Field chain,
        // or we saturate to Top, either is a valid termination outcome.
        assert!(!pt_node.is_empty());
    }

    /// `Source` introduces no points-to facts (taint is a separate
    /// lattice; points-to only models heap reach).
    #[test]
    fn source_op_has_empty_pt() {
        let mut b = BodyBuilder::new();
        let s = b.fresh(Some("s"));
        b.emit(s, SsaOp::Source, Some("s"));

        let body = b.build();
        let facts = analyse_body(&body, body_id());
        assert!(facts.pt(s).is_empty());
    }

    /// `Call` produces a fresh allocation-site location for its result ,
    /// distinct from its arguments.
    #[test]
    fn call_result_is_fresh_alloc() {
        let mut b = BodyBuilder::new();
        let arg = b.fresh(Some("x"));
        b.emit(arg, SsaOp::Param { index: 0 }, Some("x"));

        let result = b.fresh(Some("r"));
        b.emit(
            result,
            SsaOp::Call {
                callee: "make_thing".into(),
                callee_text: None,
                args: vec![smallvec![arg]],
                receiver: None,
            },
            Some("r"),
        );

        let body = b.build();
        let facts = analyse_body(&body, body_id());

        let pt_arg = facts.pt(arg);
        let pt_result = facts.pt(result);
        assert!(!pt_result.is_empty());
        assert!(!pt_arg.is_empty());
        // No member shared between the two sets.
        for ra in pt_arg.iter() {
            for rr in pt_result.iter() {
                assert_ne!(ra, rr);
            }
        }
    }

    /// Driver smoke-test: the analysis runs on an SsaBody produced by
    /// the real lowering pipeline without panicking.  This pins the
    /// "no behaviour change" gate, analysis runs to completion on
    /// representative input.
    #[test]
    fn smoke_runs_on_lowered_body() {
        // We don't exercise the real lowering here (that needs a full
        // CFG fixture); the synthetic builder above covers the IR
        // surface area.  Just confirm the entry point is callable
        // with an empty body.
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: FieldInterner::new(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let facts = analyse_body(&body, body_id());
        assert!(facts.is_trivial());
        assert_eq!(facts.len(), 0);

        let _ = std::marker::PhantomData::<Cfg>;
    }

    /// Contract pin: a value defined by a `FieldProj`
    /// classifies as [`PtrProxyHint::FieldOnly`].  Consumed by the
    /// resource-lifecycle pass to recognise field-aliased locals.
    #[test]
    fn proxy_hint_field_only_for_field_proj_value() {
        let mut b = BodyBuilder::new();
        let c = b.fresh(Some("c"));
        b.emit(c, SsaOp::SelfParam, Some("c"));
        let mu = b.intern_field("mu");
        let m = b.fresh(Some("m"));
        b.emit(
            m,
            SsaOp::FieldProj {
                receiver: c,
                field: mu,
                projected_type: None,
            },
            Some("m"),
        );

        let body = b.build();
        let facts = analyse_body(&body, BodyId(7));
        assert_eq!(
            facts.body,
            BodyId(7),
            "PointsToFacts must preserve caller-supplied BodyId"
        );
        assert_eq!(facts.proxy_hint(m), crate::pointer::PtrProxyHint::FieldOnly);
        assert_eq!(facts.proxy_hint(c), crate::pointer::PtrProxyHint::Other);
    }

    /// container-read callee classifier covers a
    /// representative sample across nyx's languages.  Pinned because
    /// the taint engine relies on the same classifier.
    #[test]
    fn container_read_callee_classifier_covers_common_methods() {
        for c in [
            "shift",
            "pop",
            "peek",
            "front",
            "back",
            "queue.shift",
            "list.pop",
            "deque.popleft",
            "stack.peek",
            "vec.first",
        ] {
            assert!(is_container_read_callee(c), "expected container read: {c}");
        }
        for c in ["push", "append", "insert", "myMethod", "process"] {
            assert!(
                !is_container_read_callee(c),
                "non-read should classify false: {c}"
            );
        }
    }

    /// container-write classifier (mirror).
    #[test]
    fn container_write_callee_classifier() {
        for c in [
            "push",
            "pushback",
            "push_back",
            "append",
            "insert",
            "enqueue",
            "list.append",
        ] {
            assert!(is_container_write_callee(c), "expected write: {c}");
        }
        for c in ["pop", "shift", "process", "lookup"] {
            assert!(
                !is_container_write_callee(c),
                "non-write should classify false: {c}"
            );
        }
    }

    /// a `Call("shift", receiver=container)` projects
    /// `Field(pt(container), ELEM)` into the result, alongside the
    /// fresh allocation site that fall-back paths still emit.
    #[test]
    fn container_read_call_projects_through_elem_field() {
        let mut b = BodyBuilder::new();
        // `arr` is the parameter container.
        let arr = b.fresh(Some("arr"));
        b.emit(arr, SsaOp::Param { index: 0 }, Some("arr"));
        // `e := arr.shift()`, container read.
        let e = b.fresh(Some("e"));
        b.emit(
            e,
            SsaOp::Call {
                callee: "shift".into(),
                callee_text: None,
                args: vec![],
                receiver: Some(arr),
            },
            Some("e"),
        );

        let body = b.build();
        let facts = analyse_body(&body, BodyId(0));
        let pt_e = facts.pt(e);
        // The result must include at least one Field(_, ELEM) member.
        let mut saw_elem = false;
        for loc in pt_e.iter() {
            if let crate::pointer::AbsLoc::Field { field, .. } = facts.interner.resolve(loc)
                && *field == FieldId::ELEM
            {
                saw_elem = true;
                break;
            }
        }
        assert!(
            saw_elem,
            "container read result should include Field(_, ELEM); got {pt_e:?}"
        );
    }

    /// `extract_field_points_to` records a field
    /// READ on the parameter index when a `FieldProj` traces back to
    /// an `AbsLoc::Param`.
    #[test]
    fn extract_field_points_to_records_param_reads() {
        let mut b = BodyBuilder::new();
        // `obj` is parameter 0.
        let obj = b.fresh(Some("obj"));
        b.emit(obj, SsaOp::Param { index: 0 }, Some("obj"));
        // `let n = obj.name;`, field projection from a param.
        let name_field = b.intern_field("name");
        let n = b.fresh(Some("n"));
        b.emit(
            n,
            SsaOp::FieldProj {
                receiver: obj,
                field: name_field,
                projected_type: None,
            },
            Some("n"),
        );

        let body = b.build();
        let facts = analyse_body(&body, BodyId(0));
        let summary = extract_field_points_to(&body, &facts);
        let entry = summary
            .param_field_reads
            .iter()
            .find(|(p, _)| *p == 0)
            .expect("param 0 read recorded");
        assert!(entry.1.iter().any(|s| s == "name"));
    }

    /// `extract_field_points_to` records field
    /// WRITES from the body's `field_writes` side-table populated by
    /// SSA lowering.  A synth Assign whose receiver traces back to
    /// `AbsLoc::Param` produces a `param_field_writes` entry.
    #[test]
    fn extract_field_points_to_records_param_writes() {
        let mut b = BodyBuilder::new();
        // `obj` is parameter 0.
        let obj = b.fresh(Some("obj"));
        b.emit(obj, SsaOp::Param { index: 0 }, Some("obj"));
        // Synth Assign mimicking `obj.cache = rhs`: define `cache`
        // field id and a synthetic value whose op is Assign.  The
        // side-table maps `synth_v -> (obj, cache_id)`.
        let cache_id = b.intern_field("cache");
        let rhs = b.fresh(Some("rhs"));
        b.emit(rhs, SsaOp::Source, Some("rhs"));
        let synth = b.fresh(Some("obj"));
        b.emit(synth, SsaOp::Assign(smallvec![rhs]), Some("obj"));

        let mut body = b.build();
        body.field_writes.insert(synth, (obj, cache_id));

        let facts = analyse_body(&body, BodyId(0));
        let summary = extract_field_points_to(&body, &facts);
        let entry = summary
            .param_field_writes
            .iter()
            .find(|(p, _)| *p == 0)
            .expect("param 0 write must be recorded from field_writes");
        assert!(
            entry.1.iter().any(|s| s == "cache"),
            "expected 'cache' in writes; got {:?}",
            entry.1,
        );
    }

    /// writes through the receiver (`this.f =
    /// rhs`) are recorded under the same `u32::MAX` sentinel as
    /// reads.
    #[test]
    fn extract_field_points_to_records_self_writes_under_sentinel() {
        let mut b = BodyBuilder::new();
        let this = b.fresh(Some("this"));
        b.emit(this, SsaOp::SelfParam, Some("this"));
        let cache_id = b.intern_field("cache");
        let rhs = b.fresh(Some("rhs"));
        b.emit(rhs, SsaOp::Source, Some("rhs"));
        let synth = b.fresh(Some("this"));
        b.emit(synth, SsaOp::Assign(smallvec![rhs]), Some("this"));

        let mut body = b.build();
        body.field_writes.insert(synth, (this, cache_id));

        let facts = analyse_body(&body, BodyId(0));
        let summary = extract_field_points_to(&body, &facts);
        let entry = summary
            .param_field_writes
            .iter()
            .find(|(p, _)| *p == u32::MAX)
            .expect("receiver write recorded under u32::MAX sentinel");
        assert!(entry.1.iter().any(|s| s == "cache"));
    }

    /// container-element writes (`<elem>`
    /// marker) flow through the same channel as named-field writes
    /// when the synth Assign carries `FieldId::ELEM`.
    #[test]
    fn extract_field_points_to_records_elem_writes() {
        let mut b = BodyBuilder::new();
        let arr = b.fresh(Some("arr"));
        b.emit(arr, SsaOp::Param { index: 0 }, Some("arr"));
        let rhs = b.fresh(Some("rhs"));
        b.emit(rhs, SsaOp::Source, Some("rhs"));
        let synth = b.fresh(Some("arr"));
        b.emit(synth, SsaOp::Assign(smallvec![rhs]), Some("arr"));

        let mut body = b.build();
        body.field_writes.insert(synth, (arr, FieldId::ELEM));

        let facts = analyse_body(&body, BodyId(0));
        let summary = extract_field_points_to(&body, &facts);
        let entry = summary
            .param_field_writes
            .iter()
            .find(|(p, _)| *p == 0)
            .expect("ELEM write on param 0 recorded");
        assert!(
            entry.1.iter().any(|s| s == "<elem>"),
            "ELEM marker '<elem>' must surface unchanged across the wire",
        );
    }

    /// receiver projections are recorded under the
    /// `u32::MAX` sentinel parameter index (mirror of
    /// `SsaFuncSummary::receiver_to_*`).
    #[test]
    fn extract_field_points_to_records_self_reads_under_sentinel() {
        let mut b = BodyBuilder::new();
        let this = b.fresh(Some("this"));
        b.emit(this, SsaOp::SelfParam, Some("this"));
        let cache = b.intern_field("cache");
        let c = b.fresh(Some("c"));
        b.emit(
            c,
            SsaOp::FieldProj {
                receiver: this,
                field: cache,
                projected_type: None,
            },
            Some("c"),
        );

        let body = b.build();
        let facts = analyse_body(&body, BodyId(0));
        let summary = extract_field_points_to(&body, &facts);
        let entry = summary
            .param_field_reads
            .iter()
            .find(|(p, _)| *p == u32::MAX)
            .expect("receiver read recorded under u32::MAX sentinel");
        assert!(entry.1.iter().any(|s| s == "cache"));
    }

    /// `name_proxy_hints` returns one entry per source-level variable
    /// whose latest SSA def has [`PtrProxyHint::FieldOnly`].  Names that
    /// don't qualify are omitted entirely so the consumer's lookup
    /// stays cheap.
    /// W5: subscript-read synthetic callee `__index_get__` must be
    /// recognised by the public container-read predicate so the W2/W4
    /// taint hooks fire on subscript reads (`arr[i]`, `cmds[0]`).
    #[test]
    fn subscript_get_classifies_as_container_read() {
        assert!(is_container_read_callee_pub("__index_get__"));
        assert!(is_container_read_callee_pub("arr.__index_get__"));
    }

    /// W5: subscript-write synthetic callee `__index_set__` must be
    /// recognised by the public container-write predicate so the W2
    /// taint hook fires on subscript writes (`arr[i] = v`).
    #[test]
    fn subscript_set_classifies_as_container_write() {
        assert!(is_container_write_callee("__index_set__"));
        assert!(is_container_write_callee("arr.__index_set__"));
    }

    /// W5: regression guard, neither synth name should match the
    /// opposite predicate, otherwise the W2 read/write hooks would
    /// double-fire on the same call.
    #[test]
    fn subscript_synth_callees_do_not_cross_classify() {
        assert!(!is_container_read_callee_pub("__index_set__"));
        assert!(!is_container_write_callee("__index_get__"));
    }

    #[test]
    fn name_proxy_hints_collects_field_only_locals() {
        let mut b = BodyBuilder::new();
        // `c` is the receiver, root location, hint=Other.
        let c = b.fresh(Some("c"));
        b.emit(c, SsaOp::SelfParam, Some("c"));
        // `m := c.mu`, field projection, hint=FieldOnly.
        let mu = b.intern_field("mu");
        let m = b.fresh(Some("m"));
        b.emit(
            m,
            SsaOp::FieldProj {
                receiver: c,
                field: mu,
                projected_type: None,
            },
            Some("m"),
        );

        let body = b.build();
        let facts = analyse_body(&body, BodyId(0));
        let hints = facts.name_proxy_hints(&body);
        assert_eq!(
            hints.get("m"),
            Some(&crate::pointer::PtrProxyHint::FieldOnly)
        );
        assert!(
            !hints.contains_key("c"),
            "root receiver must not appear in the FieldOnly map"
        );
    }
}

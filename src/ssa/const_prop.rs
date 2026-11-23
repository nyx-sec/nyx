use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::ir::*;

/// Lattice value for constant propagation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstLattice {
    /// Not yet analyzed (optimistic top).
    Top,
    /// Known string constant.
    Str(String),
    /// Known integer constant.
    Int(i64),
    /// Known boolean constant.
    Bool(bool),
    /// Null / nil / None.
    Null,
    /// Multiple possible values, not constant.
    Varying,
}

impl ConstLattice {
    /// Meet operation: combine two lattice values.
    fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (ConstLattice::Top, x) | (x, ConstLattice::Top) => x.clone(),
            (ConstLattice::Varying, _) | (_, ConstLattice::Varying) => ConstLattice::Varying,
            (a, b) if a == b => a.clone(),
            _ => ConstLattice::Varying,
        }
    }

    /// Parse a raw constant text into a typed lattice value.
    pub(crate) fn parse(text: &str) -> Self {
        let trimmed = text.trim();

        // Boolean
        if trimmed == "true" || trimmed == "True" || trimmed == "TRUE" {
            return ConstLattice::Bool(true);
        }
        if trimmed == "false" || trimmed == "False" || trimmed == "FALSE" {
            return ConstLattice::Bool(false);
        }

        // Null variants
        if trimmed == "null"
            || trimmed == "nil"
            || trimmed == "None"
            || trimmed == "NULL"
            || trimmed == "nullptr"
        {
            return ConstLattice::Null;
        }

        // Integer (including negative)
        if let Ok(i) = trimmed.parse::<i64>() {
            return ConstLattice::Int(i);
        }

        // String: strip surrounding quotes. Require len >= 2 so a lone `'`
        // or `"` (where starts_with and ends_with both match the same byte)
        // does not produce an empty `[1..0]` slice and panic.
        if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
        {
            let inner = &trimmed[1..trimmed.len() - 1];
            return ConstLattice::Str(inner.to_string());
        }

        // Bare string (no quotes), treat as string constant
        ConstLattice::Str(trimmed.to_string())
    }

    /// Returns the boolean value if this is a known Bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConstLattice::Bool(b) => Some(*b),
            // Truthiness: null is false, 0 is false, empty string is false
            ConstLattice::Null => Some(false),
            ConstLattice::Int(0) => Some(false),
            ConstLattice::Str(s) if s.is_empty() => Some(false),
            _ => None,
        }
    }
}

/// Dense, `SsaValue`-indexed table of constant-propagation lattice values.
///
/// SCCP already computes into a dense `Vec<ConstLattice>` indexed by
/// `SsaValue.0` (every value is defined by exactly one inst, so the range
/// `0..num_values` is fully populated).  Historically the result was then
/// re-materialised into a `HashMap<SsaValue, ConstLattice>` — one SipHash
/// insert per value, per body, discarded on the next scan — and every
/// downstream `.get(&v)` paid a SipHash lookup where a `Vec` index would do.
/// This newtype lets `const_propagate` **move** its internal `Vec` out with
/// zero conversion and turns every consumer lookup into a bounds-checked
/// index.  It exposes exactly the surface the old `HashMap` did that consumers
/// use (`get`, `iter`, `is_empty`, `len`), so the swap is a pure
/// type-signature change.
///
/// Complexity: result construction `O(1)` (move) vs the old `O(num_values)`
/// hashed inserts; each lookup `O(1)` array index vs SipHash.  The lattice is
/// never serialised (it is recomputed per body and lives only inside a
/// transient `OptimizeResult`), so no wire-compat shim is required.
///
/// `get` returns `Top` semantics identically to the old map: an in-range slot
/// yields `Some(&lattice)`, and any out-of-range value yields `None` — matching
/// `HashMap::get` over the dense `0..num_values` key set the old path built.
#[derive(Debug, Clone, Default)]
pub struct ConstValues(Vec<ConstLattice>);

impl ConstValues {
    /// Constant lattice for `v`, or `None` when `v` is outside the dense range.
    /// Mirrors `HashMap::get` over the `0..num_values` key set (every in-range
    /// value was inserted by the old conversion, out-of-range never).
    #[inline]
    pub fn get(&self, v: &SsaValue) -> Option<&ConstLattice> {
        self.0.get(v.0 as usize)
    }

    /// Number of dense slots (== `num_values` for a real result).
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate `(SsaValue, &ConstLattice)` over every dense slot in ascending
    /// index order.  The old `HashMap` path inserted **every** value
    /// `0..num_values` (including `Top`/`Varying`), so this visits the same
    /// entry set.  `SymbolicState::seed_from_const_values` applies an
    /// order-independent per-value keyed update.  `PathEnv::
    /// seed_from_optimization` does not: its fact table is capped and drops
    /// late arrivals, so it relies on this ascending order to keep the
    /// admitted set stable across runs.
    pub fn iter(&self) -> impl Iterator<Item = (SsaValue, &ConstLattice)> {
        self.0
            .iter()
            .enumerate()
            .map(|(i, v)| (SsaValue(i as u32), v))
    }
}

/// Build a `ConstValues` from sparse `(SsaValue, ConstLattice)` pairs.
///
/// Used only by unit tests that hand-seed a few values; production always
/// constructs the dense `Vec` directly inside `const_propagate`.  Sizes the
/// dense range to `max(index) + 1` and fills unspecified slots with `Top`.
/// Because every consumer treats `Some(&Top)` and `None` identically ("not a
/// known constant"), a gap-filled dense table is behaviourally equivalent to a
/// sparse map for test seeds.
impl FromIterator<(SsaValue, ConstLattice)> for ConstValues {
    fn from_iter<I: IntoIterator<Item = (SsaValue, ConstLattice)>>(iter: I) -> Self {
        let pairs: Vec<(SsaValue, ConstLattice)> = iter.into_iter().collect();
        let max = pairs.iter().map(|(v, _)| v.0 as usize).max();
        let mut dense = match max {
            Some(m) => vec![ConstLattice::Top; m + 1],
            None => Vec::new(),
        };
        for (v, cl) in pairs {
            let idx = v.0 as usize;
            if idx < dense.len() {
                dense[idx] = cl;
            }
        }
        ConstValues(dense)
    }
}

impl Serialize for ConstValues {
    /// Emits the same map form (`{ ssa_value: lattice }`) the former
    /// `HashMap<SsaValue, ConstLattice>` produced, keeping persisted
    /// `CalleeSsaBody.opt` DB blobs byte-compatible.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (v, cl) in self.iter() {
            map.serialize_entry(&v, cl)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ConstValues {
    /// Accepts the map form written by any prior binary (`HashMap` or this
    /// newtype), rebuilding the dense `Vec` from the `(SsaValue, ConstLattice)`
    /// entries.  Gaps (absent indices) fill with `Top`, which every consumer
    /// treats identically to an absent key.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> serde::de::Visitor<'de> for MapVisitor {
            type Value = ConstValues;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map of SSA value to constant lattice")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut access: M,
            ) -> Result<ConstValues, M::Error> {
                let mut pairs: Vec<(SsaValue, ConstLattice)> = Vec::new();
                if let Some(hint) = access.size_hint() {
                    pairs.reserve(hint);
                }
                while let Some((k, v)) = access.next_entry::<SsaValue, ConstLattice>()? {
                    pairs.push((k, v));
                }
                Ok(pairs.into_iter().collect())
            }
        }
        deserializer.deserialize_map(MapVisitor)
    }
}

/// Result of constant propagation analysis.
pub struct ConstPropResult {
    /// Per-SSA-value constant lattice.
    pub values: ConstValues,
    /// Blocks that are statically unreachable.
    pub unreachable_blocks: HashSet<BlockId>,
}

/// One place where a value is read: instruction `slot` of `block`, counting
/// the block's phis first and its body instructions after them.  For a phi,
/// `operand` is the index of the incoming edge that carries the value, so a
/// changed value can be folded into the phi without rescanning its operands.
/// Body instructions leave `operand` at 0.
#[derive(Clone, Copy, PartialEq, Eq)]
struct UseSite {
    block: BlockId,
    slot: u32,
    operand: u32,
}

/// Per-value use lists in one flat allocation (`start[v]..end[v]` indexes
/// `sites`).  Sites for a value are stored in block order, then slot order, so
/// all the sites of one block are contiguous.
struct UseIndex {
    start: Vec<u32>,
    end: Vec<u32>,
    sites: Vec<UseSite>,
}

impl UseIndex {
    fn build(body: &SsaBody, num_values: usize) -> Self {
        let mut start = vec![0u32; num_values + 1];
        for block in &body.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                inst_uses_each(inst, |used, _| {
                    if let Some(n) = start.get_mut(used.0 as usize + 1) {
                        *n += 1;
                    }
                });
            }
        }
        for i in 0..num_values {
            start[i + 1] += start[i];
        }
        // `start[v]` is now the first slot of v's bucket; `end` is the write
        // cursor and ends up one past the last site actually kept.
        let mut end: Vec<u32> = start[..num_values].to_vec();
        let mut sites = vec![
            UseSite {
                block: BlockId(0),
                slot: 0,
                operand: 0
            };
            start[num_values] as usize
        ];
        for block in &body.blocks {
            for (slot, inst) in block.phis.iter().chain(block.body.iter()).enumerate() {
                inst_uses_each(inst, |used, operand| {
                    let idx = used.0 as usize;
                    if idx >= num_values {
                        return;
                    }
                    let site = UseSite {
                        block: block.id,
                        slot: slot as u32,
                        operand,
                    };
                    let cursor = end[idx] as usize;
                    // An instruction that reads a value twice is one site.
                    if cursor > start[idx] as usize && sites[cursor - 1] == site {
                        return;
                    }
                    sites[cursor] = site;
                    end[idx] += 1;
                });
            }
        }
        start.truncate(num_values);
        UseIndex { start, end, sites }
    }

    #[inline]
    fn of(&self, v: SsaValue) -> &[UseSite] {
        let i = v.0 as usize;
        match (self.start.get(i), self.end.get(i)) {
            (Some(&s), Some(&e)) => &self.sites[s as usize..e as usize],
            _ => &[],
        }
    }
}

/// Destinations with more executable predecessors than this answer
/// "is this edge executable" from a hash set instead of scanning the list.
const EDGE_LINEAR_LIMIT: usize = 8;

/// Executable CFG edges, grouped by destination block.
///
/// Phi evaluation asks "is `(pred, this_block)` executable?" once per operand.
/// Most blocks have one or two predecessors, where a scan of the short list
/// beats hashing.  A wide join (a switch exit with one `break` per case) would
/// make that scan quadratic per phi, so wide destinations get a hash index.
struct ExecEdges {
    preds: Vec<SmallVec<[BlockId; 2]>>,
    wide: rustc_hash::FxHashSet<(u32, u32)>,
}

impl ExecEdges {
    fn new(num_blocks: usize) -> Self {
        ExecEdges {
            preds: vec![SmallVec::new(); num_blocks],
            wide: Default::default(),
        }
    }

    #[inline]
    fn contains(&self, from: BlockId, to: BlockId) -> bool {
        match self.preds.get(to.0 as usize) {
            Some(list) if list.len() <= EDGE_LINEAR_LIMIT => list.contains(&from),
            Some(_) => self.wide.contains(&(from.0, to.0)),
            None => false,
        }
    }

    /// Record `from -> to`. Returns false when the edge was already known.
    fn insert(&mut self, from: BlockId, to: BlockId) -> bool {
        let Some(list) = self.preds.get_mut(to.0 as usize) else {
            return false;
        };
        if list.len() <= EDGE_LINEAR_LIMIT {
            if list.contains(&from) {
                return false;
            }
            list.push(from);
            if list.len() > EDGE_LINEAR_LIMIT {
                for p in list.iter() {
                    self.wide.insert((p.0, to.0));
                }
            }
            true
        } else if self.wide.insert((from.0, to.0)) {
            list.push(from);
            true
        } else {
            false
        }
    }
}

/// Which blocks and edges SCCP has found executable so far.
struct Reach {
    executable_blocks: Vec<bool>,
    edges: ExecEdges,
    /// Blocks sitting in `cfg_worklist` right now, so a join that gains many
    /// incoming edges before it is popped is evaluated once, not once per edge.
    queued: Vec<bool>,
    /// Blocks whose goto, switch or return successors are all marked. Those
    /// terminators do not depend on any value, so a second pass changes nothing.
    terminator_done: Vec<bool>,
    cfg_worklist: VecDeque<BlockId>,
}

impl Reach {
    fn new(num_blocks: usize) -> Self {
        Reach {
            executable_blocks: vec![false; num_blocks],
            edges: ExecEdges::new(num_blocks),
            queued: vec![false; num_blocks],
            terminator_done: vec![false; num_blocks],
            cfg_worklist: VecDeque::new(),
        }
    }

    fn enqueue(&mut self, block: BlockId) {
        let idx = block.0 as usize;
        if !self.queued[idx] {
            self.queued[idx] = true;
            self.cfg_worklist.push_back(block);
        }
    }

    fn mark_edge_executable(&mut self, from: BlockId, to: BlockId) {
        let to_idx = to.0 as usize;
        if to_idx >= self.executable_blocks.len() || !self.edges.insert(from, to) {
            return;
        }
        self.executable_blocks[to_idx] = true;
        // Either the block just became reachable, or it already was and a new
        // predecessor edge means its phis need to meet the new operand.
        self.enqueue(to);
    }
}

/// Run Sparse Conditional Constant Propagation on an SSA body.
///
/// Internal storage is dense `Vec`-indexed by [`SsaValue`] / [`BlockId`] to
/// avoid the per-lookup `SipHash` cost of `HashMap<SsaValue, _>` /
/// `HashSet<(BlockId, BlockId)>` that previously dominated the inner
/// fixed-point loop. The result hands the dense lattice over as
/// [`ConstValues`] without a conversion pass.
///
/// Cost is linear in the number of operand uses plus the lattice height times
/// the number of uses: a changed value re-evaluates exactly the instructions
/// that read it (per-instruction use lists), a phi absorbs a changed operand in
/// constant time, and a block is queued at most once at a time however many
/// incoming edges it gains.
pub fn const_propagate(body: &SsaBody) -> ConstPropResult {
    let num_blocks = body.blocks.len();
    let num_values = body.value_defs.len();

    // Dense per-value lattice (`Vec` indexed by `SsaValue.0`).  All values
    // are defined by exactly one inst (phi or body), so initialising the
    // entire range to Top is equivalent to the previous per-inst insert
    // pass at strictly lower cost (no hashing).
    let mut values: Vec<ConstLattice> = vec![ConstLattice::Top; num_values];

    let mut reach = Reach::new(num_blocks);
    let mut ssa_worklist: VecDeque<SsaValue> = VecDeque::new();

    // Mark entry executable
    reach.executable_blocks[body.entry.0 as usize] = true;
    reach.enqueue(body.entry);

    // Use lists are built once, before either worklist runs, and never
    // mutated, so the SSA worklist can borrow them while it mutates `values`.
    let uses = UseIndex::build(body, num_values);

    // Process until both worklists are empty
    loop {
        let mut changed = false;

        // Process CFG worklist
        while let Some(block_id) = reach.cfg_worklist.pop_front() {
            reach.queued[block_id.0 as usize] = false;
            let block = body.block(block_id);

            // Evaluate phis
            for phi in &block.phis {
                if let SsaOp::Phi(operands) = &phi.op {
                    let new_val = eval_phi(operands, &values, &reach.edges, block_id);
                    if changed_from(&values, phi.value, &new_val) {
                        store(&mut values, phi.value, new_val);
                        ssa_worklist.push_back(phi.value);
                        changed = true;
                    }
                }
            }

            // Evaluate body instructions
            for inst in &block.body {
                let new_val = eval_inst(inst, &values);
                if changed_from(&values, inst.value, &new_val) {
                    store(&mut values, inst.value, new_val);
                    ssa_worklist.push_back(inst.value);
                    changed = true;
                }
            }

            // Process terminator: determine which successors are executable
            process_terminator(block, body, &values, &mut reach);
        }

        // Process SSA worklist
        while let Some(val) = ssa_worklist.pop_front() {
            let sites = uses.of(val);
            let mut i = 0;
            while i < sites.len() {
                // All sites in one block are adjacent; handle them as a run.
                let block_id = sites[i].block;
                let run_end = i + sites[i..]
                    .iter()
                    .take_while(|s| s.block == block_id)
                    .count();
                let run = &sites[i..run_end];
                i = run_end;

                if !reach.executable_blocks[block_id.0 as usize] {
                    continue;
                }
                let block = body.block(block_id);
                let phi_count = block.phis.len();

                for site in run {
                    let slot = site.slot as usize;
                    let (inst, new_val) = if slot < phi_count {
                        // Fold the changed operand into the phi. Values only
                        // move down the lattice and executable edges only
                        // grow, so meeting the new operand into the stored
                        // phi value equals re-meeting every operand.
                        let phi = &block.phis[slot];
                        let SsaOp::Phi(operands) = &phi.op else {
                            continue;
                        };
                        let Some(&(pred, _)) = operands.get(site.operand as usize) else {
                            continue;
                        };
                        if !reach.edges.contains(pred, block_id) {
                            continue;
                        }
                        let merged = lookup_ref(&values, phi.value).meet(lookup_ref(&values, val));
                        (phi, merged)
                    } else {
                        let inst = &block.body[slot - phi_count];
                        (inst, eval_inst(inst, &values))
                    };
                    if changed_from(&values, inst.value, &new_val) {
                        store(&mut values, inst.value, new_val);
                        ssa_worklist.push_back(inst.value);
                        changed = true;
                    }
                }

                // The branch condition resolves through `cfg_node_map`, not
                // through a use list, so look at the terminator again after
                // any instruction of the block was re-evaluated.
                process_terminator(block, body, &values, &mut reach);
            }
        }

        if !changed {
            break;
        }
    }

    // A/B escape hatch (benchmark-only, off in production): reproduce the
    // pre-2026-07-15 per-value `HashMap<SsaValue, ConstLattice>` build so a
    // single binary can measure the result-materialisation delta via
    // `NYX_CONST_VALUES_LEGACY_BUILD=1`.  The map is thrown away (`black_box`
    // keeps the compiler from eliding the inserts); the real dense result is
    // still returned, so only the extra build cost is measured.
    if legacy_result_build_enabled() {
        let mut m: HashMap<SsaValue, ConstLattice> = HashMap::with_capacity(values.len());
        for (i, v) in values.iter().enumerate() {
            m.insert(SsaValue(i as u32), v.clone());
        }
        std::hint::black_box(&m);
    }

    // Move the dense lattice into the public result with zero conversion.
    // The unreachable-blocks set is small (often empty), so building it from
    // a linear scan is fine.
    let mut unreachable_blocks: HashSet<BlockId> = HashSet::new();
    for (i, exec) in reach.executable_blocks.iter().enumerate() {
        if !exec {
            unreachable_blocks.insert(BlockId(i as u32));
        }
    }

    ConstPropResult {
        values: ConstValues(values),
        unreachable_blocks,
    }
}

/// Benchmark A/B toggle: when `NYX_CONST_VALUES_LEGACY_BUILD=1`, `const_propagate`
/// reproduces the old per-body `HashMap` result build to isolate the
/// dense-`Vec`-result win on a single binary.  Read once (env is process-stable).
#[inline]
fn legacy_result_build_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NYX_CONST_VALUES_LEGACY_BUILD").is_some())
}

/// Dense lattice lookup. Returns Top for out-of-range values to match the
/// pre-refactor `HashMap::get(&v).cloned().unwrap_or(Top)` semantics.
#[inline]
fn lookup(values: &[ConstLattice], v: SsaValue) -> ConstLattice {
    values
        .get(v.0 as usize)
        .cloned()
        .unwrap_or(ConstLattice::Top)
}

/// Borrowing variant of [`lookup`]: returns a reference to the stored
/// lattice (or a shared `Top` sentinel for out-of-range values) so phi
/// meet, branch-condition resolution, and change-detection avoid cloning
/// `ConstLattice::Str` heap data on the hot fixed-point path.
#[inline]
fn lookup_ref(values: &[ConstLattice], v: SsaValue) -> &ConstLattice {
    const TOP: ConstLattice = ConstLattice::Top;
    values.get(v.0 as usize).unwrap_or(&TOP)
}

/// True iff `new_val` differs from the value currently stored for `v`,
/// mirroring `lookup(values, v) != *new_val` WITHOUT cloning the stored
/// lattice. Out-of-range slots read as `Top` (matching `lookup`'s
/// `unwrap_or(Top)`), and a store to an out-of-range slot is a no-op either
/// way, so this is bit-identical to the prior `let old = lookup(..); new !=
/// old` shape while eliminating a per-instruction clone (a heap allocation
/// for `Str` values) on every worklist re-evaluation.
#[inline]
fn changed_from(values: &[ConstLattice], v: SsaValue, new_val: &ConstLattice) -> bool {
    match values.get(v.0 as usize) {
        Some(cur) => cur != new_val,
        None => *new_val != ConstLattice::Top,
    }
}

/// Dense lattice store. Out-of-range writes are silently dropped to
/// preserve robustness against malformed SSA input — the prior HashMap
/// path would have inserted a stray entry; the dense path leaves it
/// implicit (Top). Either way the value is unobservable downstream
/// because no use-map entry would point at it.
#[inline]
fn store(values: &mut [ConstLattice], v: SsaValue, val: ConstLattice) {
    let idx = v.0 as usize;
    if idx < values.len() {
        values[idx] = val;
    }
}

#[cfg(test)]
thread_local! {
    /// Phi operands `eval_phi` has looked at, so a test can pin its cost.
    static PHI_OPERAND_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Evaluate a phi: meet of operands from executable predecessors.
fn eval_phi(
    operands: &[(BlockId, SsaValue)],
    values: &[ConstLattice],
    edges: &ExecEdges,
    this_block: BlockId,
) -> ConstLattice {
    let mut result = ConstLattice::Top;
    for (pred_block, val) in operands {
        #[cfg(test)]
        PHI_OPERAND_VISITS.with(|c| c.set(c.get() + 1));
        if !edges.contains(*pred_block, this_block) {
            continue; // skip non-executable predecessors
        }
        // Borrow the operand's stored lattice instead of cloning it; `meet`
        // only reads `&other`, so a phi over `Str` operands no longer heap-
        // allocates one clone per incoming edge.
        result = result.meet(lookup_ref(values, *val));
        if result == ConstLattice::Varying {
            break; // absorbing: no later operand can change it
        }
    }
    result
}

/// Evaluate a single instruction.
fn eval_inst(inst: &SsaInst, values: &[ConstLattice]) -> ConstLattice {
    match &inst.op {
        SsaOp::Const(Some(text)) => ConstLattice::parse(text),
        SsaOp::Const(None) => ConstLattice::Varying, // unknown constant
        SsaOp::Assign(uses) if uses.len() == 1 => {
            // Copy: propagate the source's value
            lookup(values, uses[0])
        }
        SsaOp::Assign(_) => ConstLattice::Varying, // expression with multiple uses
        SsaOp::Call { .. }
        | SsaOp::Source
        | SsaOp::Param { .. }
        | SsaOp::SelfParam
        | SsaOp::CatchParam => ConstLattice::Varying,
        // FieldProj: projecting a field is dynamic with respect to the
        // const-propagation lattice, there is no general way to fold
        // `obj.field` to a known scalar at this phase.  Returning Varying
        // matches Call: callers needing field-level constness will go
        // through the points-to / heap analysis.
        SsaOp::FieldProj { .. } => ConstLattice::Varying,
        SsaOp::Phi(_) => ConstLattice::Varying, // phis in body shouldn't happen
        SsaOp::Nop => ConstLattice::Varying,
        // Undef contributes no knowledge: `Top` is the lattice identity
        // for meet, so a phi operand of Undef leaves the joined value
        // to the other incoming operands.
        SsaOp::Undef => ConstLattice::Top,
    }
}

/// Apply a closure to every SSA value used by an instruction, along with the
/// index of the phi operand that carries it (0 for every other instruction).
/// Avoids the `Vec<SsaValue>` heap allocation that the previous
/// `inst_uses(inst)` helper paid on every call.
#[inline]
fn inst_uses_each<F: FnMut(SsaValue, u32)>(inst: &SsaInst, mut f: F) {
    match &inst.op {
        SsaOp::Phi(operands) => {
            for (i, (_, v)) in operands.iter().enumerate() {
                f(*v, i as u32);
            }
        }
        SsaOp::Assign(uses) => {
            for v in uses {
                f(*v, 0);
            }
        }
        SsaOp::Call { args, receiver, .. } => {
            if let Some(rv) = receiver {
                f(*rv, 0);
            }
            for arg in args {
                for v in arg {
                    f(*v, 0);
                }
            }
        }
        SsaOp::FieldProj { receiver, .. } => f(*receiver, 0),
        SsaOp::Source
        | SsaOp::Const(_)
        | SsaOp::Param { .. }
        | SsaOp::SelfParam
        | SsaOp::CatchParam
        | SsaOp::Nop
        | SsaOp::Undef => {}
    }
}

/// Process a block's terminator to determine successor executability.
fn process_terminator(
    block: &SsaBlock,
    body: &SsaBody,
    values: &[ConstLattice],
    reach: &mut Reach,
) {
    match &block.terminator {
        Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            condition: _,
        } => {
            // Try to resolve the condition to a known boolean
            let cond_val = body
                .cfg_node_map
                .get(cond)
                .and_then(|v| lookup_ref(values, *v).as_bool());

            match cond_val {
                Some(true) => reach.mark_edge_executable(block.id, *true_blk),
                Some(false) => reach.mark_edge_executable(block.id, *false_blk),
                None => {
                    // Unknown: both successors executable
                    reach.mark_edge_executable(block.id, *true_blk);
                    reach.mark_edge_executable(block.id, *false_blk);
                }
            }
        }
        // Goto, Switch, Return and Unreachable all flow to `block.succs`,
        // whatever the values are.
        //
        // `block.succs` is authoritative. For collapsed >=3-way fanouts
        // (see src/ssa/lower.rs `three_successor_collapse`) a Goto only
        // records the first successor; marking just that one would leave the
        // others unreachable for SCCP. A Switch has no per-case literals
        // threaded through yet, so every successor stays executable, which
        // mirrors the pre-Switch cascade. Return/Unreachable keep their
        // finally/cleanup continuation edges on `succs` too, so SCCP reaches
        // downstream (e.g. finally) blocks.
        Terminator::Goto(_)
        | Terminator::Switch { .. }
        | Terminator::Return(_)
        | Terminator::Unreachable => {
            let done = &mut reach.terminator_done[block.id.0 as usize];
            if *done {
                return;
            }
            *done = true;
            for &target in &block.succs {
                reach.mark_edge_executable(block.id, target);
            }
        }
    }
}

/// Apply constant propagation results: prune branches where condition is known constant.
///
/// Returns the number of branches pruned.
pub fn apply_const_prop(body: &mut SsaBody, result: &ConstPropResult) -> usize {
    // Collect pruning decisions first to avoid borrow conflicts.
    // Each entry: (block_index, taken_block, untaken_block)
    let mut prune_ops: Vec<(usize, BlockId, BlockId)> = Vec::new();

    for (block_idx, block) in body.blocks.iter().enumerate() {
        if let Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            condition: _,
        } = &block.terminator
        {
            let cond_val = body
                .cfg_node_map
                .get(cond)
                .and_then(|v| result.values.get(v))
                .and_then(|c| c.as_bool());

            match cond_val {
                Some(true) => {
                    prune_ops.push((block_idx, *true_blk, *false_blk));
                }
                Some(false) => {
                    prune_ops.push((block_idx, *false_blk, *true_blk));
                }
                None => {}
            }
        }
    }

    let pruned = prune_ops.len();

    // Apply pruning
    for (block_idx, taken, untaken) in prune_ops {
        let pred_id = body.blocks[block_idx].id;
        body.blocks[block_idx].terminator = Terminator::Goto(taken);

        // Remove pred from untaken's preds
        let untaken_idx = untaken.0 as usize;
        if untaken_idx < body.blocks.len() {
            body.blocks[untaken_idx].preds.retain(|p| *p != pred_id);
            // Remove phi operands referencing this pred
            for phi in &mut body.blocks[untaken_idx].phis {
                if let SsaOp::Phi(operands) = &mut phi.op {
                    operands.retain(|(bid, _)| *bid != pred_id);
                }
            }
        }

        // Remove untaken from pred's succs
        body.blocks[block_idx].succs.retain(|s| *s != untaken);
    }

    // Mark unreachable blocks
    for &bid in &result.unreachable_blocks {
        body.block_mut(bid).terminator = Terminator::Unreachable;
    }

    pruned
}

/// Resolve a condition variable name to the SSA value reaching `block`.
///
/// Mirrors `constraint::lower::resolve_single_var` (the established resolver
/// for branch-condition variables): prefer the highest-indexed definition in
/// the branch block itself, else the highest-indexed definition elsewhere.
/// Kept local to avoid a `ssa → constraint` dependency cycle (constraint
/// already depends on ssa).
fn resolve_const_var(body: &SsaBody, var_name: &str, block: BlockId) -> Option<SsaValue> {
    let mut best_in_block: Option<SsaValue> = None;
    let mut best_outside: Option<SsaValue> = None;
    for (idx, vd) in body.value_defs.iter().enumerate() {
        if vd.var_name.as_deref() != Some(var_name) {
            continue;
        }
        let v = SsaValue(idx as u32);
        if vd.block == block {
            best_in_block = Some(match best_in_block {
                Some(existing) if existing.0 > v.0 => existing,
                _ => v,
            });
        } else {
            best_outside = Some(match best_outside {
                Some(existing) if existing.0 > v.0 => existing,
                _ => v,
            });
        }
    }
    best_in_block.or(best_outside)
}

/// Fold branch conditions that are pure integer-arithmetic comparisons over
/// constant operands, pruning the statically-dead edge.
///
/// Complements [`apply_const_prop`], which only folds a condition that lowers
/// to a single SSA boolean value.  An arithmetic comparison condition such as
/// `(7*42) - num > 200` is **never** an SSA value — condition nodes lower to
/// `Nop` and the comparison is held structurally on the branch terminator — so
/// SCCP cannot reach it.  This pass instead evaluates the
/// [`crate::cfg::CondArith`] tree captured at CFG-build time, resolving each
/// variable to its const-propagated integer.
///
/// Sound by construction:
///   * A branch is pruned only when its `CondArith` evaluates to a **definite**
///     boolean — every variable bound to a known integer constant and every
///     operation defined (no div-by-zero / overflow).  `None`/`Varying` leaves
///     both edges intact.
///   * After the terminator is rewritten to `Goto(taken)` and the dead edge is
///     dropped (symmetrically, preserving pred/succ consistency), every phi
///     operand whose predecessor is no longer reachable from entry is removed.
///     That last step is what actually drops the dead-branch operand from a
///     merge phi like `bar = phi(then: "const", else: param)` — without it the
///     taint engine's phi fallback would still read the tainted `param` from
///     the joined entry state.
///
/// Returns the number of branches pruned.
pub fn fold_constant_branches(
    body: &mut SsaBody,
    cfg: &crate::cfg::Cfg,
    const_values: &ConstValues,
) -> usize {
    use crate::ssa::ir::Terminator;

    // 1. Collect definite fold decisions: (branch_block_idx, taken, untaken).
    let mut prune_ops: Vec<(usize, BlockId, BlockId)> = Vec::new();
    for (block_idx, block) in body.blocks.iter().enumerate() {
        let Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            ..
        } = &block.terminator
        else {
            continue;
        };
        // Degenerate `cond ? X : X` (both edges to one block): nothing to prune.
        if true_blk == false_blk {
            continue;
        }
        let Some(cond_info) = cfg.node_weight(*cond) else {
            continue;
        };
        let Some(arith) = cond_info.cond_arith.as_ref() else {
            continue;
        };
        let branch_block = block.id;
        let resolve = |name: &str| -> Option<i64> {
            let v = resolve_const_var(body, name, branch_block)?;
            match const_values.get(&v) {
                Some(ConstLattice::Int(n)) => Some(*n),
                _ => None,
            }
        };
        match arith.eval_bool(&resolve) {
            Some(true) => prune_ops.push((block_idx, *true_blk, *false_blk)),
            Some(false) => prune_ops.push((block_idx, *false_blk, *true_blk)),
            None => {}
        }
    }

    let pruned = prune_ops.len();
    if pruned == 0 {
        return 0;
    }

    // 2. Rewrite terminators + drop the dead edge (symmetrically).
    for &(block_idx, taken, untaken) in &prune_ops {
        let pred_id = body.blocks[block_idx].id;
        body.blocks[block_idx].terminator = Terminator::Goto(taken);
        body.blocks[block_idx].succs.retain(|s| *s != untaken);
        let untaken_idx = untaken.0 as usize;
        if untaken_idx < body.blocks.len() {
            body.blocks[untaken_idx].preds.retain(|p| *p != pred_id);
        }
    }

    // 3. Recompute reachability from entry over the (now-pruned) succ edges.
    let n = body.blocks.len();
    let mut reachable = vec![false; n];
    let mut stack = vec![body.entry];
    if (body.entry.0 as usize) < n {
        reachable[body.entry.0 as usize] = true;
    }
    while let Some(b) = stack.pop() {
        let bidx = b.0 as usize;
        if bidx >= n {
            continue;
        }
        // Clone succs to avoid borrow conflict with `reachable`.
        let succs: SmallVec<[BlockId; 2]> = body.blocks[bidx].succs.clone();
        for s in succs {
            let sidx = s.0 as usize;
            if sidx < n && !reachable[sidx] {
                reachable[sidx] = true;
                stack.push(s);
            }
        }
    }

    // 4. Reachable blocks: drop the now-dead predecessor.  Removing the phi
    //    operand from the merge block is what stops the tainted dead-branch
    //    value feeding the phi; removing the pred keeps pred/succ symmetric
    //    with step 5's succ clearing.  Operands from still-reachable
    //    predecessors are untouched, so no live flow is lost.
    for (bidx, block) in body.blocks.iter_mut().enumerate() {
        if !reachable[bidx] {
            continue;
        }
        block.preds.retain(|p| {
            let pidx = p.0 as usize;
            pidx < n && reachable[pidx]
        });
        for phi in &mut block.phis {
            if let SsaOp::Phi(operands) = &mut phi.op {
                operands.retain(|(pred, _)| {
                    let pidx = pred.0 as usize;
                    pidx < n && reachable[pidx]
                });
            }
        }
    }

    // 5. Unreachable blocks: neutralise them so the *later* optimiser passes
    //    (copy-prop, base-alias grouping, type-facts, points-to) and the taint
    //    transfer never observe their dead instructions.  This is the
    //    load-bearing step for precision: a dead `else bar = param` would
    //    otherwise make copy-prop alias `bar`↔`param`, and
    //    `propagate_taint_to_aliases` would then poison the *surviving const*
    //    `bar` with `param`'s (still-reachable) taint — defeating the whole
    //    prune.  Each instruction is rewritten to `Nop` (value + cfg_node
    //    preserved so `value_defs` coverage holds), the terminator to
    //    `Unreachable`, and the block is fully disconnected.
    for (bidx, block) in body.blocks.iter_mut().enumerate() {
        if reachable[bidx] {
            continue;
        }
        for inst in block.phis.iter_mut().chain(block.body.iter_mut()) {
            inst.op = SsaOp::Nop;
        }
        block.terminator = Terminator::Unreachable;
        block.succs.clear();
        block.preds.clear();
    }

    pruned
}

/// Collect module aliases from `require()` calls in the SSA body.
///
/// Detects patterns like `const http = require("http")` and propagates
/// aliases through phi nodes (e.g., `const lib = cond ? https : http`).
/// Returns a map from SSA value → set of possible module names.
///
/// Only tracks known HTTP-related modules to avoid false positives.
pub fn collect_module_aliases(
    body: &SsaBody,
    const_values: &ConstValues,
) -> HashMap<SsaValue, smallvec::SmallVec<[String; 2]>> {
    use smallvec::SmallVec;

    // Known modules whose methods are security-relevant for alias tracking.
    const KNOWN_MODULES: &[&str] = &["http", "https", "child_process", "fs", "net", "dgram"];

    let mut aliases: HashMap<SsaValue, SmallVec<[String; 2]>> = HashMap::new();

    // Pass 1: detect `require("module")` calls.
    for block in &body.blocks {
        for inst in &block.body {
            if let SsaOp::Call { callee, args, .. } = &inst.op
                && (callee == "require" || callee.ends_with(".require"))
            {
                // Check if the first argument is a known module string constant.
                if let Some(first_arg) = args.first()
                    && let Some(&first_val) = first_arg.first()
                    && let Some(ConstLattice::Str(module_name)) = const_values.get(&first_val)
                    && KNOWN_MODULES.contains(&module_name.as_str())
                {
                    aliases
                        .entry(inst.value)
                        .or_default()
                        .push(module_name.clone());
                }
            }
        }
    }

    if aliases.is_empty() {
        return aliases;
    }

    // Pass 2: propagate through copies (single-use Assign) and phi nodes.
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 10 {
        changed = false;
        iterations += 1;
        for block in &body.blocks {
            // Phi nodes
            for phi in &block.phis {
                if let SsaOp::Phi(operands) = &phi.op {
                    let mut merged: SmallVec<[String; 2]> = SmallVec::new();
                    for (_, operand_val) in operands {
                        if let Some(operand_aliases) = aliases.get(operand_val) {
                            for a in operand_aliases {
                                if !merged.contains(a) {
                                    merged.push(a.clone());
                                }
                            }
                        }
                    }
                    if !merged.is_empty() {
                        let entry = aliases.entry(phi.value).or_default();
                        for a in &merged {
                            if !entry.contains(a) {
                                entry.push(a.clone());
                                changed = true;
                            }
                        }
                    }
                }
            }
            // Copy propagation through single-use Assign
            for inst in &block.body {
                if let SsaOp::Assign(uses) = &inst.op
                    && uses.len() == 1
                    && let Some(src_aliases) = aliases.get(&uses[0]).cloned()
                {
                    let entry = aliases.entry(inst.value).or_default();
                    for a in &src_aliases {
                        if !entry.contains(a) {
                            entry.push(a.clone());
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    aliases
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::NodeIndex;
    use smallvec::SmallVec;

    /// The dense `ConstValues` result must be behaviourally identical to the
    /// old `HashMap<SsaValue, ConstLattice>` it replaced: `get` matches
    /// `HashMap::get` over the `0..len` key set, `iter` visits every slot in
    /// index order, the `FromIterator` test builder gap-fills with `Top`, and
    /// the custom serde emits/consumes the same `{ ssa_value: lattice }` map
    /// form so persisted `CalleeSsaBody.opt` DB blobs stay wire-compatible
    /// (checked through both `serde_json` and the `rmp_serde` codec used by
    /// the summary store, and by decoding a blob written from the legacy
    /// `HashMap` shape).
    #[test]
    fn const_values_positional_semantics_and_wire_compat() {
        let cv: ConstValues = [
            (SsaValue(0), ConstLattice::Int(42)),
            (SsaValue(2), ConstLattice::Str("s".into())),
        ]
        .into_iter()
        .collect();

        // Dense range = max index + 1; gap (index 1) filled with Top.
        assert_eq!(cv.len(), 3);
        assert!(!cv.is_empty());
        assert_eq!(cv.get(&SsaValue(0)), Some(&ConstLattice::Int(42)));
        assert_eq!(cv.get(&SsaValue(1)), Some(&ConstLattice::Top));
        assert_eq!(cv.get(&SsaValue(2)), Some(&ConstLattice::Str("s".into())));
        // Out-of-range yields None, matching HashMap::get over the key set.
        assert_eq!(cv.get(&SsaValue(3)), None);

        // iter visits every slot in ascending index order.
        let collected: Vec<(SsaValue, ConstLattice)> =
            cv.iter().map(|(v, cl)| (v, cl.clone())).collect();
        assert_eq!(
            collected,
            vec![
                (SsaValue(0), ConstLattice::Int(42)),
                (SsaValue(1), ConstLattice::Top),
                (SsaValue(2), ConstLattice::Str("s".into())),
            ]
        );

        // serde_json round-trip preserves every entry.
        let json = serde_json::to_string(&cv).unwrap();
        let back: ConstValues = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back.get(&SsaValue(0)), Some(&ConstLattice::Int(42)));
        assert_eq!(back.get(&SsaValue(2)), Some(&ConstLattice::Str("s".into())));

        // rmp_serde (the CalleeSsaBody blob codec) round-trip.
        let mp = rmp_serde::to_vec_named(&cv).unwrap();
        let back_mp: ConstValues = rmp_serde::from_slice(&mp).unwrap();
        assert_eq!(back_mp.get(&SsaValue(0)), Some(&ConstLattice::Int(42)));
        assert_eq!(
            back_mp.get(&SsaValue(2)),
            Some(&ConstLattice::Str("s".into()))
        );

        // A blob written by the LEGACY `HashMap<SsaValue, ConstLattice>` shape
        // must decode into an equivalent `ConstValues` (map wire form).
        let legacy: HashMap<SsaValue, ConstLattice> = [
            (SsaValue(0), ConstLattice::Int(42)),
            (SsaValue(1), ConstLattice::Top),
            (SsaValue(2), ConstLattice::Str("s".into())),
        ]
        .into_iter()
        .collect();
        let legacy_json = serde_json::to_string(&legacy).unwrap();
        let from_legacy: ConstValues = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(from_legacy.get(&SsaValue(0)), Some(&ConstLattice::Int(42)));
        assert_eq!(
            from_legacy.get(&SsaValue(2)),
            Some(&ConstLattice::Str("s".into()))
        );
    }

    fn make_body(blocks: Vec<SsaBlock>, value_defs: Vec<ValueDef>) -> SsaBody {
        let cfg_node_map = value_defs
            .iter()
            .enumerate()
            .map(|(i, vd)| (vd.cfg_node, SsaValue(i as u32)))
            .collect();
        SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs,
            cfg_node_map,
            exception_edges: Vec::new(),
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        }
    }

    #[test]
    fn const_literal_parsed() {
        assert_eq!(ConstLattice::parse("42"), ConstLattice::Int(42));
        assert_eq!(ConstLattice::parse("-1"), ConstLattice::Int(-1));
        assert_eq!(ConstLattice::parse("true"), ConstLattice::Bool(true));
        assert_eq!(ConstLattice::parse("false"), ConstLattice::Bool(false));
        assert_eq!(ConstLattice::parse("null"), ConstLattice::Null);
        assert_eq!(ConstLattice::parse("nil"), ConstLattice::Null);
        assert_eq!(
            ConstLattice::parse("\"hello\""),
            ConstLattice::Str("hello".into())
        );
        assert_eq!(
            ConstLattice::parse("'world'"),
            ConstLattice::Str("world".into())
        );
    }

    #[test]
    fn meet_lattice() {
        let a = ConstLattice::Int(42);
        let b = ConstLattice::Int(42);
        assert_eq!(a.meet(&b), ConstLattice::Int(42));

        let c = ConstLattice::Int(99);
        assert_eq!(a.meet(&c), ConstLattice::Varying);

        assert_eq!(ConstLattice::Top.meet(&a), ConstLattice::Int(42));
        assert_eq!(a.meet(&ConstLattice::Top), ConstLattice::Int(42));

        assert_eq!(ConstLattice::Varying.meet(&a), ConstLattice::Varying);
    }

    #[test]
    fn single_block_const() {
        // v0 = const("42")
        let n0 = NodeIndex::new(0);
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(0),
                op: SsaOp::Const(Some("42".into())),
                cfg_node: n0,
                var_name: Some("x".into()),
                span: (0, 2),
            }],
            terminator: Terminator::Return(None),
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        };
        let body = make_body(
            vec![block],
            vec![ValueDef {
                var_name: Some("x".into()),
                cfg_node: n0,
                block: BlockId(0),
            }],
        );

        let result = const_propagate(&body);
        assert_eq!(
            result.values.get(&SsaValue(0)),
            Some(&ConstLattice::Int(42))
        );
        assert!(result.unreachable_blocks.is_empty());
    }

    #[test]
    fn copy_propagation_through_assign() {
        // v0 = const("true"), v1 = assign(v0)
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Const(Some("true".into())),
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    span: (0, 4),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                    cfg_node: n1,
                    var_name: Some("y".into()),
                    span: (5, 9),
                },
            ],
            terminator: Terminator::Return(None),
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        };
        let body = make_body(
            vec![block],
            vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("y".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
        );

        let result = const_propagate(&body);
        assert_eq!(
            result.values.get(&SsaValue(0)),
            Some(&ConstLattice::Bool(true))
        );
        assert_eq!(
            result.values.get(&SsaValue(1)),
            Some(&ConstLattice::Bool(true))
        );
    }

    /// Meet must be commutative: `a ⊓ b == b ⊓ a` for every pair of
    /// lattice values. Iterates a representative cross product; failure
    /// would indicate the implementation special-cased one operand.
    #[test]
    fn meet_lattice_is_commutative() {
        let vals = [
            ConstLattice::Top,
            ConstLattice::Varying,
            ConstLattice::Null,
            ConstLattice::Int(0),
            ConstLattice::Int(42),
            ConstLattice::Bool(true),
            ConstLattice::Bool(false),
            ConstLattice::Str("a".into()),
            ConstLattice::Str("b".into()),
        ];
        for a in &vals {
            for b in &vals {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "meet should be commutative for ({a:?}, {b:?})"
                );
            }
        }
    }

    /// Meet must be associative: `(a ⊓ b) ⊓ c == a ⊓ (b ⊓ c)`.
    #[test]
    fn meet_lattice_is_associative() {
        let vals = [
            ConstLattice::Top,
            ConstLattice::Varying,
            ConstLattice::Null,
            ConstLattice::Int(0),
            ConstLattice::Int(42),
            ConstLattice::Bool(true),
            ConstLattice::Str("x".into()),
        ];
        for a in &vals {
            for b in &vals {
                for c in &vals {
                    let lhs = a.meet(b).meet(c);
                    let rhs = a.meet(&b.meet(c));
                    assert_eq!(lhs, rhs, "associativity broken on ({a:?},{b:?},{c:?})");
                }
            }
        }
    }

    /// Meet must be idempotent: `a ⊓ a == a` for every lattice value.
    #[test]
    fn meet_lattice_is_idempotent() {
        let vals = [
            ConstLattice::Top,
            ConstLattice::Varying,
            ConstLattice::Null,
            ConstLattice::Int(7),
            ConstLattice::Bool(false),
            ConstLattice::Str("y".into()),
        ];
        for a in &vals {
            assert_eq!(a.meet(a), a.clone(), "idempotence broken on {a:?}");
        }
    }

    /// Top is the meet identity: `Top ⊓ x == x` for every value.
    /// Varying is meet-absorbing: `Varying ⊓ x == Varying`.
    /// Two distinct concrete values meet to Varying.
    #[test]
    fn meet_lattice_extremes() {
        let xs = [
            ConstLattice::Null,
            ConstLattice::Int(1),
            ConstLattice::Bool(true),
            ConstLattice::Str("a".into()),
        ];
        for x in &xs {
            assert_eq!(ConstLattice::Top.meet(x), x.clone());
            assert_eq!(x.meet(&ConstLattice::Top), x.clone());
            assert_eq!(ConstLattice::Varying.meet(x), ConstLattice::Varying);
            assert_eq!(x.meet(&ConstLattice::Varying), ConstLattice::Varying);
        }
        assert_eq!(
            ConstLattice::Int(1).meet(&ConstLattice::Int(2)),
            ConstLattice::Varying
        );
        assert_eq!(
            ConstLattice::Bool(true).meet(&ConstLattice::Bool(false)),
            ConstLattice::Varying
        );
        assert_eq!(
            ConstLattice::Str("a".into()).meet(&ConstLattice::Str("b".into())),
            ConstLattice::Varying
        );
    }

    /// Const parsing must round-trip integer signs. i64::MIN/MAX must
    /// parse without overflow; arbitrary text falls back to a bare-string
    /// const (current contract, tested here so a future change is
    /// caught explicitly).
    #[test]
    fn const_parse_extremes_and_fallback() {
        assert_eq!(
            ConstLattice::parse(&i64::MAX.to_string()),
            ConstLattice::Int(i64::MAX)
        );
        assert_eq!(
            ConstLattice::parse(&i64::MIN.to_string()),
            ConstLattice::Int(i64::MIN)
        );
        // Larger than i64 falls back to bare-string.
        let huge = "99999999999999999999";
        assert_eq!(
            ConstLattice::parse(huge),
            ConstLattice::Str(huge.to_string())
        );
        // Empty string parses as empty Str (not panic).
        assert_eq!(ConstLattice::parse(""), ConstLattice::Str("".into()));
        // Lone quote characters must not panic in the quote-stripping path
        // (regression for fuzz crash-2f943c14: `'` triggered &s[1..0]).
        assert_eq!(ConstLattice::parse("'"), ConstLattice::Str("'".into()));
        assert_eq!(ConstLattice::parse("\""), ConstLattice::Str("\"".into()));
    }

    /// The pre-use-list SCCP, kept verbatim as an oracle. It rescans every
    /// instruction of a use block per changed value and re-evaluates a phi from
    /// scratch on every edge, so it is slow on big bodies but obviously right.
    /// The production `const_propagate` must produce the same lattice and the
    /// same unreachable set on every body.
    mod reference {
        use super::super::*;

        pub(super) fn const_propagate_reference(body: &SsaBody) -> ConstPropResult {
            let num_blocks = body.blocks.len();
            let num_values = body.value_defs.len();

            // Dense per-value lattice (`Vec` indexed by `SsaValue.0`).  All values
            // are defined by exactly one inst (phi or body), so initialising the
            // entire range to Top is equivalent to the previous per-inst insert
            // pass at strictly lower cost (no hashing).
            let mut values: Vec<ConstLattice> = vec![ConstLattice::Top; num_values];

            // Per-block executability and per-(dest, pred) executable-edge bitmap.
            // Edges are stored as a per-destination list of executable predecessors
            // — phi evaluation only ever asks "is `(pred, this_block)` executable?",
            // so a tiny SmallVec scan over the dest's predecessors beats a
            // `HashSet<(BlockId, BlockId)>::contains` (which hashes a 64-bit pair
            // for every operand of every phi).
            let mut executable_blocks: Vec<bool> = vec![false; num_blocks];
            let mut executable_preds: Vec<SmallVec<[BlockId; 2]>> =
                vec![SmallVec::new(); num_blocks];

            // Worklists
            let mut cfg_worklist: VecDeque<BlockId> = VecDeque::new();
            let mut ssa_worklist: VecDeque<SsaValue> = VecDeque::new();

            // Mark entry executable
            executable_blocks[body.entry.0 as usize] = true;
            cfg_worklist.push_back(body.entry);

            // Use-map: dense `Vec` indexed by `SsaValue.0`.  Populated in a single
            // pass via the closure-based [`inst_uses_each`] helper, which avoids
            // the heap allocation of the prior `inst_uses() -> Vec<SsaValue>`
            // factory.
            let mut use_sites: Vec<SmallVec<[BlockId; 2]>> = vec![SmallVec::new(); num_values];
            for block in &body.blocks {
                for inst in block.phis.iter().chain(block.body.iter()) {
                    inst_uses_each_ref(inst, |used_val| {
                        let idx = used_val.0 as usize;
                        if idx < use_sites.len() {
                            let bucket = &mut use_sites[idx];
                            if bucket.last() != Some(&block.id) {
                                bucket.push(block.id);
                            }
                        }
                    });
                }
            }

            // Process until both worklists are empty
            loop {
                let mut changed = false;

                // Process CFG worklist
                while let Some(block_id) = cfg_worklist.pop_front() {
                    let block = body.block(block_id);

                    // Evaluate phis
                    for phi in &block.phis {
                        if let SsaOp::Phi(operands) = &phi.op {
                            let new_val =
                                eval_phi_ref(operands, &values, &executable_preds, block_id);
                            if changed_from(&values, phi.value, &new_val) {
                                store(&mut values, phi.value, new_val);
                                ssa_worklist.push_back(phi.value);
                                changed = true;
                            }
                        }
                    }

                    // Evaluate body instructions
                    for inst in &block.body {
                        let new_val = eval_inst(inst, &values);
                        if changed_from(&values, inst.value, &new_val) {
                            store(&mut values, inst.value, new_val);
                            ssa_worklist.push_back(inst.value);
                            changed = true;
                        }
                    }

                    // Process terminator: determine which successors are executable
                    process_terminator_ref(
                        block,
                        body,
                        &values,
                        &mut executable_preds,
                        &mut executable_blocks,
                        &mut cfg_worklist,
                    );
                }

                // Process SSA worklist
                while let Some(val) = ssa_worklist.pop_front() {
                    let val_idx = val.0 as usize;
                    if val_idx >= use_sites.len() {
                        continue;
                    }
                    // Iterate the use-list by reference. `use_sites` is built once
                    // before the worklist and never mutated inside it, and it is a
                    // distinct allocation from `values` / `executable_*` / the
                    // worklists, so the borrow checker allows borrowing the block-id
                    // list immutably while `values` is mutated — the previous per-pop
                    // `SmallVec` clone (a heap allocation whenever a value is used in
                    // >2 blocks) was spurious.
                    for &block_id in &use_sites[val_idx] {
                        if !executable_blocks[block_id.0 as usize] {
                            continue;
                        }
                        let block = body.block(block_id);

                        // Re-evaluate phis using this value
                        for phi in &block.phis {
                            if let SsaOp::Phi(operands) = &phi.op
                                && operands.iter().any(|(_, v)| *v == val)
                            {
                                let new_val =
                                    eval_phi_ref(operands, &values, &executable_preds, block_id);
                                if changed_from(&values, phi.value, &new_val) {
                                    store(&mut values, phi.value, new_val);
                                    ssa_worklist.push_back(phi.value);
                                    changed = true;
                                }
                            }
                        }

                        // Re-evaluate body instructions using this value
                        for inst in &block.body {
                            if inst_has_use_ref(inst, val) {
                                let new_val = eval_inst(inst, &values);
                                if changed_from(&values, inst.value, &new_val) {
                                    store(&mut values, inst.value, new_val);
                                    ssa_worklist.push_back(inst.value);
                                    changed = true;
                                }
                            }
                        }

                        // Re-evaluate terminator if condition changed
                        process_terminator_ref(
                            block,
                            body,
                            &values,
                            &mut executable_preds,
                            &mut executable_blocks,
                            &mut cfg_worklist,
                        );
                    }
                }

                if !changed {
                    break;
                }
            }

            // Move the dense lattice into the public result with zero conversion —
            // no per-value hashed insert (the old `HashMap<SsaValue, ConstLattice>`
            // build was `O(num_values)` SipHash inserts per body, discarded next
            // scan).  The unreachable-blocks set is small (often empty), so building
            // it from a linear scan is fine.
            let mut unreachable_blocks: HashSet<BlockId> = HashSet::new();
            for (i, exec) in executable_blocks.iter().enumerate() {
                if !exec {
                    unreachable_blocks.insert(BlockId(i as u32));
                }
            }

            ConstPropResult {
                values: ConstValues(values),
                unreachable_blocks,
            }
        }

        // Evaluate a phi: meet of operands from executable predecessors.
        fn eval_phi_ref(
            operands: &[(BlockId, SsaValue)],
            values: &[ConstLattice],
            executable_preds: &[SmallVec<[BlockId; 2]>],
            this_block: BlockId,
        ) -> ConstLattice {
            let preds = executable_preds
                .get(this_block.0 as usize)
                .map(|p| p.as_slice())
                .unwrap_or(&[]);
            let mut result = ConstLattice::Top;
            for (pred_block, val) in operands {
                if !preds.contains(pred_block) {
                    continue; // skip non-executable predecessors
                }
                // Borrow the operand's stored lattice instead of cloning it; `meet`
                // only reads `&other`, so a phi over `Str` operands no longer heap-
                // allocates one clone per incoming edge.
                result = result.meet(lookup_ref(values, *val));
            }
            result
        }

        // Apply a closure to every SSA value used by an instruction. Avoids the
        // `Vec<SsaValue>` heap allocation that the previous `inst_uses(inst)`
        // helper paid on every call (use-map build is O(num_insts), the prior
        // path bottle-necked there).
        #[inline]
        fn inst_uses_each_ref<F: FnMut(SsaValue)>(inst: &SsaInst, mut f: F) {
            match &inst.op {
                SsaOp::Phi(operands) => {
                    for (_, v) in operands {
                        f(*v);
                    }
                }
                SsaOp::Assign(uses) => {
                    for v in uses {
                        f(*v);
                    }
                }
                SsaOp::Call { args, receiver, .. } => {
                    if let Some(rv) = receiver {
                        f(*rv);
                    }
                    for arg in args {
                        for v in arg {
                            f(*v);
                        }
                    }
                }
                SsaOp::FieldProj { receiver, .. } => f(*receiver),
                SsaOp::Source
                | SsaOp::Const(_)
                | SsaOp::Param { .. }
                | SsaOp::SelfParam
                | SsaOp::CatchParam
                | SsaOp::Nop
                | SsaOp::Undef => {}
            }
        }

        // Zero-allocation predicate: does `inst` use `target` as an operand?
        // Replaces the prior `inst_uses(inst).contains(&target)` shape, which
        // allocated a fresh `Vec<SsaValue>` on every check inside the SCCP
        // re-evaluation worklist.
        #[inline]
        fn inst_has_use_ref(inst: &SsaInst, target: SsaValue) -> bool {
            match &inst.op {
                SsaOp::Phi(operands) => operands.iter().any(|(_, v)| *v == target),
                SsaOp::Assign(uses) => uses.contains(&target),
                SsaOp::Call { args, receiver, .. } => {
                    if let Some(rv) = receiver
                        && *rv == target
                    {
                        return true;
                    }
                    args.iter().any(|arg| arg.contains(&target))
                }
                SsaOp::FieldProj { receiver, .. } => *receiver == target,
                SsaOp::Source
                | SsaOp::Const(_)
                | SsaOp::Param { .. }
                | SsaOp::SelfParam
                | SsaOp::CatchParam
                | SsaOp::Nop
                | SsaOp::Undef => false,
            }
        }

        // Process a block's terminator to determine successor executability.
        fn process_terminator_ref(
            block: &SsaBlock,
            body: &SsaBody,
            values: &[ConstLattice],
            executable_preds: &mut [SmallVec<[BlockId; 2]>],
            executable_blocks: &mut [bool],
            cfg_worklist: &mut VecDeque<BlockId>,
        ) {
            match &block.terminator {
                Terminator::Goto(_) => {
                    // `block.succs` is authoritative. For collapsed ≥3-way fanouts
                    // (see src/ssa/lower.rs `three_successor_collapse`) the terminator
                    // only records the first successor; marking just that one would
                    // leave the others unreachable for SCCP. Iterate succs so every
                    // CFG successor is marked executable.
                    for &target in &block.succs {
                        mark_edge_executable_ref(
                            block.id,
                            target,
                            executable_preds,
                            executable_blocks,
                            cfg_worklist,
                        );
                    }
                }
                Terminator::Branch {
                    cond,
                    true_blk,
                    false_blk,
                    condition: _,
                } => {
                    // Try to resolve the condition to a known boolean
                    let cond_val = body
                        .cfg_node_map
                        .get(cond)
                        .and_then(|v| lookup_ref(values, *v).as_bool());

                    match cond_val {
                        Some(true) => {
                            mark_edge_executable_ref(
                                block.id,
                                *true_blk,
                                executable_preds,
                                executable_blocks,
                                cfg_worklist,
                            );
                        }
                        Some(false) => {
                            mark_edge_executable_ref(
                                block.id,
                                *false_blk,
                                executable_preds,
                                executable_blocks,
                                cfg_worklist,
                            );
                        }
                        None => {
                            // Unknown: both successors executable
                            mark_edge_executable_ref(
                                block.id,
                                *true_blk,
                                executable_preds,
                                executable_blocks,
                                cfg_worklist,
                            );
                            mark_edge_executable_ref(
                                block.id,
                                *false_blk,
                                executable_preds,
                                executable_blocks,
                                cfg_worklist,
                            );
                        }
                    }
                }
                Terminator::Switch {
                    scrutinee,
                    targets,
                    default,
                    case_values,
                } => {
                    // Try to resolve scrutinee to a concrete integer literal; if
                    // we can match it against one of the case literals (not
                    // currently available on the SSA IR), mark just that target.
                    // Until per-case literals are threaded through, fall back to
                    // the sound "any successor executable" behavior, which mirrors
                    // the pre-Switch cascade.
                    let _ = (scrutinee, targets, default, case_values);
                    for &target in &block.succs {
                        mark_edge_executable_ref(
                            block.id,
                            target,
                            executable_preds,
                            executable_blocks,
                            cfg_worklist,
                        );
                    }
                }
                Terminator::Return(_) | Terminator::Unreachable => {
                    // `block.succs` is authoritative; the terminator is advisory.
                    // Finally/cleanup continuation edges live on `succs` even when
                    // the structured terminator is `Return`/`Unreachable`. Mark them
                    // executable so SCCP reaches downstream (e.g. finally) blocks.
                    for &target in &block.succs {
                        mark_edge_executable_ref(
                            block.id,
                            target,
                            executable_preds,
                            executable_blocks,
                            cfg_worklist,
                        );
                    }
                }
            }
        }

        fn mark_edge_executable_ref(
            from: BlockId,
            to: BlockId,
            executable_preds: &mut [SmallVec<[BlockId; 2]>],
            executable_blocks: &mut [bool],
            cfg_worklist: &mut VecDeque<BlockId>,
        ) {
            let to_idx = to.0 as usize;
            if to_idx >= executable_preds.len() {
                return;
            }
            let preds = &mut executable_preds[to_idx];
            if preds.contains(&from) {
                return;
            }
            preds.push(from);
            let was_already_exec = executable_blocks[to_idx];
            if !was_already_exec {
                executable_blocks[to_idx] = true;
            }
            // Always re-enqueue: either the block became newly reachable, or it
            // already was but a new predecessor edge means phi operands need
            // re-meeting against the now-executable predecessor.
            cfg_worklist.push_back(to);
        }
    }

    fn assert_matches_reference(body: &SsaBody, what: &str) {
        let new = const_propagate(body);
        let old = reference::const_propagate_reference(body);
        assert_eq!(
            new.values.len(),
            old.values.len(),
            "{what}: value table size differs"
        );
        for (v, cl) in old.values.iter() {
            assert_eq!(
                new.values.get(&v),
                Some(cl),
                "{what}: lattice differs for {v:?}"
            );
        }
        assert_eq!(
            new.unreachable_blocks, old.unreachable_blocks,
            "{what}: unreachable blocks differ"
        );
    }

    fn inst(value: u32, op: SsaOp) -> SsaInst {
        SsaInst {
            value: SsaValue(value),
            op,
            cfg_node: NodeIndex::new(value as usize),
            var_name: None,
            span: (0, 0),
        }
    }

    fn konst(value: u32, text: &str) -> SsaInst {
        inst(value, SsaOp::Const(Some(text.into())))
    }

    fn copy_of(value: u32, src: u32) -> SsaInst {
        inst(value, SsaOp::Assign(SmallVec::from_elem(SsaValue(src), 1)))
    }

    fn phi_of(value: u32, operands: &[(u32, u32)]) -> SsaInst {
        inst(
            value,
            SsaOp::Phi(
                operands
                    .iter()
                    .map(|&(b, v)| (BlockId(b), SsaValue(v)))
                    .collect(),
            ),
        )
    }

    fn blk(
        id: u32,
        phis: Vec<SsaInst>,
        body: Vec<SsaInst>,
        terminator: Terminator,
        preds: &[u32],
        succs: &[u32],
    ) -> SsaBlock {
        SsaBlock {
            id: BlockId(id),
            phis,
            body,
            terminator,
            preds: preds.iter().map(|&b| BlockId(b)).collect(),
            succs: succs.iter().map(|&b| BlockId(b)).collect(),
        }
    }

    /// `n` values, value `i` defined at node `i` of block `blocks[i]`.
    fn defs(owner: &[u32]) -> Vec<ValueDef> {
        owner
            .iter()
            .enumerate()
            .map(|(i, &b)| ValueDef {
                var_name: None,
                cfg_node: NodeIndex::new(i),
                block: BlockId(b),
            })
            .collect()
    }

    fn branch(cond_value: u32, t: u32, f: u32) -> Terminator {
        Terminator::Branch {
            cond: NodeIndex::new(cond_value as usize),
            true_blk: BlockId(t),
            false_blk: BlockId(f),
            condition: None,
        }
    }

    /// A switch-shaped body: block 0 fans out to `cases` blocks, each defines
    /// one constant and jumps to a single exit block, whose phi joins them all.
    /// `case_text(i)` is the constant of case `i`.
    fn wide_join(cases: u32, case_text: impl Fn(u32) -> String) -> (SsaBody, SsaValue) {
        let exit = cases + 1;
        let mut blocks = Vec::new();
        let succs: Vec<u32> = (1..=cases).collect();
        blocks.push(blk(
            0,
            vec![],
            vec![],
            Terminator::Goto(BlockId(1)),
            &[],
            &succs,
        ));
        let mut owner = Vec::new();
        let mut operands = Vec::new();
        for i in 0..cases {
            let b = i + 1;
            blocks.push(blk(
                b,
                vec![],
                vec![konst(i, &case_text(i))],
                Terminator::Goto(BlockId(exit)),
                &[0],
                &[exit],
            ));
            owner.push(b);
            operands.push((b, i));
        }
        let phi_value = cases;
        owner.push(exit);
        let preds: Vec<u32> = (1..=cases).collect();
        blocks.push(blk(
            exit,
            vec![phi_of(phi_value, &operands)],
            vec![],
            Terminator::Return(None),
            &preds,
            &[],
        ));
        (make_body(blocks, defs(&owner)), SsaValue(phi_value))
    }

    #[test]
    fn wide_join_phi_of_distinct_constants_is_varying() {
        let (body, phi) = wide_join(300, |i| i.to_string());
        let result = const_propagate(&body);
        assert_eq!(result.values.get(&phi), Some(&ConstLattice::Varying));
        assert!(result.unreachable_blocks.is_empty());
        assert_matches_reference(&body, "wide join, distinct constants");
    }

    #[test]
    fn wide_join_phi_of_equal_constants_stays_constant() {
        let (body, phi) = wide_join(300, |_| "7".to_string());
        let result = const_propagate(&body);
        assert_eq!(result.values.get(&phi), Some(&ConstLattice::Int(7)));
        assert_matches_reference(&body, "wide join, equal constants");
    }

    /// The join is evaluated once however many predecessors it has: the
    /// operand visits are counted, so a regression to one re-evaluation per
    /// incoming edge shows up as a quadratic count rather than as a slow test.
    #[test]
    fn wide_join_phi_visits_each_operand_a_bounded_number_of_times() {
        let cases = 4000;
        let (body, phi) = wide_join(cases, |_| "7".to_string());
        PHI_OPERAND_VISITS.with(|c| c.set(0));
        let result = const_propagate(&body);
        let visits = PHI_OPERAND_VISITS.with(|c| c.get());
        assert_eq!(result.values.get(&phi), Some(&ConstLattice::Int(7)));
        assert!(
            visits <= 2 * cases as usize,
            "phi operands visited {visits} times for {cases} operands"
        );
    }

    /// Operands arriving over a pruned edge are excluded from the meet, also
    /// when the join is wide enough to use the hashed edge index.
    #[test]
    fn wide_join_ignores_operands_from_pruned_branch() {
        // 0: v0 = true; if v0 -> 1 else 2
        // 1: fans out to 12 live cases (consts 5), each jumps to 15
        // 2: dead, jumps to 15 with a different constant
        // 15: phi over the 12 live cases and the dead block
        let live = 12u32;
        let exit = 3 + live;
        let mut blocks = vec![
            blk(
                0,
                vec![],
                vec![konst(0, "true"), copy_of(1, 0)],
                branch(1, 1, 2),
                &[],
                &[1, 2],
            ),
            blk(
                1,
                vec![],
                vec![],
                Terminator::Goto(BlockId(3)),
                &[0],
                &(3..3 + live).collect::<Vec<_>>(),
            ),
            blk(
                2,
                vec![],
                vec![konst(2, "99")],
                Terminator::Goto(BlockId(exit)),
                &[0],
                &[exit],
            ),
        ];
        let mut owner = vec![0, 0, 2];
        let mut operands = vec![(2u32, 2u32)];
        for i in 0..live {
            let b = 3 + i;
            let v = 3 + i;
            blocks.push(blk(
                b,
                vec![],
                vec![konst(v, "5")],
                Terminator::Goto(BlockId(exit)),
                &[1],
                &[exit],
            ));
            owner.push(b);
            operands.push((b, v));
        }
        let phi_value = 3 + live;
        owner.push(exit);
        let mut preds: Vec<u32> = (3..3 + live).collect();
        preds.push(2);
        blocks.push(blk(
            exit,
            vec![phi_of(phi_value, &operands)],
            vec![],
            Terminator::Return(None),
            &preds,
            &[],
        ));
        let body = make_body(blocks, defs(&owner));
        let result = const_propagate(&body);
        assert_eq!(
            result.values.get(&SsaValue(phi_value)),
            Some(&ConstLattice::Int(5)),
            "the dead branch's 99 must not reach the join"
        );
        assert!(result.unreachable_blocks.contains(&BlockId(2)));
        assert_matches_reference(&body, "wide join with a pruned predecessor");
    }

    /// A loop header phi first sees only the preheader value, so the branch on
    /// it looks constant; the back edge then widens the phi and the exit edge
    /// has to become executable.
    #[test]
    fn branch_on_phi_widened_by_back_edge_reaches_exit() {
        // 0: v0 = true            -> 1
        // 1: v1 = phi(0:v0, 2:v3); v2 = copy v1; if v2 -> 2 else 3
        // 2: v3 = false           -> 1
        // 3: return
        let blocks = vec![
            blk(
                0,
                vec![],
                vec![konst(0, "true")],
                Terminator::Goto(BlockId(1)),
                &[],
                &[1],
            ),
            blk(
                1,
                vec![phi_of(1, &[(0, 0), (2, 3)])],
                vec![copy_of(2, 1)],
                branch(2, 2, 3),
                &[0, 2],
                &[2, 3],
            ),
            blk(
                2,
                vec![],
                vec![konst(3, "false")],
                Terminator::Goto(BlockId(1)),
                &[1],
                &[1],
            ),
            blk(3, vec![], vec![], Terminator::Return(None), &[1], &[]),
        ];
        let body = make_body(blocks, defs(&[0, 1, 1, 2]));
        let result = const_propagate(&body);
        assert_eq!(
            result.values.get(&SsaValue(1)),
            Some(&ConstLattice::Varying)
        );
        assert_eq!(
            result.values.get(&SsaValue(2)),
            Some(&ConstLattice::Varying)
        );
        assert!(
            result.unreachable_blocks.is_empty(),
            "the exit must be reachable once the phi widens: {:?}",
            result.unreachable_blocks
        );
        assert_matches_reference(&body, "loop header phi widened by the back edge");
    }

    /// A value read twice by one call and again by an instruction of a later
    /// block and a phi: every reader must see the final lattice value.
    #[test]
    fn value_used_by_several_instructions_blocks_and_phis() {
        // 0: v0 = "1"; v1 = call(v0, v0); v2 = copy v0; v3 = assign(v0, v2); if v2 -> 1 else 2
        // 1: v4 = copy v0 -> 3
        // 2: v5 = "1"     -> 3
        // 3: v6 = phi(1:v4, 2:v5); v7 = copy v6
        let blocks = vec![
            blk(
                0,
                vec![],
                vec![
                    konst(0, "1"),
                    inst(
                        1,
                        SsaOp::Call {
                            callee: "f".into(),
                            callee_text: None,
                            args: vec![
                                SmallVec::from_elem(SsaValue(0), 1),
                                SmallVec::from_elem(SsaValue(0), 1),
                            ],
                            receiver: None,
                        },
                    ),
                    copy_of(2, 0),
                    inst(
                        3,
                        SsaOp::Assign(SmallVec::from_slice(&[SsaValue(0), SsaValue(2)])),
                    ),
                ],
                branch(2, 1, 2),
                &[],
                &[1, 2],
            ),
            blk(
                1,
                vec![],
                vec![copy_of(4, 0)],
                Terminator::Goto(BlockId(3)),
                &[0],
                &[3],
            ),
            blk(
                2,
                vec![],
                vec![konst(5, "1")],
                Terminator::Goto(BlockId(3)),
                &[0],
                &[3],
            ),
            blk(
                3,
                vec![phi_of(6, &[(1, 4), (2, 5)])],
                vec![copy_of(7, 6)],
                Terminator::Return(None),
                &[1, 2],
                &[],
            ),
        ];
        let body = make_body(blocks, defs(&[0, 0, 0, 0, 1, 2, 3, 3]));
        let result = const_propagate(&body);
        assert_eq!(result.values.get(&SsaValue(6)), Some(&ConstLattice::Int(1)));
        assert_eq!(result.values.get(&SsaValue(7)), Some(&ConstLattice::Int(1)));
        assert_eq!(
            result.values.get(&SsaValue(3)),
            Some(&ConstLattice::Varying)
        );
        assert_matches_reference(&body, "multi-use value");
    }

    /// One long straight-line block of copies chained off a constant, then a
    /// widening phi after it; checks the per-instruction use lists on a body
    /// where the old whole-block rescan was quadratic.
    #[test]
    fn long_straight_line_block_matches_reference() {
        let n = 3000u32;
        let mut body_insts = vec![konst(0, "3")];
        for i in 1..n {
            body_insts.push(copy_of(i, i - 1));
        }
        let blocks = vec![blk(
            0,
            vec![],
            body_insts,
            Terminator::Return(None),
            &[],
            &[],
        )];
        let owner = vec![0u32; n as usize];
        let body = make_body(blocks, defs(&owner));
        let result = const_propagate(&body);
        assert_eq!(
            result.values.get(&SsaValue(n - 1)),
            Some(&ConstLattice::Int(3))
        );
        assert_matches_reference(&body, "long straight-line block");
    }

    /// Builds bodies from real source files in the benchmark corpus and checks
    /// the production SCCP against the oracle on every function body.
    #[test]
    fn corpus_bodies_match_reference() {
        use crate::utils::config::Config;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/benchmark/corpus");
        let mut files = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        files.sort();
        let cfg = Config::default();
        let mut bodies = 0usize;
        let mut folded = 0usize;
        for path in files {
            let Ok(Some((file_cfg, _lang))) = crate::ast::build_cfg_for_file(&path, &cfg) else {
                continue;
            };
            for b in &file_cfg.bodies {
                let scope = b.meta.name.as_deref();
                let Ok(ssa) = crate::ssa::lower_to_ssa(&b.graph, b.entry, scope, scope.is_none())
                else {
                    continue;
                };
                assert_matches_reference(&ssa, &path.display().to_string());
                bodies += 1;
                let r = const_propagate(&ssa);
                if !r.unreachable_blocks.is_empty() {
                    folded += 1;
                }
            }
        }
        assert!(
            bodies > 200,
            "expected a real corpus, lowered {bodies} bodies"
        );
        eprintln!(
            "[const_prop] {bodies} corpus bodies matched the reference ({folded} with pruned blocks)"
        );
    }
}

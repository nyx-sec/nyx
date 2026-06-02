//! Formal points-to / heap analysis for SSA-based taint propagation.
//!
//! Provides bounded intra-procedural points-to analysis: each container
//! allocation creates an abstract `HeapObjectId`, assignments and phi nodes
//! propagate points-to sets, and the taint engine uses heap state to track
//! taint through container store/load operations with proper aliasing.
//!
//! Key design:
//! - HeapObjectId is keyed by allocation-site SsaValue (deterministic, zero-cost)
//! - PointsToSet is bounded to `analysis.engine.max_pointsto` entries
//!   (default 32, widening on overflow, see [`effective_max_pointsto`]).
//!   Overflow drops emit an [`crate::engine_notes::EngineNote::PointsToTruncated`]
//!   note and increment `POINTSTO_TRUNCATION_COUNT` so operators can
//!   tell when the cap is firing on their corpus.
//! - HeapState tracks per-(heap-object, slot) taint (monotone lattice)
//!   - HeapSlot::Index(u64) for constant-index container access (proven by const propagation)
//!   - HeapSlot::Elements for coarse element access (push/pop, dynamic index, overflow)
//!   - Intraprocedural: constant-index sensitivity is guaranteed when const propagation proves it
//!   - Interprocedural: best-effort, relies on correct const_values threading (already handled)
//!   - Unknown/unproven indices fall back to Elements (conservative)
//! - Analysis runs as a pre-pass in optimize_ssa(), like type_facts

#![allow(clippy::unnecessary_map_or)]

use crate::cfg::Cfg;
use crate::labels::{Cap, bare_method_name};
use crate::ssa::ir::*;
use crate::ssa::pointsto::{ContainerOp, classify_container_op};
use crate::symbol::Lang;
use crate::taint::domain::TaintOrigin;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

// Heap origin cap used to be `const MAX_HEAP_ORIGINS: usize = 4`, now
// governed by the shared `analysis.engine.max_origins` knob through
// `crate::taint::ssa_transfer::push_origin_bounded`.  Unifying the two
// lattices behind a single tunable means operators raise *one* value to
// eliminate silent truncation everywhere.

/// Test-only override for the points-to cap.  `cap = 0` restores the
/// runtime-configured default (see [`effective_max_pointsto`]).  Used to
/// force `PointsToTruncated` emission on small fixtures.
static MAX_POINTSTO_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Total heap-object members dropped by [`PointsToSet`] truncation since
/// the last reset.  Captured from `insert`/`union` so tests (and
/// operators inspecting scan output) can detect truncation events that
/// don't propagate to a finding, e.g. when the cap is tight enough
/// that no taint flow survives to emit a sink event.
pub(crate) static POINTSTO_TRUNCATION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Test-only hook: pin the effective `max_pointsto` cap.  `cap = 0`
/// clears the override.
#[doc(hidden)]
pub fn set_max_pointsto_override(cap: usize) {
    MAX_POINTSTO_OVERRIDE.store(cap, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the live points-to cap.
///
/// Precedence (highest first):
/// 1. The test-only `MAX_POINTSTO_OVERRIDE` atomic
///    ([`set_max_pointsto_override`]).
/// 2. The runtime `analysis.engine.max_pointsto` option, which itself
///    resolves through the installed runtime → `NYX_MAX_POINTSTO` →
///    [`crate::utils::analysis_options::DEFAULT_MAX_POINTSTO`].
///
/// The runtime path clamps to
/// [`crate::utils::analysis_options::MIN_MAX_POINTSTO`] on ingest, so the
/// engine always carries at least one heap-object slot.
pub fn effective_max_pointsto() -> usize {
    let o = MAX_POINTSTO_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o != 0 {
        return o;
    }
    crate::utils::analysis_options::current().max_pointsto as usize
}

/// Observability: total heap-object members dropped by the points-to
/// analysis since the most recent [`reset_points_to_observability`]
/// call.  Monotone-increasing; `0` when no truncation happened.
pub fn points_to_truncation_count() -> usize {
    POINTSTO_TRUNCATION_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reset the points-to truncation counter.  Intended for tests.
pub fn reset_points_to_observability() {
    POINTSTO_TRUNCATION_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Record `dropped` truncated heap-object members on the counter and on
/// the active body's engine-note collector.  Called from the two
/// [`PointsToSet`] cap sites (insert/union).
fn record_pointsto_truncation(dropped: usize) {
    if dropped == 0 {
        return;
    }
    POINTSTO_TRUNCATION_COUNT.fetch_add(dropped, std::sync::atomic::Ordering::Relaxed);
    crate::taint::ssa_transfer::record_engine_note(
        crate::engine_notes::EngineNote::PointsToTruncated {
            dropped: dropped as u32,
        },
    );
}

/// Maximum distinct `Index(n)` slots tracked per heap object.
/// When exceeded, all indexed entries for that object collapse into `Elements`.
pub const MAX_TRACKED_INDICES: usize = 8;

// ── HeapSlot ────────────────────────────────────────────────────────────

/// Distinguishes constant-index container access from coarse element access.
///
/// `Elements` is the conservative default, all container elements merge into
/// a single taint.  `Index(n)` provides per-index precision when the index is
/// provably a non-negative integer constant (via the function's own const
/// propagation pass).
///
/// Ordering: `Elements < Index(0) < Index(1) < … < Key(h0) < Key(h1) < …` so
/// that sorted merge-join in `HeapState` groups all slots for the same
/// `HeapObjectId` together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapSlot {
    /// Coarse union of all elements (push/pop, dynamic index, overflow).
    Elements,
    /// Constant-index slot, proven by the current function's const propagation.
    Index(u64),
    /// Constant **string-key** slot, proven by const propagation (`map.put("k",
    /// v)` / `map.get("k")` with a literal `"k"`).  The `u64` is a stable hash
    /// of the key string ([`hash_const_key`]).  Distinct from `Index(n)` so an
    /// integer index and a string key that happen to share a numeric value
    /// never alias.  A hash collision between two distinct string keys merely
    /// reverts to the pre-existing coarse merge for those two keys (sound, no
    /// new false negative).
    Key(u64),
}

/// Stable FNV-1a hash of a constant string key.  Deterministic across runs
/// (no `RandomState`), so a `put("k", …)` and a later `get("k")` resolve to
/// the same [`HeapSlot::Key`] within and across analysis passes.
pub fn hash_const_key(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl HeapSlot {
    /// Whether this is a precise per-key/per-index slot (as opposed to the
    /// coarse `Elements` slot).  Keyed slots share the `MAX_TRACKED_INDICES`
    /// budget and the overflow-collapse-to-`Elements` policy.
    #[inline]
    fn is_keyed(self) -> bool {
        matches!(self, HeapSlot::Index(_) | HeapSlot::Key(_))
    }
}

// ── HeapObjectId ─────────────────────────────────────────────────────────

/// Abstract heap object identity, keyed by the SSA value of the allocation site.
///
/// When `items = []` creates SsaValue(5), the heap object is HeapObjectId(SsaValue(5)).
/// SSA guarantees each definition is unique, so heap identity is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HeapObjectId(pub SsaValue);

// ── PointsToSet ──────────────────────────────────────────────────────────

/// Bounded set of heap objects that an SSA value may reference.
///
/// Stored as a sorted, deduped SmallVec for O(n) merge-join, matching the
/// pattern used by SsaTaintState.values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointsToSet {
    ids: SmallVec<[HeapObjectId; 4]>,
}

impl PointsToSet {
    /// Empty points-to set.
    pub fn empty() -> Self {
        Self {
            ids: SmallVec::new(),
        }
    }

    /// Points-to set containing a single heap object.
    pub fn singleton(id: HeapObjectId) -> Self {
        let mut ids = SmallVec::new();
        ids.push(id);
        Self { ids }
    }

    /// Bounded union of two points-to sets.
    ///
    /// Truncates to [`effective_max_pointsto`]; any heap-object member
    /// that would be admitted after the cap is reached is dropped and
    /// counted via `record_pointsto_truncation`.  Truncation is
    /// deterministic: the merge proceeds in sorted order, so survivors
    /// are always the smallest `HeapObjectId`s across the two inputs.
    pub fn union(&self, other: &Self) -> Self {
        let cap = effective_max_pointsto();
        let mut result: SmallVec<[HeapObjectId; 4]> = SmallVec::new();
        let mut dropped = 0usize;
        let (mut i, mut j) = (0, 0);
        while i < self.ids.len() && j < other.ids.len() {
            match self.ids[i].cmp(&other.ids[j]) {
                std::cmp::Ordering::Less => {
                    if result.len() < cap {
                        result.push(self.ids[i]);
                    } else {
                        dropped += 1;
                    }
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    if result.len() < cap {
                        result.push(other.ids[j]);
                    } else {
                        dropped += 1;
                    }
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    if result.len() < cap {
                        result.push(self.ids[i]);
                    } else {
                        // The same id is in both sides; count as a single drop.
                        dropped += 1;
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        while i < self.ids.len() {
            if result.len() < cap {
                result.push(self.ids[i]);
            } else {
                dropped += 1;
            }
            i += 1;
        }
        while j < other.ids.len() {
            if result.len() < cap {
                result.push(other.ids[j]);
            } else {
                dropped += 1;
            }
            j += 1;
        }
        record_pointsto_truncation(dropped);
        Self { ids: result }
    }

    /// Insert a single HeapObjectId, maintaining sorted order and bound.
    ///
    /// When the set is already at [`effective_max_pointsto`], the new id
    /// is dropped and the drop is counted via
    /// `record_pointsto_truncation`.
    pub fn insert(&mut self, id: HeapObjectId) {
        match self.ids.binary_search(&id) {
            Ok(_) => {} // already present
            Err(pos) => {
                if self.ids.len() < effective_max_pointsto() {
                    self.ids.insert(pos, id);
                } else {
                    record_pointsto_truncation(1);
                }
            }
        }
    }

    pub fn contains(&self, id: HeapObjectId) -> bool {
        self.ids.binary_search(&id).is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &HeapObjectId> {
        self.ids.iter()
    }
}

// ── HeapTaint ────────────────────────────────────────────────────────────

/// Taint stored inside an abstract heap object (container contents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeapTaint {
    pub caps: Cap,
    pub origins: SmallVec<[TaintOrigin; 2]>,
}

impl HeapTaint {
    /// Monotone merge: OR caps, union origins (bounded, deterministic).
    ///
    /// Delegates to
    /// [`crate::taint::ssa_transfer::push_origin_bounded`] so the heap
    /// and SSA taint lattices share one origin cap
    /// (`analysis.engine.max_origins`) and one truncation-notification
    /// path.
    fn merge(&mut self, caps: Cap, origins: &[TaintOrigin]) {
        self.caps |= caps;
        for orig in origins {
            crate::taint::ssa_transfer::push_origin_bounded(&mut self.origins, *orig);
        }
    }

    /// Union two HeapTaint values (for load_set).
    fn union(&self, other: &HeapTaint) -> HeapTaint {
        let mut result = self.clone();
        result.merge(other.caps, &other.origins);
        result
    }
}

// ── HeapState ────────────────────────────────────────────────────────────

/// Per-(heap-object, slot) taint state: abstract contents of all tracked
/// containers with optional per-index precision.
///
/// Sorted by `(HeapObjectId, HeapSlot)` for O(n) merge-join (lattice join =
/// union of per-slot taint), matching the `SsaTaintState` pattern.
///
/// Load semantics:
/// - `load(id, Index(n))`: union of `(id, Index(n))` and `(id, Elements)` ,
///   indexed reads also see taint from dynamic/push operations.
/// - `load(id, Elements)`: union of `(id, Elements)` and ALL `(id, Index(*))`
///   entries, dynamic reads conservatively see all indexed taint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeapState {
    entries: SmallVec<[((HeapObjectId, HeapSlot), HeapTaint); 4]>,
}

impl HeapState {
    pub fn empty() -> Self {
        Self {
            entries: SmallVec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Store taint into a specific (object, slot) pair (monotone merge).
    ///
    /// If storing to `Index(n)` would exceed `MAX_TRACKED_INDICES` distinct
    /// indices for this object, all `Index(*)` entries for the object are
    /// collapsed into `Elements` and the new taint is merged there instead.
    pub fn store(&mut self, id: HeapObjectId, slot: HeapSlot, caps: Cap, origins: &[TaintOrigin]) {
        if caps.is_empty() {
            return;
        }

        // Keyed-slot overflow: when a container already tracks the maximum
        // number of distinct keyed (`Index`/`Key`) slots, a *new* key is
        // folded into the coarse `Elements` slot instead of creating another
        // keyed cell.  Existing keyed cells are **kept** — they are never
        // removed.  This keeps the lattice monotone: the old collapse-to-
        // Elements behaviour *removed* keyed cells, so a `join` that
        // re-introduced distinct keys followed by a `store` that re-collapsed
        // them made the per-block state oscillate forever and the taint
        // worklist never converged (it bailed at the 100k-iteration safety
        // cap, silently dropping that function's findings).  Keyed slots only
        // ever arise from bounded sources (integer indices `0..MAX_TRACKED_
        // INDICES` and the finite set of constant string keys in the source;
        // dynamic keys already resolve to `Elements`), so refusing to grow
        // past the cap bounds the state without any removal.
        if slot.is_keyed() {
            let key = (id, slot);
            let already_present = self.entries.binary_search_by_key(&key, |(k, _)| *k).is_ok();
            if !already_present && self.count_indices_for(id) >= MAX_TRACKED_INDICES {
                self.store_raw(id, HeapSlot::Elements, caps, origins);
                return;
            }
        }

        self.store_raw(id, slot, caps, origins);
    }

    /// Raw store without overflow checking.
    fn store_raw(&mut self, id: HeapObjectId, slot: HeapSlot, caps: Cap, origins: &[TaintOrigin]) {
        let key = (id, slot);
        match self.entries.binary_search_by_key(&key, |(k, _)| *k) {
            Ok(idx) => {
                self.entries[idx].1.merge(caps, origins);
            }
            Err(idx) => {
                let mut o: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                for orig in origins {
                    crate::taint::ssa_transfer::push_origin_bounded(&mut o, *orig);
                }
                self.entries
                    .insert(idx, (key, HeapTaint { caps, origins: o }));
            }
        }
    }

    /// Store taint into all heap objects in a points-to set.
    pub fn store_set(
        &mut self,
        pts: &PointsToSet,
        slot: HeapSlot,
        caps: Cap,
        origins: &[TaintOrigin],
    ) {
        for &id in pts.iter() {
            self.store(id, slot, caps, origins);
        }
    }

    /// Load taint from a specific (object, slot) pair.
    ///
    /// - `Index(n)`: returns union of `(id, Index(n))` ∪ `(id, Elements)`.
    /// - `Key(h)`: returns union of `(id, Key(h))` ∪ `(id, Elements)` — a
    ///   constant-key read sees only its own key's taint plus any taint
    ///   written under a dynamic/unknown key (which lands in `Elements`); it
    ///   does NOT see other constant keys' cells.
    /// - `Elements`: returns union of `(id, Elements)` ∪ all keyed slots
    ///   (`Index(*)` and `Key(*)`) — a dynamic/unknown-key read conservatively
    ///   sees every recorded keyed write.
    pub fn load(&self, id: HeapObjectId, slot: HeapSlot) -> Option<HeapTaint> {
        match slot {
            HeapSlot::Index(_) | HeapSlot::Key(_) => {
                // Union the specific keyed slot with Elements.
                let slot_taint = self.load_raw(id, slot);
                let elem_taint = self.load_raw(id, HeapSlot::Elements);
                match (slot_taint, elem_taint) {
                    (Some(a), Some(b)) => Some(a.union(b)),
                    (Some(a), None) => Some(a.clone()),
                    (None, Some(b)) => Some(b.clone()),
                    (None, None) => None,
                }
            }
            HeapSlot::Elements => {
                // Union Elements with ALL Index(*) entries for this object.
                let mut result: Option<HeapTaint> = None;
                for ((eid, _slot), taint) in &self.entries {
                    if *eid == id {
                        result = Some(match result {
                            Some(r) => r.union(taint),
                            None => taint.clone(),
                        });
                    }
                }
                result
            }
        }
    }

    /// Direct lookup of a single (id, slot) entry without cross-slot unioning.
    fn load_raw(&self, id: HeapObjectId, slot: HeapSlot) -> Option<&HeapTaint> {
        let key = (id, slot);
        self.entries
            .binary_search_by_key(&key, |(k, _)| *k)
            .ok()
            .map(|idx| &self.entries[idx].1)
    }

    /// Load and union taint from all heap objects in a points-to set.
    pub fn load_set(&self, pts: &PointsToSet, slot: HeapSlot) -> Option<HeapTaint> {
        let mut result: Option<HeapTaint> = None;
        for &id in pts.iter() {
            if let Some(ht) = self.load(id, slot) {
                result = Some(match result {
                    Some(r) => r.union(&ht),
                    None => ht,
                });
            }
        }
        result
    }

    /// Lattice join: merge-join by (HeapObjectId, HeapSlot), union per-slot taint.
    pub fn join(&self, other: &Self) -> Self {
        let mut result = SmallVec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.entries.len() && j < other.entries.len() {
            let (ka, ta) = &self.entries[i];
            let (kb, tb) = &other.entries[j];
            match ka.cmp(kb) {
                std::cmp::Ordering::Less => {
                    result.push((*ka, ta.clone()));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    result.push((*kb, tb.clone()));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    result.push((*ka, ta.union(tb)));
                    i += 1;
                    j += 1;
                }
            }
        }
        while i < self.entries.len() {
            result.push(self.entries[i].clone());
            i += 1;
        }
        while j < other.entries.len() {
            result.push(other.entries[j].clone());
            j += 1;
        }
        Self { entries: result }
    }

    /// Lattice ordering: every entry in self must be present in other with subset caps.
    pub fn leq(&self, other: &Self) -> bool {
        let mut j = 0;
        for (ka, ta) in &self.entries {
            loop {
                if j >= other.entries.len() {
                    return false;
                }
                let (kb, _) = &other.entries[j];
                match ka.cmp(kb) {
                    std::cmp::Ordering::Equal => break,
                    std::cmp::Ordering::Greater => j += 1,
                    std::cmp::Ordering::Less => return false,
                }
            }
            let (_, tb) = &other.entries[j];
            if (ta.caps & !tb.caps) != Cap::empty() {
                return false;
            }
            j += 1;
        }
        true
    }

    /// Count distinct keyed (`Index(*)` / `Key(*)`) slots for a given object.
    fn count_indices_for(&self, id: HeapObjectId) -> usize {
        self.entries
            .iter()
            .filter(|((eid, slot), _)| *eid == id && slot.is_keyed())
            .count()
    }
}

// ── PointsToResult ───────────────────────────────────────────────────────

/// Result of intra-procedural points-to analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointsToResult {
    pts: HashMap<SsaValue, PointsToSet>,
}

impl PointsToResult {
    pub fn empty() -> Self {
        Self {
            pts: HashMap::new(),
        }
    }

    /// Look up the points-to set for an SSA value.
    pub fn get(&self, v: SsaValue) -> Option<&PointsToSet> {
        self.pts.get(&v)
    }

    pub fn is_empty(&self) -> bool {
        self.pts.is_empty()
    }
}

// ── Allocation site detection ────────────────────────────────────────────

/// Public re-export wrapper for container-literal detection.
///
/// Called from [`crate::ssa::param_points_to`] to decide whether a return
/// path traces to a fresh allocation.  Keeps the internal helper private
/// while exposing the classification via a stable name.
pub fn is_container_literal_public(text: &str) -> bool {
    is_container_literal(text)
}

/// Check if a const literal text represents a container/collection literal.
fn is_container_literal(text: &str) -> bool {
    let t = text.trim();
    // Empty or non-empty array/list literals
    if t.starts_with('[') && t.ends_with(']') {
        return true;
    }
    // Empty or non-empty object/dict/map/set literals
    if t.starts_with('{') && t.ends_with('}') {
        return true;
    }
    // `new Array(...)`, `new Map(...)`, etc.
    if t.starts_with("new ") {
        return true;
    }
    // Python dict()/list()/set() as literals
    if t == "dict()" || t == "list()" || t == "set()" {
        return true;
    }
    false
}

/// Check if a callee creates a new container (constructor/factory).
pub fn is_container_constructor(callee: &str, lang: Lang) -> bool {
    // Extract last segment after '.' or '::' (whichever comes last)
    let after_dot = bare_method_name(callee);
    let suffix = after_dot.rsplit("::").next().unwrap_or(after_dot);
    let suffix_lower = suffix.to_ascii_lowercase();

    match lang {
        Lang::JavaScript | Lang::TypeScript => {
            matches!(suffix, "Array" | "Map" | "Set" | "WeakMap" | "WeakSet")
        }
        Lang::Python => matches!(
            suffix,
            "list"
                | "dict"
                | "set"
                | "frozenset"
                | "defaultdict"
                | "OrderedDict"
                | "deque"
                | "Counter"
        ),
        Lang::Java => matches!(
            suffix,
            "ArrayList"
                | "LinkedList"
                | "HashMap"
                | "TreeMap"
                | "HashSet"
                | "TreeSet"
                | "Vector"
                | "Stack"
                | "ArrayDeque"
                | "PriorityQueue"
                | "ConcurrentHashMap"
                | "LinkedHashMap"
                | "LinkedHashSet"
                | "CopyOnWriteArrayList"
        ),
        Lang::Go => callee == "make",
        Lang::Ruby => {
            matches!(suffix, "new") && {
                // Only for known container types
                let prefix = callee.rsplit('.').nth(1).unwrap_or("");
                matches!(prefix, "Array" | "Hash" | "Set")
            }
        }
        Lang::Php => matches!(suffix, "array"),
        Lang::C | Lang::Cpp => matches!(
            suffix_lower.as_str(),
            "vector"
                | "map"
                | "set"
                | "unordered_map"
                | "unordered_set"
                | "list"
                | "deque"
                | "queue"
                | "stack"
                | "multimap"
                | "multiset"
                | "priority_queue"
        ),
        Lang::Rust => {
            // Vec::new, HashMap::new, etc.
            suffix == "new" && callee.contains("::") && {
                let type_part = callee.rsplit("::").nth(1).unwrap_or("");
                matches!(
                    type_part,
                    "Vec"
                        | "HashMap"
                        | "HashSet"
                        | "BTreeMap"
                        | "BTreeSet"
                        | "VecDeque"
                        | "LinkedList"
                        | "BinaryHeap"
                )
            }
        }
    }
}

// ── Points-to analysis ───────────────────────────────────────────────────

/// Run intra-procedural points-to analysis on an SSA body.
///
/// Identifies allocation sites, propagates points-to sets through assignments
/// and phi nodes, and returns a result that the taint engine can query.
///
/// Runs as a pre-pass in optimize_ssa(), after type_facts.
pub fn analyze_points_to(body: &SsaBody, _cfg: &Cfg, lang: Option<Lang>) -> PointsToResult {
    let mut pts: HashMap<SsaValue, PointsToSet> = HashMap::new();

    // Pass 1: identify allocation sites and seed points-to sets
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                SsaOp::Const(Some(text)) if is_container_literal(text) => {
                    pts.insert(inst.value, PointsToSet::singleton(HeapObjectId(inst.value)));
                }
                SsaOp::Call { callee, .. } => {
                    if let Some(l) = lang {
                        if is_container_constructor(callee, l) {
                            pts.insert(
                                inst.value,
                                PointsToSet::singleton(HeapObjectId(inst.value)),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if pts.is_empty() {
        return PointsToResult::empty();
    }

    // Pass 2: forward propagation with fixed-point for phis (max 10 rounds)
    let max_rounds = 10;
    for _ in 0..max_rounds {
        let mut changed = false;
        for block in &body.blocks {
            // Process phis
            for inst in &block.phis {
                if let SsaOp::Phi(operands) = &inst.op {
                    let mut merged = PointsToSet::empty();
                    for (_, v) in operands {
                        if let Some(p) = pts.get(v) {
                            merged = merged.union(p);
                        }
                    }
                    if !merged.is_empty() {
                        let old = pts.get(&inst.value);
                        if old.map_or(true, |o| o != &merged) {
                            let existing = pts.entry(inst.value).or_insert_with(PointsToSet::empty);
                            let new = existing.union(&merged);
                            if &new != existing {
                                *existing = new;
                                changed = true;
                            }
                        }
                    }
                }
            }
            // Process body
            for inst in &block.body {
                match &inst.op {
                    SsaOp::Assign(uses) => {
                        let mut merged = PointsToSet::empty();
                        for &u in uses {
                            if let Some(p) = pts.get(&u) {
                                merged = merged.union(p);
                            }
                        }
                        if !merged.is_empty() {
                            let old = pts.get(&inst.value);
                            if old.map_or(true, |o| o != &merged) {
                                pts.insert(inst.value, merged);
                                changed = true;
                            }
                        }
                    }
                    SsaOp::Call {
                        callee,
                        args,
                        receiver,
                        ..
                    } => {
                        // For container Store ops that return the container (Go append),
                        // propagate receiver pts to result.
                        if let Some(l) = lang {
                            if let Some(ContainerOp::Store { .. }) =
                                classify_container_op(callee, l)
                            {
                                // Find receiver pts
                                let recv_pts =
                                    receiver.and_then(|rv| pts.get(&rv).cloned()).or_else(|| {
                                        // Go append: arg 0 is the slice
                                        if l == Lang::Go {
                                            args.first()
                                                .and_then(|a| a.first())
                                                .and_then(|&v| pts.get(&v).cloned())
                                        } else {
                                            // JS-style: find receiver from dotted callee
                                            let dot_pos = callee.rfind('.')?;
                                            let recv_name = &callee[..dot_pos];
                                            for arg_group in args {
                                                for &v in arg_group {
                                                    if let Some(def) =
                                                        body.value_defs.get(v.0 as usize)
                                                    {
                                                        if def.var_name.as_deref()
                                                            == Some(recv_name)
                                                        {
                                                            return pts.get(&v).cloned();
                                                        }
                                                    }
                                                }
                                            }
                                            None
                                        }
                                    });
                                // For Go append, result gets receiver pts
                                if l == Lang::Go && receiver.is_none() {
                                    if let Some(rp) = recv_pts {
                                        let old = pts.get(&inst.value);
                                        if old.map_or(true, |o| o != &rp) {
                                            pts.insert(inst.value, rp);
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }

    PointsToResult { pts }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::SourceKind;
    use petgraph::graph::NodeIndex;
    use std::sync::Mutex;

    /// Serializes tests that touch [`MAX_POINTSTO_OVERRIDE`] or
    /// [`POINTSTO_TRUNCATION_COUNT`].  Both are process-wide atomics, so
    /// parallel tests would otherwise race on the counter and the
    /// override.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn origin(idx: u32) -> TaintOrigin {
        TaintOrigin {
            node: NodeIndex::new(idx as usize),
            source_kind: SourceKind::UserInput,
            source_span: None,
        }
    }

    // ── PointsToSet tests ────────────────────────────────────────────

    #[test]
    fn pts_singleton() {
        let s = PointsToSet::singleton(HeapObjectId(SsaValue(0)));
        assert_eq!(s.len(), 1);
        assert!(s.contains(HeapObjectId(SsaValue(0))));
        assert!(!s.contains(HeapObjectId(SsaValue(1))));
    }

    #[test]
    fn pts_union() {
        let a = PointsToSet::singleton(HeapObjectId(SsaValue(1)));
        let b = PointsToSet::singleton(HeapObjectId(SsaValue(3)));
        let c = a.union(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(HeapObjectId(SsaValue(1))));
        assert!(c.contains(HeapObjectId(SsaValue(3))));
    }

    #[test]
    fn pts_union_dedup() {
        let a = PointsToSet::singleton(HeapObjectId(SsaValue(1)));
        let b = PointsToSet::singleton(HeapObjectId(SsaValue(1)));
        let c = a.union(&b);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn pts_union_overflow() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // Tight override so the test runs deterministically against the
        // configured default.
        set_max_pointsto_override(8);
        reset_points_to_observability();

        // Build a set with `cap` entries.
        let cap = effective_max_pointsto();
        let mut big = PointsToSet::empty();
        for i in 0..cap as u32 {
            big.insert(HeapObjectId(SsaValue(i)));
        }
        assert_eq!(big.len(), cap);

        // Union with one more should not grow, and should count the drop.
        let extra = PointsToSet::singleton(HeapObjectId(SsaValue(100)));
        let result = big.union(&extra);
        assert_eq!(result.len(), cap);
        assert_eq!(points_to_truncation_count(), 1);

        set_max_pointsto_override(0);
        reset_points_to_observability();
    }

    #[test]
    fn pts_insert_overflow_counts_drops() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_pointsto_override(4);
        reset_points_to_observability();

        let mut s = PointsToSet::empty();
        // First 4 fit.
        for i in 0..4u32 {
            s.insert(HeapObjectId(SsaValue(i)));
        }
        assert_eq!(s.len(), 4);
        assert_eq!(points_to_truncation_count(), 0);

        // Next 3 are dropped; counter records each drop.
        for i in 4..7u32 {
            s.insert(HeapObjectId(SsaValue(i)));
        }
        assert_eq!(s.len(), 4);
        assert_eq!(points_to_truncation_count(), 3);

        // Duplicates of existing entries are *not* drops.
        s.insert(HeapObjectId(SsaValue(0)));
        assert_eq!(points_to_truncation_count(), 3);

        set_max_pointsto_override(0);
        reset_points_to_observability();
    }

    #[test]
    fn pts_union_overflow_counts_exact_drops() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_pointsto_override(4);
        reset_points_to_observability();

        // a = {0,1,2,3}, b = {4,5,6}, union wants 7 members; cap is 4
        // so 3 members are dropped.  Deterministic order: smallest
        // ids survive.
        let mut a = PointsToSet::empty();
        for i in 0..4u32 {
            a.insert(HeapObjectId(SsaValue(i)));
        }
        let mut b = PointsToSet::empty();
        for i in 4..7u32 {
            b.insert(HeapObjectId(SsaValue(i)));
        }
        // Sanity: the pre-union sets should not themselves have triggered
        // truncation (both are ≤ cap).
        assert_eq!(points_to_truncation_count(), 0);

        let c = a.union(&b);
        assert_eq!(c.len(), 4);
        assert!(c.contains(HeapObjectId(SsaValue(0))));
        assert!(c.contains(HeapObjectId(SsaValue(3))));
        assert!(!c.contains(HeapObjectId(SsaValue(6))));
        assert_eq!(points_to_truncation_count(), 3);

        set_max_pointsto_override(0);
        reset_points_to_observability();
    }

    #[test]
    fn pts_reset_observability_clears_counter() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_pointsto_override(2);
        reset_points_to_observability();

        let mut s = PointsToSet::empty();
        s.insert(HeapObjectId(SsaValue(0)));
        s.insert(HeapObjectId(SsaValue(1)));
        s.insert(HeapObjectId(SsaValue(2))); // dropped
        assert_eq!(points_to_truncation_count(), 1);

        reset_points_to_observability();
        assert_eq!(points_to_truncation_count(), 0);

        set_max_pointsto_override(0);
    }

    #[test]
    fn pts_effective_cap_defaults_to_runtime() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // With no override, the cap comes from the installed runtime
        // (which defaults to `DEFAULT_MAX_POINTSTO` in tests).
        set_max_pointsto_override(0);
        assert_eq!(
            effective_max_pointsto(),
            crate::utils::analysis_options::DEFAULT_MAX_POINTSTO as usize
        );
        set_max_pointsto_override(5);
        assert_eq!(effective_max_pointsto(), 5);
        set_max_pointsto_override(0);
    }

    #[test]
    fn pts_empty() {
        let e = PointsToSet::empty();
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
    }

    #[test]
    fn pts_insert() {
        let mut s = PointsToSet::empty();
        s.insert(HeapObjectId(SsaValue(5)));
        s.insert(HeapObjectId(SsaValue(2)));
        s.insert(HeapObjectId(SsaValue(5))); // dup
        assert_eq!(s.len(), 2);
        // Sorted order
        let ids: Vec<_> = s.iter().collect();
        assert_eq!(ids[0].0, SsaValue(2));
        assert_eq!(ids[1].0, SsaValue(5));
    }

    // ── HeapState tests ──────────────────────────────────────────────

    #[test]
    fn heap_store_and_load() {
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);

        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE);
        assert_eq!(t.origins.len(), 1);
    }

    #[test]
    fn heap_store_monotone_merge() {
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(id, HeapSlot::Elements, Cap::SQL_QUERY, &[origin(1)]);

        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
        assert_eq!(t.origins.len(), 2);
    }

    #[test]
    fn heap_store_empty_caps_noop() {
        let mut h = HeapState::empty();
        h.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::empty(),
            &[origin(0)],
        );
        assert!(h.is_empty());
    }

    #[test]
    fn heap_load_missing() {
        let h = HeapState::empty();
        assert!(
            h.load(HeapObjectId(SsaValue(0)), HeapSlot::Elements)
                .is_none()
        );
    }

    #[test]
    fn heap_load_set_unions() {
        let mut h = HeapState::empty();
        h.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::HTML_ESCAPE,
            &[origin(0)],
        );
        h.store(
            HeapObjectId(SsaValue(1)),
            HeapSlot::Elements,
            Cap::SQL_QUERY,
            &[origin(1)],
        );

        let mut pts = PointsToSet::empty();
        pts.insert(HeapObjectId(SsaValue(0)));
        pts.insert(HeapObjectId(SsaValue(1)));

        let t = h.load_set(&pts, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
        assert_eq!(t.origins.len(), 2);
    }

    #[test]
    fn heap_load_set_empty_pts() {
        let mut h = HeapState::empty();
        h.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::HTML_ESCAPE,
            &[origin(0)],
        );
        let pts = PointsToSet::empty();
        assert!(h.load_set(&pts, HeapSlot::Elements).is_none());
    }

    #[test]
    fn heap_store_set() {
        let mut h = HeapState::empty();
        let mut pts = PointsToSet::empty();
        pts.insert(HeapObjectId(SsaValue(0)));
        pts.insert(HeapObjectId(SsaValue(1)));

        h.store_set(&pts, HeapSlot::Elements, Cap::HTML_ESCAPE, &[origin(0)]);

        assert_eq!(
            h.load(HeapObjectId(SsaValue(0)), HeapSlot::Elements)
                .unwrap()
                .caps,
            Cap::HTML_ESCAPE
        );
        assert_eq!(
            h.load(HeapObjectId(SsaValue(1)), HeapSlot::Elements)
                .unwrap()
                .caps,
            Cap::HTML_ESCAPE
        );
    }

    #[test]
    fn heap_join() {
        let mut a = HeapState::empty();
        a.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::HTML_ESCAPE,
            &[origin(0)],
        );

        let mut b = HeapState::empty();
        b.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::SQL_QUERY,
            &[origin(1)],
        );
        b.store(
            HeapObjectId(SsaValue(1)),
            HeapSlot::Elements,
            Cap::FILE_IO,
            &[origin(2)],
        );

        let c = a.join(&b);
        let t0 = c
            .load(HeapObjectId(SsaValue(0)), HeapSlot::Elements)
            .unwrap();
        assert_eq!(t0.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
        let t1 = c
            .load(HeapObjectId(SsaValue(1)), HeapSlot::Elements)
            .unwrap();
        assert_eq!(t1.caps, Cap::FILE_IO);
    }

    #[test]
    fn heap_leq() {
        let mut a = HeapState::empty();
        a.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::HTML_ESCAPE,
            &[origin(0)],
        );

        let mut b = HeapState::empty();
        b.store(
            HeapObjectId(SsaValue(0)),
            HeapSlot::Elements,
            Cap::HTML_ESCAPE | Cap::SQL_QUERY,
            &[origin(0)],
        );

        assert!(a.leq(&b)); // a ⊆ b
        assert!(!b.leq(&a)); // b ⊄ a
    }

    #[test]
    fn heap_leq_missing_entry() {
        let mut a = HeapState::empty();
        a.store(
            HeapObjectId(SsaValue(5)),
            HeapSlot::Elements,
            Cap::HTML_ESCAPE,
            &[origin(0)],
        );
        let b = HeapState::empty();
        assert!(!a.leq(&b)); // a has entry, b doesn't
        assert!(b.leq(&a)); // b empty is always ⊆
    }

    // ── HeapSlot indexed tests ──────────────────────────────────────

    #[test]
    fn heap_indexed_store_load_isolation() {
        // Store to Index(0), load from Index(1) → no taint
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::HTML_ESCAPE, &[origin(0)]);

        // Index(0) should have taint
        let t0 = h.load(id, HeapSlot::Index(0)).unwrap();
        assert_eq!(t0.caps, Cap::HTML_ESCAPE);

        // Index(1) should NOT have taint (no Elements, no Index(1) entry)
        assert!(h.load(id, HeapSlot::Index(1)).is_none());
    }

    #[test]
    fn heap_indexed_load_unions_with_elements() {
        // Store to Elements → indexed load should see it
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::SQL_QUERY, &[origin(0)]);

        // Index(1) load should union with Elements
        let t = h.load(id, HeapSlot::Index(1)).unwrap();
        assert_eq!(t.caps, Cap::SQL_QUERY);
    }

    #[test]
    fn heap_elements_load_unions_all_indices() {
        // Store to Index(0) and Index(2), Elements load should see both
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(id, HeapSlot::Index(2), Cap::SQL_QUERY, &[origin(1)]);

        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
    }

    #[test]
    fn heap_indexed_and_elements_combined() {
        // Index(0) = tainted, Elements = tainted with different cap
        // Index(0) load should see both; Index(1) should see only Elements
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::HTML_ESCAPE, &[origin(0)]);
        h.store(id, HeapSlot::Elements, Cap::FILE_IO, &[origin(1)]);

        let t0 = h.load(id, HeapSlot::Index(0)).unwrap();
        assert_eq!(t0.caps, Cap::HTML_ESCAPE | Cap::FILE_IO);

        let t1 = h.load(id, HeapSlot::Index(1)).unwrap();
        assert_eq!(t1.caps, Cap::FILE_IO); // only Elements taint
    }

    #[test]
    fn heap_max_tracked_indices_overflow_to_elements() {
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));

        // Fill MAX_TRACKED_INDICES index slots
        for i in 0..MAX_TRACKED_INDICES as u64 {
            h.store(
                id,
                HeapSlot::Index(i),
                Cap::HTML_ESCAPE,
                &[origin(i as u32)],
            );
        }
        assert_eq!(h.count_indices_for(id), MAX_TRACKED_INDICES);

        // One more (a NEW key past the cap) folds into Elements, but the
        // existing keyed cells are KEPT — the lattice must be monotone (no
        // removal), or the taint worklist oscillates and never converges.
        h.store(
            id,
            HeapSlot::Index(MAX_TRACKED_INDICES as u64),
            Cap::SQL_QUERY,
            &[origin(99)],
        );
        // Existing keyed cells preserved (not collapsed away).
        assert_eq!(h.count_indices_for(id), MAX_TRACKED_INDICES);

        // The overflowed key's taint is now reachable via Elements.
        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert!(t.caps.contains(Cap::HTML_ESCAPE)); // ∪ over kept Index slots
        assert!(t.caps.contains(Cap::SQL_QUERY)); // the overflowed key
        // An existing key still reads its own cell (∪ Elements).
        let t0 = h.load(id, HeapSlot::Index(0)).unwrap();
        assert!(t0.caps.contains(Cap::HTML_ESCAPE));
    }

    // ── HeapSlot::Key (string-key) tests ────────────────────────────

    #[test]
    fn hash_const_key_is_deterministic_and_distinct() {
        // Same key → same hash (so put("k") and get("k") resolve identically).
        assert_eq!(hash_const_key("keyB-85059"), hash_const_key("keyB-85059"));
        // Distinct keys → distinct hashes (the common case).
        assert_ne!(hash_const_key("keyA-85059"), hash_const_key("keyB-85059"));
    }

    #[test]
    fn heap_key_store_load_isolation() {
        // Store under "keyB", load under "keyA" → no taint (the BenchmarkTest00171
        // shape: map.put("keyB", param); map.get("keyA")).
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        let kb = HeapSlot::Key(hash_const_key("keyB-85059"));
        let ka = HeapSlot::Key(hash_const_key("keyA-85059"));
        h.store(id, kb, Cap::SHELL_ESCAPE, &[origin(0)]);

        // Same key sees the taint.
        let t = h.load(id, kb).unwrap();
        assert_eq!(t.caps, Cap::SHELL_ESCAPE);
        // A different constant key does NOT (no Elements, no other Key cell).
        assert!(h.load(id, ka).is_none());
    }

    #[test]
    fn heap_key_load_unions_with_elements() {
        // A dynamic/unknown-key write lands in Elements; a constant-key read
        // still conservatively sees it.
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Elements, Cap::SQL_QUERY, &[origin(0)]);
        let t = h.load(id, HeapSlot::Key(hash_const_key("k"))).unwrap();
        assert_eq!(t.caps, Cap::SQL_QUERY);
    }

    #[test]
    fn heap_elements_load_unions_all_keys() {
        // A dynamic/unknown-key read (Elements slot) sees every constant-key write.
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(
            id,
            HeapSlot::Key(hash_const_key("a")),
            Cap::HTML_ESCAPE,
            &[origin(0)],
        );
        h.store(
            id,
            HeapSlot::Key(hash_const_key("b")),
            Cap::SQL_QUERY,
            &[origin(1)],
        );
        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert_eq!(t.caps, Cap::HTML_ESCAPE | Cap::SQL_QUERY);
    }

    #[test]
    fn heap_key_and_index_are_disjoint() {
        // A string-key slot and an integer-index slot never alias, even if the
        // index value coincides with a key hash bucket.
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        h.store(id, HeapSlot::Index(0), Cap::FILE_IO, &[origin(0)]);
        // A keyed read sees only its own cell (+ Elements, which is empty here),
        // never the Index(0) cell.
        assert!(h.load(id, HeapSlot::Key(hash_const_key("0"))).is_none());
    }

    #[test]
    fn heap_max_tracked_keys_overflow_to_elements() {
        // A NEW string key past the cap folds into Elements (over-approx,
        // sound) while existing keyed cells are kept (monotone — no removal).
        let mut h = HeapState::empty();
        let id = HeapObjectId(SsaValue(0));
        for i in 0..MAX_TRACKED_INDICES {
            h.store(
                id,
                HeapSlot::Key(hash_const_key(&format!("key{i}"))),
                Cap::HTML_ESCAPE,
                &[origin(i as u32)],
            );
        }
        assert_eq!(h.count_indices_for(id), MAX_TRACKED_INDICES);
        h.store(
            id,
            HeapSlot::Key(hash_const_key("overflow")),
            Cap::SQL_QUERY,
            &[origin(99)],
        );
        // Existing keyed cells preserved.
        assert_eq!(h.count_indices_for(id), MAX_TRACKED_INDICES);
        let t = h.load(id, HeapSlot::Elements).unwrap();
        assert!(t.caps.contains(Cap::HTML_ESCAPE));
        assert!(t.caps.contains(Cap::SQL_QUERY));
    }

    // ── is_container_literal tests ───────────────────────────────────

    #[test]
    fn container_literal_detection() {
        assert!(is_container_literal("[]"));
        assert!(is_container_literal("[1, 2, 3]"));
        assert!(is_container_literal("{}"));
        assert!(is_container_literal("{a: 1}"));
        assert!(is_container_literal("new Map()"));
        assert!(is_container_literal("new ArrayList<>()"));
        assert!(is_container_literal("dict()"));
        assert!(is_container_literal("list()"));
        assert!(is_container_literal("set()"));
        assert!(!is_container_literal("42"));
        assert!(!is_container_literal("\"hello\""));
        assert!(!is_container_literal("true"));
    }

    // ── is_container_constructor tests ───────────────────────────────

    #[test]
    fn container_constructor_js() {
        assert!(is_container_constructor("Array", Lang::JavaScript));
        assert!(is_container_constructor("Map", Lang::JavaScript));
        assert!(is_container_constructor("Set", Lang::JavaScript));
        assert!(!is_container_constructor("Object", Lang::JavaScript));
    }

    #[test]
    fn container_constructor_python() {
        assert!(is_container_constructor("list", Lang::Python));
        assert!(is_container_constructor("dict", Lang::Python));
        assert!(is_container_constructor("defaultdict", Lang::Python));
        assert!(!is_container_constructor("str", Lang::Python));
    }

    #[test]
    fn container_constructor_java() {
        assert!(is_container_constructor("ArrayList", Lang::Java));
        assert!(is_container_constructor("HashMap", Lang::Java));
        assert!(is_container_constructor("ConcurrentHashMap", Lang::Java));
        assert!(!is_container_constructor("String", Lang::Java));
    }

    #[test]
    fn container_constructor_go() {
        assert!(is_container_constructor("make", Lang::Go));
        assert!(!is_container_constructor("new", Lang::Go));
    }

    #[test]
    fn container_constructor_rust() {
        assert!(is_container_constructor("Vec::new", Lang::Rust));
        assert!(is_container_constructor("HashMap::new", Lang::Rust));
        assert!(!is_container_constructor("String::new", Lang::Rust));
        assert!(!is_container_constructor("new", Lang::Rust));
    }

    #[test]
    fn container_constructor_cpp() {
        assert!(is_container_constructor("vector", Lang::Cpp));
        assert!(is_container_constructor("std::map", Lang::Cpp));
        assert!(is_container_constructor("unordered_set", Lang::Cpp));
    }

    // ── PointsToResult tests ─────────────────────────────────────────

    #[test]
    fn pts_result_empty() {
        let r = PointsToResult::empty();
        assert!(r.is_empty());
        assert!(r.get(SsaValue(0)).is_none());
    }
}

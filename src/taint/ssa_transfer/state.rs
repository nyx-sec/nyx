//! Taint state, lattice, and per-body observability hooks extracted from
//! the original monolithic `ssa_transfer.rs`.
//!
//! Contains:
//! * [`SsaTaintState`], the per-block lattice value with `values`,
//!   `validated_must`/`validated_may`, `predicates`, `heap`, `path_env`,
//!   `abstract_state`.
//! * [`BindingKey`] / [`seed_lookup`] for cross-body taint seeding.
//! * Observability globals and overrides for worklist iterations and
//!   origin truncation (`MAX_ORIGINS`, `WORKLIST_SAFETY_CAP`, etc.).
//! * The merge-join helpers used by [`Lattice::join`] / [`Lattice::leq`].

use crate::abstract_interp::{self, AbstractState};
use crate::cfg::BodyId;
use crate::constraint;
use crate::pointer::LocId;
use crate::ssa::heap::HeapState;
use crate::ssa::ir::{FieldId, SsaValue};
use crate::state::lattice::Lattice;
use crate::state::symbol::SymbolId;
use crate::taint::domain::{PredicateSummary, SmallBitSet, TaintOrigin, VarTaint};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::HashMap;

// NOTE: The per-SSA-value origin cap used to be a hardcoded
// `MAX_ORIGINS: usize = 4`.  It is now governed by the stable
// `analysis.engine.max_origins` option (default `32`), see
// `crate::utils::analysis_options` and [`effective_max_origins`].  The
// test-only override below still short-circuits the config read so
// `engine_notes_tests.rs` can force a tiny cap to trigger truncation
// on small fixtures.

/// Default safety cap on taint worklist iterations.  Deliberately large so
/// well-formed programs never hit it; the cap exists to bound adversarial
/// inputs that would otherwise loop forever.  Observable and override-able
/// via [`set_worklist_cap_override`] / [`max_worklist_iterations`] for
/// tests; production behaviour unchanged.
pub(super) const WORKLIST_SAFETY_CAP: usize = 100_000;

static WORKLIST_CAP_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Records the MAX iteration count observed across every
/// `run_ssa_taint_full` call since the most recent reset.  Cheaper and
/// more useful for regression tests than the last-call value, a cap
/// hit anywhere in the scan is remembered.
pub(super) static MAX_WORKLIST_ITERATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Counts how many times the worklist safety cap tripped since the
/// most recent reset.  Lets tests assert "the cap fired at least once"
/// without depending on per-finding attribution, which can lose the
/// signal when cap-hit analyses produce no findings.
pub(super) static WORKLIST_CAP_HITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Test-only override for [`WORKLIST_SAFETY_CAP`].  `cap = 0` restores the
/// default.  Intended exclusively for the engine-notes regression tests
/// that need to force a worklist cap-hit on tiny fixtures.
#[doc(hidden)]
pub fn set_worklist_cap_override(cap: usize) {
    WORKLIST_CAP_OVERRIDE.store(cap, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn effective_worklist_cap() -> usize {
    let o = WORKLIST_CAP_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o == 0 { WORKLIST_SAFETY_CAP } else { o }
}

/// Observability hook: records the max iteration count used by any
/// `run_ssa_taint_full` call since the most recent reset.
pub fn max_worklist_iterations() -> usize {
    MAX_WORKLIST_ITERATIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// How many times the worklist cap has tripped since the most recent
/// reset.  Zero when the cap was never hit.
pub fn worklist_cap_hit_count() -> usize {
    WORKLIST_CAP_HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reset the worklist observability counters.  Intended for tests that
/// want a clean baseline before a scan.
pub fn reset_worklist_observability() {
    MAX_WORKLIST_ITERATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
    WORKLIST_CAP_HITS.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Test-only override for the origin cap.  `cap = 0` restores the
/// runtime-configured default (see [`effective_max_origins`]).  Used to
/// force `OriginsTruncated` emission on small fixtures.
static MAX_ORIGINS_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Total number of origins dropped since the most recent reset, captured
/// from `merge_origins` and the post-hoc saturation scan.  Used by tests
/// to detect truncation events that don't propagate to a finding (e.g.
/// when the cap is so tight no taint flow survives to emit a sink event).
pub(super) static ORIGINS_TRUNCATION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[doc(hidden)]
pub fn set_max_origins_override(cap: usize) {
    MAX_ORIGINS_OVERRIDE.store(cap, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the live origin cap.
///
/// Precedence (highest first):
/// 1. The test-only `MAX_ORIGINS_OVERRIDE` atomic (`set_max_origins_override`).
/// 2. The runtime `analysis.engine.max_origins` option, which itself
///    resolves through the installed runtime → `NYX_MAX_ORIGINS` →
///    [`crate::utils::analysis_options::DEFAULT_MAX_ORIGINS`].
///
/// A result of `0` is never returned: the runtime path clamps to
/// [`crate::utils::analysis_options::MIN_MAX_ORIGINS`] on ingest, so the
/// engine always carries at least one origin slot.
pub(super) fn effective_max_origins() -> usize {
    let o = MAX_ORIGINS_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if o != 0 {
        return o;
    }
    crate::utils::analysis_options::current().max_origins as usize
}

/// Observability: total origins dropped by the engine since the most
/// recent `reset_origins_observability` call.  Zero when no truncation
/// happened.  Monotone-increasing across calls.
pub fn origins_truncation_count() -> usize {
    ORIGINS_TRUNCATION_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reset the origins-truncation counter.  Intended for tests.
pub fn reset_origins_observability() {
    ORIGINS_TRUNCATION_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
}

thread_local! {
    /// Per-body engine-note collector.  Cleared at the start of each
    /// `analyse_body_with_seed` invocation and drained after
    /// `run_ssa_taint_full` returns, notes are then attached to every
    /// finding emitted from that body.  Living as a thread-local avoids
    /// threading a `&RefCell` through the nearly-10-argument transfer
    /// struct; inline analysis recursion is intentionally allowed to
    /// bubble callee-side cap hits up into the caller's collector.
    static BODY_ENGINE_NOTES: RefCell<SmallVec<[crate::engine_notes::EngineNote; 2]>> =
        RefCell::new(SmallVec::new());

    /// File-level set of CFG sink spans whose path-traversal taint flow
    /// was suppressed by an SSA-engine path-safety proof (PathFact
    /// `dotdot=No && absolute=No`).  Populated by `is_path_safe_for_sink`
    /// and consumed by the state-analysis pass to suppress
    /// `state-unauthed-access` on the same sink, when the taint engine
    /// has already proved the user-controlled input cannot escape into a
    /// privileged location, the auth concern on that sink is reduced.
    /// Reset at start of `analyse_file`, drained before state analysis.
    static PATH_SAFE_SUPPRESSED_SPANS: RefCell<std::collections::HashSet<(usize, usize)>> =
        RefCell::new(std::collections::HashSet::new());

    /// File-level set of CFG sink spans where the SSA engine emitted an
    /// `all_validated` event, every tainted input to the sink passed
    /// through a recognised validation/sanitisation predicate before
    /// reaching it.  Distinct from `PATH_SAFE_SUPPRESSED_SPANS`, which
    /// is FILE_IO-scoped and feeds state analysis: this set is
    /// cap-agnostic and feeds AST-pattern suppression, providing
    /// positive evidence that the engine reached the sink and proved
    /// safety so that downstream AST-pattern findings on the same line
    /// can be safely silenced.
    ///
    /// Without this signal the suppression gate has to fall back to
    /// "function emitted at least one taint-unsanitised-flow finding"
    /// or "function contains a labelled Sanitizer node", both of
    /// which miss validated/dominated/early-return safety where the
    /// engine cleared the flow without firing or hitting an explicit
    /// sanitiser.
    ///
    /// Reset at start of `analyse_file` (mirrors the existing
    /// path-safe span lifecycle); drained inside
    /// `TaintSuppressionCtx::build`.
    static ALL_VALIDATED_SPANS: RefCell<std::collections::HashSet<(usize, usize)>> =
        RefCell::new(std::collections::HashSet::new());
}

/// Record an engine note for the body currently being analysed.  Safe to
/// call from anywhere under a `run_ssa_taint_full` call stack; duplicates
/// against notes already present in the body collector are suppressed.
pub(crate) fn record_engine_note(note: crate::engine_notes::EngineNote) {
    BODY_ENGINE_NOTES.with(|c| {
        crate::engine_notes::push_unique(&mut c.borrow_mut(), note);
    });
}

/// Reset the per-body collector (called at start of each body analysis).
pub(crate) fn reset_body_engine_notes() {
    BODY_ENGINE_NOTES.with(|c| c.borrow_mut().clear());
}

/// Take the current collected notes, leaving the collector empty.  Called
/// after `run_ssa_taint_full` to attach collected notes to findings.
pub(crate) fn take_body_engine_notes() -> SmallVec<[crate::engine_notes::EngineNote; 2]> {
    BODY_ENGINE_NOTES.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// Record a sink CFG-node span whose tainted input is proven path-safe by
/// the SSA abstract domain (`PathFact::is_path_safe()`).  Consumed by the
/// state-analysis pass to suppress `state-unauthed-access` on the same
/// span: once the taint engine has proved the input cannot reach a
/// privileged location, the auth concern is structurally reduced.
pub(crate) fn record_path_safe_suppressed_span(span: (usize, usize)) {
    PATH_SAFE_SUPPRESSED_SPANS.with(|c| {
        c.borrow_mut().insert(span);
    });
}

/// Reset the file-level path-safe-suppressed sink-span set.  Called at
/// the start of `analyse_file` so each file scan starts with a clean
/// slate.
pub fn reset_path_safe_suppressed_spans() {
    PATH_SAFE_SUPPRESSED_SPANS.with(|c| c.borrow_mut().clear());
}

/// Take the file-level path-safe-suppressed sink-span set, leaving it
/// empty.  Called by the analysis orchestrator after `analyse_file` and
/// before `run_state_analysis` so the state pass can read which sinks
/// the taint engine already proved safe.
pub fn take_path_safe_suppressed_spans() -> std::collections::HashSet<(usize, usize)> {
    PATH_SAFE_SUPPRESSED_SPANS.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// Record a sink CFG-node span where the SSA engine proved every
/// tainted input was validated (`SsaTaintEvent::all_validated`).
/// Cap-agnostic, fires for any sink the engine evaluated and cleared.
/// Consumed by `TaintSuppressionCtx::build` as positive evidence that
/// taint analysis reached this line and proved safety, so AST-pattern
/// findings on the same line can be suppressed without misclassifying
/// silent engine failures as "safe by validation".
pub(crate) fn record_all_validated_span(span: (usize, usize)) {
    ALL_VALIDATED_SPANS.with(|c| {
        c.borrow_mut().insert(span);
    });
}

/// Reset the file-level all-validated sink-span set.  Called at the
/// start of `analyse_file` alongside `reset_path_safe_suppressed_spans`
/// so each file scan starts clean.
pub fn reset_all_validated_spans() {
    ALL_VALIDATED_SPANS.with(|c| c.borrow_mut().clear());
}

/// Take the file-level all-validated sink-span set, leaving it empty.
/// Called inside `TaintSuppressionCtx::build` to attribute each
/// validated sink to its enclosing function for the suppression gate.
pub fn take_all_validated_spans() -> std::collections::HashSet<(usize, usize)> {
    ALL_VALIDATED_SPANS.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

/// Stable identity for a variable binding at body boundaries.
///
/// Translates between independent per-body `SymbolId` spaces.
/// `SymbolId` remains body-local for intra-body analysis; `BindingKey`
/// is used when taint crosses body boundaries via `global_seed`.
///
/// The `body_id` scopes the binding to a specific body.  Same-named
/// bindings across different bodies never alias.  Callers that write
/// into the seed map always specify the owning body's id; readers look
/// up by the scope they know they want (typically their own
/// `parent_body_id`, with a fallback to `BodyId(0)` for entries that
/// the JS/TS two-level solve has re-keyed onto the top-level scope ,
/// see [`crate::taint::ssa_transfer::filter_seed_to_toplevel`]).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BindingKey {
    pub name: String,
    /// Owning body id.
    pub body_id: BodyId,
}

impl BindingKey {
    pub fn new(name: impl Into<String>, body_id: BodyId) -> Self {
        Self {
            name: name.into(),
            body_id,
        }
    }
}

/// Look up a binding in a seed map.
///
/// Thin wrapper over [`HashMap::get`] retained for call-site readability
///, every seed entry is now exactly scoped to a single `(name,
/// BodyId)`, so the lookup is O(1) with no fallback.  Writers that want
/// cross-scope reachability must explicitly re-key their entries (see
/// [`crate::taint::ssa_transfer::filter_seed_to_toplevel`]).
pub fn seed_lookup<'a>(
    seed: &'a HashMap<BindingKey, VarTaint>,
    key: &BindingKey,
) -> Option<&'a VarTaint> {
    seed.get(key)
}

// ── SSA Taint State ─────────────────────────────────────────────────────

/// Compact key for a heap-field taint cell.
///
/// `(loc, field)`, `loc` is the abstract location of the *parent*
/// (interned by the body's [`crate::pointer::LocInterner`]), `field`
/// is the [`FieldId`] of the projected field.  The pair survives lattice
/// joins / leq comparisons by `Ord`-derived sort.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldTaintKey {
    pub loc: LocId,
    pub field: FieldId,
}

/// per-field-cell taint record.
///
/// Carries the union of writers' taint for the abstract field cell plus
/// two validation channels:
/// * `validated_must`, set when *every* writer recorded a value that was
///   `validated_must` in its own SSA scope.  Lattice join intersects
///   (`AND`), matching the symbol-keyed [`SsaTaintState::validated_must`]
///   semantics for "validated on every path".
/// * `validated_may`, set when *any* writer recorded a `validated_may`
///   value.  Lattice join unions (`OR`), matching the symbol-keyed
///   [`SsaTaintState::validated_may`] semantics for "validated on some
///   path".
///
/// Cells with `taint.caps == empty()` never get inserted (see
/// [`SsaTaintState::add_field`]) so the lattice bottom remains `[]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldCell {
    pub taint: VarTaint,
    pub validated_must: bool,
    pub validated_may: bool,
}

impl FieldCell {
    /// Construct a cell with no validation bits, convenience for the
    /// pre-W4 callers that don't propagate symbol-level validation.
    pub fn unvalidated(taint: VarTaint) -> Self {
        Self {
            taint,
            validated_must: false,
            validated_may: false,
        }
    }
}

/// Taint state keyed by SsaValue instead of SymbolId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaTaintState {
    /// Per-SSA-value taint, sorted by SsaValue for O(n) merge-join.
    pub values: SmallVec<[(SsaValue, VarTaint); 16]>,
    /// Variables validated on ALL paths (intersection on join). Keyed by SymbolId.
    pub validated_must: SmallBitSet,
    /// Variables validated on ANY path (union on join). Keyed by SymbolId.
    pub validated_may: SmallBitSet,
    /// Per-variable predicate summary (sorted by SymbolId, intersection on join).
    pub predicates: SmallVec<[(SymbolId, PredicateSummary); 4]>,
    /// Per-heap-object taint: container contents taint tracked through
    /// abstract heap identity. Separate from `values` so container taint
    /// persists independently of the SSA value referencing the container.
    pub heap: HeapState,
    /// Path constraint environment. `None` when constraint solving is
    /// disabled (`analysis.engine.constraint_solving = false`).
    pub path_env: Option<constraint::PathEnv>,
    /// Per-SSA-value abstract domain state. `None` when abstract
    /// interpretation is disabled (`analysis.engine.abstract_interpretation
    /// = false`).
    pub abstract_state: Option<AbstractState>,
    /// per-heap-field taint cells, keyed by
    /// `(parent_loc, field)`.  Sorted by [`FieldTaintKey`] for O(n)
    /// merge-join.  Populated only when the body's
    /// [`crate::pointer::PointsToFacts`] is available
    /// (`NYX_POINTER_ANALYSIS=1`); empty otherwise so the lattice join
    /// is a strict no-op for pointer-disabled runs.  Field reads
    /// (`SsaOp::FieldProj`) consult the cells; field writes record into
    /// them.  Cross-call propagation lands during lowering via the
    /// field-granularity `PointsToSummary`.
    ///
    /// Cell shape: [`FieldCell`] carries `taint` plus
    /// `validated_must` / `validated_may` flags so validation flows
    /// through abstract field / element identity.
    pub field_taint: SmallVec<[(FieldTaintKey, FieldCell); 4]>,
}

impl SsaTaintState {
    pub fn initial() -> Self {
        Self {
            values: SmallVec::new(),
            validated_must: SmallBitSet::empty(),
            validated_may: SmallBitSet::empty(),
            predicates: SmallVec::new(),
            heap: HeapState::empty(),
            path_env: if constraint::is_enabled() {
                Some(constraint::PathEnv::empty())
            } else {
                None
            },
            abstract_state: if abstract_interp::is_enabled() {
                Some(AbstractState::empty())
            } else {
                None
            },
            field_taint: SmallVec::new(),
        }
    }

    /// read the field cell at `key`.  Returns `None`
    /// when no cell has been recorded (caller should treat as
    /// untainted).  O(log n) on the sorted [`field_taint`] list.
    pub fn get_field(&self, key: FieldTaintKey) -> Option<&FieldCell> {
        self.field_taint
            .binary_search_by_key(&key, |(k, _)| *k)
            .ok()
            .map(|idx| &self.field_taint[idx].1)
    }

    /// union `t` into the field cell at `key`,
    /// recording per-write `validated_must` / `validated_may` channels.
    ///
    /// Maintains sorted invariant.  No-op when `t.caps` is empty (so the
    /// lattice bottom stays `[]`).  When the cell already exists, the
    /// validation channels merge with the lattice-join semantics ,
    /// `must` AND-intersects, `may` OR-unions, matching the symbol-
    /// keyed [`SsaTaintState::validated_must`] / `validated_may`
    /// semantics so a write coming through a non-validated path tears
    /// down `must` while preserving `may` of any earlier validated path.
    pub fn add_field(
        &mut self,
        key: FieldTaintKey,
        t: VarTaint,
        validated_must: bool,
        validated_may: bool,
    ) {
        if t.caps.is_empty() {
            return;
        }
        match self.field_taint.binary_search_by_key(&key, |(k, _)| *k) {
            Ok(idx) => {
                let cell = &mut self.field_taint[idx].1;
                cell.taint.caps |= t.caps;
                cell.taint.uses_summary |= t.uses_summary;
                let merged = merge_origins(&cell.taint.origins, &t.origins);
                cell.taint.origins = merged;
                // Lattice-join semantics on a fresh write joining an
                // existing cell: must AND-intersects (a single un-
                // validated writer breaks the invariant); may OR-unions.
                cell.validated_must &= validated_must;
                cell.validated_may |= validated_may;
            }
            Err(idx) => self.field_taint.insert(
                idx,
                (
                    key,
                    FieldCell {
                        taint: t,
                        validated_must,
                        validated_may,
                    },
                ),
            ),
        }
    }

    /// Check if any variable has contradictory predicates or path constraints.
    pub fn has_contradiction(&self) -> bool {
        self.predicates.iter().any(|(_, s)| s.has_contradiction())
            || self.path_env.as_ref().is_some_and(|e| e.is_unsat())
    }

    pub fn get(&self, v: SsaValue) -> Option<&VarTaint> {
        self.values
            .binary_search_by_key(&v, |(id, _)| *id)
            .ok()
            .map(|idx| &self.values[idx].1)
    }

    pub fn set(&mut self, v: SsaValue, taint: VarTaint) {
        match self.values.binary_search_by_key(&v, |(id, _)| *id) {
            Ok(idx) => self.values[idx].1 = taint,
            Err(idx) => self.values.insert(idx, (v, taint)),
        }
    }

    pub fn remove(&mut self, v: SsaValue) {
        if let Ok(idx) = self.values.binary_search_by_key(&v, |(id, _)| *id) {
            self.values.remove(idx);
        }
    }
}

impl Lattice for SsaTaintState {
    fn bot() -> Self {
        Self::initial()
    }

    fn join(&self, other: &Self) -> Self {
        let values = merge_join_ssa_vars(&self.values, &other.values);
        let validated_must = self.validated_must.intersection(other.validated_must);
        let validated_may = self.validated_may.union(other.validated_may);
        let predicates = merge_join_ssa_predicates(&self.predicates, &other.predicates);
        let heap = self.heap.join(&other.heap);
        let path_env = match (&self.path_env, &other.path_env) {
            (Some(a), Some(b)) => Some(a.join(b)),
            _ => None, // absent = Top, Top.join(x) = Top
        };
        let abstract_state = match (&self.abstract_state, &other.abstract_state) {
            (Some(a), Some(b)) => Some(a.join(b)),
            _ => None,
        };
        let field_taint = merge_join_field_taint(&self.field_taint, &other.field_taint);
        SsaTaintState {
            values,
            validated_must,
            validated_may,
            predicates,
            heap,
            path_env,
            abstract_state,
            field_taint,
        }
    }

    fn leq(&self, other: &Self) -> bool {
        if !ssa_vars_leq(&self.values, &other.values) {
            return false;
        }
        if !self.validated_must.is_superset_of(other.validated_must) {
            return false;
        }
        if !self.validated_may.is_subset_of(other.validated_may) {
            return false;
        }
        if !self.heap.leq(&other.heap) {
            return false;
        }
        if !field_taint_leq(&self.field_taint, &other.field_taint) {
            return false;
        }
        // path_env: None (Top) ≥ everything; Some(a) ≤ None only if a is Top-equivalent
        match (&self.path_env, &other.path_env) {
            (None, Some(_)) => return false, // Top is NOT ≤ constrained
            (Some(_), None) => {}            // constrained ≤ Top: ok
            (None, None) => {}
            (Some(a), Some(b)) => {
                // a ≤ b means a has at least as many constraints as b.
                // For the worklist to converge, we only need: if the
                // joined state didn't change, we stop. The PartialEq
                // check on the full SsaTaintState handles this.
                // For leq, we use a simple approximation: a ≤ b iff
                // a.fact_count() >= b.fact_count() (more facts = lower).
                // This is sound for convergence but approximate.
                if a.fact_count() < b.fact_count() {
                    return false;
                }
            }
        }
        // Abstract-state comparison
        match (&self.abstract_state, &other.abstract_state) {
            (None, Some(_)) => return false,
            (Some(a), Some(b)) if !a.leq(b) => return false,
            _ => {}
        }
        true
    }
}

/// merge-join two sorted `field_taint` lists.
/// Same shape as [`merge_join_ssa_vars`] but keyed on [`FieldTaintKey`]:
/// * `taint.caps` , OR-union
/// * `taint.origins`, merged with cap-respecting de-dup
/// * `taint.uses_summary`, OR-union
/// * `validated_must`, AND-intersect (matches the symbol-keyed
///   `validated_must` lattice: a path that didn't validate this cell
///   breaks the invariant)
/// * `validated_may`, OR-union (any path's validation contributes)
pub(super) fn merge_join_field_taint(
    a: &[(FieldTaintKey, FieldCell)],
    b: &[(FieldTaintKey, FieldCell)],
) -> SmallVec<[(FieldTaintKey, FieldCell); 4]> {
    let mut result = SmallVec::with_capacity(a.len().max(b.len()));
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                // Cell present only in `a`, counterpart in `b` is the
                // lattice bottom (no validation, no taint), so:
                //   must = a.must AND false = false
                //   may  = a.may  OR  false = a.may
                let mut cell = a[i].1.clone();
                cell.validated_must = false;
                result.push((a[i].0, cell));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                let mut cell = b[j].1.clone();
                cell.validated_must = false;
                result.push((b[j].0, cell));
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let caps = a[i].1.taint.caps | b[j].1.taint.caps;
                let origins = merge_origins(&a[i].1.taint.origins, &b[j].1.taint.origins);
                let uses_summary = a[i].1.taint.uses_summary || b[j].1.taint.uses_summary;
                let validated_must = a[i].1.validated_must && b[j].1.validated_must;
                let validated_may = a[i].1.validated_may || b[j].1.validated_may;
                result.push((
                    a[i].0,
                    FieldCell {
                        taint: VarTaint {
                            caps,
                            origins,
                            uses_summary,
                        },
                        validated_must,
                        validated_may,
                    },
                ));
                i += 1;
                j += 1;
            }
        }
    }
    while i < a.len() {
        let mut cell = a[i].1.clone();
        cell.validated_must = false;
        result.push((a[i].0, cell));
        i += 1;
    }
    while j < b.len() {
        let mut cell = b[j].1.clone();
        cell.validated_must = false;
        result.push((b[j].0, cell));
        j += 1;
    }
    result
}

/// `a ≤ b` for sorted `field_taint` lists.  Used by the convergence
/// check in [`Lattice::leq`].  Per-cell criteria:
///
/// * `taint.caps`, `a ⊆ b` (sub-state on caps; matches per-SSA-value
///   `ssa_vars_leq`).
/// * `validated_must`, `a.must ⊇ b.must` (super-state on must; same
///   shape as the symbol-keyed `validated_must` leq).
/// * `validated_may`, `a.may ⊆ b.may` (sub-state on may).
///
/// When `b` lacks a key present in `a`, `b`'s side is the lattice
/// bottom: no caps, no validation.  `a`'s caps must also be empty
/// AND `a.validated_must == false` for `a ≤ b` to hold, otherwise `a`
/// is strictly greater than `b` on that cell.
pub(super) fn field_taint_leq(
    a: &[(FieldTaintKey, FieldCell)],
    b: &[(FieldTaintKey, FieldCell)],
) -> bool {
    let mut j = 0;
    for (key, ca) in a {
        while j < b.len() && b[j].0 < *key {
            j += 1;
        }
        if j >= b.len() || b[j].0 != *key {
            // Key absent in b ⇒ b's value is bottom for this cell;
            // a's caps must also be empty AND a.must = false.
            if !ca.taint.caps.is_empty() || ca.validated_must {
                return false;
            }
            continue;
        }
        let cb = &b[j].1;
        // Caps: a ⊆ b.
        if (ca.taint.caps - cb.taint.caps).bits() != 0 {
            return false;
        }
        // Must: a ⊇ b, every must-validated key in b is must-validated
        // in a.  Equivalently: !cb.must OR ca.must.
        if cb.validated_must && !ca.validated_must {
            return false;
        }
        // May: a ⊆ b, every may-validated key in a is may-validated
        // in b.  Equivalently: !ca.may OR cb.may.
        if ca.validated_may && !cb.validated_may {
            return false;
        }
    }
    true
}

/// Merge-join two sorted SSA var lists.
pub(super) fn merge_join_ssa_vars(
    a: &[(SsaValue, VarTaint)],
    b: &[(SsaValue, VarTaint)],
) -> SmallVec<[(SsaValue, VarTaint); 16]> {
    let mut result = SmallVec::with_capacity(a.len().max(b.len()));
    let (mut i, mut j) = (0, 0);

    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                result.push(a[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                result.push(b[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let caps = a[i].1.caps | b[j].1.caps;
                let origins = merge_origins(&a[i].1.origins, &b[j].1.origins);
                let uses_summary = a[i].1.uses_summary || b[j].1.uses_summary;
                result.push((
                    a[i].0,
                    VarTaint {
                        caps,
                        origins,
                        uses_summary,
                    },
                ));
                i += 1;
                j += 1;
            }
        }
    }

    while i < a.len() {
        result.push(a[i].clone());
        i += 1;
    }
    while j < b.len() {
        result.push(b[j].clone());
        j += 1;
    }

    result
}

/// Deterministic sort key for a [`TaintOrigin`].
///
/// Ordering is lexicographic over
/// `(source_span_start, source_span_end, source_kind_tag, node_index)`.
/// `source_span` is the most stable component across bodies, cross-body
/// remapped origins carry the original byte span explicitly; intra-body
/// origins default to `(0, 0)` and fall through to the secondary keys.
///
/// Using a total order lets [`push_origin_bounded`] and
/// [`merge_origins`] decide *which* origin to drop when the cap is
/// exceeded: they always drop the origin with the largest key, making
/// the survivor set a deterministic function of the input set rather
/// than of merge visitation order.
fn origin_sort_key(o: &TaintOrigin) -> (usize, usize, u8, usize) {
    let (span_start, span_end) = o.source_span.unwrap_or((0, 0));
    let kind_tag: u8 = match o.source_kind {
        crate::labels::SourceKind::UserInput => 0,
        crate::labels::SourceKind::EnvironmentConfig => 1,
        crate::labels::SourceKind::FileSystem => 2,
        crate::labels::SourceKind::Database => 3,
        crate::labels::SourceKind::CaughtException => 4,
        crate::labels::SourceKind::Unknown => 5,
        crate::labels::SourceKind::Cookie => 6,
        crate::labels::SourceKind::Header => 7,
    };
    (span_start, span_end, kind_tag, o.node.index())
}

/// Bounded, deterministic insertion of an origin into a sorted origin
/// set.  Returns `true` when `new` was admitted (or de-duplicated against
/// an existing entry), `false` when the cap forced a drop.  On drop,
/// the origin with the *largest* sort key is evicted first, the caller
/// sees a survivor set that depends only on the input multiset and
/// [`effective_max_origins`], not on insertion order.
///
/// Records the engine note and increments [`ORIGINS_TRUNCATION_COUNT`]
/// exactly once per physical drop.  Calling sites that used to inline
/// the "dedup + push if under cap" pattern should migrate here so
/// truncation is globally consistent.
pub(crate) fn push_origin_bounded(
    target: &mut SmallVec<[TaintOrigin; 2]>,
    new: TaintOrigin,
) -> bool {
    // Identity check: same node counts as the same origin.  We keep
    // node-only dedup to match [`ssa_vars_leq`], which compares origin
    // sets by node membership, widening dedup here without tightening
    // there would break the monotonicity invariant.
    if target.iter().any(|o| o.node == new.node) {
        return true;
    }

    let cap = effective_max_origins();
    let new_key = origin_sort_key(&new);

    if target.len() < cap {
        // Insert in sorted order so iteration is deterministic.
        let pos = target
            .iter()
            .position(|o| origin_sort_key(o) > new_key)
            .unwrap_or(target.len());
        target.insert(pos, new);
        return true;
    }

    // Cap reached: evict the worst (largest key) entry iff `new` is better.
    let worst_idx = target
        .iter()
        .enumerate()
        .max_by_key(|(_, o)| origin_sort_key(o))
        .map(|(i, _)| i)
        .expect("cap ≥ MIN_MAX_ORIGINS (1) means target is non-empty");
    let worst_key = origin_sort_key(&target[worst_idx]);

    ORIGINS_TRUNCATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated { dropped: 1 });

    if new_key < worst_key {
        target.remove(worst_idx);
        let pos = target
            .iter()
            .position(|o| origin_sort_key(o) > new_key)
            .unwrap_or(target.len());
        target.insert(pos, new);
        true
    } else {
        // `new` itself is the worst, drop it instead of the survivor.
        false
    }
}

/// Merge two origin sets with deterministic truncation.
///
/// Equivalent to seeding the survivor list with `a` and folding each
/// element of `b` through [`push_origin_bounded`].  The resulting list
/// is sorted by [`origin_sort_key`] and bounded at
/// [`effective_max_origins`].
pub(super) fn merge_origins(
    a: &SmallVec<[TaintOrigin; 2]>,
    b: &SmallVec<[TaintOrigin; 2]>,
) -> SmallVec<[TaintOrigin; 2]> {
    // Seed the result with `a`, but re-sort defensively in case the
    // caller constructed `a` through non-bounded paths.  Historically
    // every write goes through `push_origin_bounded` (or `merge_origins`
    // itself), so this resort is a no-op on the steady state but costs
    // nothing at cap sizes ≤ 32.
    let mut merged: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    for o in a.iter().copied() {
        push_origin_bounded(&mut merged, o);
    }
    for o in b.iter().copied() {
        push_origin_bounded(&mut merged, o);
    }
    merged
}

#[allow(dead_code)] // called by Lattice::leq
fn ssa_vars_leq(a: &[(SsaValue, VarTaint)], b: &[(SsaValue, VarTaint)]) -> bool {
    let (mut i, mut j) = (0, 0);

    while i < a.len() {
        if j >= b.len() {
            return false;
        }
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Greater => {
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if a[i].1.caps & b[j].1.caps != a[i].1.caps {
                    return false;
                }
                // uses_summary is monotone: a.uses_summary ≤ b.uses_summary
                if a[i].1.uses_summary && !b[j].1.uses_summary {
                    return false;
                }
                for orig in &a[i].1.origins {
                    if !b[j].1.origins.iter().any(|o| o.node == orig.node) {
                        return false;
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    true
}

/// Merge-join predicate summaries with intersection semantics.
pub(super) fn merge_join_ssa_predicates(
    a: &[(SymbolId, PredicateSummary)],
    b: &[(SymbolId, PredicateSummary)],
) -> SmallVec<[(SymbolId, PredicateSummary); 4]> {
    let mut result = SmallVec::new();
    let (mut i, mut j) = (0, 0);

    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                let joined = a[i].1.join(b[j].1);
                if !joined.is_empty() {
                    result.push((a[i].0, joined));
                }
                i += 1;
                j += 1;
            }
        }
    }
    result
}

#[cfg(test)]
mod origin_cap_tests {
    //! Tests for the deterministic, config-driven origin cap.  These
    //! cover the behavior at the `push_origin_bounded` / `merge_origins`
    //! boundary, the end-to-end engine-note signal is exercised in
    //! `tests/engine_notes_tests.rs`.

    use super::*;
    use crate::labels::SourceKind;
    use petgraph::graph::NodeIndex;
    use std::sync::Mutex;

    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn origin(node: usize, span_start: usize) -> TaintOrigin {
        TaintOrigin {
            node: NodeIndex::new(node),
            source_kind: SourceKind::UserInput,
            source_span: Some((span_start, span_start + 1)),
        }
    }

    #[test]
    fn push_origin_bounded_dedups_by_node() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_origins_override(4);

        let mut target: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        assert!(push_origin_bounded(&mut target, origin(1, 10)));
        assert!(push_origin_bounded(&mut target, origin(1, 99))); // same node, dedups
        assert_eq!(target.len(), 1, "duplicate node must not grow the set");

        set_max_origins_override(0);
    }

    #[test]
    fn push_origin_bounded_is_order_independent() {
        // Core invariant: the survivor set is a function of the input
        // multiset and the cap, not of insertion order.  Regression
        // guard against the pre-fix "keep first 4, drop rest" policy
        // which made the survivor set depend on merge-visitation order.
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_origins_override(3);

        let origins = [
            origin(1, 50),
            origin(2, 10), // smallest span
            origin(3, 30),
            origin(4, 70),
            origin(5, 90), // largest span
        ];

        let mut forward: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        for o in origins.iter() {
            push_origin_bounded(&mut forward, *o);
        }

        let mut reverse: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        for o in origins.iter().rev() {
            push_origin_bounded(&mut reverse, *o);
        }

        let forward_nodes: Vec<_> = forward.iter().map(|o| o.node.index()).collect();
        let reverse_nodes: Vec<_> = reverse.iter().map(|o| o.node.index()).collect();
        assert_eq!(
            forward_nodes, reverse_nodes,
            "survivor set must not depend on insertion order: forward {forward_nodes:?} \
             reverse {reverse_nodes:?}"
        );

        // Spot-check: the 3 smallest-span origins (nodes 2, 3, 1 by span
        // order) survive; the two largest (4, 5) are evicted.
        assert_eq!(forward_nodes, vec![2, 3, 1]);

        set_max_origins_override(0);
    }

    #[test]
    fn push_origin_bounded_increments_truncation_counter() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_origins_override(2);
        reset_origins_observability();

        let mut target: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        push_origin_bounded(&mut target, origin(1, 10));
        push_origin_bounded(&mut target, origin(2, 20));
        // Both below cause truncation (new is worse than worst survivor
        // at node 2 because span=50 > 20, or new beats and evicts).
        push_origin_bounded(&mut target, origin(3, 30));
        push_origin_bounded(&mut target, origin(4, 40));

        assert_eq!(
            origins_truncation_count(),
            2,
            "expected 2 truncation events (3rd and 4th push at cap=2)"
        );

        set_max_origins_override(0);
        reset_origins_observability();
    }

    #[test]
    fn merge_origins_is_symmetric() {
        // join(a, b) and join(b, a) must produce identical survivor
        // sets.  The old implementation was asymmetric: it always kept
        // all of `a` and only added from `b` until cap, so which side
        // was passed as `a` determined the survivors at truncation.
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_origins_override(3);

        let a: SmallVec<[TaintOrigin; 2]> = [origin(1, 100), origin(2, 200)].into_iter().collect();
        let b: SmallVec<[TaintOrigin; 2]> = [origin(3, 10), origin(4, 50)].into_iter().collect();

        let ab = merge_origins(&a, &b);
        let ba = merge_origins(&b, &a);

        let ab_nodes: Vec<_> = ab.iter().map(|o| o.node.index()).collect();
        let ba_nodes: Vec<_> = ba.iter().map(|o| o.node.index()).collect();
        assert_eq!(
            ab_nodes, ba_nodes,
            "merge must be commutative under truncation: ab={ab_nodes:?} ba={ba_nodes:?}"
        );

        set_max_origins_override(0);
    }

    #[test]
    fn effective_cap_reads_runtime_config_when_override_zero() {
        // Override takes priority; override=0 falls through to config.
        // `current()` returns the default (32) when no runtime is
        // installed, which is the state the rest of the test suite runs
        // under.  Guard that the fallback path reaches 32.
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_max_origins_override(0);
        assert_eq!(
            effective_max_origins(),
            crate::utils::analysis_options::DEFAULT_MAX_ORIGINS as usize
        );
        set_max_origins_override(7);
        assert_eq!(effective_max_origins(), 7);
        set_max_origins_override(0);
    }
}

#[cfg(test)]
mod field_taint_tests {
    //!: tests for the heap-field taint cells on
    //! [`SsaTaintState`].  Cover get/add round-trip, lattice join
    //! (cap union + origin merge), and `leq` convergence semantics.
    use super::*;
    use crate::labels::Cap;
    use crate::pointer::LocId;
    use crate::ssa::ir::FieldId;
    use crate::taint::domain::TaintOrigin;
    use smallvec::SmallVec;

    fn key(loc_raw: u32, field_raw: u32) -> FieldTaintKey {
        FieldTaintKey {
            loc: LocId(loc_raw),
            field: FieldId(field_raw),
        }
    }

    fn taint(caps: Cap) -> VarTaint {
        VarTaint {
            caps,
            origins: SmallVec::new(),
            uses_summary: false,
        }
    }

    /// Convenience helper: pre-W4 `add_field` calls didn't carry
    /// validation channels.  The new signature accepts them explicitly;
    /// pre-W4 tests pass `(false, false)` to preserve the original
    /// semantics.
    fn add(s: &mut SsaTaintState, k: FieldTaintKey, t: VarTaint) {
        s.add_field(k, t, false, false);
    }

    #[test]
    fn add_field_round_trips() {
        let mut s = SsaTaintState::initial();
        let k = key(1, 7);
        add(&mut s, k, taint(Cap::ENV_VAR));
        let got = s.get_field(k).expect("field cell present");
        assert!(got.taint.caps.contains(Cap::ENV_VAR));
    }

    #[test]
    fn add_field_unions_caps() {
        let mut s = SsaTaintState::initial();
        let k = key(1, 7);
        add(&mut s, k, taint(Cap::ENV_VAR));
        add(&mut s, k, taint(Cap::ENV_VAR));
        let got = s.get_field(k).unwrap();
        assert!(got.taint.caps.contains(Cap::ENV_VAR));
    }

    #[test]
    fn add_field_skips_empty_caps() {
        let mut s = SsaTaintState::initial();
        let k = key(2, 3);
        add(&mut s, k, taint(Cap::empty()));
        assert!(s.get_field(k).is_none(), "empty caps must not insert");
    }

    #[test]
    fn lattice_join_unions_keys_and_caps() {
        let k1 = key(1, 7);
        let k2 = key(2, 9);
        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        add(&mut a, k1, taint(Cap::ENV_VAR));
        add(&mut b, k1, taint(Cap::ENV_VAR));
        add(&mut b, k2, taint(Cap::FILE_IO));
        let joined = a.join(&b);
        let v1 = joined.get_field(k1).unwrap();
        assert!(v1.taint.caps.contains(Cap::ENV_VAR));
        let v2 = joined.get_field(k2).unwrap();
        assert!(v2.taint.caps.contains(Cap::FILE_IO));
    }

    #[test]
    fn lattice_leq_detects_strict_increase() {
        // a is empty; b has a cell.  Empty ≤ any state, so a.leq(b)
        // holds.  b ≤ a fails because b has a cell with non-empty caps
        // that a lacks.
        let mut b = SsaTaintState::initial();
        add(&mut b, key(1, 7), taint(Cap::ENV_VAR));
        let a = SsaTaintState::initial();
        assert!(a.leq(&b), "empty state ≤ state with a field cell");
        assert!(!b.leq(&a), "state with a field cell is NOT ≤ empty state");
    }

    #[test]
    fn lattice_leq_holds_when_caps_subset() {
        let k = key(3, 4);
        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        add(&mut a, k, taint(Cap::ENV_VAR));
        add(&mut b, k, taint(Cap::ENV_VAR | Cap::FILE_IO));
        assert!(a.leq(&b));
        assert!(!b.leq(&a));
    }

    #[test]
    fn merge_origins_via_join_dedups_by_node() {
        use petgraph::graph::NodeIndex;
        let k = key(1, 1);
        let o1 = TaintOrigin {
            node: NodeIndex::new(5),
            source_kind: crate::labels::SourceKind::UserInput,
            source_span: Some((0, 1)),
        };
        let o2 = TaintOrigin {
            node: NodeIndex::new(7),
            source_kind: crate::labels::SourceKind::EnvironmentConfig,
            source_span: Some((10, 11)),
        };
        let mut t1 = taint(Cap::ENV_VAR);
        t1.origins.push(o1);
        let mut t2 = taint(Cap::ENV_VAR);
        t2.origins.push(o1);
        t2.origins.push(o2);

        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        add(&mut a, k, t1);
        add(&mut b, k, t2);
        let joined = a.join(&b);
        let cell = joined.get_field(k).unwrap();
        // Both origins survive; the duplicate o1 dedups.
        assert_eq!(cell.taint.origins.len(), 2);
        let nodes: Vec<_> = cell.taint.origins.iter().map(|o| o.node).collect();
        assert!(nodes.contains(&NodeIndex::new(5)));
        assert!(nodes.contains(&NodeIndex::new(7)));
    }

    /// W4 audit: `merge_join_field_taint` AND-intersects
    /// `validated_must` when joining cells with the same key.  Two
    /// states whose paths each independently must-validate the cell
    /// keep `must = true`; if either path doesn't validate, `must`
    /// drops to false on the join.
    #[test]
    fn lattice_validated_must_intersects_on_join() {
        let k = key(1, 7);
        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        a.add_field(k, taint(Cap::ENV_VAR), true, true);
        b.add_field(k, taint(Cap::ENV_VAR), true, true);
        let joined_aa = a.join(&b);
        let cell = joined_aa.get_field(k).unwrap();
        assert!(cell.validated_must, "a.must AND b.must = true");
        assert!(cell.validated_may);

        // Now make `b`'s validated_must false, must should drop to
        // false on the join, may stays at OR.
        let mut c = SsaTaintState::initial();
        c.add_field(k, taint(Cap::ENV_VAR), false, true);
        let joined_ac = a.join(&c);
        let cell2 = joined_ac.get_field(k).unwrap();
        assert!(!cell2.validated_must, "a.must AND c.must = false");
        assert!(cell2.validated_may, "a.may OR c.may = true");
    }

    /// W4 audit: `merge_join_field_taint` OR-unions `validated_may`
    ///, any path's may-validation contributes to the joined cell.
    #[test]
    fn lattice_validated_may_unions_on_join() {
        let k = key(1, 7);
        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        a.add_field(k, taint(Cap::ENV_VAR), false, false);
        b.add_field(k, taint(Cap::ENV_VAR), false, true);
        let joined = a.join(&b);
        let cell = joined.get_field(k).unwrap();
        assert!(!cell.validated_must);
        assert!(cell.validated_may, "a.may OR b.may = true");
    }

    /// W4 audit: when one side of the join lacks the key, the
    /// counterpart's validated_must drops to false (intersection with
    /// the lattice bottom's `must = false`); validated_may is preserved
    /// (`OR false = self`).  Caps and origins are preserved.
    #[test]
    fn lattice_validated_consistent_with_taint_join() {
        let k = key(2, 11);
        let mut a = SsaTaintState::initial();
        let b = SsaTaintState::initial();
        a.add_field(k, taint(Cap::ENV_VAR), true, true);
        let joined = a.join(&b);
        let cell = joined.get_field(k).unwrap();
        assert!(
            !cell.validated_must,
            "joined with empty side must drop validated_must"
        );
        assert!(
            cell.validated_may,
            "joined with empty side keeps validated_may"
        );
        assert!(cell.taint.caps.contains(Cap::ENV_VAR));

        // Symmetric: empty.join(populated) yields the same cell shape.
        let joined2 = b.join(&a);
        let cell2 = joined2.get_field(k).unwrap();
        assert!(!cell2.validated_must);
        assert!(cell2.validated_may);
    }

    /// W4 audit: `field_taint_leq` respects both validation channels.
    /// `must` is super-state (a.must ⊇ b.must); `may` is sub-state
    /// (a.may ⊆ b.may).  A state strictly "smaller" on caps but
    /// strictly "larger" on may must NOT compare ≤.
    #[test]
    fn lattice_leq_respects_validated_channels() {
        let k = key(3, 5);

        // Case 1: a has must=true, b has must=false. a.must ⊇ b.must
        // holds (true ⊇ false), so a ≤ b on this channel.  But b's
        // caps must dominate a's for a ≤ b overall.
        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        a.add_field(k, taint(Cap::ENV_VAR), true, false);
        b.add_field(k, taint(Cap::ENV_VAR), false, false);
        assert!(
            a.leq(&b),
            "must super-state and equal caps: a ≤ b should hold"
        );
        // Reverse: b.must=false, a.must=true, for b ≤ a, we need
        // b.must ⊇ a.must which is false ⊇ true = false.  So b ≤ a
        // must fail.
        assert!(!b.leq(&a), "b lacks the must invariant a holds");

        // Case 2: a has may=true, b has may=false.  a.may ⊆ b.may
        // requires true ⊆ false = false, so a ≤ b must fail.
        let mut a2 = SsaTaintState::initial();
        let mut b2 = SsaTaintState::initial();
        a2.add_field(k, taint(Cap::ENV_VAR), false, true);
        b2.add_field(k, taint(Cap::ENV_VAR), false, false);
        assert!(!a2.leq(&b2), "a.may=true is NOT ⊆ b.may=false");
    }

    /// the field_taint lattice is monotone
    /// and converges under a deterministic enumeration of inputs.
    /// Caps grow (OR), `uses_summary` grows (OR), origins grow modulo
    /// the cap (merge_origins is bounded).  Joins must:
    /// 1. Be commutative: join(a, b) == join(b, a).
    /// 2. Be associative: join(join(a, b), c) == join(a, join(b, c)).
    /// 3. Be idempotent: join(a, a) == a.
    /// 4. Reach a fixed point in at most |unique cells| iterations.
    #[test]
    fn lattice_converges_under_deterministic_enumeration() {
        use crate::labels::Cap;
        use petgraph::graph::NodeIndex;

        // Build N distinct (key, taint) pairs.
        let inputs: Vec<(FieldTaintKey, VarTaint)> = (0..6)
            .map(|i| {
                let key = FieldTaintKey {
                    loc: LocId(1 + (i % 3) as u32),
                    field: FieldId((i % 4) as u32),
                };
                let taint = VarTaint {
                    caps: if i % 2 == 0 {
                        Cap::ENV_VAR
                    } else {
                        Cap::FILE_IO
                    },
                    origins: smallvec::SmallVec::from_iter([TaintOrigin {
                        node: NodeIndex::new(i + 10),
                        source_kind: crate::labels::SourceKind::UserInput,
                        source_span: Some((i * 5, i * 5 + 2)),
                    }]),
                    uses_summary: false,
                };
                (key, taint)
            })
            .collect();

        // Build a list of states, each with a single (key, taint) pair.
        let states: Vec<SsaTaintState> = inputs
            .iter()
            .map(|(k, t)| {
                let mut s = SsaTaintState::initial();
                add(&mut s, *k, t.clone());
                s
            })
            .collect();

        // Compute LUB by folding `join` over `states`.
        let lub = states
            .iter()
            .skip(1)
            .fold(states[0].clone(), |acc, s| acc.join(s));

        // 1. Commutativity: join(a, b) == join(b, a).
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                let ab = states[i].join(&states[j]);
                let ba = states[j].join(&states[i]);
                assert_eq!(
                    ab, ba,
                    "join must commute: states[{i}] ⊕ states[{j}] != states[{j}] ⊕ states[{i}]",
                );
            }
        }

        // 2. Associativity: ((a ⊕ b) ⊕ c) == (a ⊕ (b ⊕ c)).
        for i in 0..states.len() {
            for j in 0..states.len() {
                for k in 0..states.len() {
                    let a = &states[i];
                    let b = &states[j];
                    let c = &states[k];
                    let left = a.join(b).join(c);
                    let right = a.join(&b.join(c));
                    assert_eq!(
                        left, right,
                        "join must associate: states[{i},{j},{k}] left vs right",
                    );
                }
            }
        }

        // 3. Idempotency: lub ⊕ lub == lub, lub ⊕ s == lub for every input s.
        let lub_lub = lub.join(&lub);
        assert_eq!(lub, lub_lub, "lub must be idempotent under self-join");
        for (i, s) in states.iter().enumerate() {
            let merged = lub.join(s);
            assert_eq!(
                lub, merged,
                "lub.join(states[{i}]) must equal lub (s ≤ lub)",
            );
        }

        // 4. Convergence within a bounded number of iterations.  The
        // worklist tightens after each input is folded in; once every
        // unique key has been seen, further folds are no-ops.
        let mut acc = SsaTaintState::initial();
        let mut iter_count = 0;
        loop {
            iter_count += 1;
            if iter_count > inputs.len() + 4 {
                panic!("lattice did not converge within bounded iterations");
            }
            let mut next = acc.clone();
            for s in &states {
                next = next.join(s);
            }
            if next.field_taint == acc.field_taint {
                break;
            }
            acc = next;
        }
        assert_eq!(
            acc, lub,
            "iterative fold must converge to the lub regardless of order",
        );
    }

    /// `field_taint_leq` is the soundness gate for worklist
    /// convergence: once `next ≤ acc`, the worklist halts.  Pin that
    /// `leq` is consistent with `join`, i.e. `s.leq(s.join(t))` holds
    /// for any `s, t`.  Without this, the worklist could loop
    /// indefinitely on inputs whose join produces a state not
    /// dominated by both inputs.
    #[test]
    fn lattice_leq_consistent_with_join() {
        use crate::labels::Cap;
        let mut a = SsaTaintState::initial();
        let mut b = SsaTaintState::initial();
        add(&mut a, key(1, 7), taint(Cap::ENV_VAR));
        add(&mut b, key(1, 7), taint(Cap::FILE_IO));
        add(&mut b, key(2, 9), taint(Cap::SHELL_ESCAPE));
        let j = a.join(&b);
        assert!(a.leq(&j), "a ≤ a ⊕ b");
        assert!(b.leq(&j), "b ≤ a ⊕ b");
        // Reflexive: x ≤ x.
        assert!(a.leq(&a));
        assert!(b.leq(&b));
        assert!(j.leq(&j));
    }
}

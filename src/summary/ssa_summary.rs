use crate::abstract_interp::{AbstractTransfer, AbstractValue, PathFact};
use crate::labels::Cap;
use crate::ssa::type_facts::TypeKind;
use crate::summary::SinkSite;
use crate::summary::points_to::{FieldPointsToSummary, PointsToSummary};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Per-parameter taint transform describing how taint flows through a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintTransform {
    /// Parameter flows to return value unchanged.
    Identity,
    /// Parameter flows to return minus sanitizer bits.
    StripBits(Cap),
    /// Return value gains additional source bits regardless of input.
    AddBits(Cap),
}

/// Cap on per-parameter return-path entries. Overflow is joined into
/// a single Top-predicate entry so callers always see a bounded vec.
pub const MAX_RETURN_PATHS: usize = 8;

/// One return-path entry in a per-parameter summary. Records the path
/// predicate, the transform on that path, and optionally an abstract
/// contribution. Callers apply only entries consistent with their
/// caller-side path state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnPathTransform {
    /// Behavioural kind on this path (Identity / StripBits / AddBits).
    pub transform: TaintTransform,
    /// Deterministic hash of the path-predicate gate. `0` = no gate.
    /// Equivalent predicates collide and are joined.
    pub path_predicate_hash: u64,
    /// `known_true` predicate bits (bit 0 = NullCheck, 1 = EmptyCheck,
    /// 2 = ErrorCheck) that hold on every path into this return.
    pub known_true: u8,
    /// `known_false` bits at this return.
    pub known_false: u8,
    /// Abstract contribution when non-Top. Callers `meet` it with the
    /// caller-side abstract fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abstract_contribution: Option<AbstractValue>,
}

impl ReturnPathTransform {
    /// Dedup key. `abstract_contribution` is intentionally excluded
    ///, colliding entries join their abstract facts.
    pub fn dedup_key(&self) -> (u64, &TaintTransform, u8, u8) {
        (
            self.path_predicate_hash,
            &self.transform,
            self.known_true,
            self.known_false,
        )
    }
}

/// Merge `incoming` into `existing`, deduping by
/// [`ReturnPathTransform::dedup_key`] and joining abstract contributions on
/// collision.  Caps the final vector at [`MAX_RETURN_PATHS`]; overflow is
/// conservatively joined into a single Top-predicate entry.
pub fn merge_return_paths(
    existing: &mut SmallVec<[ReturnPathTransform; 2]>,
    incoming: &[ReturnPathTransform],
) {
    for new_entry in incoming {
        let key = new_entry.dedup_key();
        if let Some(slot) = existing.iter_mut().find(|e| e.dedup_key() == key) {
            slot.abstract_contribution = match (
                slot.abstract_contribution.take(),
                &new_entry.abstract_contribution,
            ) {
                (Some(a), Some(b)) => Some(a.join(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            };
        } else {
            existing.push(new_entry.clone());
        }
    }
    if existing.len() > MAX_RETURN_PATHS {
        let mut joined = ReturnPathTransform {
            transform: TaintTransform::Identity,
            path_predicate_hash: 0,
            known_true: 0,
            known_false: 0,
            abstract_contribution: None,
        };
        let mut strip_bits = Cap::all();
        let mut add_bits = Cap::empty();
        let mut saw_add = false;
        let mut abs: Option<AbstractValue> = None;
        let mut known_true = u8::MAX;
        let mut known_false = u8::MAX;
        for e in existing.iter() {
            match &e.transform {
                TaintTransform::Identity => {
                    // Identity strips nothing; join intersects to empty.
                    strip_bits = Cap::empty();
                }
                TaintTransform::StripBits(bits) => strip_bits &= *bits,
                TaintTransform::AddBits(bits) => {
                    add_bits |= *bits;
                    saw_add = true;
                }
            }
            known_true &= e.known_true;
            known_false &= e.known_false;
            abs = match (abs, &e.abstract_contribution) {
                (None, None) => None,
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b.clone()),
                (Some(a), Some(b)) => Some(a.join(b)),
            };
        }
        joined.transform = if saw_add {
            TaintTransform::AddBits(add_bits)
        } else if strip_bits.is_empty() {
            TaintTransform::Identity
        } else {
            TaintTransform::StripBits(strip_bits)
        };
        joined.known_true = known_true;
        joined.known_false = known_false;
        joined.abstract_contribution = abs;
        existing.clear();
        existing.push(joined);
    }
}

/// Precise per-parameter SSA-derived function summary.
///
/// Produced by running SSA taint analysis with each parameter individually
/// seeded, then observing which caps survive to return/sink positions.
/// This is more precise than the legacy `FuncSummary` bitmask approach
/// because it can express per-parameter transforms (e.g., "param 0 flows
/// to return but loses HTML_ESCAPE bits").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SsaFuncSummary {
    /// Per-parameter flows to return value: (param_index, transform).
    pub param_to_return: Vec<(usize, TaintTransform)>,
    /// Per-parameter flows to internal sinks: each entry binds a parameter
    /// index to one or more [`SinkSite`]s inside this function's body.
    ///
    /// Carrying the callee's sink source-location through the summary
    /// enables primary sink-location attribution: cross-file findings
    /// attribute the finding to the actual dangerous instruction rather
    /// than to the call site.  Each `SinkSite` records the bits (`cap`) it
    /// contributes, so consumers deriving a coarse `Cap` union across all
    /// sites for a given parameter remain behavior-compatible.
    #[serde(default)]
    pub param_to_sink: Vec<(usize, SmallVec<[SinkSite; 1]>)>,
    /// Source caps introduced regardless of parameters (e.g., function reads env).
    pub source_caps: Cap,
    /// Per-parameter flows to specific internal sink argument positions:
    /// (caller_param_index, sink_arg_position, sink_caps).
    #[serde(default)]
    pub param_to_sink_param: Vec<(usize, usize, Cap)>,
    /// Per-parameter gate-filter cap masks lifted from inner multi-gate
    /// sink call sites.
    ///
    /// When a function body contains a callee whose
    /// [`crate::cfg::CallMeta::gate_filters`] carries more than one entry
    /// (e.g. `fetch` is both an `SSRF` gate on the URL arg and a
    /// `DATA_EXFIL` gate on the body arg), the multi-gate dispatch in
    /// [`super::super::collect_block_events`] cap-narrows the event's
    /// `sink_caps` to the specific gate's `label_caps`.  Each
    /// `(param_idx, label_caps)` entry records that this function's
    /// parameter `param_idx` flowed into a gated sink whose narrowed
    /// caps were `label_caps`.
    ///
    /// Cross-file callers consume this list to preserve per-position cap
    /// attribution through wrapper functions: a wrapper
    /// `fn forward(url, body) { fetch(url, {body}) }` records
    /// `[(0, SSRF), (1, DATA_EXFIL)]` so a caller of `forward` splits
    /// URL-tainted SSRF findings from body-tainted DATA_EXFIL findings
    /// instead of conflating both caps onto every parameter.
    ///
    /// `Vec<(param_idx, label_caps)>` is sufficient at cross-file
    /// granularity, the corresponding `payload_args` and
    /// `destination_uses` are intra-file context that does not survive
    /// the function-summary boundary (field idents reference SSA
    /// values from the callee body).
    ///
    /// Empty (the default) for callees whose internal sinks carry zero
    /// or one gate filter, the existing
    /// [`Self::param_to_sink`] /
    /// [`Self::param_to_sink_param`] machinery already records those
    /// cases without per-position cap conflict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_to_gate_filters: Vec<(usize, Cap)>,
    /// Parameter indices whose container identity flows to the return value
    /// (e.g., function returns the same container it received as input).
    ///
    /// Populated by
    /// [`crate::taint::ssa_transfer::summary_extract::extract_container_flow_summary`]
    /// and applied at cross-file call sites to propagate the caller's
    /// points-to set for that argument onto the call's return SSA value.
    #[serde(default)]
    pub param_container_to_return: Vec<usize>,
    /// `(src_param, container_param)` pairs: `src_param`'s taint is stored
    /// into `container_param`'s container contents inside this function
    /// (e.g., `fn storeInto(value, arr) { arr.push(value); }` → `[(0, 1)]`).
    ///
    /// Populated by
    /// [`crate::taint::ssa_transfer::summary_extract::extract_container_flow_summary`]
    /// and applied at cross-file call sites by writing the caller's taint on
    /// the `src_param` argument into the heap objects pointed to by the
    /// `container_param` argument.
    #[serde(default)]
    pub param_to_container_store: Vec<(usize, usize)>,
    /// Inferred return type of the function, when determinable from constructor
    /// calls or type annotations. Enables cross-file type-qualified resolution.
    #[serde(default)]
    pub return_type: Option<TypeKind>,
    /// Abstract domain fact for the return value.
    /// When present, callers can use this to seed the return SSA value's
    /// abstract state for cross-procedural interval/string analysis.
    #[serde(default)]
    pub return_abstract: Option<AbstractValue>,
    /// Internal source taint flows to a call of parameter N with these caps.
    /// Detects callback patterns like `fn apply(f: F) { let x = source(); f(x); }`
    /// where the function invokes a callback parameter with tainted data.
    #[serde(default)]
    pub source_to_callback: Vec<(usize, Cap)>,
    /// How receiver (`self`/`this`) taint flows to the return value.
    /// `None` when receiver taint does not reach the return.  Matches the
    /// semantics of `param_to_return`'s `TaintTransform` for positional params.
    #[serde(default)]
    pub receiver_to_return: Option<TaintTransform>,
    /// Caps that the receiver's taint reaches in internal sinks.
    /// Empty when the receiver is not used as a sink payload inside the body.
    #[serde(default)]
    pub receiver_to_sink: Cap,
    /// Per-parameter abstract-domain transfer channels.
    ///
    /// Each entry `(param_index, transfer)` describes how a caller-known
    /// abstract value at that parameter maps to the function's return
    /// abstract value.  At cross-file call sites the caller applies each
    /// transfer to the corresponding argument's abstract state and joins
    /// the results (then `meet`s with [`Self::return_abstract`]) to
    /// synthesise the return abstract value, recovering interval bounds
    /// and string prefixes that would otherwise be lost to the summary's
    /// Top-seeded baseline.
    ///
    /// Empty when no parameter carries useful abstract flow.  Individual
    /// entries are omitted when their transfer is "top" (no knowledge),
    /// so on-disk size grows only when the callee really does propagate
    /// abstract values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub abstract_transfer: Vec<(usize, AbstractTransfer)>,
    /// Per-parameter return-path decomposition.
    ///
    /// When non-empty, supplies finer-grained per-path data than
    /// [`Self::param_to_return`].  Each parameter maps to up to
    /// [`MAX_RETURN_PATHS`] [`ReturnPathTransform`] entries, one per
    /// distinct path-predicate gate.  Callers consult their own predicate
    /// state at the call site and apply only entries whose predicate is
    /// consistent with the caller's validated set, joining the applicable
    /// set into the effective call-site transform.
    ///
    /// Empty when the callee has a single return path, the aggregate
    /// [`param_to_return`] is already precise, or when extraction
    /// could not derive per-return state (e.g. early-exit probes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_return_paths: Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)>,
    /// Parameter-granularity points-to summary.
    ///
    /// Records bounded alias edges between parameter positions and the
    /// return value, so summary-path cross-file resolution can spread
    /// taint through object mutations that do not flow via the return.
    /// Empty (the default) for functions whose parameters do not alias
    /// each other or the return value.
    #[serde(default, skip_serializing_if = "PointsToSummary::is_empty")]
    pub points_to: PointsToSummary,
    /// field-granularity per-parameter points-to
    /// summary.  Records which fields the callee reads from / writes
    /// to on each parameter, so cross-file resolution can spread
    /// taint through field-level mutations the callee performs on
    /// caller-supplied objects.
    ///
    /// Default-empty (most functions don't field-mutate their params)
    /// and elided from serialised output via `skip_serializing_if` so
    /// pre-Phase-5 summaries deserialise cleanly without migration.
    /// Built by extraction in `summary_extract.rs` when the per-body
    /// [`crate::pointer::PointsToFacts`] are available
    /// (`NYX_POINTER_ANALYSIS=1`); empty otherwise.
    #[serde(default, skip_serializing_if = "FieldPointsToSummary::is_empty")]
    pub field_points_to: FieldPointsToSummary,
    /// Per-return-path abstract [`PathFact`] decomposition.
    ///
    /// When non-empty, supplies per-predicate-gate facts finer than the
    /// aggregate `return_abstract.path` (which is the join over all
    /// return blocks and loses narrowing on any block whose rv is Top).
    /// Each entry records the fact on one distinct predicate gate and,
    /// when the rv is a structural one-arg variant constructor, the
    /// inner fact so match-arm-sensitive callers can pick the arm-
    /// specific fact.
    ///
    /// Empty for callees whose return blocks produce no non-Top fact,
    /// or whose single return path makes the aggregate already precise.
    /// Cross-file callers that cannot pick a specific path fall back to
    /// joining the entries, equivalent to the pre-decomposition
    /// behaviour.
    #[serde(default, skip_serializing_if = "SmallVec::is_empty")]
    pub return_path_facts: SmallVec<[PathFactReturnEntry; 2]>,
    /// Per-call-site receiver-type info: `(call_ordinal, container_name)`.
    ///
    /// Populated during SSA lowering (`lower_all_functions_from_bodies`)
    /// when type-fact analysis can resolve a method call's receiver SSA
    /// value to a concrete [`crate::ssa::type_facts::TypeKind`] with a
    /// non-empty [`crate::ssa::type_facts::TypeKind::container_name`].
    ///
    /// Consumed by [`crate::callgraph::build_call_graph`] to feed
    /// `CalleeQuery.receiver_type` for the matching ordinal, letting
    /// the call graph narrow indirect method-call edges to only those
    /// targets whose defining container matches the inferred type.
    /// Strictly additive: an empty map means today's name-only
    /// resolution applies unchanged.
    ///
    /// Ordinal here is the per-function `CallMeta.call_ordinal` shared
    /// with [`crate::summary::CalleeSite::ordinal`] so the two tables
    /// can be joined by ordinal at call-graph build time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub typed_call_receivers: Vec<(u32, String)>,
}

/// A per-return-path [`PathFact`] entry.
///
/// `SsaFuncSummary.param_return_paths` decomposes taint transforms by
/// predicate hash; `PathFactReturnEntry` records the matching decomposition
/// for the abstract [`PathFact`] on the return SSA value.  Each entry keys
/// on the same `predicate_hash` so the two vectors can be joined at the
/// call site.
///
/// `variant_inner_fact` captures the *inner* fact when the return value on
/// this path is a recognised one-argument variant constructor (e.g.
/// `Some(s)` / `Ok(s)`).  Callers that destructure the call result via a
/// `match` or `if let` use the inner fact in the matching arm instead of
/// the outer wrapper's fact.  `None` when the return rv is not a variant
/// wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathFactReturnEntry {
    /// Deterministic hash of the predicate gate at this return block.
    /// `0` = unguarded return.  Shares the same hash space as
    /// [`ReturnPathTransform::path_predicate_hash`] so the two tables
    /// align per-path.
    pub predicate_hash: u64,
    /// `PredicateSummary::known_true` bits that hold on every path into
    /// this return (same encoding as
    /// [`ReturnPathTransform::known_true`]).
    pub known_true: u8,
    /// `PredicateSummary::known_false` bits at this return.
    pub known_false: u8,
    /// The return value's [`PathFact`] on this path.
    pub path_fact: PathFact,
    /// Inner [`PathFact`] when the rv on this path is a one-arg variant
    /// constructor; [`None`] otherwise.  Match-arm-sensitive callers
    /// consume this in the variant-binding arm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_inner_fact: Option<PathFact>,
}

impl PathFactReturnEntry {
    /// Dedup key.  Two entries with identical `(predicate_hash,
    /// path_fact, variant_inner_fact)` describe the same abstract return
    /// under the same predicate gate and collapse losslessly.
    pub fn dedup_key(&self) -> (u64, &PathFact, Option<&PathFact>) {
        (
            self.predicate_hash,
            &self.path_fact,
            self.variant_inner_fact.as_ref(),
        )
    }
}

/// Maximum per-summary [`PathFactReturnEntry`] count.
///
/// Mirrors [`MAX_RETURN_PATHS`]: a return-heavy callee pays bounded space
/// while still preserving the typical 2-4 path decomposition.
pub const MAX_PATH_FACT_RETURN_ENTRIES: usize = 8;

/// Merge `incoming` into `existing`, deduping by
/// [`PathFactReturnEntry::dedup_key`].  Entries whose
/// `predicate_hash` matches but whose facts differ are joined
/// (component-wise fact join) so the resulting entry over-approximates
/// both paths.  Caps the result at
/// [`MAX_PATH_FACT_RETURN_ENTRIES`]; overflow collapses into a single
/// Top-predicate entry whose fact is the join of all dropped entries'
/// facts.
pub fn merge_path_fact_return_paths(
    existing: &mut SmallVec<[PathFactReturnEntry; 2]>,
    incoming: &[PathFactReturnEntry],
) {
    for new_entry in incoming {
        if let Some(slot) = existing
            .iter_mut()
            .find(|e| e.predicate_hash == new_entry.predicate_hash)
        {
            // Same predicate gate: join facts (component-wise over-approximation).
            slot.path_fact = slot.path_fact.join(&new_entry.path_fact);
            slot.variant_inner_fact = match (
                slot.variant_inner_fact.take(),
                &new_entry.variant_inner_fact,
            ) {
                (Some(a), Some(b)) => Some(a.join(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            };
            // Intersect known_true / known_false: only bits proved on
            // every path into this predicate gate survive.
            slot.known_true &= new_entry.known_true;
            slot.known_false &= new_entry.known_false;
        } else {
            existing.push(new_entry.clone());
        }
    }
    if existing.len() > MAX_PATH_FACT_RETURN_ENTRIES {
        let mut joined_fact = PathFact::bottom();
        let mut joined_inner: Option<PathFact> = None;
        let mut kt = u8::MAX;
        let mut kf = u8::MAX;
        for e in existing.iter() {
            joined_fact = joined_fact.join(&e.path_fact);
            joined_inner = match (joined_inner, &e.variant_inner_fact) {
                (None, None) => None,
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b.clone()),
                (Some(a), Some(b)) => Some(a.join(b)),
            };
            kt &= e.known_true;
            kf &= e.known_false;
        }
        existing.clear();
        existing.push(PathFactReturnEntry {
            predicate_hash: 0,
            known_true: kt,
            known_false: kf,
            path_fact: joined_fact,
            variant_inner_fact: joined_inner,
        });
    }
}

/// Union-merge two `param_return_paths` lists keyed by parameter
/// index.  Each parameter keeps its own deduped [`ReturnPathTransform`] list,
/// joining abstract contributions on collision and enforcing the
/// [`MAX_RETURN_PATHS`] cap.  Used by merge paths that combine summaries
/// across iterations or files (SSA summaries are currently last-writer-wins
/// in `GlobalSummaries`, but this helper is the entry point future union
/// paths should call so per-path semantics stay centralised).
pub fn union_param_return_paths(
    existing: &mut Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)>,
    incoming: &[(usize, SmallVec<[ReturnPathTransform; 2]>)],
) {
    for (idx, paths) in incoming {
        if let Some((_, slot)) = existing.iter_mut().find(|(i, _)| *i == *idx) {
            merge_return_paths(slot, paths);
        } else {
            let mut fresh: SmallVec<[ReturnPathTransform; 2]> = SmallVec::new();
            merge_return_paths(&mut fresh, paths);
            existing.push((*idx, fresh));
        }
    }
}

impl SsaFuncSummary {
    /// Per-parameter union of [`Cap`] bits across every [`SinkSite`] recorded
    /// for that parameter.
    ///
    /// Returns one `(param_index, caps)` pair per distinct parameter, with
    /// `caps` being the bitwise OR of every site's own `cap`.  This is the
    /// backward-compatible view that pre-`SinkSite` consumers (resolver,
    /// taint engine) still rely on.
    pub fn param_to_sink_caps(&self) -> Vec<(usize, Cap)> {
        self.param_to_sink
            .iter()
            .map(|(idx, sites)| {
                let caps = sites.iter().fold(Cap::empty(), |acc, s| acc | s.cap);
                (*idx, caps)
            })
            .collect()
    }

    /// Total [`Cap`] bits reached across every parameter's recorded sink sites.
    pub fn total_param_sink_caps(&self) -> Cap {
        self.param_to_sink
            .iter()
            .flat_map(|(_, sites)| sites.iter())
            .fold(Cap::empty(), |acc, s| acc | s.cap)
    }
}

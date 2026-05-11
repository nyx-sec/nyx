//! Context-sensitive inline analysis, cache, body, and attribution types.
//!
//! The cache ([`InlineCache`]) is keyed by `(FuncKey, ArgTaintSig)`,
//! where [`ArgTaintSig`] is per-arg cap bits only (not origin identity).
//! Stored values ([`CachedInlineShape`]) capture the structural shape of
//! the callee's return taint; caller-specific origins are re-attributed
//! at apply time.

use crate::labels::Cap;
use crate::ssa::ir::{SsaBody, Terminator};
use crate::summary::ssa_summary::PathFactReturnEntry;
use crate::symbol::FuncKey;
use crate::taint::domain::{TaintOrigin, VarTaint};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::HashMap;

/// Maximum SSA blocks in a callee body before skipping inline analysis.
pub(super) const MAX_INLINE_BLOCKS: usize = 500;

/// Compact cache key: per-arg-position cap bits (sorted, non-empty
/// only). Origin identity is not part of the key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ArgTaintSig(pub(super) SmallVec<[(usize, u32); 4]>);

/// Call-site-adapted result of inline-analyzing a callee. Built fresh
/// per call site so origins point to the current caller's chain.
#[derive(Clone, Debug)]
pub(crate) struct InlineResult {
    pub(super) return_taint: Option<VarTaint>,
    /// PathFact on the return value. Non-top when the callee body
    /// provably narrows it (e.g. a `sanitize_path` early-returning on
    /// `s.contains("..")`).
    pub(super) return_path_fact: crate::abstract_interp::PathFact,
    /// Per-return-path decomposition of `return_path_fact`. Non-empty
    /// when the callee has ≥2 return blocks with different predicate
    /// gates.
    #[allow(dead_code)]
    pub(super) return_path_facts: SmallVec<[PathFactReturnEntry; 2]>,
}

/// Structural (callsite-agnostic) summary of an inline-analyzed
/// callee. `None` means "no return taint for this arg shape", still
/// meaningful, short-circuits subsequent calls with matching caps.
#[derive(Clone, Debug)]
pub(crate) struct CachedInlineShape(pub(super) Option<ReturnShape>);

/// Structural parts of a non-trivial inline-analysis result.
///
/// Split from the full [`VarTaint`] so that cached entries can be re-used
/// across call sites with matching arg-cap signatures but differing source
/// origins.  See the module-level note above on origin attribution.
#[derive(Clone, Debug)]
pub(crate) struct ReturnShape {
    /// Return value caps (cap bits only, structural).
    pub(super) caps: Cap,
    /// Origins produced **inside the callee body** (e.g. `Source` op fired
    /// in the callee).  `node` is set to a placeholder; at apply time the
    /// caller remaps it to its own call-site NodeIndex.  `source_span` is
    /// stable (from the callee CFG) and preserved as-is.
    pub(super) internal_origins: SmallVec<[TaintOrigin; 2]>,
    /// Bit i set = callee's `Param(i)` seed taint reached the return value.
    /// At apply time, caller arg origins at matching positions are
    /// unioned into the applied `VarTaint`. Params beyond 63 are
    /// dropped (matches `SmallBitSet`); rare and still cap-correct.
    pub(super) param_provenance: u64,
    /// Whether the receiver (`SelfParam`) seed taint flowed to return.
    pub(super) receiver_provenance: bool,
    pub(super) uses_summary: bool,
    /// PathFact of the return value, observed from the callee exit
    /// state under Top-seeded Params. Describes the callee's intrinsic
    /// narrowing.
    pub(super) return_path_fact: crate::abstract_interp::PathFact,
    /// Per-return-path decomposition of the return value. Populated
    /// when the callee has ≥2 return blocks with different predicates.
    pub(super) return_path_facts: SmallVec<[PathFactReturnEntry; 2]>,
}

impl CachedInlineShape {
    /// Cap bits of the return value, or zero if this shape records "no
    /// return taint".  Used by [`inline_cache_fingerprint`].
    fn return_caps_bits(&self) -> u32 {
        self.0.as_ref().map(|s| s.caps.bits()).unwrap_or(0)
    }
}

/// Cache for context-sensitive inline analysis results, keyed by
/// canonical [`FuncKey`] so same-name definitions in different scopes
/// never collide.
pub(crate) type InlineCache = HashMap<(FuncKey, ArgTaintSig), CachedInlineShape>;

/// Drop every entry from the inline cache between SCC fixpoint
/// iterations so stale results don't leak forward.
#[allow(dead_code)]
pub(crate) fn inline_cache_clear_epoch(cache: &mut InlineCache) {
    cache.clear();
}

/// Set-equal fingerprint of the inline cache, used by the SCC
/// orchestrator to detect convergence.
#[allow(dead_code)]
pub(crate) fn inline_cache_fingerprint(
    cache: &InlineCache,
) -> HashMap<(FuncKey, ArgTaintSig), u32> {
    cache
        .iter()
        .map(|(k, v)| (k.clone(), v.return_caps_bits()))
        .collect()
}

/// CFG node metadata embedded in cross-file callee bodies.
///
/// Stores a full serde-able [`crate::cfg::NodeInfo`] snapshot rather
/// than projecting individual fields, so the indexed-scan path can
/// rehydrate an equivalent `Cfg` (see [`rebuild_body_graph`]) and feed
/// the same `&Cfg` into the taint engine regardless of whether the
/// body came from pass 1 or SQLite.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrossFileNodeMeta {
    /// Full `NodeInfo` snapshot for this body-local NodeIndex.
    pub info: crate::cfg::NodeInfo,
}

/// Pre-lowered and optimized SSA body for a function,
/// ready for context-sensitive re-analysis with different argument taint.
///
/// For intra-file use, `node_meta` is empty and the original CFG is used.
/// For cross-file persistence, `node_meta` carries the minimal CFG
/// metadata needed by the symex executor.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CalleeSsaBody {
    pub ssa: SsaBody,
    pub opt: crate::ssa::OptimizeResult,
    pub param_count: usize,
    /// Per-NodeIndex CFG metadata for cross-file bodies.
    /// Empty for intra-file bodies (the original CFG is used instead).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub node_meta: std::collections::HashMap<u32, CrossFileNodeMeta>,
    /// The body's own CFG graph.  Populated for intra-file bodies so that
    /// inline analysis can reference the correct graph (per-body CFGs have
    /// body-local NodeIndex spaces).  `None` for cross-file deserialized
    /// bodies.
    #[serde(skip)]
    pub body_graph: Option<crate::cfg::Cfg>,
    /// The callee body's own file-level cross-package import map (Phase 09
    /// step 0.7 keyset).
    ///
    /// Populated when the body is freshly lowered with the file's
    /// [`crate::cfg::FileCfg::resolved_imports`] in scope.  Forwarded into
    /// the inline-analysis child transfer so transitive cross-package
    /// resolution inside an inlined frame can land in
    /// `crate::summary::GlobalSummaries::ssa_by_key` using the callee's
    /// own import view rather than the caller's (which would mis-resolve
    /// names against the caller's package boundary).
    ///
    /// Wrapped in `Arc` so every body in a file shares one heap
    /// allocation; per-file bodies typically count in the tens to
    /// hundreds, and import maps are append-only after construction.
    /// `#[serde(skip)]` because the map is reproducible from the file's
    /// `resolved_imports` and bears no identity on its own; an indexed
    /// scan that loads a body from SQLite simply skips step 0.7 inside
    /// the inlined frame (same conservative behaviour as before this
    /// field existed).
    #[serde(skip)]
    pub cross_package_imports: std::sync::Arc<std::collections::HashMap<String, FuncKey>>,
}

/// Populate `node_meta` from the original CFG for cross-file persistence.
///
/// Returns `true` if all referenced NodeIndex values were resolved
/// successfully.  Returns `false` if any node was out of bounds (body is
/// ineligible for cross-file use).
pub fn populate_node_meta(body: &mut CalleeSsaBody, cfg: &crate::cfg::Cfg) -> bool {
    // Collect every NodeIndex this body references, then snapshot each one's
    // NodeInfo into `node_meta`.  Done in two passes so the inner loop can
    // mutate `body.node_meta` without borrow-checker conflicts on
    // `body.ssa.blocks`.
    //
    // `Terminator::Branch.cond` must be captured as well: it is consumed by
    // `compute_succ_states` via `cfg[*cond]`, so without it the synthesized
    // cross-file proxy CFG (`rebuild_body_graph`) ends up too small whenever
    // the callee body has any conditional branch whose `cond` index sits
    // past the maximum `inst.cfg_node` index, inline analysis then panics
    // with an out-of-bounds index.
    let mut referenced: Vec<NodeIndex> = Vec::new();
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            referenced.push(inst.cfg_node);
        }
        if let Terminator::Branch { cond, .. } = &block.terminator {
            referenced.push(*cond);
        }
    }
    for node in referenced {
        let idx = node.index() as u32;
        if body.node_meta.contains_key(&idx) {
            continue;
        }
        if node.index() >= cfg.node_count() {
            return false;
        }
        let info = cfg[node].clone();
        body.node_meta.insert(idx, CrossFileNodeMeta { info });
    }
    true
}

/// Synthesize a proxy [`crate::cfg::Cfg`] from `node_meta` so the taint
/// engine can index `cfg[inst.cfg_node]` uniformly on the indexed-scan
/// path.
///
/// When the callee body was loaded from SQLite, `body_graph` is `None`
/// (it is `#[serde(skip)]`), but `node_meta` carries a full
/// [`crate::cfg::NodeInfo`] for every referenced NodeIndex (see
/// [`populate_node_meta`]).  This helper rebuilds a petgraph `Cfg` with
/// nodes at exactly the right NodeIndex positions so the taint engine's
/// existing indexing works without change.
///
/// Returns `true` if a proxy graph was freshly installed.  Idempotent:
/// subsequent calls are cheap no-ops once `body_graph` is `Some`.  No-op
/// for intra-file bodies (which arrive with `body_graph` already set and
/// `node_meta` empty).
pub fn rebuild_body_graph(body: &mut CalleeSsaBody) -> bool {
    if body.body_graph.is_some() {
        return false;
    }
    if body.node_meta.is_empty() {
        return false;
    }
    // Determine the maximum NodeIndex referenced by the SSA so the
    // synthesized graph has an entry at every position the engine may
    // index.  We fill any unreferenced intermediate indices with
    // `NodeInfo::default()`.
    //
    // Walks both instruction `cfg_node`s and `Terminator::Branch.cond` ,
    // the latter is read by `compute_succ_states` via `cfg[*cond]`, so
    // missing it produces an OOB panic when a conditional branch's cond
    // node has a higher index than any `inst.cfg_node` in the body.
    let mut max_idx: u32 = 0;
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let idx = inst.cfg_node.index() as u32;
            if idx > max_idx {
                max_idx = idx;
            }
        }
        if let Terminator::Branch { cond, .. } = &block.terminator {
            let idx = cond.index() as u32;
            if idx > max_idx {
                max_idx = idx;
            }
        }
    }
    // Also consider node_meta keys, they should be a subset of the
    // SSA-referenced indices, but be defensive.
    for &k in body.node_meta.keys() {
        if k > max_idx {
            max_idx = k;
        }
    }

    use petgraph::graph::Graph;
    let mut graph: crate::cfg::Cfg = Graph::new();
    // petgraph allocates sequential NodeIndex values.  Insert placeholders
    // up to and including max_idx.
    for i in 0..=max_idx {
        let info = body
            .node_meta
            .get(&i)
            .map(|m| m.info.clone())
            .unwrap_or_default();
        graph.add_node(info);
    }
    // Edges are not consulted by the taint engine during inline analysis
    // (control flow comes from `SsaBlock::preds`/`succs` and
    // `SsaBlock::terminator`), so we leave the graph edge-free.
    body.body_graph = Some(graph);
    true
}

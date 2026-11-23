//! Incremental pass 2 for indexed scans.
//!
//! Pass 2 analyses each file against the shared [`GlobalSummaries`] in
//! call-graph order.  A file's result depends on its bytes, the analysis
//! settings, and whatever shared state the analysis read.  Every analysis run
//! under this cache records those reads (see [`crate::summary::deps`]) and
//! stores them next to its output.  On the next scan a unit whose files are
//! unchanged and whose recorded reads still give the same answers against the
//! current state reuses its output instead of being analysed again.
//!
//! The output of a unit is the findings it produced plus the summary writes
//! it made, in order.  Replaying those writes on reuse leaves the shared state
//! exactly as a fresh analysis would, so later units see the same view either
//! way.
//!
//! A unit is one file of a non-recursive batch, one orphan file, or a whole
//! recursive batch (its fixed-point loop is cached as one piece).
//!
//! `NYX_INCREMENTAL_VERIFY=1` analyses every reusable unit anyway, compares
//! the result with the cached one, and keeps the fresh result.  With
//! `NYX_INCREMENTAL_DUMP=<dir>` as well, each differing unit's cached and
//! fresh outputs are written there as JSON.

use crate::callgraph::{CallGraph, FileBatch};
use crate::commands::scan::Diag;
use crate::database::index::Indexer;
use crate::errors::NyxResult;
use crate::summary::deps::{self, DepTrace};
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::summary::{FuncSummary, GlobalSummaries};
use crate::symbol::FuncKey;
use crate::utils::config::Config;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bump when the payload layout or the meaning of a cached unit changes.
const PAYLOAD_VERSION: u32 = 2;

/// `nyx_metadata` key holding [`cache_key`] of the stored units.
const CACHE_KEY_META: &str = "pass2_cache_key";

/// Environment variables that do not change analysis results.
const NEUTRAL_ENV: &[&str] = &[
    "NYX_INCREMENTAL_VERIFY",
    "NYX_INCREMENTAL_DUMP",
    "NYX_INCREMENTAL_EXPLAIN",
    "NYX_CONVERGENCE_TELEMETRY",
    "NYX_PROBE_CLOSURE",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum UnitKind {
    /// One file of a non-recursive batch.
    File,
    /// A recursive batch, run to a fixed point as a whole.
    Batch,
    /// A file with no function in the call graph.
    Orphan,
}

/// One write a unit made to the shared summaries, in the order it was made.
#[derive(Serialize, Deserialize)]
pub(crate) enum GsOp {
    Func(FuncKey, FuncSummary),
    Ssa(FuncKey, SsaFuncSummary),
    Body(FuncKey, crate::taint::ssa_transfer::CalleeSsaBody),
    Auth(FuncKey, crate::auth_analysis::model::AuthCheckSummary),
}

impl GsOp {
    /// Whether applying this write to `gs` changes nothing: the key already
    /// holds an equal value.  Coarse summaries merge, and the other maps
    /// replace, so an equal value leaves the entry as it was either way.
    pub(crate) fn is_noop(&self, gs: &GlobalSummaries) -> bool {
        use crate::summary::deps::{DepOracle, KeyedRead};
        let _quiet = deps::Suppress::new();
        let (kind, key, fp) = match self {
            GsOp::Func(k, s) => (KeyedRead::Func, k, deps::fp_value(s)),
            GsOp::Ssa(k, s) => (KeyedRead::Ssa, k, deps::fp_value(s)),
            GsOp::Body(k, b) => (KeyedRead::Body, k, deps::fp_value(b)),
            GsOp::Auth(k, a) => (KeyedRead::Auth, k, deps::fp_value(a)),
        };
        gs.keyed_fp(kind, key) == fp
    }

    /// Apply the write through the same entry point a fresh analysis uses.
    pub(crate) fn apply(self, gs: &mut GlobalSummaries) {
        match self {
            GsOp::Func(k, s) => gs.insert(k, s),
            GsOp::Ssa(k, s) => gs.insert_ssa(k, s),
            GsOp::Body(k, b) => gs.insert_body(k, b),
            GsOp::Auth(k, a) => gs.insert_auth(k, a),
        }
    }
}

/// Everything a unit hands back to the scan.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct UnitOutputs {
    pub diags: Vec<Diag>,
    pub ops: Vec<GsOp>,
}

/// Borrowed view of [`UnitOutputs`] with some writes left out.  Encodes to
/// the same layout, so it decodes as a `UnitOutputs`.
#[derive(Serialize)]
pub(crate) struct UnitOutputsView<'a> {
    pub diags: &'a [Diag],
    pub ops: Vec<&'a GsOp>,
}

impl<'a> UnitOutputsView<'a> {
    pub(crate) fn all(outputs: &'a UnitOutputs) -> Self {
        UnitOutputsView {
            diags: &outputs.diags,
            ops: outputs.ops.iter().collect(),
        }
    }

    /// `outputs` without the writes that would not change `gs`.  `gs` must
    /// be the state the unit was analysed against: a reused unit is
    /// replayed against the same state, so the dropped writes are no-ops
    /// there too.
    pub(crate) fn without_noops(outputs: &'a UnitOutputs, gs: &GlobalSummaries) -> Self {
        UnitOutputsView {
            diags: &outputs.diags,
            ops: outputs.ops.iter().filter(|op| !op.is_noop(gs)).collect(),
        }
    }
}

/// The part of a cached unit consulted before deciding to reuse it.
#[derive(Serialize, Deserialize)]
struct UnitHeader {
    kind: UnitKind,
    /// Member files with the content hash each was analysed at.
    members: Vec<(String, Vec<u8>)>,
    /// Structure of a recursive batch (see [`batch_shape`]); 0 otherwise.
    shape: u64,
    /// Fixed-point iterations a recursive batch took.
    iterations: usize,
    trace: DepTrace,
}

/// A reused unit.
pub(crate) struct Reused {
    pub outputs: UnitOutputs,
    pub iterations: usize,
}

/// Counters from the most recent incremental pass 2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pass2Stats {
    pub units_reused: usize,
    pub units_analysed: usize,
    pub verify_mismatches: usize,
}

static LAST_STATS: Mutex<Pass2Stats> = Mutex::new(Pass2Stats {
    units_reused: 0,
    units_analysed: 0,
    verify_mismatches: 0,
});

/// Counters of the most recent indexed scan's pass 2.  For tests and
/// diagnostics.
pub fn last_pass2_stats() -> Pass2Stats {
    *LAST_STATS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Test override for [`verify_enabled`]: 0 = follow the environment.
static VERIFY_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Turn verification on or off for later scans in this process, whatever
/// `NYX_INCREMENTAL_VERIFY` says.  For tests.
pub fn force_verify(on: bool) {
    VERIFY_OVERRIDE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
}

/// Whether reusable units are re-analysed and compared.
pub(crate) fn verify_enabled() -> bool {
    match VERIFY_OVERRIDE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => matches!(
            std::env::var("NYX_INCREMENTAL_VERIFY").as_deref(),
            Ok("1" | "true" | "TRUE" | "True")
        ),
    }
}

/// Everything besides file bytes and recorded reads that pass-2 results
/// depend on.  Units stored under another key are never reused.
pub(crate) fn cache_key(cfg: &Config, scan_root: &Path, topo_refine: bool) -> String {
    let mut h = blake3::Hasher::new();
    h.update(&PAYLOAD_VERSION.to_le_bytes());
    h.update(cfg.analysis_cache_key().as_bytes());
    h.update(scan_root.to_string_lossy().as_bytes());
    h.update(&[topo_refine as u8]);
    let graph_fp = cfg.module_graph.as_deref().map_or(deps::ABSENT, |g| {
        deps::fp_value(&(g.packages(), g.tsconfigs()))
    });
    h.update(&graph_fp.to_le_bytes());
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k.starts_with("NYX_") && !NEUTRAL_ENV.contains(&k.as_str()))
        .collect();
    env.sort();
    for (k, v) in env {
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(v.as_bytes());
        h.update(b"\n");
    }
    h.finalize().to_hex().to_string()
}

/// Key a unit is stored under.
pub(crate) fn unit_key(kind: UnitKind, files: &[&PathBuf]) -> String {
    match kind {
        UnitKind::File => format!("file:{}", files[0].display()),
        UnitKind::Orphan => format!("orphan:{}", files[0].display()),
        UnitKind::Batch => {
            let mut h = blake3::Hasher::new();
            for f in files {
                h.update(f.to_string_lossy().as_bytes());
                h.update(b"\0");
            }
            format!("batch:{}", h.finalize().to_hex())
        }
    }
}

/// Fingerprint of what a recursive batch's fixed-point loop depends on
/// beyond its files and recorded reads: file order, the fixed-point groups,
/// and the call edges between member functions (they pick the files each
/// iteration re-analyses).
pub(crate) fn batch_shape(
    batch: &FileBatch<'_>,
    call_graph: &CallGraph,
    scan_root: Option<&Path>,
    cfg: &Config,
) -> u64 {
    use petgraph::visit::EdgeRef;
    let root = scan_root.map(|r| r.to_string_lossy());
    let mg = cfg.module_graph.as_deref();
    let namespaces: HashSet<String> = batch
        .files
        .iter()
        .map(|p| crate::symbol::namespace_with_package(&p.to_string_lossy(), root.as_deref(), mg))
        .collect();
    let mut edges: Vec<(u64, u64)> = call_graph
        .graph
        .edge_references()
        .filter_map(|e| {
            let from = &call_graph.graph[e.source()];
            let to = &call_graph.graph[e.target()];
            (namespaces.contains(&from.namespace) && namespaces.contains(&to.namespace)).then(
                || {
                    (
                        deps::fp_keys(std::iter::once(from)),
                        deps::fp_keys(std::iter::once(to)),
                    )
                },
            )
        })
        .collect();
    edges.sort_unstable();
    edges.dedup();
    let groups: Vec<(usize, bool)> = (0..batch.files.len())
        .map(|i| {
            let g = batch.group_of(i);
            (g, batch.group_is_cross_file(g))
        })
        .collect();
    let files: Vec<String> = batch
        .files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    deps::fp_value(&(files, groups, batch.cross_file, edges))
}

const MAGIC: &[u8; 4] = b"NXP2";

fn encode_payload(header: &UnitHeader, outputs: &[u8]) -> Option<Vec<u8>> {
    let head = rmp_serde::to_vec_named(header).ok()?;
    let mut out = Vec::with_capacity(16 + head.len() + outputs.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
    out.extend_from_slice(&(head.len() as u64).to_le_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(outputs);
    Some(out)
}

/// Split a stored payload into its header and encoded outputs.
fn decode_payload(payload: &[u8]) -> Option<(UnitHeader, &[u8])> {
    if payload.len() < 16 || &payload[..4] != MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    if version != PAYLOAD_VERSION {
        return None;
    }
    let head_len = u64::from_le_bytes(payload[8..16].try_into().ok()?) as usize;
    let head_end = 16usize.checked_add(head_len)?;
    if head_end > payload.len() {
        return None;
    }
    let header: UnitHeader = rmp_serde::from_slice(&payload[16..head_end]).ok()?;
    Some((header, &payload[head_end..]))
}

pub(crate) fn encode_outputs(outputs: &UnitOutputsView<'_>) -> Option<Vec<u8>> {
    rmp_serde::to_vec_named(outputs).ok()
}

fn decode_outputs(bytes: &[u8]) -> Option<UnitOutputs> {
    let mut outputs: UnitOutputs = rmp_serde::from_slice(bytes).ok()?;
    for op in &mut outputs.ops {
        if let GsOp::Body(_, body) = op {
            // Same rehydration the summary loader applies to stored bodies.
            crate::taint::ssa_transfer::rebuild_body_graph(body);
        }
    }
    Some(outputs)
}

/// Cached pass-2 units of one indexed scan, plus the units it produces.
pub(crate) struct Pass2Cache {
    /// Stored payloads by unit key, decoded when a unit is looked up (on
    /// the worker that analyses it) rather than all at once at load.
    units: HashMap<String, Vec<u8>>,
    /// Content hash of every file pass 1 read successfully this scan.
    hashes: HashMap<PathBuf, Vec<u8>>,
    verify: bool,
    fresh: Mutex<Vec<(String, Vec<u8>)>>,
    used: Mutex<HashSet<String>>,
    /// Files of every unit analysed this scan (whose findings may differ
    /// from the stored ones).
    analysed_paths: Mutex<HashSet<PathBuf>>,
    reused: AtomicUsize,
    analysed: AtomicUsize,
    verify_mismatches: AtomicUsize,
}

impl Pass2Cache {
    /// Load the stored units, dropping them all when `key` differs from the
    /// key they were written under.
    pub(crate) fn load(
        idx: &Indexer,
        key: &str,
        hashes: HashMap<PathBuf, Vec<u8>>,
    ) -> NyxResult<Self> {
        let rows = if idx.get_metadata(CACHE_KEY_META)?.as_deref() == Some(key) {
            idx.load_pass2_units()?
        } else {
            idx.clear_pass2_units()?;
            idx.set_metadata(CACHE_KEY_META, key)?;
            Vec::new()
        };
        let units = rows.into_iter().collect();
        Ok(Pass2Cache {
            units,
            hashes,
            verify: verify_enabled(),
            fresh: Mutex::new(Vec::new()),
            used: Mutex::new(HashSet::new()),
            analysed_paths: Mutex::new(HashSet::new()),
            reused: AtomicUsize::new(0),
            analysed: AtomicUsize::new(0),
            verify_mismatches: AtomicUsize::new(0),
        })
    }

    pub(crate) fn verify(&self) -> bool {
        self.verify
    }

    fn mark_used(&self, key: &str) {
        self.used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string());
    }

    fn members(&self, files: &[&PathBuf]) -> Option<Vec<(String, Vec<u8>)>> {
        files
            .iter()
            .map(|f| {
                self.hashes
                    .get(*f)
                    .map(|h| (f.to_string_lossy().into_owned(), h.clone()))
            })
            .collect()
    }

    /// The cached outputs of `key` when they are still valid against `gs`.
    pub(crate) fn lookup(
        &self,
        key: &str,
        kind: UnitKind,
        files: &[&PathBuf],
        shape: u64,
        gs: &GlobalSummaries,
    ) -> Option<Reused> {
        let explain = std::env::var_os("NYX_INCREMENTAL_EXPLAIN").is_some();
        let Some((h, outputs)) = self.units.get(key).and_then(|p| decode_payload(p)) else {
            if explain {
                tracing::info!(unit = key, "pass-2 miss: no readable stored unit");
            }
            return None;
        };
        if h.kind != kind || h.shape != shape || Some(&h.members) != self.members(files).as_ref() {
            if explain {
                tracing::info!(unit = key, "pass-2 miss: files or batch shape changed");
            }
            return None;
        }
        if !h.trace.holds(gs) {
            if explain {
                let misses = h.trace.misses(gs);
                tracing::info!(
                    unit = key,
                    count = misses.len(),
                    reads = %misses.join(" | "),
                    "pass-2 miss: read changed"
                );
            }
            return None;
        }
        let outputs = decode_outputs(outputs)?;
        self.mark_used(key);
        self.reused.fetch_add(1, Ordering::Relaxed);
        Some(Reused {
            outputs,
            iterations: h.iterations,
        })
    }

    /// Record a freshly analysed unit.  Units with a member whose bytes
    /// pass 1 could not read are not stored.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store(
        &self,
        key: &str,
        kind: UnitKind,
        files: &[&PathBuf],
        shape: u64,
        iterations: usize,
        trace: DepTrace,
        outputs: &[u8],
    ) {
        self.analysed.fetch_add(1, Ordering::Relaxed);
        self.analysed_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(files.iter().map(|f| (*f).clone()));
        let Some(members) = self.members(files) else {
            return;
        };
        if trace.is_opaque() {
            tracing::debug!(unit = key, "pass-2 unit read shared state it cannot replay");
        }
        let header = UnitHeader {
            kind,
            members,
            shape,
            iterations,
            trace,
        };
        let Some(payload) = encode_payload(&header, outputs) else {
            return;
        };
        self.mark_used(key);
        self.fresh
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((key.to_string(), payload));
    }

    /// Compare a reused unit with a fresh analysis of it.  Returns `true`
    /// when they agree.
    ///
    /// Both sides are compared as multisets: the engine emits a file's
    /// summaries in hash-map order, which changes from one process to the
    /// next, and the writes target distinct keys, so their order does not
    /// change the merged state.
    pub(crate) fn check(
        &self,
        key: &str,
        cached: &UnitOutputs,
        fresh: &UnitOutputsView<'_>,
    ) -> bool {
        fn multiset<T: Serialize>(items: impl IntoIterator<Item = T>) -> Vec<deps::Fp> {
            let mut fps: Vec<deps::Fp> = items.into_iter().map(|i| deps::fp_value(&i)).collect();
            fps.sort_unstable();
            fps
        }
        let diags_ok = multiset(&cached.diags) == multiset(fresh.diags);
        let ops_ok = multiset(&cached.ops) == multiset(&fresh.ops);
        if diags_ok && ops_ok {
            return true;
        }
        self.verify_mismatches.fetch_add(1, Ordering::Relaxed);
        let first_diff = cached
            .ops
            .iter()
            .zip(fresh.ops.iter())
            .position(|(a, b)| deps::fp_value(a) != deps::fp_value(*b));
        let describe = |op: Option<&GsOp>| match op {
            Some(GsOp::Func(k, _)) => format!("func {k}"),
            Some(GsOp::Ssa(k, _)) => format!("ssa {k}"),
            Some(GsOp::Body(k, _)) => format!("body {k}"),
            Some(GsOp::Auth(k, _)) => format!("auth {k}"),
            None => "none".to_string(),
        };
        if let Some(dir) = std::env::var_os("NYX_INCREMENTAL_DUMP") {
            let name: String = key
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            let dir = PathBuf::from(dir);
            let _ = std::fs::create_dir_all(&dir);
            let cached = UnitOutputsView::all(cached);
            for (tag, out) in [("cached", &cached), ("fresh", fresh)] {
                if let Ok(json) = serde_json::to_string_pretty(out) {
                    let _ = std::fs::write(dir.join(format!("{name}.{tag}.json")), json);
                }
            }
        }
        tracing::warn!(
            first_differing_write = %describe(first_diff.and_then(|i| cached.ops.get(i))),
            cached_writes = cached.ops.len(),
            fresh_writes = fresh.ops.len(),
            unit = key,
            diags_match = diags_ok,
            writes_match = ops_ok,
            cached_findings = cached.diags.len(),
            fresh_findings = fresh.diags.len(),
            "incremental pass 2: reused unit differs from a fresh analysis"
        );
        false
    }

    /// Files of every unit analysed so far this scan.
    pub(crate) fn analysed_paths(&self) -> HashSet<PathBuf> {
        self.analysed_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Persist new units, drop units this scan no longer has, and publish
    /// the counters.
    pub(crate) fn finish(self, idx: &mut Indexer) -> NyxResult<Pass2Stats> {
        let stats = Pass2Stats {
            units_reused: self.reused.load(Ordering::Relaxed),
            units_analysed: self.analysed.load(Ordering::Relaxed),
            verify_mismatches: self.verify_mismatches.load(Ordering::Relaxed),
        };
        *LAST_STATS.lock().unwrap_or_else(|e| e.into_inner()) = stats;
        let fresh = self.fresh.into_inner().unwrap_or_else(|e| e.into_inner());
        let used = self.used.into_inner().unwrap_or_else(|e| e.into_inner());
        idx.write_pass2_units(&fresh, &used)?;
        Ok(stats)
    }
}

/// Run `analyse` with a dependency trace when `cache` is set.
pub(crate) fn traced<R>(cache: Option<&Pass2Cache>, analyse: impl FnOnce() -> R) -> (R, DepTrace) {
    if cache.is_none() {
        return (analyse(), DepTrace::default());
    }
    let guard = deps::start_trace();
    let out = analyse();
    (out, guard.finish())
}

//! Per-function summaries for cross-file taint analysis.
//!
//! [`FuncSummary`] describes a function's boundary behaviour: which parameters
//! flow to sinks, which sources it reads, whether it propagates taint from
//! arguments to its return value, and what capabilities it strips. Summaries
//! are serialized to SQLite in pass 1 and merged into [`GlobalSummaries`]
//! before pass 2 begins.
//!
//! [`crate::summary::ssa_summary::SsaFuncSummary`] is a richer summary
//! derived from the SSA taint engine and takes precedence over [`FuncSummary`]
//! during call resolution. [`GlobalSummaries::ssa_by_key`] stores SSA summaries
//! keyed by [`FuncKey`]; [`GlobalSummaries::by_name`] holds the fallback
//! name-keyed map for cases where an exact key is not found.
//!
//! Same-name collisions across files are merged conservatively: capabilities
//! are unioned and booleans are OR-ed so no true positive is silently dropped.

pub mod points_to;
pub mod ssa_summary;

use crate::labels::Cap;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::{FuncKey, FuncKind, Lang, normalize_namespace};
use serde::{Deserialize, Deserializer, Serialize};
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

// ── Sink site (primary sink-location attribution) ───────────────────────

/// A single dangerous-instruction site inside a function's body.
/// Pairs a [`Cap`] with the source location of the consuming
/// instruction so cross-file findings can attribute to the callee
/// rather than the caller call-site.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SinkSite {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_rel: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub line: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub col: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snippet: String,
    pub cap: Cap,
}

impl SinkSite {
    /// Dedup key: two sites with the same `(file_rel, line, col, cap)`
    /// describe the same consumption and collapse on merge.
    pub(crate) fn dedup_key(&self) -> (&str, u32, u32, u16) {
        (self.file_rel.as_str(), self.line, self.col, self.cap.bits())
    }

    /// Build a cap-only site for extraction paths with no tree/bytes
    /// context (pass-2 transient summaries).
    pub fn cap_only(cap: Cap) -> Self {
        Self {
            file_rel: String::new(),
            line: 0,
            col: 0,
            snippet: String::new(),
            cap,
        }
    }
}

/// Tree/bytes context for resolving a CFG span to a [`SinkSite`].
/// Threaded as `Option<&Locator>` so extraction paths without tree
/// access can pass `None` cheaply.
pub struct SinkSiteLocator<'a> {
    pub tree: &'a tree_sitter::Tree,
    pub bytes: &'a [u8],
    pub file_rel: &'a str,
}

impl<'a> SinkSiteLocator<'a> {
    /// Resolve a span to a [`SinkSite`]. Coordinates fall back to
    /// `(0, 0)` and the snippet to empty when out of range.
    pub fn site_for_span(&self, span: (usize, usize), cap: Cap) -> SinkSite {
        let byte = span.0;
        let point = self
            .tree
            .root_node()
            .descendant_for_byte_range(byte, byte)
            .map(|n| n.start_position())
            .unwrap_or(tree_sitter::Point { row: 0, column: 0 });
        let snippet = line_snippet(self.bytes, byte).unwrap_or_default();
        SinkSite {
            file_rel: self.file_rel.to_string(),
            line: (point.row + 1) as u32,
            col: (point.column + 1) as u32,
            snippet,
            cap,
        }
    }
}

pub(crate) use crate::utils::snippet::line_snippet;

/// Union two `SmallVec<[SinkSite; 1]>` lists with `(file_rel, line, col,
/// cap)` dedup.  Preserves insertion order of `existing` then appends any
/// new sites from `incoming` not already present.
pub(crate) fn union_sink_sites(existing: &mut SmallVec<[SinkSite; 1]>, incoming: &[SinkSite]) {
    for site in incoming {
        let key = site.dedup_key();
        if !existing.iter().any(|s| s.dedup_key() == key) {
            existing.push(site.clone());
        }
    }
}

/// Union two `Vec<(usize, SmallVec<[SinkSite; 1]>)>` lists keyed by
/// parameter index.  Each parameter keeps its own deduped site list.
pub(crate) fn union_param_sink_sites(
    existing: &mut Vec<(usize, SmallVec<[SinkSite; 1]>)>,
    incoming: &[(usize, SmallVec<[SinkSite; 1]>)],
) {
    for (idx, sites) in incoming {
        if let Some((_, ex)) = existing.iter_mut().find(|(i, _)| *i == *idx) {
            union_sink_sites(ex, sites);
        } else {
            existing.push((*idx, sites.clone()));
        }
    }
}

/// Top bit of [`FuncKey::disambig`] reserved for synthetic discriminators
/// minted by [`GlobalSummaries`] when an identity collision is detected
/// between structurally incompatible summaries.
///
/// Real disambigs come from `tree_sitter::Node::start_byte` (see
/// `cfg.rs:fn_disambig`), which is a byte offset into the source file.
/// Source files in practice are far below 2 GiB, so bit 31 of a real
/// disambig is always zero, setting it marks a value as synthetic and
/// keeps it in a disjoint namespace from byte-offset disambigs.
const SYNTHETIC_DISAMBIG_BIT: u32 = 0x8000_0000;

// ── Callee site metadata ────────────────────────────────────────────────

/// Richer per-call-site metadata preserved in a function's summary.
///
/// Replaces the legacy `Vec<String>` callee list.  Carries enough structure
/// to disambiguate same-name overloads and method calls at resolution time
/// without having to re-parse the raw callee string.
///
/// * `name`, the raw callee text as it appeared in source
///   (`"obj.method"`, `"env::var"`, `"helper"`). Preserved for diagnostics.
/// * `arity`, number of positional arguments at the call site.  `None`
///   when splats / keyword-args / rest-params make the count unreliable.
/// * `receiver`, structured receiver identifier for method calls
///   (e.g. `"obj"` in `obj.method()`).  Carries the root receiver for
///   chained calls; `None` for non-method or complex receivers.
/// * `qualifier`, the segment immediately before the leaf for non-method
///   qualified calls (e.g. `"env"` in `env::var`).  Extracted once at CFG
///   time rather than re-parsed downstream.
/// * `ordinal`, the per-function call ordinal matching
///   `CallMeta.call_ordinal`, allowing cross-file consumers to address a
///   specific call site rather than just a callee name.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CalleeSite {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ordinal: u32,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

impl CalleeSite {
    /// Construct a bare call-site reference from a name, with no other metadata.
    pub fn bare(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

impl From<String> for CalleeSite {
    fn from(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }
}

impl From<&str> for CalleeSite {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }
}

/// Deserialize a `Vec<CalleeSite>` while tolerating the legacy
/// on-disk form where callees were a plain array of strings.
///
/// Accepts:
///   * `[{"name": "foo", "arity": 1, ...}, ...]`  ← current structured form
///   * `["foo", "bar", ...]`                       ← legacy string form
fn deserialize_callee_sites<'de, D>(de: D) -> Result<Vec<CalleeSite>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Entry {
        Structured(CalleeSite),
        Bare(String),
    }

    let raw: Vec<Entry> = Vec::deserialize(de)?;
    Ok(raw
        .into_iter()
        .map(|e| match e {
            Entry::Structured(s) => s,
            Entry::Bare(name) => CalleeSite::bare(name),
        })
        .collect())
}

/// Serialisable summary of a single function's taint behaviour.
///
/// One of these is produced per function during **pass 1** of a scan and
/// persisted to the `function_summaries` SQLite table.  During **pass 2** the
/// full set of summaries across every file is loaded into memory so the taint
/// engine can resolve cross‑file calls.
///
/// Design notes
/// ────────────
/// * **All three cap fields are independent.**  A function can simultaneously
///   act as a source (introduces fresh taint), a sanitizer (cleans certain
///   bits), and a sink (passes tainted data to a dangerous operation).
///   The old code picked a single `DataLabel` which lost information.
///
/// * **`propagating_params`** captures per‑argument pass‑through behaviour:
///   which parameter indices (0‑based) flow through to the return value.
///   This is essential for chains like `let y = transform(tainted_x); sink(y);`.
///   The legacy boolean `propagates_taint` is kept for deserialising old JSON.
///
/// * **`callees`** drive call‑graph construction in `callgraph.rs`, which
///   yields the topological order and SCC batches used between pass 1 and
///   pass 2 (see `scan::run_topo_batches` and `scc_file_batches_with_metadata`).
///
/// * **`tainted_sink_params`** marks which parameter *positions* flow to
///   internal sinks and is consumed by SSA callee resolution
///   (`ssa_transfer::mod.rs` `resolve_callee`) to build the per-parameter
///   `param_to_sink` list, so caller-side sink propagation fires on the
///   specific argument positions rather than the whole call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuncSummary {
    /// Function name as it appears in the source (`my_func`, not the full path).
    pub name: String,

    /// Absolute path of the file that defines this function.
    pub file_path: String,

    /// Language slug (`"rust"`, `"javascript"`, …).
    pub lang: String,

    // ── Signature information ────────────────────────────────────────────
    /// Total number of parameters (including `self`/`&self` for methods).
    pub param_count: usize,

    /// Parameter names in declaration order.
    pub param_names: Vec<String>,

    // ── Taint behaviour ──────────────────────────────────────────────────
    // Stored as raw `u16` so serde doesn't need to know about `bitflags`.
    /// Caps this function **introduces**, i.e. the return value carries
    /// freshly‑tainted data even if no argument was tainted.
    pub source_caps: u16,

    /// Caps this function **cleans**, passing tainted data through this
    /// function strips the corresponding bits.
    pub sanitizer_caps: u16,

    /// Caps this function **consumes unsafely**, calling it with tainted
    /// arguments that still carry these bits is a finding.
    pub sink_caps: u16,

    /// Which parameter indices (0‑based) flow through to the return value.
    #[serde(default)]
    pub propagating_params: Vec<usize>,

    /// Legacy field, kept only for deserialising old JSON from SQLite.
    /// New code should use `propagating_params` instead.
    #[serde(default, skip_serializing)]
    pub propagates_taint: bool,

    /// Indices of parameters that flow to internal sinks (0‑based).
    pub tainted_sink_params: Vec<usize>,

    /// Per-parameter [`SinkSite`] records, mirrors
    /// [`SsaFuncSummary::param_to_sink`] so the coarse legacy summary also
    /// carries primary sink-location attribution through the two-pass
    /// architecture.  Empty when the extractor lacked tree access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_to_sink: Vec<(usize, SmallVec<[SinkSite; 1]>)>,

    /// Per-call-site metadata for every function/method/macro invoked
    /// inside this body (`CalleeSite`).  Carries arity, receiver,
    /// qualifier, and call ordinal so downstream resolution does not have
    /// to re-parse the raw callee string.
    ///
    /// A custom deserializer tolerates legacy on-disk rows whose callees
    /// field was a plain `Vec<String>`; those are lifted to
    /// `CalleeSite { name, .. }` with no additional metadata.
    #[serde(default, deserialize_with = "deserialize_callee_sites")]
    pub callees: Vec<CalleeSite>,

    // ── Identity discriminators ──────────────────────────────────────────
    /// Enclosing container path (class / impl / module / outer function),
    /// segments joined with `::`.  Empty for free top-level functions.
    #[serde(default)]
    pub container: String,

    /// Numeric discriminator for same-name siblings (closure byte offset,
    /// nested-function occurrence index).  `None` when no sibling collision.
    #[serde(default)]
    pub disambig: Option<u32>,

    /// Structural role of this definition.  Defaults to `Function` when
    /// deserialising legacy JSON.
    #[serde(default)]
    pub kind: FuncKind,

    // ── Rust-specific module-resolution metadata ────────────────────────
    /// Crate-relative module path for this function's defining file
    /// (e.g. `"auth::token"` for `src/auth/token.rs`). Only populated
    /// when `lang == "rust"`. Used by the call graph to resolve
    /// `use`-imported callees to their fully-qualified module.
    ///
    /// `None` for non-Rust files and for Rust files outside a recognised
    /// `src/` tree (tests, examples, build scripts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_path: Option<String>,

    /// Per-file `use`-alias map for the defining Rust source.
    ///
    /// Maps the local identifier introduced by a `use` declaration to its
    /// fully qualified path (`"validate"` → `"crate::auth::token::validate"`).
    /// Carried on every summary for the file even though it is per-file
    /// information; the duplication keeps the persistence schema simple
    /// and lets resolution operate purely off the caller's summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust_use_map: Option<BTreeMap<String, String>>,

    /// Fully qualified prefixes of any wildcard `use ...::*` imports in
    /// the defining Rust source. Stored separately because they expand
    /// the candidate space at resolution time rather than naming a single
    /// alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust_wildcards: Option<Vec<String>>,

    /// Per-file class / trait / interface hierarchy edges captured at
    /// CFG-construction time.  Each entry is
    /// `(sub_container, super_container)` after language-specific
    /// normalisation:
    ///
    /// * Java `class X extends Y` → `(X, Y)`; `implements I, J` → `(X, I)`, `(X, J)`
    /// * Rust `impl Trait for Type` → `(Type, Trait)`
    /// * TypeScript `class X extends Y implements I` → `(X, Y)`, `(X, I)`
    /// * Python `class X(A, B)` → `(X, A)`, `(X, B)`
    /// * PHP `class X extends Y implements I` → `(X, Y)`, `(X, I)`
    /// * Ruby `class X < Y` → `(X, Y)`
    /// * C++ `class X : public Y` → `(X, Y)`
    ///
    /// Empty for files with no declared inheritance / impl
    /// relationships and for Go (which uses implicit interface
    /// satisfaction, not computed).
    ///
    /// **Per-file duplication.**  Every `FuncSummary` produced from a
    /// given file carries the **same** `hierarchy_edges` vector so the
    /// information survives summary-by-summary persistence to SQLite.
    /// `merge_summaries` deduplicates downstream when building
    /// [`crate::callgraph::TypeHierarchyIndex`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hierarchy_edges: Vec<(String, String)>,
}

// ── Cap conversion helpers ──────────────────────────────────────────────

impl FuncSummary {
    #[inline]
    pub fn source_caps(&self) -> Cap {
        Cap::from_bits_truncate(self.source_caps)
    }

    #[inline]
    pub fn sanitizer_caps(&self) -> Cap {
        Cap::from_bits_truncate(self.sanitizer_caps)
    }

    #[inline]
    pub fn sink_caps(&self) -> Cap {
        Cap::from_bits_truncate(self.sink_caps)
    }

    /// Returns `true` when any parameter flows to the return value.
    /// Also returns `true` for legacy summaries with `propagates_taint: true`
    /// but empty `propagating_params` (backward compat).
    pub fn propagates_any(&self) -> bool {
        !self.propagating_params.is_empty() || self.propagates_taint
    }

    /// Build a [`FuncKey`] from this summary, normalizing the namespace
    /// relative to `scan_root`.
    pub fn func_key(&self, scan_root: Option<&str>) -> FuncKey {
        FuncKey {
            lang: Lang::from_slug(&self.lang).unwrap_or(Lang::Rust),
            namespace: normalize_namespace(&self.file_path, scan_root),
            container: self.container.clone(),
            name: self.name.clone(),
            arity: Some(self.param_count),
            disambig: self.disambig,
            kind: self.kind,
        }
    }
}

// ── Callee resolution ────────────────────────────────────────────────────

/// Result of resolving a bare callee name to a [`FuncKey`].
///
/// Three-valued: the call graph builder and taint engine need to distinguish
/// "no candidates at all" from "multiple candidates, can't pick one".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalleeResolution {
    /// Exactly one candidate matched.
    Resolved(FuncKey),
    /// No candidates found at all.
    NotFound,
    /// Multiple candidates, ambiguous, cannot pick one.
    Ambiguous(Vec<FuncKey>),
}

/// Structured query describing a call site.
///
/// Carries every hint needed to pick the right callee *by qualified identity*
/// first and only fall back on bare-leaf lookup as a last resort.  The old
/// entry points (`resolve_callee_key`, `resolve_callee_key_with_container`)
/// are now thin wrappers that build a `CalleeQuery` with partial information.
///
/// Hint categories, ordered from strongest to weakest:
///
/// * `receiver_type`, authoritative class/impl/module name (e.g. from
///   type inference or a `use ...` resolution). When set, the resolver
///   *requires* the callee's container to equal this name and refuses to
///   fall back to a leaf-name collision if the qualified lookup misses.
/// * `namespace_qualifier`, syntactic qualifier parsed from the callee
///   (e.g. `"env"` in `env::var`, `"http"` in `http.Get`). Treated as a
///   container hint but not authoritative: a miss falls through.
/// * `receiver_var`, syntactic receiver variable name (e.g. `"obj"` in
///   `obj.method()`). Soft hint, used only to tie-break ambiguity.
/// * `caller_container`, caller's own enclosing container, used to
///   resolve bare self-calls inside a class/impl body.
///
/// `arity` is a hard filter, when `Some`, every candidate whose arity
/// differs is excluded from consideration.
#[derive(Debug, Clone)]
pub struct CalleeQuery<'a> {
    /// Leaf (unqualified) callee name, e.g. `"process"` for `OrderService::process`.
    pub name: &'a str,
    pub caller_lang: Lang,
    /// Project-relative namespace (file path) of the caller.  Used for
    /// same-namespace disambiguation when qualified hints miss.
    pub caller_namespace: &'a str,
    /// The caller's own container (`FuncKey::container`), for resolving
    /// bare `self`/intra-class calls without a receiver.
    pub caller_container: Option<&'a str>,
    /// Authoritative receiver class/impl name.  Populated from type facts
    /// (`TypeKind::label_prefix`) or from Rust use-map resolution.
    pub receiver_type: Option<&'a str>,
    /// Syntactic namespace qualifier (non-authoritative).  For
    /// `std::env::var` in Rust the caller passes `"env"`; for `http.Get`
    /// in Go, `"http"`.  Left `None` for purely bare calls.
    pub namespace_qualifier: Option<&'a str>,
    /// Syntactic receiver variable name.  Used only as a tie-breaker, a
    /// variable name is a weak proxy for a class name.
    pub receiver_var: Option<&'a str>,
    /// Positional-argument count at the call site.  Hard filter when set.
    pub arity: Option<usize>,
}

impl<'a> CalleeQuery<'a> {
    /// Whether this query carries any qualified identity hint stronger than
    /// a bare leaf name.  Used by the resolver to decide whether an
    /// unresolved qualified match should still fall through to leaf lookup
    /// (no hints → fall through; authoritative hints → refuse to guess).
    pub fn has_qualified_hint(&self) -> bool {
        self.receiver_type.is_some()
            || self.namespace_qualifier.is_some()
            || self.caller_container.is_some_and(|s| !s.is_empty())
    }
}

// ── Lookup map used by the taint engine ─────────────────────────────────

/// A merged view of all function summaries keyed by qualified [`FuncKey`].
///
/// Functions are partitioned by language + namespace + name + arity.  Two
/// functions with the same bare name but different languages or namespaces
/// are stored separately, no implicit cross-language merging occurs.
///
/// A secondary index `(Lang, name)` supports fast lookup by language + name
/// for same-language resolution in the taint engine.
#[derive(Default)]
pub struct GlobalSummaries {
    by_key: HashMap<FuncKey, FuncSummary>,
    /// Bare leaf-name index, kept for compatibility with callers that only
    /// see an unqualified call string.  A single name may map to many keys
    /// across containers / files / arities.
    by_lang_name: HashMap<(Lang, String), Vec<FuncKey>>,
    /// Container-qualified index: keyed on `"{container}::{name}"` (or just
    /// `name` for free functions).  Used to resolve calls when the call-site
    /// can supply a receiver / container hint (e.g. `OrderService::process`).
    by_lang_qualified: HashMap<(Lang, String), Vec<FuncKey>>,
    /// Rust-only secondary index keyed on `(module_path, name)`.
    ///
    /// Populated whenever a Rust [`FuncSummary`] is inserted with a
    /// `module_path` set. Used by use-map driven resolution to look up
    /// candidates by their crate-relative module rather than their
    /// filesystem path. Same name / module / arity overloads land on the
    /// same vector, arity narrowing happens at resolution time.
    by_rust_module: HashMap<(String, String), Vec<FuncKey>>,
    /// Precise SSA-derived per-parameter summaries, keyed by `FuncKey`.
    /// These take precedence over `FuncSummary` during callee resolution.
    ssa_by_key: HashMap<FuncKey, SsaFuncSummary>,
    /// Cross-file callee bodies for interprocedural symbolic execution.
    /// Keyed by `FuncKey` (same identity model as SSA summaries).
    bodies_by_key: HashMap<FuncKey, crate::taint::ssa_transfer::CalleeSsaBody>,
    /// Per-function auth-check summaries for cross-file helper lifting.
    /// Keyed by `FuncKey` so a call-site resolver can go from a resolved
    /// callee name to the helper's auth-check signature.  Populated in
    /// pass 1 and consumed by
    /// [`crate::auth_analysis::run_auth_analysis`] during pass 2.
    auth_by_key: HashMap<FuncKey, crate::auth_analysis::model::AuthCheckSummary>,
    /// Type hierarchy index for runtime virtual-dispatch fan-out.
    ///
    /// Installed by [`Self::install_hierarchy`] after pass 1 from the
    /// merged `FuncSummary::hierarchy_edges` vectors.  Consumed by
    /// [`Self::resolve_callee_widened`] during pass 2 so the taint
    /// engine sees every concrete implementer of a method when the
    /// receiver is statically typed as a super-class / trait /
    /// interface, recovering the dispatch precision that today's
    /// single-result [`Self::resolve_callee`] discards.
    ///
    /// `None` until installed: every consumer treats `None` as
    /// "fall through to today's bare resolution", so the index is
    /// strictly additive.
    hierarchy: Option<crate::callgraph::TypeHierarchyIndex>,
}

impl GlobalSummaries {
    pub fn new() -> Self {
        Self::default()
    }

    /// Walk a proposed insertion key, bumping the synthetic disambig
    /// until either (a) the key is unoccupied, or (b) the entry found at
    /// that key is compatible with the incoming summary (safe to merge).
    ///
    /// Identity collisions are extraordinarily rare in practice (they
    /// require two structurally distinct functions to land on the same
    /// non-synthetic key, e.g. both with `disambig: None`).  The loop
    /// bound is defensive, if synthetic probing still collides after
    /// 1024 attempts we fall through and let the caller merge, which
    /// degrades gracefully to the old behaviour rather than looping
    /// forever.
    fn reconcile_func_summary_key(&self, mut key: FuncKey, summary: &FuncSummary) -> FuncKey {
        let mut probe: u32 = 0;
        loop {
            match self.by_key.get(&key) {
                Some(existing) if !summaries_compatible(existing, summary) => {
                    let synth = synthesize_disambig(summary).wrapping_add(probe);
                    key.disambig = Some(SYNTHETIC_DISAMBIG_BIT | (synth & !SYNTHETIC_DISAMBIG_BIT));
                    probe = probe.wrapping_add(1);
                    if probe >= 1024 {
                        tracing::warn!(
                            "summary identity collision probe gave up after 1024 attempts; \
                             falling back to union-merge for {}",
                            key
                        );
                        return key;
                    }
                }
                _ => return key,
            }
        }
    }

    /// SSA-summary variant of [`Self::reconcile_func_summary_key`].
    ///
    /// Distinctness signals for SSA summaries are weaker than for
    /// coarse `FuncSummary`s, the summary itself carries no explicit
    /// `param_count`, only references to parameter indices.  We combine:
    ///
    /// * **Key arity fit**, any parameter index referenced by the new
    ///   summary that exceeds `key.arity` is a structural mismatch.
    /// * **Existing-entry compare**, if an entry already lives at
    ///   this key and it disagrees on the set of referenced parameter
    ///   indices, the two cannot both describe the same function.
    fn reconcile_ssa_summary_key(&self, mut key: FuncKey, summary: &SsaFuncSummary) -> FuncKey {
        let mut probe: u32 = 0;
        loop {
            let conflict = match self.ssa_by_key.get(&key) {
                Some(existing) => !ssa_summaries_compatible(existing, summary, key.arity),
                None => !ssa_summary_fits_arity(summary, key.arity),
            };
            if !conflict {
                return key;
            }
            let synth = synthesize_ssa_disambig(summary).wrapping_add(probe);
            key.disambig = Some(SYNTHETIC_DISAMBIG_BIT | (synth & !SYNTHETIC_DISAMBIG_BIT));
            probe = probe.wrapping_add(1);
            if probe >= 1024 {
                tracing::warn!(
                    "SSA summary identity collision probe gave up after 1024 attempts \
                     for {}",
                    key
                );
                return key;
            }
        }
    }

    /// Body variant of [`Self::reconcile_func_summary_key`].
    ///
    /// `CalleeSsaBody` carries an explicit `param_count`, which must
    /// agree with both `key.arity` and any co-located body's
    /// `param_count`.  A mismatch is a hard collision.
    fn reconcile_body_key(
        &self,
        mut key: FuncKey,
        body: &crate::taint::ssa_transfer::CalleeSsaBody,
    ) -> FuncKey {
        let mut probe: u32 = 0;
        loop {
            let conflict = match self.bodies_by_key.get(&key) {
                Some(existing) => existing.param_count != body.param_count,
                None => match key.arity {
                    Some(a) => a != body.param_count,
                    None => false,
                },
            };
            if !conflict {
                return key;
            }
            let synth = (body.param_count as u32)
                .wrapping_mul(0x9E37_79B9)
                .wrapping_add(probe);
            key.disambig = Some(SYNTHETIC_DISAMBIG_BIT | (synth & !SYNTHETIC_DISAMBIG_BIT));
            probe = probe.wrapping_add(1);
            if probe >= 1024 {
                tracing::warn!(
                    "SSA body identity collision probe gave up after 1024 attempts for {}",
                    key
                );
                return key;
            }
        }
    }

    /// Insert or merge a summary.  If an exact `FuncKey` match exists and
    /// the two summaries describe the same function, merge conservatively
    /// (OR caps/booleans, union params/callees).
    ///
    /// `FuncKey` is structurally precise *when every producer populates
    /// `disambig`*.  Legacy on-disk JSON, interop configs, DB rows written
    /// by older versions, and any code path that keeps `disambig: None`
    /// can produce two keys that hash-equal even though they belong to
    /// structurally distinct functions (e.g. different `param_count`,
    /// `kind`, `container`, or `param_names`).  Silently unioning those
    /// would leak security-relevant caps across unrelated functions and
    /// drop one of the two summaries entirely.
    ///
    /// We therefore inspect the existing entry first.  If the new summary
    /// is not [`summaries_compatible`] with it, we mint a synthetic
    /// disambig (top bit set to stay disjoint from byte-offset disambigs)
    /// and retry the insert under the fresh key so *both* functions are
    /// preserved.
    pub fn insert(&mut self, key: FuncKey, summary: FuncSummary) {
        let key = self.reconcile_func_summary_key(key, &summary);
        let lang = key.lang;
        let name = key.name.clone();
        let qualified = key.qualified_name();
        let rust_module = if lang == Lang::Rust {
            summary.module_path.clone()
        } else {
            None
        };

        self.by_key
            .entry(key.clone())
            .and_modify(|existing| {
                existing.source_caps |= summary.source_caps;
                existing.sanitizer_caps |= summary.sanitizer_caps;
                existing.sink_caps |= summary.sink_caps;
                existing.propagates_taint |= summary.propagates_taint;
                for &idx in &summary.propagating_params {
                    if !existing.propagating_params.contains(&idx) {
                        existing.propagating_params.push(idx);
                    }
                }
                for &idx in &summary.tainted_sink_params {
                    if !existing.tainted_sink_params.contains(&idx) {
                        existing.tainted_sink_params.push(idx);
                    }
                }
                union_param_sink_sites(&mut existing.param_to_sink, &summary.param_to_sink);
                for c in &summary.callees {
                    if !existing.callees.iter().any(|e| {
                        e.name == c.name
                            && e.arity == c.arity
                            && e.receiver == c.receiver
                            && e.qualifier == c.qualifier
                            && e.ordinal == c.ordinal
                    }) {
                        existing.callees.push(c.clone());
                    }
                }
            })
            .or_insert(summary);

        let keys = self.by_lang_name.entry((lang, name)).or_default();
        if !keys.contains(&key) {
            keys.push(key.clone());
        }

        let q_keys = self.by_lang_qualified.entry((lang, qualified)).or_default();
        if !q_keys.contains(&key) {
            q_keys.push(key.clone());
        }

        if let Some(mp) = rust_module {
            let mk = self
                .by_rust_module
                .entry((mp, key.name.clone()))
                .or_default();
            if !mk.contains(&key) {
                mk.push(key);
            }
        }
    }

    /// Exact lookup by fully-qualified key.
    pub fn get(&self, key: &FuncKey) -> Option<&FuncSummary> {
        self.by_key.get(key)
    }

    /// Interop / external-edge lookup: tolerant of `disambig` being `None`.
    ///
    /// Interop edges originate outside the source code (user-specified JSON,
    /// language-bridge config) and cannot know a callee's internal byte-offset
    /// disambiguator.  When the query key has `disambig = None` we fall back to
    /// scanning for a single match on `(lang, namespace, container, name,
    /// arity, kind)`.  If exactly one matches it is returned; otherwise we
    /// return `None` to preserve determinism (ambiguity is treated as unknown).
    pub fn get_for_interop(&self, key: &FuncKey) -> Option<&FuncSummary> {
        if let Some(hit) = self.by_key.get(key) {
            return Some(hit);
        }
        if key.disambig.is_some() {
            return None;
        }
        let mut matches = self.by_key.iter().filter(|(k, _)| {
            k.lang == key.lang
                && k.namespace == key.namespace
                && k.container == key.container
                && k.name == key.name
                && k.arity == key.arity
                && k.kind == key.kind
        });
        let first = matches.next()?;
        if matches.next().is_some() {
            None
        } else {
            Some(first.1)
        }
    }

    /// All same-language matches for a bare function name.
    pub fn lookup_same_lang(&self, lang: Lang, name: &str) -> Vec<(&FuncKey, &FuncSummary)> {
        self.by_lang_name
            .get(&(lang, name.to_string()))
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.by_key.get(k).map(|v| (k, v)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rust-only lookup by `(module_path, name)`.
    ///
    /// Returns every candidate that was inserted with a matching module
    /// path. Arity filtering is applied by the caller so that the index
    /// stays ambiguity-aware (two overloads legitimately share a module
    /// path + name and only differ in arity).
    pub fn lookup_rust_module(
        &self,
        module_path: &str,
        name: &str,
    ) -> Vec<(&FuncKey, &FuncSummary)> {
        self.by_rust_module
            .get(&(module_path.to_string(), name.to_string()))
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.by_key.get(k).map(|v| (k, v)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Container-qualified lookup.  `qualified` should be
    /// `"Container::name"` (use [`FuncKey::qualified_name`]) or `"name"`.
    pub fn lookup_qualified(&self, lang: Lang, qualified: &str) -> Vec<(&FuncKey, &FuncSummary)> {
        self.by_lang_qualified
            .get(&(lang, qualified.to_string()))
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.by_key.get(k).map(|v| (k, v)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Merge another `GlobalSummaries` into this one (for parallel fold/reduce).
    pub fn merge(&mut self, other: GlobalSummaries) {
        // `insert` rebuilds every secondary index (by_lang_name, by_lang_qualified,
        // by_rust_module) from the summary itself, so we do not need to copy
        // `other.by_rust_module` explicitly, draining `other.by_key` is enough.
        for (key, summary) in other.by_key {
            self.insert(key, summary);
        }
        // SSA summaries: last-writer-wins (exact-key replacement, no unioning)
        for (key, ssa_sum) in other.ssa_by_key {
            self.ssa_by_key.insert(key, ssa_sum);
        }
        // Cross-file bodies: last-writer-wins
        for (key, body) in other.bodies_by_key {
            self.bodies_by_key.insert(key, body);
        }
        // Auth summaries: last-writer-wins (exact-key replacement)
        for (key, auth_sum) in other.auth_by_key {
            self.auth_by_key.insert(key, auth_sum);
        }
        // Hierarchy index: invalidate after a merge so the next consumer
        // sees a freshly-built view that includes `other`'s edges.  The
        // alternative, point-merging two indexes, is racy when the
        // same `(lang, super)` key carries different sub-orderings in
        // each input; rebuild is O(n) over `by_key.iter()` and is the
        // single source of truth.
        self.hierarchy = None;
    }

    /// Insert an SSA summary.
    ///
    /// Per-function refinement is expressed via last-writer-wins for
    /// *compatible* summaries: re-analysing the same function body with
    /// more precise seeds yields a strictly better summary, and the
    /// caller genuinely wants the new one to replace the old.
    ///
    /// When the existing entry is **incompatible** with the incoming
    /// one, the key's `arity` disagrees with the new summary's referenced
    /// parameter indices, or the two summaries would describe different
    /// functions, we synthesize a disambig so both are kept.  Silent
    /// replacement in that case would drop one function's cross-file
    /// taint signal entirely, which the caller cannot recover.
    ///
    /// Before reconciliation, drop any parameter-index reference at or
    /// above `key.arity`.  Such indices come from synthetic SSA `Param`
    /// ops emitted by scoped lowering for **external captures** (free
    /// identifiers like `this`, module imports, or unresolved method
    /// names) and are useful for *intra-file* pass-2 analysis (the
    /// caller's implicit-uses argument group at the same index aligns
    /// with the synthetic Param) but never for cross-file consumers,
    /// which key off the FuncKey arity exclusively.  Without the trim,
    /// `ssa_summary_fits_arity` would reject the summary and
    /// `reconcile_ssa_summary_key` would synthesise a disambig that
    /// uncouples the SSA FuncKey from the matching FuncSummary FuncKey
    /// (audit gap A.2.1.G1 ,
    /// `project_typed_callgraph_audit_gap_ssa_disambig.md`).
    pub fn insert_ssa(&mut self, key: FuncKey, summary: SsaFuncSummary) {
        // The summary may reference a parameter index ≥ `key.arity` when
        // scoped SSA lowering synthesised `Param` ops for **external
        // captures** (free identifiers like `this`, module imports,
        // unresolved method names), see audit gap A.2.1.G1
        // (`project_typed_callgraph_audit_gap_ssa_disambig.md`).  These
        // synthetic refs are useful inside the file they were extracted
        // in (caller implicit-uses align with the synthetic Param) and
        // stay useful when resolved cross-file by name. But they trip
        // [`ssa_summary_fits_arity`] inside
        // [`reconcile_ssa_summary_key`], forcing a synthetic disambig
        // that uncouples the SSA FuncKey from the FuncSummary FuncKey
        //, `summaries.get_ssa(caller_key)` (consuming
        // `typed_call_receivers` at the FuncSummary-aligned key) would
        // miss.
        //
        // Resolution rule (applies only when `summary` does not fit
        // arity):
        //
        // * **No existing entry, or existing entry also has out-of-range
        //   refs**, keep the untrimmed summary at the original key,
        //   bypassing disambig synthesis. Resolution finds the entry
        //   under the FuncSummary's own disambig with its full
        //   per-param signal (closures, lambdas, captured-var sinks).  The "existing also
        //   has out-of-range refs" branch covers the iterative-rescan
        //   case where round 2's incoming summary lands on top of round
        //   1's already-installed copy of the same function.
        //
        // * **Existing entry fits arity (legit) but new doesn't**, fall
        //   back to the disambig synthesis.  This preserves the
        //   `insert_ssa_arity_overflow_rekeys` invariant: a structurally
        //   incompatible incoming summary (different function sharing
        //   name + container + arity, with param refs at indices that
        //   don't even exist in the legitimate function) cannot
        //   dethrone the existing entry by silent overwrite.  Both
        //   summaries survive, the existing one at the original key,
        //   the new one at the synthesised disambig.
        let key = if key.arity.is_some() && !ssa_summary_fits_arity(&summary, key.arity) {
            let existing_also_overflows = self
                .ssa_by_key
                .get(&key)
                .is_some_and(|existing| !ssa_summary_fits_arity(existing, key.arity));
            let existing_present = self.ssa_by_key.contains_key(&key);
            if !existing_present || existing_also_overflows {
                key
            } else {
                self.reconcile_ssa_summary_key(key, &summary)
            }
        } else {
            self.reconcile_ssa_summary_key(key, &summary)
        };
        self.ssa_by_key.insert(key, summary);
    }

    /// Exact lookup of an SSA summary by fully-qualified key.
    pub fn get_ssa(&self, key: &FuncKey) -> Option<&SsaFuncSummary> {
        self.ssa_by_key.get(key)
    }

    /// Insert an `AuthCheckSummary` for cross-file helper lifting.
    ///
    /// Last-writer-wins: re-analysing a file produces a fresh summary
    /// that fully replaces any earlier entry.  No compatibility
    /// reconciliation is needed because `AuthCheckSummary` carries no
    /// identity-sensitive signal beyond the key itself.
    pub fn insert_auth(
        &mut self,
        key: FuncKey,
        summary: crate::auth_analysis::model::AuthCheckSummary,
    ) {
        self.auth_by_key.insert(key, summary);
    }

    /// Exact lookup of an `AuthCheckSummary` by fully-qualified key.
    pub fn get_auth(
        &self,
        key: &FuncKey,
    ) -> Option<&crate::auth_analysis::model::AuthCheckSummary> {
        self.auth_by_key.get(key)
    }

    /// Direct access to the auth-summary map.  `None` when empty so
    /// callers can distinguish "no cross-file auth summaries loaded"
    /// from "some were loaded but none matched the call site".
    pub fn auth_by_key(
        &self,
    ) -> Option<&HashMap<FuncKey, crate::auth_analysis::model::AuthCheckSummary>> {
        if self.auth_by_key.is_empty() {
            None
        } else {
            Some(&self.auth_by_key)
        }
    }

    /// Count of cross-file auth summaries currently loaded.
    pub fn auth_len(&self) -> usize {
        self.auth_by_key.len()
    }

    /// Insert a cross-file callee body.
    ///
    /// See [`insert_ssa`](Self::insert_ssa) for the identity-safety rule.
    /// Bodies additionally carry `param_count`, giving a hard structural
    /// signal: a collision between bodies with different `param_count`
    /// cannot be the same function and is always rekeyed.
    pub fn insert_body(&mut self, key: FuncKey, body: crate::taint::ssa_transfer::CalleeSsaBody) {
        let key = self.reconcile_body_key(key, &body);
        self.bodies_by_key.insert(key, body);
    }

    /// Exact lookup of a cross-file callee body by fully-qualified key.
    pub fn get_body(&self, key: &FuncKey) -> Option<&crate::taint::ssa_transfer::CalleeSsaBody> {
        self.bodies_by_key.get(key)
    }

    /// Direct access to the cross-file body map.
    ///
    /// Returns `None` when no cross-file bodies were loaded (empty map).
    /// The taint engine uses this to thread bodies through
    /// [`crate::taint::ssa_transfer::SsaTaintTransfer::cross_file_bodies`]
    /// and `resolve_callee` for context-sensitive cross-file inline
    /// analysis.
    pub fn bodies_by_key(
        &self,
    ) -> Option<&HashMap<FuncKey, crate::taint::ssa_transfer::CalleeSsaBody>> {
        if self.bodies_by_key.is_empty() {
            None
        } else {
            Some(&self.bodies_by_key)
        }
    }

    /// Count of cross-file bodies currently loaded.  Exposed for
    /// `tracing::debug!` observability, lets callers distinguish "no
    /// bodies available" from "bodies available but inline didn't fire".
    pub fn bodies_len(&self) -> usize {
        self.bodies_by_key.len()
    }

    /// Resolve a bare callee name to a cross-file body.
    ///
    /// Uses `resolve_callee_key()` for strict deterministic resolution,
    /// then checks `bodies_by_key`. Returns `None` on `Ambiguous` or `NotFound`.
    pub fn resolve_callee_body(
        &self,
        lang: Lang,
        name: &str,
        arity_hint: Option<usize>,
        caller_namespace: &str,
    ) -> Option<&crate::taint::ssa_transfer::CalleeSsaBody> {
        match self.resolve_callee_key(name, lang, caller_namespace, arity_hint) {
            CalleeResolution::Resolved(key) => self.bodies_by_key.get(&key),
            CalleeResolution::NotFound | CalleeResolution::Ambiguous(_) => None,
        }
    }

    #[allow(dead_code)] // used by tests and future call-graph consumers
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty() && self.ssa_by_key.is_empty() && self.auth_by_key.is_empty()
    }

    /// Iterate over all (key, summary) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&FuncKey, &FuncSummary)> {
        self.by_key.iter()
    }

    /// Snapshot the convergence-relevant fields of every summary.
    ///
    /// Returns `(source_caps, sanitizer_caps, sink_caps, propagating_params)`
    /// per key.  Used by the SCC fixed-point loop to detect when an iteration
    /// has not changed any summary, i.e. convergence.
    pub fn snapshot_caps(&self) -> HashMap<FuncKey, (u16, u16, u16, Vec<usize>)> {
        self.by_key
            .iter()
            .map(|(k, s)| {
                (
                    k.clone(),
                    (
                        s.source_caps,
                        s.sanitizer_caps,
                        s.sink_caps,
                        s.propagating_params.clone(),
                    ),
                )
            })
            .collect()
    }

    /// Snapshot the SSA summaries for convergence detection.
    ///
    /// Used alongside [`snapshot_caps`] in the SCC fixed-point loop so that
    /// SSA-only refinements (e.g. a `StripBits` transform appearing after a
    /// cross-file sanitizer is resolved) are not invisible to convergence.
    pub fn snapshot_ssa(&self) -> &HashMap<FuncKey, SsaFuncSummary> {
        &self.ssa_by_key
    }

    /// Rust-only resolution that consults the caller's `use` map before
    /// falling back to generic resolution.
    ///
    /// The caller passes the callee's leaf name plus the (optional)
    /// structured qualifier that `CalleeSite.qualifier` carries for Rust
    /// call sites (e.g. `"crate::auth::token"` for `crate::auth::token::validate()`).
    /// The `use` map and wildcard list come from the caller's own
    /// [`FuncSummary`].
    ///
    /// Resolution order:
    ///
    /// 1. If the caller has a `use_map` and (qualifier, name) resolves to a
    ///    fully qualified path, strip the leading `crate::` and look up
    ///    `(module_path, name)` in the Rust module index.  If arity filtering
    ///    leaves exactly one candidate → resolved.
    /// 2. Otherwise, for each wildcard prefix in scope, try
    ///    `(wildcard_prefix, name)` in the module index.  If across all
    ///    wildcards exactly one arity-filtered candidate appears → resolved.
    /// 3. Otherwise fall through to [`resolve_callee_key_with_container`]
    ///    with no `container_hint`, meaning only the existing namespace /
    ///    arity disambiguation applies.
    ///
    /// A `None` use_map (non-Rust file or no `use` declarations) makes this
    /// equivalent to the generic path.
    pub fn resolve_callee_key_rust(
        &self,
        callee: &str,
        qualifier: Option<&str>,
        arity_hint: Option<usize>,
        caller_namespace: &str,
        use_map: Option<&crate::rust_resolve::RustUseMap>,
    ) -> CalleeResolution {
        use crate::rust_resolve::{resolve_with_use_map, split_module_and_name};

        // 1) Try direct use-map resolution.
        if let Some(um) = use_map
            && let Some(full) = resolve_with_use_map(um, qualifier, callee)
        {
            let (module_path, name) = split_module_and_name(&full);
            if !module_path.is_empty() {
                let candidates = self.lookup_rust_module(&module_path, &name);
                let filtered: Vec<&FuncKey> = match arity_hint {
                    Some(a) => candidates
                        .iter()
                        .filter(|(k, _)| k.arity == Some(a))
                        .map(|(k, _)| *k)
                        .collect(),
                    None => candidates.iter().map(|(k, _)| *k).collect(),
                };
                if filtered.len() == 1 {
                    return CalleeResolution::Resolved(filtered[0].clone());
                }
            }
        }

        // 2) Try wildcards.  Each wildcard expands `use prefix::*;` into an
        //    implicit `(prefix, name)` candidate set; we union across all
        //    wildcards and only resolve when exactly one matches under the
        //    arity filter.
        if let Some(um) = use_map
            && !um.wildcards.is_empty()
        {
            let mut collected: Vec<FuncKey> = Vec::new();
            for w in &um.wildcards {
                let prefix = w.strip_prefix("crate::").unwrap_or(w);
                if prefix.is_empty() {
                    continue;
                }
                for (k, _) in self.lookup_rust_module(prefix, callee) {
                    if let Some(a) = arity_hint
                        && k.arity != Some(a)
                    {
                        continue;
                    }
                    if !collected.contains(k) {
                        collected.push(k.clone());
                    }
                }
            }
            if collected.len() == 1 {
                return CalleeResolution::Resolved(collected.remove(0));
            }
        }

        // 3) Fall back to generic same-language resolution.
        self.resolve_callee_key_with_container(
            callee,
            Lang::Rust,
            caller_namespace,
            None,
            arity_hint,
        )
    }

    /// Resolve a bare (already-normalized) callee name to a [`FuncKey`].
    ///
    /// Thin wrapper around [`resolve_callee`] that constructs a minimal
    /// [`CalleeQuery`] with no qualified hints.  Kept for call sites that
    /// only hold a string callee and an arity; prefer [`resolve_callee`]
    /// whenever receiver / qualifier / container information is available.
    pub fn resolve_callee_key(
        &self,
        callee: &str,
        caller_lang: Lang,
        caller_namespace: &str,
        arity_hint: Option<usize>,
    ) -> CalleeResolution {
        self.resolve_callee(&CalleeQuery {
            name: callee,
            caller_lang,
            caller_namespace,
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: arity_hint,
        })
    }

    /// Resolve a callee name with an optional container hint.
    ///
    /// Legacy entry point, kept so tests and older callers compile
    /// unchanged.  `container_hint` is interpreted as a syntactic
    /// container qualifier (not an authoritative receiver type), so a
    /// miss is allowed to fall through to leaf-name lookup.  New
    /// callers should route through [`resolve_callee`] and classify
    /// their hint as `receiver_type` vs `namespace_qualifier` vs
    /// `receiver_var` so the resolver can apply the correct policy.
    pub fn resolve_callee_key_with_container(
        &self,
        callee: &str,
        caller_lang: Lang,
        caller_namespace: &str,
        container_hint: Option<&str>,
        arity_hint: Option<usize>,
    ) -> CalleeResolution {
        self.resolve_callee(&CalleeQuery {
            name: callee,
            caller_lang,
            caller_namespace,
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: container_hint,
            receiver_var: None,
            arity: arity_hint,
        })
    }

    /// Resolve a callee with full structured hints.
    ///
    /// **New resolution order** (qualified identity primary, leaf name
    /// fallback):
    ///
    /// 1. **Receiver-type qualified**, if `receiver_type` is set,
    ///    consult `by_lang_qualified[{receiver_type}::{name}]` with the
    ///    arity filter.  Exactly-one → resolved; same-namespace
    ///    tie-breaker if multiple.  *Receiver types are authoritative*:
    ///    a miss does not fall back to bare leaf lookup (that would be
    ///    a silent reinterpretation).
    /// 2. **Namespace-qualifier qualified**, if `namespace_qualifier`
    ///    is set, try the qualified index with that container.
    ///    Non-authoritative: a miss falls through.
    /// 3. **Caller-self-container**, when the caller lives inside a
    ///    container (method body), try the qualified index against the
    ///    caller's own container.  Resolves bare `foo()` self-calls
    ///    inside a class without collapsing into an unrelated same-leaf
    ///    definition in another file.
    /// 4. **Same-namespace unique leaf**, intra-file bare-leaf call:
    ///    if the caller's namespace contains exactly one arity-matched
    ///    candidate with this leaf, resolve to it.
    /// 5. **Receiver-variable tie-break**, if the same-namespace
    ///    lookup misses but the raw call came with a receiver variable,
    ///    try `{receiver_var}::{name}` as a last qualified attempt.
    ///
    /// 5.5. **Bare-call free-function preference**, for a truly bare
    ///      call (no receiver type, no namespace qualifier, no receiver
    ///      variable), if exactly one same-namespace arity-matched
    ///      candidate has an empty container, resolve to it.  A class
    ///      method cannot be invoked with bare-call syntax from outside
    ///      its class, so this disambiguation is safe even when same-name
    ///      methods exist elsewhere in the file.
    /// 6. **Leaf-name fallback**, arity-filtered same-language lookup.
    ///    Unique → resolved.  Multiple + we had any qualified hint →
    ///    Ambiguous (refuse to guess when a qualifier exists but
    ///    missed).  Multiple + no qualified hint → narrow by namespace,
    ///    then container.
    pub fn resolve_callee(&self, q: &CalleeQuery<'_>) -> CalleeResolution {
        // ── Helpers ─────────────────────────────────────────────────
        let arity_matches = |k: &FuncKey| match q.arity {
            Some(a) => k.arity == Some(a),
            None => true,
        };

        // Look up `{container}::{name}` and return a single arity-matched
        // candidate if one exists (using same-namespace to break ties).
        let try_qualified = |container: &str| -> Option<FuncKey> {
            if container.is_empty() {
                return None;
            }
            let qual = format!("{container}::{}", q.name);
            let candidates: Vec<&FuncKey> = self
                .lookup_qualified(q.caller_lang, &qual)
                .into_iter()
                .map(|(k, _)| k)
                .filter(|k| arity_matches(k))
                .collect();
            match candidates.len() {
                0 => None,
                1 => Some(candidates[0].clone()),
                _ => {
                    let same_ns: Vec<&FuncKey> = candidates
                        .iter()
                        .copied()
                        .filter(|k| k.namespace == q.caller_namespace)
                        .collect();
                    if same_ns.len() == 1 {
                        Some(same_ns[0].clone())
                    } else {
                        None
                    }
                }
            }
        };

        // ── Step 1: receiver_type (authoritative) ───────────────────
        if let Some(rt) = q.receiver_type {
            if let Some(key) = try_qualified(rt) {
                return CalleeResolution::Resolved(key);
            }
            // Authoritative miss: before returning, check whether any
            // candidate exists at all for the leaf name.  If there are
            // some, report Ambiguous with the leaf candidates (so the
            // caller knows we saw the name but refused to pick the
            // wrong container).  If there are none, return NotFound.
            let bare: Vec<&FuncKey> = self
                .lookup_same_lang(q.caller_lang, q.name)
                .into_iter()
                .map(|(k, _)| k)
                .filter(|k| arity_matches(k))
                .collect();
            return if bare.is_empty() {
                CalleeResolution::NotFound
            } else {
                CalleeResolution::Ambiguous(bare.into_iter().cloned().collect())
            };
        }

        // ── Step 2: namespace_qualifier (non-authoritative) ─────────
        if let Some(nq) = q.namespace_qualifier
            && let Some(key) = try_qualified(nq)
        {
            return CalleeResolution::Resolved(key);
        }

        // ── Step 3: caller self-container ───────────────────────────
        if let Some(cc) = q.caller_container
            && let Some(key) = try_qualified(cc)
        {
            return CalleeResolution::Resolved(key);
        }

        // ── Step 4: same-namespace unique leaf ──────────────────────
        let all_candidates: Vec<&FuncKey> = self
            .lookup_same_lang(q.caller_lang, q.name)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        if all_candidates.is_empty() {
            return CalleeResolution::NotFound;
        }

        let arity_filtered: Vec<&FuncKey> = all_candidates
            .iter()
            .copied()
            .filter(|k| arity_matches(k))
            .collect();
        if arity_filtered.is_empty() {
            return CalleeResolution::NotFound;
        }

        let same_ns: Vec<&FuncKey> = arity_filtered
            .iter()
            .copied()
            .filter(|k| k.namespace == q.caller_namespace)
            .collect();
        if same_ns.len() == 1 {
            return CalleeResolution::Resolved(same_ns[0].clone());
        }

        // ── Step 5: receiver_var tie-break (soft) ───────────────────
        if let Some(rv) = q.receiver_var
            && let Some(key) = try_qualified(rv)
        {
            return CalleeResolution::Resolved(key);
        }

        // ── Step 5.5: bare-call free-function preference ────────────
        // A call with no receiver, no namespace qualifier, and no
        // authoritative receiver type is syntactically a free-function
        // invocation: a class method cannot be invoked that way from
        // outside its own class (intra-class self-calls were already
        // resolved by step 3).  When the same-namespace candidate set
        // contains exactly one empty-container entry, it is the
        // unambiguous target, returning Ambiguous here would be a
        // silent false negative whenever a top-level helper happens to
        // share a name with some method elsewhere in the file.
        let syntactic_bare = q.receiver_type.is_none()
            && q.namespace_qualifier.is_none()
            && q.receiver_var.is_none();
        if syntactic_bare {
            let empty_container_same_ns: Vec<&FuncKey> = same_ns
                .iter()
                .copied()
                .filter(|k| k.container.is_empty())
                .collect();
            if empty_container_same_ns.len() == 1 {
                return CalleeResolution::Resolved(empty_container_same_ns[0].clone());
            }
        }

        // ── Step 6: leaf fallback ───────────────────────────────────
        if arity_filtered.len() == 1 {
            return CalleeResolution::Resolved(arity_filtered[0].clone());
        }

        // Multiple arity-matched candidates remain.  When a qualified
        // hint was supplied but missed, refuse to guess, a silent
        // leaf-name pick would defeat the point of qualified-first
        // resolution.  (`receiver_type` is handled in Step 1 and never
        // reaches here; `namespace_qualifier` / `caller_container`
        // missing their target flow through as a soft miss.)
        if q.has_qualified_hint() {
            return CalleeResolution::Ambiguous(arity_filtered.into_iter().cloned().collect());
        }

        // No qualified hints whatsoever, tolerate namespace narrowing.
        match same_ns.len() {
            1 => CalleeResolution::Resolved(same_ns[0].clone()),
            0 => CalleeResolution::Ambiguous(arity_filtered.into_iter().cloned().collect()),
            _ => CalleeResolution::Ambiguous(same_ns.into_iter().cloned().collect()),
        }
    }

    /// Install / refresh the type-hierarchy index from the currently
    /// loaded summaries.  Idempotent, calling twice rebuilds.
    ///
    /// Call this once after pass-1 merge (and again whenever
    /// summary state changes in a way that could affect virtual
    /// dispatch, typically: after the call-graph is rebuilt mid-fixed-point).
    /// `merge()` automatically invalidates so a forgotten reinstall
    /// degrades to today's behaviour rather than a stale lookup.
    pub fn install_hierarchy(&mut self) {
        let h = crate::callgraph::TypeHierarchyIndex::build(self);
        self.hierarchy = Some(h);
    }

    /// Borrow the installed hierarchy index, if any.
    pub fn hierarchy(&self) -> Option<&crate::callgraph::TypeHierarchyIndex> {
        self.hierarchy.as_ref()
    }

    /// Hard cap on hierarchy fan-out from a single call site, see
    /// [`Self::resolve_callee_widened`] for rationale.  Public for tests
    /// that need to assert cap behaviour without hard-coding the value.
    pub const MAX_HIERARCHY_FANOUT: usize = 8;

    /// Resolve a call site to *every* candidate FuncKey reachable
    /// through type-hierarchy fan-out.  This is the runtime counterpart
    /// of the [`crate::callgraph::TypeHierarchyIndex::resolve_with_hierarchy`]
    /// step that the call-graph builder applies at edge-construction time.
    ///
    /// Behaviour:
    ///
    /// * `receiver_type = None` → falls through to
    ///   [`Self::resolve_callee`]; returns `[k]` on `Resolved`, `[]`
    ///   otherwise.
    /// * `receiver_type = Some(rt)` and either no hierarchy is installed
    ///   or `rt` has no recorded sub-types → identical fall-through;
    ///   the hierarchy lookup is a no-op.
    /// * `receiver_type = Some(rt)` with sub-types `s1, s2, …` →
    ///   union of `lookup_qualified` for `(rt, s1, s2, …)` after arity
    ///   filtering.  Result is dedup'd in insertion order
    ///   (direct-receiver match first, then each sub-type's match).
    ///
    /// Hard cap: at most [`Self::MAX_HIERARCHY_FANOUT`] keys are
    /// returned.  When the cap fires, the cap-hit is logged at `debug`
    /// and the tail impls are silently dropped, over-fanning is a
    /// precision-tax knob, not a soundness one.
    ///
    /// Empty result + non-empty `subs` triggers a
    /// secondary fall-through to [`Self::resolve_callee`] so a
    /// type-fact misclassification (receiver typed as a super-class
    /// that has no method by this name on any sub) does not silently
    /// regress to "no resolution at all", the leaf-name path can still
    /// pick up a match.  This preserves the
    /// "subset of today's targets, never a superset" rule under
    /// hierarchy-aware resolution failure.
    pub fn resolve_callee_widened(&self, q: &CalleeQuery<'_>) -> Vec<FuncKey> {
        let arity_matches = |k: &FuncKey| match q.arity {
            Some(a) => k.arity == Some(a),
            None => true,
        };

        let single_fallback = || -> Vec<FuncKey> {
            match self.resolve_callee(q) {
                CalleeResolution::Resolved(k) => vec![k],
                _ => Vec::new(),
            }
        };

        // Hierarchy fan-out only fires when the call has an
        // authoritative receiver type AND the index is installed AND
        // the type has recorded sub-types.  Every other case collapses
        // to today's resolver.
        let Some(rt) = q.receiver_type.filter(|s| !s.is_empty()) else {
            return single_fallback();
        };
        let Some(h) = self.hierarchy.as_ref() else {
            return single_fallback();
        };
        let subs = h.subs_of(q.caller_lang, rt);
        if subs.is_empty() {
            return single_fallback();
        }

        // Union direct + sub-type matches in insertion order.  Dedup is
        // O(n²) over the cap (n ≤ 8) so a HashSet would be wasted
        // overhead; linear scan is faster and order-preserving.
        let mut out: Vec<FuncKey> = Vec::new();
        let push_unique = |out: &mut Vec<FuncKey>, k: FuncKey| -> bool {
            if !out.iter().any(|e| e == &k) {
                out.push(k);
                true
            } else {
                false
            }
        };
        let qualified_lookup = |container: &str| -> Vec<FuncKey> {
            let qual = format!("{container}::{}", q.name);
            self.lookup_qualified(q.caller_lang, &qual)
                .into_iter()
                .map(|(k, _)| k.clone())
                .filter(|k| arity_matches(k))
                .collect()
        };
        for k in qualified_lookup(rt) {
            push_unique(&mut out, k);
            if out.len() >= Self::MAX_HIERARCHY_FANOUT {
                tracing::debug!(
                    receiver = rt,
                    method = q.name,
                    cap = Self::MAX_HIERARCHY_FANOUT,
                    "hierarchy fan-out cap reached on direct receiver match"
                );
                return out;
            }
        }
        for sub in subs {
            for k in qualified_lookup(sub.as_str()) {
                push_unique(&mut out, k);
                if out.len() >= Self::MAX_HIERARCHY_FANOUT {
                    tracing::debug!(
                        receiver = rt,
                        method = q.name,
                        cap = Self::MAX_HIERARCHY_FANOUT,
                        "hierarchy fan-out cap reached; tail impls dropped"
                    );
                    return out;
                }
            }
        }

        if out.is_empty() {
            // Hierarchy widening produced nothing (e.g., none of the
            // recorded sub-types declare this method).  Fall back to
            // today's qualified-first resolver so the misclassified-
            // type case still finds a leaf match, the same
            // "preserve today's behaviour on miss" rule the call-graph
            // builder applies.
            return single_fallback();
        }

        out
    }
}

impl std::fmt::Debug for GlobalSummaries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalSummaries")
            .field("len", &self.by_key.len())
            .field("ssa_len", &self.ssa_by_key.len())
            .field("bodies_len", &self.bodies_by_key.len())
            .field("auth_len", &self.auth_by_key.len())
            .finish()
    }
}

/// Return `true` iff two `FuncSummary`s can be safely union-merged at the
/// same `FuncKey`.
///
/// Only fields that a single function definition is guaranteed to agree on
/// are compared.  Behaviour fields (`source_caps`, `propagating_params`,
/// `callees`, …) are deliberately ignored: merge is *allowed* to combine
/// those.  The test is symmetric.
///
/// Comparison rules
/// ────────────────
/// * **`param_count` / `kind` / `container`**, unconditional agreement.
///   Any mismatch is a hard collision between distinct functions.
/// * **`file_path`**, agree when both sides are populated.  A blank path
///   can come from synthetic summaries constructed in tests / interop
///   configs and should not force a split.
/// * **`param_names`**, agree when both sides are populated.  Legacy
///   summaries may persist with empty names; treating empty as "unknown"
///   avoids gratuitous splits while still catching real divergence.
/// * **`module_path`**, Rust-only.  Agreed when both sides are `Some`.
///   A missing module path on one side is legacy-compatible; two *distinct*
///   `Some` values mean the two summaries belong to different crates'
///   module trees.
pub(crate) fn summaries_compatible(a: &FuncSummary, b: &FuncSummary) -> bool {
    if a.param_count != b.param_count {
        return false;
    }
    if a.kind != b.kind {
        return false;
    }
    if a.container != b.container {
        return false;
    }
    if !a.file_path.is_empty() && !b.file_path.is_empty() && a.file_path != b.file_path {
        return false;
    }
    if !a.param_names.is_empty() && !b.param_names.is_empty() && a.param_names != b.param_names {
        return false;
    }
    match (&a.module_path, &b.module_path) {
        (Some(l), Some(r)) if l != r => return false,
        _ => {}
    }
    true
}

/// Derive a deterministic synthetic disambiguator from the
/// identity-relevant fields of a `FuncSummary`.
///
/// The top bit is **not** set here, the caller composes the final value
/// via `SYNTHETIC_DISAMBIG_BIT | (hash & !SYNTHETIC_DISAMBIG_BIT)` so that
/// (a) the caller can safely bump the low bits to probe for a free slot,
/// and (b) the synthetic namespace stays disjoint from byte-offset
/// disambigs produced by `cfg.rs`.
pub(crate) fn synthesize_disambig(summary: &FuncSummary) -> u32 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    summary.param_count.hash(&mut h);
    summary.param_names.hash(&mut h);
    summary.container.hash(&mut h);
    summary.kind.hash(&mut h);
    summary.file_path.hash(&mut h);
    summary.source_caps.hash(&mut h);
    summary.sanitizer_caps.hash(&mut h);
    summary.sink_caps.hash(&mut h);
    summary.module_path.hash(&mut h);
    h.finish() as u32
}

/// Return `true` iff the new `SsaFuncSummary` is consistent with the
/// existing one at the same `FuncKey`.
///
/// `SsaFuncSummary` carries no explicit `param_count`; we approximate
/// it via the maximum parameter index referenced by either summary.
/// Two summaries are compatible when neither references a parameter
/// index the other cannot, an upward compatibility check, so a refined
/// summary that merely adds flows for previously-silent parameters is
/// still considered compatible.
fn ssa_summaries_compatible(
    existing: &SsaFuncSummary,
    new: &SsaFuncSummary,
    key_arity: Option<usize>,
) -> bool {
    if !ssa_summary_fits_arity(existing, key_arity) {
        // Existing entry itself is inconsistent with the key; don't let
        // that inconsistency mask a real collision with the new entry.
        return false;
    }
    if !ssa_summary_fits_arity(new, key_arity) {
        return false;
    }
    true
}

/// Every parameter index referenced by `summary` must fit inside
/// `key_arity` when it is known.  `None` (unknown arity) accepts any
/// index.
fn ssa_summary_fits_arity(summary: &SsaFuncSummary, key_arity: Option<usize>) -> bool {
    let arity = match key_arity {
        Some(a) => a,
        None => return true,
    };
    let refs = summary
        .param_to_return
        .iter()
        .map(|(i, _)| *i)
        .chain(summary.param_to_sink.iter().map(|(i, _)| *i))
        .chain(summary.param_to_sink_param.iter().map(|(i, _, _)| *i))
        .chain(summary.param_container_to_return.iter().copied())
        .chain(
            summary
                .param_to_container_store
                .iter()
                .flat_map(|(a, b)| [*a, *b]),
        )
        .chain(summary.source_to_callback.iter().map(|(i, _)| *i))
        .chain(summary.abstract_transfer.iter().map(|(i, _)| *i))
        .chain(summary.param_return_paths.iter().map(|(i, _)| *i));
    for i in refs {
        if i >= arity {
            return false;
        }
    }
    // Every parameter referenced by a points-to edge must also fit the
    // key's arity.  An overflow-flagged summary is conservative by
    // construction and can be kept as-is.
    if let Some(max) = summary.points_to.max_param_index()
        && (max as usize) >= arity
    {
        return false;
    }
    true
}

/// Derive a deterministic synthetic disambiguator for an
/// `SsaFuncSummary`.  Mirrors `synthesize_disambig` but restricted to
/// SSA-level structural signals.
fn synthesize_ssa_disambig(summary: &SsaFuncSummary) -> u32 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    summary.param_to_return.len().hash(&mut h);
    summary.param_to_sink.len().hash(&mut h);
    summary.source_caps.bits().hash(&mut h);
    summary.param_to_sink_param.len().hash(&mut h);
    summary.param_container_to_return.len().hash(&mut h);
    summary.param_to_container_store.len().hash(&mut h);
    summary.receiver_to_sink.bits().hash(&mut h);
    summary.receiver_to_return.is_some().hash(&mut h);
    summary.return_type.is_some().hash(&mut h);
    summary.return_abstract.is_some().hash(&mut h);
    summary.source_to_callback.len().hash(&mut h);
    summary.abstract_transfer.len().hash(&mut h);
    summary.param_return_paths.len().hash(&mut h);
    summary.points_to.edges.len().hash(&mut h);
    summary.points_to.overflow.hash(&mut h);
    summary.points_to.returns_fresh_alloc.hash(&mut h);
    h.finish() as u32
}

/// Merge a set of per‑file summaries into a single `GlobalSummaries` map.
///
/// Merging only happens for exact `FuncKey` matches (same lang + namespace +
/// name + arity).  Functions with the same bare name but different languages
/// or namespaces are stored separately.
pub fn merge_summaries(
    per_file: impl IntoIterator<Item = FuncSummary>,
    scan_root: Option<&str>,
) -> GlobalSummaries {
    let mut map = GlobalSummaries::new();

    for fs in per_file {
        let key = fs.func_key(scan_root);
        map.insert(key, fs);
    }

    map
}

#[cfg(test)]
mod tests;

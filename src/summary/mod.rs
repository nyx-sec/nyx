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
//! during call resolution. `GlobalSummaries::ssa_by_key` stores SSA summaries
//! keyed by [`FuncKey`]; `GlobalSummaries::by_name` holds the fallback
//! name-keyed map for cases where an exact key is not found.
//!
//! Same-name collisions across files are merged conservatively: capabilities
//! are unioned and booleans are OR-ed so no true positive is silently dropped.

mod body_cell;
pub mod deps;
pub mod points_to;
pub mod ssa_summary;

use crate::labels::Cap;
use crate::summary::deps::{Fp, KeyedRead, MapId, NamedRead};
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::{FuncKey, FuncKind, Lang, normalize_namespace};
use body_cell::BodyCell;
pub use body_cell::EncodedBody;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Deserializer, Serialize};
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

// ── Sink site (primary sink-location attribution) ───────────────────────

/// A single dangerous-instruction site inside a function's body.
/// Pairs a [`Cap`] with the source location of the consuming
/// instruction so cross-file findings can attribute to the callee
/// rather than the caller call-site.
///
/// `from_chain` distinguishes two flavours of recorded site:
/// * `false`, the site was resolved via the body-local locator span,
///   i.e. it points at a sink instruction in the function's own body.
/// * `true`, the site was promoted from a deeper callee through
///   `event.primary_sink_site`, i.e. this function's summary carries
///   a chain-hop marker for a sink several frames down.
///
/// Pass-2 emission gates promotion of a site into `Finding.primary_location`
/// on `from_chain || file_rel != caller_file_rel`: same-file single-hop
/// helpers keep call-site emission (matching benchmark and real-world
/// fixture calibration), multi-hop chains and cross-file callees surface
/// the deep sink line.  See "Multi-hop intra-file sink attribution gap"
/// in deferred.md for the design tradeoff.
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
    /// True when this site was promoted from a deeper callee's summary
    /// (`event.primary_sink_site` chain-hop), false when recorded from
    /// the function's own locator span.  See struct docs.
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_chain: bool,
}

impl SinkSite {
    /// Dedup key: two sites with the same `(file_rel, line, col, cap)`
    /// describe the same consumption and collapse on merge.  `from_chain`
    /// is intentionally excluded, the upgrade rule in [`union_sink_sites`]
    /// takes over when two sites with different `from_chain` collide.
    pub(crate) fn dedup_key(&self) -> (&str, u32, u32, u32) {
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
            from_chain: false,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
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
            from_chain: false,
        }
    }
}

pub(crate) use crate::utils::snippet::line_snippet;

/// Union two `SmallVec<[SinkSite; 1]>` lists with `(file_rel, line, col,
/// cap)` dedup.  Preserves insertion order of `existing` then appends any
/// new sites from `incoming` not already present.  When two sites with the
/// same dedup key collide, `from_chain=true` wins, so a chain-hop marker is
/// never lost when a same-file locator span happens to share coordinates.
pub(crate) fn union_sink_sites(existing: &mut SmallVec<[SinkSite; 1]>, incoming: &[SinkSite]) {
    for site in incoming {
        let key = site.dedup_key();
        if let Some(ex) = existing.iter_mut().find(|s| s.dedup_key() == key) {
            if site.from_chain && !ex.from_chain {
                ex.from_chain = true;
            }
        } else {
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
/// * `span`, optional 1-based `(line, col)` source coordinate of the call
///   expression, populated at CFG-build time when source bytes are
///   available.  `None` for legacy summaries loaded from SQLite that
///   pre-date the span field, and for synthetic test fixtures that build
///   `CalleeSite` values directly.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<(u32, u32)>,
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
    // Stored as raw `u32` so serde doesn't need to know about `bitflags`.
    /// Caps this function **introduces**, i.e. the return value carries
    /// freshly‑tainted data even if no argument was tainted.
    pub source_caps: u32,

    /// Caps this function **cleans**, passing tainted data through this
    /// function strips the corresponding bits.
    pub sanitizer_caps: u32,

    /// Caps this function **consumes unsafely**, calling it with tainted
    /// arguments that still carry these bits is a finding.
    pub sink_caps: u32,

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

    /// Phase-10 Next.js entry-point classification.  When `Some(_)`,
    /// the function is treated as an externally-driven entry point
    /// whose parameters are seeded as `TaintOrigin::Source` at SSA
    /// entry, mirroring the way an HTTP request handler's formals are
    /// adversary-controlled by default.  `None` for ordinary
    /// helpers — pass-2 keeps its existing baseline-subtraction
    /// semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_kind: Option<crate::entry_points::EntryKind>,
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
        FuncKey::from_parts(
            Lang::from_slug(&self.lang).unwrap_or(Lang::Rust),
            normalize_namespace(&self.file_path, scan_root),
            self.container.clone(),
            self.name.clone(),
            Some(self.param_count),
            self.disambig,
            self.kind,
        )
    }

    /// Phase-04 [`FuncKey`] builder that consults a project-wide
    /// [`crate::resolve::ModuleGraph`].
    ///
    /// When the file producing this summary lies inside a discovered
    /// package, `namespace` becomes `"@scope/name::src/file.ts"`;
    /// otherwise the result matches [`Self::func_key`] exactly.
    /// Phase 04 only adds the helper, no resolution call site uses
    /// it. Phase 10 switches the JS/TS pass-1 path to call this
    /// instead of [`Self::func_key`].
    pub fn func_key_with_resolver(
        &self,
        scan_root: Option<&str>,
        module_graph: Option<&crate::resolve::ModuleGraph>,
    ) -> FuncKey {
        FuncKey::from_parts(
            Lang::from_slug(&self.lang).unwrap_or(Lang::Rust),
            crate::symbol::namespace_with_package(&self.file_path, scan_root, module_graph),
            self.container.clone(),
            self.name.clone(),
            Some(self.param_count),
            self.disambig,
            self.kind,
        )
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
    /// Syntactic receiver: the segment right before the leaf name (`"repo"`
    /// in `this.repo.find()`, `"super"` in `super.init()`).  Decides
    /// whether the caller's own container may hold the target (see
    /// [`CallReceiver`]); otherwise only a tie-breaker, since a variable
    /// name is a weak proxy for a class name.
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

    /// How the call's receiver relates to the caller's own instance.
    pub fn receiver(&self) -> CallReceiver {
        classify_call_receiver(self.caller_lang, self.receiver_var, self.caller_container)
    }
}

/// How a call's receiver relates to the instance the calling function
/// runs on.  Only an [`CallReceiver::Own`] call can target a method of the
/// caller's own container through the caller-container resolution step,
/// and only an `Own` call can be the caller calling itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallReceiver {
    /// No receiver (`foo()`), the caller's own instance or class
    /// (`this.foo()`, `self::foo()`, `static::foo()`, `cls.foo()`,
    /// `Owner::foo()` inside `Owner`), or a Go method receiver, which each
    /// method names freely.
    Own,
    /// The caller's supertype: `super.foo()`, `super().foo()`,
    /// `parent::foo()`.  Never the caller's own container.
    Super,
    /// Any other object: `repo.find()`, `this.repo.find()`,
    /// `$this->inner->get()`, `json.dumps()`.
    Other,
}

/// Classify a call's receiver.  `receiver` is the receiver text the
/// callee name carries before its leaf (`None` for a bare call); a
/// multi-segment chain such as `this.repo` or `$this->inner` is a field
/// of some object, never the caller's own instance.
pub fn classify_call_receiver(
    lang: Lang,
    receiver: Option<&str>,
    caller_container: Option<&str>,
) -> CallReceiver {
    let Some(r) = receiver.filter(|r| !r.is_empty()) else {
        return CallReceiver::Own;
    };
    match r {
        "this" | "self" | "$this" | "static" | "Self" | "cls" => CallReceiver::Own,
        "super" | "parent" => CallReceiver::Super,
        _ if r.starts_with("super(") => CallReceiver::Super,
        _ if caller_container.is_some_and(|c| !c.is_empty() && c == r) => CallReceiver::Own,
        _ if lang == Lang::Go && r.chars().all(|c| c == '_' || c.is_alphanumeric()) => {
            CallReceiver::Own
        }
        _ => CallReceiver::Other,
    }
}

/// The fields of a [`FuncSummary`] the SCC fixed-point loop compares
/// between iterations: `(source_caps, sanitizer_caps, sink_caps,
/// propagating_params)`.
pub type CapsFingerprint = (u32, u32, u32, Vec<usize>);

pub fn caps_fingerprint(s: &FuncSummary) -> CapsFingerprint {
    (
        s.source_caps,
        s.sanitizer_caps,
        s.sink_caps,
        s.propagating_params.clone(),
    )
}

/// Pre-write values of every key written through
/// [`GlobalSummaries::insert_tracked`] / [`GlobalSummaries::insert_ssa_tracked`]
/// since the log was created.
///
/// One SCC fixed-point iteration writes only the summaries of the files it
/// re-analysed, so comparing each written key's first pre-write value with
/// its current value finds every key that changed, at O(keys written)
/// instead of the O(functions in the repo) a whole-map snapshot diff costs.
/// A key that did not exist before its first write counts as changed.
#[derive(Default)]
pub struct SummaryChangeLog {
    caps_before: HashMap<FuncKey, Option<CapsFingerprint>>,
    ssa_before: HashMap<FuncKey, Option<SsaFuncSummary>>,
}

impl SummaryChangeLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Written keys whose [`caps_fingerprint`] differs from before.
    pub fn changed_cap_keys(&self, gs: &GlobalSummaries) -> std::collections::HashSet<FuncKey> {
        self.caps_before
            .iter()
            .filter(|(k, before)| {
                let now = gs.by_key.get(*k).map(|e| caps_fingerprint(&e.v));
                now != **before
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Written keys whose SSA summary carries different facts than before
    /// (see [`SsaFuncSummary::same_facts`]).
    pub fn changed_ssa_keys(&self, gs: &GlobalSummaries) -> std::collections::HashSet<FuncKey> {
        self.ssa_before
            .iter()
            .filter(|(k, before)| {
                match (gs.ssa_by_key.get(*k).map(|e| &e.v), Option::as_ref(*before)) {
                    (Some(now), Some(before)) => !now.same_facts(before),
                    (None, None) => false,
                    _ => true,
                }
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The SSA summary `key` held before its first write, `None` when the
    /// key was not written or did not exist yet.
    pub fn ssa_before(&self, key: &FuncKey) -> Option<&SsaFuncSummary> {
        self.ssa_before.get(key).and_then(Option::as_ref)
    }

    /// The cap tuple and SSA summary `key` held before this log's writes:
    /// the logged pre-write value for each part that was written, the
    /// current value for a part that was not.
    pub fn values_before<'a>(
        &'a self,
        gs: &'a GlobalSummaries,
        key: &FuncKey,
    ) -> (Option<CapsFingerprint>, Option<&'a SsaFuncSummary>) {
        let caps = match self.caps_before.get(key) {
            Some(before) => before.clone(),
            None => gs.by_key.get(key).map(|e| caps_fingerprint(&e.v)),
        };
        let ssa = match self.ssa_before.get(key) {
            Some(before) => before.as_ref(),
            None => gs.ssa_by_key.get(key).map(|e| &e.v),
        };
        (caps, ssa)
    }

    /// Every key written through this log, coarse and SSA.
    pub fn written_keys(&self) -> impl Iterator<Item = &FuncKey> {
        self.caps_before.keys().chain(self.ssa_before.keys())
    }
}

/// A stored summary plus its content fingerprint, computed on first use.
///
/// The fingerprint is only needed while incremental pass 2 records or
/// replays reads, so it is computed lazily and reset on every write.
#[derive(Debug)]
struct Stored<T> {
    v: T,
    fp: std::sync::OnceLock<Fp>,
    /// Fingerprint with positions rebased (see [`deps::fp_value_rebased`]),
    /// computed on first use.  Only bodies are read this way.
    shape: std::sync::OnceLock<Fp>,
}

impl<T> Stored<T> {
    fn new(v: T) -> Self {
        Stored {
            v,
            fp: std::sync::OnceLock::new(),
            shape: std::sync::OnceLock::new(),
        }
    }

    /// A value whose fingerprints were computed when it was stored.
    fn with_fps(v: T, fp: Fp, shape: Fp) -> Self {
        Stored {
            v,
            fp: std::sync::OnceLock::from(fp),
            shape: std::sync::OnceLock::from(shape),
        }
    }

    fn into_inner(self) -> T {
        self.v
    }

    /// Mutable access; drops the cached fingerprint.
    fn get_mut(&mut self) -> &mut T {
        self.fp = std::sync::OnceLock::new();
        self.shape = std::sync::OnceLock::new();
        &mut self.v
    }
}

impl<T: Serialize> Stored<T> {
    fn fp(&self) -> Fp {
        *self.fp.get_or_init(|| deps::fp_value(&self.v))
    }

    fn shape_fp(&self) -> Fp {
        *self
            .shape
            .get_or_init(|| deps::fp_value_rebased(&self.v, deps::POSITION_FIELDS))
    }
}

fn stored_fp<T: Serialize>(e: Option<&Stored<T>>) -> Fp {
    e.map_or(deps::ABSENT, Stored::fp)
}

// ── Lookup map used by the taint engine ─────────────────────────────────

/// `name -> keys` maps split by language.
///
/// Resolution probes these once per call instruction, so a lookup takes the
/// name as a `&str` and borrows the key list: a `(Lang, String)` map key would
/// need an owned `String` per probe. Keys are only ever added, and every key
/// listed here is also present in [`GlobalSummaries::by_key`].
#[derive(Default)]
struct LangIndex(FxHashMap<Lang, FxHashMap<String, Vec<FuncKey>>>);

impl LangIndex {
    fn get(&self, lang: Lang, name: &str) -> &[FuncKey] {
        self.0
            .get(&lang)
            .and_then(|by_name| by_name.get(name))
            .map_or(&[], Vec::as_slice)
    }

    fn insert_unique(&mut self, lang: Lang, name: String, key: &FuncKey) {
        insert_canonical(
            self.0.entry(lang).or_default().entry(name).or_default(),
            key,
        );
    }
}

/// Total order on key identity used inside every name-index bucket.
fn canonical_key_order(a: &FuncKey, b: &FuncKey) -> std::cmp::Ordering {
    type Rank<'k> = (
        &'k str,
        &'k str,
        &'k str,
        Option<usize>,
        Option<u32>,
        u8,
        u8,
    );
    fn rank(k: &FuncKey) -> Rank<'_> {
        (
            k.namespace.as_str(),
            k.container.as_str(),
            k.name.as_str(),
            k.arity,
            k.disambig,
            k.kind as u8,
            k.lang as u8,
        )
    }
    rank(a).cmp(&rank(b))
}

/// Add `key` to a name-index bucket unless present, keeping the bucket
/// sorted by [`canonical_key_order`].  The order of a bucket is then a
/// function of its contents alone: a full scan and an indexed rescan that
/// inserted the same keys in a different order see the same list, and a
/// recorded read of the bucket stays valid when an unchanged file's keys are
/// re-inserted.
fn insert_canonical(keys: &mut Vec<FuncKey>, key: &FuncKey) {
    if let Err(pos) = keys.binary_search_by(|k| canonical_key_order(k, key)) {
        keys.insert(pos, key.clone());
    }
}

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
    /// FxHashMap (rustc_hash) replaces stdlib SipHash.  FuncKey carries 3
    /// String fields, so any HashMap operation walks ≥30 bytes through the
    /// hasher; FxHash is ~5x faster than SipHash on this workload.  Seed
    /// is fixed (no DoS hardening), which is fine for an in-process index
    /// keyed by static program-derived names.
    by_key: FxHashMap<FuncKey, Stored<FuncSummary>>,
    /// Bare leaf-name index, kept for compatibility with callers that only
    /// see an unqualified call string.  A single name may map to many keys
    /// across containers / files / arities.
    by_lang_name: LangIndex,
    /// Container-qualified index: keyed on `"{container}::{name}"` (or just
    /// `name` for free functions).  Used to resolve calls when the call-site
    /// can supply a receiver / container hint (e.g. `OrderService::process`).
    by_lang_qualified: LangIndex,
    /// Rust-only secondary index keyed on `(module_path, name)`.
    ///
    /// Populated whenever a Rust [`FuncSummary`] is inserted with a
    /// `module_path` set. Used by use-map driven resolution to look up
    /// candidates by their crate-relative module rather than their
    /// filesystem path. Same name / module / arity overloads land on the
    /// same vector, arity narrowing happens at resolution time.
    by_rust_module: FxHashMap<(String, String), Vec<FuncKey>>,
    /// Precise SSA-derived per-parameter summaries, keyed by `FuncKey`.
    /// These take precedence over `FuncSummary` during callee resolution.
    ssa_by_key: HashMap<FuncKey, Stored<SsaFuncSummary>>,
    /// Sibling index over [`Self::ssa_by_key`] keyed by
    /// `(lang, namespace, name)`.  Populated in lockstep with `ssa_by_key`
    /// (every `insert_ssa` / `merge` adds the key).  Used by the
    /// cross-package SSA resolution path (step 0.7 in
    /// `taint::ssa_transfer::resolve_callee`) to avoid an
    /// `O(|ssa_by_key|)` linear scan per cross-package call site:
    /// the resolver looks up the candidate `Vec<FuncKey>` and narrows
    /// to a single hit by container / arity / disambig.  Strictly
    /// additive: when the index is empty (e.g. tests that never insert
    /// SSA summaries) the resolver falls back to its existing flat
    /// paths.
    ///
    /// Note: SSA summaries are append-only on `GlobalSummaries` (no
    /// remove/clear methods), so the index never needs invalidation.
    /// Synthetic-disambig probing in
    /// [`Self::reconcile_ssa_summary_key`] only mutates the inserted
    /// key's `disambig` field, never the `(lang, namespace, name)`
    /// triple, so the index value still points at every relevant
    /// `FuncKey` after reconciliation.
    ssa_by_lang_ns_name: HashMap<(Lang, String, String), Vec<FuncKey>>,
    /// Cross-file callee bodies for interprocedural symbolic execution.
    /// Keyed by `FuncKey` (same identity model as SSA summaries).
    bodies_by_key: HashMap<FuncKey, Stored<BodyCell>>,
    /// Per-function auth-check summaries for cross-file helper lifting.
    /// Keyed by `FuncKey` so a call-site resolver can go from a resolved
    /// callee name to the helper's auth-check signature.  Populated in
    /// pass 1 and consumed by
    /// [`crate::auth_analysis::run_auth_analysis`] during pass 2.
    auth_by_key: HashMap<FuncKey, Stored<crate::auth_analysis::model::AuthCheckSummary>>,
    /// Per-Python-file router declarations + `include_router` edges,
    /// keyed by `module_id_for_storage(file_path)` (basename without
    /// `.py`, or `parent_dir::__init__` for `__init__.py`).  Populated
    /// during pass 1 and consumed by
    /// [`Self::resolve_cross_file_router_deps`] at pass 2 entry to lift
    /// FastAPI router-level `dependencies=[Security(...)]` declared in a
    /// parent file (`__init__.py` calling
    /// `<parent>.include_router(<child>.router, ...)`) onto the bare
    /// child router declared in another file — closing the airflow
    /// execution-API auth-recognition gap on routes attached to bare
    /// child routers.
    router_facts_by_module: HashMap<String, crate::auth_analysis::router_facts::PerFileRouterFacts>,
    /// Per-file Phase-09 cross-package import maps, keyed by file
    /// namespace (scan-root-relative path, the same form
    /// [`FuncKey::namespace`] uses).  Populated in pass 1 from each
    /// file's [`crate::cfg::FileCfg::resolved_imports`] and consumed by
    /// `inline_analyse_callee` when the inlined callee body's own
    /// `cross_package_imports` Arc is empty (i.e. the body was loaded
    /// from SQLite, where the field is `#[serde(skip)]`).  Closes the
    /// indexed-mode parity gap on transitive cross-package IPA inside
    /// inlined frames.
    cross_package_imports_by_namespace: HashMap<String, std::sync::Arc<HashMap<String, FuncKey>>>,
    /// Cross-file caller-scope IPA accumulator (Phase 2), keyed by
    /// `(Lang, callee_leaf_name)`.  For each callee leaf observed in
    /// pass 1, records whether EVERY caller across the whole index is an
    /// authorized route handler, plus the union of route-level checks to
    /// lift onto the callee.  Consumed by
    /// [`crate::auth_analysis::caller_scope::apply_cross_file_caller_scope`]
    /// at pass 2 to suppress `missing_ownership_check` /
    /// `token_override_without_validation` on private helpers that live in
    /// a different file from their authorized route handler (the dominant
    /// sentry / saleor / airflow FP shape).  Folded with AND/OR/union so
    /// it combines safely under rayon `reduce`.  See
    /// [`crate::auth_analysis::caller_scope`] for the soundness argument.
    caller_scope_by_callee:
        HashMap<(Lang, String), crate::auth_analysis::caller_scope::CalleeCallerAcc>,
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
    /// Functions with at least one resolved caller elsewhere in the
    /// program, from the pass-2 call graph.  Installed by
    /// [`Self::install_called_keys`]; empty until then, which reads as "no
    /// known caller" everywhere.  Consulted by the JS/TS handler-param
    /// auto-seed, which only stands in for callers the scan cannot see.
    called_keys: rustc_hash::FxHashSet<FuncKey>,
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
            match self.by_key.get(&key).map(|e| &e.v) {
                Some(existing) if !summaries_compatible(existing, summary) => {
                    let synth = synthesize_disambig(summary).wrapping_add(probe);
                    key.set_disambig(Some(
                        SYNTHETIC_DISAMBIG_BIT | (synth & !SYNTHETIC_DISAMBIG_BIT),
                    ));
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
            let conflict = match self.ssa_by_key.get(&key).map(|e| &e.v) {
                Some(existing) => !ssa_summaries_compatible(existing, summary, key.arity),
                None => !ssa_summary_fits_arity(summary, key.arity),
            };
            if !conflict {
                return key;
            }
            let synth = synthesize_ssa_disambig(summary).wrapping_add(probe);
            key.set_disambig(Some(
                SYNTHETIC_DISAMBIG_BIT | (synth & !SYNTHETIC_DISAMBIG_BIT),
            ));
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
    fn reconcile_body_key(&self, mut key: FuncKey, param_count: usize) -> FuncKey {
        let mut probe: u32 = 0;
        loop {
            let conflict = match self.bodies_by_key.get(&key).map(|e| &e.v) {
                Some(existing) => existing.param_count() != param_count,
                None => match key.arity {
                    Some(a) => a != param_count,
                    None => false,
                },
            };
            if !conflict {
                return key;
            }
            let synth = (param_count as u32)
                .wrapping_mul(0x9E37_79B9)
                .wrapping_add(probe);
            key.set_disambig(Some(
                SYNTHETIC_DISAMBIG_BIT | (synth & !SYNTHETIC_DISAMBIG_BIT),
            ));
            key.set_arity(Some(param_count));
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
    /// is not `summaries_compatible` with it, we mint a synthetic
    /// disambig (top bit set to stay disjoint from byte-offset disambigs)
    /// and retry the insert under the fresh key so *both* functions are
    /// preserved.
    pub fn insert(&mut self, key: FuncKey, summary: FuncSummary) {
        let key = self.reconcile_func_summary_key(key, &summary);
        self.insert_reconciled(key, summary);
    }

    /// [`Self::insert`] that also records in `log` the convergence view
    /// the target key held before this iteration first wrote it.  Used by
    /// the SCC fixed-point loop so it can tell which keys changed without
    /// snapshotting every summary in the repo.
    pub fn insert_tracked(
        &mut self,
        key: FuncKey,
        summary: FuncSummary,
        log: &mut SummaryChangeLog,
    ) {
        let key = self.reconcile_func_summary_key(key, &summary);
        if !log.caps_before.contains_key(&key) {
            let before = self.by_key.get(&key).map(|e| caps_fingerprint(&e.v));
            log.caps_before.insert(key.clone(), before);
        }
        self.insert_reconciled(key, summary);
    }

    fn insert_reconciled(&mut self, key: FuncKey, summary: FuncSummary) {
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
            .and_modify(|stored| {
                let existing = stored.get_mut();
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
            .or_insert_with(|| Stored::new(summary));

        self.by_lang_name.insert_unique(lang, name, &key);
        self.by_lang_qualified.insert_unique(lang, qualified, &key);

        if let Some(mp) = rust_module {
            let mk = self
                .by_rust_module
                .entry((mp, key.name.clone()))
                .or_default();
            insert_canonical(mk, &key);
        }
    }

    /// Exact lookup by fully-qualified key.
    pub fn get(&self, key: &FuncKey) -> Option<&FuncSummary> {
        let e = self.by_key.get(key);
        deps::note_keyed(KeyedRead::Func, key, || stored_fp(e));
        e.map(|e| &e.v)
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
        if let Some(hit) = self.get(key) {
            return Some(hit);
        }
        if key.disambig.is_some() {
            return None;
        }
        deps::note_keyed(KeyedRead::Interop, key, || self.interop_fp(key));
        self.interop_scan(key).map(|e| &e.v)
    }

    /// The single entry `get_for_interop` falls back to for a key without
    /// `disambig`.
    fn interop_scan(&self, key: &FuncKey) -> Option<&Stored<FuncSummary>> {
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

    fn interop_fp(&self, key: &FuncKey) -> Fp {
        let _quiet = deps::Suppress::new();
        stored_fp(self.interop_scan(key))
    }

    /// All same-language matches for a bare function name.
    pub fn lookup_same_lang(&self, lang: Lang, name: &str) -> Vec<(&FuncKey, &FuncSummary)> {
        self.keys_same_lang(lang, name)
            .iter()
            .filter_map(|k| self.get(k).map(|v| (k, v)))
            .collect()
    }

    /// Keys of every same-language function with this bare name, in insertion
    /// order. Borrows the index: no allocation and no summary lookup, for the
    /// resolver, which only needs the keys.
    pub fn keys_same_lang(&self, lang: Lang, name: &str) -> &[FuncKey] {
        let keys = self.by_lang_name.get(lang, name);
        deps::note_named(
            || NamedRead::LangName(lang, name.to_string()),
            || deps::fp_keys(keys),
        );
        keys
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
        let keys = self
            .by_rust_module
            .get(&(module_path.to_string(), name.to_string()));
        deps::note_named(
            || NamedRead::RustModule(module_path.to_string(), name.to_string()),
            || deps::fp_keys(keys.into_iter().flatten()),
        );
        keys.map(|keys| {
            keys.iter()
                .filter_map(|k| self.get(k).map(|v| (k, v)))
                .collect()
        })
        .unwrap_or_default()
    }

    /// Container-qualified lookup.  `qualified` should be
    /// `"Container::name"` (use [`FuncKey::qualified_name`]) or `"name"`.
    pub fn lookup_qualified(&self, lang: Lang, qualified: &str) -> Vec<(&FuncKey, &FuncSummary)> {
        self.keys_qualified(lang, qualified)
            .iter()
            .filter_map(|k| self.get(k).map(|v| (k, v)))
            .collect()
    }

    /// Keys indexed under `"Container::name"` (or `"name"`), in insertion
    /// order. Borrowing counterpart of [`Self::lookup_qualified`].
    pub fn keys_qualified(&self, lang: Lang, qualified: &str) -> &[FuncKey] {
        let keys = self.by_lang_qualified.get(lang, qualified);
        deps::note_named(
            || NamedRead::Qualified(lang, qualified.to_string()),
            || deps::fp_keys(keys),
        );
        keys
    }

    /// Merge another `GlobalSummaries` into this one (for parallel fold/reduce).
    pub fn merge(&mut self, other: GlobalSummaries) {
        // `insert` rebuilds every secondary index (by_lang_name, by_lang_qualified,
        // by_rust_module) from the summary itself, so we do not need to copy
        // `other.by_rust_module` explicitly, draining `other.by_key` is enough.
        for (key, summary) in other.by_key {
            self.insert(key, summary.into_inner());
        }
        // SSA summaries: last-writer-wins (exact-key replacement, no unioning)
        for (key, ssa_sum) in other.ssa_by_key {
            self.index_ssa_key(&key);
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
        // Router facts: last-writer-wins per (module_id) key.  Re-analysing
        // a file produces a fresh snapshot of its router declarations + edges.
        for (module_id, facts) in other.router_facts_by_module {
            self.router_facts_by_module.insert(module_id, facts);
        }
        // Cross-package imports: last-writer-wins per namespace.
        for (ns, map) in other.cross_package_imports_by_namespace {
            self.cross_package_imports_by_namespace.insert(ns, map);
        }
        // Caller-scope accumulator: NOT last-writer-wins — combine via the
        // associative/commutative `CalleeCallerAcc::merge` (OR on
        // has_caller, AND on all_authorized, union on lifted_checks) so a
        // callee's caller set is the union across every file.
        for (key, acc) in other.caller_scope_by_callee {
            self.caller_scope_by_callee
                .entry(key)
                .or_default()
                .merge(acc);
        }
        // Hierarchy index: invalidate after a merge so the next consumer
        // sees a freshly-built view that includes `other`'s edges.  The
        // alternative, point-merging two indexes, is racy when the
        // same `(lang, super)` key carries different sub-orderings in
        // each input; rebuild is O(n) over `by_key.iter()` and is the
        // single source of truth.
        self.hierarchy = None;
        // Same for the caller index: it is rebuilt from the call graph.
        self.called_keys.clear();
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
        let key = self.ssa_insert_key(key, &summary);
        self.index_ssa_key(&key);
        self.ssa_by_key.insert(key, Stored::new(summary));
    }

    /// [`Self::insert_ssa`] that also records in `log` the summary the
    /// target key held before this iteration first wrote it.  The replaced
    /// value is moved into the log, so tracking costs no clone.
    pub fn insert_ssa_tracked(
        &mut self,
        key: FuncKey,
        summary: SsaFuncSummary,
        log: &mut SummaryChangeLog,
    ) {
        let key = self.ssa_insert_key(key, &summary);
        self.index_ssa_key(&key);
        let before = self
            .ssa_by_key
            .insert(key.clone(), Stored::new(summary))
            .map(Stored::into_inner);
        log.ssa_before.entry(key).or_insert(before);
    }

    /// The key [`Self::insert_ssa`] stores `summary` under.
    fn ssa_insert_key(&self, key: FuncKey, summary: &SsaFuncSummary) -> FuncKey {
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
        if key.arity.is_some() && !ssa_summary_fits_arity(summary, key.arity) {
            let existing_also_overflows = self
                .ssa_by_key
                .get(&key)
                .is_some_and(|existing| !ssa_summary_fits_arity(&existing.v, key.arity));
            let existing_present = self.ssa_by_key.contains_key(&key);
            if !existing_present || existing_also_overflows {
                key
            } else {
                self.reconcile_ssa_summary_key(key, summary)
            }
        } else {
            self.reconcile_ssa_summary_key(key, summary)
        }
    }

    /// Push `key` onto the secondary `(lang, namespace, name)` index.
    /// Idempotent: a re-insert at the same triple does not duplicate
    /// the key in the candidate vector.
    fn index_ssa_key(&mut self, key: &FuncKey) {
        let triple = (key.lang, key.namespace.clone(), key.name.clone());
        insert_canonical(self.ssa_by_lang_ns_name.entry(triple).or_default(), key);
    }

    /// Look up SSA summary `FuncKey`s by `(lang, namespace, name)`.
    /// Returns `&[]` when no SSA summary at that triple has been
    /// stored.  Used by the cross-package resolution path so the
    /// step-0.7 narrowing can iterate only the candidate set rather
    /// than every persisted SSA key.
    pub fn ssa_keys_by_qualified(&self, lang: Lang, namespace: &str, name: &str) -> &[FuncKey] {
        // Borrow against (Lang, &str, &str) avoiding allocation by
        // looking up with a tuple of owned Strings only when present.
        // HashMap requires equivalent hash; (Lang, String, String)
        // hashes the same as the equivalent tuple of equivalent
        // values, so we construct a small owned key for the probe.
        // Profile-light: this runs once per cross-package callee and
        // both string clones are short (namespace path + leaf name).
        let probe = (lang, namespace.to_string(), name.to_string());
        let keys = self
            .ssa_by_lang_ns_name
            .get(&probe)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        deps::note_named(
            || NamedRead::SsaTriple(probe.0, probe.1.clone(), probe.2.clone()),
            || deps::fp_keys(keys),
        );
        keys
    }

    /// Exact lookup of an SSA summary by fully-qualified key.
    pub fn get_ssa(&self, key: &FuncKey) -> Option<&SsaFuncSummary> {
        let e = self.ssa_by_key.get(key);
        deps::note_keyed(KeyedRead::Ssa, key, || stored_fp(e));
        e.map(|e| &e.v)
    }

    /// SSA summaries of every function named exactly `name`, in any
    /// language or namespace.  Order is unspecified.
    pub fn ssa_named(&self, name: &str) -> Vec<&SsaFuncSummary> {
        let found = self.ssa_named_uncached(name);
        deps::note_named(
            || NamedRead::SsaByName(name.to_string()),
            || ssa_named_fp(&found),
        );
        found.into_iter().map(|(_, s)| &s.v).collect()
    }

    fn ssa_named_uncached(&self, name: &str) -> Vec<(&FuncKey, &Stored<SsaFuncSummary>)> {
        self.ssa_by_key
            .iter()
            .filter(|(k, _)| k.name == name)
            .collect()
    }

    /// Number of stored SSA summaries.
    pub fn ssa_len(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::Ssa),
            || deps::fp_usize(self.ssa_by_key.len()),
        );
        self.ssa_by_key.len()
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
        self.auth_by_key.insert(key, Stored::new(summary));
    }

    /// Exact lookup of an `AuthCheckSummary` by fully-qualified key.
    pub fn get_auth(
        &self,
        key: &FuncKey,
    ) -> Option<&crate::auth_analysis::model::AuthCheckSummary> {
        let e = self.auth_by_key.get(key);
        deps::note_keyed(KeyedRead::Auth, key, || stored_fp(e));
        e.map(|e| &e.v)
    }

    /// Whether any cross-file auth summary is loaded, which tells "none
    /// loaded" apart from "some were loaded but none matched the call site".
    pub fn has_auth_summaries(&self) -> bool {
        let any = !self.auth_by_key.is_empty();
        deps::note_named(
            || NamedRead::MapNonEmpty(MapId::Auth),
            || deps::fp_bool(any),
        );
        any
    }

    /// Count of cross-file auth summaries currently loaded.
    pub fn auth_len(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::Auth),
            || deps::fp_usize(self.auth_by_key.len()),
        );
        self.auth_by_key.len()
    }

    /// Fold one pass-1 caller-scope edge into the accumulator.
    ///
    /// Accumulates per `(Lang, callee_leaf)`: OR on `has_caller`, AND on
    /// `all_authorized`, union on `lifted_checks`.  Idempotent under the
    /// rayon fold/reduce because the underlying accumulator's `fold_edge`
    /// / `merge` are associative + commutative.
    pub fn fold_caller_scope_edge(
        &mut self,
        edge: crate::auth_analysis::caller_scope::CallerScopeEdge,
    ) {
        let crate::auth_analysis::caller_scope::CallerScopeEdge {
            lang,
            callee_leaf,
            caller_authorized,
            route_checks,
        } = edge;
        self.caller_scope_by_callee
            .entry((lang, callee_leaf))
            .or_default()
            .fold_edge(caller_authorized, &route_checks);
    }

    /// Resolve the cross-file caller-scope accumulator for a callee leaf.
    pub fn resolve_caller_scope(
        &self,
        lang: Lang,
        leaf: &str,
    ) -> Option<&crate::auth_analysis::caller_scope::CalleeCallerAcc> {
        // Avoid allocating a `String` key on the hot lookup path by
        // probing with a borrowed tuple via the `Borrow` blanket impl —
        // but `(Lang, String)` keys can't be borrowed as `(Lang, &str)`,
        // so fall back to a cheap owned probe.  Caller-scope lookups run
        // once per helper unit at pass 2, not per instruction.
        let probe = (lang, leaf.to_string());
        let acc = self.caller_scope_by_callee.get(&probe);
        deps::note_named(
            || NamedRead::CallerScope(probe.0, probe.1.clone()),
            || acc.map_or(deps::ABSENT, deps::fp_debug),
        );
        acc
    }

    /// Count of distinct `(Lang, callee_leaf)` caller-scope entries.
    pub fn caller_scope_len(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::CallerScope),
            || deps::fp_usize(self.caller_scope_by_callee.len()),
        );
        self.caller_scope_by_callee.len()
    }

    /// Insert a per-file `PerFileRouterFacts` snapshot.  Last-writer-wins
    /// per `module_id` key — re-analysing a file produces a fresh
    /// snapshot of its router declarations and `include_router` edges.
    pub fn insert_router_facts(
        &mut self,
        module_id: String,
        facts: crate::auth_analysis::router_facts::PerFileRouterFacts,
    ) {
        self.router_facts_by_module.insert(module_id, facts);
    }

    /// Resolve cross-file router-level deps for the file identified by
    /// `child_module_id`.  Produces a `<child_var> →
    /// Vec<(CallSite, scoped_security)>` map of the deps a router declared
    /// in this file inherits from its FastAPI ancestor routers, ready to
    /// merge into the active file's
    /// `AuthorizationModel.cross_file_router_deps`.
    ///
    /// **Transitive.**  FastAPI applies a router's `dependencies=[...]` to
    /// every route reachable through `include_router`, including nested
    /// chains: `grandparent.include_router(parent);
    /// parent.include_router(child)` lifts the grandparent's deps onto the
    /// child even when the intermediate `parent` declares no deps of its
    /// own.  This resolver builds a router graph over
    /// `(storage_key, var)` nodes — where an edge points a child node at
    /// its parent router — and accumulates every ancestor's own deps via a
    /// cycle-guarded DFS.  Both dotted cross-file child refs
    /// (`task_instances.router`) and bare same-file child refs
    /// (`outer.include_router(inner_router)`, `child_local == true`) are
    /// modeled.
    ///
    /// Nodes are keyed by the file's **storage key** (full path) rather
    /// than its basename module id, because a parent router can live in a
    /// `__init__.py` file whose [`module_id_for_path`] is `None`
    /// (`__init__.py` is unaddressable as a *child* target).  Storage-key
    /// keying keeps such root/parent routers in the graph so their deps
    /// still propagate — a basename keying would silently drop every
    /// `__init__.py`-declared parent's deps and regress the airflow
    /// single-hop shape.  Duplicate basenames still over-accumulate (a
    /// dotted child ref wires the parent onto *every* file sharing that
    /// basename), matching the prior single-hop behavior.
    ///
    /// [`module_id_for_path`]: crate::auth_analysis::router_facts::module_id_for_path
    ///
    /// Returns an empty map when `child_module_id` matches no edges or
    /// when the index is empty.
    pub fn resolve_cross_file_router_deps(
        &self,
        child_module_id: &str,
    ) -> HashMap<String, Vec<(crate::auth_analysis::model::CallSite, bool)>> {
        let out = self.router_deps_uncached(child_module_id);
        deps::note_named(
            || NamedRead::RouterDeps(child_module_id.to_string()),
            || router_deps_fp(&out),
        );
        out
    }

    fn router_deps_uncached(
        &self,
        child_module_id: &str,
    ) -> HashMap<String, Vec<(crate::auth_analysis::model::CallSite, bool)>> {
        use crate::auth_analysis::router_facts::module_id_for_path;
        use std::path::Path;

        let mut out: HashMap<String, Vec<(crate::auth_analysis::model::CallSite, bool)>> =
            HashMap::new();
        if self.router_facts_by_module.is_empty() {
            return out;
        }

        // ── Build the router graph (all borrows outlive this fn) ──────
        // `files_by_module[basename]` = storage keys sharing that
        // basename, for dotted child-ref resolution.
        // `own_deps[(storage_key, var)]` = that router's inline deps.
        let mut files_by_module: HashMap<String, Vec<&str>> = HashMap::new();
        let mut own_deps: HashMap<
            (&str, &str),
            &Vec<(crate::auth_analysis::model::CallSite, bool)>,
        > = HashMap::new();
        for (storage_key, facts) in &self.router_facts_by_module {
            if let Some(m) = module_id_for_path(Path::new(storage_key)) {
                files_by_module
                    .entry(m)
                    .or_default()
                    .push(storage_key.as_str());
            }
            for (var, deps) in &facts.local_router_deps {
                if !deps.is_empty() {
                    own_deps.insert((storage_key.as_str(), var.as_str()), deps);
                }
            }
        }

        // `parents[child_node]` = router nodes that `include_router` the
        // child (FastAPI parents whose deps flow downward).  A dotted
        // child ref wires the parent onto every file sharing the child's
        // basename; a local (bare-identifier) ref wires it onto the
        // sibling var in the edge's own file.
        let mut parents: HashMap<(&str, &str), Vec<(&str, &str)>> = HashMap::new();
        for (storage_key, facts) in &self.router_facts_by_module {
            for edge in &facts.include_router_edges {
                let parent_node = (storage_key.as_str(), edge.parent_var.as_str());
                if edge.child_local {
                    let child_node = (storage_key.as_str(), edge.child_var.as_str());
                    parents.entry(child_node).or_default().push(parent_node);
                } else if let Some(files) = files_by_module.get(edge.child_module_id.as_str()) {
                    for &child_sk in files {
                        let child_node = (child_sk, edge.child_var.as_str());
                        parents.entry(child_node).or_default().push(parent_node);
                    }
                }
            }
        }

        // ── For each edge whose child resolves to the target module,
        // accumulate the parent node's full ancestor deps onto the child
        // var.  `effective_deps(parent)` already folds in the parent's own
        // inline deps plus every transitively-reachable ancestor. ──
        for (storage_key, facts) in &self.router_facts_by_module {
            let owner_mod = module_id_for_path(Path::new(storage_key));
            for edge in &facts.include_router_edges {
                let matches_target = if edge.child_local {
                    owner_mod.as_deref() == Some(child_module_id)
                } else {
                    edge.child_module_id == child_module_id
                };
                if !matches_target {
                    continue;
                }
                let parent_node = (storage_key.as_str(), edge.parent_var.as_str());
                let mut visited = std::collections::HashSet::new();
                let mut deps = Vec::new();
                accumulate_router_ancestor_deps(
                    parent_node,
                    &own_deps,
                    &parents,
                    &mut visited,
                    &mut deps,
                );
                if deps.is_empty() {
                    continue;
                }
                let entry = out.entry(edge.child_var.clone()).or_default();
                for dep in deps {
                    // Dedup by (callee name, scoped flag) so multiple
                    // ancestors declaring the same dep don't double-fire.
                    let already = entry
                        .iter()
                        .any(|(call, scoped)| call.name == dep.0.name && *scoped == dep.1);
                    if !already {
                        entry.push(dep);
                    }
                }
            }
        }
        out
    }

    /// Count of files that contributed router facts to the index.
    /// Exposed for `tracing::debug!` observability.
    pub fn router_facts_len(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::RouterFacts),
            || deps::fp_usize(self.router_facts_by_module.len()),
        );
        self.router_facts_by_module.len()
    }

    /// Insert a per-file Phase-09 cross-package import map.  Last-writer-wins
    /// per namespace key — re-analysing a file produces a fresh snapshot
    /// of its `(local_name → FuncKey)` resolutions.
    pub fn insert_cross_package_imports(
        &mut self,
        namespace: String,
        map: std::sync::Arc<HashMap<String, FuncKey>>,
    ) {
        if map.is_empty() {
            return;
        }
        self.cross_package_imports_by_namespace
            .insert(namespace, map);
    }

    /// Look up a per-file cross-package import map by file namespace.
    /// Used by [`crate::taint::ssa_transfer`]'s inline-analysis frame to
    /// recover the callee body's own import view when the body was loaded
    /// from SQLite (where the Arc on `CalleeSsaBody` is stripped by
    /// `#[serde(skip)]`).
    pub fn get_cross_package_imports(
        &self,
        namespace: &str,
    ) -> Option<&std::sync::Arc<HashMap<String, FuncKey>>> {
        let map = self.cross_package_imports_by_namespace.get(namespace);
        deps::note_named(
            || NamedRead::CrossPackageImports(namespace.to_string()),
            || map.map_or(deps::ABSENT, |m| deps::fp_value(&**m)),
        );
        map
    }

    /// Count of files that contributed cross-package import maps.
    pub fn cross_package_imports_len(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::CrossPackageImports),
            || deps::fp_usize(self.cross_package_imports_by_namespace.len()),
        );
        self.cross_package_imports_by_namespace.len()
    }

    /// Insert a cross-file callee body.
    ///
    /// See [`insert_ssa`](Self::insert_ssa) for the identity-safety rule.
    /// Bodies additionally carry `param_count`, giving a hard structural
    /// signal: a collision between bodies with different `param_count`
    /// cannot be the same function and is always rekeyed.
    pub fn insert_body(&mut self, key: FuncKey, body: crate::taint::ssa_transfer::CalleeSsaBody) {
        let key = self.reconcile_body_key(key, body.param_count);
        self.bodies_by_key
            .insert(key, Stored::new(BodyCell::decoded(body)));
    }

    /// Insert a body loaded from the index without decoding it.  It is
    /// decoded on first read; its fingerprints come from the index row.
    pub fn insert_encoded_body(&mut self, key: FuncKey, body: EncodedBody) {
        let key = self.reconcile_body_key(key, body.param_count);
        let (fp, shape) = (body.fp, body.shape_fp);
        self.bodies_by_key
            .insert(key, Stored::with_fps(BodyCell::encoded(body), fp, shape));
    }

    /// Exact lookup of a cross-file callee body by fully-qualified key.
    pub fn get_body(&self, key: &FuncKey) -> Option<&crate::taint::ssa_transfer::CalleeSsaBody> {
        let e = self.bodies_by_key.get(key);
        deps::note_keyed(KeyedRead::Body, key, || stored_fp(e));
        e.and_then(|e| e.v.get())
    }

    /// [`Self::get_body`] for a reader whose results do not depend on where
    /// the body sits in its file.  The read records the body with positions
    /// rebased, so moving the function (an edit above it) keeps the read
    /// valid.  A reader that does carry one of the body's absolute positions
    /// into its results must also call [`Self::note_body_positions`].
    pub fn get_body_shape(
        &self,
        key: &FuncKey,
    ) -> Option<&crate::taint::ssa_transfer::CalleeSsaBody> {
        let e = self.bodies_by_key.get(key);
        deps::note_keyed(KeyedRead::BodyShape, key, || {
            e.map_or(deps::ABSENT, Stored::shape_fp)
        });
        e.and_then(|e| e.v.get())
    }

    /// Record that the current analysis used the absolute positions of
    /// `key`'s body, read earlier through [`Self::get_body_shape`].
    pub fn note_body_positions(&self, key: &FuncKey) {
        deps::note_keyed(KeyedRead::Body, key, || {
            stored_fp(self.bodies_by_key.get(key))
        });
    }

    /// Count of cross-file bodies currently loaded.  Exposed for
    /// `tracing::debug!` observability, lets callers distinguish "no
    /// bodies available" from "bodies available but inline didn't fire".
    pub fn bodies_len(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::Bodies),
            || deps::fp_usize(self.bodies_by_key.len()),
        );
        self.bodies_by_key.len()
    }

    /// Every stored callee body.  Whole-map read: a trace that sees it
    /// can never be replayed.
    pub fn bodies(
        &self,
    ) -> impl Iterator<Item = (&FuncKey, &crate::taint::ssa_transfer::CalleeSsaBody)> {
        deps::note_opaque();
        self.bodies_by_key
            .iter()
            .filter_map(|(k, e)| e.v.get().map(|b| (k, b)))
    }

    /// The cross-file body backwards analysis uses for a call to `leaf`:
    /// among same-language bodies named `leaf` with at most `max_blocks`
    /// blocks, the one with the smallest `(namespace, container, arity,
    /// disambig)`.
    pub fn body_by_leaf(
        &self,
        lang: Lang,
        leaf: &str,
        max_blocks: usize,
    ) -> Option<(&crate::taint::ssa_transfer::CalleeSsaBody, FuncKey)> {
        let found = self.body_by_leaf_uncached(lang, leaf, max_blocks);
        deps::note_named(
            || NamedRead::BodyByLeaf(lang, leaf.to_string(), max_blocks),
            || body_pick_fp(found),
        );
        found.and_then(|(stored, key)| stored.v.get().map(|b| (b, key.clone())))
    }

    fn body_by_leaf_uncached(
        &self,
        lang: Lang,
        leaf: &str,
        max_blocks: usize,
    ) -> Option<(&Stored<BodyCell>, &FuncKey)> {
        let mut best: Option<(&FuncKey, &Stored<BodyCell>)> = None;
        for (key, body) in &self.bodies_by_key {
            if key.name != leaf || key.lang != lang || body.v.block_count() > max_blocks {
                continue;
            }
            let better = match best {
                None => true,
                // Smallest by the structural fields that tell same-leaf
                // siblings apart, so the pick does not depend on map order.
                Some((bk, _)) => {
                    (&key.namespace, &key.container, &key.arity, &key.disambig)
                        < (&bk.namespace, &bk.container, &bk.arity, &bk.disambig)
                }
            };
            if better {
                best = Some((key, body));
            }
        }
        best.map(|(k, b)| (b, k))
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
        let key = self.resolve_callee_key_unique(name, lang, caller_namespace, arity_hint)?;
        self.get_body(&key)
    }

    #[allow(dead_code)] // used by tests and future call-graph consumers
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
            && self.ssa_by_key.is_empty()
            && self.ssa_by_lang_ns_name.is_empty()
            && self.auth_by_key.is_empty()
            && self.router_facts_by_module.is_empty()
            && self.cross_package_imports_by_namespace.is_empty()
            && self.caller_scope_by_callee.is_empty()
    }

    /// Iterate over all (key, summary) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&FuncKey, &FuncSummary)> {
        deps::note_opaque();
        self.by_key.iter().map(|(k, e)| (k, &e.v))
    }

    /// Number of coarse [`FuncSummary`] entries.
    pub fn func_count(&self) -> usize {
        deps::note_named(
            || NamedRead::MapLen(MapId::Funcs),
            || deps::fp_usize(self.by_key.len()),
        );
        self.by_key.len()
    }

    /// Snapshot the convergence-relevant fields of every summary.
    ///
    /// Returns [`caps_fingerprint`] per key.  The SCC fixed-point loop
    /// tracks changes per write through [`SummaryChangeLog`] instead, since
    /// a whole-map snapshot per iteration costs O(functions in the repo).
    pub fn snapshot_caps(&self) -> HashMap<FuncKey, CapsFingerprint> {
        deps::note_opaque();
        self.by_key
            .iter()
            .map(|(k, s)| (k.clone(), caps_fingerprint(&s.v)))
            .collect()
    }

    /// Every SSA summary.  Whole-map read: a trace that sees it can never
    /// be replayed.
    pub fn ssa_entries(&self) -> impl Iterator<Item = (&FuncKey, &SsaFuncSummary)> {
        deps::note_opaque();
        self.ssa_by_key.iter().map(|(k, e)| (k, &e.v))
    }

    /// Copy of every SSA summary.
    pub fn snapshot_ssa(&self) -> HashMap<FuncKey, SsaFuncSummary> {
        deps::note_opaque();
        self.ssa_by_key
            .iter()
            .map(|(k, s)| (k.clone(), s.v.clone()))
            .collect()
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
    /// 3. Otherwise fall through to [`Self::resolve_callee_key_with_container`]
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

    /// [`Self::resolve_callee_key`] for a caller that only uses a unique
    /// match.  Same decision, but an ambiguous call yields `None` without
    /// building (or depending on) its candidate list.
    pub fn resolve_callee_key_unique(
        &self,
        callee: &str,
        caller_lang: Lang,
        caller_namespace: &str,
        arity_hint: Option<usize>,
    ) -> Option<FuncKey> {
        self.resolve_callee_unique(&CalleeQuery {
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

    /// Resolve a bare (already-normalized) callee name to a [`FuncKey`].
    ///
    /// Thin wrapper around [`Self::resolve_callee`] that constructs a minimal
    /// [`CalleeQuery`] with no qualified hints.  Kept for call sites that
    /// only hold a string callee and an arity; prefer [`Self::resolve_callee`]
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
    /// callers should route through [`Self::resolve_callee`] and classify
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
        match self.resolve_callee_core(q, true) {
            BorrowedResolution::Resolved(key) => CalleeResolution::Resolved(key.clone()),
            BorrowedResolution::NotFound => CalleeResolution::NotFound,
            BorrowedResolution::Ambiguous(keys) => {
                CalleeResolution::Ambiguous(keys.into_iter().cloned().collect())
            }
        }
    }

    /// The single function `q` resolves to, if it resolves to exactly one.
    ///
    /// Same decision as [`Self::resolve_callee`] with `Ambiguous` and
    /// `NotFound` both folded into `None`. For callers that never read the
    /// candidates of an ambiguous call (a common method name can have
    /// thousands) this skips building and cloning that list.
    pub fn resolve_callee_unique(&self, q: &CalleeQuery<'_>) -> Option<FuncKey> {
        match self.resolve_callee_core(q, false) {
            BorrowedResolution::Resolved(key) => Some(key.clone()),
            BorrowedResolution::NotFound | BorrowedResolution::Ambiguous(_) => None,
        }
    }

    /// [`Self::resolve_callee_steps`], recorded by its outcome.
    ///
    /// The steps read name-index buckets that grow with every same-named
    /// function in the project.  The caller only learns the outcome, so the
    /// outcome is the dependency: adding `func Close()` in one package leaves
    /// a `x.Close()` elsewhere that still resolves the same way valid.
    fn resolve_callee_core(
        &self,
        q: &CalleeQuery<'_>,
        want_candidates: bool,
    ) -> BorrowedResolution<'_> {
        if !deps::recording() {
            return self.resolve_callee_steps(q, want_candidates);
        }
        let out = {
            let _quiet = deps::Suppress::new();
            self.resolve_callee_steps(q, want_candidates)
        };
        let mode = if want_candidates {
            deps::ResolveMode::Candidates
        } else {
            deps::ResolveMode::Unique
        };
        deps::note_named(
            || NamedRead::Resolve(resolve_read(q, mode)),
            || resolution_fp(&out),
        );
        out
    }

    /// Replay a recorded resolution against the current state.
    fn replayed_resolution_fp(&self, r: &deps::ResolveRead) -> Fp {
        let q = CalleeQuery {
            name: &r.name,
            caller_lang: r.lang,
            caller_namespace: &r.namespace,
            caller_container: r.container.as_deref(),
            receiver_type: r.receiver_type.as_deref(),
            namespace_qualifier: r.namespace_qualifier.as_deref(),
            receiver_var: r.receiver_var.as_deref(),
            arity: r.arity,
        };
        match r.mode {
            deps::ResolveMode::Unique => resolution_fp(&self.resolve_callee_steps(&q, false)),
            deps::ResolveMode::Candidates => resolution_fp(&self.resolve_callee_steps(&q, true)),
            deps::ResolveMode::Widened => deps::fp_keys(&self.resolve_callee_widened_steps(&q)),
        }
    }

    /// The resolution steps behind [`Self::resolve_callee`], with keys
    /// borrowed from the index. Candidate sets are counted in place, and the
    /// ambiguous list is only gathered when `want_candidates` is set.
    fn resolve_callee_steps(
        &self,
        q: &CalleeQuery<'_>,
        want_candidates: bool,
    ) -> BorrowedResolution<'_> {
        use BorrowedResolution::{Ambiguous, NotFound, Resolved};

        let lang = q.caller_lang;
        let gather =
            |keys, keep: &dyn Fn(&FuncKey) -> bool| gather_candidates(want_candidates, keys, keep);

        // ── Step 1: receiver_type (authoritative) ───────────────────
        if let Some(rt) = q.receiver_type {
            if let Some(key) = self.qualified_unique(q, rt) {
                return Resolved(key);
            }
            // Authoritative miss: before returning, check whether any
            // candidate exists at all for the leaf name.  If there are
            // some, report Ambiguous with the leaf candidates (so the
            // caller knows we saw the name but refused to pick the
            // wrong container).  If there are none, return NotFound.
            let leaf = self.keys_same_lang(lang, q.name);
            let (matching, _) = tally(leaf, |k| arity_matches(q, k));
            return if matching == 0 {
                NotFound
            } else {
                Ambiguous(gather(leaf, &|k| arity_matches(q, k)))
            };
        }

        // ── Step 2: namespace_qualifier (authoritative for `::` paths) ──
        if let Some(nq) = q.namespace_qualifier {
            if let Some(key) = self.qualified_unique(q, nq) {
                return Resolved(key);
            }
            // A `::`-qualified callee names a concrete type or module.  With
            // no summary in that container it is an external associated
            // function (stdlib / third-party crate) or a module-path free
            // function — never a same-leaf METHOD in an unrelated container.
            // Refuse the caller-container (step 3) and leaf/arity fallbacks
            // (steps 4/6) that would bind the stdlib `File::open` to the
            // enclosing `impl V5Reader { fn open }`, or `BufReader::new` to a
            // unique-arity `UpdateFile::new`.  Allow only a unique same-leaf
            // FREE function (`crate::util::sanitize` → top-level `fn
            // sanitize`).  `Self::` / `self::` is a real self-call and defers
            // to the caller-container step below.
            if !matches!(nq, "Self" | "self") {
                let leaf = self.keys_same_lang(lang, q.name);
                let is_free = |k: &FuncKey| k.container.is_empty() && arity_matches(q, k);
                let (free, first) = tally(leaf, is_free);
                return match (free, first) {
                    (1, Some(only)) => Resolved(only),
                    (0, _) => NotFound,
                    _ => Ambiguous(gather(leaf, &is_free)),
                };
            }
        }

        // ── Step 3: caller self-container ───────────────────────────
        // Only a call on the caller's own instance can land in the
        // caller's container.  `repo.find(id)` inside `find` names another
        // object's method, and `super.init(cfg)` inside `init` names the
        // supertype's, so neither may resolve to the caller.
        match q.receiver() {
            CallReceiver::Own => {
                if let Some(cc) = q.caller_container
                    && let Some(key) = self.qualified_unique(q, cc)
                {
                    return Resolved(key);
                }
            }
            CallReceiver::Super => {
                return match q.caller_container {
                    Some(cc) => self
                        .supertypes_of(lang, cc)
                        .iter()
                        .find_map(|sup| self.defined_in_supertype(q, sup))
                        .map_or(NotFound, Resolved),
                    None => NotFound,
                };
            }
            CallReceiver::Other => {}
        }

        // ── Step 4: same-namespace unique leaf ──────────────────────
        let all = self.keys_same_lang(lang, q.name);
        if all.is_empty() {
            return NotFound;
        }

        let mut widened = false;
        let (mut arity_n, mut arity_first) = tally(all, |k| arity_ok(q, k, widened));
        if arity_n == 0 && q.arity.is_some() && q.caller_lang.allows_under_application() {
            // Exact-arity match found nothing. Tolerate under-application:
            // `FuncKey::arity` is the *total* parameter count, so a call
            // supplying `a` arguments to a function declared with more
            // parameters (the surplus being default-valued / optional) is a
            // routine, valid call shape in Python, JS/TS, PHP, and Ruby. Retry
            // with `param_count >= call_arity` so these calls still resolve.
            //
            // This only ever WIDENS the candidate set, and resolution below
            // still requires a unique candidate, so a genuinely ambiguous name
            // degrades to `Ambiguous`, never a wrong `Resolved`. Exact-arity
            // matches always take precedence (this branch runs only when none
            // exist), so no existing exact-match resolution regresses.
            widened = true;
            (arity_n, arity_first) = tally(all, |k| arity_ok(q, k, true));
        }
        if arity_n == 0 {
            return NotFound;
        }
        let in_arity = |k: &FuncKey| arity_ok(q, k, widened);

        let in_caller_ns = |k: &FuncKey| in_arity(k) && k.namespace == q.caller_namespace;
        let (same_ns_n, same_ns_first) = tally(all, in_caller_ns);
        if same_ns_n == 1
            && let Some(only) = same_ns_first
        {
            return Resolved(only);
        }

        // ── Step 5: receiver_var tie-break (soft) ───────────────────
        if let Some(rv) = q.receiver_var
            && let Some(key) = self.qualified_unique(q, rv)
        {
            return Resolved(key);
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
            let (n, first) = tally(all, |k| in_caller_ns(k) && k.container.is_empty());
            if n == 1
                && let Some(only) = first
            {
                return Resolved(only);
            }
        }

        // ── Step 6: leaf fallback ───────────────────────────────────
        if arity_n == 1
            && let Some(only) = arity_first
        {
            return Resolved(only);
        }

        // Multiple arity-matched candidates remain.  When a qualified
        // hint was supplied but missed, refuse to guess, a silent
        // leaf-name pick would defeat the point of qualified-first
        // resolution.  (`receiver_type` is handled in Step 1 and never
        // reaches here; `namespace_qualifier` / `caller_container`
        // missing their target flow through as a soft miss.)
        if q.has_qualified_hint() {
            return Ambiguous(gather(all, &in_arity));
        }

        // No qualified hints whatsoever, tolerate namespace narrowing.
        match (same_ns_n, same_ns_first) {
            (1, Some(only)) => Resolved(only),
            (0, _) => Ambiguous(gather(all, &in_arity)),
            _ => Ambiguous(gather(all, &in_caller_ns)),
        }
    }

    /// The one arity-matched function indexed as `{container}::{q.name}`,
    /// using the caller's namespace to break a tie. `None` when there is no
    /// such function or the tie stays unbroken.
    fn qualified_unique(&self, q: &CalleeQuery<'_>, container: &str) -> Option<&FuncKey> {
        if container.is_empty() {
            return None;
        }
        let qual = format!("{container}::{}", q.name);
        let keys = self.keys_qualified(q.caller_lang, &qual);
        match tally(keys, |k| arity_matches(q, k)) {
            (0, _) => None,
            (1, first) => first,
            _ => match tally(keys, |k| {
                arity_matches(q, k) && k.namespace == q.caller_namespace
            }) {
                (1, only) => only,
                _ => None,
            },
        }
    }

    /// `q.name` as defined by the supertype `sup`. Like step 4, tolerates a
    /// declaration with more parameters than the call passes (defaults, or
    /// Python's explicit `self`).
    fn defined_in_supertype(&self, q: &CalleeQuery<'_>, sup: &str) -> Option<&FuncKey> {
        self.qualified_unique(q, sup).or_else(|| {
            let a = q.arity?;
            let qual = format!("{sup}::{}", q.name);
            let keys = self.keys_qualified(q.caller_lang, &qual);
            match tally(keys, |k| matches!(k.arity, Some(p) if p > a)) {
                (1, only) => only,
                _ => None,
            }
        })
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
        deps::note_opaque();
        self.hierarchy.as_ref()
    }

    fn supers_list(&self, lang: Lang, container: &str) -> &[String] {
        let list = self
            .hierarchy
            .as_ref()
            .map_or(&[][..], |h| h.supers_of(lang, container));
        deps::note_named(
            || NamedRead::Supers(lang, container.to_string()),
            || deps::fp_strs(list),
        );
        list
    }

    fn subs_list(&self, lang: Lang, container: &str) -> &[String] {
        let list = self
            .hierarchy
            .as_ref()
            .map_or(&[][..], |h| h.subs_of(lang, container));
        deps::note_named(
            || NamedRead::Subs(lang, container.to_string()),
            || deps::fp_strs(list),
        );
        list
    }

    /// Every recorded supertype of `container`, nearest first (direct
    /// supertypes, then theirs).  Empty when no hierarchy is installed.
    /// Used to resolve `super.m()` / `parent::m()` to the closest
    /// supertype that defines `m`.
    pub fn supertypes_of(&self, lang: Lang, container: &str) -> Vec<String> {
        /// Bound on the inheritance depth walked; real chains are short and
        /// the visited set already stops cycles.
        const MAX_SUPERTYPES: usize = 32;
        if self.hierarchy.is_none() {
            return Vec::new();
        }
        let mut out: Vec<String> = Vec::new();
        let mut next = 0;
        let mut current = container.to_string();
        loop {
            for sup in self.supers_list(lang, &current) {
                if sup != container && !out.contains(sup) && out.len() < MAX_SUPERTYPES {
                    out.push(sup.clone());
                }
            }
            if next >= out.len() {
                return out;
            }
            current = out[next].clone();
            next += 1;
        }
    }

    /// Record which functions the call graph shows a caller for.
    ///
    /// Self-recursion does not count, and neither do callers in test files:
    /// a production handler whose only callers are its tests is still an
    /// entry point.  Only resolved edges exist in the graph, so an
    /// ambiguous or unresolved call never marks a function as called.
    /// `merge()` clears the set, so a forgotten reinstall degrades to "no
    /// known caller" rather than a stale answer.
    pub fn install_called_keys(&mut self, cg: &crate::callgraph::CallGraph) {
        self.called_keys.clear();
        for edge in cg.graph.edge_indices() {
            let Some((from, to)) = cg.graph.edge_endpoints(edge) else {
                continue;
            };
            if from == to {
                continue;
            }
            let caller = &cg.graph[from];
            if crate::ast::is_test_file(std::path::Path::new(&caller.namespace)) {
                continue;
            }
            self.called_keys.insert(cg.graph[to].clone());
        }
    }

    /// Whether the installed call graph shows a caller of `key` outside
    /// `key` itself and outside test files.
    pub fn has_known_caller(&self, key: &FuncKey) -> bool {
        let called = self.called_keys.contains(key);
        deps::note_keyed(KeyedRead::Called, key, || deps::fp_bool(called));
        called
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
        if !deps::recording() {
            return self.resolve_callee_widened_steps(q);
        }
        let out = {
            let _quiet = deps::Suppress::new();
            self.resolve_callee_widened_steps(q)
        };
        deps::note_named(
            || NamedRead::Resolve(resolve_read(q, deps::ResolveMode::Widened)),
            || deps::fp_keys(&out),
        );
        out
    }

    /// The steps behind [`Self::resolve_callee_widened`].
    fn resolve_callee_widened_steps(&self, q: &CalleeQuery<'_>) -> Vec<FuncKey> {
        let arity_matches = |k: &FuncKey| match q.arity {
            Some(a) => k.arity == Some(a),
            None => true,
        };

        let single_fallback =
            || -> Vec<FuncKey> { self.resolve_callee_unique(q).into_iter().collect() };

        // Hierarchy fan-out only fires when the call has an
        // authoritative receiver type AND the index is installed AND
        // the type has recorded sub-types.  Every other case collapses
        // to today's resolver.
        let Some(rt) = q.receiver_type.filter(|s| !s.is_empty()) else {
            return single_fallback();
        };
        if self.hierarchy.is_none() {
            return single_fallback();
        }
        let subs = self.subs_list(q.caller_lang, rt);
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
            self.keys_qualified(q.caller_lang, &qual)
                .iter()
                .filter(|k| self.by_key.contains_key(*k) && arity_matches(k))
                .cloned()
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

/// Order-independent fingerprint of a set of `(key, SSA summary)` pairs.
fn ssa_named_fp(found: &[(&FuncKey, &Stored<SsaFuncSummary>)]) -> Fp {
    let mut sum: u64 = 0;
    for (k, s) in found {
        sum = sum.wrapping_add(deps::fp_value(&(
            deps::fp_keys(std::iter::once(*k)),
            s.fp(),
        )));
    }
    deps::fp_value(&(sum, found.len()))
}

/// Fingerprint of the backwards-analysis body pick: the body and its key.
fn body_pick_fp(found: Option<(&Stored<BodyCell>, &FuncKey)>) -> Fp {
    match found {
        Some((stored, key)) => deps::fp_value(&(stored.fp(), deps::fp_keys(std::iter::once(key)))),
        None => deps::ABSENT,
    }
}

/// Fingerprint of a `resolve_cross_file_router_deps` result.  `CallSite`
/// has no `Serialize`, and its `Debug` rendering is deterministic, so the
/// entries are sorted by child variable and rendered.
fn router_deps_fp(out: &HashMap<String, Vec<(crate::auth_analysis::model::CallSite, bool)>>) -> Fp {
    let mut entries: Vec<_> = out.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    deps::fp_debug(&entries)
}

impl deps::DepOracle for GlobalSummaries {
    fn keyed_fp(&self, kind: KeyedRead, key: &FuncKey) -> Fp {
        match kind {
            KeyedRead::Func => stored_fp(self.by_key.get(key)),
            KeyedRead::Ssa => stored_fp(self.ssa_by_key.get(key)),
            KeyedRead::Body => stored_fp(self.bodies_by_key.get(key)),
            KeyedRead::BodyShape => self
                .bodies_by_key
                .get(key)
                .map_or(deps::ABSENT, Stored::shape_fp),
            KeyedRead::Auth => stored_fp(self.auth_by_key.get(key)),
            KeyedRead::Called => deps::fp_bool(self.called_keys.contains(key)),
            KeyedRead::Interop => self.interop_fp(key),
        }
    }

    fn named_fp(&self, read: &NamedRead) -> Fp {
        match read {
            NamedRead::LangName(lang, name) => deps::fp_keys(self.by_lang_name.get(*lang, name)),
            NamedRead::Qualified(lang, q) => deps::fp_keys(self.by_lang_qualified.get(*lang, q)),
            NamedRead::RustModule(module_path, name) => deps::fp_keys(
                self.by_rust_module
                    .get(&(module_path.clone(), name.clone()))
                    .into_iter()
                    .flatten(),
            ),
            NamedRead::SsaTriple(lang, ns, name) => deps::fp_keys(
                self.ssa_by_lang_ns_name
                    .get(&(*lang, ns.clone(), name.clone()))
                    .into_iter()
                    .flatten(),
            ),
            NamedRead::CallerScope(lang, leaf) => self
                .caller_scope_by_callee
                .get(&(*lang, leaf.clone()))
                .map_or(deps::ABSENT, deps::fp_debug),
            NamedRead::CrossPackageImports(ns) => self
                .cross_package_imports_by_namespace
                .get(ns)
                .map_or(deps::ABSENT, |m| deps::fp_value(&**m)),
            NamedRead::Supers(lang, c) => deps::fp_strs(
                self.hierarchy
                    .as_ref()
                    .map_or(&[][..], |h| h.supers_of(*lang, c)),
            ),
            NamedRead::Subs(lang, c) => deps::fp_strs(
                self.hierarchy
                    .as_ref()
                    .map_or(&[][..], |h| h.subs_of(*lang, c)),
            ),
            NamedRead::RouterDeps(child) => router_deps_fp(&self.router_deps_uncached(child)),
            NamedRead::BodyByLeaf(lang, leaf, max_blocks) => {
                body_pick_fp(self.body_by_leaf_uncached(*lang, leaf, *max_blocks))
            }
            NamedRead::MapNonEmpty(MapId::Auth) => deps::fp_bool(!self.auth_by_key.is_empty()),
            NamedRead::MapNonEmpty(id) => {
                deps::fp_bool(self.named_fp(&NamedRead::MapLen(*id)) != deps::fp_usize(0))
            }
            NamedRead::SsaByName(name) => ssa_named_fp(&self.ssa_named_uncached(name)),
            NamedRead::Resolve(r) => self.replayed_resolution_fp(r),
            NamedRead::MapLen(id) => deps::fp_usize(match id {
                MapId::Funcs => self.by_key.len(),
                MapId::Ssa => self.ssa_by_key.len(),
                MapId::Bodies => self.bodies_by_key.len(),
                MapId::Auth => self.auth_by_key.len(),
                MapId::RouterFacts => self.router_facts_by_module.len(),
                MapId::CrossPackageImports => self.cross_package_imports_by_namespace.len(),
                MapId::CallerScope => self.caller_scope_by_callee.len(),
            }),
            NamedRead::IsFile(path) => deps::fp_bool(std::path::Path::new(path).is_file()),
        }
    }
}

/// Result of [`GlobalSummaries::resolve_callee_core`]: the keys stay borrowed
/// from the index. `Ambiguous` holds the candidates only when the caller asked
/// for them, otherwise it is empty.
enum BorrowedResolution<'a> {
    Resolved(&'a FuncKey),
    NotFound,
    Ambiguous(Vec<&'a FuncKey>),
}

/// The owned form of a resolution query, for [`NamedRead::Resolve`].
fn resolve_read(q: &CalleeQuery<'_>, mode: deps::ResolveMode) -> deps::ResolveRead {
    deps::ResolveRead {
        lang: q.caller_lang,
        name: q.name.to_string(),
        namespace: q.caller_namespace.to_string(),
        container: q.caller_container.map(str::to_string),
        receiver_type: q.receiver_type.map(str::to_string),
        namespace_qualifier: q.namespace_qualifier.map(str::to_string),
        receiver_var: q.receiver_var.map(str::to_string),
        arity: q.arity,
        mode,
    }
}

/// Fingerprint of what a resolution tells its caller.  An ambiguous
/// outcome carries its candidate list only when it was gathered.
fn resolution_fp(r: &BorrowedResolution<'_>) -> Fp {
    match r {
        BorrowedResolution::Resolved(k) => deps::fp_value(&("resolved", deps::fp_keys([*k]))),
        BorrowedResolution::NotFound => deps::fp_value(&"not-found"),
        BorrowedResolution::Ambiguous(keys) => {
            deps::fp_value(&("ambiguous", deps::fp_keys(keys.iter().copied())))
        }
    }
}

/// The keys of `keys` that pass `keep`, or nothing when the caller did not ask
/// for the candidate list.
fn gather_candidates<'a>(
    want: bool,
    keys: &'a [FuncKey],
    keep: &dyn Fn(&FuncKey) -> bool,
) -> Vec<&'a FuncKey> {
    if want {
        keys.iter().filter(|k| keep(k)).collect()
    } else {
        Vec::new()
    }
}

/// Hard arity filter: with no call arity every key passes.
fn arity_matches(q: &CalleeQuery<'_>, k: &FuncKey) -> bool {
    match q.arity {
        Some(a) => k.arity == Some(a),
        None => true,
    }
}

/// [`arity_matches`], or with `widened` the under-application rule
/// (`param_count >= call_arity`) used when no exact-arity match exists.
fn arity_ok(q: &CalleeQuery<'_>, k: &FuncKey, widened: bool) -> bool {
    match (q.arity, widened) {
        (Some(a), true) => matches!(k.arity, Some(p) if p >= a),
        _ => arity_matches(q, k),
    }
}

/// How many of `keys` satisfy `keep`, counted up to 2 (every decision in the
/// resolver is "none", "exactly one" or "more"), plus the first one found.
fn tally(keys: &[FuncKey], keep: impl Fn(&FuncKey) -> bool) -> (usize, Option<&FuncKey>) {
    let mut count = 0;
    let mut first = None;
    for k in keys {
        if keep(k) {
            first.get_or_insert(k);
            count += 1;
            if count == 2 {
                break;
            }
        }
    }
    (count, first)
}

impl std::fmt::Debug for GlobalSummaries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalSummaries")
            .field("len", &self.by_key.len())
            .field("ssa_len", &self.ssa_by_key.len())
            .field("bodies_len", &self.bodies_by_key.len())
            .field("auth_len", &self.auth_by_key.len())
            .field("router_facts_len", &self.router_facts_by_module.len())
            .field(
                "cross_package_imports_len",
                &self.cross_package_imports_by_namespace.len(),
            )
            .field("caller_scope_len", &self.caller_scope_by_callee.len())
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

/// Depth-first accumulation of a router node's ancestor deps for
/// [`GlobalSummaries::resolve_cross_file_router_deps`].  Collects the
/// node's own inline deps, then recurses into every parent router that
/// `include_router`s it, deduping by `(callee name, scoped flag)`.  The
/// `visited` set both prevents cycles (`a.include_router(b);
/// b.include_router(a)`) and collapses diamond ancestries to a single
/// visit — correct because the dedup makes the union idempotent.
fn accumulate_router_ancestor_deps<'a>(
    node: (&'a str, &'a str),
    own_deps: &HashMap<(&'a str, &'a str), &'a Vec<(crate::auth_analysis::model::CallSite, bool)>>,
    parents: &HashMap<(&'a str, &'a str), Vec<(&'a str, &'a str)>>,
    visited: &mut std::collections::HashSet<(&'a str, &'a str)>,
    out: &mut Vec<(crate::auth_analysis::model::CallSite, bool)>,
) {
    if !visited.insert(node) {
        return;
    }
    if let Some(deps) = own_deps.get(&node) {
        for dep in deps.iter() {
            let already = out
                .iter()
                .any(|(call, scoped)| call.name == dep.0.name && *scoped == dep.1);
            if !already {
                out.push(dep.clone());
            }
        }
    }
    if let Some(ps) = parents.get(&node) {
        for &parent in ps {
            accumulate_router_ancestor_deps(parent, own_deps, parents, visited, out);
        }
    }
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
///
/// This variant keys summaries via the plain [`FuncSummary::func_key`]
/// (`normalize_namespace`), so it is only safe for repos with no
/// package boundaries. The indexed scan path must use
/// [`merge_summaries_with_resolver`] so the loaded coarse summaries are
/// keyed with the same package-qualified namespaces that pass-1 SSA
/// summaries, cross-package import maps, and pass-2 refinements use.
pub fn merge_summaries(
    per_file: impl IntoIterator<Item = FuncSummary>,
    scan_root: Option<&str>,
) -> GlobalSummaries {
    merge_summaries_with_resolver(per_file, scan_root, None)
}

/// Module-graph-aware variant of [`merge_summaries`].
///
/// Keys each summary via [`FuncSummary::func_key_with_resolver`], so a
/// file inside a discovered package gets a package-qualified namespace
/// (`"@scope/name::src/file.ts"`) instead of the plain
/// `normalize_namespace` form. This must match the keying convention
/// used by pass-1 SSA summaries (`namespace_with_package`) and pass-2
/// topo refinements (`func_key_with_resolver`); otherwise exact-key
/// joins between the coarse FuncSummary tier and the SSA tier miss, and
/// same-namespace narrowing in [`GlobalSummaries::resolve_callee`] never
/// matches the package-qualified caller namespace.
///
/// Passing `module_graph: None` is equivalent to [`merge_summaries`].
pub fn merge_summaries_with_resolver(
    per_file: impl IntoIterator<Item = FuncSummary>,
    scan_root: Option<&str>,
    module_graph: Option<&crate::resolve::ModuleGraph>,
) -> GlobalSummaries {
    let mut map = GlobalSummaries::new();

    for fs in per_file {
        let key = fs.func_key_with_resolver(scan_root, module_graph);
        map.insert(key, fs);
    }

    map
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod arity_leniency_tests {
    use super::*;
    use crate::symbol::{FuncKey, Lang};

    fn py_func(name: &str, namespace: &str, param_count: usize) -> (FuncKey, FuncSummary) {
        let key = FuncKey::from_parts(
            Lang::Python,
            namespace,
            String::new(),
            name,
            Some(param_count),
            None,
            FuncKind::Function,
        );
        let summary = FuncSummary {
            name: name.into(),
            file_path: namespace.into(),
            lang: "python".into(),
            param_count,
            ..Default::default()
        };
        (key, summary)
    }

    /// `run_cmd(cmd, opts=None)` (param_count 2) called as `run_cmd(user)`
    /// (arity 1) must resolve via the under-application tolerance, not fall
    /// through to NotFound.
    #[test]
    fn under_application_resolves_unique_defaulted_callee() {
        let mut gs = GlobalSummaries::new();
        let (key, summary) = py_func("run_cmd", "helper.py", 2);
        gs.insert(key.clone(), summary);

        let resolved = gs.resolve_callee(&CalleeQuery {
            name: "run_cmd",
            caller_lang: Lang::Python,
            caller_namespace: "routes.py",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert_eq!(
            resolved,
            CalleeResolution::Resolved(key),
            "under-applied unique callee with default params must resolve"
        );
    }

    /// Exact-arity matches still take precedence: when both an exact-arity and
    /// a higher-arity candidate exist, the exact one wins (no regression).
    #[test]
    fn exact_arity_match_preferred_over_lenient() {
        let mut gs = GlobalSummaries::new();
        let (exact_key, exact_sum) = py_func("run_cmd", "a.py", 1);
        let (wide_key, wide_sum) = py_func("run_cmd", "b.py", 3);
        gs.insert(exact_key.clone(), exact_sum);
        gs.insert(wide_key, wide_sum);

        let resolved = gs.resolve_callee(&CalleeQuery {
            name: "run_cmd",
            caller_lang: Lang::Python,
            caller_namespace: "routes.py",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        // The exact-arity candidate (a.py, arity 1) is the sole exact match,
        // so the lenient branch never runs and resolution is unambiguous.
        assert_eq!(resolved, CalleeResolution::Resolved(exact_key));
    }

    /// Leniency only widens the candidate set; it never produces a wrong
    /// Resolved. Two distinct higher-arity callees both tolerating the call
    /// arity must degrade to Ambiguous, not a silent pick.
    #[test]
    fn under_application_ambiguous_when_multiple_candidates() {
        let mut gs = GlobalSummaries::new();
        let (k1, s1) = py_func("run_cmd", "a.py", 2);
        let (k2, s2) = py_func("run_cmd", "b.py", 3);
        gs.insert(k1, s1);
        gs.insert(k2, s2);

        let resolved = gs.resolve_callee(&CalleeQuery {
            name: "run_cmd",
            caller_lang: Lang::Python,
            caller_namespace: "routes.py",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        });
        assert!(
            matches!(resolved, CalleeResolution::Ambiguous(_)),
            "two under-applied candidates must be Ambiguous, not a wrong Resolved: {resolved:?}"
        );
    }

    /// Over-application (more args than params) must NOT be tolerated: the
    /// lenient predicate is `param_count >= call_arity`, so a 1-param function
    /// called with 2 args still returns NotFound.
    #[test]
    fn over_application_not_tolerated() {
        let mut gs = GlobalSummaries::new();
        let (key, summary) = py_func("run_cmd", "helper.py", 1);
        gs.insert(key, summary);

        let resolved = gs.resolve_callee(&CalleeQuery {
            name: "run_cmd",
            caller_lang: Lang::Python,
            caller_namespace: "routes.py",
            caller_container: None,
            receiver_type: None,
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(2),
        });
        assert_eq!(resolved, CalleeResolution::NotFound);
    }
}

#[cfg(test)]
mod namespace_qualifier_authority_tests {
    //! `::`-qualified callee authority in [`GlobalSummaries::resolve_callee`].
    //! A qualifier that names no local container must not fall through to the
    //! caller-container / leaf-arity heuristics and bind an unrelated same-leaf
    //! method (meilisearch dump-reader leaf collisions: `File::open` →
    //! `Reader::open`, `BufReader::new` → `IndexReader::new`).
    use super::*;
    use crate::symbol::{FuncKey, FuncKind, Lang};

    fn rs_method(container: &str, name: &str, arity: usize) -> (FuncKey, FuncSummary) {
        let key = FuncKey::from_parts(
            Lang::Rust,
            "mod.rs",
            container,
            name,
            Some(arity),
            None,
            FuncKind::Method,
        );
        let summary = FuncSummary {
            name: name.into(),
            file_path: "mod.rs".into(),
            lang: "rust".into(),
            container: container.into(),
            param_count: arity,
            ..Default::default()
        };
        (key, summary)
    }

    fn rs_free(name: &str, arity: usize) -> (FuncKey, FuncSummary) {
        let key = FuncKey::new_function(Lang::Rust, "mod.rs", name, Some(arity));
        let summary = FuncSummary {
            name: name.into(),
            file_path: "mod.rs".into(),
            lang: "rust".into(),
            param_count: arity,
            ..Default::default()
        };
        (key, summary)
    }

    fn base_gs() -> GlobalSummaries {
        let mut gs = GlobalSummaries::new();
        let (k1, s1) = rs_method("Reader", "open", 1);
        let (k2, s2) = rs_method("IndexReader", "new", 1);
        let (k3, s3) = rs_free("sanitize", 1);
        gs.insert(k1, s1);
        gs.insert(k2, s2);
        gs.insert(k3, s3);
        gs
    }

    fn query<'a>(
        name: &'a str,
        qualifier: Option<&'a str>,
        caller_container: Option<&'a str>,
    ) -> CalleeQuery<'a> {
        CalleeQuery {
            name,
            caller_lang: Lang::Rust,
            caller_namespace: "mod.rs",
            caller_container,
            receiver_type: None,
            namespace_qualifier: qualifier,
            receiver_var: None,
            arity: Some(1),
        }
    }

    #[test]
    fn file_open_qualifier_miss_does_not_bind_caller_container() {
        let gs = base_gs();
        let r = gs.resolve_callee(&query("open", Some("File"), Some("Reader")));
        assert_eq!(
            r,
            CalleeResolution::NotFound,
            "File::open must not bind caller-container Reader::open"
        );
    }

    #[test]
    fn bufreader_new_qualifier_miss_does_not_bind_unique_leaf() {
        let gs = base_gs();
        let r = gs.resolve_callee(&query("new", Some("BufReader"), Some("Reader")));
        assert_eq!(
            r,
            CalleeResolution::NotFound,
            "BufReader::new must not bind the unique-arity IndexReader::new"
        );
    }

    #[test]
    fn qualifier_matching_container_resolves() {
        let gs = base_gs();
        let (k, _) = rs_method("Reader", "open", 1);
        let r = gs.resolve_callee(&query("open", Some("Reader"), None));
        assert_eq!(r, CalleeResolution::Resolved(k));
    }

    #[test]
    fn self_qualifier_defers_to_caller_container() {
        let gs = base_gs();
        let (k, _) = rs_method("Reader", "open", 1);
        let r = gs.resolve_callee(&query("open", Some("Self"), Some("Reader")));
        assert_eq!(r, CalleeResolution::Resolved(k));
    }

    #[test]
    fn module_path_qualifier_resolves_free_function() {
        let gs = base_gs();
        let (k, _) = rs_free("sanitize", 1);
        let r = gs.resolve_callee(&query("sanitize", Some("util"), Some("Reader")));
        assert_eq!(r, CalleeResolution::Resolved(k));
    }
}

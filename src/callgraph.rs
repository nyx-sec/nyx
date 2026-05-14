//! Whole-program call graph built from pass-1 function summaries.
//!
//! Nodes are [`FuncKey`]s (one per function definition across all files).
//! Edges represent call-site relationships resolved after pass 1 completes.
//! Unresolved and ambiguous callees are tracked separately so they can be
//! surfaced in diagnostics without blocking analysis.
//!
//! [`CallGraphAnalysis`] computes SCCs and topological order. The scanner
//! uses topo order in pass 2 so callees are analysed before their callers,
//! and iterates over SCC groups to a fixed point for mutually recursive
//! functions.

use crate::interop::InteropEdge;
use crate::rust_resolve::RustUseMap;
use crate::summary::{CalleeQuery, CalleeResolution, GlobalSummaries};
use crate::symbol::{FuncKey, Lang};
use petgraph::graph::NodeIndex;
use petgraph::prelude::*;
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata attached to each call-graph edge.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// The raw callee string as it appeared in source (e.g. `"env::var"`).
    /// Preserved for diagnostics, **not** the normalized form used for resolution.
    #[allow(dead_code)] // used for future diagnostics and path display
    pub call_site: String,
}

/// A callee that could not be resolved to any known function definition.
#[derive(Debug, Clone)]
pub struct UnresolvedCallee {
    pub caller: FuncKey,
    pub callee_name: String,
}

/// A callee that matched multiple function definitions, ambiguous.
#[derive(Debug, Clone)]
pub struct AmbiguousCallee {
    pub caller: FuncKey,
    pub callee_name: String,
    pub candidates: Vec<FuncKey>,
}

/// The whole-program call graph.
///
/// Nodes are [`FuncKey`]s (one per function definition across all files).
/// Edges represent call-site relationships resolved after pass 1.
#[derive(Debug)]
pub struct CallGraph {
    pub graph: DiGraph<FuncKey, CallEdge>,
    /// `FuncKey → NodeIndex` for quick lookup.
    #[allow(dead_code)] // used for future topo-ordered analysis and call-graph queries
    pub index: HashMap<FuncKey, NodeIndex>,
    /// Callee strings that could not be resolved to any [`FuncKey`].
    pub unresolved_not_found: Vec<UnresolvedCallee>,
    /// Callee strings that matched multiple candidates.
    pub unresolved_ambiguous: Vec<AmbiguousCallee>,
}

/// Result of SCC / topological analysis on the call graph.
pub struct CallGraphAnalysis {
    /// Strongly connected components.
    pub sccs: Vec<Vec<NodeIndex>>,
    /// Maps each `NodeIndex` to its SCC index in `sccs`.
    #[allow(dead_code)] // used for future topo-ordered taint propagation
    pub node_to_scc: HashMap<NodeIndex, usize>,
    /// SCC indices in **callee-first** (leaves-first) order.
    ///
    /// Functions with no callees appear first; callers appear later.
    /// Suitable for bottom-up taint propagation.
    pub topo_scc_callee_first: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Callee-name normalization
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the last segment of a qualified callee name for resolution.
///
/// ```text
/// "env::var"              → "var"
/// "std::process::Command" → "Command"
/// "obj.method"            → "method"
/// "pkg.mod.func"          → "func"
/// "foo"                   → "foo"  (unchanged)
/// ""                      → ""     (edge case)
/// ```
///
/// The original raw text is preserved on [`CallEdge::call_site`] for
/// diagnostics; this function only produces the lookup key.
/// Preserve the last **two** segments for better disambiguation.
///
/// ```text
/// "std::env::var"      → "env::var"
/// "env::var"           → "env::var"
/// "pkg.mod.func"       → "mod.func"
/// "http_client.send"   → "http_client.send"
/// "send"               → "send"
/// ""                   → ""
/// ```
pub(crate) fn normalize_callee_name(raw: &str) -> &str {
    // Try "::" separators first (Rust / C++ qualification)
    if let Some(pos) = raw.rfind("::") {
        let before_last = &raw[..pos];
        if let Some(pos2) = before_last.rfind("::") {
            // ≥3 segments → keep last two: "std::env::var" → "env::var"
            return &raw[pos2 + 2..];
        }
        // ≤2 segments → keep all: "env::var" → "env::var"
        return raw;
    }

    // Try "." separators (method calls, Python/JS dotted paths)
    if let Some(pos) = raw.rfind('.') {
        let before_last = &raw[..pos];
        if let Some(pos2) = before_last.rfind('.') {
            // ≥3 segments → keep last two: "pkg.mod.func" → "mod.func"
            return &raw[pos2 + 1..];
        }
        // ≤2 segments → keep all: "http_client.send" → "http_client.send"
        return raw;
    }

    // No separators → return as-is
    raw
}

/// Extract the final (leaf) segment after `::` or `.` separators.
///
/// This is the original single-segment normalization, used for direct
/// map lookups where keys are stored as bare function names.
///
/// ```text
/// "std::env::var" → "var"
/// "obj.method"    → "method"
/// "foo"           → "foo"
/// ```
pub(crate) fn callee_leaf_name(raw: &str) -> &str {
    let after_colons = raw.rsplit("::").next().unwrap_or(raw);
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

/// Extract the segment *immediately before* the leaf as a container hint.
///
/// For `"OrderService::process"` this yields `"OrderService"`; for
/// `"obj.method"`, `"obj"`.  When the raw name is unqualified (`"send"`) the
/// hint is empty.  The intent is to give [`resolve_callee_key_with_container`]
/// enough context to pick the right method when two classes in the same file
/// define the same leaf name.
pub(crate) fn callee_container_hint(raw: &str) -> &str {
    if let Some(pos) = raw.rfind("::") {
        let prefix = &raw[..pos];
        return prefix.rsplit("::").next().unwrap_or(prefix);
    }
    if let Some(pos) = raw.rfind('.') {
        let prefix = &raw[..pos];
        return prefix.rsplit('.').next().unwrap_or(prefix);
    }
    ""
}

// ─────────────────────────────────────────────────────────────────────────────
//  Class / container → method index
// ─────────────────────────────────────────────────────────────────────────────

/// Per-language `(container, method_name)` → candidate [`FuncKey`] index.
///
/// Built once per call-graph construction over every merged
/// [`crate::summary::FuncSummary`].  Used by edge insertion to restrict an indirect method
/// call (`receiver.method(...)`) to only those targets whose defining
/// container matches the receiver's static type.  Without a container
/// hint the index falls back to the bare-name list, matching today's
/// name-only resolution byte-for-byte.
///
/// Key design notes:
///
/// * Keys are **language-scoped**, a Java `findById` and a Python
///   `findById` never alias.  Every other index in this module is also
///   language-scoped (`by_lang_name`, `by_lang_qualified`); keeping the
///   same partition here means devirtualisation's "subset of today's
///   targets" invariant is structurally preserved.
/// * The container key carries the [`FuncKey::container`] verbatim
///   (e.g. `"Repository"` or nested `"Outer::Inner"`).  Empty containers
///   are not indexed in `by_container`, free top-level functions live
///   only in `by_name` and are looked up via the `None` container path.
/// * `SmallVec` inline capacity is sized for the common case (≤ 2 same-
///   container overloads, ≤ 4 same-name candidates across containers);
///   spillover allocates but keeps lookups O(1) amortised.
#[derive(Debug, Default, Clone)]
pub struct ClassMethodIndex {
    /// `(lang, container, method_name)` → all candidate `FuncKey`s
    /// whose defining container matches.  Empty containers are not
    /// indexed here; use the `None` arm of [`Self::resolve`] for those.
    by_container: HashMap<(Lang, String, String), SmallVec<[FuncKey; 2]>>,
    /// `(lang, method_name)` → every `FuncKey` with that leaf name in
    /// the language, regardless of container.  This is the fallback
    /// path for calls with no resolvable receiver type and matches
    /// today's name-only edge insertion.
    by_name: HashMap<(Lang, String), SmallVec<[FuncKey; 4]>>,
}

impl ClassMethodIndex {
    /// Build the index from a [`GlobalSummaries`] map.
    ///
    /// Iteration is over every `FuncKey` in the map; each key is
    /// inserted into `by_name` and (when its container is non-empty)
    /// into `by_container`.  No ordering guarantees on the candidate
    /// vectors, call sites that need determinism should sort downstream.
    pub fn build(summaries: &GlobalSummaries) -> Self {
        let mut by_container: HashMap<(Lang, String, String), SmallVec<[FuncKey; 2]>> =
            HashMap::new();
        let mut by_name: HashMap<(Lang, String), SmallVec<[FuncKey; 4]>> = HashMap::new();

        for (key, _) in summaries.iter() {
            let name_key = (key.lang, key.name.clone());
            by_name.entry(name_key).or_default().push(key.clone());

            if !key.container.is_empty() {
                let cont_key = (key.lang, key.container.clone(), key.name.clone());
                by_container.entry(cont_key).or_default().push(key.clone());
            }
        }

        ClassMethodIndex {
            by_container,
            by_name,
        }
    }

    /// Resolve `(container, method)` to its candidate target set.
    ///
    /// * `container = Some(c)`, return only candidates whose defining
    ///   container equals `c`.  Empty slice when no such target exists,
    ///   even if a same-name function lives in another container.
    ///   This is the **devirtualised** path: a hard subset of `by_name`.
    /// * `container = None`, return every same-name candidate in the
    ///   language.  This is the **fallback** path used when the receiver
    ///   type is unknown; matches today's name-only behaviour.
    ///
    /// The returned slice is borrowed from the index; lifetime ties to
    /// `&self`.  Callers may need to clone keys before mutating the
    /// owning graph.
    pub fn resolve(&self, lang: Lang, container: Option<&str>, method: &str) -> &[FuncKey] {
        match container {
            Some(c) if !c.is_empty() => self
                .by_container
                .get(&(lang, c.to_string(), method.to_string()))
                .map(|v| v.as_slice())
                .unwrap_or_default(),
            _ => self
                .by_name
                .get(&(lang, method.to_string()))
                .map(|v| v.as_slice())
                .unwrap_or_default(),
        }
    }

    /// Number of distinct `(lang, container, method)` keys.  Exposed
    /// for diagnostics / tests; production code uses [`Self::resolve`].
    #[allow(dead_code)]
    pub fn container_keys_len(&self) -> usize {
        self.by_container.len()
    }

    /// Number of distinct `(lang, method)` keys.  Exposed for
    /// diagnostics / tests.
    #[allow(dead_code)]
    pub fn name_keys_len(&self) -> usize {
        self.by_name.len()
    }
}

// ── Type hierarchy index ────────────────────────────────────────────────

/// Per-language `(super_type) → sub-types` index built from every merged
/// [`crate::summary::FuncSummary::hierarchy_edges`]. Lets virtual
/// dispatch fan out to every concrete implementer's matching method.
///
/// Covers Java `extends`/`implements`, Rust `impl Trait for Type`, TS
/// `extends`/`implements`, Python `class X(Base)`, plus PHP/Ruby/C++
/// (see `crate::cfg::hierarchy`). Go's structural interfaces are
/// intentionally omitted, name-only resolution is used instead.
///
/// Container names are bare (no namespace), so cross-namespace aliases
/// may over-fan-out. That is conservative for correctness.
#[derive(Debug, Default, Clone)]
pub struct TypeHierarchyIndex {
    /// `(lang, super_type)` → distinct sub-type / impl container names.
    by_super: HashMap<(Lang, String), SmallVec<[String; 4]>>,
    /// `(lang, sub_type)` → super-types this type extends / implements.
    /// Future use for `super.method()` resolution; populated for
    /// completeness today.
    #[allow(dead_code)]
    by_sub: HashMap<(Lang, String), SmallVec<[String; 2]>>,
}

impl TypeHierarchyIndex {
    /// Build the index from every merged
    /// [`crate::summary::FuncSummary::hierarchy_edges`] vector.  Each
    /// `(sub, super)` pair is inserted once per language; duplicates
    /// across files (the same edge written into every per-file
    /// summary) collapse via the membership check.
    pub fn build(summaries: &GlobalSummaries) -> Self {
        let mut by_super: HashMap<(Lang, String), SmallVec<[String; 4]>> = HashMap::new();
        let mut by_sub: HashMap<(Lang, String), SmallVec<[String; 2]>> = HashMap::new();

        for (key, summary) in summaries.iter() {
            let lang = key.lang;
            for (sub, sup) in &summary.hierarchy_edges {
                if sub.is_empty() || sup.is_empty() {
                    continue;
                }
                let subs = by_super.entry((lang, sup.clone())).or_default();
                if !subs.iter().any(|s| s == sub) {
                    subs.push(sub.clone());
                }
                let sups = by_sub.entry((lang, sub.clone())).or_default();
                if !sups.iter().any(|s| s == sup) {
                    sups.push(sup.clone());
                }
            }
        }

        TypeHierarchyIndex { by_super, by_sub }
    }

    /// Return the distinct sub-type / impl container names for
    /// `super_type`.  Empty slice when the type has no recorded
    /// subs (i.e. either it's a leaf type or no matching
    /// hierarchy edges were extracted).
    pub fn subs_of(&self, lang: Lang, super_type: &str) -> &[String] {
        self.by_super
            .get(&(lang, super_type.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or_default()
    }

    /// Return the recorded super-types of `sub_type`.  Empty when
    /// `sub_type` has no recorded super-types in this language.
    #[allow(dead_code)]
    pub fn supers_of(&self, lang: Lang, sub_type: &str) -> &[String] {
        self.by_sub
            .get(&(lang, sub_type.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or_default()
    }

    /// Number of distinct `(lang, super_type)` keys.  Exposed for
    /// diagnostics / tests.
    #[allow(dead_code)]
    pub fn super_keys_len(&self) -> usize {
        self.by_super.len()
    }

    /// Resolve `(container, method)` widened by hierarchy lookup,
    /// returning every concrete-implementer FuncKey whose container
    /// is `container` itself OR a known sub-type of `container`.
    ///
    /// Behaviour:
    /// * `container = None` → falls through to
    ///   [`ClassMethodIndex::resolve`]'s name-only path; the
    ///   hierarchy lookup is a no-op.
    /// * `container = Some(c)` and `c` has no recorded sub-types →
    ///   identical to `ClassMethodIndex::resolve(_, Some(c), _)`.
    /// * `container = Some(c)` with sub-types `s1, s2, …` → union of
    ///   `resolve(_, Some(c), m)` ∪ `resolve(_, Some(s1), m)` ∪
    ///   `resolve(_, Some(s2), m)` ∪ ….  Dedup is applied.
    ///
    /// The returned `Vec` is a fresh allocation since the union is
    /// computed across multiple borrowed slices in the underlying
    /// [`ClassMethodIndex`] and cannot share storage with any of them.
    /// Cost: O(k · m) where k = number of sub-types and m = average
    /// candidates per `(container, method)` lookup; in practice k is
    /// in the single digits.
    pub fn resolve_with_hierarchy(
        &self,
        method_index: &ClassMethodIndex,
        lang: Lang,
        container: Option<&str>,
        method: &str,
    ) -> Vec<FuncKey> {
        let Some(c) = container.filter(|s| !s.is_empty()) else {
            return method_index.resolve(lang, None, method).to_vec();
        };
        let mut out: Vec<FuncKey> = Vec::new();
        let push_unique = |dst: &mut Vec<FuncKey>, src: &[FuncKey]| {
            for k in src {
                if !dst.iter().any(|e| e == k) {
                    dst.push(k.clone());
                }
            }
        };
        // Direct container match first.
        push_unique(&mut out, method_index.resolve(lang, Some(c), method));
        // Each known sub-type of `c`.
        for sub in self.subs_of(lang, c) {
            push_unique(
                &mut out,
                method_index.resolve(lang, Some(sub.as_str()), method),
            );
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Call-graph construction
// ─────────────────────────────────────────────────────────────────────────────

/// Build the whole-program call graph from merged summaries.
///
/// Resolution strategy:
///   1. Extract leaf name for `resolve_callee_key` lookup
///   2. Same-language, arity-filtered, namespace-disambiguated lookup
///   3. On ambiguity: use two-segment qualified name to narrow candidates
///   4. Interop edges (explicit cross-language bridges)
///
/// Typed-call devirtualisation: when the caller's SSA summary carries
/// a typed container for a call ordinal, that site is first resolved
/// via [`ClassMethodIndex`] restricted to the receiver type. Exact
/// match → edge; multi-candidate → fed back through
/// `CalleeQuery.receiver_type`; zero match → name-only fallback.
///
/// Unresolved and ambiguous callees are recorded for diagnostics but
/// do **not** create edges.
pub fn build_call_graph(summaries: &GlobalSummaries, interop_edges: &[InteropEdge]) -> CallGraph {
    let mut graph = DiGraph::new();
    let mut index = HashMap::new();

    // 1. Create one node per FuncKey.
    for (key, _) in summaries.iter() {
        let idx = graph.add_node(key.clone());
        index.insert(key.clone(), idx);
    }

    // build a single `(lang, container, name) → candidates`
    // index from the merged summaries.  Used below to devirtualise
    // every method-call edge whose receiver has a recoverable type
    // fact.  Cost is one allocation per FuncKey across the program;
    // amortised against the per-call-site savings, this is a clear
    // win on codebases with many same-name methods.
    let method_index = ClassMethodIndex::build(summaries);

    // build a sibling `(lang, super_type) → sub_types` index
    // from every merged summary's `hierarchy_edges`.  Consumed below
    // to fan out method-call edges to all known concrete
    // implementers when a receiver's static type is a super-class /
    // trait / interface.  Empty for languages without an extractor
    // (Go, C) and for files with no inheritance / impl declarations.
    let hierarchy = TypeHierarchyIndex::build(summaries);

    let mut unresolved_not_found = Vec::new();
    let mut unresolved_ambiguous = Vec::new();

    // 2. Resolve callees and add edges.
    for (caller_key, summary) in summaries.iter() {
        let caller_node = index[caller_key];

        // Rebuild the caller's `use` map once per function rather than per
        // call site.  Non-Rust callers always get `None`.
        let rust_use_map: Option<RustUseMap> = if caller_key.lang == Lang::Rust {
            match (&summary.rust_use_map, &summary.rust_wildcards) {
                (None, None) => None,
                (a, w) => Some(RustUseMap {
                    aliases: a.clone().unwrap_or_default(),
                    wildcards: w.clone().unwrap_or_default(),
                }),
            }
        } else {
            None
        };

        // per-caller `(call_ordinal → container_name)` map
        // pulled from the caller's SSA summary, when one exists.
        // Empty when the caller has no SSA summary (zero-param trivial
        // bodies skip extraction unless they had typed receivers) or
        // when no method call inside the caller had a recoverable
        // receiver type.  Empty maps mean today's resolution path
        // applies unchanged for every site in this caller.
        let typed_receivers: HashMap<u32, &str> = summaries
            .get_ssa(caller_key)
            .map(|ssa| {
                ssa.typed_call_receivers
                    .iter()
                    .map(|(ord, c)| (*ord, c.as_str()))
                    .collect()
            })
            .unwrap_or_default();

        for site in &summary.callees {
            let raw_callee = site.name.as_str();
            // Use leaf name for the initial lookup (FuncKey.name is always leaf).
            let leaf = callee_leaf_name(raw_callee);
            // Two-segment form for diagnostics / fallback disambiguation.
            let qualified = normalize_callee_name(raw_callee);
            // Structured arity carried per call site, used to disambiguate
            // same-name/different-arity overloads during resolution.
            let arity_hint: Option<usize> = site.arity;

            // Devirtualisation: for method calls whose SSA summary
            // recorded a typed container, resolve via ClassMethodIndex
            // first. Single match → direct edge; multi → fall through
            // with `receiver_type` set; zero → name-only fallback so
            // misclassified receivers never silently drop edges.
            let typed_container: Option<&str> = if site.receiver.is_some() {
                typed_receivers.get(&site.ordinal).copied()
            } else {
                None
            };

            if let Some(container) = typed_container {
                // Resolve the typed container plus every known
                // sub-type / impl, so a super-class / trait / interface
                // receiver fans out to every concrete implementer.
                // No hierarchy entry → direct-container lookup.
                let widened: Vec<FuncKey> = hierarchy.resolve_with_hierarchy(
                    &method_index,
                    caller_key.lang,
                    Some(container),
                    leaf,
                );
                let arity_filtered: Vec<&FuncKey> = widened
                    .iter()
                    .filter(|k| match arity_hint {
                        Some(a) => k.arity == Some(a),
                        None => true,
                    })
                    .collect();
                if arity_filtered.len() == 1 {
                    if let Some(&target_node) = index.get(arity_filtered[0]) {
                        graph.add_edge(
                            caller_node,
                            target_node,
                            CallEdge {
                                call_site: raw_callee.to_string(),
                            },
                        );
                    }
                    continue;
                }
                // multiple arity-filtered candidates means
                // genuine virtual dispatch through a super-type, fan
                // out to *every* implementer.  This widens edges
                // (correctly: the call genuinely may target any
                // implementer at runtime) so SCC sizes may grow on
                // codebases with deep inheritance hierarchies.
                //
                // Authoritative narrowing via `resolve_callee` only
                // applies when the typed container is a *concrete*
                // class (sub-types empty); we detect this by checking
                // whether the direct method_index lookup would yield
                // every arity-filtered candidate.  If hierarchy
                // expansion produced extra candidates, fan out.
                let direct_matches: Vec<&FuncKey> = method_index
                    .resolve(caller_key.lang, Some(container), leaf)
                    .iter()
                    .filter(|k| match arity_hint {
                        Some(a) => k.arity == Some(a),
                        None => true,
                    })
                    .collect();
                if !arity_filtered.is_empty() && arity_filtered.len() > direct_matches.len() {
                    // Hierarchy fan-out path: add an edge per
                    // implementer.  Continue past the
                    // `resolve_callee` block so we don't double-add.
                    for &target_key in &arity_filtered {
                        if let Some(&target_node) = index.get(target_key) {
                            graph.add_edge(
                                caller_node,
                                target_node,
                                CallEdge {
                                    call_site: raw_callee.to_string(),
                                },
                            );
                        }
                    }
                    continue;
                }
                // Either zero matches (fall through to legacy path) or
                // multiple matches on the direct container, let
                // `resolve_callee` apply its authoritative
                // receiver_type filter + tie-breakers.
                if !arity_filtered.is_empty() {
                    let caller_container: Option<&str> = if caller_key.container.is_empty() {
                        None
                    } else {
                        Some(caller_key.container.as_str())
                    };
                    let resolution = summaries.resolve_callee(&CalleeQuery {
                        name: leaf,
                        caller_lang: caller_key.lang,
                        caller_namespace: &caller_key.namespace,
                        caller_container,
                        receiver_type: Some(container),
                        namespace_qualifier: site.qualifier.as_deref(),
                        receiver_var: site.receiver.as_deref(),
                        arity: arity_hint,
                    });
                    if let CalleeResolution::Resolved(key) = resolution
                        && let Some(&target_node) = index.get(&key)
                    {
                        graph.add_edge(
                            caller_node,
                            target_node,
                            CallEdge {
                                call_site: raw_callee.to_string(),
                            },
                        );
                        continue;
                    }
                    // Authoritative receiver_type miss with multiple
                    // bare candidates: fall through to today's path.
                }
            }

            // Rust callers with a module-qualified call (no receiver) go
            // through the `use`-map aware resolver first.  When the call has
            // a structured receiver it is a method call, the qualifier is
            // an impl/trait name, not a module path, so we fall back to the
            // structured resolver.  All other languages skip the use-map
            // branch entirely.
            let use_rust_path = caller_key.lang == Lang::Rust && site.receiver.is_none();
            let resolution = if use_rust_path {
                summaries.resolve_callee_key_rust(
                    leaf,
                    site.qualifier.as_deref(),
                    arity_hint,
                    &caller_key.namespace,
                    rust_use_map.as_ref(),
                )
            } else {
                // Non-Rust, or Rust method call with a receiver: route
                // through the qualified-first resolver.  We deliberately
                // categorize each hint so the resolver can apply the right
                // policy:
                //
                //   * `namespace_qualifier`, structured module/namespace
                //     prefix (`env` in `env::var`, `http` in `http.Get`).
                //   * `receiver_var`, syntactic receiver variable (e.g.
                //     `obj` in `obj.method`); used only as a last tie-break.
                //   * `caller_container`, caller's own class/impl, so bare
                //     `foo()` inside a method resolves to the same class.
                //
                // The raw text-parsed container (legacy
                // `callee_container_hint`) is only consulted when the
                // structured `CalleeSite` fields are absent (e.g. old
                // summaries loaded from SQLite without `qualifier`).
                let parsed_container = {
                    let raw = callee_container_hint(raw_callee);
                    if raw.is_empty() {
                        None
                    } else {
                        Some(raw.to_string())
                    }
                };
                let namespace_qualifier = site.qualifier.clone().or_else(|| {
                    if site.receiver.is_none() {
                        parsed_container.clone()
                    } else {
                        None
                    }
                });
                let receiver_var = site.receiver.clone();
                let caller_container: Option<&str> = if caller_key.container.is_empty() {
                    None
                } else {
                    Some(caller_key.container.as_str())
                };
                summaries.resolve_callee(&CalleeQuery {
                    name: leaf,
                    caller_lang: caller_key.lang,
                    caller_namespace: &caller_key.namespace,
                    caller_container,
                    receiver_type: None,
                    namespace_qualifier: namespace_qualifier.as_deref(),
                    receiver_var: receiver_var.as_deref(),
                    arity: arity_hint,
                })
            };

            match resolution {
                CalleeResolution::Resolved(target_key) => {
                    if let Some(&target_node) = index.get(&target_key) {
                        graph.add_edge(
                            caller_node,
                            target_node,
                            CallEdge {
                                call_site: raw_callee.to_string(),
                            },
                        );
                    }
                }
                CalleeResolution::NotFound => {
                    // Try interop edges before recording as not-found.
                    if let Some(target_key) =
                        resolve_via_interop(raw_callee, caller_key, interop_edges)
                        && let Some(&target_node) = index.get(&target_key)
                    {
                        graph.add_edge(
                            caller_node,
                            target_node,
                            CallEdge {
                                call_site: raw_callee.to_string(),
                            },
                        );
                        continue;
                    }
                    unresolved_not_found.push(UnresolvedCallee {
                        caller: caller_key.clone(),
                        callee_name: raw_callee.to_string(),
                    });
                }
                CalleeResolution::Ambiguous(candidates) => {
                    // Use the two-segment qualified name to narrow ambiguous candidates.
                    // If the callee was qualified (e.g. "env::var"), prefer candidates
                    // whose namespace contains the qualifier prefix.
                    if qualified != leaf {
                        let qualifier =
                            &qualified[..qualified.len() - leaf.len()].trim_end_matches([':', '.']);
                        let narrowed: Vec<_> = candidates
                            .iter()
                            .filter(|k| k.namespace.contains(qualifier))
                            .cloned()
                            .collect();
                        if narrowed.len() == 1
                            && let Some(&target_node) = index.get(&narrowed[0])
                        {
                            graph.add_edge(
                                caller_node,
                                target_node,
                                CallEdge {
                                    call_site: raw_callee.to_string(),
                                },
                            );
                            continue;
                        }
                    }
                    unresolved_ambiguous.push(AmbiguousCallee {
                        caller: caller_key.clone(),
                        callee_name: raw_callee.to_string(),
                        candidates,
                    });
                }
            }
        }
    }

    CallGraph {
        graph,
        index,
        unresolved_not_found,
        unresolved_ambiguous,
    }
}

/// Check interop edges for a matching cross-language bridge.
fn resolve_via_interop(
    raw_callee: &str,
    caller_key: &FuncKey,
    interop_edges: &[InteropEdge],
) -> Option<FuncKey> {
    for edge in interop_edges {
        if edge.from.caller_lang == caller_key.lang
            && edge.from.caller_namespace == caller_key.namespace
            && edge.from.callee_symbol == raw_callee
            && (edge.from.caller_func.is_empty() || edge.from.caller_func == caller_key.name)
        {
            return Some(edge.to.clone());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
//  SCC / topological analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Compute SCC decomposition and topological ordering of the call graph.
///
/// `petgraph::algo::tarjan_scc` returns SCCs in *reverse* topological order
/// of the condensation DAG, i.e. leaf SCCs (no outgoing cross-SCC edges)
/// come **first**.  That is exactly the **callee-first** order suitable for
/// bottom-up taint propagation.
pub fn analyse(cg: &CallGraph) -> CallGraphAnalysis {
    let sccs = petgraph::algo::tarjan_scc(&cg.graph);

    let mut node_to_scc = HashMap::with_capacity(cg.graph.node_count());
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for &node in scc {
            node_to_scc.insert(node, scc_idx);
        }
    }

    // tarjan_scc already gives callee-first ordering.
    let topo_scc_callee_first: Vec<usize> = (0..sccs.len()).collect();

    CallGraphAnalysis {
        sccs,
        node_to_scc,
        topo_scc_callee_first,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  File-level batch ordering
// ─────────────────────────────────────────────────────────────────────────────

/// A batch of files at a single topological position, annotated with whether
/// any contributing SCC contains mutual recursion (len > 1) and whether any
/// such SCC has nodes in more than one file (`cross_file`).
///
/// `has_mutual_recursion` triggers the SCC fixed-point loop in
/// `run_topo_batches`.  `cross_file` is a tighter
/// signal used by joint fixed-point convergence: it implies the
/// recursion involves at least one cross-file call edge, so the inline
/// cache and per-iteration findings need joint convergence, not just
/// summary convergence.
pub struct FileBatch<'a> {
    pub files: Vec<&'a PathBuf>,
    pub has_mutual_recursion: bool,
    /// True when at least one SCC contributing to this batch has nodes
    /// in more than one distinct file (namespace).  When `true`, the
    /// SCC iteration loop should consult the cross-file inline cache
    /// fingerprint as part of its convergence check.
    ///
    /// `cross_file` ⊆ `has_mutual_recursion`: a cross-file SCC must be
    /// recursive (else it would topo-sort linearly across files and not
    /// be batched together).
    pub cross_file: bool,
}

/// Returns `true` when the given SCC has nodes belonging to more than one
/// distinct namespace (file).  Used to flag cross-file SCCs that need the
/// cross-file joint fixed-point treatment.
///
/// Single-node SCCs always return `false`.  Multi-node SCCs whose nodes
/// all belong to the same namespace return `false`.
/// Reverse-edge traversal: return every [`FuncKey`] that has a call
/// edge *into* `callee`.  Used by the Phase-B worklist to compute
/// which callers need re-analysis after a callee's summary has
/// changed.
///
/// Returns an empty vector when the callee is unknown to the call
/// graph (e.g. summary was never produced, or the key was synthesised
/// post-build).
///
/// Cost: O(in_degree) via petgraph's `Incoming` neighbours iterator;
/// no allocation beyond the returned `Vec`.
pub fn callers_of(cg: &CallGraph, callee: &FuncKey) -> Vec<FuncKey> {
    let Some(&node) = cg.index.get(callee) else {
        return Vec::new();
    };
    cg.graph
        .neighbors_directed(node, petgraph::Direction::Incoming)
        .map(|caller_node| cg.graph[caller_node].clone())
        .collect()
}

/// Compute the set of file namespaces that must be re-analysed when a
/// given set of callee [`FuncKey`]s have had their summaries refined.
///
/// Fans out from each changed callee to its callers via
/// [`callers_of`], then projects onto `FuncKey::namespace`.  The
/// result is a `HashSet<String>` suitable for membership checks while
/// filtering the batch's file list.
///
/// A changed callee's *own* namespace is also included, if the
/// callee's summary was refined, the file it lives in may itself
/// have been a caller (intra-file recursion) or may carry sibling
/// functions whose analysis should be re-run alongside the callee
/// for consistency.
///
/// Deterministic: returns a [`std::collections::HashSet`] so iteration
/// order is not guaranteed, but membership is deterministic.  Callers
/// that need ordered output should collect and sort.
pub fn namespaces_for_callers(
    cg: &CallGraph,
    changed: &std::collections::HashSet<FuncKey>,
) -> std::collections::HashSet<String> {
    let mut result = std::collections::HashSet::new();
    for key in changed {
        result.insert(key.namespace.clone());
        for caller in callers_of(cg, key) {
            result.insert(caller.namespace);
        }
    }
    result
}

pub fn scc_spans_files(cg: &CallGraph, scc: &[NodeIndex]) -> bool {
    if scc.len() < 2 {
        return false;
    }
    let mut iter = scc.iter();
    let first_ns = iter.next().map(|n| cg.graph[*n].namespace.as_str());
    let Some(first_ns) = first_ns else {
        return false;
    };
    iter.any(|n| cg.graph[*n].namespace.as_str() != first_ns)
}

/// Like [`scc_file_batches`] but annotates each batch with whether any
/// contributing SCC has mutual recursion (`len > 1`).
///
/// Returns `(ordered_batches, orphan_files)`.
pub fn scc_file_batches_with_metadata<'a>(
    cg: &CallGraph,
    analysis: &CallGraphAnalysis,
    all_files: &'a [PathBuf],
    root: &Path,
) -> (Vec<FileBatch<'a>>, Vec<&'a PathBuf>) {
    let root_str = root.to_string_lossy();

    // 1. Map relative-path → &PathBuf for each file in all_files.
    let mut rel_to_path: HashMap<String, &'a PathBuf> = HashMap::with_capacity(all_files.len());
    for p in all_files {
        let abs = p.to_string_lossy();
        let rel = crate::symbol::normalize_namespace(&abs, Some(&root_str));
        rel_to_path.insert(rel, p);
    }

    // 2. Build file relative-path → (min topo index, has_mutual_recursion, cross_file).
    //    `cross_file` is set whenever the file participates in an SCC whose
    //    nodes span more than one namespace, the cross-file signal.
    let mut file_topo: HashMap<&str, (usize, bool, bool)> = HashMap::new();
    for (topo_pos, &scc_idx) in analysis.topo_scc_callee_first.iter().enumerate() {
        let scc_recursive = analysis.sccs[scc_idx].len() > 1;
        let scc_cross_file = scc_spans_files(cg, &analysis.sccs[scc_idx]);
        for &node in &analysis.sccs[scc_idx] {
            let ns = &cg.graph[node].namespace;
            file_topo
                .entry(ns.as_str())
                .and_modify(|(min_pos, recursive, cross_file)| {
                    if topo_pos < *min_pos {
                        *min_pos = topo_pos;
                    }
                    *recursive |= scc_recursive;
                    *cross_file |= scc_cross_file;
                })
                .or_insert((topo_pos, scc_recursive, scc_cross_file));
        }
    }

    // 3. Group files by min topo index, preserving order via BTreeMap.
    //    Track mutual-recursion and cross-file flags per group.
    let mut topo_groups: BTreeMap<usize, (Vec<&'a PathBuf>, bool, bool)> = BTreeMap::new();
    let mut orphans: Vec<&'a PathBuf> = Vec::new();

    for p in all_files {
        let abs = p.to_string_lossy();
        let rel = crate::symbol::normalize_namespace(&abs, Some(&root_str));
        if let Some(&(topo_pos, recursive, cross_file)) = file_topo.get(rel.as_str()) {
            let entry = topo_groups
                .entry(topo_pos)
                .or_insert_with(|| (Vec::new(), false, false));
            entry.0.push(p);
            entry.1 |= recursive;
            entry.2 |= cross_file;
        } else {
            orphans.push(p);
        }
    }

    let batches: Vec<FileBatch<'a>> = topo_groups
        .into_values()
        .map(|(files, has_mutual_recursion, cross_file)| FileBatch {
            files,
            has_mutual_recursion,
            cross_file,
        })
        .collect();
    (batches, orphans)
}

/// Map SCC topological order to an ordered sequence of file-path batches.
///
/// Uses **min** topo index: a file is placed in the earliest batch where any
/// of its functions appear. This ensures leaf callees are available as early
/// as possible for files that depend on them. Caller functions in the same
/// file that happen to be in a later SCC are no worse off than the current
/// fully-parallel approach, they simply don't yet benefit from ordering,
/// but nothing is lost.
///
/// Returns `(ordered_batches, orphan_files)` where orphan_files are paths
/// from `all_files` that have no functions in the call graph.
#[allow(dead_code)] // kept for tests; production callers use scc_file_batches_with_metadata
pub fn scc_file_batches<'a>(
    cg: &CallGraph,
    analysis: &CallGraphAnalysis,
    all_files: &'a [PathBuf],
    root: &Path,
) -> (Vec<Vec<&'a PathBuf>>, Vec<&'a PathBuf>) {
    let root_str = root.to_string_lossy();

    // 1. Map relative-path → &PathBuf for each file in all_files.
    let mut rel_to_path: HashMap<String, &'a PathBuf> = HashMap::with_capacity(all_files.len());
    for p in all_files {
        let abs = p.to_string_lossy();
        let rel = crate::symbol::normalize_namespace(&abs, Some(&root_str));
        rel_to_path.insert(rel, p);
    }

    // 2. Build file relative-path → min topo index.
    let mut file_min_topo: HashMap<&str, usize> = HashMap::new();
    for (topo_pos, &scc_idx) in analysis.topo_scc_callee_first.iter().enumerate() {
        for &node in &analysis.sccs[scc_idx] {
            let ns = &cg.graph[node].namespace;
            file_min_topo.entry(ns.as_str()).or_insert(topo_pos);
        }
    }

    // 3. Group files by min topo index, preserving order via BTreeMap.
    let mut topo_groups: BTreeMap<usize, Vec<&'a PathBuf>> = BTreeMap::new();
    let mut orphans: Vec<&'a PathBuf> = Vec::new();

    for p in all_files {
        let abs = p.to_string_lossy();
        let rel = crate::symbol::normalize_namespace(&abs, Some(&root_str));
        if let Some(&topo_pos) = file_min_topo.get(rel.as_str()) {
            topo_groups.entry(topo_pos).or_default().push(p);
        } else {
            orphans.push(p);
        }
    }

    let batches: Vec<Vec<&'a PathBuf>> = topo_groups.into_values().collect();
    (batches, orphans)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::CallSiteKey;
    use crate::summary::{CalleeSite, FuncSummary, merge_summaries};
    use crate::symbol::Lang;

    /// Helper to create a minimal FuncSummary.
    fn make_summary(
        name: &str,
        file_path: &str,
        lang: &str,
        param_count: usize,
        callees: Vec<&str>,
    ) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: file_path.into(),
            lang: lang.into(),
            param_count,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: callees
                .into_iter()
                .map(crate::summary::CalleeSite::bare)
                .collect(),
            ..Default::default()
        }
    }

    // ── normalize_callee_name (two-segment) ─────────────────────────────

    #[test]
    fn normalize_callee_two_segment() {
        // Two-segment normalization preserves one level of qualification.
        assert_eq!(normalize_callee_name("env::var"), "env::var");
        assert_eq!(normalize_callee_name("std::env::var"), "env::var");
        assert_eq!(
            normalize_callee_name("std::process::Command"),
            "process::Command"
        );
        assert_eq!(normalize_callee_name("a::b::c"), "b::c");
        assert_eq!(normalize_callee_name("obj.method"), "obj.method");
        assert_eq!(normalize_callee_name("pkg.mod.func"), "mod.func");
        assert_eq!(
            normalize_callee_name("http_client.send"),
            "http_client.send"
        );
        assert_eq!(normalize_callee_name("send"), "send");
        assert_eq!(normalize_callee_name("foo"), "foo");
        assert_eq!(normalize_callee_name(""), "");
    }

    // ── callee_leaf_name (single-segment, backward compat) ───────────────

    #[test]
    fn callee_leaf_basic() {
        assert_eq!(callee_leaf_name("env::var"), "var");
        assert_eq!(callee_leaf_name("std::process::Command"), "Command");
        assert_eq!(callee_leaf_name("obj.method"), "method");
        assert_eq!(callee_leaf_name("pkg.mod.func"), "func");
        assert_eq!(callee_leaf_name("foo"), "foo");
        assert_eq!(callee_leaf_name(""), "");
    }

    // ── same name, different Rust modules ────────────────────────────────

    #[test]
    fn same_name_different_rust_modules() {
        let helper_a = make_summary("helper", "src/a.rs", "rust", 0, vec![]);
        let helper_b = make_summary("helper", "src/b.rs", "rust", 0, vec![]);
        let caller = make_summary("caller", "src/a.rs", "rust", 0, vec!["helper"]);

        let gs = merge_summaries(vec![helper_a, helper_b, caller], None);
        let cg = build_call_graph(&gs, &[]);

        // Two helper nodes + one caller node = 3 nodes
        assert_eq!(cg.graph.node_count(), 3);

        // Caller is in src/a.rs, so "helper" resolves to src/a.rs::helper
        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/a.rs".into(),
            name: "caller".into(),
            arity: Some(0),
            ..Default::default()
        };
        let helper_a_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/a.rs".into(),
            name: "helper".into(),
            arity: Some(0),
            ..Default::default()
        };

        let caller_node = cg.index[&caller_key];
        let helper_a_node = cg.index[&helper_a_key];

        // Exactly one edge: caller → helper_a
        let edges: Vec<_> = cg
            .graph
            .edges(caller_node)
            .filter(|e| e.target() == helper_a_node)
            .collect();
        assert_eq!(edges.len(), 1);
        assert!(cg.unresolved_not_found.is_empty());
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    // ── same name, Python vs Rust ────────────────────────────────────────

    #[test]
    fn same_name_python_and_rust() {
        let py_foo = make_summary("foo", "handler.py", "python", 0, vec![]);
        let rs_foo = make_summary("foo", "handler.rs", "rust", 0, vec![]);
        // Python caller calls "foo", should only see the Python one
        let py_caller = make_summary("main", "app.py", "python", 0, vec!["foo"]);

        let gs = merge_summaries(vec![py_foo, rs_foo, py_caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.node_count(), 3);

        let py_foo_key = FuncKey {
            lang: Lang::Python,
            namespace: "handler.py".into(),
            name: "foo".into(),
            arity: Some(0),
            ..Default::default()
        };
        let caller_key = FuncKey {
            lang: Lang::Python,
            namespace: "app.py".into(),
            name: "main".into(),
            arity: Some(0),
            ..Default::default()
        };

        let caller_node = cg.index[&caller_key];
        let py_foo_node = cg.index[&py_foo_key];

        // Edge goes to Python foo, not Rust foo
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target(), py_foo_node);
    }

    // ── arity differences → separate nodes ───────────────────────────────

    #[test]
    fn arity_differences_separate_nodes() {
        let helper1 = make_summary("helper", "lib.rs", "rust", 1, vec![]);
        let helper2 = make_summary("helper", "lib.rs", "rust", 2, vec![]);

        let gs = merge_summaries(vec![helper1, helper2], None);
        let cg = build_call_graph(&gs, &[]);

        // Two separate nodes (different arity → different FuncKey)
        assert_eq!(cg.graph.node_count(), 2);

        let key1 = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "helper".into(),
            arity: Some(1),
            ..Default::default()
        };
        let key2 = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "helper".into(),
            arity: Some(2),
            ..Default::default()
        };
        assert!(cg.index.contains_key(&key1));
        assert!(cg.index.contains_key(&key2));
    }

    // ── recursive SCC detection ──────────────────────────────────────────

    #[test]
    fn recursive_scc_detection() {
        let a = make_summary("a", "lib.rs", "rust", 0, vec!["b"]);
        let b = make_summary("b", "lib.rs", "rust", 0, vec!["a"]);

        let gs = merge_summaries(vec![a, b], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 2); // a→b and b→a

        let analysis = analyse(&cg);

        // Both nodes should be in the same SCC
        let key_a = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "a".into(),
            arity: Some(0),
            ..Default::default()
        };
        let key_b = FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: "b".into(),
            arity: Some(0),
            ..Default::default()
        };

        let scc_a = analysis.node_to_scc[&cg.index[&key_a]];
        let scc_b = analysis.node_to_scc[&cg.index[&key_b]];
        assert_eq!(scc_a, scc_b);
        assert_eq!(analysis.sccs[scc_a].len(), 2);
    }

    // ── unresolved callee → recorded as not found ────────────────────────

    #[test]
    fn unresolved_callee_recorded_as_not_found() {
        let caller = make_summary("caller", "lib.rs", "rust", 0, vec!["nonexistent"]);

        let gs = merge_summaries(vec![caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 0);
        assert_eq!(cg.unresolved_not_found.len(), 1);
        assert_eq!(cg.unresolved_not_found[0].callee_name, "nonexistent");
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    // ── ambiguous callee → recorded as ambiguous ─────────────────────────

    #[test]
    fn ambiguous_callee_recorded() {
        // Two "helper" functions in different namespaces.
        let helper_a = make_summary("helper", "a.rs", "rust", 0, vec![]);
        let helper_b = make_summary("helper", "b.rs", "rust", 0, vec![]);
        // Caller is in a THIRD namespace, so neither is preferred.
        let caller = make_summary("caller", "c.rs", "rust", 0, vec!["helper"]);

        let gs = merge_summaries(vec![helper_a, helper_b, caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 0); // no edge, ambiguous
        assert!(cg.unresolved_not_found.is_empty());
        assert_eq!(cg.unresolved_ambiguous.len(), 1);
        assert_eq!(cg.unresolved_ambiguous[0].callee_name, "helper");
        assert_eq!(cg.unresolved_ambiguous[0].candidates.len(), 2);
    }

    // ── diamond topo order (callee-first) ────────────────────────────────

    #[test]
    fn diamond_topo_callee_first() {
        // A → B, A → C, B → D, C → D
        let d = make_summary("d", "lib.rs", "rust", 0, vec![]);
        let b = make_summary("b", "lib.rs", "rust", 0, vec!["d"]);
        let c = make_summary("c", "lib.rs", "rust", 0, vec!["d"]);
        let a = make_summary("a", "lib.rs", "rust", 0, vec!["b", "c"]);

        let gs = merge_summaries(vec![a, b, c, d], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.node_count(), 4);

        let analysis = analyse(&cg);

        let key = |name: &str| FuncKey {
            lang: Lang::Rust,
            namespace: "lib.rs".into(),
            name: name.into(),
            arity: Some(0),
            ..Default::default()
        };

        let scc_of = |name: &str| analysis.node_to_scc[&cg.index[&key(name)]];
        let topo_pos = |name: &str| {
            analysis
                .topo_scc_callee_first
                .iter()
                .position(|&s| s == scc_of(name))
                .unwrap()
        };

        // D (leaf) must come before B and C, which must come before A (root).
        assert!(topo_pos("d") < topo_pos("b"));
        assert!(topo_pos("d") < topo_pos("c"));
        assert!(topo_pos("b") < topo_pos("a"));
        assert!(topo_pos("c") < topo_pos("a"));
    }

    // ── interop edge resolution ──────────────────────────────────────────

    #[test]
    fn interop_edge_resolution() {
        let py_caller = make_summary("process", "handler.py", "python", 0, vec!["js_func"]);
        let js_target = make_summary("js_func", "util.js", "javascript", 1, vec![]);

        let gs = merge_summaries(vec![py_caller, js_target], None);

        let interop = vec![InteropEdge {
            from: CallSiteKey {
                caller_lang: Lang::Python,
                caller_namespace: "handler.py".into(),
                caller_func: String::new(), // wildcard
                callee_symbol: "js_func".into(),
                ordinal: 0,
            },
            to: FuncKey {
                lang: Lang::JavaScript,
                namespace: "util.js".into(),
                name: "js_func".into(),
                arity: Some(1),
                ..Default::default()
            },
        }];

        let cg = build_call_graph(&gs, &interop);

        let caller_key = FuncKey {
            lang: Lang::Python,
            namespace: "handler.py".into(),
            name: "process".into(),
            arity: Some(0),
            ..Default::default()
        };
        let target_key = FuncKey {
            lang: Lang::JavaScript,
            namespace: "util.js".into(),
            name: "js_func".into(),
            arity: Some(1),
            ..Default::default()
        };

        let caller_node = cg.index[&caller_key];
        let target_node = cg.index[&target_key];

        let edges: Vec<_> = cg
            .graph
            .edges(caller_node)
            .filter(|e| e.target() == target_node)
            .collect();
        assert_eq!(edges.len(), 1);
        assert!(cg.unresolved_not_found.is_empty());
    }

    // ── namespace normalization consistency ───────────────────────────────

    #[test]
    fn namespace_normalization_consistency() {
        // FuncSummary::func_key with a scan root produces the same namespace
        // string that would be used as caller_namespace in resolution.
        let summary = FuncSummary {
            name: "my_func".into(),
            file_path: "/home/user/proj/src/lib.rs".into(),
            lang: "rust".into(),
            param_count: 0,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: vec![],
            ..Default::default()
        };

        let root = "/home/user/proj";
        let key = summary.func_key(Some(root));

        // The namespace in the key must be the same as what normalize_namespace produces
        let expected_ns = crate::symbol::normalize_namespace(&summary.file_path, Some(root));
        assert_eq!(key.namespace, expected_ns);
        assert_eq!(key.namespace, "src/lib.rs");
    }

    // ── raw call_site preserved on edge ──────────────────────────────────

    #[test]
    fn raw_call_site_preserved_on_edge() {
        // Callee "env::var" normalizes to "var" for resolution, but
        // the edge should retain the original raw text.
        let source = make_summary("var", "util.rs", "rust", 0, vec![]);
        let caller = make_summary("main", "util.rs", "rust", 0, vec!["env::var"]);

        let gs = merge_summaries(vec![source, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "util.rs".into(),
            name: "main".into(),
            arity: Some(0),
            ..Default::default()
        };
        let caller_node = cg.index[&caller_key];

        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 1);
        // Raw call_site preserved, not the normalized "var"
        assert_eq!(edges[0].weight().call_site, "env::var");
    }

    // ── scc_file_batches ────────────────────────────────────────────────

    /// Helper: build summaries, call graph, analysis, and file batches in one go.
    fn build_batches<'a>(
        summaries: Vec<FuncSummary>,
        all_files: &'a [PathBuf],
        root: &Path,
    ) -> (Vec<Vec<&'a PathBuf>>, Vec<&'a PathBuf>) {
        let gs = merge_summaries(summaries, Some(&root.to_string_lossy()));
        let cg = build_call_graph(&gs, &[]);
        let analysis = analyse(&cg);
        scc_file_batches(&cg, &analysis, all_files, root)
    }

    #[test]
    fn scc_file_batches_linear_chain() {
        // A (a.rs) → B (b.rs) → C (c.rs)
        let root = Path::new("/proj");
        let c = make_summary("c_fn", "/proj/c.rs", "rust", 0, vec![]);
        let b = make_summary("b_fn", "/proj/b.rs", "rust", 0, vec!["c_fn"]);
        let a = make_summary("a_fn", "/proj/a.rs", "rust", 0, vec!["b_fn"]);

        let files: Vec<PathBuf> = vec![
            PathBuf::from("/proj/a.rs"),
            PathBuf::from("/proj/b.rs"),
            PathBuf::from("/proj/c.rs"),
        ];

        let (batches, orphans) = build_batches(vec![a, b, c], &files, root);

        assert!(orphans.is_empty());
        assert_eq!(batches.len(), 3, "3 files in a linear chain → 3 batches");

        // C's file in first batch, B's in second, A's in third
        let batch_of = |name: &str| {
            batches
                .iter()
                .position(|batch: &Vec<&PathBuf>| {
                    batch.iter().any(|p| p.to_str().unwrap().ends_with(name))
                })
                .unwrap()
        };
        assert!(batch_of("c.rs") < batch_of("b.rs"));
        assert!(batch_of("b.rs") < batch_of("a.rs"));
    }

    #[test]
    fn scc_file_batches_orphan_files() {
        let root = Path::new("/proj");
        let a = make_summary("a_fn", "/proj/a.rs", "rust", 0, vec![]);

        let files: Vec<PathBuf> = vec![
            PathBuf::from("/proj/a.rs"),
            PathBuf::from("/proj/orphan.rs"),
        ];

        let (batches, orphans) = build_batches(vec![a], &files, root);

        // a.rs is in the graph, orphan.rs is not
        assert_eq!(orphans.len(), 1);
        assert!(orphans[0].to_str().unwrap().ends_with("orphan.rs"));
        // a.rs should be in exactly one batch
        let total_in_batches: usize = batches.iter().map(|b: &Vec<&PathBuf>| b.len()).sum();
        assert_eq!(total_in_batches, 1);
    }

    #[test]
    fn scc_file_batches_multi_scc_same_file() {
        // File has a leaf fn (SCC 0) and a caller fn (SCC 2) that calls
        // through a middle function in another file.
        // leaf (a.rs) ← mid (b.rs) ← caller (a.rs)
        // With min-topo, a.rs placed at earliest SCC (leaf's position).
        let root = Path::new("/proj");
        let leaf = make_summary("leaf", "/proj/a.rs", "rust", 0, vec![]);
        let mid = make_summary("mid", "/proj/b.rs", "rust", 0, vec!["leaf"]);
        let caller = make_summary("caller", "/proj/a.rs", "rust", 0, vec!["mid"]);

        let files: Vec<PathBuf> = vec![PathBuf::from("/proj/a.rs"), PathBuf::from("/proj/b.rs")];

        let (batches, orphans) = build_batches(vec![leaf, mid, caller], &files, root);

        assert!(orphans.is_empty());
        let batch_of = |name: &str| {
            batches
                .iter()
                .position(|batch: &Vec<&PathBuf>| {
                    batch.iter().any(|p| p.to_str().unwrap().ends_with(name))
                })
                .unwrap()
        };
        // a.rs should be in the earliest batch (min topo from leaf)
        assert!(
            batch_of("a.rs") < batch_of("b.rs"),
            "a.rs has leaf fn so should be in earlier batch than b.rs"
        );
    }

    #[test]
    fn scc_file_batches_mutual_recursion() {
        // Two mutually-recursive functions across two files → same SCC → same batch.
        let root = Path::new("/proj");
        let a = make_summary("ping", "/proj/a.rs", "rust", 0, vec!["pong"]);
        let b = make_summary("pong", "/proj/b.rs", "rust", 0, vec!["ping"]);

        let files: Vec<PathBuf> = vec![PathBuf::from("/proj/a.rs"), PathBuf::from("/proj/b.rs")];

        let (batches, orphans) = build_batches(vec![a, b], &files, root);

        assert!(orphans.is_empty());
        // Both files should be in the same batch (same SCC)
        assert_eq!(
            batches.len(),
            1,
            "mutual recursion → single SCC → single batch"
        );
        assert_eq!(batches[0].len(), 2);
    }

    #[test]
    fn scc_file_batches_empty_graph() {
        let root = Path::new("/proj");
        let files: Vec<PathBuf> = vec![PathBuf::from("/proj/a.rs"), PathBuf::from("/proj/b.rs")];

        let gs = merge_summaries(vec![], None);
        let cg = build_call_graph(&gs, &[]);
        let analysis = analyse(&cg);
        let (batches, orphans) = scc_file_batches(&cg, &analysis, &files, root);

        assert!(batches.is_empty(), "empty graph → no batches");
        assert_eq!(orphans.len(), 2, "all files are orphans");
    }

    // ── scc_file_batches_with_metadata ────────────────────────────────

    /// Helper: build summaries, call graph, analysis, and metadata batches.
    fn build_metadata_batches<'a>(
        summaries: Vec<FuncSummary>,
        all_files: &'a [PathBuf],
        root: &Path,
    ) -> (Vec<FileBatch<'a>>, Vec<&'a PathBuf>) {
        let gs = merge_summaries(summaries, Some(&root.to_string_lossy()));
        let cg = build_call_graph(&gs, &[]);
        let analysis = analyse(&cg);
        scc_file_batches_with_metadata(&cg, &analysis, all_files, root)
    }

    #[test]
    fn scc_file_batches_with_metadata_marks_recursive() {
        // Two mutually-recursive functions → SCC with len > 1 → has_mutual_recursion = true
        let root = Path::new("/proj");
        let a = make_summary("ping", "/proj/a.rs", "rust", 0, vec!["pong"]);
        let b = make_summary("pong", "/proj/b.rs", "rust", 0, vec!["ping"]);

        let files: Vec<PathBuf> = vec![PathBuf::from("/proj/a.rs"), PathBuf::from("/proj/b.rs")];

        let (batches, orphans) = build_metadata_batches(vec![a, b], &files, root);

        assert!(orphans.is_empty());
        assert_eq!(batches.len(), 1, "mutual recursion → single batch");
        assert!(
            batches[0].has_mutual_recursion,
            "batch with mutual recursion should be marked"
        );
        assert_eq!(batches[0].files.len(), 2);
    }

    #[test]
    fn scc_file_batches_with_metadata_marks_cross_file() {
        // Two mutually-recursive functions in different files → cross_file = true
        let root = Path::new("/proj");
        let a = make_summary("ping", "/proj/a.rs", "rust", 0, vec!["pong"]);
        let b = make_summary("pong", "/proj/b.rs", "rust", 0, vec!["ping"]);

        let files: Vec<PathBuf> = vec![PathBuf::from("/proj/a.rs"), PathBuf::from("/proj/b.rs")];

        let (batches, _orphans) = build_metadata_batches(vec![a, b], &files, root);
        assert_eq!(
            batches.len(),
            1,
            "cross-file mutual recursion → single batch"
        );
        assert!(batches[0].has_mutual_recursion);
        assert!(
            batches[0].cross_file,
            "batch whose SCC spans two namespaces should be marked cross_file"
        );
    }

    #[test]
    fn scc_file_batches_with_metadata_intra_file_scc_not_cross_file() {
        // Two mutually-recursive functions in the SAME file → not cross_file
        let root = Path::new("/proj");
        let a = make_summary("ping", "/proj/a.rs", "rust", 0, vec!["pong"]);
        let b = make_summary("pong", "/proj/a.rs", "rust", 0, vec!["ping"]);

        let files: Vec<PathBuf> = vec![PathBuf::from("/proj/a.rs")];

        let (batches, _orphans) = build_metadata_batches(vec![a, b], &files, root);
        assert_eq!(batches.len(), 1);
        assert!(batches[0].has_mutual_recursion);
        assert!(
            !batches[0].cross_file,
            "single-file SCC must not be flagged as cross_file"
        );
    }

    #[test]
    fn scc_spans_files_single_node() {
        // Singleton SCC is never cross-file.
        let root = Path::new("/proj");
        let a = make_summary("f", "/proj/a.rs", "rust", 0, vec![]);
        let gs = merge_summaries(vec![a], Some(&root.to_string_lossy()));
        let cg = build_call_graph(&gs, &[]);
        let analysis = analyse(&cg);
        for scc in &analysis.sccs {
            assert!(!scc_spans_files(&cg, scc));
        }
    }

    #[test]
    fn scc_file_batches_with_metadata_singleton_not_recursive() {
        // Linear chain: no mutual recursion → has_mutual_recursion = false for all batches
        let root = Path::new("/proj");
        let c = make_summary("c_fn", "/proj/c.rs", "rust", 0, vec![]);
        let b = make_summary("b_fn", "/proj/b.rs", "rust", 0, vec!["c_fn"]);
        let a = make_summary("a_fn", "/proj/a.rs", "rust", 0, vec!["b_fn"]);

        let files: Vec<PathBuf> = vec![
            PathBuf::from("/proj/a.rs"),
            PathBuf::from("/proj/b.rs"),
            PathBuf::from("/proj/c.rs"),
        ];

        let (batches, orphans) = build_metadata_batches(vec![a, b, c], &files, root);

        assert!(orphans.is_empty());
        assert_eq!(batches.len(), 3, "3 files in linear chain → 3 batches");
        for (i, batch) in batches.iter().enumerate() {
            assert!(
                !batch.has_mutual_recursion,
                "batch {i} should not be marked as recursive"
            );
        }
    }

    // ── qualified disambiguation resolves ambiguous common names ──────

    #[test]
    fn qualified_callee_disambiguates_ambiguous() {
        // Two "send" functions in different namespaces.
        let send_http = make_summary("send", "src/http.rs", "rust", 0, vec![]);
        let send_mail = make_summary("send", "src/mail.rs", "rust", 0, vec![]);
        // Caller is in a third namespace, calling "http::send", leaf "send"
        // is ambiguous, but "http" qualifier should match "src/http.rs".
        let caller = make_summary("caller", "src/main.rs", "rust", 0, vec!["http::send"]);

        let gs = merge_summaries(vec![send_http, send_mail, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "caller".into(),
            arity: Some(0),
            ..Default::default()
        };
        let send_http_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/http.rs".into(),
            name: "send".into(),
            arity: Some(0),
            ..Default::default()
        };

        let caller_node = cg.index[&caller_key];
        let send_http_node = cg.index[&send_http_key];

        // The qualified name "http::send" disambiguates to src/http.rs::send
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(
            edges.len(),
            1,
            "qualified name should resolve the ambiguity"
        );
        assert_eq!(edges[0].target(), send_http_node);
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    #[test]
    fn unqualified_callee_stays_ambiguous() {
        // Same setup but caller uses unqualified "send", no disambiguation
        let send_http = make_summary("send", "src/http.rs", "rust", 0, vec![]);
        let send_mail = make_summary("send", "src/mail.rs", "rust", 0, vec![]);
        let caller = make_summary("caller", "src/main.rs", "rust", 0, vec!["send"]);

        let gs = merge_summaries(vec![send_http, send_mail, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "caller".into(),
            arity: Some(0),
            ..Default::default()
        };
        let caller_node = cg.index[&caller_key];

        // Unqualified "send" → still ambiguous (no edge)
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 0, "unqualified name should remain ambiguous");
        assert_eq!(cg.unresolved_ambiguous.len(), 1);
    }

    #[test]
    fn simple_unqualified_resolves_as_before() {
        // Regression: a simple unqualified callee that isn't ambiguous should still resolve.
        let helper = make_summary("helper", "src/lib.rs", "rust", 0, vec![]);
        let caller = make_summary("caller", "src/lib.rs", "rust", 0, vec!["helper"]);

        let gs = merge_summaries(vec![helper, caller], None);
        let cg = build_call_graph(&gs, &[]);

        assert_eq!(cg.graph.edge_count(), 1);
        assert!(cg.unresolved_not_found.is_empty());
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    // ── structured-metadata disambiguation (callee metadata) ─────────────

    /// Helper: build a summary whose callees carry structured CalleeSite
    /// metadata, used by the tests below to exercise arity / receiver /
    /// qualifier propagation into resolution.
    fn summary_with_sites(
        name: &str,
        file_path: &str,
        lang: &str,
        param_count: usize,
        sites: Vec<CalleeSite>,
    ) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: file_path.into(),
            lang: lang.into(),
            param_count,
            param_names: vec![],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: 0,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![],
            callees: sites,
            ..Default::default()
        }
    }

    /// Arity in the structured `CalleeSite` must disambiguate two same-name
    /// overloads in the same namespace that previously could only be
    /// distinguished after caller-namespace narrowing.
    #[test]
    fn arity_hint_disambiguates_same_name_overloads() {
        // Two `encode` functions in the same file, different arities.
        let encode1 = make_summary("encode", "src/codec.rs", "rust", 1, vec![]);
        let encode2 = make_summary("encode", "src/codec.rs", "rust", 2, vec![]);
        // Caller lives in *another* file so namespace does not disambiguate ,
        // the only signal is the per-call-site arity.
        let caller = summary_with_sites(
            "driver",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "encode".into(),
                arity: Some(2),
                ..Default::default()
            }],
        );

        let gs = merge_summaries(vec![encode1, encode2, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "driver".into(),
            arity: Some(0),
            ..Default::default()
        };
        let encode2_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/codec.rs".into(),
            name: "encode".into(),
            arity: Some(2),
            ..Default::default()
        };
        let caller_node = cg.index[&caller_key];
        let encode2_node = cg.index[&encode2_key];
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 1, "arity hint should pick the 2-arg overload");
        assert_eq!(edges[0].target(), encode2_node);
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    /// Without an arity hint the same setup would be genuinely ambiguous.
    /// This is the negative control for the arity disambiguation test above.
    #[test]
    fn no_arity_hint_stays_ambiguous() {
        let encode1 = make_summary("encode", "src/codec.rs", "rust", 1, vec![]);
        let encode2 = make_summary("encode", "src/codec.rs", "rust", 2, vec![]);
        // Legacy-style callee entry with no structured metadata.
        let caller = summary_with_sites(
            "driver",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite::bare("encode")],
        );

        let gs = merge_summaries(vec![encode1, encode2, caller], None);
        let cg = build_call_graph(&gs, &[]);
        assert_eq!(cg.graph.edge_count(), 0, "no arity hint → ambiguous");
        assert_eq!(cg.unresolved_ambiguous.len(), 1);
    }

    /// Structured `receiver` field should route to the correct container
    /// when two classes in the same file define the same method name.
    #[test]
    fn receiver_field_disambiguates_methods() {
        // Two `process` methods on two classes in the same file.
        let mut fs_order = make_summary("process", "src/app.rs", "rust", 1, vec![]);
        fs_order.container = "OrderService".into();
        let mut fs_user = make_summary("process", "src/app.rs", "rust", 1, vec![]);
        fs_user.container = "UserService".into();

        // Caller in another file uses the structured receiver field rather
        // than baking the receiver into the callee name string.
        let caller = summary_with_sites(
            "main",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "process".into(),
                arity: Some(1),
                receiver: Some("OrderService".into()),
                ..Default::default()
            }],
        );

        let gs = merge_summaries(vec![fs_order, fs_user, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "main".into(),
            arity: Some(0),
            ..Default::default()
        };
        let order_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/app.rs".into(),
            container: "OrderService".into(),
            name: "process".into(),
            arity: Some(1),
            ..Default::default()
        };
        let caller_node = cg.index[&caller_key];
        let order_node = cg.index[&order_key];
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(
            edges.len(),
            1,
            "structured receiver should route to OrderService::process"
        );
        assert_eq!(edges[0].target(), order_node);
    }

    /// The `qualifier` field carries the non-method qualifier (`env` in
    /// `env::var`) directly, removing the need to re-parse the raw string.
    #[test]
    fn qualifier_field_disambiguates_non_method_calls() {
        let var_env = make_summary("var", "src/env.rs", "rust", 1, vec![]);
        // A same-named function that would otherwise be a tie-breaker target.
        let var_local = make_summary("var", "src/locals.rs", "rust", 1, vec![]);
        let caller = summary_with_sites(
            "main",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "env::var".into(),
                arity: Some(1),
                qualifier: Some("env".into()),
                ..Default::default()
            }],
        );

        let gs = merge_summaries(vec![var_env, var_local, caller], None);
        let cg = build_call_graph(&gs, &[]);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "main".into(),
            arity: Some(0),
            ..Default::default()
        };
        let env_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/env.rs".into(),
            name: "var".into(),
            arity: Some(1),
            ..Default::default()
        };
        let caller_node = cg.index[&caller_key];
        let env_node = cg.index[&env_key];
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].target(),
            env_node,
            "qualifier `env` should select src/env.rs::var"
        );
    }

    /// When the legacy `Vec<String>` form is loaded from an old database row,
    /// resolution should still work for unambiguous callers (no regression).
    #[test]
    fn legacy_string_callees_still_resolve() {
        let helper = make_summary("helper", "src/lib.rs", "rust", 0, vec![]);
        // make_summary already returns CalleeSite::bare entries, i.e. the
        // "lifted legacy" form with no arity or receiver metadata.
        let caller = make_summary("main", "src/lib.rs", "rust", 0, vec!["helper"]);
        let gs = merge_summaries(vec![helper, caller], None);
        let cg = build_call_graph(&gs, &[]);
        assert_eq!(cg.graph.edge_count(), 1);
        assert!(cg.unresolved_not_found.is_empty());
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    // ── ClassMethodIndex ────────────────────────────────────────────────

    /// Helper: `(name, container)` pairs in the same file.  Builds two
    /// summaries with the same leaf name on different containers so the
    /// container-keyed map has a non-trivial discriminator to preserve.
    fn make_method_summary(
        name: &str,
        container: &str,
        file_path: &str,
        lang: &str,
        param_count: usize,
    ) -> FuncSummary {
        let mut s = make_summary(name, file_path, lang, param_count, vec![]);
        s.container = container.into();
        s
    }

    #[test]
    fn class_method_index_disambiguates_same_name_across_containers() {
        // Two `findById` definitions on different classes in different
        // files.  The container-keyed lookup must return only the
        // container-matching candidate; the bare-name lookup must
        // return both.
        let repo = make_method_summary("findById", "Repository", "src/repo.rs", "rust", 1);
        let cache = make_method_summary("findById", "Cache", "src/cache.rs", "rust", 1);

        let gs = merge_summaries(vec![repo, cache], None);
        let idx = ClassMethodIndex::build(&gs);

        let repo_hits = idx.resolve(Lang::Rust, Some("Repository"), "findById");
        assert_eq!(
            repo_hits.len(),
            1,
            "Repository::findById should resolve to exactly one target"
        );
        assert_eq!(repo_hits[0].container, "Repository");

        let cache_hits = idx.resolve(Lang::Rust, Some("Cache"), "findById");
        assert_eq!(cache_hits.len(), 1);
        assert_eq!(cache_hits[0].container, "Cache");

        // Bare-name lookup keeps both candidates, fallback behaviour.
        let bare_hits = idx.resolve(Lang::Rust, None, "findById");
        assert_eq!(
            bare_hits.len(),
            2,
            "bare-name lookup should keep both same-name candidates"
        );
    }

    #[test]
    fn class_method_index_falls_back_to_name_when_container_unknown() {
        // `None` container or empty-string container both route to
        // the bare-name index, equivalent to today's name-only edge
        // insertion.
        let svc = make_method_summary("process", "OrderService", "src/svc.rs", "rust", 1);
        let helper = make_summary("process", "src/util.rs", "rust", 1, vec![]);

        let gs = merge_summaries(vec![svc, helper], None);
        let idx = ClassMethodIndex::build(&gs);

        // None → bare-name list (both targets).
        let none_hits = idx.resolve(Lang::Rust, None, "process");
        assert_eq!(none_hits.len(), 2);

        // Empty string container behaves identically to None, it is
        // not stored under any container key.
        let empty_hits = idx.resolve(Lang::Rust, Some(""), "process");
        assert_eq!(empty_hits.len(), 2);

        // Container `"OrderService"` narrows to the method only; the
        // free-function helper lives under empty container and does
        // not appear here.
        let cont_hits = idx.resolve(Lang::Rust, Some("OrderService"), "process");
        assert_eq!(cont_hits.len(), 1);
        assert_eq!(cont_hits[0].container, "OrderService");
    }

    #[test]
    fn class_method_index_empty_for_unknown_method() {
        let svc = make_method_summary("findById", "Repository", "src/repo.rs", "rust", 1);
        let gs = merge_summaries(vec![svc], None);
        let idx = ClassMethodIndex::build(&gs);

        // Wrong method name on the right container → empty.
        assert!(
            idx.resolve(Lang::Rust, Some("Repository"), "findByName")
                .is_empty()
        );
        // Right method, wrong container → empty (no fallback to bare-name
        // when a container is supplied, that's the whole devirtualisation
        // promise).
        assert!(
            idx.resolve(Lang::Rust, Some("OtherClass"), "findById")
                .is_empty()
        );
        // Unknown method name with no container → empty.
        assert!(idx.resolve(Lang::Rust, None, "doesNotExist").is_empty());
    }

    #[test]
    fn class_method_index_partitions_by_language() {
        // Same `(container, name)` in Java and TypeScript → must not
        // alias.  Cross-language calls are forbidden by the rest of the
        // pipeline; the index reflects that partition.
        let java_repo = make_method_summary("findById", "Repository", "Repo.java", "java", 1);
        let ts_repo = make_method_summary("findById", "Repository", "repo.ts", "typescript", 1);

        let gs = merge_summaries(vec![java_repo, ts_repo], None);
        let idx = ClassMethodIndex::build(&gs);

        let java_hits = idx.resolve(Lang::Java, Some("Repository"), "findById");
        assert_eq!(java_hits.len(), 1);
        assert_eq!(java_hits[0].lang, Lang::Java);

        let ts_hits = idx.resolve(Lang::TypeScript, Some("Repository"), "findById");
        assert_eq!(ts_hits.len(), 1);
        assert_eq!(ts_hits[0].lang, Lang::TypeScript);
    }

    #[test]
    fn class_method_index_handles_arity_overloads() {
        // Two arity overloads on the same container are both kept under
        // the same `(container, name)` key, arity narrowing is the
        // caller's responsibility (today's resolver also does this).
        let one = make_method_summary("encode", "Codec", "src/codec.rs", "rust", 1);
        let two = make_method_summary("encode", "Codec", "src/codec.rs", "rust", 2);

        let gs = merge_summaries(vec![one, two], None);
        let idx = ClassMethodIndex::build(&gs);

        let hits = idx.resolve(Lang::Rust, Some("Codec"), "encode");
        assert_eq!(
            hits.len(),
            2,
            "arity overloads should both appear under the same container key"
        );
    }

    // ── devirtualised edge insertion via typed_call_receivers ──

    /// Two `findById` definitions live on different containers in
    /// different files.  A caller whose SSA summary records the
    /// receiver type as `"Repository"` for the relevant ordinal must
    /// produce an edge **only** to `Repository::findById`, not to
    /// `Cache::findById`.  Without typed_call_receivers, today's
    /// receiver_var-based resolution would have to guess between the
    /// two and would record the call as ambiguous (no edge at all).
    #[test]
    fn typed_call_receivers_devirtualises_method_call() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let repo = make_method_summary("findById", "Repository", "src/repo.rs", "rust", 1);
        let cache = make_method_summary("findById", "Cache", "src/cache.rs", "rust", 1);
        // Caller's SSA summary will record `(ordinal=0, "Repository")`
        // for the single method call below.
        let caller = summary_with_sites(
            "lookup",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "findById".into(),
                arity: Some(1),
                receiver: Some("repo".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![repo, cache, caller], None);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "lookup".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Repository".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);

        let repo_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/repo.rs".into(),
            container: "Repository".into(),
            name: "findById".into(),
            arity: Some(1),
            ..Default::default()
        };
        let caller_node = cg.index[&caller_key];
        let repo_node = cg.index[&repo_key];

        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        assert_eq!(
            edges.len(),
            1,
            "typed receiver should resolve to exactly one target; got {edges:?}"
        );
        assert_eq!(
            edges[0].target(),
            repo_node,
            "edge must point to Repository::findById, not Cache::findById"
        );
        assert!(cg.unresolved_ambiguous.is_empty());
    }

    /// Negative control: when typed_call_receivers points at a
    /// container that doesn't define the method, devirtualisation
    /// must NOT silently drop the edge.  We fall through to today's
    /// name-only resolution so a stale or misclassified type fact
    /// can never cause regression.
    #[test]
    fn typed_call_receivers_falls_through_on_zero_match() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        // Single `process` on `Worker`.  No `process` exists on
        // `Other`, that's the receiver type the caller's SSA
        // summary will (incorrectly) record.
        let worker = make_method_summary("process", "Worker", "src/worker.rs", "rust", 1);
        let caller = summary_with_sites(
            "drive",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "process".into(),
                arity: Some(1),
                receiver: Some("worker".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![worker, caller], None);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "drive".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                // Wrong receiver type, `Other::process` does not exist.
                typed_call_receivers: vec![(0, "Other".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);

        let caller_node = cg.index[&caller_key];
        let edges: Vec<_> = cg.graph.edges(caller_node).collect();
        // Today's name-only resolution finds the unique `process`
        // candidate (Worker::process) and records the edge.  The
        // typed_call_receivers miss must not have suppressed it.
        assert_eq!(
            edges.len(),
            1,
            "stale/wrong type fact must fall through to today's resolution; \
             got {edges:?} (cf. ambiguous: {:?})",
            cg.unresolved_ambiguous,
        );
    }

    // ── TypeHierarchyIndex ───────────────────────────────────

    /// Helper: build a hierarchy index from a list of
    /// `(lang, sub, super)` edges by injecting them onto a single
    /// per-file FuncSummary.  Mirrors the production path:
    /// `merge_summaries` would receive these via
    /// `FuncSummary::hierarchy_edges`.
    fn hierarchy_from_edges(edges: Vec<(Lang, &str, &str)>) -> TypeHierarchyIndex {
        let mut summary = make_summary("dummy", "dummy.rs", "rust", 0, vec![]);
        // The lang on the FuncSummary is per-edge, so we group by
        // language and produce one summary per language.
        let mut by_lang: std::collections::HashMap<Lang, Vec<(String, String)>> =
            std::collections::HashMap::new();
        for (lang, sub, sup) in edges {
            by_lang
                .entry(lang)
                .or_default()
                .push((sub.to_string(), sup.to_string()));
        }
        let _ = &mut summary; // silence the dummy
        let mut all: Vec<FuncSummary> = Vec::new();
        for (lang, edges) in by_lang {
            let slug = match lang {
                Lang::Rust => "rust",
                Lang::Java => "java",
                Lang::Python => "python",
                Lang::TypeScript => "typescript",
                Lang::JavaScript => "javascript",
                Lang::Go => "go",
                Lang::Php => "php",
                Lang::Ruby => "ruby",
                Lang::C => "c",
                Lang::Cpp => "cpp",
            };
            let mut s = make_summary("dummy", "dummy.x", slug, 0, vec![]);
            s.hierarchy_edges = edges;
            all.push(s);
        }
        let gs = merge_summaries(all, None);
        TypeHierarchyIndex::build(&gs)
    }

    /// B-1: Round-trip, a hierarchy built from a small set of edges
    /// answers `subs_of` correctly and `super_keys_len` matches the
    /// distinct super count.
    #[test]
    fn b1_type_hierarchy_index_round_trip() {
        let h = hierarchy_from_edges(vec![
            (Lang::Java, "UserRepo", "Repository"),
            (Lang::Java, "CacheRepo", "Repository"),
            (Lang::Java, "Derived", "Base"),
        ]);
        let mut subs: Vec<&str> = h
            .subs_of(Lang::Java, "Repository")
            .iter()
            .map(|s| s.as_str())
            .collect();
        subs.sort();
        assert_eq!(subs, vec!["CacheRepo", "UserRepo"]);
        assert_eq!(h.subs_of(Lang::Java, "Base"), &["Derived".to_string()]);
        assert_eq!(h.subs_of(Lang::Java, "Unknown"), &[] as &[String]);
        assert_eq!(h.super_keys_len(), 2);
    }

    /// B-2: Java interface dispatch, `Repository r; r.findById(...)`
    /// fans out to every concrete implementer's `findById`.
    #[test]
    fn b2_java_interface_dispatch_fans_out_to_all_impls() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let user_repo = make_method_summary("findById", "UserRepo", "src/UserRepo.java", "java", 1);
        let cache_repo =
            make_method_summary("findById", "CacheRepo", "src/CacheRepo.java", "java", 1);
        let mut iface_marker = make_method_summary(
            "__placeholder",
            "Repository",
            "src/Repository.java",
            "java",
            0,
        );
        iface_marker.hierarchy_edges = vec![
            ("UserRepo".to_string(), "Repository".to_string()),
            ("CacheRepo".to_string(), "Repository".to_string()),
        ];
        let caller = summary_with_sites(
            "lookup",
            "src/main.java",
            "java",
            0,
            vec![CalleeSite {
                name: "findById".into(),
                arity: Some(1),
                receiver: Some("r".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![user_repo, cache_repo, iface_marker, caller], None);
        let caller_key = FuncKey {
            lang: Lang::Java,
            namespace: "src/main.java".into(),
            name: "lookup".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Repository".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        let containers: Vec<&str> = targets.iter().map(|k| k.container.as_str()).collect();
        assert!(
            containers.contains(&"UserRepo") && containers.contains(&"CacheRepo"),
            "B-2: edges must reach BOTH UserRepo::findById and CacheRepo::findById; got {targets:?}"
        );
        assert_eq!(targets.len(), 2, "B-2: exactly two fan-out edges expected");
    }

    /// B-3: Java extends, `Base b; b.foo()` reaches Base AND Derived
    /// when Derived extends Base.  Pins inheritance fan-out separately
    /// from interface implements.
    #[test]
    fn b3_java_extends_fans_out_to_subclass() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let base = make_method_summary("foo", "Base", "src/Base.java", "java", 0);
        let mut derived = make_method_summary("foo", "Derived", "src/Derived.java", "java", 0);
        derived.hierarchy_edges = vec![("Derived".to_string(), "Base".to_string())];
        let caller = summary_with_sites(
            "go",
            "src/main.java",
            "java",
            0,
            vec![CalleeSite {
                name: "foo".into(),
                arity: Some(0),
                receiver: Some("b".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![base, derived, caller], None);
        let caller_key = FuncKey {
            lang: Lang::Java,
            namespace: "src/main.java".into(),
            name: "go".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Base".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        let containers: Vec<&str> = targets.iter().map(|k| k.container.as_str()).collect();
        assert!(
            containers.contains(&"Base"),
            "B-3: edge must reach Base::foo; got {targets:?}"
        );
        assert!(
            containers.contains(&"Derived"),
            "B-3: edge must reach Derived::foo; got {targets:?}"
        );
    }

    /// B-4: Rust trait dispatch, `Box<dyn Repo>; r.find(...)` reaches
    /// every `impl Repo for X` `find`.
    #[test]
    fn b4_rust_trait_dispatch_fans_out_to_impls() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let user_repo = make_method_summary("find", "UserRepo", "src/user_repo.rs", "rust", 1);
        let cache_repo = make_method_summary("find", "CacheRepo", "src/cache_repo.rs", "rust", 1);
        let mut hierarchy_carrier = make_method_summary("__h", "Repo", "src/repo.rs", "rust", 0);
        hierarchy_carrier.hierarchy_edges = vec![
            ("UserRepo".to_string(), "Repo".to_string()),
            ("CacheRepo".to_string(), "Repo".to_string()),
        ];
        let caller = summary_with_sites(
            "lookup",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "find".into(),
                arity: Some(1),
                receiver: Some("r".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![user_repo, cache_repo, hierarchy_carrier, caller], None);
        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "lookup".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Repo".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        let containers: Vec<&str> = targets.iter().map(|k| k.container.as_str()).collect();
        assert!(
            containers.contains(&"UserRepo") && containers.contains(&"CacheRepo"),
            "B-4: edges must fan out to both impls; got {targets:?}"
        );
    }

    /// B-7: Empty hierarchy, when the typed container has no recorded
    /// sub-types, `resolve_with_hierarchy` collapses to the direct
    /// `ClassMethodIndex::resolve` lookup.
    #[test]
    fn b7_empty_hierarchy_falls_back_to_single_container() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let repo = make_method_summary("findById", "Repository", "src/repo.rs", "rust", 1);
        let cache = make_method_summary("findById", "Cache", "src/cache.rs", "rust", 1);
        let caller = summary_with_sites(
            "lookup",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "findById".into(),
                arity: Some(1),
                receiver: Some("repo".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![repo, cache, caller], None);
        // No hierarchy_edges set anywhere, Repository has no
        // sub-types, so devirtualisation collapses to direct match.
        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "lookup".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Repository".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        assert_eq!(targets.len(), 1, "B-7: empty hierarchy → single edge");
        assert_eq!(targets[0].container, "Repository");
    }

    /// B-8: Concrete sub-type, when the receiver is typed as the
    /// concrete sub-class (not the super-type), no hierarchy
    /// expansion fires.
    #[test]
    fn b8_concrete_subtype_does_not_widen() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let user_repo = make_method_summary("findById", "UserRepo", "src/user_repo.rs", "rust", 1);
        let cache_repo =
            make_method_summary("findById", "CacheRepo", "src/cache_repo.rs", "rust", 1);
        let mut h = make_method_summary("__h", "Repo", "src/repo.rs", "rust", 0);
        h.hierarchy_edges = vec![
            ("UserRepo".to_string(), "Repo".to_string()),
            ("CacheRepo".to_string(), "Repo".to_string()),
        ];
        let caller = summary_with_sites(
            "lookup",
            "src/main.rs",
            "rust",
            0,
            vec![CalleeSite {
                name: "findById".into(),
                arity: Some(1),
                receiver: Some("r".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![user_repo, cache_repo, h, caller], None);
        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/main.rs".into(),
            name: "lookup".into(),
            arity: Some(0),
            ..Default::default()
        };
        // Caller types the receiver as `UserRepo` (concrete).
        // `subs_of(Lang::Rust, "UserRepo")` returns `[]` so the
        // hierarchy expansion is a no-op and only `UserRepo::findById`
        // is reached.
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "UserRepo".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        assert_eq!(
            targets.len(),
            1,
            "B-8: concrete sub-type must not fan out; got {targets:?}"
        );
        assert_eq!(targets[0].container, "UserRepo");
    }

    /// B-9: Diamond, multiple impls sharing a super-type, dedup
    /// applied per call site so each FuncKey is edged at most once.
    #[test]
    fn b9_diamond_dedup_one_edge_per_funckey() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let a = make_method_summary("doIt", "A", "src/A.java", "java", 0);
        let b = make_method_summary("doIt", "B", "src/B.java", "java", 0);
        // A and B both extend Iface in two separate file emissions ,
        // hierarchy_edges duplicates across files; dedup expected.
        let mut h1 = make_method_summary("__h", "Iface", "src/I1.java", "java", 0);
        h1.hierarchy_edges = vec![
            ("A".to_string(), "Iface".to_string()),
            ("B".to_string(), "Iface".to_string()),
        ];
        let mut h2 = make_method_summary("__h2", "Iface", "src/I2.java", "java", 0);
        h2.hierarchy_edges = vec![
            ("A".to_string(), "Iface".to_string()),
            ("B".to_string(), "Iface".to_string()),
        ];
        let caller = summary_with_sites(
            "go",
            "src/main.java",
            "java",
            0,
            vec![CalleeSite {
                name: "doIt".into(),
                arity: Some(0),
                receiver: Some("x".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![a, b, h1, h2, caller], None);
        let caller_key = FuncKey {
            lang: Lang::Java,
            namespace: "src/main.java".into(),
            name: "go".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Iface".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        // Each unique implementer reached at most once.
        let containers: std::collections::HashSet<&str> =
            targets.iter().map(|k| k.container.as_str()).collect();
        assert_eq!(
            containers.len(),
            targets.len(),
            "B-9: dedup must give one edge per FuncKey; got {targets:?}"
        );
        assert!(containers.contains("A") && containers.contains("B"));
    }

    /// B-13: Stale hierarchy edge, sub-type referenced by an edge
    /// no longer has a matching FuncKey.  Resolver must not panic
    /// and must still resolve to whatever IS present.
    #[test]
    fn b13_stale_subtype_no_panic() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        // `Base` exists; `Derived` referenced by hierarchy_edges but
        // its `foo` is never defined.  Resolver must not panic and
        // must still emit the Base::foo edge.
        let base = make_method_summary("foo", "Base", "src/Base.java", "java", 0);
        let mut h = make_method_summary("__h", "X", "src/X.java", "java", 0);
        h.hierarchy_edges = vec![("Derived".to_string(), "Base".to_string())];
        let caller = summary_with_sites(
            "go",
            "src/main.java",
            "java",
            0,
            vec![CalleeSite {
                name: "foo".into(),
                arity: Some(0),
                receiver: Some("b".into()),
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![base, h, caller], None);
        let caller_key = FuncKey {
            lang: Lang::Java,
            namespace: "src/main.java".into(),
            name: "go".into(),
            arity: Some(0),
            ..Default::default()
        };
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "Base".to_string())],
                ..Default::default()
            },
        );

        // Build must not panic.
        let cg = build_call_graph(&gs, &[]);
        let caller_node = cg.index[&caller_key];
        let targets: Vec<&FuncKey> = cg
            .graph
            .edges(caller_node)
            .map(|e| &cg.graph[e.target()])
            .collect();
        assert!(
            targets
                .iter()
                .any(|k| k.container == "Base" && k.name == "foo"),
            "B-13: stale Derived must not block Base::foo edge; got {targets:?}"
        );
    }

    /// Free-function calls (no receiver on the CalleeSite) must
    /// never trigger the devirtualisation path, even if some bogus
    /// typed_call_receivers entry happened to match the ordinal.
    /// Regression guard: today's namespace + use-map resolution
    /// stays in charge for free-function calls.
    #[test]
    fn typed_call_receivers_skips_free_function_sites() {
        use crate::summary::ssa_summary::SsaFuncSummary;

        let helper = make_summary("helper", "src/lib.rs", "rust", 0, vec![]);
        let caller = summary_with_sites(
            "main",
            "src/lib.rs",
            "rust",
            0,
            // No receiver on the call site → free function.
            vec![CalleeSite {
                name: "helper".into(),
                arity: Some(0),
                receiver: None,
                ordinal: 0,
                ..Default::default()
            }],
        );

        let mut gs = merge_summaries(vec![helper, caller], None);

        let caller_key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/lib.rs".into(),
            name: "main".into(),
            arity: Some(0),
            ..Default::default()
        };
        // A typed_call_receivers entry with ordinal=0, but since the
        // site has receiver=None, this MUST be ignored.
        gs.insert_ssa(
            caller_key.clone(),
            SsaFuncSummary {
                typed_call_receivers: vec![(0, "FakeContainer".to_string())],
                ..Default::default()
            },
        );

        let cg = build_call_graph(&gs, &[]);
        // Standard same-namespace resolution still finds `helper`.
        assert_eq!(cg.graph.edge_count(), 1);
        assert!(cg.unresolved_not_found.is_empty());
        assert!(cg.unresolved_ambiguous.is_empty());
    }
}

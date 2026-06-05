//! Framework adapter abstraction (Track L.0).
//!
//! Replaces the ad-hoc per-language route / `main` detection that was
//! scattered across [`crate::dynamic::lang`] sub-modules with a single
//! dispatching trait.  Every later phase in Track L plugs a concrete
//! adapter (Flask, Spring, Express, axum, …) into this trait.
//!
//! # Determinism
//!
//! [`detect_binding`] iterates the per-language adapter slice returned
//! by [`registry::adapters_for`] in registration order and returns the
//! first non-`None` match.  The registration order is fixed at
//! compile time and kept sorted by [`FrameworkAdapter::name`] so a
//! phase that adds a new adapter cannot silently re-order an existing
//! match.

pub mod adapters;
pub mod auth_markers;
pub mod registry;
pub mod runtime_deps;

use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Small project-file index exposed to framework adapters that need
/// config files outside the entry source.
///
/// Keys are project-relative paths using `/` separators, for example
/// `config/routes.rb` or `routes/web.php`. Values are raw file bytes.
/// The index is intentionally narrow: callers decide which config
/// files to load so adapter dispatch does not walk the whole project.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProjectFileIndex {
    files: BTreeMap<String, Vec<u8>>,
}

impl ProjectFileIndex {
    /// Create an empty file index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from a project root and a fixed list of
    /// project-relative paths. Missing or unreadable files are skipped.
    pub fn from_root(root: &Path, rel_paths: &[&str]) -> Self {
        let mut index = Self::new();
        for rel in rel_paths {
            let path = root.join(rel);
            if let Ok(bytes) = std::fs::read(&path) {
                index.insert(*rel, bytes);
            }
        }
        index
    }

    /// Add files under each project-relative directory when their
    /// extension matches `extensions`. Missing directories are skipped.
    pub fn include_dirs(mut self, root: &Path, rel_dirs: &[&str], extensions: &[&str]) -> Self {
        for rel_dir in rel_dirs {
            let dir = root.join(rel_dir);
            self.insert_matching_files(root, &dir, extensions, 0);
        }
        self
    }

    /// Insert or replace a project-relative file.
    pub fn insert(&mut self, rel_path: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.files
            .insert(normalize_project_rel(rel_path), bytes.into());
    }

    /// Return bytes for `rel_path` when present.
    pub fn get(&self, rel_path: &str) -> Option<&[u8]> {
        self.files
            .get(&normalize_project_rel(rel_path))
            .map(Vec::as_slice)
    }

    /// Iterate project-relative file paths and raw bytes.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// True when the index has no files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    fn insert_matching_files(
        &mut self,
        root: &Path,
        dir: &Path,
        extensions: &[&str],
        depth: usize,
    ) {
        const MAX_DEPTH: usize = 4;
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                self.insert_matching_files(root, &path, extensions, depth + 1);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if !extensions.iter().any(|want| ext.eq_ignore_ascii_case(want)) {
                continue;
            }
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let Some(rel) = rel.to_str() else {
                continue;
            };
            if let Ok(bytes) = std::fs::read(&path) {
                self.insert(rel, bytes);
            }
        }
    }
}

fn normalize_project_rel(rel_path: impl Into<String>) -> String {
    rel_path.into().replace('\\', "/")
}

/// Extra context supplied to framework adapters during detection.
#[derive(Debug, Clone, Copy)]
pub struct FrameworkDetectionContext<'a> {
    /// Optional SSA summary for receiver-type-aware narrowing.
    pub ssa_summary: Option<&'a SsaFuncSummary>,
    /// Project config files known to the caller.
    pub project_files: &'a ProjectFileIndex,
}

/// HTTP method recognised by route bindings.  Mirrors
/// [`crate::entry_points::HttpMethod`] but is re-declared here so the
/// framework module does not pull in the static-analysis entry-point
/// types in callers that only need the dynamic-side shape.
pub use crate::entry_points::HttpMethod;

/// HTTP route shape extracted from a framework binding (path +
/// method).  Only populated when [`FrameworkBinding::kind`] is
/// [`EntryKind::HttpRoute`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteShape {
    /// HTTP verb (`GET`, `POST`, …).
    pub method: HttpMethod,
    /// Additional HTTP verbs that reach the same handler.  Empty for
    /// single-verb routes; when populated, [`Self::method`] is the
    /// first element for backward-compatible callers that still need a
    /// single representative method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<HttpMethod>,
    /// Route path template as registered with the framework (e.g.
    /// `"/users/{id}"`).  Adapter-specific placeholder syntax is
    /// preserved verbatim.
    pub path: String,
}

impl RouteShape {
    /// Construct a single-method route while preserving the legacy
    /// empty-`methods` representation.
    pub fn single(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            methods: Vec::new(),
            path: path.into(),
        }
    }

    /// Construct a route reachable through multiple HTTP methods.
    pub fn multi(methods: Vec<HttpMethod>, path: impl Into<String>) -> Self {
        let mut deduped = Vec::new();
        for method in methods {
            if !deduped.contains(&method) {
                deduped.push(method);
            }
        }
        let method = deduped.first().copied().unwrap_or(HttpMethod::GET);
        Self {
            method,
            methods: deduped,
            path: path.into(),
        }
    }

    /// Return every method that reaches this route.  Legacy single-method
    /// shapes return a one-element vector containing [`Self::method`].
    pub fn reachable_methods(&self) -> Vec<HttpMethod> {
        if self.methods.is_empty() {
            vec![self.method]
        } else {
            self.methods.clone()
        }
    }
}

/// Where on the external surface a function formal originates from.
///
/// Adapters classify each declared parameter into one of these
/// buckets so downstream harness emitters know which request field
/// carries the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamSource {
    /// URL path placeholder (e.g. `/users/{id}` → `id`).
    PathSegment(String),
    /// URL query string parameter.
    QueryParam(String),
    /// HTTP request header.
    Header(String),
    /// JSON request body (deserialised whole).
    JsonBody,
    /// HTML form field.
    FormField(String),
    /// HTTP cookie.
    Cookie(String),
    /// Implicit context object (e.g. `*gin.Context`, `HttpRequest`).
    /// Not adversary-controlled directly; included so the binding
    /// captures every formal position.
    Implicit,
}

/// Binding between a function formal and its external request slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamBinding {
    /// 0-based position in [`FuncSummary::param_names`].
    pub index: usize,
    /// Declared parameter name (mirrors
    /// `summary.param_names[index]`).
    pub name: String,
    /// External slot this parameter is wired to.
    pub source: ParamSource,
}

/// Shape of how the handler writes a response.  Track L plans to use
/// this to pick the right oracle (HTML render → XSS, JSON → no-op,
/// redirect → open-redirect).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseShape {
    /// Response media kind.
    pub kind: ResponseKind,
}

/// Coarse classification of a response writer's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Json,
    Html,
    Text,
    Redirect,
    Stream,
}

/// Middleware attached to a route (auth filter, CSRF guard,
/// before-action, decorator chain, …).  Adapters record the name so
/// later phases can classify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiddlewareShape {
    /// Adapter-local middleware identifier (e.g. `"login_required"`,
    /// `"@PreAuthorize"`, `"csrf"`).
    pub name: String,
}

/// Full framework binding for a function: every detail about how an
/// external surface reaches the function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkBinding {
    /// Stable id of the adapter that produced this binding.  Equal to
    /// the originating [`FrameworkAdapter::name`].  Persisted into
    /// trace details verbatim.
    pub adapter: String,
    /// Entry-surface taxonomy bucket this function falls into.
    pub kind: EntryKind,
    /// HTTP route shape when [`Self::kind`] is
    /// [`EntryKind::HttpRoute`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteShape>,
    /// Per-formal external-slot classification.  May be empty if the
    /// adapter does not yet model parameter shapes (e.g. a Phase-01
    /// stub).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_params: Vec<ParamBinding>,
    /// Response writer shape, when the adapter can determine it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_writer: Option<ResponseShape>,
    /// Middleware chain attached to the route, in declaration order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub middleware: Vec<MiddlewareShape>,
}

/// Per-framework adapter trait.  Each implementation inspects a
/// function (via its [`FuncSummary`] and the file's AST root) and
/// decides whether the function is bound to an external entry
/// surface.
///
/// Implementations live next to the per-language harness emitters in
/// [`crate::dynamic::lang`] and register into [`registry::adapters_for`]
/// in subsequent Track-L phases.  Phase 01 ships the trait and an
/// empty registry per language.
pub trait FrameworkAdapter: Sync {
    /// Stable adapter id (e.g. `"flask"`, `"spring-mvc"`, `"axum"`).
    /// Used for deterministic ordering inside the registry and for
    /// the trace-event detail string emitted by the verifier.
    fn name(&self) -> &'static str;

    /// Runtime package-manager dependencies needed when a real harness
    /// loads code matched by this adapter.
    ///
    /// Most adapters need no extra metadata because the entry source's
    /// imports are enough for dependency capture.  Adapters that can bind
    /// from route files, annotations, or marker comments use the central
    /// adapter-id registry so manifest synthesis can still install the
    /// actual framework library before execution.
    fn runtime_dependencies(&self) -> runtime_deps::FrameworkRuntimeDeps {
        runtime_deps::deps_for_adapter(self.name())
    }

    /// Language this adapter targets.
    fn lang(&self) -> Lang;

    /// Inspect a function and return its [`FrameworkBinding`] when
    /// the function is driven by this adapter, otherwise `None`.
    ///
    /// `ast` is the file's tree-sitter root node and `file_bytes` is
    /// the raw source so adapters can re-walk for decorators,
    /// routing macros, or registration sites that the
    /// [`FuncSummary`] alone does not preserve.
    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding>;

    /// Detection variant that also receives the function's
    /// [`SsaFuncSummary`] when one is available on the caller side.
    ///
    /// The SSA summary carries per-call-site receiver-type info via
    /// [`SsaFuncSummary::typed_call_receivers`], which adapters can
    /// use to discriminate permissive callee-name matches (e.g.
    /// distinguishing `gin.Engine::Get` from `cache.Get`).  The
    /// default implementation ignores the SSA input and delegates to
    /// [`Self::detect`], so existing adapters keep working unchanged.
    /// Adapters that want receiver-type-aware FP narrowing override
    /// this method and consult the SSA summary directly.
    ///
    /// Callers without an SSA summary in hand (most test paths,
    /// pre-pass-1 callers) pass `None` here.
    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        _ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        self.detect(summary, ast, file_bytes)
    }

    /// Detection variant with all optional framework context bundled
    /// into a single struct. Adapters that need project-level route
    /// files override this method; the default delegates to the
    /// SSA-aware legacy method so existing adapters keep their current
    /// behaviour.
    fn detect_with_project_context(
        &self,
        summary: &FuncSummary,
        context: FrameworkDetectionContext<'_>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        self.detect_with_context(summary, context.ssa_summary, ast, file_bytes)
    }
}

/// Walk every adapter registered for `lang` in registration order
/// and return the first non-`None` binding.  Returns `None` when no
/// adapter matches or when no adapters are registered for `lang`.
pub fn detect_binding(
    summary: &FuncSummary,
    ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
    lang: Lang,
) -> Option<FrameworkBinding> {
    detect_binding_with_context(summary, None, ast, file_bytes, lang)
}

/// SSA-aware sibling of [`detect_binding`].
///
/// Threads an `Option<&SsaFuncSummary>` through to every adapter's
/// [`FrameworkAdapter::detect_with_context`] so adapters can
/// consume receiver-type facts when available.  Callers without an
/// SSA summary in hand pass `None`, at which point this function is
/// behaviourally identical to [`detect_binding`] (adapters' default
/// `detect_with_context` delegates to `detect`).
pub fn detect_binding_with_context(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
    lang: Lang,
) -> Option<FrameworkBinding> {
    let project_files = ProjectFileIndex::new();
    let context = FrameworkDetectionContext {
        ssa_summary,
        project_files: &project_files,
    };
    detect_binding_with_project_context(summary, context, ast, file_bytes, lang)
}

/// Full-context sibling of [`detect_binding_with_context`].
///
/// This is the entry point used by spec derivation once it has a
/// project root available. Test callers and single-file callers can
/// keep using [`detect_binding`] / [`detect_binding_with_context`].
pub fn detect_binding_with_project_context(
    summary: &FuncSummary,
    context: FrameworkDetectionContext<'_>,
    ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
    lang: Lang,
) -> Option<FrameworkBinding> {
    for adapter in registry::adapters_for(lang) {
        debug_assert_eq!(
            adapter.lang(),
            lang,
            "adapter '{}' registered under wrong lang",
            adapter.name()
        );
        if let Some(binding) =
            adapter.detect_with_project_context(summary, context, ast, file_bytes)
        {
            return Some(binding);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::FuncSummary;

    fn synth_summary(name: &str, lang: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: "tests/synthetic.rs".into(),
            lang: lang.into(),
            ..Default::default()
        }
    }

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn registry_baseline_after_phase_21() {
        // Phase 21 (Track M.3) adds the remaining five `EntryKind`
        // variants — `ScheduledJob` / `GraphQLResolver` / `WebSocket`
        // / `Middleware` / `Migration` — distributed across the
        // language slices.  Per-lang deltas vs the Phase 20 baseline:
        //   Java: +2 (ScheduledQuartz, MiddlewareSpring)        14 → 16
        //         +1 follow-up (MigrationFlyway)                16 → 17
        //   Php:  +2 (MiddlewareLaravel, MigrationLaravel)      10 → 12
        //   Python: +7 (GraphqlGraphene, MiddlewareDjango,
        //              MigrationDjango, MigrationFlask,
        //              ScheduledCelery, WebsocketChannels,
        //              WebsocketSocketIo)                       15 → 22
        //   Ruby: +4 (MiddlewareRails, MigrationRails,
        //              ScheduledSidekiq, WebsocketActionCable)   8 → 12
        //   JavaScript: +7 (GraphqlApollo, GraphqlRelay,
        //              MiddlewareExpress, MigrationPrisma,
        //              MigrationSequelize, ScheduledCron,
        //              WebsocketWs)                            12 → 19
        //   Go: +1 (GraphqlGqlgen)                              9 → 10
        //   Rust: +1 (GraphqlJuniper)                           6 → 7
        // TypeScript / C / Cpp stay unchanged.
        //
        // Track L.9 starter slice (Phase 11 follow-up): adds per-cap
        // adapters for `Cap::CRYPTO` (Python / Java / JavaScript)
        // and `Cap::DATA_EXFIL` (Python / JavaScript / Go).
        //   Java: +1 (CryptoJava)                              18 → 19
        //   Python: +2 (CryptoPython, DataExfilPython)         22 → 24
        //   JavaScript: +2 (CryptoJs, DataExfilJs)             20 → 22
        //   Go: +1 (DataExfilGo)                               11 → 12
        // Track L.9 follow-up slice (session-0015 of run 7d60):
        // CRYPTO × {Php, Ruby} + DATA_EXFIL × Ruby.
        //   Php: +1 (CryptoPhp)                                12 → 13
        //   Ruby: +2 (CryptoRuby, DataExfilRuby)               12 → 14
        // Track L.9 closing slice (session-0017 of run 7d60):
        // CRYPTO × {Go, Rust} + DATA_EXFIL × {Java, Php, Rust}.
        //   Go: +1 (CryptoGo)                                  12 → 13
        //   Java: +1 (DataExfilJava)                           19 → 20
        //   Php: +1 (DataExfilPhp)                             13 → 14
        //   Rust: +2 (CryptoRust, DataExfilRust)                8 → 10
        let java_registered = registry::adapters_for(Lang::Java);
        assert_eq!(
            java_registered.len(),
            20,
            "Java must have Phase 21 baseline (18) + Track L.9 (CryptoJava, DataExfilJava)",
        );
        for adapter in java_registered {
            assert_eq!(adapter.lang(), Lang::Java);
        }
        let php_registered = registry::adapters_for(Lang::Php);
        assert_eq!(
            php_registered.len(),
            14,
            "Php must have Phase 20 baseline (10) + M.3 Laravel middleware+migration (2) + Track L.9 (CryptoPhp, DataExfilPhp)",
        );
        for adapter in php_registered {
            assert_eq!(adapter.lang(), Lang::Php);
        }
        let python_registered = registry::adapters_for(Lang::Python);
        assert_eq!(
            python_registered.len(),
            24,
            "Python must have Phase 21 baseline (22) + Track L.9 (CryptoPython, DataExfilPython)",
        );
        for adapter in python_registered {
            assert_eq!(adapter.lang(), Lang::Python);
        }
        let ruby_registered = registry::adapters_for(Lang::Ruby);
        assert_eq!(
            ruby_registered.len(),
            14,
            "Ruby must have Phase 20 baseline (8) + M.3 Phase-21 (4) + Track L.9 (CryptoRuby, DataExfilRuby)",
        );
        for adapter in ruby_registered {
            assert_eq!(adapter.lang(), Lang::Ruby);
        }
        let js_registered = registry::adapters_for(Lang::JavaScript);
        assert_eq!(
            js_registered.len(),
            22,
            "JavaScript must have Phase 21 baseline (20) + Track L.9 (CryptoJs, DataExfilJs)",
        );
        for adapter in js_registered {
            assert_eq!(adapter.lang(), Lang::JavaScript);
        }
        let ts_registered = registry::adapters_for(Lang::TypeScript);
        assert_eq!(
            ts_registered.len(),
            4,
            "TypeScript stays at Phase 20 baseline (4)",
        );
        for adapter in ts_registered {
            assert_eq!(adapter.lang(), Lang::TypeScript);
        }
        let go_registered = registry::adapters_for(Lang::Go);
        assert_eq!(
            go_registered.len(),
            13,
            "Go must have Phase 21 baseline (11) + Track L.9 (CryptoGo, DataExfilGo)",
        );
        for adapter in go_registered {
            assert_eq!(adapter.lang(), Lang::Go);
        }
        let rust_registered = registry::adapters_for(Lang::Rust);
        assert_eq!(
            rust_registered.len(),
            11,
            "Rust must have Phase 20 baseline (6) + M.3 juniper/refinery/sqlx (3) + Track L.9 (CryptoRust, DataExfilRust)",
        );
        for adapter in rust_registered {
            assert_eq!(adapter.lang(), Lang::Rust);
        }
        for lang in [Lang::C, Lang::Cpp] {
            assert!(
                registry::adapters_for(lang).is_empty(),
                "{:?} should still have zero adapters before its Track-L phase",
                lang,
            );
        }
    }

    #[test]
    fn detect_binding_returns_none_with_empty_registry() {
        // Empty registry means `detect_binding` short-circuits to
        // `None` for every input regardless of summary content.
        let summary = synth_summary("handler", "python");
        let src: &[u8] = b"def handler():\n    pass\n";
        let tree = parse_python(src);
        let binding = detect_binding(&summary, tree.root_node(), src, Lang::Python);
        assert!(binding.is_none());
    }

    /// Adapter that overrides the SSA-aware variant only.  Returns a
    /// binding whose `adapter` field encodes whether the SSA summary
    /// was visible (`"with-ssa"` vs `"no-ssa"`).
    struct SsaProbingAdapter;
    impl FrameworkAdapter for SsaProbingAdapter {
        fn name(&self) -> &'static str {
            "ssa-probe"
        }
        fn lang(&self) -> Lang {
            Lang::Python
        }
        fn detect(
            &self,
            _summary: &FuncSummary,
            _ast: tree_sitter::Node<'_>,
            _file_bytes: &[u8],
        ) -> Option<FrameworkBinding> {
            None
        }
        fn detect_with_context(
            &self,
            _summary: &FuncSummary,
            ssa: Option<&SsaFuncSummary>,
            _ast: tree_sitter::Node<'_>,
            _file_bytes: &[u8],
        ) -> Option<FrameworkBinding> {
            let tag = if ssa.is_some() { "with-ssa" } else { "no-ssa" };
            Some(FrameworkBinding {
                adapter: tag.into(),
                kind: EntryKind::HttpRoute,
                route: None,
                request_params: vec![],
                response_writer: None,
                middleware: vec![],
            })
        }
    }

    /// Adapter that only overrides `detect` and relies on the
    /// trait's default `detect_with_context` to delegate.  Used to
    /// pin the additive-by-default contract: callers passing an SSA
    /// summary still reach the legacy `detect` path on adapters that
    /// have not been upgraded.
    struct LegacyDetectOnlyAdapter;
    impl FrameworkAdapter for LegacyDetectOnlyAdapter {
        fn name(&self) -> &'static str {
            "legacy"
        }
        fn lang(&self) -> Lang {
            Lang::Python
        }
        fn detect(
            &self,
            summary: &FuncSummary,
            _ast: tree_sitter::Node<'_>,
            _file_bytes: &[u8],
        ) -> Option<FrameworkBinding> {
            Some(FrameworkBinding {
                adapter: format!("legacy:{}", summary.name),
                kind: EntryKind::HttpRoute,
                route: None,
                request_params: vec![],
                response_writer: None,
                middleware: vec![],
            })
        }
    }

    #[test]
    fn detect_with_context_default_impl_delegates_to_detect() {
        // A legacy adapter that only implements `detect` must still
        // produce a binding when reached via the SSA-aware entry
        // point, with or without an SSA summary in hand.
        let summary = synth_summary("handler", "python");
        let src: &[u8] = b"def handler():\n    pass\n";
        let tree = parse_python(src);
        let adapter = LegacyDetectOnlyAdapter;

        let no_ssa = adapter.detect_with_context(&summary, None, tree.root_node(), src);
        assert_eq!(
            no_ssa.as_ref().map(|b| b.adapter.as_str()),
            Some("legacy:handler")
        );

        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Repository".to_string()));
        let with_ssa = adapter.detect_with_context(&summary, Some(&ssa), tree.root_node(), src);
        // Default impl ignores the SSA summary, so both calls produce
        // the same binding identity.
        assert_eq!(with_ssa, no_ssa);
    }

    #[test]
    fn detect_with_context_lets_adapter_observe_ssa_summary() {
        // An adapter that overrides `detect_with_context` sees the
        // SSA summary handed in by the caller.
        let summary = synth_summary("handler", "python");
        let src: &[u8] = b"def handler():\n    pass\n";
        let tree = parse_python(src);
        let adapter = SsaProbingAdapter;

        let no_ssa = adapter.detect_with_context(&summary, None, tree.root_node(), src);
        assert_eq!(no_ssa.as_ref().map(|b| b.adapter.as_str()), Some("no-ssa"));

        let ssa = SsaFuncSummary::default();
        let with_ssa = adapter.detect_with_context(&summary, Some(&ssa), tree.root_node(), src);
        assert_eq!(
            with_ssa.as_ref().map(|b| b.adapter.as_str()),
            Some("with-ssa")
        );
    }

    #[test]
    fn detect_binding_function_uses_legacy_detect_path() {
        // The bare `detect_binding` entry point must keep working
        // for every existing test in the tree — empty registry
        // means no binding regardless of how it dispatches.
        let summary = synth_summary("handler", "python");
        let src: &[u8] = b"def handler():\n    pass\n";
        let tree = parse_python(src);
        let binding = detect_binding(&summary, tree.root_node(), src, Lang::Python);
        assert!(binding.is_none());
    }

    #[test]
    fn detect_binding_with_context_function_accepts_none() {
        // Passing `None` for the SSA summary is behaviourally
        // identical to calling `detect_binding`.
        let summary = synth_summary("handler", "python");
        let src: &[u8] = b"def handler():\n    pass\n";
        let tree = parse_python(src);
        let binding =
            detect_binding_with_context(&summary, None, tree.root_node(), src, Lang::Python);
        assert!(binding.is_none());
    }

    #[test]
    fn framework_binding_round_trips_through_serde() {
        // The binding is persisted into repro bundles; ensure every
        // field round-trips.
        let original = FrameworkBinding {
            adapter: "flask".into(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(HttpMethod::POST, "/users/{id}")),
            request_params: vec![ParamBinding {
                index: 0,
                name: "id".into(),
                source: ParamSource::PathSegment("id".into()),
            }],
            response_writer: Some(ResponseShape {
                kind: ResponseKind::Json,
            }),
            middleware: vec![MiddlewareShape {
                name: "login_required".into(),
            }],
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: FrameworkBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }
}

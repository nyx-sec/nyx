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
pub mod registry;

use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};

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
    /// Route path template as registered with the framework (e.g.
    /// `"/users/{id}"`).  Adapter-specific placeholder syntax is
    /// preserved verbatim.
    pub path: String,
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
    for adapter in registry::adapters_for(lang) {
        debug_assert_eq!(
            adapter.lang(),
            lang,
            "adapter '{}' registered under wrong lang",
            adapter.name()
        );
        if let Some(binding) = adapter.detect(summary, ast, file_bytes) {
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
    fn registry_baseline_after_phase_07() {
        // Phase 07 (Track J.5) adds the XPath-sink adapter for Java /
        // Python / PHP / JavaScript, layered on top of the Phase 03
        // deserialize + Phase 04 SSTI + Phase 05 XXE + Phase 06 LDAP
        // adapters.  Java / Python / PHP each grow from 4 → 5; the
        // JavaScript slice grows from 1 (Handlebars only) → 2.  Ruby
        // still carries the 03+04+05 trio (no Ruby LDAP adapter); Go
        // still has only the XXE adapter; Rust / C / Cpp / TypeScript
        // still carry the Phase-01 empty baseline.
        for lang in [Lang::Java, Lang::Python, Lang::Php] {
            let registered = registry::adapters_for(lang);
            assert_eq!(
                registered.len(),
                5,
                "{:?} must have the J.1 deserialize + J.2 ssti + J.3 xxe + J.4 ldap + J.5 xpath adapters",
                lang,
            );
            for adapter in registered {
                assert_eq!(adapter.lang(), lang);
            }
        }
        let ruby_registered = registry::adapters_for(Lang::Ruby);
        assert_eq!(
            ruby_registered.len(),
            3,
            "Ruby must still carry the J.1 deserialize + J.2 ssti + J.3 xxe adapters",
        );
        for adapter in ruby_registered {
            assert_eq!(adapter.lang(), Lang::Ruby);
        }
        let js_registered = registry::adapters_for(Lang::JavaScript);
        assert_eq!(
            js_registered.len(),
            2,
            "JavaScript must have the J.2 Handlebars + J.5 xpath-js adapters",
        );
        for adapter in js_registered {
            assert_eq!(adapter.lang(), Lang::JavaScript);
        }
        let go_registered = registry::adapters_for(Lang::Go);
        assert_eq!(
            go_registered.len(),
            1,
            "Go must have exactly the J.3 xxe-go adapter",
        );
        assert_eq!(go_registered[0].lang(), Lang::Go);
        for lang in [Lang::Rust, Lang::C, Lang::Cpp, Lang::TypeScript] {
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

    #[test]
    fn framework_binding_round_trips_through_serde() {
        // The binding is persisted into repro bundles; ensure every
        // field round-trips.
        let original = FrameworkBinding {
            adapter: "flask".into(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape {
                method: HttpMethod::POST,
                path: "/users/{id}".into(),
            }),
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

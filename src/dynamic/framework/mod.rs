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
    fn registry_baseline_after_phase_17() {
        // Phase 17 (Track L.15) adds four Go framework adapters
        // (`go-chi`, `go-echo`, `go-fiber`, `go-gin`) to the Go
        // slice, growing it 3 → 7, plus four Rust framework adapters
        // (`rust-actix`, `rust-axum`, `rust-rocket`, `rust-warp`)
        // growing the Rust slice 2 → 6.  The Phase 16 baseline for
        // the other languages stays put: Java 11, Php 10, Python 11,
        // Ruby 8, JavaScript 11, TypeScript 4.  C / Cpp stay empty.
        let java_registered = registry::adapters_for(Lang::Java);
        assert_eq!(
            java_registered.len(),
            11,
            "Java must have J.1+J.2+J.3+J.4+J.5+J.6+J.7 (7) + L.12 Spring/Quarkus/Micronaut/Servlet (4)",
        );
        for adapter in java_registered {
            assert_eq!(adapter.lang(), Lang::Java);
        }
        let php_registered = registry::adapters_for(Lang::Php);
        assert_eq!(
            php_registered.len(),
            10,
            "Php must have J.1..J.7 (7) + L.14 Laravel/Symfony/CodeIgniter (3) adapters",
        );
        for adapter in php_registered {
            assert_eq!(adapter.lang(), Lang::Php);
        }
        let python_registered = registry::adapters_for(Lang::Python);
        assert_eq!(
            python_registered.len(),
            11,
            "Python must have J.1..J.7 (7) + L.10 Flask/Django/FastAPI/Starlette (4)",
        );
        for adapter in python_registered {
            assert_eq!(adapter.lang(), Lang::Python);
        }
        let ruby_registered = registry::adapters_for(Lang::Ruby);
        assert_eq!(
            ruby_registered.len(),
            8,
            "Ruby must have the J.1 + J.2 + J.3 + J.6 + J.7 (5) + L.13 Rails/Sinatra/Hanami (3) adapters",
        );
        for adapter in ruby_registered {
            assert_eq!(adapter.lang(), Lang::Ruby);
        }
        let js_registered = registry::adapters_for(Lang::JavaScript);
        assert_eq!(
            js_registered.len(),
            11,
            "JavaScript must have J.2 + J.5 + J.6 + J.7 + J.8(×3) + L.11(×4) adapters",
        );
        for adapter in js_registered {
            assert_eq!(adapter.lang(), Lang::JavaScript);
        }
        let ts_registered = registry::adapters_for(Lang::TypeScript);
        assert_eq!(
            ts_registered.len(),
            4,
            "TypeScript must have the J.8(×3) prototype-pollution adapters + L.11 ts-nest",
        );
        for adapter in ts_registered {
            assert_eq!(adapter.lang(), Lang::TypeScript);
        }
        let go_registered = registry::adapters_for(Lang::Go);
        assert_eq!(
            go_registered.len(),
            7,
            "Go must have J.3 + J.6 + J.7 (3) + L.15 chi/echo/fiber/gin (4) adapters",
        );
        for adapter in go_registered {
            assert_eq!(adapter.lang(), Lang::Go);
        }
        let rust_registered = registry::adapters_for(Lang::Rust);
        assert_eq!(
            rust_registered.len(),
            6,
            "Rust must have the J.6 + J.7 (2) + L.15 actix/axum/rocket/warp (4) adapters",
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

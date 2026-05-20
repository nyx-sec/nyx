//! Axum [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises the canonical axum route builder:
//!
//! ```rust
//! let app = Router::new()
//!     .route("/users/{id}", get(show))
//!     .route("/save", post(save));
//! ```
//!
//! The adapter binds the route to the function whose name matches
//! `summary.name`.  Both the lowercase `get(handler)` helper and the
//! scoped `axum::routing::get(handler)` form are accepted.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::rust_routes::{
    bind_rust_path_params, find_axum_route, find_rust_function, rust_formal_names,
    source_imports_axum,
};

pub struct RustAxumAdapter;

const ADAPTER_NAME: &str = "rust-axum";

impl FrameworkAdapter for RustAxumAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Rust
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_axum(file_bytes) {
            return None;
        }
        let (method, path) = find_axum_route(ast, file_bytes, &summary.name)?;
        let request_params = find_rust_function(ast, file_bytes, &summary.name)
            .map(|func| {
                let formals = rust_formal_names(func, file_bytes);
                bind_rust_path_params(&formals, &path)
            })
            .unwrap_or_default();
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape { method, path }),
            request_params,
            response_writer: None,
            middleware: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::{HttpMethod, ParamSource};

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "rust".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_get_handler() {
        let src: &[u8] = b"use axum::Router;\nfn build() -> Router { Router::new().route(\"/u/{id}\", get(show)) }\nfn show(id: String) -> String { id }\n";
        let tree = parse(src);
        let binding = RustAxumAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "rust-axum");
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/u/{id}");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_scoped_post_handler() {
        let src: &[u8] = b"use axum::Router;\nfn build() -> Router { Router::new().route(\"/save\", axum::routing::post(save)) }\nfn save(body: String) {}\n";
        let tree = parse(src);
        let binding = RustAxumAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn skips_when_axum_not_imported() {
        let src: &[u8] = b"fn show() {}\n";
        let tree = parse(src);
        assert!(RustAxumAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_route_does_not_reference_function() {
        let src: &[u8] = b"use axum::Router;\nfn build() -> Router { Router::new().route(\"/u\", get(show)) }\nfn helper() {}\n";
        let tree = parse(src);
        assert!(RustAxumAdapter
            .detect(&summary("helper"), tree.root_node(), src)
            .is_none());
    }
}

//! Warp [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises warp's `warp::path!(...)` macro chained with `.map(...)`
//! or `.and_then(...)` to bridge into a handler function:
//!
//! ```rust
//! let r = warp::path!("users" / u32)
//!     .and(warp::get())
//!     .map(show);
//! ```
//!
//! Warp's path DSL embeds typed segments as positional placeholders;
//! the adapter reconstructs a brace-style path template
//! (`/users/{u32}`) and binds formals positionally via the per-arg
//! name in the handler's signature.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::rust_routes::{
    bind_rust_path_params, collect_rust_middleware, find_rust_function, find_warp_route,
    rust_formal_names, source_imports_warp,
};

pub struct RustWarpAdapter;

const ADAPTER_NAME: &str = "rust-warp";

impl FrameworkAdapter for RustWarpAdapter {
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
        if !source_imports_warp(file_bytes) {
            return None;
        }
        let (method, path) = find_warp_route(ast, file_bytes, &summary.name)?;
        let request_params = find_rust_function(ast, file_bytes, &summary.name)
            .map(|func| {
                let formals = rust_formal_names(func, file_bytes);
                bind_rust_path_params(&formals, &path)
            })
            .unwrap_or_default();
        let middleware = collect_rust_middleware(ast, file_bytes);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape { method, path }),
            request_params,
            response_writer: None,
            middleware,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::HttpMethod;

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
    fn fires_on_path_macro_with_map_target() {
        let src: &[u8] = b"use warp::Filter;\nfn build() { let r = warp::path!(\"users\" / u32).map(show); }\nfn show(id: u32) -> String { String::new() }\n";
        let tree = parse(src);
        let binding = RustWarpAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "rust-warp");
        let route = binding.route.expect("route");
        assert!(route.path.contains("users"));
        assert_eq!(route.method, HttpMethod::GET);
    }

    #[test]
    fn fires_on_path_macro_with_and_then_target() {
        let src: &[u8] = b"use warp::Filter;\nfn build() { let r = warp::path!(\"x\").and_then(handle); }\nasync fn handle() -> Result<&'static str, warp::Rejection> { Ok(\"ok\") }\n";
        let tree = parse(src);
        let binding = RustWarpAdapter
            .detect(&summary("handle"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.route.unwrap().path.contains("x"));
    }

    #[test]
    fn populates_middleware_from_and_filter() {
        let src: &[u8] = b"use warp::Filter;\nfn build() { let r = warp::path!(\"x\" / u32).and(BearerAuth).map(show); }\nfn show(id: u32) -> String { String::new() }\n";
        let tree = parse(src);
        let binding = RustWarpAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.middleware.len(), 1);
        assert_eq!(binding.middleware[0].name, "BearerAuth");
    }

    #[test]
    fn skips_when_warp_not_imported() {
        let src: &[u8] = b"fn show() {}\n";
        let tree = parse(src);
        assert!(
            RustWarpAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_no_path_macro() {
        let src: &[u8] = b"use warp::Filter;\nfn show() {}\n";
        let tree = parse(src);
        assert!(
            RustWarpAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }
}

//! Actix-web [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises actix's `#[get("/path")]` / `#[post("/path")]`
//! attribute macros on handler functions:
//!
//! ```rust
//! #[get("/users/{id}")]
//! async fn show(id: web::Path<String>) -> impl Responder { id }
//! ```
//!
//! The adapter walks the attribute_items immediately preceding the
//! `function_item` named `summary.name`, picks up the verb leaf
//! (`get` / `post` / ...) and the first string-literal argument.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::rust_routes::{
    bind_rust_path_params, collect_rust_middleware, find_actix_route_chain, find_method_attribute,
    find_rust_function, rust_formal_names, source_imports_actix,
};

pub struct RustActixAdapter;

const ADAPTER_NAME: &str = "rust-actix";

impl FrameworkAdapter for RustActixAdapter {
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
        if !source_imports_actix(file_bytes) {
            return None;
        }
        let func = find_rust_function(ast, file_bytes, &summary.name)?;
        let (method, path) = find_method_attribute(func, file_bytes)
            .or_else(|| find_actix_route_chain(ast, file_bytes, &summary.name))?;
        let formals = rust_formal_names(func, file_bytes);
        let request_params = bind_rust_path_params(&formals, &path);
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
    fn fires_on_get_attribute() {
        let src: &[u8] = b"use actix_web::get;\n#[get(\"/u/{id}\")]\nasync fn show(id: String) -> String { id }\n";
        let tree = parse(src);
        let binding = RustActixAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "rust-actix");
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
    fn fires_on_post_attribute() {
        let src: &[u8] = b"use actix_web::post;\n#[post(\"/save\")]\nasync fn save(body: String) -> String { body }\n";
        let tree = parse(src);
        let binding = RustActixAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn skips_when_actix_not_imported() {
        let src: &[u8] = b"#[get(\"/u\")]\nfn show() {}\n";
        let tree = parse(src);
        assert!(
            RustActixAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_attribute_missing() {
        let src: &[u8] = b"use actix_web::App;\nfn helper(x: String) {}\n";
        let tree = parse(src);
        assert!(
            RustActixAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn fires_on_app_new_route_chain() {
        let src: &[u8] = b"use actix_web::{App, web};\n\
            fn build() -> App<()> { App::new().route(\"/u/{id}\", web::get().to(show)) }\n\
            async fn show(id: String) -> String { id }\n";
        let tree = parse(src);
        let binding = RustActixAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "rust-actix");
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
    fn fires_on_web_resource_route_chain() {
        let src: &[u8] = b"use actix_web::{App, web};\n\
            fn build() -> App<()> { App::new().service(web::resource(\"/save\").route(web::post().to(save))) }\n\
            async fn save(body: String) -> String { body }\n";
        let tree = parse(src);
        let binding = RustActixAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn populates_middleware_from_wrap_call() {
        let src: &[u8] = b"use actix_web::{App, web};\n\
            fn build() -> App<()> { App::new().wrap(HttpAuthentication::bearer(validator)).route(\"/u\", web::get().to(show)) }\n\
            async fn show() -> String { String::new() }\n";
        let tree = parse(src);
        let binding = RustActixAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.iter().any(|m| m.name.contains("HttpAuthentication")));
    }

    #[test]
    fn chained_builder_requires_handler_match() {
        let src: &[u8] = b"use actix_web::{App, web};\n\
            fn build() -> App<()> { App::new().route(\"/x\", web::get().to(other)) }\n\
            async fn show() -> String { String::new() }\n\
            async fn other() -> String { String::new() }\n";
        let tree = parse(src);
        assert!(
            RustActixAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }
}

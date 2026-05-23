//! Gin [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises the canonical gin route declaration:
//!
//! ```go
//! r := gin.Default()
//! r.GET("/users/:id", Show)
//! r.POST("/save", func(c *gin.Context) { /* ... */ })
//! ```
//!
//! The adapter binds the route to the function whose name matches
//! `summary.name` either via a bare identifier callable, a selector
//! callable (`controllers.Show`), or via a func literal (closure)
//! that this implementation accepts as a wildcard because the
//! surrounding adapter has already narrowed to the func whose name
//! matches the summary.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::go_routes::{
    bind_go_path_params, collect_use_middleware, find_go_function, find_route_for_callee,
    go_formal_names, source_imports_gin,
};

pub struct GoGinAdapter;

const ADAPTER_NAME: &str = "go-gin";

impl FrameworkAdapter for GoGinAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_gin(file_bytes) {
            return None;
        }
        let (method, path) = find_route_for_callee(ast, file_bytes, &summary.name)?;
        let request_params = find_go_function(ast, file_bytes, &summary.name)
            .map(|func| {
                let formals = go_formal_names(func, file_bytes);
                bind_go_path_params(&formals, &path)
            })
            .unwrap_or_default();
        let middleware = collect_use_middleware(ast, file_bytes);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(method, path)),
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
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "go".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_get_with_identifier_callable() {
        let src: &[u8] = b"package main\nimport \"github.com/gin-gonic/gin\"\n\
            func init() { r := gin.Default(); r.GET(\"/users/:id\", Show) }\n\
            func Show(c *gin.Context, id string) {}\n";
        let tree = parse(src);
        let binding = GoGinAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "go-gin");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/:id");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_closure() {
        let src: &[u8] = b"package main\nimport \"github.com/gin-gonic/gin\"\n\
            func Save(c *gin.Context) {}\n\
            func init() { r := gin.Default(); r.POST(\"/save\", Save) }\n";
        let tree = parse(src);
        let binding = GoGinAdapter
            .detect(&summary("Save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn skips_when_gin_not_imported() {
        let src: &[u8] = b"package main\nfunc Show(id string) {}\n";
        let tree = parse(src);
        assert!(
            GoGinAdapter
                .detect(&summary("Show"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_route_does_not_reference_function() {
        let src: &[u8] =
            b"package main\nimport \"github.com/gin-gonic/gin\"\nfunc init() { r := gin.Default(); r.GET(\"/users\", Show) }\nfunc Helper(x string) {}\n";
        let tree = parse(src);
        assert!(
            GoGinAdapter
                .detect(&summary("Helper"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn populates_middleware_from_use_calls() {
        let src: &[u8] = b"package main\nimport \"github.com/gin-gonic/gin\"\n\
            func init() { r := gin.Default(); r.Use(AuthMiddleware); r.GET(\"/u/:id\", Show) }\n\
            func Show(c *gin.Context, id string) {}\n";
        let tree = parse(src);
        let binding = GoGinAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.middleware.len(), 1);
        assert_eq!(binding.middleware[0].name, "AuthMiddleware");
    }

    #[test]
    fn fires_on_marker_comment() {
        let src: &[u8] =
            b"// nyx-shape: gin\npackage main\nfunc init() { r.GET(\"/x\", Show) }\nfunc Show(c interface{}) {}\n";
        let tree = parse(src);
        let binding = GoGinAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "go-gin");
    }
}

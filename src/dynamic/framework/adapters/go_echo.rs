//! Echo [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises the canonical echo route declaration:
//!
//! ```go
//! e := echo.New()
//! e.GET("/users/:id", Show)
//! e.POST("/save", func(c echo.Context) error { return nil })
//! ```
//!
//! The adapter binds the route to the function whose name matches
//! `summary.name`; the path-placeholder syntax (`:id`) shares the
//! same vocabulary as gin / fiber.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::go_routes::{
    bind_go_path_params, find_go_function, find_route_for_callee, go_formal_names,
    source_imports_echo,
};

pub struct GoEchoAdapter;

const ADAPTER_NAME: &str = "go-echo";

impl FrameworkAdapter for GoEchoAdapter {
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
        if !source_imports_echo(file_bytes) {
            return None;
        }
        let (method, path) = find_route_for_callee(ast, file_bytes, &summary.name)?;
        let request_params = find_go_function(ast, file_bytes, &summary.name)
            .map(|func| {
                let formals = go_formal_names(func, file_bytes);
                bind_go_path_params(&formals, &path)
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
        let src: &[u8] = b"package main\nimport \"github.com/labstack/echo/v4\"\n\
            func init() { e := echo.New(); e.GET(\"/users/:id\", Show) }\n\
            func Show(c echo.Context, id string) error { return nil }\n";
        let tree = parse(src);
        let binding = GoEchoAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "go-echo");
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
    fn fires_on_put_verb() {
        let src: &[u8] = b"package main\nimport \"github.com/labstack/echo\"\n\
            func init() { e := echo.New(); e.PUT(\"/users/:id\", Update) }\n\
            func Update(c echo.Context, id string) error { return nil }\n";
        let tree = parse(src);
        let binding = GoEchoAdapter
            .detect(&summary("Update"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::PUT);
    }

    #[test]
    fn skips_when_echo_not_imported() {
        let src: &[u8] = b"package main\nfunc Show() {}\n";
        let tree = parse(src);
        assert!(
            GoEchoAdapter
                .detect(&summary("Show"), tree.root_node(), src)
                .is_none()
        );
    }
}

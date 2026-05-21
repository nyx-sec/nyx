//! Fiber [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises the canonical fiber route declaration:
//!
//! ```go
//! app := fiber.New()
//! app.Get("/users/:id", Show)
//! app.Post("/save", func(c *fiber.Ctx) error { return nil })
//! ```
//!
//! Fiber uses pascal-cased verb methods (`Get`/`Post`/`Put`/...), and
//! its path vocabulary includes `:id`, `:id?` (optional), `+name`
//! (greedy non-empty), and `*name` (greedy match-all).  All three
//! placeholder shapes resolve via [`super::go_routes::extract_go_path_placeholders`].

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::go_routes::{
    bind_go_path_params, find_go_function, find_route_for_callee, go_formal_names,
    source_imports_fiber,
};

pub struct GoFiberAdapter;

const ADAPTER_NAME: &str = "go-fiber";

impl FrameworkAdapter for GoFiberAdapter {
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
        if !source_imports_fiber(file_bytes) {
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
        let src: &[u8] = b"package main\nimport \"github.com/gofiber/fiber/v2\"\n\
            func init() { app := fiber.New(); app.Get(\"/users/:id\", Show) }\n\
            func Show(c *fiber.Ctx, id string) error { return nil }\n";
        let tree = parse(src);
        let binding = GoFiberAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "go-fiber");
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
    fn fires_on_greedy_plus_wildcard() {
        let src: &[u8] = b"package main\nimport \"github.com/gofiber/fiber/v2\"\n\
            func init() { app := fiber.New(); app.Get(\"/files/+rest\", Stream) }\n\
            func Stream(c *fiber.Ctx, rest string) error { return nil }\n";
        let tree = parse(src);
        let binding = GoFiberAdapter
            .detect(&summary("Stream"), tree.root_node(), src)
            .expect("binding");
        let rest = binding
            .request_params
            .iter()
            .find(|p| p.name == "rest")
            .unwrap();
        assert!(matches!(rest.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn skips_when_fiber_not_imported() {
        let src: &[u8] = b"package main\nfunc Show() {}\n";
        let tree = parse(src);
        assert!(
            GoFiberAdapter
                .detect(&summary("Show"), tree.root_node(), src)
                .is_none()
        );
    }
}

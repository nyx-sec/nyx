//! Chi [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises the canonical chi route declaration:
//!
//! ```go
//! r := chi.NewRouter()
//! r.Get("/users/{id}", Show)
//! r.Post("/save", func(w http.ResponseWriter, r *http.Request) {})
//! ```
//!
//! Chi uses brace placeholders (`{id}`, `{id:[0-9]+}`) and pascal-
//! cased verb methods.  Handler signature is `func(w, r)` — the
//! request-param binder treats `w` / `r` as implicit context.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::go_routes::{
    bind_go_path_params, collect_use_middleware, find_go_function, find_route_for_callee,
    go_formal_names, source_imports_chi,
};

pub struct GoChiAdapter;

const ADAPTER_NAME: &str = "go-chi";

impl FrameworkAdapter for GoChiAdapter {
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
        if !source_imports_chi(file_bytes) {
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
    fn fires_on_get_with_brace_placeholder() {
        let src: &[u8] = b"package main\nimport (\"net/http\"; \"github.com/go-chi/chi/v5\")\n\
            func init() { r := chi.NewRouter(); r.Get(\"/users/{id}\", Show) }\n\
            func Show(w http.ResponseWriter, r *http.Request) {}\n";
        let tree = parse(src);
        let binding = GoChiAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "go-chi");
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/{id}");
    }

    #[test]
    fn fires_on_regex_placeholder() {
        let src: &[u8] = b"package main\nimport \"github.com/go-chi/chi/v5\"\n\
            func init() { r := chi.NewRouter(); r.Get(\"/u/{id:[0-9]+}\", Show) }\n\
            func Show(w interface{}, id string) {}\n";
        let tree = parse(src);
        let binding = GoChiAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn populates_middleware_from_with_chain() {
        let src: &[u8] = b"package main\nimport (\"net/http\"; \"github.com/go-chi/chi/v5\")\n\
            func init() { r := chi.NewRouter(); r.With(jwtauth.Verifier).Get(\"/users/{id}\", Show) }\n\
            func Show(w http.ResponseWriter, r *http.Request) {}\n";
        let tree = parse(src);
        let binding = GoChiAdapter
            .detect(&summary("Show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.middleware.len(), 1);
        assert_eq!(binding.middleware[0].name, "jwtauth.Verifier");
    }

    #[test]
    fn skips_when_chi_not_imported() {
        let src: &[u8] = b"package main\nfunc Show() {}\n";
        let tree = parse(src);
        assert!(
            GoChiAdapter
                .detect(&summary("Show"), tree.root_node(), src)
                .is_none()
        );
    }
}

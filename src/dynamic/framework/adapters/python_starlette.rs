//! Python Starlette [`super::super::FrameworkAdapter`] (Phase 12 — Track L.10).
//!
//! Recognises `Route("/path", endpoint=handler)` and
//! `Route("/path", handler)` registrations inside a Starlette
//! application file (`from starlette.routing import Route` /
//! `from starlette.applications import Starlette`).  Detection walks
//! every `call` node in the AST so the order of declaration relative
//! to the handler does not matter.  Methods are picked up from the
//! `methods=[...]` kwarg when present and default to `GET`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::python_routes::{
    bind_path_params, find_python_function, first_string_arg, function_formal_names, methods_kwarg,
    source_imports_starlette,
};

pub struct PythonStarletteAdapter;

const ADAPTER_NAME: &str = "python-starlette";

/// Find a `Route("/path", endpoint=target)` or
/// `Route("/path", target)` call and return its `(method, path)`.
/// Returns `None` when no matching call is present.
fn route_registration_for(
    root: Node<'_>,
    bytes: &[u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    walk_routes(root, bytes, target, &mut hit);
    hit
}

fn walk_routes(node: Node<'_>, bytes: &[u8], target: &str, out: &mut Option<(HttpMethod, String)>) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call"
        && let Some(callee) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
    {
        let last = callee.rsplit_once('.').map(|(_, s)| s).unwrap_or(callee);
        if matches!(last, "Route" | "WebSocketRoute")
            && let Some(args) = node.child_by_field_name("arguments")
            && let Some(path) = first_string_arg(args, bytes)
            && endpoint_references(args, bytes, target)
        {
            let method = methods_kwarg(args, bytes).unwrap_or(HttpMethod::GET);
            *out = Some((method, path));
            return;
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_routes(child, bytes, target, out);
    }
}

fn endpoint_references(args: Node<'_>, bytes: &[u8], target: &str) -> bool {
    let mut cur = args.walk();
    let mut seen_positional = 0usize;
    for arg in args.named_children(&mut cur) {
        if arg.kind() == "keyword_argument" {
            let Some(name) = arg.child_by_field_name("name") else {
                continue;
            };
            let Ok(name_text) = name.utf8_text(bytes) else {
                continue;
            };
            if name_text == "endpoint"
                && let Some(value) = arg.child_by_field_name("value")
                && identifier_matches(value, bytes, target)
            {
                return true;
            }
        } else {
            seen_positional += 1;
            // Second positional argument is the endpoint when no
            // keyword form is used.
            if seen_positional == 2 && identifier_matches(arg, bytes, target) {
                return true;
            }
        }
    }
    false
}

fn identifier_matches(node: Node<'_>, bytes: &[u8], target: &str) -> bool {
    let Ok(text) = node.utf8_text(bytes) else {
        return false;
    };
    let trimmed = text.trim().trim_end_matches("()");
    let last = trimmed.rsplit_once('.').map(|(_, s)| s).unwrap_or(trimmed);
    last == target || trimmed == target
}

impl FrameworkAdapter for PythonStarletteAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_starlette(file_bytes) {
            return None;
        }
        let (func_node, _) = find_python_function(ast, file_bytes, &summary.name)?;
        let (method, path) = route_registration_for(ast, file_bytes, &summary.name)?;
        let formals = function_formal_names(func_node, file_bytes);
        let request_params = bind_path_params(&formals, &path);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(method, path)),
            request_params,
            response_writer: None,
            middleware: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::ParamSource;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "python".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_route_with_keyword_endpoint() {
        let src: &[u8] = b"from starlette.applications import Starlette\nfrom starlette.routing import Route\nasync def homepage(request):\n    return None\napp = Starlette(routes=[Route(\"/\", endpoint=homepage)])\n";
        let tree = parse(src);
        let binding = PythonStarletteAdapter
            .detect(&summary("homepage"), tree.root_node(), src)
            .unwrap();
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/");
        assert_eq!(route.method, HttpMethod::GET);
    }

    #[test]
    fn fires_on_route_with_positional_endpoint() {
        let src: &[u8] = b"from starlette.routing import Route\nasync def homepage(request):\n    return None\nroutes = [Route(\"/items/{id}\", homepage)]\n";
        let tree = parse(src);
        let binding = PythonStarletteAdapter
            .detect(&summary("homepage"), tree.root_node(), src)
            .unwrap();
        assert_eq!(binding.route.unwrap().path, "/items/{id}");
    }

    #[test]
    fn picks_up_post_methods_kwarg() {
        let src: &[u8] = b"from starlette.routing import Route\nasync def create(request):\n    return None\nroutes = [Route(\"/items\", endpoint=create, methods=[\"POST\"])]\n";
        let tree = parse(src);
        let binding = PythonStarletteAdapter
            .detect(&summary("create"), tree.root_node(), src)
            .unwrap();
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn binds_request_as_implicit() {
        let src: &[u8] = b"from starlette.routing import Route\nasync def homepage(request):\n    return None\nroutes = [Route(\"/\", endpoint=homepage)]\n";
        let tree = parse(src);
        let binding = PythonStarletteAdapter
            .detect(&summary("homepage"), tree.root_node(), src)
            .unwrap();
        let req = binding
            .request_params
            .iter()
            .find(|p| p.name == "request")
            .unwrap();
        assert!(matches!(req.source, ParamSource::Implicit));
    }

    #[test]
    fn skips_when_starlette_not_imported() {
        let src: &[u8] = b"def homepage(request):\n    return None\n";
        let tree = parse(src);
        assert!(
            PythonStarletteAdapter
                .detect(&summary("homepage"), tree.root_node(), src)
                .is_none()
        );
    }
}

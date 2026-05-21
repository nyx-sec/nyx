//! Python Flask [`super::super::FrameworkAdapter`] (Phase 12 — Track L.10).
//!
//! Recognises `@app.route("/path", methods=[…])` plus the verb-shortcut
//! decorators `@app.get`, `@app.post`, `@app.put`, `@app.patch`,
//! `@app.delete` on either an application object or a
//! `flask.Blueprint` (typical aliases: `app`, `application`, `bp`,
//! `blueprint`, `router`).  Decorator detection walks the AST so the
//! adapter sees the literal path template + the `methods=` kwarg —
//! both of which feed [`super::super::RouteShape`] and the per-formal
//! [`super::super::ParamBinding`] list that downstream harness emitters
//! use to construct a real HTTP request.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::python_routes::{
    bind_path_params, find_python_function, first_string_arg, function_formal_names, methods_kwarg,
    source_imports_flask,
};

pub struct PythonFlaskAdapter;

const ADAPTER_NAME: &str = "python-flask";

/// Verb shortcuts (`@app.get` / `@app.post` / …).  Excludes
/// `route` — that decorator carries the verb in a `methods=` kwarg
/// instead of in the attribute name and is handled separately.
fn shortcut_method(attr: &str) -> Option<HttpMethod> {
    match attr.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::GET),
        "head" => Some(HttpMethod::HEAD),
        "post" => Some(HttpMethod::POST),
        "put" => Some(HttpMethod::PUT),
        "patch" => Some(HttpMethod::PATCH),
        "delete" => Some(HttpMethod::DELETE),
        "options" => Some(HttpMethod::OPTIONS),
        _ => None,
    }
}

/// Receiver names accepted on the left side of `@<recv>.route(...)`.
/// Flask convention covers `app`, `application`, plus blueprint
/// aliases (`bp`, `blueprint`, `router`).  The check is permissive
/// because Phase 12 only uses the adapter to surface a route shape
/// for the harness — false positives are bounded by the
/// caller-supplied `summary` (the function must actually exist).
fn receiver_looks_like_flask(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "app" | "application" | "bp" | "blueprint" | "router"
    ) || lower.ends_with("_bp")
        || lower.ends_with("_app")
        || lower.ends_with("_blueprint")
        || lower.ends_with("_router")
}

/// Parse a single decorator node into (method, path).  Returns `None`
/// when the decorator is not a Flask route decorator on a recognised
/// receiver.
fn decorator_route_shape(decorator: Node<'_>, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut cur = decorator.walk();
    let expr = decorator.children(&mut cur).find(|c| c.kind() != "@")?;
    let call = match expr.kind() {
        "call" => expr,
        _ => return None,
    };
    let target = call.child_by_field_name("function")?;
    let args = call.child_by_field_name("arguments")?;
    if target.kind() != "attribute" {
        return None;
    }
    let object = target.child_by_field_name("object")?;
    let attr = target.child_by_field_name("attribute")?;
    let object_text = object.utf8_text(bytes).ok()?;
    let attr_text = attr.utf8_text(bytes).ok()?;
    if !receiver_looks_like_flask(object_text) {
        return None;
    }

    let path = first_string_arg(args, bytes)?;

    if attr_text.eq_ignore_ascii_case("route") {
        let method = methods_kwarg(args, bytes).unwrap_or(HttpMethod::GET);
        return Some((method, path));
    }
    let method = shortcut_method(attr_text)?;
    Some((method, path))
}

impl FrameworkAdapter for PythonFlaskAdapter {
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
        if !source_imports_flask(file_bytes) {
            return None;
        }
        let (func_node, decorated_node) = find_python_function(ast, file_bytes, &summary.name)?;
        let decorated = decorated_node?;
        let mut cur = decorated.walk();
        for d in decorated.children(&mut cur) {
            if d.kind() != "decorator" {
                continue;
            }
            if let Some((method, path)) = decorator_route_shape(d, file_bytes) {
                let formals = function_formal_names(func_node, file_bytes);
                let request_params = bind_path_params(&formals, &path);
                return Some(FrameworkBinding {
                    adapter: ADAPTER_NAME.to_owned(),
                    kind: EntryKind::HttpRoute,
                    route: Some(RouteShape { method, path }),
                    request_params,
                    response_writer: None,
                    middleware: Vec::new(),
                });
            }
        }
        None
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
    fn fires_on_app_route_with_get_default() {
        let src: &[u8] =
            b"from flask import Flask\napp = Flask(__name__)\n@app.route(\"/users\")\ndef list_users():\n    return []\n";
        let tree = parse(src);
        let binding = PythonFlaskAdapter
            .detect(&summary("list_users"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "python-flask");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.expect("route shape");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users");
    }

    #[test]
    fn fires_on_app_route_with_methods_kwarg() {
        let src: &[u8] =
            b"from flask import Flask\napp = Flask(__name__)\n@app.route(\"/x\", methods=[\"POST\"])\ndef save(payload):\n    return payload\n";
        let tree = parse(src);
        let binding = PythonFlaskAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/x");
    }

    #[test]
    fn fires_on_verb_shortcut_post() {
        let src: &[u8] =
            b"from flask import Flask\napp = Flask(__name__)\n@app.post(\"/items\")\ndef create_item(payload):\n    return payload\n";
        let tree = parse(src);
        let binding = PythonFlaskAdapter
            .detect(&summary("create_item"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn fires_on_blueprint_route() {
        let src: &[u8] =
            b"from flask import Blueprint\nuser_bp = Blueprint('user_bp', __name__)\n@user_bp.route(\"/users/<id>\")\ndef get_user(id):\n    return id\n";
        let tree = parse(src);
        let binding = PythonFlaskAdapter
            .detect(&summary("get_user"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/users/<id>");
        assert!(
            binding
                .request_params
                .iter()
                .any(|p| p.name == "id" && matches!(p.source, ParamSource::PathSegment(_)))
        );
    }

    #[test]
    fn binds_path_segment_and_implicit_formal() {
        let src: &[u8] =
            b"from flask import Flask\napp = Flask(__name__)\n@app.route(\"/users/<int:id>\")\ndef show(id, extra=\"x\"):\n    return id\n";
        let tree = parse(src);
        let binding = PythonFlaskAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        let id_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id_binding.source, ParamSource::PathSegment(_)));
        let extra_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "extra")
            .unwrap();
        assert!(matches!(extra_binding.source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn skips_when_flask_not_imported() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse(src);
        assert!(
            PythonFlaskAdapter
                .detect(&summary("add"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_function_has_no_decorator() {
        let src: &[u8] =
            b"from flask import Flask\napp = Flask(__name__)\ndef helper(x):\n    return x\n";
        let tree = parse(src);
        assert!(
            PythonFlaskAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }
}

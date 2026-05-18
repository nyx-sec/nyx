//! Python FastAPI [`super::super::FrameworkAdapter`] (Phase 12 — Track L.10).
//!
//! Recognises `@app.get("/path")`, `@app.post(...)`, `@router.put(...)`,
//! `@router.patch(...)`, `@router.delete(...)`, `@app.options(...)`,
//! `@app.head(...)`, `@app.websocket(...)`, and the `Depends(...)` /
//! Pydantic `BaseModel` formals that come with them.  Decorator
//! detection walks the AST so the adapter sees the literal path
//! template; the per-formal [`super::super::ParamBinding`] list
//! classifies request-body-typed formals as
//! [`super::super::ParamSource::JsonBody`] when the annotation refers
//! to a class declared earlier in the same file (a strong Pydantic
//! signal) and falls back to `QueryParam(name)` otherwise.

use crate::dynamic::framework::{
    FrameworkAdapter, FrameworkBinding, HttpMethod, ParamBinding, ParamSource, RouteShape,
};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::python_routes::{
    bind_path_params, find_python_function, function_formal_names, source_imports_fastapi,
};

pub struct PythonFastApiAdapter;

const ADAPTER_NAME: &str = "python-fastapi";

fn shortcut_method(attr: &str) -> Option<HttpMethod> {
    match attr.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::GET),
        "head" => Some(HttpMethod::HEAD),
        "post" => Some(HttpMethod::POST),
        "put" => Some(HttpMethod::PUT),
        "patch" => Some(HttpMethod::PATCH),
        "delete" => Some(HttpMethod::DELETE),
        "options" => Some(HttpMethod::OPTIONS),
        "websocket" | "websocket_route" => Some(HttpMethod::GET),
        _ => None,
    }
}

fn receiver_looks_like_fastapi(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "app" | "application" | "router" | "api_router"
    ) || lower.ends_with("_router")
        || lower.ends_with("_app")
}

fn decorator_route_shape(decorator: Node<'_>, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut cur = decorator.walk();
    let expr = decorator.children(&mut cur).find(|c| c.kind() != "@")?;
    if expr.kind() != "call" {
        return None;
    }
    let target = expr.child_by_field_name("function")?;
    let args = expr.child_by_field_name("arguments")?;
    if target.kind() != "attribute" {
        return None;
    }
    let object = target.child_by_field_name("object")?.utf8_text(bytes).ok()?;
    let attr = target.child_by_field_name("attribute")?.utf8_text(bytes).ok()?;
    if !receiver_looks_like_fastapi(object) {
        return None;
    }
    let method = shortcut_method(attr)?;
    let path = first_string_arg(args, bytes)?;
    Some((method, path))
}

fn first_string_arg(args: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if c.kind() == "string" {
            let raw = c.utf8_text(bytes).ok()?;
            return Some(strip_quotes(raw).to_owned());
        }
    }
    None
}

fn strip_quotes(raw: &str) -> &str {
    let t = raw.trim();
    let t = t.strip_prefix("b").unwrap_or(t);
    let t = t.strip_prefix("r").unwrap_or(t);
    let t = t.strip_prefix("u").unwrap_or(t);
    t.trim_matches(['\'', '"'])
}

/// Refine per-formal bindings by inspecting the parameter list for
/// Pydantic body models and `Depends(...)` declarations.  An
/// annotation pointing at a class declared in the same file is
/// treated as a `JsonBody`; an `= Depends(...)` default is treated
/// as `Implicit` (dependency-injected — not adversary-controlled
/// directly).
fn refine_for_fastapi(
    func: Node<'_>,
    bytes: &[u8],
    file_classes: &[String],
    base: Vec<ParamBinding>,
) -> Vec<ParamBinding> {
    let Some(params) = func.child_by_field_name("parameters") else {
        return base;
    };
    let mut by_name: std::collections::HashMap<String, ParamRefinement> =
        std::collections::HashMap::new();
    let mut cur = params.walk();
    for child in params.named_children(&mut cur) {
        if let Some((name, refinement)) = classify_formal(child, bytes, file_classes) {
            by_name.insert(name, refinement);
        }
    }
    base.into_iter()
        .map(|b| match by_name.get(&b.name) {
            Some(ParamRefinement::JsonBody) => ParamBinding {
                source: ParamSource::JsonBody,
                ..b
            },
            Some(ParamRefinement::Implicit) => ParamBinding {
                source: ParamSource::Implicit,
                ..b
            },
            _ => b,
        })
        .collect()
}

enum ParamRefinement {
    JsonBody,
    Implicit,
}

fn classify_formal(
    node: Node<'_>,
    bytes: &[u8],
    file_classes: &[String],
) -> Option<(String, ParamRefinement)> {
    match node.kind() {
        "typed_default_parameter" | "default_parameter" => {
            let value = node.child_by_field_name("value")?;
            let name = first_identifier(node, bytes)?;
            if call_callee_text(value, bytes)
                .map(|t| t.contains("Depends"))
                .unwrap_or(false)
            {
                return Some((name, ParamRefinement::Implicit));
            }
            if let Some(t) = node.child_by_field_name("type")
                && let Some(ann) = t.utf8_text(bytes).ok()
                && file_classes.iter().any(|c| ann.contains(c))
            {
                return Some((name, ParamRefinement::JsonBody));
            }
            None
        }
        "typed_parameter" => {
            let name = first_identifier(node, bytes)?;
            let t = node.child_by_field_name("type")?.utf8_text(bytes).ok()?;
            if file_classes.iter().any(|c| t.contains(c)) {
                return Some((name, ParamRefinement::JsonBody));
            }
            None
        }
        _ => None,
    }
}

fn first_identifier(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = node.walk();
    for c in node.named_children(&mut cur) {
        if c.kind() == "identifier" {
            return c.utf8_text(bytes).ok().map(str::to_owned);
        }
    }
    None
}

fn call_callee_text(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    node.child_by_field_name("function")?
        .utf8_text(bytes)
        .ok()
        .map(str::to_owned)
}

/// Enumerate top-level class names so [`refine_for_fastapi`] can spot
/// Pydantic body models.  Conservative: walks the file once and
/// records every `class_definition`'s name.
fn collect_class_names(root: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    walk_classes(root, bytes, &mut out);
    out
}

fn walk_classes(node: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    if node.kind() == "class_definition"
        && let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(bytes).ok())
    {
        out.push(name.to_owned());
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_classes(child, bytes, out);
    }
}

impl FrameworkAdapter for PythonFastApiAdapter {
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
        if !source_imports_fastapi(file_bytes) {
            return None;
        }
        let (func_node, decorated_node) = find_python_function(ast, file_bytes, &summary.name)?;
        let decorated = decorated_node?;
        let classes = collect_class_names(ast, file_bytes);
        let mut cur = decorated.walk();
        for d in decorated.children(&mut cur) {
            if d.kind() != "decorator" {
                continue;
            }
            if let Some((method, path)) = decorator_route_shape(d, file_bytes) {
                let formals = function_formal_names(func_node, file_bytes);
                let base = bind_path_params(&formals, &path);
                let request_params = refine_for_fastapi(func_node, file_bytes, &classes, base);
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
    fn fires_on_app_get() {
        let src: &[u8] = b"from fastapi import FastAPI\napp = FastAPI()\n@app.get(\"/items/{id}\")\ndef read_item(id):\n    return id\n";
        let tree = parse(src);
        let binding = PythonFastApiAdapter
            .detect(&summary("read_item"), tree.root_node(), src)
            .unwrap();
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/items/{id}");
        let id_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id_binding.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_router_post() {
        let src: &[u8] =
            b"from fastapi import APIRouter\nrouter = APIRouter()\n@router.post(\"/items\")\ndef create_item(payload):\n    return payload\n";
        let tree = parse(src);
        let binding = PythonFastApiAdapter
            .detect(&summary("create_item"), tree.root_node(), src)
            .unwrap();
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn pydantic_body_becomes_json_body() {
        let src: &[u8] = b"from fastapi import FastAPI\nfrom pydantic import BaseModel\nclass Item(BaseModel):\n    name: str\napp = FastAPI()\n@app.post(\"/items\")\ndef create_item(item: Item):\n    return item\n";
        let tree = parse(src);
        let binding = PythonFastApiAdapter
            .detect(&summary("create_item"), tree.root_node(), src)
            .unwrap();
        let item_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "item")
            .unwrap();
        assert!(matches!(item_binding.source, ParamSource::JsonBody));
    }

    #[test]
    fn depends_default_becomes_implicit() {
        let src: &[u8] = b"from fastapi import FastAPI, Depends\napp = FastAPI()\ndef get_db():\n    return None\n@app.get(\"/items\")\ndef list_items(db = Depends(get_db)):\n    return db\n";
        let tree = parse(src);
        let binding = PythonFastApiAdapter
            .detect(&summary("list_items"), tree.root_node(), src)
            .unwrap();
        let db_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "db")
            .unwrap();
        assert!(matches!(db_binding.source, ParamSource::Implicit));
    }

    #[test]
    fn skips_when_fastapi_not_imported() {
        let src: &[u8] = b"from flask import Flask\napp = Flask(__name__)\n@app.get(\"/x\")\ndef x():\n    return 1\n";
        let tree = parse(src);
        assert!(PythonFastApiAdapter
            .detect(&summary("x"), tree.root_node(), src)
            .is_none());
    }
}

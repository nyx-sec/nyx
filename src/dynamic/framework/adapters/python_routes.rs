//! Shared Python-route adapter helpers (Phase 12 — Track L.10).
//!
//! The Flask / Django / FastAPI / Starlette adapters all need the same
//! handful of tree-sitter helpers: locate a `function_definition` by
//! name, peek at its parent `decorated_definition` for decorator data,
//! enumerate formal parameter names, and bind a path template's
//! placeholders to those formals.  Centralising the helpers here keeps
//! the four adapters terse and lets every framework share the same
//! placeholder-binding semantics (so an unmatched formal becomes a
//! `QueryParam(name)` everywhere, not just in one adapter).

use crate::dynamic::framework::{ParamBinding, ParamSource};
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known Flask import
/// stanzas.  Used by [`super::python_flask::PythonFlaskAdapter`] to
/// short-circuit non-Flask Python files before the AST walk.
pub fn source_imports_flask(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"from flask",
            b"import flask",
            b"Flask(",
            b"Blueprint(",
            b"flask.Blueprint",
        ],
    )
}

/// True when `bytes` carries any of the well-known FastAPI import
/// stanzas.
pub fn source_imports_fastapi(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[b"from fastapi", b"import fastapi", b"FastAPI(", b"APIRouter("],
    )
}

/// True when `bytes` carries any of the well-known Django import
/// stanzas — including the `urls.py` `path(` / `re_path(` / `url(`
/// registration helpers that the Django adapter consults.
pub fn source_imports_django(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"from django",
            b"import django",
            b"django.http",
            b"django.urls",
            b"django.views",
            b"django.shortcuts",
            b"urlpatterns",
        ],
    )
}

/// True when `bytes` carries any of the well-known Starlette import
/// stanzas.  Excludes the FastAPI-only imports so the Starlette
/// adapter does not collide with FastAPI files that re-export
/// Starlette types.
pub fn source_imports_starlette(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"from starlette",
            b"import starlette",
            b"Starlette(",
            b"starlette.routing",
            b"starlette.applications",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Find the `function_definition` node whose `name` field equals
/// `target`.  Returns `(func_node, Option<decorated_definition>)` —
/// the decorated parent is `Some` when the function carries one or
/// more decorators.
pub fn find_python_function<'a>(
    root: Node<'a>,
    bytes: &[u8],
    target: &str,
) -> Option<(Node<'a>, Option<Node<'a>>)> {
    walk(root, bytes, target)
}

fn walk<'a>(node: Node<'a>, bytes: &[u8], target: &str) -> Option<(Node<'a>, Option<Node<'a>>)> {
    if node.kind() == "function_definition" {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(bytes).ok())
        {
            if name == target {
                let decorated = node.parent().filter(|p| p.kind() == "decorated_definition");
                return Some((node, decorated));
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        if let Some(found) = walk(child, bytes, target) {
            return Some(found);
        }
    }
    None
}

/// Enumerate formal parameter names from a `function_definition` node.
/// Skips `self`/`cls` so class-based handler methods bind only the
/// adversary-controlled formals.
pub fn function_formal_names(func: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(parameters) = func.child_by_field_name("parameters") else {
        return out;
    };
    let mut cur = parameters.walk();
    for child in parameters.named_children(&mut cur) {
        if let Some(name) = parameter_name(child, bytes) {
            if name == "self" || name == "cls" {
                continue;
            }
            out.push(name);
        }
    }
    out
}

fn parameter_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(bytes).ok().map(str::to_owned),
        "default_parameter"
        | "typed_parameter"
        | "typed_default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern" => {
            // Each of these wraps either a plain identifier or another
            // structure whose first identifier is the parameter name.
            let mut cur = node.walk();
            for c in node.named_children(&mut cur) {
                if c.kind() == "identifier" {
                    return c.utf8_text(bytes).ok().map(str::to_owned);
                }
                if let Some(n) = parameter_name(c, bytes) {
                    return Some(n);
                }
            }
            None
        }
        _ => None,
    }
}

/// Bind formals to request slots given a route path template.
///
/// Accepts both Flask-style placeholders (`<id>`, `<int:id>`) and
/// FastAPI/Starlette/Django-style placeholders (`{id}`, `<int:id>`).
/// A formal whose name matches a placeholder becomes a
/// [`ParamSource::PathSegment`]; an unmatched formal becomes a
/// [`ParamSource::QueryParam`] of the same name so downstream
/// harness emitters have a deterministic slot to populate.
pub fn bind_path_params(formals: &[String], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_path_placeholders(path);
    formals
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let source = if name == "request" || name == "req" {
                ParamSource::Implicit
            } else if placeholders.iter().any(|p| p == name) {
                ParamSource::PathSegment(name.clone())
            } else {
                ParamSource::QueryParam(name.clone())
            };
            ParamBinding {
                index: idx,
                name: name.clone(),
                source,
            }
        })
        .collect()
}

/// Extract placeholder names from a route path template.
///
/// Supports three placeholder syntaxes:
///   - Flask: `/users/<id>`, `/users/<int:id>` → `id`
///   - FastAPI / Starlette: `/users/{id}` → `id`
///   - Django: `<int:id>`, `<id>` (same as Flask) plus regex
///     `(?P<id>...)` capture groups.
///
/// Names are deduplicated while preserving first-occurrence order
/// so a single placeholder reused across the path (or matched by
/// two scanners on the same span — e.g. `(?P<id>...)`) does not
/// double-bind a formal.
pub fn extract_path_placeholders(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if !name.is_empty() && !out.iter().any(|n| n == &name) {
            out.push(name);
        }
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => {
                // Skip the `<` that opens a Django named capture
                // group `(?P<id>...)` — the `(?P<id>` scan below
                // handles it.  The two preceding bytes encode the
                // `?P` marker.
                let in_named_group = i >= 2 && &bytes[i - 2..i] == b"?P";
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'>') {
                    if !in_named_group {
                        let inner = &path[i + 1..i + 1 + end];
                        let name = inner.rsplit_once(':').map(|(_, n)| n).unwrap_or(inner);
                        push(name.to_owned());
                    }
                    i += end + 2;
                    continue;
                }
            }
            b'{' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                    let inner = &path[i + 1..i + 1 + end];
                    let name = inner.split(':').next().unwrap_or(inner);
                    push(name.to_owned());
                    i += end + 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let mut rest = path;
    while let Some(pos) = rest.find("(?P<") {
        let after = &rest[pos + 4..];
        if let Some(end) = after.find('>') {
            push(after[..end].to_owned());
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    out
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

    #[test]
    fn finds_decorated_function() {
        let src: &[u8] = b"@dec\ndef target(a, b):\n    return a + b\n";
        let tree = parse(src);
        let (_func, decorated) = find_python_function(tree.root_node(), src, "target").unwrap();
        assert!(decorated.is_some());
    }

    #[test]
    fn finds_function_without_decorator() {
        let src: &[u8] = b"def target(a):\n    return a\n";
        let tree = parse(src);
        let (_func, decorated) = find_python_function(tree.root_node(), src, "target").unwrap();
        assert!(decorated.is_none());
    }

    #[test]
    fn skips_self_and_cls() {
        let src: &[u8] = b"class X:\n    def m(self, a, b):\n        return a + b\n";
        let tree = parse(src);
        let (func, _) = find_python_function(tree.root_node(), src, "m").unwrap();
        let names = function_formal_names(func, src);
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn extracts_flask_placeholders() {
        let p = extract_path_placeholders("/users/<id>");
        assert_eq!(p, vec!["id"]);
        let p = extract_path_placeholders("/items/<int:id>/<slug>");
        assert_eq!(p, vec!["id", "slug"]);
    }

    #[test]
    fn extracts_fastapi_placeholders() {
        let p = extract_path_placeholders("/users/{id}");
        assert_eq!(p, vec!["id"]);
        let p = extract_path_placeholders("/items/{id:int}");
        assert_eq!(p, vec!["id"]);
    }

    #[test]
    fn extracts_django_regex_placeholders() {
        let p = extract_path_placeholders(r"^/users/(?P<id>\d+)/?$");
        assert_eq!(p, vec!["id"]);
    }

    #[test]
    fn binds_known_placeholder_as_path_segment() {
        let formals = vec!["id".to_string(), "extra".to_string()];
        let bindings = bind_path_params(&formals, "/users/{id}");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[1].source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn binds_request_as_implicit() {
        let formals = vec!["request".to_string(), "id".to_string()];
        let bindings = bind_path_params(&formals, "/users/{id}");
        assert!(matches!(bindings[0].source, ParamSource::Implicit));
        assert!(matches!(bindings[1].source, ParamSource::PathSegment(_)));
    }
}

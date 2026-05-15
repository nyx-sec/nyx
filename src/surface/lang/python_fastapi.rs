//! Python + FastAPI framework probe.
//!
//! Recognises FastAPI / Starlette route declarations:
//!
//! * `@app.get("/path")` / `.post("/path")` / `.put` / `.patch` / `.delete`
//! * `@router.get("/path")` / `.post(...)` / etc. on an `APIRouter`
//! * `@app.api_route("/path", methods=["GET","POST"])`
//! * `@app.websocket("/ws")` (treated as GET)
//!
//! `auth_required` is inferred from `Depends(<auth>)` parameters in the
//! handler signature (FastAPI's idiomatic auth pattern) and from
//! decorator-stack guards drawn from [`AUTH_DECORATORS`].

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{
    leaf_matches, loc_for, python_imports_any, rel_file, string_node_value,
};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

/// Auth markers recognised in the decorator stack.  FastAPI's primary
/// auth idiom is `Depends(...)` parameter injection, handled separately.
pub const AUTH_DECORATORS: &[&str] = &[
    "login_required",
    "auth_required",
    "jwt_required",
    "token_required",
    "requires_auth",
    "authenticated",
    "require_auth",
    "require_login",
    "current_user",
];

/// Auth-callee names recognised inside a `Depends(...)` parameter.
const AUTH_DEPENDS_CALLEES: &[&str] = &[
    "get_current_user",
    "get_current_active_user",
    "current_user",
    "require_user",
    "require_auth",
    "auth",
    "verify_token",
    "verify_jwt",
    "validate_token",
];

pub fn detect_fastapi_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    // File-level gate: avoid double-detection on Flask files that
    // also use `app.get(...)` shape.  Phase 23 follow-up tightens the
    // witness to actual top-level `import` / `from` statements so a
    // comment or string mention of "fastapi" cannot trigger detection.
    if !python_imports_any(bytes, &["fastapi", "starlette"]) {
        return Vec::new();
    }
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_decorated(tree.root_node(), &mut |func, decorators| {
        let auth_via_decorator = decorators
            .iter()
            .any(|d| decorator_is_auth_marker(*d, bytes));
        let auth_via_depends = function_signature_uses_auth_depends(*func, bytes);
        let auth_required = auth_via_decorator || auth_via_depends;
        for dec in decorators {
            if let Some((method, route_path)) = fastapi_route_decorator(*dec, bytes) {
                let handler_name = function_name(*func, bytes).unwrap_or_default();
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: loc_for(*dec, &file_rel),
                    framework: Framework::FastApi,
                    method,
                    route: route_path,
                    handler_name,
                    handler_location: SourceLocation::new(
                        file_rel.clone(),
                        (func.start_position().row + 1) as u32,
                        (func.start_position().column + 1) as u32,
                    ),
                    auth_required,
                }));
            }
        }
    });
    out
}

fn walk_decorated<'tree, F>(root: Node<'tree>, visit: &mut F)
where
    F: FnMut(&Node<'tree>, &[Node<'tree>]),
{
    if root.kind() == "decorated_definition" {
        let mut cursor = root.walk();
        let mut decorators: Vec<Node<'tree>> = Vec::new();
        let mut func: Option<Node<'tree>> = None;
        for child in root.children(&mut cursor) {
            match child.kind() {
                "decorator" => decorators.push(child),
                "function_definition" => func = Some(child),
                _ => {}
            }
        }
        if let Some(f) = func {
            visit(&f, &decorators);
        }
    }
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        walk_decorated(child, visit);
    }
}

fn fastapi_route_decorator(decorator: Node, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut cursor = decorator.walk();
    let expr = decorator
        .children(&mut cursor)
        .find(|c| c.kind() != "@" && c.kind() != "comment")?;
    if expr.kind() != "call" {
        return None;
    }
    let target = expr.child_by_field_name("function")?;
    let args = expr.child_by_field_name("arguments");
    if target.kind() != "attribute" {
        return None;
    }
    let object = target.child_by_field_name("object")?;
    if !receiver_is_fastapi(object, bytes) {
        return None;
    }
    let attr = target.child_by_field_name("attribute")?;
    let attr_text = attr.utf8_text(bytes).ok()?;
    let route_path = args
        .and_then(|a| first_string_arg(a, bytes))
        .unwrap_or_default();
    if let Some(m) = HttpMethod::from_ident(attr_text) {
        return Some((m, route_path));
    }
    let lower = attr_text.to_ascii_lowercase();
    if lower == "websocket" || lower == "websocket_route" {
        return Some((HttpMethod::GET, route_path));
    }
    if lower == "api_route" {
        let method = args
            .and_then(|a| first_methods_kwarg(a, bytes))
            .unwrap_or(HttpMethod::GET);
        return Some((method, route_path));
    }
    None
}

fn receiver_is_fastapi(object: Node, bytes: &[u8]) -> bool {
    fn name_matches(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower == "app"
            || lower == "router"
            || lower == "api"
            || lower.ends_with("_app")
            || lower.ends_with("_router")
            || lower.ends_with("_api")
    }
    match object.kind() {
        "identifier" => object.utf8_text(bytes).ok().is_some_and(name_matches),
        "attribute" => object
            .child_by_field_name("attribute")
            .and_then(|a| a.utf8_text(bytes).ok())
            .is_some_and(name_matches),
        "call" => {
            let Some(callee) = object.child_by_field_name("function") else {
                return false;
            };
            let Ok(text) = callee.utf8_text(bytes) else {
                return false;
            };
            let leaf = text.rsplit('.').next().unwrap_or(text).trim();
            leaf == "FastAPI" || leaf == "APIRouter" || leaf == "Starlette"
        }
        _ => false,
    }
}

fn first_string_arg(args: Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() == "string" {
            return string_node_value(arg, bytes);
        }
    }
    None
}

fn first_methods_kwarg(args: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() != "keyword_argument" {
            continue;
        }
        let name = arg.child_by_field_name("name")?;
        if name.utf8_text(bytes).ok()? != "methods" {
            continue;
        }
        let value = arg.child_by_field_name("value")?;
        let mut vw = value.walk();
        for child in value.children(&mut vw) {
            if child.kind() == "string"
                && let Some(v) = string_node_value(child, bytes)
                && let Some(m) = HttpMethod::from_ident(&v)
            {
                return Some(m);
            }
        }
    }
    None
}

fn decorator_is_auth_marker(decorator: Node, bytes: &[u8]) -> bool {
    let mut cursor = decorator.walk();
    let Some(expr) = decorator
        .children(&mut cursor)
        .find(|c| c.kind() != "@" && c.kind() != "comment")
    else {
        return false;
    };
    let target = match expr.kind() {
        "call" => expr.child_by_field_name("function"),
        _ => Some(expr),
    };
    let Some(target) = target else { return false };
    let Ok(text) = target.utf8_text(bytes) else {
        return false;
    };
    leaf_matches(text, AUTH_DECORATORS)
}

/// Look for a parameter with default `Depends(<auth_callee>)`.
fn function_signature_uses_auth_depends(func: Node, bytes: &[u8]) -> bool {
    let Some(params) = func.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = params.walk();
    for param in params.children(&mut cursor) {
        if !matches!(
            param.kind(),
            "default_parameter" | "typed_default_parameter"
        ) {
            continue;
        }
        let Some(value) = param.child_by_field_name("value") else {
            continue;
        };
        if value.kind() != "call" {
            continue;
        }
        let Some(call_target) = value.child_by_field_name("function") else {
            continue;
        };
        let Ok(text) = call_target.utf8_text(bytes) else {
            continue;
        };
        let leaf = text.rsplit('.').next().unwrap_or(text).trim();
        if leaf != "Depends" && leaf != "Security" {
            continue;
        }
        let Some(args) = value.child_by_field_name("arguments") else {
            continue;
        };
        let mut aw = args.walk();
        for arg in args.children(&mut aw) {
            if let Ok(arg_text) = arg.utf8_text(bytes)
                && leaf_matches(arg_text, AUTH_DEPENDS_CALLEES)
            {
                return true;
            }
        }
    }
    false
}

fn function_name(func: Node, bytes: &[u8]) -> Option<String> {
    let name_node = func.child_by_field_name("name")?;
    name_node.utf8_text(bytes).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_get_route() {
        let src = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/users')\ndef list_users(): pass\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_fastapi_routes(&tree, &bytes, &PathBuf::from("api.py"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
        assert_eq!(ep.framework, Framework::FastApi);
    }

    #[test]
    fn detects_router_post() {
        let src = "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/items')\ndef create(): pass\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_fastapi_routes(&tree, &bytes, &PathBuf::from("api.py"), None);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::POST);
    }

    #[test]
    fn detects_depends_auth() {
        let src = "from fastapi import Depends\n@app.get('/me')\ndef me(user = Depends(get_current_user)): pass\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_fastapi_routes(&tree, &bytes, &PathBuf::from("api.py"), None);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert!(ep.auth_required);
    }
}

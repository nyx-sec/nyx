//! JavaScript / TypeScript + Koa framework probe.
//!
//! Koa apps register routes through `koa-router` (or `@koa/router`):
//! `router.get(path, handler)`, `router.post(path, ...middleware,
//! handler)`, etc.  The receiver is named `router`, `r`, or has a
//! `_router`/`Router` suffix.  Additional Koa-specific recognition:
//!
//! * `router.use('/path', subrouter.routes())` is *not* an
//!   entry-point — the inner middleware chain is.  Filtered by
//!   ignoring `use` for path-less middleware mounting.

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{leaf_matches, loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub use crate::auth_analysis::auth_markers::KOA_MIDDLEWARES as AUTH_MIDDLEWARES;

const VERBS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "options", "head", "all",
];

pub fn detect_koa_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_koa_call(call, bytes, &file_rel) {
            out.push(node);
        }
    });
    out
}

fn walk_calls<'tree, F: FnMut(Node<'tree>)>(node: Node<'tree>, visit: &mut F) {
    if matches!(node.kind(), "call_expression") {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_calls(child, visit);
    }
}

fn match_koa_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "member_expression" {
        return None;
    }
    let object = func.child_by_field_name("object")?;
    if !receiver_is_koa_router(object, bytes) {
        return None;
    }
    let prop = func.child_by_field_name("property")?;
    let prop_text = prop.utf8_text(bytes).ok()?;
    if !VERBS.contains(&prop_text) {
        return None;
    }
    let method = HttpMethod::from_ident(prop_text).unwrap_or(HttpMethod::GET);
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut positional: Vec<Node> = args.children(&mut cursor).collect();
    positional.retain(|n| n.kind() != "(" && n.kind() != ")" && n.kind() != ",");
    let route_idx = positional
        .iter()
        .position(|n| matches!(n.kind(), "string" | "template_string"))?;
    let route = string_node_value(positional[route_idx], bytes).unwrap_or_default();
    let handler_node = positional.iter().rev().find(|n| {
        matches!(
            n.kind(),
            "arrow_function"
                | "function"
                | "function_expression"
                | "function_declaration"
                | "identifier"
                | "member_expression"
        )
    })?;
    let auth_required = positional
        .iter()
        .filter(|n| !std::ptr::eq(*n, handler_node))
        .any(|n| arg_is_auth_marker(*n, bytes));
    let handler_name = handler_function_name(*handler_node, bytes).unwrap_or_default();
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Koa,
        method,
        route,
        handler_name,
        handler_location: SourceLocation::new(
            file_rel,
            (handler_node.start_position().row + 1) as u32,
            (handler_node.start_position().column + 1) as u32,
        ),
        auth_required,
    }))
}

fn handler_function_name(node: Node, bytes: &[u8]) -> Option<String> {
    if matches!(node.kind(), "identifier" | "member_expression") {
        return node.utf8_text(bytes).ok().map(str::to_string);
    }
    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(bytes)
    {
        return Some(name.to_string());
    }
    None
}

fn arg_is_auth_marker(node: Node, bytes: &[u8]) -> bool {
    match node.kind() {
        "identifier" | "member_expression" => node
            .utf8_text(bytes)
            .map(|t| leaf_matches(t, AUTH_MIDDLEWARES))
            .unwrap_or(false),
        "call_expression" => {
            let Some(callee) = node.child_by_field_name("function") else {
                return false;
            };
            let Ok(text) = callee.utf8_text(bytes) else {
                return false;
            };
            leaf_matches(text, AUTH_MIDDLEWARES)
        }
        _ => false,
    }
}

fn receiver_is_koa_router(object: Node, bytes: &[u8]) -> bool {
    fn name_matches(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower == "router" || lower == "r" || lower.ends_with("_router") || lower.ends_with("router")
    }
    match object.kind() {
        "identifier" => object.utf8_text(bytes).ok().is_some_and(name_matches),
        "member_expression" => object
            .child_by_field_name("property")
            .and_then(|p| p.utf8_text(bytes).ok())
            .is_some_and(name_matches),
        "call_expression" => {
            let Some(callee) = object.child_by_field_name("function") else {
                return false;
            };
            let Ok(text) = callee.utf8_text(bytes) else {
                return false;
            };
            let leaf = text.rsplit('.').next().unwrap_or(text);
            leaf == "Router" || leaf == "KoaRouter"
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_router_get() {
        let src = "const router = new Router();\nrouter.get('/users', async ctx => { ctx.body = []; });\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_koa_routes(&tree, &bytes, &PathBuf::from("server.js"), None);
        assert_eq!(nodes.len(), 1);
    }
}

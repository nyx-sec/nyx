//! Rust + axum framework probe.
//!
//! Detects axum route registration:
//!
//! * `Router::new().route("/path", get(handler))` /
//!   `.route("/path", post(handler))` / etc.
//! * Bare extractor-shaped function items in files that import axum
//!   (handler typing alone is treated as a candidate, but only when a
//!   `Router::route(...)` registration in the same file references it).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

const VERBS: &[(&str, HttpMethod)] = &[
    ("get", HttpMethod::GET),
    ("post", HttpMethod::POST),
    ("put", HttpMethod::PUT),
    ("delete", HttpMethod::DELETE),
    ("patch", HttpMethod::PATCH),
    ("head", HttpMethod::HEAD),
    ("options", HttpMethod::OPTIONS),
];

pub const AUTH_EXTRACTORS: &[&str] = &[
    "Extension<User",
    "BearerAuth",
    "RequireAuth",
    "AuthenticatedUser",
    "JwtClaims",
];

pub fn detect_axum_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_text = std::str::from_utf8(bytes).unwrap_or("");
    if !file_text.contains("axum::") && !file_text.contains("use axum") {
        return Vec::new();
    }
    let file_rel = rel_file(path, scan_root);
    let function_index = collect_functions(tree.root_node(), bytes);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_router_route(call, bytes, &file_rel, &function_index) {
            out.push(node);
        }
    });
    out
}

fn walk_calls<'tree, F: FnMut(Node<'tree>)>(node: Node<'tree>, visit: &mut F) {
    if node.kind() == "call_expression" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_calls(child, visit);
    }
}

fn collect_functions<'tree>(
    root: Node<'tree>,
    bytes: &'tree [u8],
) -> HashMap<String, (Node<'tree>, bool)> {
    let mut out: HashMap<String, (Node<'tree>, bool)> = HashMap::new();
    fn walk<'tree>(
        node: Node<'tree>,
        bytes: &'tree [u8],
        out: &mut HashMap<String, (Node<'tree>, bool)>,
    ) {
        if node.kind() == "function_item"
            && let Some(name_node) = node.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(bytes)
        {
            let auth = node
                .child_by_field_name("parameters")
                .and_then(|p| p.utf8_text(bytes).ok())
                .map(|t| AUTH_EXTRACTORS.iter().any(|x| t.contains(x)))
                .unwrap_or(false);
            out.insert(name.to_string(), (node, auth));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, bytes, out);
        }
    }
    walk(root, bytes, &mut out);
    out
}

fn match_router_route<'tree>(
    call: Node<'tree>,
    bytes: &[u8],
    file_rel: &str,
    function_index: &HashMap<String, (Node<'tree>, bool)>,
) -> Option<SurfaceNode> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "field_expression" {
        return None;
    }
    let field = func.child_by_field_name("field")?;
    if field.utf8_text(bytes).ok()? != "route" {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let positional: Vec<Node> = args
        .children(&mut cursor)
        .filter(|n| !matches!(n.kind(), "(" | ")" | ","))
        .collect();
    if positional.len() < 2 {
        return None;
    }
    let route = string_node_value(positional[0], bytes)?;
    let method_args = positional[1];
    if method_args.kind() != "call_expression" {
        return None;
    }
    let method_callee = method_args.child_by_field_name("function")?;
    let method_text = method_callee.utf8_text(bytes).ok()?;
    let leaf = method_text.rsplit("::").next().unwrap_or(method_text);
    let (_, method) = VERBS.iter().find(|(v, _)| *v == leaf)?;
    let method_args_node = method_args.child_by_field_name("arguments")?;
    let mut hcur = method_args_node.walk();
    let handler_node = method_args_node
        .children(&mut hcur)
        .find(|n| n.kind() == "identifier" || n.kind() == "scoped_identifier")?;
    let handler_name = handler_node.utf8_text(bytes).ok()?.to_string();
    let auth_required = function_index
        .get(&handler_name)
        .map(|(_, a)| *a)
        .unwrap_or(false);
    let handler_loc = function_index
        .get(&handler_name)
        .map(|(node, _)| {
            SourceLocation::new(
                file_rel,
                (node.start_position().row + 1) as u32,
                (node.start_position().column + 1) as u32,
            )
        })
        .unwrap_or_else(|| loc_for(handler_node, file_rel));
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Axum,
        method: *method,
        route,
        handler_name,
        handler_location: handler_loc,
        auth_required,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_router_get() {
        let src = r#"
use axum::{Router, routing::get};
async fn list_users() -> &'static str { "ok" }
fn app() -> Router {
    Router::new().route("/users", get(list_users))
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_axum_routes(&tree, &bytes, &PathBuf::from("main.rs"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }
}

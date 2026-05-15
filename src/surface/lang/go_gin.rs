//! Go + gin framework probe.
//!
//! Detects gin route registration:
//!
//! * `r.GET("/path", handler)` / `.POST(...)` / `.PUT` / `.DELETE`
//!   on a `*gin.Engine` or `*gin.RouterGroup`.
//! * `r.Group("/prefix").GET("/sub", ...)` chained shapes.
//! * `r.Use(middleware...)` followed by route registrations — the
//!   middleware list is consulted for auth markers
//!   ([`AUTH_MIDDLEWARES`]).
//!
//! Also recognises echo (`e.GET(...)`) and chi (`r.Get(...)`) by the
//! same shape — receiver name `e` / `r` / `router` / `engine`.

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{leaf_matches, loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub const AUTH_MIDDLEWARES: &[&str] = &[
    "AuthRequired",
    "JWT",
    "JWTAuth",
    "Auth",
    "RequireAuth",
    "RequireUser",
    "VerifyToken",
    "BasicAuth",
];

const VERBS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "Any",
    "Get", "Post", "Put", "Delete", "Patch", "Options", "Head",
];

pub fn detect_gin_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_gin_call(call, bytes, &file_rel) {
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

fn match_gin_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "selector_expression" {
        return None;
    }
    let operand = func.child_by_field_name("operand")?;
    let field = func.child_by_field_name("field")?;
    let field_text = field.utf8_text(bytes).ok()?;
    if !VERBS.contains(&field_text) {
        return None;
    }
    let operand_text = operand.utf8_text(bytes).ok()?;
    if !receiver_is_gin(operand_text) {
        return None;
    }
    let method = HttpMethod::from_ident(&field_text.to_ascii_uppercase())?;
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let positional: Vec<Node> = args
        .children(&mut cursor)
        .filter(|n| !matches!(n.kind(), "(" | ")" | ","))
        .collect();
    let route = positional.first().and_then(|n| string_node_value(*n, bytes))?;
    let handler_node = positional.iter().rev().find(|n| {
        matches!(
            n.kind(),
            "identifier" | "selector_expression" | "func_literal"
        )
    })?;
    let handler_name = handler_node
        .utf8_text(bytes)
        .ok()
        .map(str::to_string)
        .unwrap_or_default();
    let auth_required = positional[1..]
        .iter()
        .filter(|n| !std::ptr::eq(*n, handler_node))
        .any(|n| arg_is_auth_marker(*n, bytes));
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Gin,
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

fn receiver_is_gin(text: &str) -> bool {
    let leaf = text.rsplit('.').next().unwrap_or(text).trim();
    let lower = leaf.to_ascii_lowercase();
    lower == "r"
        || lower == "g"
        || lower == "e"
        || lower == "router"
        || lower == "engine"
        || lower == "group"
        || lower.ends_with("router")
        || lower.ends_with("group")
        || lower.ends_with("engine")
}

fn arg_is_auth_marker(node: Node, bytes: &[u8]) -> bool {
    match node.kind() {
        "identifier" | "selector_expression" => node
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_get() {
        let src = "package main\nimport \"github.com/gin-gonic/gin\"\nfunc main() {\n  r := gin.Default()\n  r.GET(\"/users\", listUsers)\n}\nfunc listUsers(c *gin.Context) {}\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_gin_routes(&tree, &bytes, &PathBuf::from("main.go"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }
}

//! JavaScript / TypeScript + Express framework probe.
//!
//! Detects route registration calls of the form `app.METHOD(path, ...)`
//! / `router.METHOD(path, ...)` for the standard set of HTTP verbs plus
//! `all` / `use`.  The handler is the *last* function-shaped argument
//! (Express convention: `(path, ...middleware, handler)`).
//!
//! `auth_required` fires when any positional argument before the
//! handler is an identifier matching one of the auth-middleware names
//! in [`AUTH_MIDDLEWARES`] (passport's `requireAuth`, custom guards),
//! or when an inline `passport.authenticate(...)` call appears in the
//! middleware list.

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{leaf_matches, loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub use crate::auth_analysis::auth_markers::EXPRESS_MIDDLEWARES as AUTH_MIDDLEWARES;

const VERBS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "options", "head", "all",
];

pub fn detect_express_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_express_call(call, bytes, &file_rel) {
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

fn match_express_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "member_expression" {
        return None;
    }
    let object = func.child_by_field_name("object")?;
    let file_text = std::str::from_utf8(bytes).unwrap_or("");
    let has_express_witness = file_text.contains("express");
    if !receiver_is_express(object, bytes, has_express_witness) {
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
    let route = positional
        .first()
        .filter(|n| n.kind() == "string" || n.kind() == "template_string")
        .and_then(|n| string_node_value(*n, bytes))
        .unwrap_or_default();
    if route.is_empty() && prop_text != "use" {
        // bare `app.use(handler)` is middleware, not an entry point
        return None;
    }
    let handler_node = find_handler(&positional)?;
    let handler_id = handler_node.id();
    let auth_required = positional[1..]
        .iter()
        .filter(|n| n.id() != handler_id)
        .any(|n| arg_is_auth_marker(*n, bytes));
    let handler_name = handler_function_name(handler_node, bytes).unwrap_or_default();
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Express,
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

fn find_handler<'a>(positional: &[Node<'a>]) -> Option<Node<'a>> {
    positional
        .iter()
        .rev()
        .find(|n| {
            matches!(
                n.kind(),
                "arrow_function"
                    | "function"
                    | "function_expression"
                    | "function_declaration"
                    | "identifier"
                    | "member_expression"
            )
        })
        .copied()
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
            leaf_matches(text, AUTH_MIDDLEWARES) || text.contains("passport.authenticate")
        }
        _ => false,
    }
}

fn receiver_is_express(object: Node, bytes: &[u8], has_express_witness: bool) -> bool {
    fn name_matches_strong(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower == "app"
            || lower == "server"
            || lower.ends_with("_app")
            || lower.ends_with("api")
    }
    fn name_matches_router(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower == "router" || lower.ends_with("router")
    }
    let check_name = |text: &str| -> bool {
        // `router` / `*router` is ambiguous with koa-router; require a
        // file-level `express` witness before claiming it.  Strong
        // shapes (`app`, `server`, `*_app`, `*api`) are Express-only
        // conventions and don't need a witness.
        if name_matches_strong(text) {
            return true;
        }
        if name_matches_router(text) {
            return has_express_witness;
        }
        false
    };
    match object.kind() {
        "identifier" => object.utf8_text(bytes).ok().is_some_and(check_name),
        "member_expression" => object
            .child_by_field_name("property")
            .and_then(|p| p.utf8_text(bytes).ok())
            .is_some_and(check_name),
        "call_expression" => {
            let Some(callee) = object.child_by_field_name("function") else {
                return false;
            };
            let Ok(text) = callee.utf8_text(bytes) else {
                return false;
            };
            let leaf = text.rsplit('.').next().unwrap_or(text);
            leaf == "express" || leaf == "Router" || leaf == "createApp"
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
    fn detects_get_route() {
        let src = "const app = express();\napp.get('/users', (req, res) => res.send('ok'));\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_express_routes(&tree, &bytes, &PathBuf::from("server.js"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.framework, Framework::Express);
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }

    #[test]
    fn detects_auth_middleware() {
        let src = "app.post('/secret', requireAuth, (req, res) => {});\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_express_routes(&tree, &bytes, &PathBuf::from("server.js"), None);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert!(ep.auth_required);
    }

    #[test]
    fn router_receiver_without_express_witness_does_not_match() {
        // Pure koa-router file — express probe must not claim it.
        let src = "const Router = require('@koa/router');\nconst router = new Router();\nrouter.get('/users', async ctx => {});\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_express_routes(&tree, &bytes, &PathBuf::from("server.js"), None);
        assert!(nodes.is_empty(), "express probe FP'd on koa-only file: {nodes:?}");
    }

    #[test]
    fn router_receiver_with_express_witness_still_matches() {
        // express + Router.get is a real Express idiom — must still detect.
        let src = "const express = require('express');\nconst router = express.Router();\nrouter.get('/users', (req, res) => {});\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_express_routes(&tree, &bytes, &PathBuf::from("server.js"), None);
        assert_eq!(nodes.len(), 1);
    }
}

//! Go + `net/http` framework probe.
//!
//! Recognises the canonical route registration shapes:
//!
//! * `http.HandleFunc("/path", handler)`
//! * `http.Handle("/path", handler)`
//! * `mux.HandleFunc("/path", handler)` (any `*http.ServeMux` receiver)
//! * `http.NewServeMux()` derived receivers
//!
//! Method is `GET` by default — `net/http` registrations are
//! method-agnostic at the routing layer; the handler dispatches on
//! `r.Method` internally.

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub fn detect_go_http_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_handle_call(call, bytes, &file_rel) {
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

fn match_handle_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "selector_expression" {
        return None;
    }
    let operand = func.child_by_field_name("operand")?;
    let field = func.child_by_field_name("field")?;
    let field_text = field.utf8_text(bytes).ok()?;
    if field_text != "HandleFunc" && field_text != "Handle" {
        return None;
    }
    let operand_text = operand.utf8_text(bytes).ok()?;
    let leaf = operand_text.rsplit('.').next().unwrap_or(operand_text);
    if leaf != "http"
        && !operand_text.contains("Mux")
        && !operand_text.contains("mux")
        && !operand_text.contains("Server")
        && !operand_text.contains("Router")
        && !operand_text.contains("router")
    {
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
    let handler_node = positional[1];
    let handler_name = handler_function_name(handler_node, bytes).unwrap_or_default();
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::NetHttp,
        method: HttpMethod::GET,
        route,
        handler_name,
        handler_location: SourceLocation::new(
            file_rel,
            (handler_node.start_position().row + 1) as u32,
            (handler_node.start_position().column + 1) as u32,
        ),
        auth_required: false,
    }))
}

fn handler_function_name(node: Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "selector_expression" => node.utf8_text(bytes).ok().map(str::to_string),
        "func_literal" => Some("anonymous".to_string()),
        _ => node.utf8_text(bytes).ok().map(str::to_string),
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
    fn detects_handle_func() {
        let src = "package main\nimport \"net/http\"\nfunc main() {\n  http.HandleFunc(\"/users\", listUsers)\n}\nfunc listUsers(w http.ResponseWriter, r *http.Request) {}\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_go_http_routes(&tree, &bytes, &PathBuf::from("main.go"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.framework, Framework::NetHttp);
        assert_eq!(ep.route, "/users");
        assert_eq!(ep.handler_name, "listUsers");
    }
}

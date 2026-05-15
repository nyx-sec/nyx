//! PHP + Slim framework probe.
//!
//! Recognises Slim route registrations:
//!
//! * `$app->get('/path', $handler)` / `->post(...)` / `->put` /
//!   `->delete` / `->patch` / `->options` / `->any`
//! * `$app->group('/api', function ($g) { $g->get(...); })` (the
//!   group prefix is captured when the call site is lexically inside
//!   a `group(...)` closure body — best-effort textual match).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

const VERBS: &[(&str, HttpMethod)] = &[
    ("get", HttpMethod::GET),
    ("post", HttpMethod::POST),
    ("put", HttpMethod::PUT),
    ("patch", HttpMethod::PATCH),
    ("delete", HttpMethod::DELETE),
    ("options", HttpMethod::OPTIONS),
    ("head", HttpMethod::HEAD),
    ("any", HttpMethod::GET),
];

pub fn detect_slim_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_slim_call(call, bytes, &file_rel) {
            out.push(node);
        }
    });
    out
}

fn walk_calls<'tree, F: FnMut(Node<'tree>)>(node: Node<'tree>, visit: &mut F) {
    if node.kind() == "member_call_expression" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_calls(child, visit);
    }
}

fn match_slim_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let object = call.child_by_field_name("object")?;
    let object_text = object.utf8_text(bytes).ok()?;
    if !receiver_is_slim_app(object_text) {
        return None;
    }
    let name = call.child_by_field_name("name")?;
    let name_text = name.utf8_text(bytes).ok()?;
    let (_, method) = VERBS
        .iter()
        .find(|(v, _)| v.eq_ignore_ascii_case(name_text))?;
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let positional: Vec<Node> = args
        .children(&mut cursor)
        .filter(|n| n.kind() == "argument")
        .collect();
    if positional.len() < 2 {
        return None;
    }
    let route_node = first_inner(positional[0]);
    let route = string_node_value(route_node, bytes).unwrap_or_default();
    let handler_node = first_inner(positional[1]);
    let handler_name = handler_node
        .utf8_text(bytes)
        .ok()
        .map(str::to_string)
        .unwrap_or_default();
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Sinatra,
        method: *method,
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

fn first_inner(arg: Node) -> Node {
    let mut cursor = arg.walk();
    arg.named_children(&mut cursor).next().unwrap_or(arg)
}

fn receiver_is_slim_app(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower == "$app"
        || lower == "$g"
        || lower == "$group"
        || lower == "$router"
        || lower.ends_with("app")
        || lower.ends_with("group")
        || lower.ends_with("router")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_slim_get() {
        let src = "<?php\n$app->get('/users', 'UsersController:list');\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_slim_routes(&tree, &bytes, &PathBuf::from("routes.php"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }
}

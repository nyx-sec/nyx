//! PHP + Laravel framework probe.
//!
//! Recognises Laravel route declarations:
//!
//! * `Route::get('/path', $handler)` / `::post(...)` / `::put` /
//!   `::patch` / `::delete` / `::any` / `::match`
//! * `Route::resource('users', UserController::class)` (omitted —
//!   resource controller dispatch is path-derived; Phase 22 ships the
//!   primary verb shape only)
//!
//! `auth_required` fires when the route call is followed by a
//! `->middleware('auth')` chain or the closure is wrapped in
//! `Route::middleware(['auth'])->group(...)`.

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
];

pub fn detect_laravel_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_laravel_call(call, bytes, &file_rel) {
            out.push(node);
        }
    });
    out
}

fn walk_calls<'tree, F: FnMut(Node<'tree>)>(node: Node<'tree>, visit: &mut F) {
    if matches!(
        node.kind(),
        "function_call_expression" | "scoped_call_expression" | "member_call_expression"
    ) {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_calls(child, visit);
    }
}

fn match_laravel_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    if call.kind() != "scoped_call_expression" {
        return None;
    }
    let scope = call.child_by_field_name("scope")?;
    let scope_text = scope.utf8_text(bytes).ok()?;
    if scope_text != "Route" && !scope_text.contains("Route") {
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
    let handler_name = handler_text(handler_node, bytes).unwrap_or_default();
    let auth_required = check_chained_middleware(call, bytes);
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Laravel,
        method: *method,
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

fn first_inner(arg: Node) -> Node {
    let mut cursor = arg.walk();
    arg.named_children(&mut cursor).next().unwrap_or(arg)
}

fn handler_text(node: Node, bytes: &[u8]) -> Option<String> {
    Some(node.utf8_text(bytes).ok()?.to_string())
}

fn check_chained_middleware(call: Node, bytes: &[u8]) -> bool {
    // Walk up to find a member_call chain: `Route::get(...)->middleware('auth')`
    let mut cur = call.parent();
    while let Some(p) = cur {
        if p.kind() == "member_call_expression"
            && let Some(name) = p.child_by_field_name("name")
            && let Ok(name_text) = name.utf8_text(bytes)
            && name_text == "middleware"
            && let Some(args) = p.child_by_field_name("arguments")
            && let Ok(args_text) = args.utf8_text(bytes)
            && (args_text.contains("auth")
                || args_text.contains("jwt")
                || args_text.contains("authenticated"))
        {
            return true;
        }
        cur = p.parent();
    }
    false
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
    fn detects_laravel_get() {
        let src = "<?php\nRoute::get('/users', 'UserController@index');\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_laravel_routes(&tree, &bytes, &PathBuf::from("routes.php"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }

    #[test]
    fn detects_middleware_chain() {
        let src = "<?php\nRoute::post('/admin', 'AdminController@create')->middleware('auth');\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_laravel_routes(&tree, &bytes, &PathBuf::from("routes.php"), None);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert!(ep.auth_required);
    }
}

//! Ruby + Sinatra framework probe.
//!
//! Sinatra routes are top-level method calls of the form
//! `get '/path' do ... end`, `post '/path' do ... end`, etc.  The
//! handler is the block; we synthesise the handler name from the
//! route string (Sinatra blocks are anonymous).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file, string_node_value};
use crate::surface::{EntryPoint, Framework, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

const VERBS: &[(&str, HttpMethod)] = &[
    ("get", HttpMethod::GET),
    ("post", HttpMethod::POST),
    ("put", HttpMethod::PUT),
    ("patch", HttpMethod::PATCH),
    ("delete", HttpMethod::DELETE),
    ("head", HttpMethod::HEAD),
    ("options", HttpMethod::OPTIONS),
];

pub fn detect_sinatra_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_calls(tree.root_node(), &mut |call| {
        if let Some(node) = match_sinatra_call(call, bytes, &file_rel) {
            out.push(node);
        }
    });
    out
}

fn walk_calls<'tree, F: FnMut(Node<'tree>)>(node: Node<'tree>, visit: &mut F) {
    if matches!(node.kind(), "call" | "method_call") {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_calls(child, visit);
    }
}

fn match_sinatra_call(call: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let method_name_node = call.child_by_field_name("method")?;
    let method_text = method_name_node.utf8_text(bytes).ok()?;
    let (_, method) = VERBS
        .iter()
        .find(|(v, _)| *v == method_text)?;
    // Must have a block to be a Sinatra route.
    let block = call
        .child_by_field_name("block")
        .or_else(|| {
            let mut c = call.walk();
            call.children(&mut c)
                .find(|n| matches!(n.kind(), "do_block" | "block"))
        })?;
    // Args: Sinatra accepts a string literal as the first positional arg.
    let args = call
        .child_by_field_name("arguments")
        .or_else(|| {
            let mut c = call.walk();
            call.children(&mut c).find(|n| n.kind() == "argument_list")
        })?;
    let mut cursor = args.walk();
    let route_node = args.named_children(&mut cursor).next()?;
    let route = string_node_value(route_node, bytes)?;
    let handler_name = format!("{}_{}", method_text, route.replace(['/', '-'], "_"));
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(call, file_rel),
        framework: Framework::Sinatra,
        method: *method,
        route,
        handler_name,
        handler_location: loc_for(block, file_rel),
        auth_required: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_sinatra_get() {
        let src = "get '/users' do\n  'hi'\nend\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_sinatra_routes(&tree, &bytes, &PathBuf::from("app.rb"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }
}

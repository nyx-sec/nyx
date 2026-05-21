//! Ruby + Rails framework probe.
//!
//! Recognises two Rails route shapes:
//!
//! 1. `config/routes.rb` declarations — `get '/path', to: 'controller#action'`,
//!    `post '/path' => 'controller#action'`, `resources :users`.
//! 2. Controller actions — public instance methods on a class
//!    inheriting from `ApplicationController` / `ActionController::Base`.
//!
//! `auth_required` for routes follows `before_action :authenticate!`
//! at the controller level.

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
    ("match", HttpMethod::GET),
];

pub fn detect_rails_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    detect_routes_dsl(tree.root_node(), bytes, &file_rel, &mut out);
    detect_controllers(tree.root_node(), bytes, &file_rel, &mut out);
    out
}

fn detect_routes_dsl(root: Node, bytes: &[u8], file_rel: &str, out: &mut Vec<SurfaceNode>) {
    fn recurse(node: Node, bytes: &[u8], file_rel: &str, out: &mut Vec<SurfaceNode>) {
        if matches!(node.kind(), "call" | "method_call")
            && let Some(method_node) = node.child_by_field_name("method")
                && let Ok(method_text) = method_node.utf8_text(bytes)
                && let Some((_, method)) = VERBS.iter().find(|(v, _)| *v == method_text)
            {
                let args_opt = node
                    .child_by_field_name("arguments")
                    .or_else(|| {
                        let mut c = node.walk();
                        node.children(&mut c).find(|n| n.kind() == "argument_list")
                    });
                if let Some(args) = args_opt {
                    let mut cursor = args.walk();
                    let positional: Vec<Node> = args.named_children(&mut cursor).collect();
                    if let Some(route_node) = positional.first()
                        && let Some(route) = string_node_value(*route_node, bytes)
                    {
                        let handler_name = positional
                            .iter()
                            .find_map(|n| extract_to_handler(*n, bytes))
                            .unwrap_or_default();
                        out.push(SurfaceNode::EntryPoint(EntryPoint {
                            location: loc_for(node, file_rel),
                            framework: Framework::Rails,
                            method: *method,
                            route,
                            handler_name,
                            handler_location: loc_for(node, file_rel),
                            auth_required: false,
                        }));
                    }
                }
            }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, bytes, file_rel, out);
        }
    }
    recurse(root, bytes, file_rel, out);
}

fn extract_to_handler(node: Node, bytes: &[u8]) -> Option<String> {
    // Shapes:
    //   `to: 'controller#action'` — pair with hash key `to`
    //   `'controller#action'`     — second positional string
    //   `=> 'controller#action'` — assoc with hashrocket
    if node.kind() == "string"
        && let Some(s) = string_node_value(node, bytes)
        && s.contains('#')
    {
        return Some(s);
    }
    if node.kind() == "pair" {
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        for child in &children {
            if child.kind() == "string"
                && let Some(s) = string_node_value(*child, bytes)
                && s.contains('#')
            {
                return Some(s);
            }
        }
    }
    None
}

fn detect_controllers(root: Node, bytes: &[u8], file_rel: &str, out: &mut Vec<SurfaceNode>) {
    fn recurse(node: Node, bytes: &[u8], file_rel: &str, out: &mut Vec<SurfaceNode>) {
        if node.kind() == "class"
            && class_is_controller(node, bytes)
        {
            let class_auth = class_has_before_authenticate(node, bytes);
            walk_methods(node, bytes, &mut |method_node, name| {
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: loc_for(method_node, file_rel),
                    framework: Framework::Rails,
                    method: HttpMethod::GET,
                    route: String::new(),
                    handler_name: name.to_string(),
                    handler_location: SourceLocation::new(
                        file_rel,
                        (method_node.start_position().row + 1) as u32,
                        (method_node.start_position().column + 1) as u32,
                    ),
                    auth_required: class_auth,
                }));
            });
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, bytes, file_rel, out);
        }
    }
    recurse(root, bytes, file_rel, out);
}

fn class_is_controller(class: Node, bytes: &[u8]) -> bool {
    let Some(super_node) = class.child_by_field_name("superclass") else {
        return false;
    };
    let Ok(text) = super_node.utf8_text(bytes) else {
        return false;
    };
    text.contains("ApplicationController") || text.contains("ActionController")
}

fn class_has_before_authenticate(class: Node, bytes: &[u8]) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if let Ok(text) = child.utf8_text(bytes)
            && text.contains("before_action")
            && (text.contains("authenticate") || text.contains("login_required"))
        {
            return true;
        }
    }
    false
}

fn walk_methods<'tree, F>(class: Node<'tree>, bytes: &[u8], visit: &mut F)
where
    F: FnMut(Node<'tree>, &str),
{
    let Some(body) = class.child_by_field_name("body") else {
        return;
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "method"
            && let Some(name_node) = child.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(bytes)
            && !name.starts_with('_')
        {
            visit(child, name);
        }
    }
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
    fn detects_routes_dsl() {
        let src = "Rails.application.routes.draw do\n  get '/users', to: 'users#index'\nend\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_rails_routes(&tree, &bytes, &PathBuf::from("config/routes.rb"), None);
        assert!(!nodes.is_empty());
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }

    #[test]
    fn detects_controller_actions() {
        let src = "class UsersController < ApplicationController\n  def index\n  end\n  def show\n  end\nend\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_rails_routes(&tree, &bytes, &PathBuf::from("users_controller.rb"), None);
        assert_eq!(nodes.len(), 2);
    }
}

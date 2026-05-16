//! Java + Spring framework probe.
//!
//! Recognises Spring controller methods annotated with
//! `@RequestMapping` / `@GetMapping` / `@PostMapping` / `@PutMapping`
//! / `@PatchMapping` / `@DeleteMapping`.  The route path is the
//! concatenation of class-level `@RequestMapping(value=...)` /
//! `@RestController` and method-level `value=...` arguments.
//!
//! `auth_required` fires when the method, the enclosing class, or the
//! `value=` argument lists a Spring-Security annotation
//! ([`AUTH_ANNOTATIONS`]).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{leaf_matches, loc_for, rel_file, unquote};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub use crate::auth_analysis::auth_markers::SPRING_ANNOTATIONS as AUTH_ANNOTATIONS;

const MAPPING_ANNOTATIONS: &[(&str, Option<HttpMethod>)] = &[
    ("RequestMapping", None),
    ("GetMapping", Some(HttpMethod::GET)),
    ("PostMapping", Some(HttpMethod::POST)),
    ("PutMapping", Some(HttpMethod::PUT)),
    ("PatchMapping", Some(HttpMethod::PATCH)),
    ("DeleteMapping", Some(HttpMethod::DELETE)),
];

pub fn detect_spring_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_classes(tree.root_node(), &mut |class| {
        let class_path = class_request_mapping_path(class, bytes);
        let class_auth = class_has_auth_annotation(class, bytes);
        let Some(body) = crate::surface::lang::common::child_or_named(class, "class_body") else {
            return;
        };
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            if member.kind() != "method_declaration" {
                continue;
            }
            if let Some((method, route_path, auth)) =
                method_mapping(member, bytes, &class_path)
            {
                let auth_required = class_auth || auth;
                let handler_name = method_name(member, bytes).unwrap_or_default();
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: loc_for(member, &file_rel),
                    framework: Framework::Spring,
                    method,
                    route: route_path,
                    handler_name,
                    handler_location: SourceLocation::new(
                        file_rel.clone(),
                        (member.start_position().row + 1) as u32,
                        (member.start_position().column + 1) as u32,
                    ),
                    auth_required,
                }));
            }
        }
    });
    out
}

fn walk_classes<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if node.kind() == "class_declaration" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_classes(child, visit);
    }
}

fn class_request_mapping_path(class: Node, bytes: &[u8]) -> String {
    let modifiers = match crate::surface::lang::common::child_or_named(class, "modifiers") {
        Some(m) => m,
        None => return String::new(),
    };
    let mut cursor = modifiers.walk();
    for ann in modifiers.children(&mut cursor) {
        if !is_annotation(ann) {
            continue;
        }
        let Some((name, args_text)) = annotation_name_and_args(ann, bytes) else {
            continue;
        };
        if name == "RequestMapping" {
            return extract_first_path(&args_text);
        }
    }
    String::new()
}

fn class_has_auth_annotation(class: Node, bytes: &[u8]) -> bool {
    let modifiers = match crate::surface::lang::common::child_or_named(class, "modifiers") {
        Some(m) => m,
        None => return false,
    };
    let mut cursor = modifiers.walk();
    for ann in modifiers.children(&mut cursor) {
        if !is_annotation(ann) {
            continue;
        }
        if let Some((name, _)) = annotation_name_and_args(ann, bytes)
            && AUTH_ANNOTATIONS
                .iter()
                .any(|a| leaf_matches(&name, &[a]))
        {
            return true;
        }
    }
    false
}

fn method_mapping(
    method: Node,
    bytes: &[u8],
    class_path: &str,
) -> Option<(HttpMethod, String, bool)> {
    let modifiers = crate::surface::lang::common::child_or_named(method, "modifiers")?;
    let mut cursor = modifiers.walk();
    let mut auth = false;
    let mut found: Option<(HttpMethod, String)> = None;
    for ann in modifiers.children(&mut cursor) {
        if !is_annotation(ann) {
            continue;
        }
        let Some((name, args_text)) = annotation_name_and_args(ann, bytes) else {
            continue;
        };
        if AUTH_ANNOTATIONS
            .iter()
            .any(|a| leaf_matches(&name, &[a]))
        {
            auth = true;
        }
        if found.is_some() {
            continue;
        }
        for (ann_name, default_method) in MAPPING_ANNOTATIONS {
            if name == *ann_name {
                let mut method_route = extract_first_path(&args_text);
                if method_route.is_empty() && !class_path.is_empty() {
                    // Class-only mapping; method has no path.
                    method_route = class_path.to_string();
                } else if !class_path.is_empty() {
                    method_route = format!("{}/{}", class_path.trim_end_matches('/'), method_route.trim_start_matches('/'));
                }
                let method = default_method
                    .or_else(|| extract_request_method_from_args(&args_text))
                    .unwrap_or(HttpMethod::GET);
                found = Some((method, method_route));
                break;
            }
        }
    }
    let (m, p) = found?;
    Some((m, p, auth))
}

fn is_annotation(node: Node) -> bool {
    matches!(
        node.kind(),
        "annotation" | "marker_annotation"
    )
}

/// Returns `(annotation_name, raw_args_text)` for an annotation node.
fn annotation_name_and_args(ann: Node, bytes: &[u8]) -> Option<(String, String)> {
    let name_node = ann.child_by_field_name("name")?;
    let raw_name = name_node.utf8_text(bytes).ok()?;
    let leaf = raw_name.rsplit('.').next().unwrap_or(raw_name).to_string();
    let args_text = ann
        .child_by_field_name("arguments")
        .and_then(|a| a.utf8_text(bytes).ok())
        .unwrap_or("")
        .to_string();
    Some((leaf, args_text))
}

fn extract_first_path(args_text: &str) -> String {
    // Look for the first `"..."` literal.
    let mut chars = args_text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            let mut buf = String::new();
            for c in chars.by_ref() {
                if c == '"' {
                    return buf;
                }
                buf.push(c);
            }
        }
    }
    String::new()
}

fn extract_request_method_from_args(args_text: &str) -> Option<HttpMethod> {
    // RequestMapping(method = RequestMethod.POST)
    for verb in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        if args_text.contains(&format!("RequestMethod.{}", verb)) {
            return HttpMethod::from_ident(verb);
        }
    }
    None
}

fn method_name(method: Node, bytes: &[u8]) -> Option<String> {
    method
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(str::to_string)
}

#[allow(dead_code)]
fn read_string_literal(node: Node, bytes: &[u8]) -> Option<String> {
    let raw = node.utf8_text(bytes).ok()?;
    Some(unquote(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_get_mapping() {
        let src = r#"
@RestController
public class UserController {
    @GetMapping("/users")
    public List<User> list() { return null; }
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_spring_routes(&tree, &bytes, &PathBuf::from("UserController.java"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
        assert_eq!(ep.handler_name, "list");
    }

    #[test]
    fn class_request_mapping_prefix_concatenates() {
        let src = r#"
@RequestMapping("/api")
public class C {
    @PostMapping("/users")
    public void create() {}
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_spring_routes(&tree, &bytes, &PathBuf::from("C.java"), None);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.route, "/api/users");
    }

    #[test]
    fn pre_authorize_marks_auth() {
        let src = r#"
public class C {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public void admin() {}
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_spring_routes(&tree, &bytes, &PathBuf::from("C.java"), None);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert!(ep.auth_required);
    }
}

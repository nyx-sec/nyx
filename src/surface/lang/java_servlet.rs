//! Java + Servlet (JAX-RS / Jakarta REST) framework probe.
//!
//! Recognises:
//!
//! * `@WebServlet("/path")` annotated `HttpServlet` subclasses — every
//!   `doGet` / `doPost` / `doPut` / `doDelete` method is one entry-point.
//! * `@Path("/path")` annotated JAX-RS resource methods with verb
//!   annotation `@GET` / `@POST` / `@PUT` / `@DELETE` / `@PATCH`.
//!
//! Auth markers: `@DenyAll`, `@RolesAllowed`, `@PermitAll` — the
//! presence of any of these implies a security configuration is
//! actively gating the resource (we report `auth_required = true`
//! conservatively for `@RolesAllowed` and `@DenyAll`).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub use crate::auth_analysis::auth_markers::SERVLET_ANNOTATIONS as AUTH_ANNOTATIONS;

const SERVLET_VERBS: &[(&str, HttpMethod)] = &[
    ("doGet", HttpMethod::GET),
    ("doPost", HttpMethod::POST),
    ("doPut", HttpMethod::PUT),
    ("doDelete", HttpMethod::DELETE),
    ("doHead", HttpMethod::HEAD),
    ("doOptions", HttpMethod::OPTIONS),
];

const JAXRS_VERBS: &[(&str, HttpMethod)] = &[
    ("GET", HttpMethod::GET),
    ("POST", HttpMethod::POST),
    ("PUT", HttpMethod::PUT),
    ("DELETE", HttpMethod::DELETE),
    ("PATCH", HttpMethod::PATCH),
    ("HEAD", HttpMethod::HEAD),
    ("OPTIONS", HttpMethod::OPTIONS),
];

pub fn detect_servlet_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_classes(tree.root_node(), &mut |class| {
        let class_path_servlet = class_web_servlet_path(class, bytes);
        let class_path_jaxrs = class_jaxrs_path(class, bytes);
        let class_auth = class_has_auth_annotation(class, bytes);
        let Some(body) = crate::surface::lang::common::child_or_named(class, "class_body") else {
            return;
        };
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            if member.kind() != "method_declaration" {
                continue;
            }
            let name = method_name(member, bytes).unwrap_or_default();

            // HttpServlet shape
            if let Some(class_path) = class_path_servlet.as_deref()
                && let Some((_, method)) = SERVLET_VERBS
                    .iter()
                    .find(|(verb, _)| *verb == name.as_str())
            {
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: loc_for(member, &file_rel),
                    framework: Framework::JaxRs,
                    method: *method,
                    route: class_path.to_string(),
                    handler_name: name.clone(),
                    handler_location: SourceLocation::new(
                        file_rel.clone(),
                        (member.start_position().row + 1) as u32,
                        (member.start_position().column + 1) as u32,
                    ),
                    auth_required: class_auth,
                }));
                continue;
            }

            // JAX-RS shape
            if let Some((method, method_path, method_auth)) =
                jaxrs_method_mapping(member, bytes, class_path_jaxrs.as_deref().unwrap_or(""))
            {
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: loc_for(member, &file_rel),
                    framework: Framework::JaxRs,
                    method,
                    route: method_path,
                    handler_name: name,
                    handler_location: SourceLocation::new(
                        file_rel.clone(),
                        (member.start_position().row + 1) as u32,
                        (member.start_position().column + 1) as u32,
                    ),
                    auth_required: class_auth || method_auth,
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

fn class_web_servlet_path(class: Node, bytes: &[u8]) -> Option<String> {
    annotation_string_arg(class, bytes, "WebServlet")
}

fn class_jaxrs_path(class: Node, bytes: &[u8]) -> Option<String> {
    annotation_string_arg(class, bytes, "Path")
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
        if let Some(name) = annotation_name(ann, bytes)
            && AUTH_ANNOTATIONS.iter().any(|a| {
                name.rsplit('.')
                    .next()
                    .unwrap_or(&name)
                    .eq_ignore_ascii_case(a)
            })
        {
            return true;
        }
    }
    false
}

fn jaxrs_method_mapping(
    method: Node,
    bytes: &[u8],
    class_path: &str,
) -> Option<(HttpMethod, String, bool)> {
    let modifiers = crate::surface::lang::common::child_or_named(method, "modifiers")?;
    let mut cursor = modifiers.walk();
    let mut verb: Option<HttpMethod> = None;
    let mut method_path = String::new();
    let mut auth = false;
    for ann in modifiers.children(&mut cursor) {
        if !is_annotation(ann) {
            continue;
        }
        let Some(name) = annotation_name(ann, bytes) else {
            continue;
        };
        let leaf = name.rsplit('.').next().unwrap_or(&name);
        if let Some((_, m)) = JAXRS_VERBS
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(leaf))
        {
            verb = Some(*m);
        }
        if leaf == "Path"
            && let Some(path) = annotation_string_arg_from_node(ann, bytes)
        {
            method_path = path;
        }
        if AUTH_ANNOTATIONS
            .iter()
            .any(|a| leaf.eq_ignore_ascii_case(a))
        {
            auth = true;
        }
    }
    let v = verb?;
    let combined = if class_path.is_empty() {
        method_path
    } else if method_path.is_empty() {
        class_path.to_string()
    } else {
        format!(
            "{}/{}",
            class_path.trim_end_matches('/'),
            method_path.trim_start_matches('/')
        )
    };
    Some((v, combined, auth))
}

fn annotation_string_arg(class: Node, bytes: &[u8], target_name: &str) -> Option<String> {
    let modifiers = crate::surface::lang::common::child_or_named(class, "modifiers")?;
    let mut cursor = modifiers.walk();
    for ann in modifiers.children(&mut cursor) {
        if !is_annotation(ann) {
            continue;
        }
        let Some(name) = annotation_name(ann, bytes) else {
            continue;
        };
        let leaf = name.rsplit('.').next().unwrap_or(&name);
        if leaf == target_name {
            return annotation_string_arg_from_node(ann, bytes);
        }
    }
    None
}

fn annotation_string_arg_from_node(ann: Node, bytes: &[u8]) -> Option<String> {
    let args = ann.child_by_field_name("arguments")?;
    let raw = args.utf8_text(bytes).ok()?;
    let start = raw.find('"')? + 1;
    let end = raw[start..].find('"')? + start;
    Some(raw[start..end].to_string())
}

fn annotation_name(ann: Node, bytes: &[u8]) -> Option<String> {
    ann.child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(str::to_string)
}

fn method_name(method: Node, bytes: &[u8]) -> Option<String> {
    method
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(str::to_string)
}

fn is_annotation(node: Node) -> bool {
    matches!(node.kind(), "annotation" | "marker_annotation")
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
    fn detects_jaxrs_get() {
        let src = r#"
@Path("/users")
public class UsersResource {
    @GET
    @Path("/{id}")
    public User get() { return null; }
}
"#;
        let (tree, bytes) = parse(src);
        let nodes =
            detect_servlet_routes(&tree, &bytes, &PathBuf::from("UsersResource.java"), None);
        assert!(!nodes.is_empty());
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users/{id}");
    }

    #[test]
    fn detects_servlet_doget() {
        let src = r#"
@WebServlet("/admin")
public class Admin extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) {}
    public void doPost(HttpServletRequest req, HttpServletResponse resp) {}
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_servlet_routes(&tree, &bytes, &PathBuf::from("Admin.java"), None);
        assert_eq!(nodes.len(), 2);
    }
}

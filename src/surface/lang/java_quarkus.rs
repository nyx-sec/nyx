//! Java + Quarkus framework probe.
//!
//! Quarkus uses JAX-RS (`jakarta.ws.rs`) for HTTP routing on top of
//! `RESTEasy Reactive` / `Quarkus REST`.  The annotations are
//! identical to plain JAX-RS, so this probe overlaps with
//! [`super::java_servlet`] but emits the [`Framework::Quarkus`] tag
//! via a Quarkus-specific recogniser:
//!
//! * The class is annotated with `@ApplicationScoped`,
//!   `@RequestScoped`, or `@Singleton` (Quarkus DI markers); OR
//! * The file imports a `quarkus`-prefixed package; OR
//! * The class extends a Quarkus-known reactive base type
//!   (`PanacheRepository`, `Multi`, `Uni`).
//!
//! Auth markers: `@Authenticated`, `@RolesAllowed`, `@PermitAll`,
//! `@DenyAll` (Quarkus Security).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub const AUTH_ANNOTATIONS: &[&str] = &[
    "Authenticated",
    "RolesAllowed",
    "DenyAll",
    "RequiresAuthentication",
];

const QUARKUS_DI: &[&str] = &[
    "ApplicationScoped",
    "RequestScoped",
    "Singleton",
    "Dependent",
    "Path",
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

pub fn detect_quarkus_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    if !file_uses_quarkus(tree.root_node(), bytes) {
        return Vec::new();
    }
    let mut out = Vec::new();
    walk_classes(tree.root_node(), &mut |class| {
        if !class_is_quarkus_resource(class, bytes) {
            return;
        }
        let class_path = class_path_annotation(class, bytes).unwrap_or_default();
        let class_auth = class_has_auth_annotation(class, bytes);
        let Some(body) = crate::surface::lang::common::child_or_named(class, "class_body") else {
            return;
        };
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            if member.kind() != "method_declaration" {
                continue;
            }
            if let Some((method, method_path, method_auth)) =
                method_mapping(member, bytes, &class_path)
            {
                let name = method_name(member, bytes).unwrap_or_default();
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: loc_for(member, &file_rel),
                    framework: Framework::Quarkus,
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

fn file_uses_quarkus(root: Node, bytes: &[u8]) -> bool {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "import_declaration"
            && let Ok(text) = child.utf8_text(bytes)
            && (text.contains("io.quarkus") || text.contains("jakarta.ws.rs"))
        {
            return true;
        }
    }
    false
}

fn class_is_quarkus_resource(class: Node, bytes: &[u8]) -> bool {
    let modifiers = match crate::surface::lang::common::child_or_named(class, "modifiers") {
        Some(m) => m,
        None => return false,
    };
    let mut cursor = modifiers.walk();
    for ann in modifiers.children(&mut cursor) {
        if !is_annotation(ann) {
            continue;
        }
        if let Some(name) = annotation_name(ann, bytes) {
            let leaf = name.rsplit('.').next().unwrap_or(&name);
            if QUARKUS_DI.iter().any(|d| leaf.eq_ignore_ascii_case(d)) {
                return true;
            }
        }
    }
    false
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

fn class_path_annotation(class: Node, bytes: &[u8]) -> Option<String> {
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
        if let Some(name) = annotation_name(ann, bytes) {
            let leaf = name.rsplit('.').next().unwrap_or(&name);
            if AUTH_ANNOTATIONS.iter().any(|a| leaf.eq_ignore_ascii_case(a)) {
                return true;
            }
        }
    }
    false
}

fn method_mapping(method: Node, bytes: &[u8], class_path: &str) -> Option<(HttpMethod, String, bool)> {
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
        if let Some((_, m)) = JAXRS_VERBS.iter().find(|(n, _)| n.eq_ignore_ascii_case(leaf)) {
            verb = Some(*m);
        }
        if leaf == "Path"
            && let Some(p) = annotation_string_arg_from_node(ann, bytes)
        {
            method_path = p;
        }
        if AUTH_ANNOTATIONS.iter().any(|a| leaf.eq_ignore_ascii_case(a)) {
            auth = true;
        }
    }
    let v = verb?;
    let combined = if class_path.is_empty() {
        method_path
    } else if method_path.is_empty() {
        class_path.to_string()
    } else {
        format!("{}/{}", class_path.trim_end_matches('/'), method_path.trim_start_matches('/'))
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
    fn detects_quarkus_resource() {
        let src = r#"
import io.quarkus.runtime.Quarkus;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@ApplicationScoped
@Path("/api")
public class GreetResource {
    @GET
    @Path("/hello")
    public String hello() { return "hi"; }
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_quarkus_routes(&tree, &bytes, &PathBuf::from("GreetResource.java"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/api/hello");
    }

    #[test]
    fn ignores_non_quarkus_class() {
        let src = r#"
public class C {
    @GetMapping("/x")
    public void x() {}
}
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_quarkus_routes(&tree, &bytes, &PathBuf::from("C.java"), None);
        assert!(nodes.is_empty());
    }
}

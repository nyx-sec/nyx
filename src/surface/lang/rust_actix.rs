//! Rust + actix-web framework probe.
//!
//! Recognises actix-web routing macros (`#[get("/path")]`,
//! `#[post("/path")]`, `#[put]`, `#[delete]`, `#[patch]`, `#[head]`,
//! `#[options]`, `#[route("/path", method = ...)]`) attached to a
//! `function_item`.  The route path is extracted from the macro
//! argument string literal.
//!
//! `auth_required` fires when the function signature has a parameter
//! whose type matches one of [`AUTH_EXTRACTORS`] (`Identity`,
//! `BearerAuth`, `JwtClaims`, etc.).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file, rust_uses_any};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub use crate::auth_analysis::auth_markers::ACTIX_EXTRACTORS as AUTH_EXTRACTORS;

const ROUTE_MACROS: &[(&str, Option<HttpMethod>)] = &[
    ("get", Some(HttpMethod::GET)),
    ("post", Some(HttpMethod::POST)),
    ("put", Some(HttpMethod::PUT)),
    ("delete", Some(HttpMethod::DELETE)),
    ("patch", Some(HttpMethod::PATCH)),
    ("head", Some(HttpMethod::HEAD)),
    ("options", Some(HttpMethod::OPTIONS)),
    ("route", None),
];

pub fn detect_actix_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    // Phase 23 follow-up: gate on a real top-level `use actix_web…` /
    // `extern crate actix_web` so a comment or string literal
    // mentioning actix_web cannot trigger detection on a Rocket /
    // generic Rust file that also defines a `#[get]` user macro.
    if !rust_uses_any(bytes, &["actix_web"]) {
        return Vec::new();
    }
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    walk_functions(tree.root_node(), &mut |func| {
        if let Some(node) = match_actix_function(func, bytes, &file_rel) {
            out.push(node);
        }
    });
    out
}

fn walk_functions<'tree, F: FnMut(Node<'tree>)>(node: Node<'tree>, visit: &mut F) {
    if node.kind() == "function_item" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_functions(child, visit);
    }
}

fn match_actix_function(func: Node, bytes: &[u8], file_rel: &str) -> Option<SurfaceNode> {
    let attrs = collect_preceding_attributes(func);
    let mut method: Option<HttpMethod> = None;
    let mut route_path = String::new();
    for attr in attrs {
        let raw = attr.utf8_text(bytes).ok()?;
        let inner = raw
            .trim_start_matches(['#', '!'])
            .trim_matches(['[', ']']);
        for (name, default_method) in ROUTE_MACROS {
            let prefix = format!("{}(", name);
            if inner.starts_with(&prefix) {
                method = default_method.or_else(|| extract_route_method(inner));
                if route_path.is_empty()
                    && let Some(start) = inner.find('"')
                {
                    let rest = &inner[start + 1..];
                    if let Some(end) = rest.find('"') {
                        route_path = rest[..end].to_string();
                    }
                }
            } else if inner == *name && method.is_none() {
                method = *default_method;
            }
        }
    }
    let m = method?;
    let handler_name = function_name(func, bytes).unwrap_or_default();
    let auth_required = signature_uses_auth_extractor(func, bytes);
    Some(SurfaceNode::EntryPoint(EntryPoint {
        location: loc_for(func, file_rel),
        framework: Framework::Actix,
        method: m,
        route: route_path,
        handler_name,
        handler_location: SourceLocation::new(
            file_rel,
            (func.start_position().row + 1) as u32,
            (func.start_position().column + 1) as u32,
        ),
        auth_required,
    }))
}

fn collect_preceding_attributes(func: Node) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    let Some(parent) = func.parent() else {
        return out;
    };
    let mut cursor = parent.walk();
    let mut pending: Vec<Node> = Vec::new();
    for sib in parent.children(&mut cursor) {
        if sib.id() == func.id() {
            out.append(&mut pending);
            return out;
        }
        if sib.kind() == "attribute_item" || sib.kind() == "inner_attribute_item" {
            let mut aw = sib.walk();
            for inner in sib.children(&mut aw) {
                if inner.kind() == "attribute" {
                    pending.push(inner);
                }
            }
        } else {
            pending.clear();
        }
    }
    out
}

fn extract_route_method(inner: &str) -> Option<HttpMethod> {
    for verb in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
        if inner.contains(verb) {
            return HttpMethod::from_ident(verb);
        }
    }
    None
}

fn signature_uses_auth_extractor(func: Node, bytes: &[u8]) -> bool {
    let Some(params) = func.child_by_field_name("parameters") else {
        return false;
    };
    let Ok(text) = params.utf8_text(bytes) else {
        return false;
    };
    AUTH_EXTRACTORS.iter().any(|n| text.contains(n))
}

fn function_name(func: Node, bytes: &[u8]) -> Option<String> {
    func.child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_actix_get() {
        let src = r#"
use actix_web::{get, HttpResponse};
#[get("/users")]
async fn list_users() -> HttpResponse { HttpResponse::Ok().finish() }
"#;
        let (tree, bytes) = parse(src);
        let nodes = detect_actix_routes(&tree, &bytes, &PathBuf::from("main.rs"), None);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert_eq!(ep.route, "/users");
    }
}

//! TypeScript + Next.js framework probe.
//!
//! Recognises Next.js App Router route handlers (`app/**/route.{ts,tsx,js,jsx}`)
//! by walking exported function declarations whose name is one of the
//! HTTP method idents (`GET` / `POST` / …).  Also recognises Pages
//! Router API routes (`pages/api/**/*.{ts,tsx,js,jsx}`) via the
//! `export default handler` pattern.
//!
//! Server actions (`'use server'` directive at file or function scope)
//! are also reported as entry points because they expose a function
//! callable from a React client over the wire.

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{loc_for, rel_file};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub fn detect_next_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    let app_router = is_app_router_route(path);
    let pages_api = is_pages_api_route(path);
    let route_path = derive_route_path(path);
    let file_use_server = file_level_use_server(tree.root_node(), bytes);

    if app_router {
        collect_named_exports(tree.root_node(), bytes, &file_rel, &route_path, &mut out);
    }
    if pages_api {
        collect_default_export(tree.root_node(), bytes, &file_rel, &route_path, &mut out);
    }
    if file_use_server {
        collect_use_server_exports(tree.root_node(), bytes, &file_rel, &route_path, &mut out);
    }
    out
}

fn is_app_router_route(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !matches!(name, "route.ts" | "route.tsx" | "route.js" | "route.jsx") {
        return false;
    }
    path.components()
        .any(|c| c.as_os_str().to_string_lossy() == "app")
}

fn is_pages_api_route(path: &Path) -> bool {
    let mut comps = path.components().peekable();
    let mut saw_pages = false;
    while let Some(c) = comps.next() {
        if c.as_os_str().to_string_lossy() == "pages" {
            saw_pages = true;
        } else if saw_pages && c.as_os_str().to_string_lossy() == "api" {
            return true;
        }
    }
    false
}

/// Convert `app/users/[id]/route.ts` → `/users/[id]`.
/// Convert `pages/api/users/index.ts` → `/users`.
fn derive_route_path(path: &Path) -> String {
    let mut comps: Vec<String> = Vec::new();
    let mut started = false;
    for comp in path.components() {
        let text = comp.as_os_str().to_string_lossy().into_owned();
        if !started {
            if text == "app" || text == "api" || text == "pages" {
                started = true;
            }
            continue;
        }
        comps.push(text);
    }
    if let Some(last) = comps.last_mut() {
        // Drop the basename; route file becomes the trailing segment.
        if last.starts_with("route.") || last.starts_with("index.") {
            comps.pop();
        } else if let Some(idx) = last.rfind('.') {
            last.truncate(idx);
        }
    }
    let joined = comps.join("/");
    if joined.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", joined)
    }
}

fn collect_named_exports(
    root: Node,
    bytes: &[u8],
    file_rel: &str,
    route_path: &str,
    out: &mut Vec<SurfaceNode>,
) {
    fn recurse(
        node: Node,
        bytes: &[u8],
        file_rel: &str,
        route_path: &str,
        out: &mut Vec<SurfaceNode>,
    ) {
        if node.kind() == "export_statement" {
            // Look for `export async function NAME(...)` or `export const NAME = ...`
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some((name, span)) = extract_named_function(child, bytes)
                    && let Some(method) = HttpMethod::from_ident(&name)
                {
                    out.push(SurfaceNode::EntryPoint(EntryPoint {
                        location: loc_for(node, file_rel),
                        framework: Framework::NextAppRouter,
                        method,
                        route: route_path.to_string(),
                        handler_name: name,
                        handler_location: SourceLocation::new(
                            file_rel,
                            (span.0 + 1) as u32,
                            (span.1 + 1) as u32,
                        ),
                        auth_required: false,
                    }));
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, bytes, file_rel, route_path, out);
        }
    }
    recurse(root, bytes, file_rel, route_path, out);
}

fn extract_named_function(node: Node, bytes: &[u8]) -> Option<(String, (usize, usize))> {
    match node.kind() {
        "function_declaration" => {
            let name_node = node.child_by_field_name("name")?;
            let name = name_node.utf8_text(bytes).ok()?.to_string();
            let pos = node.start_position();
            Some((name, (pos.row, pos.column)))
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            for decl in node.children(&mut cursor) {
                if decl.kind() == "variable_declarator"
                    && let Some(name_node) = decl.child_by_field_name("name")
                    && let Ok(name) = name_node.utf8_text(bytes)
                {
                    let pos = decl.start_position();
                    return Some((name.to_string(), (pos.row, pos.column)));
                }
            }
            None
        }
        _ => None,
    }
}

fn collect_default_export(
    root: Node,
    bytes: &[u8],
    file_rel: &str,
    route_path: &str,
    out: &mut Vec<SurfaceNode>,
) {
    fn recurse(
        node: Node,
        bytes: &[u8],
        file_rel: &str,
        route_path: &str,
        out: &mut Vec<SurfaceNode>,
    ) {
        if node.kind() == "export_statement" {
            let raw = node.utf8_text(bytes).unwrap_or("");
            if raw.contains("default") {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    let name = match child.kind() {
                        "function_declaration" => child
                            .child_by_field_name("name")
                            .and_then(|n| n.utf8_text(bytes).ok())
                            .map(str::to_string),
                        "identifier" => child.utf8_text(bytes).ok().map(str::to_string),
                        "arrow_function" | "function" | "function_expression" => {
                            Some("default".to_string())
                        }
                        _ => None,
                    };
                    if let Some(name) = name {
                        out.push(SurfaceNode::EntryPoint(EntryPoint {
                            location: loc_for(node, file_rel),
                            framework: Framework::NextAppRouter,
                            method: HttpMethod::GET,
                            route: route_path.to_string(),
                            handler_name: name,
                            handler_location: loc_for(child, file_rel),
                            auth_required: false,
                        }));
                        return;
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, bytes, file_rel, route_path, out);
        }
    }
    recurse(root, bytes, file_rel, route_path, out);
}

fn collect_use_server_exports(
    root: Node,
    bytes: &[u8],
    file_rel: &str,
    route_path: &str,
    out: &mut Vec<SurfaceNode>,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "export_statement"
            && let Some((name, span)) = export_function_name(child, bytes)
        {
            out.push(SurfaceNode::EntryPoint(EntryPoint {
                location: loc_for(child, file_rel),
                framework: Framework::NextServerAction,
                method: HttpMethod::POST,
                route: route_path.to_string(),
                handler_name: name,
                handler_location: SourceLocation::new(
                    file_rel,
                    (span.0 + 1) as u32,
                    (span.1 + 1) as u32,
                ),
                auth_required: false,
            }));
        }
    }
}

fn export_function_name(node: Node, bytes: &[u8]) -> Option<(String, (usize, usize))> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(extracted) = extract_named_function(child, bytes) {
            return Some(extracted);
        }
    }
    None
}

fn file_level_use_server(root: Node, bytes: &[u8]) -> bool {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "expression_statement" {
            let mut cs = child.walk();
            for c in child.children(&mut cs) {
                if c.kind() == "string"
                    && let Ok(text) = c.utf8_text(bytes)
                {
                    let trimmed = text.trim().trim_matches(['\'', '"']);
                    if trimmed == "use server" {
                        return true;
                    }
                }
            }
            return false;
        }
        if !matches!(child.kind(), "comment" | "import_statement") {
            return false;
        }
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
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_app_router_get() {
        let src = "export async function GET(req: Request) { return new Response('ok'); }\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_next_routes(
            &tree,
            &bytes,
            &PathBuf::from("app/users/route.ts"),
            None,
        );
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.method, HttpMethod::GET);
        assert!(ep.route.contains("users"));
    }
}

//! Python + Django framework probe.
//!
//! Recognises two route shapes:
//!
//! 1. `urls.py`-style routing: `path("/admin", admin_view)`,
//!    `re_path(r"^api/", api_view)`, `url(r"^foo$", foo_view)`.
//!    The probe walks the URL configuration list and emits one
//!    EntryPoint per `path` / `re_path` / `url` call, resolving the
//!    handler to the function with the same name in the file when
//!    possible.
//! 2. Class-based view methods: a `get` / `post` / `put` / `delete`
//!    method on a class derived from `View`, `APIView`, `ViewSet`,
//!    `TemplateView`.  The route path is `""` because URL config lives
//!    in a separate `urls.py`.
//!
//! `auth_required` follows the standard Django decorators
//! ([`AUTH_DECORATORS`]) plus the DRF permission classes pattern
//! (`permission_classes = [IsAuthenticated]`).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::{
    leaf_matches, loc_for, python_imports_any, rel_file, string_node_value,
};
use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

pub use crate::auth_analysis::auth_markers::DJANGO_DECORATORS as AUTH_DECORATORS;

const CBV_BASES: &[&str] = &[
    "View",
    "APIView",
    "ViewSet",
    "ModelViewSet",
    "ReadOnlyModelViewSet",
    "TemplateView",
    "ListView",
    "DetailView",
    "CreateView",
    "UpdateView",
    "DeleteView",
    "RedirectView",
    "FormView",
];

pub fn detect_django_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    // File-level gate: only fire when the file actually imports
    // django or DRF.  Phase 23 follow-up tightens the witness to
    // top-level `import` / `from` statements so a comment or string
    // mention of "django" / "rest_framework" cannot trigger detection.
    if !python_imports_any(bytes, &["django", "rest_framework"]) {
        return Vec::new();
    }
    let file_rel = rel_file(path, scan_root);
    let mut out = Vec::new();
    let function_index = collect_function_definitions(tree.root_node(), bytes);
    detect_url_dispatch(tree.root_node(), bytes, &file_rel, &function_index, &mut out);
    detect_class_based_views(tree.root_node(), bytes, &file_rel, &mut out);
    out
}

fn collect_function_definitions<'tree>(
    root: Node<'tree>,
    bytes: &'tree [u8],
) -> HashMap<String, (Node<'tree>, bool)> {
    let mut index: HashMap<String, (Node<'tree>, bool)> = HashMap::new();
    fn walk<'tree>(
        node: Node<'tree>,
        bytes: &'tree [u8],
        index: &mut HashMap<String, (Node<'tree>, bool)>,
    ) {
        if node.kind() == "function_definition"
            && let Some(name_node) = node.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(bytes)
        {
            // Detect if any decorator is an auth marker.
            let mut auth = false;
            if let Some(parent) = node.parent()
                && parent.kind() == "decorated_definition"
            {
                let mut cursor = parent.walk();
                for child in parent.children(&mut cursor) {
                    if child.kind() == "decorator" && decorator_is_auth_marker(child, bytes) {
                        auth = true;
                        break;
                    }
                }
            }
            index.insert(name.to_string(), (node, auth));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, bytes, index);
        }
    }
    walk(root, bytes, &mut index);
    index
}

fn detect_url_dispatch<'tree>(
    root: Node<'tree>,
    bytes: &[u8],
    file_rel: &str,
    function_index: &HashMap<String, (Node<'tree>, bool)>,
    out: &mut Vec<SurfaceNode>,
) {
    fn recurse<'tree>(
        node: Node<'tree>,
        bytes: &[u8],
        file_rel: &str,
        function_index: &HashMap<String, (Node<'tree>, bool)>,
        out: &mut Vec<SurfaceNode>,
    ) {
        if node.kind() == "call"
            && let Some((route, handler_name)) = parse_url_call(node, bytes)
        {
            let (handler_loc, auth_required) = function_index
                .get(&handler_name)
                .map(|(h, a)| (loc_for(*h, file_rel), *a))
                .unwrap_or_else(|| (loc_for(node, file_rel), false));
            out.push(SurfaceNode::EntryPoint(EntryPoint {
                location: loc_for(node, file_rel),
                framework: Framework::Django,
                method: HttpMethod::GET,
                route,
                handler_name,
                handler_location: handler_loc,
                auth_required,
            }));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, bytes, file_rel, function_index, out);
        }
    }
    recurse(root, bytes, file_rel, function_index, out);
}

fn parse_url_call(call: Node, bytes: &[u8]) -> Option<(String, String)> {
    let target = call.child_by_field_name("function")?;
    let target_text = target.utf8_text(bytes).ok()?;
    let leaf = target_text.rsplit('.').next().unwrap_or(target_text);
    if !matches!(leaf, "path" | "re_path" | "url") {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut route: Option<String> = None;
    let mut handler: Option<String> = None;
    for arg in args.children(&mut cursor) {
        match arg.kind() {
            "string" if route.is_none() => {
                route = string_node_value(arg, bytes);
            }
            "identifier" if handler.is_none() => {
                handler = arg.utf8_text(bytes).ok().map(str::to_string);
            }
            "attribute" if handler.is_none() => {
                handler = arg.utf8_text(bytes).ok().map(str::to_string);
            }
            "call" if handler.is_none() => {
                // `MyView.as_view()` shape — extract `MyView`.
                if let Some(callee) = arg.child_by_field_name("function")
                    && let Ok(text) = callee.utf8_text(bytes)
                {
                    handler = Some(text.split('.').next().unwrap_or(text).to_string());
                }
            }
            _ => {}
        }
    }
    Some((route?, handler?))
}

fn detect_class_based_views(
    root: Node,
    bytes: &[u8],
    file_rel: &str,
    out: &mut Vec<SurfaceNode>,
) {
    fn recurse(node: Node, bytes: &[u8], file_rel: &str, out: &mut Vec<SurfaceNode>) {
        if node.kind() == "class_definition"
            && class_is_django_view(node, bytes)
        {
            let class_auth = class_has_auth_permission(node, bytes);
            // Walk the body for HTTP-named methods.
            if let Some(body) = node.child_by_field_name("body") {
                let mut bcur = body.walk();
                for stmt in body.children(&mut bcur) {
                    let func = match stmt.kind() {
                        "function_definition" => stmt,
                        "decorated_definition" => stmt
                            .child_by_field_name("definition")
                            .or_else(|| {
                                let mut c = stmt.walk();
                                stmt.children(&mut c)
                                    .find(|n| n.kind() == "function_definition")
                            })
                            .unwrap_or(stmt),
                        _ => continue,
                    };
                    if func.kind() != "function_definition" {
                        continue;
                    }
                    let Some(name_node) = func.child_by_field_name("name") else {
                        continue;
                    };
                    let Ok(name) = name_node.utf8_text(bytes) else {
                        continue;
                    };
                    let Some(method) = HttpMethod::from_ident(name) else {
                        continue;
                    };
                    out.push(SurfaceNode::EntryPoint(EntryPoint {
                        location: loc_for(func, file_rel),
                        framework: Framework::Django,
                        method,
                        route: String::new(),
                        handler_name: name.to_string(),
                        handler_location: SourceLocation::new(
                            file_rel,
                            (func.start_position().row + 1) as u32,
                            (func.start_position().column + 1) as u32,
                        ),
                        auth_required: class_auth,
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

fn class_is_django_view(class: Node, bytes: &[u8]) -> bool {
    let Some(supers) = class.child_by_field_name("superclasses") else {
        return false;
    };
    let mut cursor = supers.walk();
    for sup in supers.named_children(&mut cursor) {
        let Ok(text) = sup.utf8_text(bytes) else {
            continue;
        };
        let leaf = text.rsplit('.').next().unwrap_or(text);
        if CBV_BASES.iter().any(|b| leaf.contains(b)) {
            return true;
        }
    }
    false
}

fn class_has_auth_permission(class: Node, bytes: &[u8]) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = body.walk();
    for stmt in body.children(&mut cursor) {
        if stmt.kind() != "expression_statement" {
            continue;
        }
        let mut sc = stmt.walk();
        for child in stmt.children(&mut sc) {
            if child.kind() != "assignment" {
                continue;
            }
            let Some(left) = child.child_by_field_name("left") else {
                continue;
            };
            let Ok(left_text) = left.utf8_text(bytes) else {
                continue;
            };
            if left_text != "permission_classes" {
                continue;
            }
            let Some(right) = child.child_by_field_name("right") else {
                continue;
            };
            let Ok(right_text) = right.utf8_text(bytes) else {
                continue;
            };
            if right_text.contains("IsAuthenticated")
                || right_text.contains("IsAdminUser")
                || right_text.contains("DjangoModelPermissions")
            {
                return true;
            }
        }
    }
    false
}

fn decorator_is_auth_marker(decorator: Node, bytes: &[u8]) -> bool {
    let mut cursor = decorator.walk();
    let Some(expr) = decorator
        .children(&mut cursor)
        .find(|c| c.kind() != "@" && c.kind() != "comment")
    else {
        return false;
    };
    let target = match expr.kind() {
        "call" => expr.child_by_field_name("function"),
        _ => Some(expr),
    };
    let Some(target) = target else { return false };
    let Ok(text) = target.utf8_text(bytes) else {
        return false;
    };
    leaf_matches(text, AUTH_DECORATORS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(src: &str) -> (Tree, Vec<u8>) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        (parser.parse(src, None).unwrap(), src.as_bytes().to_vec())
    }

    #[test]
    fn detects_path_call() {
        let src = "from django.urls import path\n\ndef admin_view(request): pass\n\nurlpatterns = [\n    path('admin/', admin_view),\n]\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_django_routes(&tree, &bytes, &PathBuf::from("urls.py"), None);
        assert!(!nodes.is_empty());
        let SurfaceNode::EntryPoint(ep) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ep.framework, Framework::Django);
        assert_eq!(ep.handler_name, "admin_view");
        assert_eq!(ep.route, "admin/");
    }

    #[test]
    fn detects_class_based_view() {
        let src = "from rest_framework.views import APIView\n\nclass UserList(APIView):\n    def get(self, request): pass\n    def post(self, request): pass\n";
        let (tree, bytes) = parse(src);
        let nodes = detect_django_routes(&tree, &bytes, &PathBuf::from("views.py"), None);
        assert_eq!(nodes.len(), 2);
    }
}

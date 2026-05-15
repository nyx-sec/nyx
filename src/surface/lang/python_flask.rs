//! Python + Flask framework probe.
//!
//! Walks a parsed Python file looking for the four canonical Flask
//! route shapes:
//!
//! * `@app.route("/path", methods=[...])`
//! * `@app.get("/path")` / `.post(...)` / etc. (Flask ≥ 2.0)
//! * `@bp.route("/path", methods=[...])` on a `Blueprint`
//! * `@bp.get("/path")` / `.post(...)` / etc.
//!
//! `auth_required` is inferred from the decorator stack: any decorator
//! whose textual representation matches one of [`AUTH_DECORATORS`] is
//! treated as an auth boundary on the following route.  This catches
//! the canonical `@login_required` (Flask-Login), `@auth_required`
//! (custom guards), and `@jwt_required` / `@jwt_required()` (Flask-JWT
//! and -JWT-Extended).

use crate::entry_points::HttpMethod;
use crate::surface::lang::common::python_imports_any;
use crate::surface::{
    EntryPoint, Framework, SourceLocation, SurfaceNode, relative_path_string,
};
use std::path::Path;
use tree_sitter::{Node, Tree};

/// Decorator names that mark a route as requiring authentication.
/// Matched against the *leaf* of the decorator expression — i.e. the
/// last `attribute` / `identifier` segment — so `@login_required`,
/// `@auth.login_required`, and `@flask_login.login_required` all
/// match.  Match is case-insensitive on the underscored form.
pub const AUTH_DECORATORS: &[&str] = &[
    "login_required",
    "auth_required",
    "jwt_required",
    "token_required",
    "requires_auth",
    "authenticated",
    "require_login",
];

/// Detect every Flask route in a parsed Python file.
///
/// `scan_root` is used to convert the file path to a project-relative
/// POSIX path; pass `None` to record absolute paths.  Returns one
/// [`SurfaceNode::EntryPoint`] per `@route` / `@get` / `@post` / …
/// decorator that targets a Flask-shaped receiver (`app`, `bp`,
/// `blueprint`, or anything ending in `_bp` / `Blueprint`).
pub fn detect_flask_routes(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    scan_root: Option<&Path>,
) -> Vec<SurfaceNode> {
    // File-level gate: avoid double-detection on FastAPI files where
    // `app.get(...)` shape overlaps.  Phase 21 was lenient because no
    // sibling probe existed; Phase 22 split per-framework via free
    // text witness; Phase 23 follow-up tightens the witness to actual
    // top-level `import` / `from` statements so a comment or vendored
    // license header that names "flask" cannot trigger detection.
    if !python_imports_any(bytes, &["flask"]) {
        return Vec::new();
    }
    let file_rel = relative_path_string(path, scan_root);
    let mut out = Vec::new();
    walk_decorated(tree.root_node(), bytes, &mut |func_node, decorators| {
        // Reverse pass: find Flask-route decorators and collect auth
        // markers seen at *any* position in the decorator stack —
        // Flask honours decorators in stacked order regardless of
        // sequence relative to the route.
        let auth_required = decorators
            .iter()
            .any(|d| decorator_is_auth_marker(*d, bytes));
        for dec in decorators {
            if let Some((method, route_path)) = flask_route_decorator(*dec, bytes) {
                let dec_pos = dec.start_position();
                let handler_pos = func_node.start_position();
                let handler_name = function_name(*func_node, bytes).unwrap_or_default();
                out.push(SurfaceNode::EntryPoint(EntryPoint {
                    location: SourceLocation::new(
                        file_rel.clone(),
                        (dec_pos.row + 1) as u32,
                        (dec_pos.column + 1) as u32,
                    ),
                    framework: Framework::Flask,
                    method,
                    route: route_path,
                    handler_name,
                    handler_location: SourceLocation::new(
                        file_rel.clone(),
                        (handler_pos.row + 1) as u32,
                        (handler_pos.column + 1) as u32,
                    ),
                    auth_required,
                }));
            }
        }
    });
    out
}

/// Walk every `function_definition` in `root` and invoke `visit` with
/// the function node plus the list of decorator nodes wrapping it.
/// Handles both `decorated_definition` (one or more decorators) and
/// bare `function_definition` (zero decorators, visit skipped).
fn walk_decorated<'tree, F>(root: Node<'tree>, bytes: &[u8], visit: &mut F)
where
    F: FnMut(&Node<'tree>, &[Node<'tree>]),
{
    if root.kind() == "decorated_definition" {
        let mut cursor = root.walk();
        let mut decorators: Vec<Node<'tree>> = Vec::new();
        let mut func: Option<Node<'tree>> = None;
        for child in root.children(&mut cursor) {
            match child.kind() {
                "decorator" => decorators.push(child),
                "function_definition" => func = Some(child),
                _ => {}
            }
        }
        if let Some(func_node) = func {
            visit(&func_node, &decorators);
        }
        let _ = bytes;
    }
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        walk_decorated(child, bytes, visit);
    }
}

/// Classify a `decorator` node as a Flask route, returning the
/// `(method, path)` pair.  Recognises both the `@app.route(...)` and
/// `@app.<verb>(...)` shapes and the Blueprint equivalents.
fn flask_route_decorator(decorator: Node, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut walker = decorator.walk();
    let expr = decorator
        .children(&mut walker)
        .find(|c| c.kind() != "@" && c.kind() != "comment")?;
    let (call_target, args) = match expr.kind() {
        "call" => (
            expr.child_by_field_name("function")?,
            expr.child_by_field_name("arguments"),
        ),
        _ => return None,
    };
    if call_target.kind() != "attribute" {
        return None;
    }
    let object = call_target.child_by_field_name("object")?;
    if !receiver_is_flask(object, bytes) {
        return None;
    }
    let attr = call_target.child_by_field_name("attribute")?;
    let attr_text = attr.utf8_text(bytes).ok()?;
    let route_path = args
        .and_then(|a| first_string_arg(a, bytes))
        .unwrap_or_default();
    if attr_text == "route" {
        let method = args
            .and_then(|a| extract_first_method(a, bytes))
            .unwrap_or(HttpMethod::GET);
        return Some((method, route_path));
    }
    if let Some(method) = HttpMethod::from_ident(attr_text) {
        return Some((method, route_path));
    }
    None
}

/// `true` when the decorator receiver looks like a Flask app or
/// Blueprint binding.  Allowlist over identifier names + a structural
/// match on call expressions like `Blueprint("name", __name__)`.
fn receiver_is_flask(object: Node, bytes: &[u8]) -> bool {
    fn name_matches(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower == "app"
            || lower == "bp"
            || lower == "blueprint"
            || lower.ends_with("_app")
            || lower.ends_with("_bp")
            || lower.ends_with("blueprint")
            || lower.ends_with("api")
    }
    match object.kind() {
        "identifier" => object.utf8_text(bytes).ok().is_some_and(name_matches),
        "attribute" => object
            .child_by_field_name("attribute")
            .and_then(|a| a.utf8_text(bytes).ok())
            .is_some_and(name_matches),
        "call" => {
            let Some(callee) = object.child_by_field_name("function") else {
                return false;
            };
            let Ok(text) = callee.utf8_text(bytes) else {
                return false;
            };
            let leaf = text.rsplit('.').next().unwrap_or(text).trim();
            leaf == "Flask" || leaf == "Blueprint"
        }
        _ => false,
    }
}

/// Pull the first string literal positional argument out of a
/// `argument_list` node.  Used to extract the route path from
/// `@app.route("/path", ...)`.
fn first_string_arg(args: Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() == "string" {
            return Some(string_literal_text(arg, bytes));
        }
    }
    None
}

/// Strip Python quotes / prefix bytes (`b"..."`, `r"..."`) and return
/// the literal content.  Falls back to the raw slice when the literal
/// has an unfamiliar shape.
fn string_literal_text(node: Node, bytes: &[u8]) -> String {
    let raw = node.utf8_text(bytes).unwrap_or("");
    let trimmed = raw.trim();
    let mut s = trimmed;
    while let Some(rest) = s.strip_prefix(['b', 'r', 'B', 'R', 'f', 'F']) {
        s = rest;
    }
    let stripped = s
        .trim_start_matches(['\'', '"'])
        .trim_end_matches(['\'', '"']);
    stripped.to_string()
}

/// Extract the first HTTP method named in a `methods=[...]` kwarg, or
/// `None` when the decorator omits the kwarg.  The first method in
/// the list wins; multi-method routes are recorded as the first
/// (Flask itself runs the same handler for every listed method).
fn extract_first_method(args: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() != "keyword_argument" {
            continue;
        }
        let name_node = arg.child_by_field_name("name")?;
        let Ok(name) = name_node.utf8_text(bytes) else {
            continue;
        };
        if name != "methods" {
            continue;
        }
        let value = arg.child_by_field_name("value")?;
        let mut cur = value.walk();
        for child in value.children(&mut cur) {
            if child.kind() == "string" {
                let text = string_literal_text(child, bytes);
                if let Some(m) = HttpMethod::from_ident(&text) {
                    return Some(m);
                }
            }
        }
    }
    None
}

/// `true` when the decorator is an auth-guard marker.  Matches the
/// last segment of the decorator expression against
/// [`AUTH_DECORATORS`].
fn decorator_is_auth_marker(decorator: Node, bytes: &[u8]) -> bool {
    let mut walker = decorator.walk();
    let Some(expr) = decorator
        .children(&mut walker)
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
    let leaf = text.rsplit('.').next().unwrap_or(text).trim();
    AUTH_DECORATORS
        .iter()
        .any(|d| leaf.eq_ignore_ascii_case(d))
}

/// Read the function name from a `function_definition` node.
fn function_name(func: Node, bytes: &[u8]) -> Option<String> {
    let name_node = func.child_by_field_name("name")?;
    name_node.utf8_text(bytes).ok().map(str::to_string)
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
        let tree = parser.parse(src, None).unwrap();
        (tree, src.as_bytes().to_vec())
    }

    fn detect(src: &str) -> Vec<SurfaceNode> {
        let (tree, bytes) = parse(src);
        detect_flask_routes(&tree, &bytes, &PathBuf::from("app.py"), None)
    }

    #[test]
    fn detects_basic_route() {
        let src = r#"
from flask import Flask
app = Flask(__name__)

@app.route("/hello")
def hello():
    return "hi"
"#;
        let nodes = detect(src);
        assert_eq!(nodes.len(), 1);
        if let SurfaceNode::EntryPoint(ep) = &nodes[0] {
            assert_eq!(ep.route, "/hello");
            assert_eq!(ep.method, HttpMethod::GET);
            assert_eq!(ep.handler_name, "hello");
            assert!(!ep.auth_required);
        } else {
            panic!("not an EntryPoint");
        }
    }

    #[test]
    fn detects_methods_kwarg() {
        let src = r#"
from flask import Flask
app = Flask(__name__)

@app.route("/submit", methods=["POST"])
def submit():
    return "ok"
"#;
        let nodes = detect(src);
        let ep = match &nodes[0] {
            SurfaceNode::EntryPoint(ep) => ep,
            _ => panic!("not an EntryPoint"),
        };
        assert_eq!(ep.method, HttpMethod::POST);
    }

    #[test]
    fn detects_verb_decorator() {
        let src = r#"
from flask import Flask
app = Flask(__name__)

@app.post("/users")
def create():
    return "ok"
"#;
        let nodes = detect(src);
        let ep = match &nodes[0] {
            SurfaceNode::EntryPoint(ep) => ep,
            _ => panic!("not an EntryPoint"),
        };
        assert_eq!(ep.method, HttpMethod::POST);
    }

    #[test]
    fn detects_blueprint() {
        let src = r#"
from flask import Blueprint
bp = Blueprint("admin", __name__)

@bp.get("/admin")
def admin():
    return "secret"
"#;
        let nodes = detect(src);
        let ep = match &nodes[0] {
            SurfaceNode::EntryPoint(ep) => ep,
            _ => panic!("not an EntryPoint"),
        };
        assert_eq!(ep.route, "/admin");
    }

    #[test]
    fn detects_auth_decorator() {
        let src = r#"
from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@app.route("/secret")
@login_required
def secret():
    return "shh"
"#;
        let nodes = detect(src);
        let ep = match &nodes[0] {
            SurfaceNode::EntryPoint(ep) => ep,
            _ => panic!("not an EntryPoint"),
        };
        assert!(ep.auth_required);
    }

    #[test]
    fn rejects_non_flask_receiver() {
        let src = r#"
client = requests.Session()

@client.get("/whatever")
def x():
    pass
"#;
        let nodes = detect(src);
        // `client` does not match the Flask receiver allowlist.
        assert!(nodes.is_empty());
    }
}

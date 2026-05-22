//! Shared Go-route adapter helpers (Phase 17 — Track L.15).
//!
//! The gin / echo / fiber / chi adapters all need the same handful
//! of tree-sitter helpers: locate a `func` declaration by name,
//! enumerate formal parameter names, walk the file looking for a
//! `engine.GET("/path", handler)` / `router.Post("/x", handler)` call
//! whose callable references a target function name, parse a path
//! template into placeholder names, and bind formals to request
//! slots.  Centralising the helpers here keeps the four adapters
//! terse and lets every framework share the same placeholder-binding
//! semantics.
//!
//! Path placeholder vocabulary:
//!   - gin / echo / chi use `:id` and (chi) `{id}` interchangeably.
//!   - fiber uses `:id` and `+` / `*` greedy wildcards.
//!
//! [`extract_go_path_placeholders`] supports both syntaxes.

use crate::dynamic::framework::auth_markers;
use crate::dynamic::framework::{HttpMethod, MiddlewareShape, ParamBinding, ParamSource};
use crate::symbol::Lang;
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known gin markers.
pub fn source_imports_gin(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"github.com/gin-gonic/gin",
            b"gin.Engine",
            b"gin.Default",
            b"gin.New",
            b"// nyx-shape: gin",
        ],
    )
}

/// True when `bytes` carries any of the well-known echo markers.
pub fn source_imports_echo(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"github.com/labstack/echo",
            b"echo.Echo",
            b"echo.New",
            b"echo.Context",
            b"// nyx-shape: echo",
        ],
    )
}

/// True when `bytes` carries any of the well-known fiber markers.
pub fn source_imports_fiber(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"github.com/gofiber/fiber",
            b"fiber.App",
            b"fiber.New",
            b"fiber.Ctx",
            b"// nyx-shape: fiber",
        ],
    )
}

/// True when `bytes` carries any of the well-known chi markers.
pub fn source_imports_chi(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"github.com/go-chi/chi",
            b"chi.NewRouter",
            b"chi.Mux",
            b"chi.Router",
            b"// nyx-shape: chi",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Find a top-level `function_declaration` or a `method_declaration`
/// whose name equals `target`.  Returns the matching node.
pub fn find_go_function<'a>(root: Node<'a>, bytes: &'a [u8], target: &str) -> Option<Node<'a>> {
    let mut hit: Option<Node<'a>> = None;
    walk_go(root, bytes, target, &mut hit);
    hit
}

fn walk_go<'a>(node: Node<'a>, bytes: &'a [u8], target: &str, out: &mut Option<Node<'a>>) {
    if out.is_some() {
        return;
    }
    match node.kind() {
        "function_declaration" | "method_declaration" => {
            if let Some(name) = node.child_by_field_name("name")
                && let Ok(text) = name.utf8_text(bytes)
                && text == target
            {
                *out = Some(node);
                return;
            }
        }
        _ => {}
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_go(child, bytes, target, out);
    }
}

/// Read formal parameter names from a `function_declaration` /
/// `method_declaration` / `func_literal`.  Drops the receiver
/// parameter of a method (it is not part of the request surface).
pub fn go_formal_names(func: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(params) = func.child_by_field_name("parameters") else {
        return out;
    };
    let mut cur = params.walk();
    for p in params.named_children(&mut cur) {
        if p.kind() != "parameter_declaration" {
            continue;
        }
        let mut pc = p.walk();
        for c in p.named_children(&mut pc) {
            if c.kind() == "identifier"
                && let Ok(text) = c.utf8_text(bytes)
            {
                out.push(text.to_owned());
            }
        }
    }
    out
}

/// Extract placeholder names from a Go route path template.
///
/// Supports:
///   - gin / echo / fiber `:id` style: `/u/:id` → `id`
///   - chi `{id}` style:                `/u/{id}` → `id`
///   - fiber `+` greedy:                `/files/+rest` → `rest`
///   - fiber/chi `*` wildcard:          `/files/*rest` → `rest`
pub fn extract_go_path_placeholders(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if !name.is_empty() && !out.iter().any(|n| n == &name) {
            out.push(name);
        }
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b':' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > start {
                    push(path[start..j].to_owned());
                    i = j;
                    continue;
                }
            }
            b'{' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                    let inner = &path[i + 1..i + 1 + end];
                    let name = inner.split(':').next().unwrap_or(inner);
                    push(name.to_owned());
                    i += end + 2;
                    continue;
                }
            }
            b'*' | b'+' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > start {
                    push(path[start..j].to_owned());
                    i = j;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Bind formals to request slots given a Go route path template.
///
/// `c` / `ctx` / `w` / `r` formals become [`ParamSource::Implicit`]
/// (the framework context object or `http.ResponseWriter` /
/// `*http.Request` pair).  Names matching the path placeholder list
/// become [`ParamSource::PathSegment`].  Every other formal falls
/// back to a [`ParamSource::QueryParam`] of the same name.
pub fn bind_go_path_params(formals: &[String], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_go_path_placeholders(path);
    formals
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let source = if is_implicit_formal(name) {
                ParamSource::Implicit
            } else if placeholders.iter().any(|p| p == name) {
                ParamSource::PathSegment(name.clone())
            } else {
                ParamSource::QueryParam(name.clone())
            };
            ParamBinding {
                index: idx,
                name: name.clone(),
                source,
            }
        })
        .collect()
}

fn is_implicit_formal(name: &str) -> bool {
    matches!(name, "c" | "ctx" | "w" | "r" | "req" | "res" | "rw")
}

/// Parse Go verb-method names: `GET`, `POST`, `PUT`, `PATCH`,
/// `DELETE`, `HEAD`, `OPTIONS` (case-insensitive — gin uses upper,
/// echo / chi use upper, fiber uses pascal-cased like `Get`,
/// `Post`).  Returns `None` for unrelated identifiers.
pub fn verb_from_method(method: &str) -> Option<HttpMethod> {
    let upper = method.to_ascii_uppercase();
    match upper.as_str() {
        "GET" => Some(HttpMethod::GET),
        "POST" => Some(HttpMethod::POST),
        "PUT" => Some(HttpMethod::PUT),
        "PATCH" => Some(HttpMethod::PATCH),
        "DELETE" => Some(HttpMethod::DELETE),
        "HEAD" => Some(HttpMethod::HEAD),
        "OPTIONS" => Some(HttpMethod::OPTIONS),
        _ => None,
    }
}

/// Walk every `receiver.Use(...)` / `receiver.With(...)` call in the
/// file and collect the argument expressions whose names match a
/// known Go middleware marker (see
/// [`crate::dynamic::framework::auth_markers::is_protective`]).
///
/// gin / echo / fiber attach middleware via `r.Use(mw1, mw2, ...)`;
/// chi attaches middleware inline via `r.Use(...)` or
/// `r.With(...).Get(...)`.  Both verbs are accepted; mid-chain
/// `.With(...)` calls that follow a verb-method call (`.Get(...)`
/// returns no router so chained `.With` is impossible) are
/// conservatively still collected because tree-sitter has already
/// flattened the chain into the same `call_expression` shape.
///
/// Argument rendering:
///   - bare identifier (`r.Use(authMiddleware)`) → `"authMiddleware"`
///   - selector expression (`r.Use(middleware.JWT)`) →
///     `"middleware.JWT"`
///   - call expression (`r.Use(csrf.New(secret))`) → `"csrf.New"`
///     (callee text, args dropped — the auth-markers table is keyed
///     on the factory function, not the constructed instance)
///
/// De-duplicates within a single file; preserves declaration order.
/// Names the registry does not recognise are dropped silently —
/// callers can re-walk with a wider predicate if they need broader
/// inclusion.
pub fn collect_use_middleware(root: Node<'_>, bytes: &[u8]) -> Vec<MiddlewareShape> {
    let mut raw: Vec<String> = Vec::new();
    walk_use_calls(root, bytes, &mut raw);
    let mut out: Vec<MiddlewareShape> = Vec::new();
    for name in raw {
        if auth_markers::is_protective(Lang::Go, &name) && !out.iter().any(|m| m.name == name) {
            out.push(MiddlewareShape { name });
        }
    }
    out
}

fn walk_use_calls(node: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    if node.kind() == "call_expression" {
        try_collect_use_call(node, bytes, out);
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_use_calls(child, bytes, out);
    }
}

fn try_collect_use_call(call: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    let Some(callee) = call.child_by_field_name("function") else {
        return;
    };
    if callee.kind() != "selector_expression" {
        return;
    }
    let Some(field) = callee.child_by_field_name("field") else {
        return;
    };
    let Ok(verb) = field.utf8_text(bytes) else {
        return;
    };
    if verb != "Use" && verb != "With" {
        return;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let mut cur = args.walk();
    for arg in args.named_children(&mut cur) {
        if arg.kind() == "comment" {
            continue;
        }
        if let Some(name) = middleware_arg_name(arg, bytes) {
            out.push(name);
        }
    }
}

fn middleware_arg_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "selector_expression" => {
            node.utf8_text(bytes).ok().map(|s| s.trim().to_owned())
        }
        "call_expression" => {
            let callee = node.child_by_field_name("function")?;
            callee.utf8_text(bytes).ok().map(|s| s.trim().to_owned())
        }
        _ => None,
    }
}

/// Locate the `(method, path)` of a `receiver.Verb("/path", target)`
/// call expression registered against `target` in the file.  Walks
/// every `call_expression` in `root` and inspects each one whose
/// callee is a `selector_expression` of the shape
/// `<receiver>.<Verb>(<string>, <callable>)`.  Returns `None` when no
/// such call references `target` directly.
///
/// `target` matches against:
///   - bare identifier callee (`r.GET("/x", handler)`)
///   - qualified callee whose last segment equals `target`
///     (`r.GET("/x", controllers.Show)`)
///   - method-value callee (`r.GET("/x", (&UserController{}).Show)`)
pub fn find_route_for_callee<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    walk_routes(root, bytes, target, &mut hit);
    hit
}

fn walk_routes<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(found) = try_route_call(node, bytes, target)
    {
        *out = Some(found);
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_routes(child, bytes, target, out);
    }
}

fn try_route_call<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "selector_expression" {
        return None;
    }
    let verb_node = callee.child_by_field_name("field")?.utf8_text(bytes).ok()?;
    let method = verb_from_method(verb_node)?;
    let args = call.child_by_field_name("arguments")?;
    let positional: Vec<Node<'_>> = {
        let mut cur = args.walk();
        args.named_children(&mut cur)
            .filter(|c| c.kind() != "comment")
            .collect()
    };
    if positional.len() < 2 {
        return None;
    }
    let path = go_string_literal(positional[0], bytes)?;
    if !callable_matches(positional[1], bytes, target) {
        return None;
    }
    Some((method, path))
}

/// Read a Go interpreted_string_literal's content, dropping the
/// surrounding `"` quotes.  Returns `None` if `node` is not a string
/// literal.
pub fn go_string_literal(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if node.kind() != "interpreted_string_literal" && node.kind() != "raw_string_literal" {
        return None;
    }
    let raw = node.utf8_text(bytes).ok()?;
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let first = trimmed.as_bytes()[0];
    let last = trimmed.as_bytes()[trimmed.len() - 1];
    if (first == b'"' && last == b'"') || (first == b'`' && last == b'`') {
        Some(trimmed[1..trimmed.len() - 1].to_owned())
    } else {
        None
    }
}

/// True when the callable argument resolves to `target`.  Accepts:
///   - bare identifier (`Handler`)
///   - selector chain (`controllers.Show`, `c.Show`)
///   - func literal — wildcard (the surrounding adapter already
///     narrowed to a Go function whose name matches the summary)
///   - method-value calls — wildcard
fn callable_matches(node: Node<'_>, bytes: &[u8], target: &str) -> bool {
    match node.kind() {
        "identifier" => node.utf8_text(bytes).map(|s| s == target).unwrap_or(false),
        "selector_expression" => {
            let Some(field) = node.child_by_field_name("field") else {
                return false;
            };
            field.utf8_text(bytes).map(|s| s == target).unwrap_or(false)
        }
        "func_literal" => true,
        "call_expression" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn extracts_colon_placeholders() {
        assert_eq!(extract_go_path_placeholders("/u/:id"), vec!["id"]);
        assert_eq!(
            extract_go_path_placeholders("/u/:id/posts/:slug"),
            vec!["id", "slug"]
        );
    }

    #[test]
    fn extracts_brace_placeholders() {
        assert_eq!(extract_go_path_placeholders("/u/{id}"), vec!["id"]);
        assert_eq!(extract_go_path_placeholders("/u/{id:[0-9]+}"), vec!["id"]);
    }

    #[test]
    fn extracts_fiber_wildcards() {
        assert_eq!(extract_go_path_placeholders("/files/+rest"), vec!["rest"]);
        assert_eq!(extract_go_path_placeholders("/files/*rest"), vec!["rest"]);
    }

    #[test]
    fn binds_known_placeholder_as_path_segment() {
        let formals = vec!["c".to_string(), "id".to_string(), "extra".to_string()];
        let bindings = bind_go_path_params(&formals, "/u/:id");
        assert!(matches!(bindings[0].source, ParamSource::Implicit));
        assert!(matches!(bindings[1].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[2].source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn verb_recognises_pascal_case() {
        assert_eq!(verb_from_method("GET"), Some(HttpMethod::GET));
        assert_eq!(verb_from_method("Get"), Some(HttpMethod::GET));
        assert_eq!(verb_from_method("post"), Some(HttpMethod::POST));
        assert_eq!(verb_from_method("Handler"), None);
    }

    #[test]
    fn finds_function_declaration() {
        let src: &[u8] = b"package main\nfunc Show(c interface{}) {}\n";
        let tree = parse(src);
        let n = find_go_function(tree.root_node(), src, "Show").unwrap();
        assert_eq!(n.kind(), "function_declaration");
    }

    #[test]
    fn finds_route_for_bare_identifier_callee() {
        let src: &[u8] =
            b"package main\nfunc init() { r := gin.New(); r.GET(\"/u/:id\", Show) }\nfunc Show(c interface{}) {}\n";
        let tree = parse(src);
        let (method, path) = find_route_for_callee(tree.root_node(), src, "Show").expect("hit");
        assert_eq!(method, HttpMethod::GET);
        assert_eq!(path, "/u/:id");
    }

    #[test]
    fn finds_route_for_selector_callee() {
        let src: &[u8] =
            b"package main\nfunc init() { r := chi.NewRouter(); r.Get(\"/x\", controllers.Show) }\n";
        let tree = parse(src);
        let (method, path) = find_route_for_callee(tree.root_node(), src, "Show").expect("hit");
        assert_eq!(method, HttpMethod::GET);
        assert_eq!(path, "/x");
    }

    #[test]
    fn formal_names_skip_types() {
        let src: &[u8] = b"package main\nfunc Show(c *gin.Context, id string) {}\n";
        let tree = parse(src);
        let f = find_go_function(tree.root_node(), src, "Show").unwrap();
        let names = go_formal_names(f, src);
        assert_eq!(names, vec!["c", "id"]);
    }

    #[test]
    fn collect_use_middleware_picks_bare_identifier() {
        let src: &[u8] =
            b"package main\nfunc init() { r := gin.Default(); r.Use(AuthMiddleware) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        assert_eq!(mw.len(), 1);
        assert_eq!(mw[0].name, "AuthMiddleware");
    }

    #[test]
    fn collect_use_middleware_picks_selector_marker() {
        let src: &[u8] = b"package main\nfunc init() { e := echo.New(); e.Use(middleware.JWT) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        assert_eq!(mw.len(), 1);
        assert_eq!(mw[0].name, "middleware.JWT");
    }

    #[test]
    fn collect_use_middleware_picks_call_factory() {
        let src: &[u8] =
            b"package main\nfunc init() { r := chi.NewRouter(); r.Use(csrf.New(secret)) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        assert_eq!(mw.len(), 1);
        assert_eq!(mw[0].name, "csrf.New");
    }

    #[test]
    fn collect_use_middleware_accepts_chi_with() {
        let src: &[u8] =
            b"package main\nfunc init() { r := chi.NewRouter(); r.With(jwtauth.Verifier).Get(\"/x\", Show) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        assert_eq!(mw.len(), 1);
        assert_eq!(mw[0].name, "jwtauth.Verifier");
    }

    #[test]
    fn collect_use_middleware_drops_unknown_names() {
        let src: &[u8] =
            b"package main\nfunc init() { r := gin.Default(); r.Use(loggingHandler) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        assert!(mw.is_empty(), "loggingHandler is not a recognised marker");
    }

    #[test]
    fn collect_use_middleware_dedupes_and_collects_multiple() {
        let src: &[u8] = b"package main\nfunc init() { r := gin.Default(); r.Use(AuthMiddleware, csrf.New(s)); r.Use(AuthMiddleware) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        let names: Vec<&str> = mw.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["AuthMiddleware", "csrf.New"]);
    }

    #[test]
    fn collect_use_middleware_returns_empty_when_none_recognised() {
        let src: &[u8] = b"package main\nfunc init() { r := gin.Default(); r.GET(\"/x\", Show) }\n";
        let tree = parse(src);
        let mw = collect_use_middleware(tree.root_node(), src);
        assert!(mw.is_empty());
    }
}

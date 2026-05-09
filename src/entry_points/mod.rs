//! Phase 10 + Phase 16 — framework entry-point detection.
//!
//! Recognises HTTP-handler shapes across the major web frameworks so the
//! SSA taint engine can seed their parameters with `TaintOrigin::Source`
//! at function entry without waiting for a caller-side flow.
//!
//! Phase 10 covered Next.js JS/TS shapes (`'use server'` directive,
//! App Router route handlers).  Phase 16 generalises detection to
//! Python (Django views, FastAPI routes, Flask routes, Starlette),
//! Java (Spring `@RequestMapping` / `@GetMapping` / `@PostMapping`,
//! JAX-RS `@Path`), Ruby (Rails `ActionController` actions, Sinatra
//! `get` / `post` blocks), Rust (axum / actix-web / rocket handlers),
//! Go (`net/http` `HandleFunc`, gin / echo / chi route registration),
//! and Express (JS, non-Next.js, `app.get` / `router.post`).
//!
//! Detection runs at pass-1 summary extraction time and writes
//! [`EntryKind`] onto the matching [`crate::summary::FuncSummary`] /
//! [`crate::summary::ssa_summary::SsaFuncSummary`].  Pass 2 reads the
//! tag back from the per-body summary and seeds parameters before the
//! taint worklist starts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

/// The HTTP method an HTTP-handler entry-point is responding to.  Used
/// by the App Router, FastAPI, Flask, Spring, Sinatra, and Express
/// entry-kind variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET,
    HEAD,
    POST,
    PUT,
    PATCH,
    DELETE,
    OPTIONS,
}

impl HttpMethod {
    /// Parse an HTTP method export name (`GET`, `POST`, ...).  Used by
    /// the Next.js App Router and Python FastAPI dispatchers.
    pub fn from_ident(ident: &str) -> Option<Self> {
        match ident.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::GET),
            "HEAD" => Some(Self::HEAD),
            "POST" => Some(Self::POST),
            "PUT" => Some(Self::PUT),
            "PATCH" => Some(Self::PATCH),
            "DELETE" => Some(Self::DELETE),
            "OPTIONS" => Some(Self::OPTIONS),
            _ => None,
        }
    }
}

/// Entry-point classification recorded on a function summary.  Phase 16
/// adds variants for Python, Java, Ruby, Rust, Go, and non-Next.js
/// Express handlers.  Each variant carries the language tag implicit
/// in the variant identity so seeding policy can branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryKind {
    // ── Phase 10 (JS/TS — Next.js) ────────────────────────────────────
    /// `'use server'` directive (file-level *or* function-level).  The
    /// file-level form marks every exported function in the file; the
    /// function-level form marks one specific function whose first
    /// statement is the directive.
    UseServerDirective,
    /// A function exported from `app/**/route.{ts,tsx,js,jsx}` whose
    /// name is one of the recognised HTTP methods.
    AppRouteHandler { method: HttpMethod },
    /// A `<form action={...}>` server-action callee.  Reserved for
    /// future detection; not produced by [`detect_entries_in_file`]
    /// today, but the variant is part of the on-disk shape so older
    /// summaries serialise / deserialise cleanly when this expands.
    FormAction,

    // ── Phase 16 (cross-language) ─────────────────────────────────────
    /// Python — Django class-based view method (`get`, `post`, etc.) or
    /// function-based view decorated with `@require_http_methods` /
    /// `@api_view`.  First param is `self` for class-based, second is
    /// the `HttpRequest`; for function-based the first param is the
    /// `HttpRequest`.  All formals are seeded as Source (the request
    /// object itself + any path-captured arguments).
    ///
    /// `method` carries the HTTP verb derived from the function name
    /// (CBV) or the first decorator argument (`@api_view(['POST'])` /
    /// `@require_http_methods(['PUT'])`).  Defaults to `GET` when no
    /// verb evidence is available.
    DjangoView { method: HttpMethod },
    /// Python — FastAPI route registered via decorator `@app.get(...)`
    /// / `@router.post(...)`.  Formals are query / path / body
    /// extractors; every formal is seeded as Source.
    FastApiRoute { method: HttpMethod },
    /// Python — Flask route registered via `@app.route(...)` /
    /// `@bp.get(...)`.  Method defaults to GET when the decorator
    /// omits an explicit `methods=[...]` list.
    FlaskRoute { method: HttpMethod },

    // Java
    /// Java — Spring `@RequestMapping` / `@GetMapping` / `@PostMapping`
    /// / `@PutMapping` / `@PatchMapping` / `@DeleteMapping` annotated
    /// controller method.
    SpringMapping { method: HttpMethod },
    /// Java — JAX-RS `@Path`-annotated resource method.  Method comes
    /// from the verb annotation (`@GET`, `@POST`, etc.) when present.
    JaxRsResource,

    // Ruby
    /// Ruby — Rails `ActionController` action method (a public
    /// instance method on a class extending `ApplicationController` /
    /// `ActionController::Base`).  No parameters in the formal list;
    /// taint flows through the implicit `params` source.
    RailsAction,
    /// Ruby — Sinatra `get '/path' do |arg| ... end` block.
    SinatraRoute { method: HttpMethod },

    // Rust
    /// Rust — axum handler.  Conservative recognition: a function whose
    /// signature contains an axum extractor type (`Query<_>`,
    /// `Json<_>`, `Path<_>`, `Form<_>`, `Extension<_>`, `State<_>`,
    /// `Request`, `HeaderMap`, etc.) — strong enough signal that a
    /// router maps the path to the function.
    AxumHandler,
    /// Rust — actix-web handler.  Recognised by the routing macros
    /// `#[get("...")]` / `#[post("...")]` / etc. attached to the
    /// function item.
    ActixHandler,
    /// Rust — Rocket handler.  Recognised by the routing macros
    /// `#[get("...")]` / `#[post("...")]` / `#[route(GET, "...")]`
    /// attached to the function item.  Note the macro name overlaps
    /// with actix-web; disambiguation requires import-site evidence
    /// which Phase 16 does not consult — the conservative tag is
    /// `RocketRoute` when the function is in a file containing a
    /// Rocket-specific witness (`#[launch]`, `rocket::build`).
    RocketRoute,

    // Go
    /// Go — `net/http` `func(w http.ResponseWriter, r *http.Request)`
    /// handler.  Shape-based recognition: any function whose param
    /// list ends with a `*http.Request` is treated as an HTTP handler.
    GoNetHttp,
    /// Go — gin handler (`func(c *gin.Context)`) or echo handler
    /// (`func(c echo.Context) error`) or chi handler.  All carry a
    /// single context-receiver parameter whose type contains "Context".
    GinRoute,

    // Express (non-Next.js JS/TS)
    /// Express / Koa / Fastify handler.  Recognised at the
    /// registration site (`app.get('/path', handler)` etc.) by
    /// resolving the callback identifier to a function definition in
    /// the same file.  Anonymous arrow callbacks at the call site are
    /// tagged on the arrow definition itself.
    ExpressRoute { method: HttpMethod },
}

/// Detect every entry-point function in a single parsed file.
///
/// The result keys each detected function by its tree-sitter byte
/// span `(start, end)`.  The summary-extraction pipeline matches
/// against [`crate::cfg::BodyMeta::span`] to attach the [`EntryKind`]
/// to the corresponding summary.
///
/// Returns an empty map for unsupported languages and for files
/// without any recognised entry shape.  No caller has to special-case
/// the empty result.
pub fn detect_entries_in_file(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    lang_slug: &str,
) -> HashMap<(usize, usize), EntryKind> {
    let root = tree.root_node();
    match lang_slug {
        "javascript" | "typescript" | "tsx" => detect_js_ts(root, bytes, path),
        "python" => detect_python(root, bytes),
        "java" => detect_java(root, bytes),
        "ruby" => detect_ruby(root, bytes),
        "rust" => detect_rust(root, bytes),
        "go" => detect_go(root, bytes),
        _ => HashMap::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// JS / TS — Next.js (Phase 10) + Express (Phase 16)
// ─────────────────────────────────────────────────────────────────────

fn detect_js_ts(
    root: Node<'_>,
    bytes: &[u8],
    path: &Path,
) -> HashMap<(usize, usize), EntryKind> {
    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();

    let file_use_server = file_level_use_server(root, bytes);
    let route_methods = if is_app_route_path(path) {
        Some(collect_route_handler_exports(root, bytes))
    } else {
        None
    };

    // Express: collect `app.METHOD("...", handler)` / `router.METHOD(...)`
    // call sites and resolve handler identifiers to function definitions.
    let express_handlers = collect_express_handlers(root, bytes);

    walk_functions_js(root, bytes, &mut |node, name| {
        let span = (node.start_byte(), node.end_byte());

        if function_level_use_server(node, bytes) {
            entries
                .entry(span)
                .or_insert(EntryKind::UseServerDirective);
            return;
        }

        if file_use_server && exports_function(node, root, bytes, name) {
            entries
                .entry(span)
                .or_insert(EntryKind::UseServerDirective);
            return;
        }

        if let (Some(map), Some(name)) = (&route_methods, name)
            && let Some(method) = map.get(name).copied()
        {
            entries
                .entry(span)
                .or_insert(EntryKind::AppRouteHandler { method });
            return;
        }

        // Express handler resolution: matches by name (named function
        // declaration) OR by exact span (anonymous arrow registered at
        // the call site).
        if let Some(method) = express_handlers
            .by_span
            .get(&span)
            .copied()
            .or_else(|| name.and_then(|n| express_handlers.by_name.get(n).copied()))
        {
            entries
                .entry(span)
                .or_insert(EntryKind::ExpressRoute { method });
        }
    });

    entries
}

/// Path-based recogniser for `app/**/route.{ts,tsx,js,jsx}`.
fn is_app_route_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let recognised_basename = matches!(
        name,
        "route.ts" | "route.tsx" | "route.js" | "route.jsx"
    );
    if !recognised_basename {
        return false;
    }
    path.components()
        .any(|c| c.as_os_str().to_string_lossy() == "app")
}

/// Read the first non-comment top-level statement and return `true`
/// when it is a string-literal directive `'use server'` /
/// `"use server"`.
fn file_level_use_server(root: Node, bytes: &[u8]) -> bool {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "comment" | "hash_bang_line" => continue,
            "expression_statement" => {
                if let Some(stmt) = first_string_child(child)
                    && string_literal_equals(stmt, bytes, "use server")
                {
                    return true;
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

/// Per-function recogniser: `function() { 'use server'; ... }`.
fn function_level_use_server(func_node: Node, bytes: &[u8]) -> bool {
    let Some(body) = function_body_js(func_node) else {
        return false;
    };
    let mut cursor = body.walk();
    for stmt in body.children(&mut cursor) {
        match stmt.kind() {
            "comment" => continue,
            "expression_statement" => {
                if let Some(s) = first_string_child(stmt) {
                    return string_literal_equals(s, bytes, "use server");
                }
                return false;
            }
            "{" | "}" => continue,
            _ => return false,
        }
    }
    false
}

/// Walk every JS/TS function-like definition and invoke
/// `visit(node, name)` for each.
fn walk_functions_js<F: FnMut(Node, Option<&str>)>(
    root: Node,
    bytes: &[u8],
    visit: &mut F,
) {
    let mut cursor = root.walk();
    visit_recursive_js(root, bytes, &mut cursor, visit);
}

fn visit_recursive_js<F: FnMut(Node, Option<&str>)>(
    node: Node,
    bytes: &[u8],
    _cursor: &mut tree_sitter::TreeCursor,
    visit: &mut F,
) {
    match node.kind() {
        "function_declaration"
        | "function_expression"
        | "generator_function_declaration"
        | "generator_function" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok());
            visit(node, name);
        }
        "arrow_function" => {
            let name = function_name_for_arrow(node, bytes);
            visit(node, name.as_deref());
        }
        "method_definition" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok());
            visit(node, name);
        }
        _ => {}
    }
    let mut walker = node.walk();
    for child in node.children(&mut walker) {
        visit_recursive_js(child, bytes, _cursor, visit);
    }
}

/// Resolve the textual name attached to an arrow function via the
/// enclosing `const NAME = (…) => …` shape.  Returns `None` when the
/// arrow is not the initialiser of a `variable_declarator`.
fn function_name_for_arrow(node: Node, bytes: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "variable_declarator" {
        return None;
    }
    let name_node = parent.child_by_field_name("name")?;
    let text = name_node.utf8_text(bytes).ok()?;
    Some(text.to_string())
}

/// Get the body of a function-like node.  Returns the
/// `statement_block` for declarations / expressions; `None` for arrow
/// functions whose body is an expression rather than a block (those
/// cannot host a directive prologue).
fn function_body_js<'a>(func_node: Node<'a>) -> Option<Node<'a>> {
    let body = func_node.child_by_field_name("body")?;
    if body.kind() == "statement_block" {
        Some(body)
    } else {
        None
    }
}

/// Extract the first `string` child of an `expression_statement`.
fn first_string_child<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|child| child.kind() == "string")
}

/// Compare the textual content of a `string` node (quotes stripped)
/// to `expected`.
fn string_literal_equals(string_node: Node, bytes: &[u8], expected: &str) -> bool {
    let Ok(raw) = string_node.utf8_text(bytes) else {
        return false;
    };
    let trimmed = raw
        .trim()
        .trim_start_matches(['\'', '"', '`'])
        .trim_end_matches(['\'', '"', '`']);
    trimmed == expected
}

/// Decide whether a function declaration / arrow definition with the
/// given name is exported at the top level of the program.
fn exports_function(func_node: Node, root: Node, bytes: &[u8], name: Option<&str>) -> bool {
    if let Some(parent) = func_node.parent()
        && parent.kind() == "export_statement"
    {
        return true;
    }
    let mut cur = func_node;
    for _ in 0..4 {
        let Some(parent) = cur.parent() else {
            break;
        };
        if parent.kind() == "export_statement" {
            return true;
        }
        cur = parent;
    }
    if let Some(target) = name {
        let mut walker = root.walk();
        for child in root.children(&mut walker) {
            if child.kind() != "export_statement" {
                continue;
            }
            let mut cur = child.walk();
            for export_child in child.children(&mut cur) {
                if export_child.kind() == "export_clause" {
                    let mut spec = export_child.walk();
                    for s in export_child.children(&mut spec) {
                        if s.kind() == "export_specifier"
                            && s.child_by_field_name("name")
                                .and_then(|n| n.utf8_text(bytes).ok())
                                .is_some_and(|t| t == target)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Collect the names of exported HTTP-method functions in a
/// route-handler file.  The map binds each name to the matching
/// [`HttpMethod`].
fn collect_route_handler_exports(root: Node, bytes: &[u8]) -> HashMap<String, HttpMethod> {
    let mut out = HashMap::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "export_statement" {
            continue;
        }
        let mut walker = child.walk();
        for export_child in child.children(&mut walker) {
            collect_named_exports(export_child, bytes, &mut out);
        }
    }
    out
}

fn collect_named_exports(node: Node, bytes: &[u8], out: &mut HashMap<String, HttpMethod>) {
    match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok())
                && let Some(m) = HttpMethod::from_ident(name)
            {
                out.insert(name.to_string(), m);
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator"
                    && let Some(name) = child
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(bytes).ok())
                    && let Some(m) = HttpMethod::from_ident(name)
                {
                    out.insert(name.to_string(), m);
                }
            }
        }
        _ => {}
    }
}

/// Express handler resolution: collected from `app.METHOD(path, handler)` /
/// `router.METHOD(...)` call sites.  Anonymous arrow callbacks are
/// tagged by exact span; named identifier callbacks are tagged by name.
struct ExpressHandlers {
    by_name: HashMap<String, HttpMethod>,
    by_span: HashMap<(usize, usize), HttpMethod>,
}

fn collect_express_handlers(root: Node, bytes: &[u8]) -> ExpressHandlers {
    let mut out = ExpressHandlers {
        by_name: HashMap::new(),
        by_span: HashMap::new(),
    };
    walk_express_recursive(root, bytes, &mut out);
    out
}

fn walk_express_recursive(node: Node, bytes: &[u8], out: &mut ExpressHandlers) {
    if node.kind() == "call_expression"
        && let Some(method) = express_call_method(node, bytes)
        && let Some(args) = node.child_by_field_name("arguments")
    {
        let mut last_handler: Option<Node> = None;
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            last_handler = Some(arg);
        }
        if let Some(handler) = last_handler {
            match handler.kind() {
                "identifier" => {
                    if let Ok(name) = handler.utf8_text(bytes) {
                        out.by_name.insert(name.to_string(), method);
                    }
                }
                "arrow_function" | "function_expression" | "function_declaration" => {
                    out.by_span
                        .insert((handler.start_byte(), handler.end_byte()), method);
                }
                _ => {}
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_express_recursive(child, bytes, out);
    }
}

/// Recognise an Express-style `app.METHOD(...)` / `router.METHOD(...)`
/// call.  Returns the matching [`HttpMethod`] when the call shape is
/// `<receiver>.<verb>(...)` with `<verb>` an HTTP method AND the
/// receiver text looks like an Express app / router / route binding.
///
/// The receiver allowlist (suffixes `app` / `router` / `route` and the
/// constructor calls `express()` / `Router()`) keeps non-Express
/// `<obj>.post(...)` shapes out of the entry-point set — e.g. an HTTP
/// client `client.post(url, body, cb)` whose last positional argument
/// happens to be a callback would otherwise be tagged as an
/// `EntryKind::ExpressRoute` and propagate the seeding policy onto
/// unrelated functions.
fn express_call_method(call_node: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let func = call_node.child_by_field_name("function")?;
    if func.kind() != "member_expression" {
        return None;
    }
    let prop = func.child_by_field_name("property")?;
    let name = prop.utf8_text(bytes).ok()?;
    let method = HttpMethod::from_ident(name)?;
    let object = func.child_by_field_name("object")?;
    if !express_receiver_text_matches(object, bytes) {
        return None;
    }
    Some(method)
}

/// Returns `true` when `object` looks like an Express app / router /
/// route binding.  Accepted shapes:
///   * Identifier whose text is exactly `app` / `router` / `route` or
///     ends with one of those (e.g. `apiRouter`, `userApp`).
///   * Member expression whose property is `app` / `router` / `route`
///     (e.g. `this.router`, `module.exports.app`).
///   * Call expression whose callee is `express()` or `Router()`
///     (e.g. `express().get(...)`, `Router().post(...)`).
fn express_receiver_text_matches(object: Node, bytes: &[u8]) -> bool {
    fn matches_suffix(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower == "app"
            || lower == "router"
            || lower == "route"
            || lower.ends_with("app")
            || lower.ends_with("router")
            || lower.ends_with("route")
    }
    match object.kind() {
        "identifier" | "property_identifier" => object
            .utf8_text(bytes)
            .ok()
            .is_some_and(matches_suffix),
        "member_expression" => object
            .child_by_field_name("property")
            .and_then(|p| p.utf8_text(bytes).ok())
            .is_some_and(matches_suffix),
        "call_expression" => {
            // `express()` / `Router()` constructor inline.
            let Some(callee) = object.child_by_field_name("function") else {
                return false;
            };
            let Ok(text) = callee.utf8_text(bytes) else {
                return false;
            };
            let leaf = text.rsplit('.').next().unwrap_or(text).trim();
            leaf == "express" || leaf == "Router" || leaf == "express.Router"
        }
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Python — Django / FastAPI / Flask
// ─────────────────────────────────────────────────────────────────────

fn detect_python(root: Node, bytes: &[u8]) -> HashMap<(usize, usize), EntryKind> {
    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();
    walk_python(root, bytes, &mut |func_node, decorated_node| {
        let span = (func_node.start_byte(), func_node.end_byte());

        // FastAPI / Flask take the decorator as a `@app.<method>(...)`
        // call expression on the `decorated_definition` node.
        if let Some(dec) = decorated_node
            && let Some(kind) = python_decorator_entry_kind(dec, bytes)
        {
            entries.entry(span).or_insert(kind);
            return;
        }

        // Django class-based views: a method named `get`/`post`/... on
        // a class derived from `View` / `APIView` / `ViewSet`.
        if let Some(kind) = python_django_method_kind(func_node, bytes) {
            entries.entry(span).or_insert(kind);
        }
    });
    entries
}

fn walk_python<'a, F>(node: Node<'a>, _bytes: &'a [u8], visit: &mut F)
where
    F: FnMut(Node<'a>, Option<Node<'a>>),
{
    if node.kind() == "function_definition" {
        let dec = node
            .parent()
            .filter(|p| p.kind() == "decorated_definition");
        visit(node, dec);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_python(child, _bytes, visit);
    }
}

fn python_decorator_entry_kind(decorated: Node, bytes: &[u8]) -> Option<EntryKind> {
    let mut cursor = decorated.walk();
    for ch in decorated.children(&mut cursor) {
        if ch.kind() != "decorator" {
            continue;
        }
        let mut dw = ch.walk();
        let expr = ch.children(&mut dw).find(|c| c.kind() != "@")?;
        // FastAPI / Flask shape: `@app.get(...)` / `@router.post("/")`
        // / `@app.route("/", methods=["GET","POST"])`.
        let (call_target, call_args) = match expr.kind() {
            "call" => (
                expr.child_by_field_name("function"),
                expr.child_by_field_name("arguments"),
            ),
            _ => (Some(expr), None),
        };
        let Some(target) = call_target else { continue };
        if target.kind() != "attribute" {
            continue;
        }
        let attr = target.child_by_field_name("attribute")?;
        let attr_text = attr.utf8_text(bytes).ok()?;
        let attr_lower = attr_text.to_ascii_lowercase();
        if let Some(method) = HttpMethod::from_ident(attr_text) {
            return Some(EntryKind::FastApiRoute { method });
        }
        if attr_lower == "route" {
            // Flask `@app.route("/", methods=["POST"])` — extract
            // first method from the methods kwarg, default GET.
            let method = call_args
                .and_then(|args| extract_flask_methods_arg(args, bytes))
                .unwrap_or(HttpMethod::GET);
            return Some(EntryKind::FlaskRoute { method });
        }
        if matches!(
            attr_lower.as_str(),
            "websocket" | "websocket_route" | "include_router"
        ) {
            // FastAPI websocket / Starlette WebSocket — treat as a
            // FastApiRoute with GET so the same seeding policy
            // applies.
            return Some(EntryKind::FastApiRoute {
                method: HttpMethod::GET,
            });
        }
        // Django REST framework `@api_view(['GET'])`: extract first
        // method from the args list.
        if attr_lower == "api_view" || attr_lower == "require_http_methods" {
            let method = call_args
                .and_then(|args| extract_first_method_in_list(args, bytes))
                .unwrap_or(HttpMethod::GET);
            return Some(EntryKind::DjangoView { method });
        }
    }
    None
}

fn extract_flask_methods_arg(args: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() != "keyword_argument" {
            continue;
        }
        let name_node = arg.child_by_field_name("name")?;
        let Ok(name) = name_node.utf8_text(bytes) else {
            continue;
        };
        if name == "methods" {
            let value = arg.child_by_field_name("value")?;
            return extract_first_method_in_list(value, bytes);
        }
    }
    None
}

fn extract_first_method_in_list(node: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string" {
            let raw = child.utf8_text(bytes).ok()?;
            let trimmed = raw
                .trim()
                .trim_start_matches(['\'', '"'])
                .trim_end_matches(['\'', '"']);
            if let Some(m) = HttpMethod::from_ident(trimmed) {
                return Some(m);
            }
        }
    }
    None
}

fn python_django_method_kind(func_node: Node, bytes: &[u8]) -> Option<EntryKind> {
    // Django CBV: function named one of the HTTP methods inside a
    // `class_definition` whose superclass list mentions `View` /
    // `APIView` / `ViewSet`.
    let name_node = func_node.child_by_field_name("name")?;
    let name = name_node.utf8_text(bytes).ok()?;
    let method = HttpMethod::from_ident(name)?;
    let class = enclosing_python_class(func_node)?;
    let supers = class.child_by_field_name("superclasses")?;
    let mut cursor = supers.walk();
    for sup in supers.named_children(&mut cursor) {
        let text = sup.utf8_text(bytes).ok()?;
        if text.contains("View")
            || text.contains("APIView")
            || text.contains("ViewSet")
            || text.contains("TemplateView")
        {
            return Some(EntryKind::DjangoView { method });
        }
    }
    None
}

fn enclosing_python_class<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "class_definition" {
            return Some(p);
        }
        cur = p.parent();
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Java — Spring + JAX-RS
// ─────────────────────────────────────────────────────────────────────

fn detect_java(root: Node, bytes: &[u8]) -> HashMap<(usize, usize), EntryKind> {
    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();
    walk_java(root, bytes, &mut |method| {
        let span = (method.start_byte(), method.end_byte());
        if let Some(kind) = java_method_entry_kind(method, bytes) {
            entries.entry(span).or_insert(kind);
        }
    });
    entries
}

fn walk_java<'a, F>(node: Node<'a>, _bytes: &'a [u8], visit: &mut F)
where
    F: FnMut(Node<'a>),
{
    if node.kind() == "method_declaration" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_java(child, _bytes, visit);
    }
}

fn java_method_entry_kind(method: Node, bytes: &[u8]) -> Option<EntryKind> {
    let modifiers = method.child_by_field_name("modifiers").or_else(|| {
        let mut w = method.walk();
        method.children(&mut w).find(|c| c.kind() == "modifiers")
    })?;
    let mut cursor = modifiers.walk();
    for ch in modifiers.children(&mut cursor) {
        match ch.kind() {
            "marker_annotation" | "annotation" => {
                let name_node = ch.child_by_field_name("name")?;
                let name = name_node.utf8_text(bytes).ok()?;
                if let Some(kind) = java_annotation_to_entry_kind(name, ch, bytes) {
                    return Some(kind);
                }
            }
            _ => {}
        }
    }
    None
}

fn java_annotation_to_entry_kind(
    name: &str,
    annotation: Node,
    bytes: &[u8],
) -> Option<EntryKind> {
    match name {
        "RequestMapping" => {
            // `@RequestMapping(method = RequestMethod.POST)` carries the
            // verb on the `method` element-value-pair; default to GET when
            // absent (Spring itself defaults to "all verbs", but GET is
            // the safest single-method approximation for seeding policy).
            let method = extract_spring_request_mapping_method(annotation, bytes)
                .unwrap_or(HttpMethod::GET);
            Some(EntryKind::SpringMapping { method })
        }
        "GetMapping" => Some(EntryKind::SpringMapping {
            method: HttpMethod::GET,
        }),
        "PostMapping" => Some(EntryKind::SpringMapping {
            method: HttpMethod::POST,
        }),
        "PutMapping" => Some(EntryKind::SpringMapping {
            method: HttpMethod::PUT,
        }),
        "DeleteMapping" => Some(EntryKind::SpringMapping {
            method: HttpMethod::DELETE,
        }),
        "PatchMapping" => Some(EntryKind::SpringMapping {
            method: HttpMethod::PATCH,
        }),
        "Path" | "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {
            Some(EntryKind::JaxRsResource)
        }
        _ => None,
    }
}

/// Extract `method = RequestMethod.<VERB>` (or array form
/// `method = {RequestMethod.POST, RequestMethod.PUT}`, taking the first
/// entry) from a Java `@RequestMapping(...)` annotation node.
fn extract_spring_request_mapping_method(annotation: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let args = annotation.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() != "element_value_pair" {
            continue;
        }
        let key_node = child.child_by_field_name("key")?;
        let key = key_node.utf8_text(bytes).ok()?;
        if key != "method" {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        if let Some(m) = http_method_from_request_method_text(value, bytes) {
            return Some(m);
        }
    }
    None
}

/// Parse `RequestMethod.POST` (or its bare leaf `POST`) from an
/// `element_value` node.  Falls through to scan an array initialiser
/// (`{RequestMethod.GET, RequestMethod.POST}`) and returns the first
/// recognised verb.
fn http_method_from_request_method_text(node: Node, bytes: &[u8]) -> Option<HttpMethod> {
    let raw = node.utf8_text(bytes).ok()?;
    let trimmed = raw.trim().trim_matches('{').trim_matches('}');
    for token in trimmed.split(',') {
        let leaf = token.trim().rsplit('.').next().unwrap_or("").trim();
        if let Some(m) = HttpMethod::from_ident(leaf) {
            return Some(m);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Ruby — Rails + Sinatra
// ─────────────────────────────────────────────────────────────────────

fn detect_ruby(root: Node, bytes: &[u8]) -> HashMap<(usize, usize), EntryKind> {
    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();
    walk_ruby_methods(root, bytes, &mut |method| {
        let span = (method.start_byte(), method.end_byte());
        if let Some(class) = enclosing_ruby_controller(method, bytes) {
            let _ = class;
            entries.entry(span).or_insert(EntryKind::RailsAction);
        }
    });
    walk_ruby_sinatra(root, bytes, &mut |block, method| {
        let span = (block.start_byte(), block.end_byte());
        entries
            .entry(span)
            .or_insert(EntryKind::SinatraRoute { method });
    });
    entries
}

fn walk_ruby_methods<'a, F>(node: Node<'a>, _bytes: &'a [u8], visit: &mut F)
where
    F: FnMut(Node<'a>),
{
    if node.kind() == "method" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ruby_methods(child, _bytes, visit);
    }
}

fn enclosing_ruby_controller<'a>(node: Node<'a>, bytes: &'a [u8]) -> Option<Node<'a>> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "class" {
            // Recognise any class extending an `*Controller` superclass
            // (`ApplicationController`, `ActionController::Base`, etc.)
            // OR a class whose own name ends in `Controller`.
            if let Some(sup) = p.child_by_field_name("superclass")
                && let Ok(text) = sup.utf8_text(bytes)
                && text.contains("Controller")
            {
                return Some(p);
            }
            if let Some(name_node) = p.child_by_field_name("name")
                && let Ok(name) = name_node.utf8_text(bytes)
                && name.ends_with("Controller")
            {
                return Some(p);
            }
        }
        cur = p.parent();
    }
    None
}

fn walk_ruby_sinatra<'a, F>(node: Node<'a>, bytes: &'a [u8], visit: &mut F)
where
    F: FnMut(Node<'a>, HttpMethod),
{
    if node.kind() == "call" {
        // Sinatra DSL: `get '/path' do |arg| ... end`.  In tree-sitter-ruby
        // `get '/x' do ... end` parses as a `call` whose `method` field is
        // `get` and whose argument is the path.  The `do` block is a
        // sibling `do_block` child.
        if let Some(method_node) = node.child_by_field_name("method")
            && let Ok(method_text) = method_node.utf8_text(bytes)
            && let Some(method) = HttpMethod::from_ident(method_text)
        {
            if let Some(block) = node.child_by_field_name("block") {
                visit(block, method);
            } else {
                // Look for a sibling do_block child
                let mut w = node.walk();
                for ch in node.children(&mut w) {
                    if ch.kind() == "do_block" || ch.kind() == "block" {
                        visit(ch, method);
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ruby_sinatra(child, bytes, visit);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Rust — axum / actix-web / rocket
// ─────────────────────────────────────────────────────────────────────

fn detect_rust(root: Node, bytes: &[u8]) -> HashMap<(usize, usize), EntryKind> {
    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();
    let file_text = std::str::from_utf8(bytes).unwrap_or("");
    let has_rocket_witness = file_text.contains("rocket::")
        || file_text.contains("#[launch]")
        || file_text.contains("rocket::build")
        || file_text.contains("use rocket");
    let has_axum_witness = file_text.contains("axum::")
        || file_text.contains("use axum")
        || file_text.contains("axum::Router");
    walk_rust(root, bytes, &mut |func| {
        let span = (func.start_byte(), func.end_byte());
        if let Some(kind) =
            rust_function_entry_kind(func, bytes, has_rocket_witness, has_axum_witness)
        {
            entries.entry(span).or_insert(kind);
        }
    });
    entries
}

fn walk_rust<'a, F>(node: Node<'a>, _bytes: &'a [u8], visit: &mut F)
where
    F: FnMut(Node<'a>),
{
    if node.kind() == "function_item" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_rust(child, _bytes, visit);
    }
}

fn rust_function_entry_kind(
    func: Node,
    bytes: &[u8],
    has_rocket_witness: bool,
    has_axum_witness: bool,
) -> Option<EntryKind> {
    // 1. macro-attribute recognition: `#[get("/x")]` / `#[post(...)]` /
    //    `#[route(GET, "/x")]` etc.
    let attrs_text = collect_rust_attribute_text(func, bytes);
    let has_routing_attr = attrs_text.iter().any(|s| {
        let t = s.trim_start_matches(['#', '!', '[']);
        t.starts_with("get(")
            || t.starts_with("post(")
            || t.starts_with("put(")
            || t.starts_with("delete(")
            || t.starts_with("patch(")
            || t.starts_with("head(")
            || t.starts_with("options(")
            || t.starts_with("route(")
            || t.starts_with("connect(")
            || t.starts_with("trace(")
    });
    if has_routing_attr {
        if has_rocket_witness {
            return Some(EntryKind::RocketRoute);
        }
        return Some(EntryKind::ActixHandler);
    }

    // 2. axum handler: signature contains an axum extractor type.
    if has_axum_witness && rust_signature_has_axum_extractor(func, bytes) {
        return Some(EntryKind::AxumHandler);
    }

    None
}

fn collect_rust_attribute_text(func: Node, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut harvest = |node: Node<'_>| {
        if let Ok(text) = node.utf8_text(bytes) {
            out.push(text.to_string());
        }
    };
    let mut w = func.walk();
    for ch in func.children(&mut w) {
        if ch.kind() == "attribute_item" || ch.kind() == "inner_attribute_item" {
            // get the inside `attribute` so we have just the call shape.
            let mut aw = ch.walk();
            for inner in ch.children(&mut aw) {
                if inner.kind() == "attribute" {
                    harvest(inner);
                }
            }
        }
    }
    if let Some(parent) = func.parent() {
        let mut pw = parent.walk();
        let mut pending: Vec<Node<'_>> = Vec::new();
        for sib in parent.children(&mut pw) {
            if sib.id() == func.id() {
                for p in &pending {
                    let mut aw = p.walk();
                    for inner in p.children(&mut aw) {
                        if inner.kind() == "attribute" {
                            harvest(inner);
                        }
                    }
                }
                break;
            }
            if sib.kind() == "attribute_item" || sib.kind() == "inner_attribute_item" {
                pending.push(sib);
            } else {
                pending.clear();
            }
        }
    }
    out
}

fn rust_signature_has_axum_extractor(func: Node, bytes: &[u8]) -> bool {
    let Some(params) = func.child_by_field_name("parameters") else {
        return false;
    };
    let Ok(text) = params.utf8_text(bytes) else {
        return false;
    };
    // Conservative substring scan against known axum extractor types.
    let needles = [
        "Query<",
        "Json<",
        "Path<",
        "Form<",
        "Extension<",
        "State<",
        "TypedHeader<",
        "Multipart",
        "HeaderMap",
        "Request<",
        "Body",
        "WebSocketUpgrade",
    ];
    needles.iter().any(|n| text.contains(n))
}

// ─────────────────────────────────────────────────────────────────────
// Go — net/http + gin / echo / chi
// ─────────────────────────────────────────────────────────────────────

fn detect_go(root: Node, bytes: &[u8]) -> HashMap<(usize, usize), EntryKind> {
    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();
    walk_go(root, bytes, &mut |func| {
        let span = (func.start_byte(), func.end_byte());
        if let Some(kind) = go_function_entry_kind(func, bytes) {
            entries.entry(span).or_insert(kind);
        }
    });
    entries
}

fn walk_go<'a, F>(node: Node<'a>, _bytes: &'a [u8], visit: &mut F)
where
    F: FnMut(Node<'a>),
{
    if matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    ) {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_go(child, _bytes, visit);
    }
}

fn go_function_entry_kind(func: Node, bytes: &[u8]) -> Option<EntryKind> {
    let params = func.child_by_field_name("parameters")?;
    let Ok(text) = params.utf8_text(bytes) else {
        return None;
    };
    // net/http: signature ends with `*http.Request` (with or without the
    // leading `http.ResponseWriter` writer arg).
    if text.contains("http.Request") || text.contains("*http.Request") {
        return Some(EntryKind::GoNetHttp);
    }
    // gin: `*gin.Context`; echo: `echo.Context`; chi (passes std http
    // handler); fiber: `*fiber.Ctx`.
    if text.contains("gin.Context")
        || text.contains("echo.Context")
        || text.contains("fiber.Ctx")
        || text.contains("iris.Context")
    {
        return Some(EntryKind::GinRoute);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_lang(source: &str, lang: &str, path: &str) -> HashMap<(usize, usize), EntryKind> {
        let mut parser = tree_sitter::Parser::new();
        let language = match lang {
            "javascript" => tree_sitter_javascript::LANGUAGE.into(),
            "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            "python" => tree_sitter_python::LANGUAGE.into(),
            "java" => tree_sitter_java::LANGUAGE.into(),
            "ruby" => tree_sitter_ruby::LANGUAGE.into(),
            "rust" => tree_sitter_rust::LANGUAGE.into(),
            "go" => tree_sitter_go::LANGUAGE.into(),
            _ => panic!("unknown lang"),
        };
        parser.set_language(&language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        detect_entries_in_file(&tree, source.as_bytes(), Path::new(path), lang)
    }

    #[test]
    fn detects_python_fastapi_route() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/items/{id}")
async def read_item(id: str):
    return {"id": id}
"#;
        let entries = detect_lang(src, "python", "main.py");
        assert!(
            entries.values().any(|e| matches!(
                e,
                EntryKind::FastApiRoute {
                    method: HttpMethod::GET
                }
            )),
            "expected FastApiRoute(GET); got {entries:?}"
        );
    }

    #[test]
    fn detects_python_flask_route() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route("/submit", methods=["POST"])
def submit(name):
    return name
"#;
        let entries = detect_lang(src, "python", "app.py");
        assert!(
            entries.values().any(|e| matches!(
                e,
                EntryKind::FlaskRoute {
                    method: HttpMethod::POST
                }
            )),
            "expected FlaskRoute(POST); got {entries:?}"
        );
    }

    #[test]
    fn detects_python_django_class_view() {
        let src = r#"
from django.views import View

class MyView(View):
    def get(self, request):
        return None
"#;
        let entries = detect_lang(src, "python", "views.py");
        assert!(
            entries
                .values()
                .any(|e| matches!(e, EntryKind::DjangoView { .. })),
            "expected DjangoView; got {entries:?}"
        );
    }

    #[test]
    fn detects_java_spring_get() {
        let src = r#"
package x;

import org.springframework.web.bind.annotation.GetMapping;

public class X {
    @GetMapping("/u")
    public String u(String n) { return n; }
}
"#;
        let entries = detect_lang(src, "java", "X.java");
        assert!(
            entries.values().any(|e| matches!(
                e,
                EntryKind::SpringMapping {
                    method: HttpMethod::GET
                }
            )),
            "expected SpringMapping(GET); got {entries:?}"
        );
    }

    #[test]
    fn detects_java_jaxrs_path() {
        let src = r#"
package x;

import javax.ws.rs.Path;

public class X {
    @Path("/u")
    public String u(String n) { return n; }
}
"#;
        let entries = detect_lang(src, "java", "X.java");
        assert!(
            entries.values().any(|e| matches!(e, EntryKind::JaxRsResource)),
            "expected JaxRsResource; got {entries:?}"
        );
    }

    #[test]
    fn detects_ruby_rails_action() {
        let src = r#"
class UsersController < ApplicationController
  def show
    @user = User.find(params[:id])
  end
end
"#;
        let entries = detect_lang(src, "ruby", "users_controller.rb");
        assert!(
            entries.values().any(|e| matches!(e, EntryKind::RailsAction)),
            "expected RailsAction; got {entries:?}"
        );
    }

    #[test]
    fn detects_ruby_sinatra_route() {
        let src = r#"
require 'sinatra'

get '/hello' do |name|
  "Hello #{name}"
end
"#;
        let entries = detect_lang(src, "ruby", "app.rb");
        assert!(
            entries.values().any(|e| matches!(
                e,
                EntryKind::SinatraRoute {
                    method: HttpMethod::GET
                }
            )),
            "expected SinatraRoute(GET); got {entries:?}"
        );
    }

    #[test]
    fn detects_rust_actix_handler() {
        let src = r#"
use actix_web::{get, web, HttpResponse};

#[get("/u/{name}")]
async fn u(name: web::Path<String>) -> HttpResponse {
    HttpResponse::Ok().body(name.into_inner())
}
"#;
        let entries = detect_lang(src, "rust", "u.rs");
        assert!(
            entries.values().any(|e| matches!(e, EntryKind::ActixHandler)),
            "expected ActixHandler; got {entries:?}"
        );
    }

    #[test]
    fn detects_rust_axum_handler_via_extractor() {
        let src = r#"
use axum::{extract::Query, Router};

async fn list(Query(q): Query<String>) -> String {
    q
}
"#;
        let entries = detect_lang(src, "rust", "list.rs");
        assert!(
            entries.values().any(|e| matches!(e, EntryKind::AxumHandler)),
            "expected AxumHandler; got {entries:?}"
        );
    }

    #[test]
    fn detects_go_net_http_handler() {
        let src = r#"
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("hi"))
}
"#;
        let entries = detect_lang(src, "go", "main.go");
        assert!(
            entries.values().any(|e| matches!(e, EntryKind::GoNetHttp)),
            "expected GoNetHttp; got {entries:?}"
        );
    }

    #[test]
    fn detects_go_gin_handler() {
        let src = r#"
package main

import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
    c.String(200, "hi")
}
"#;
        let entries = detect_lang(src, "go", "main.go");
        assert!(
            entries.values().any(|e| matches!(e, EntryKind::GinRoute)),
            "expected GinRoute; got {entries:?}"
        );
    }

    #[test]
    fn detects_express_route_named_handler() {
        let src = r#"
const express = require('express');
const app = express();

function getUser(req, res) {
    res.send('hi');
}

app.get('/u', getUser);
"#;
        let entries = detect_lang(src, "javascript", "server.js");
        assert!(
            entries.values().any(|e| matches!(
                e,
                EntryKind::ExpressRoute {
                    method: HttpMethod::GET
                }
            )),
            "expected ExpressRoute(GET); got {entries:?}"
        );
    }

    #[test]
    fn detects_express_route_arrow_handler() {
        let src = r#"
const express = require('express');
const app = express();
app.post('/submit', (req, res) => {
    res.send(req.body.name);
});
"#;
        let entries = detect_lang(src, "javascript", "server.js");
        assert!(
            entries.values().any(|e| matches!(
                e,
                EntryKind::ExpressRoute {
                    method: HttpMethod::POST
                }
            )),
            "expected ExpressRoute(POST); got {entries:?}"
        );
    }

    /// Regression: phase 10 fixture must still detect the `'use server'`
    /// directive at the file level so existing nextjs_entrypoints test
    /// stays green.
    #[test]
    fn regression_use_server_file_level() {
        let src = r#"
"use server";

export async function submit(userId) {
    return userId;
}
"#;
        let entries = detect_lang(src, "javascript", "actions.ts");
        assert!(
            entries
                .values()
                .any(|e| matches!(e, EntryKind::UseServerDirective)),
            "expected UseServerDirective; got {entries:?}"
        );
    }
}

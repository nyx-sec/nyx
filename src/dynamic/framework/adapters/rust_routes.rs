//! Shared Rust-route adapter helpers (Phase 17 — Track L.15).
//!
//! The axum / actix-web / rocket / warp adapters all need the same
//! handful of tree-sitter helpers: locate a `function_item` by name,
//! enumerate formal parameter names, walk macro/attribute invocations
//! (`#[get("/x")]` for actix / rocket, `Router::new().route(...)` for
//! axum, `warp::path!(...)`for warp), extract HTTP verbs / path
//! templates, and bind formals to request slots.
//!
//! Placeholder vocabulary:
//!   - axum / actix / rocket use `{id}` or `<id>`.
//!   - warp uses `warp::path!("users" / u32)` style — different
//!     paradigm; the warp adapter binds formals positionally rather
//!     than by name.

use crate::dynamic::framework::{HttpMethod, ParamBinding, ParamSource};
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known axum markers.
pub fn source_imports_axum(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"use axum::",
            b"axum::Router",
            b"axum::routing",
            b"Router::new",
            b"IntoResponse",
            b"// nyx-shape: axum",
        ],
    )
}

/// True when `bytes` carries any of the well-known actix-web markers.
pub fn source_imports_actix(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"use actix_web",
            b"actix_web::",
            b"App::new",
            b"HttpResponse",
            b"web::resource",
            b"// nyx-shape: actix",
        ],
    )
}

/// True when `bytes` carries any of the well-known rocket markers.
pub fn source_imports_rocket(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"use rocket::",
            b"#[macro_use] extern crate rocket",
            b"rocket::routes",
            b"#[launch]",
            b"// nyx-shape: rocket",
        ],
    )
}

/// True when `bytes` carries any of the well-known warp markers.
pub fn source_imports_warp(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"use warp::",
            b"warp::Filter",
            b"warp::path",
            b"warp::serve",
            b"// nyx-shape: warp",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Find a top-level `function_item` whose `name` field equals
/// `target`.  Walks the AST recursively so functions nested inside
/// `impl` blocks are also matched.
pub fn find_rust_function<'a>(root: Node<'a>, bytes: &'a [u8], target: &str) -> Option<Node<'a>> {
    let mut hit: Option<Node<'a>> = None;
    walk_rs(root, bytes, target, &mut hit);
    hit
}

fn walk_rs<'a>(node: Node<'a>, bytes: &'a [u8], target: &str, out: &mut Option<Node<'a>>) {
    if out.is_some() {
        return;
    }
    if node.kind() == "function_item"
        && let Some(name) = node.child_by_field_name("name")
        && let Ok(text) = name.utf8_text(bytes)
        && text == target
    {
        *out = Some(node);
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_rs(child, bytes, target, out);
    }
}

/// Enumerate formal parameter names from a `function_item`'s
/// `parameters` field.  Skips the implicit `self` receiver and
/// `_` patterns.  Returns names in declaration order.
pub fn rust_formal_names(func: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(params) = func.child_by_field_name("parameters") else {
        return out;
    };
    let mut cur = params.walk();
    for p in params.named_children(&mut cur) {
        match p.kind() {
            "self_parameter" => {}
            "parameter" => {
                if let Some(pat) = p.child_by_field_name("pattern") {
                    push_pattern_name(pat, bytes, &mut out);
                }
            }
            _ => {}
        }
    }
    out
}

fn push_pattern_name(pat: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    match pat.kind() {
        "identifier" => {
            if let Ok(text) = pat.utf8_text(bytes)
                && text != "_"
            {
                out.push(text.to_owned());
            }
        }
        "mut_pattern" | "ref_pattern" => {
            let mut cur = pat.walk();
            if let Some(inner) = pat.named_children(&mut cur).next() {
                push_pattern_name(inner, bytes, out);
            }
        }
        _ => {}
    }
}

/// Extract placeholder names from a Rust framework route path
/// template.
///
/// Supports:
///   - axum / actix / rocket / chi-style `{id}`: `/u/{id}` → `id`
///   - rocket `<id>` syntax:               `/u/<id>` → `id`
///   - typed rocket `<id..>` syntax:       `/u/<id..>` → `id`
pub fn extract_rust_path_placeholders(path: &str) -> Vec<String> {
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
            b'{' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                    let inner = &path[i + 1..i + 1 + end];
                    let name = inner.split(':').next().unwrap_or(inner);
                    let name = name.trim_end_matches('*').trim_end_matches('?');
                    push(name.to_owned());
                    i += end + 2;
                    continue;
                }
            }
            b'<' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'>') {
                    let inner = &path[i + 1..i + 1 + end];
                    let name = inner.trim_end_matches("..");
                    push(name.to_owned());
                    i += end + 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Bind formals to request slots given a Rust route path template.
///
/// Names matching the path placeholder list become a
/// [`ParamSource::PathSegment`]; `req` / `request` / `state` formals
/// fall to [`ParamSource::Implicit`]; every other formal becomes a
/// [`ParamSource::QueryParam`].
///
/// warp's `warp::path!("users" / u32)` macro reconstructs placeholders
/// as type names (`u32`) rather than parameter names because the
/// segments are positional. When the placeholder list contains
/// typed-anonymous segments (Rust primitive type names like `u32` /
/// `String` / `Uuid`), the n-th typed-anonymous placeholder binds
/// positionally to the n-th non-implicit formal so handler signatures
/// like `fn show(id: u32)` bind `id` as a path segment instead of a
/// query param.
pub fn bind_rust_path_params(formals: &[String], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_rust_path_placeholders(path);
    let typed_anon_count = placeholders
        .iter()
        .filter(|p| is_typed_anonymous_placeholder(p))
        .count();
    let mut non_implicit_seen = 0usize;
    formals
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let source = if is_implicit_formal(name) {
                ParamSource::Implicit
            } else {
                let positional_slot = non_implicit_seen;
                non_implicit_seen += 1;
                let is_named_match = placeholders.iter().any(|p| p == name);
                if is_named_match || positional_slot < typed_anon_count {
                    ParamSource::PathSegment(name.clone())
                } else {
                    ParamSource::QueryParam(name.clone())
                }
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
    matches!(name, "req" | "request" | "state" | "ctx" | "cx" | "headers")
}

fn is_typed_anonymous_placeholder(name: &str) -> bool {
    matches!(
        name,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f32"
            | "f64"
            | "bool"
            | "char"
            | "String"
            | "str"
            | "Uuid"
    )
}

/// Parse Rust framework verb names (`get` / `post` / `put` / `patch`
/// / `delete` / `head` / `options`).  Both axum's lowercase routing
/// helpers (`get(handler)`) and actix's `web::get()` use the same
/// lowercase identifiers; rocket's attribute macro shape
/// (`#[get("/x")]`) uses the same.  Returns `None` for unrelated
/// identifiers.
pub fn verb_from_ident(ident: &str) -> Option<HttpMethod> {
    match ident.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::GET),
        "post" => Some(HttpMethod::POST),
        "put" => Some(HttpMethod::PUT),
        "patch" => Some(HttpMethod::PATCH),
        "delete" => Some(HttpMethod::DELETE),
        "head" => Some(HttpMethod::HEAD),
        "options" => Some(HttpMethod::OPTIONS),
        _ => None,
    }
}

/// Read the content of a Rust `string_literal` node, stripping the
/// surrounding `"` quotes.  Returns `None` if `node` is not a string
/// literal.
pub fn rust_string_literal(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let mut cur = node.walk();
    for c in node.named_children(&mut cur) {
        if c.kind() == "string_content" {
            return c.utf8_text(bytes).ok().map(str::to_owned);
        }
    }
    let raw = node.utf8_text(bytes).ok()?;
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        Some(trimmed[1..trimmed.len() - 1].to_owned())
    } else {
        None
    }
}

/// Walk every `attribute_item` immediately preceding `func` looking
/// for a `#[get("/path")]` / `#[post(...)]` / `#[route(...)]` macro.
/// Returns `(method, path)` on first match.  Used by both actix-web
/// (`#[get("/path")]`) and rocket (same syntax).
pub fn find_method_attribute<'a>(func: Node<'a>, bytes: &'a [u8]) -> Option<(HttpMethod, String)> {
    let parent = func.parent()?;
    let mut cur = parent.walk();
    let children: Vec<Node<'_>> = parent.children(&mut cur).collect();
    let pos = children.iter().position(|c| c.id() == func.id())?;
    // Walk backwards over attribute_items immediately above the
    // function declaration.
    for child in children[..pos].iter().rev() {
        if child.kind() == "attribute_item" {
            if let Some(hit) = read_route_attribute(*child, bytes) {
                return Some(hit);
            }
            continue;
        }
        if child.is_extra() {
            continue;
        }
        // Some grammars insert `line_comment` nodes between attributes
        // and the function; tolerate them but stop on any other named
        // child.
        if matches!(child.kind(), "line_comment" | "block_comment") {
            continue;
        }
        break;
    }
    // Fallback: some tree-sitter Rust grammar revisions wrap
    // attributes inside the function_item's own preamble.  Walk every
    // attribute_item descendent directly under the function node and
    // try those too.
    let mut cur = func.walk();
    for c in func.children(&mut cur) {
        if c.kind() == "attribute_item"
            && let Some(hit) = read_route_attribute(c, bytes)
        {
            return Some(hit);
        }
    }
    None
}

fn read_route_attribute(attr: Node<'_>, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut cur = attr.walk();
    let attribute = attr
        .named_children(&mut cur)
        .find(|c| c.kind() == "attribute")?;
    // The tree-sitter-rust grammar packs an attribute as
    // `<identifier|scoped_identifier> <token_tree>`.  Walk the named
    // children directly rather than `child_by_field_name`, since the
    // field labels (`path` / `arguments`) are not exposed across
    // grammar versions we depend on.
    let mut ac = attribute.walk();
    let children: Vec<Node<'_>> = attribute.named_children(&mut ac).collect();
    let head = children.first()?;
    let verb_text = match head.kind() {
        "identifier" => head.utf8_text(bytes).ok()?.to_owned(),
        "scoped_identifier" => {
            let mut sc = head.walk();
            head.named_children(&mut sc)
                .filter_map(|c| {
                    if c.kind() == "identifier" {
                        c.utf8_text(bytes).ok()
                    } else {
                        None
                    }
                })
                .last()?
                .to_owned()
        }
        _ => return None,
    };
    let method = verb_from_ident(&verb_text)?;
    for child in &children[1..] {
        if child.kind() == "token_tree" {
            // Recurse to find the first string_literal under the
            // token_tree (rocket also accepts `data = "<body>"` so we
            // can't restrict to the first child).
            if let Some(literal) = first_string_in(*child, bytes) {
                return Some((method, literal));
            }
        }
        if let Some(literal) = rust_string_literal(*child, bytes) {
            return Some((method, literal));
        }
    }
    None
}

fn first_string_in(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    if let Some(literal) = rust_string_literal(node, bytes) {
        return Some(literal);
    }
    let mut cur = node.walk();
    for child in node.named_children(&mut cur) {
        if let Some(literal) = first_string_in(child, bytes) {
            return Some(literal);
        }
    }
    None
}

/// Walk `root` looking for an axum `Router::new().route("/path",
/// get(handler))` / `.route("/path", post(handler))` chain that
/// registers `target` as the handler.  Returns `(method, path)` on
/// first match.
pub fn find_axum_route<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    walk_axum(root, bytes, target, &mut hit);
    hit
}

fn walk_axum<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(found) = try_axum_route_call(node, bytes, target)
    {
        *out = Some(found);
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_axum(child, bytes, target, out);
    }
}

fn try_axum_route_call<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "field_expression" {
        return None;
    }
    let field = func.child_by_field_name("field")?.utf8_text(bytes).ok()?;
    if field != "route" {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let positional: Vec<Node<'_>> = {
        let mut cur = args.walk();
        args.named_children(&mut cur)
            .filter(|c| !matches!(c.kind(), "line_comment" | "block_comment"))
            .collect()
    };
    if positional.len() < 2 {
        return None;
    }
    let path = rust_string_literal(positional[0], bytes)?;
    let (method, callable) = parse_axum_verb_wrapper(positional[1], bytes)?;
    if !axum_callable_matches(callable, bytes, target) {
        return None;
    }
    Some((method, path))
}

/// Parse the `get(handler)` / `axum::routing::get(handler)` wrapper
/// emitted by axum.  Returns `(method, handler_node)` on success.
fn parse_axum_verb_wrapper<'a>(node: Node<'a>, bytes: &'a [u8]) -> Option<(HttpMethod, Node<'a>)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    let leaf = match func.kind() {
        "identifier" => func.utf8_text(bytes).ok()?,
        "scoped_identifier" => func.child_by_field_name("name")?.utf8_text(bytes).ok()?,
        _ => return None,
    };
    let method = verb_from_ident(leaf)?;
    let args = node.child_by_field_name("arguments")?;
    let mut cur = args.walk();
    let handler = args
        .named_children(&mut cur)
        .find(|c| !matches!(c.kind(), "line_comment" | "block_comment"))?;
    Some((method, handler))
}

fn axum_callable_matches(node: Node<'_>, bytes: &[u8], target: &str) -> bool {
    match node.kind() {
        "identifier" => node.utf8_text(bytes).map(|s| s == target).unwrap_or(false),
        "scoped_identifier" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(bytes).ok())
            .map(|s| s == target)
            .unwrap_or(false),
        "field_expression" => node
            .child_by_field_name("field")
            .and_then(|n| n.utf8_text(bytes).ok())
            .map(|s| s == target)
            .unwrap_or(false),
        _ => false,
    }
}

/// Walk `root` looking for an actix-web chained-builder route registration
/// (`App::new().route("/path", web::get().to(handler))` or
/// `web::resource("/path").route(web::get().to(handler))`) that wires
/// `target` as the handler.  Returns `(method, path)` on first match.
pub fn find_actix_route_chain<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    walk_actix_chain(root, bytes, target, &mut hit);
    hit
}

fn walk_actix_chain<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(found) = try_actix_route_call(node, bytes, target)
    {
        *out = Some(found);
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_actix_chain(child, bytes, target, out);
    }
}

fn try_actix_route_call<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "field_expression" {
        return None;
    }
    let field = func.child_by_field_name("field")?.utf8_text(bytes).ok()?;
    if field != "route" {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let positional: Vec<Node<'_>> = {
        let mut cur = args.walk();
        args.named_children(&mut cur)
            .filter(|c| !matches!(c.kind(), "line_comment" | "block_comment"))
            .collect()
    };
    let (path, verb_node) = match positional.len() {
        2 => {
            let path = rust_string_literal(positional[0], bytes)?;
            (path, positional[1])
        }
        1 => {
            let receiver = func.child_by_field_name("value")?;
            let path = find_actix_resource_path(receiver, bytes)?;
            (path, positional[0])
        }
        _ => return None,
    };
    let (method, handler) = parse_actix_web_verb_to(verb_node, bytes)?;
    if !axum_callable_matches(handler, bytes, target) {
        return None;
    }
    Some((method, path))
}

/// Parse `web::get().to(handler)` / `web::post().to(handler)` /
/// `web::method(Method::PATCH).to(handler)` shapes.  Returns
/// `(method, handler_node)` on the first matching `.to(...)` call.
fn parse_actix_web_verb_to<'a>(node: Node<'a>, bytes: &'a [u8]) -> Option<(HttpMethod, Node<'a>)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if func.kind() != "field_expression" {
        return None;
    }
    let field = func.child_by_field_name("field")?.utf8_text(bytes).ok()?;
    if field != "to" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let handler = {
        let mut cur = args.walk();
        args.named_children(&mut cur)
            .find(|c| !matches!(c.kind(), "line_comment" | "block_comment"))?
    };
    let recv = func.child_by_field_name("value")?;
    if recv.kind() != "call_expression" {
        return None;
    }
    let recv_func = recv.child_by_field_name("function")?;
    let leaf = match recv_func.kind() {
        "scoped_identifier" => recv_func
            .child_by_field_name("name")?
            .utf8_text(bytes)
            .ok()?,
        "identifier" => recv_func.utf8_text(bytes).ok()?,
        _ => return None,
    };
    let method = verb_from_ident(leaf)?;
    Some((method, handler))
}

/// Walk a receiver-chain backwards looking for the first
/// `web::resource(path)` / `web::scope(path)` call.  Used when an actix
/// route is registered via `web::resource("/x").route(web::get().to(h))`
/// (no path argument on the `route` call itself).
fn find_actix_resource_path(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = node;
    loop {
        if cur.kind() == "call_expression" {
            let func = cur.child_by_field_name("function")?;
            let leaf = match func.kind() {
                "scoped_identifier" => func
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .unwrap_or(""),
                "identifier" => func.utf8_text(bytes).ok().unwrap_or(""),
                "field_expression" => {
                    cur = func.child_by_field_name("value")?;
                    continue;
                }
                _ => "",
            };
            if matches!(leaf, "resource" | "scope") {
                let args = cur.child_by_field_name("arguments")?;
                let mut cur_arg = args.walk();
                let first = args
                    .named_children(&mut cur_arg)
                    .find(|c| !matches!(c.kind(), "line_comment" | "block_comment"))?;
                return rust_string_literal(first, bytes);
            }
            return None;
        }
        return None;
    }
}

/// Walk `root` looking for a `warp::path!("users" / u32)` macro
/// invocation that bridges to `target` via `.map(target)` /
/// `.and_then(target)`.  Returns `(method, path)` on first match.
/// Method defaults to `GET` because warp's verb chain is added later
/// (`.and(warp::post())`); a future pass can refine.
pub fn find_warp_route<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    walk_warp(root, bytes, target, &mut hit);
    hit
}

fn walk_warp<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "macro_invocation"
        && let Some(path_text) = try_warp_path_macro(node, bytes)
    {
        // Walk siblings / outer call chain for a `.map(target)` /
        // `.and_then(target)` that wires this path macro to `target`.
        let mut parent = node.parent();
        let mut verb = HttpMethod::GET;
        let mut hit_target = false;
        while let Some(p) = parent {
            if p.kind() == "call_expression"
                && let Some(func) = p.child_by_field_name("function")
                && func.kind() == "field_expression"
                && let Some(field) = func.child_by_field_name("field")
                && let Ok(field_text) = field.utf8_text(bytes)
                && matches!(field_text, "map" | "and_then" | "untuple_one")
            {
                let args = p.child_by_field_name("arguments");
                if let Some(args) = args {
                    let mut cur = args.walk();
                    for c in args.named_children(&mut cur) {
                        if axum_callable_matches(c, bytes, target) {
                            hit_target = true;
                        }
                    }
                }
            }
            // Detect verb-filter calls (`warp::get()`, `warp::post()`).
            let mut cur = p.walk();
            for child in p.children(&mut cur) {
                if child.kind() == "call_expression"
                    && let Some(func) = child.child_by_field_name("function")
                    && func.kind() == "scoped_identifier"
                    && let Some(name) = func.child_by_field_name("name")
                    && let Ok(name_text) = name.utf8_text(bytes)
                    && let Some(method) = verb_from_ident(name_text)
                {
                    verb = method;
                }
            }
            parent = p.parent();
        }
        if hit_target {
            *out = Some((verb, path_text));
            return;
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_warp(child, bytes, target, out);
    }
}

fn try_warp_path_macro(invocation: Node<'_>, bytes: &[u8]) -> Option<String> {
    // Tree-sitter rust grammar surfaces the macro callee under
    // `macro` field.
    let macro_node = invocation.child_by_field_name("macro")?;
    let leaf = match macro_node.kind() {
        "identifier" => macro_node.utf8_text(bytes).ok()?,
        "scoped_identifier" => macro_node
            .child_by_field_name("name")?
            .utf8_text(bytes)
            .ok()?,
        _ => return None,
    };
    if leaf != "path" {
        return None;
    }
    // Reconstruct the path template from the macro's token tree.
    let mut cur = invocation.walk();
    let token_tree = invocation
        .named_children(&mut cur)
        .find(|c| c.kind() == "token_tree")?;
    let mut path = String::from("/");
    let mut first = true;
    let mut tc = token_tree.walk();
    for token in token_tree.named_children(&mut tc) {
        match token.kind() {
            "string_literal" => {
                let literal = rust_string_literal(token, bytes)?;
                if !first {
                    path.push('/');
                }
                path.push_str(&literal);
                first = false;
            }
            "primitive_type" | "type_identifier" | "identifier" => {
                if !first {
                    path.push('/');
                }
                if let Ok(text) = token.utf8_text(bytes) {
                    path.push_str(&format!("{{{}}}", text));
                }
                first = false;
            }
            _ => {}
        }
    }
    if first {
        return None;
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn extracts_brace_placeholders() {
        assert_eq!(extract_rust_path_placeholders("/u/{id}"), vec!["id"]);
        assert_eq!(
            extract_rust_path_placeholders("/u/{id}/posts/{slug}"),
            vec!["id", "slug"]
        );
    }

    #[test]
    fn extracts_rocket_angle_placeholders() {
        assert_eq!(extract_rust_path_placeholders("/u/<id>"), vec!["id"]);
        assert_eq!(extract_rust_path_placeholders("/u/<rest..>"), vec!["rest"]);
    }

    #[test]
    fn finds_axum_route_get() {
        let src: &[u8] = b"use axum::Router;\nfn build() -> Router { Router::new().route(\"/u/{id}\", get(show)) }\nfn show() {}\n";
        let tree = parse(src);
        let (method, path) = find_axum_route(tree.root_node(), src, "show").expect("hit");
        assert_eq!(method, HttpMethod::GET);
        assert_eq!(path, "/u/{id}");
    }

    #[test]
    fn finds_axum_route_with_scoped_verb() {
        let src: &[u8] = b"use axum::Router;\nfn build() -> Router { Router::new().route(\"/x\", axum::routing::post(save)) }\nfn save() {}\n";
        let tree = parse(src);
        let (method, path) = find_axum_route(tree.root_node(), src, "save").expect("hit");
        assert_eq!(method, HttpMethod::POST);
        assert_eq!(path, "/x");
    }

    #[test]
    fn finds_actix_get_attribute() {
        let src: &[u8] = b"#[get(\"/u/{id}\")]\nfn show(id: String) -> String { id }\n";
        let tree = parse(src);
        let func = find_rust_function(tree.root_node(), src, "show").unwrap();
        let (method, path) = find_method_attribute(func, src).expect("hit");
        assert_eq!(method, HttpMethod::GET);
        assert_eq!(path, "/u/{id}");
    }

    #[test]
    fn finds_rocket_post_attribute() {
        let src: &[u8] = b"#[post(\"/save\", data = \"<body>\")]\nfn save(body: String) {}\n";
        let tree = parse(src);
        let func = find_rust_function(tree.root_node(), src, "save").unwrap();
        let (method, path) = find_method_attribute(func, src).expect("hit");
        assert_eq!(method, HttpMethod::POST);
        assert_eq!(path, "/save");
    }

    #[test]
    fn binds_known_placeholder_as_path_segment() {
        let formals = vec!["id".to_string(), "extra".to_string()];
        let bindings = bind_rust_path_params(&formals, "/u/{id}");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[1].source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn binds_implicit_request_as_implicit() {
        let formals = vec![
            "req".to_string(),
            "request".to_string(),
            "state".to_string(),
        ];
        let bindings = bind_rust_path_params(&formals, "/x");
        for b in &bindings {
            assert!(matches!(b.source, ParamSource::Implicit));
        }
    }

    #[test]
    fn verb_recognises_get_post() {
        assert_eq!(verb_from_ident("get"), Some(HttpMethod::GET));
        assert_eq!(verb_from_ident("POST"), Some(HttpMethod::POST));
        assert_eq!(verb_from_ident("handler"), None);
    }

    #[test]
    fn finds_warp_path_macro_with_map_target() {
        let src: &[u8] = b"use warp::Filter;\nfn build() { let r = warp::path!(\"users\" / u32).map(show); }\nfn show(id: u32) -> String { String::new() }\n";
        let tree = parse(src);
        let (_method, path) = find_warp_route(tree.root_node(), src, "show").expect("hit");
        assert!(path.contains("users"));
    }

    #[test]
    fn warp_typed_anonymous_placeholder_binds_positionally() {
        let formals = vec!["id".to_string()];
        let bindings = bind_rust_path_params(&formals, "/users/{u32}");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn warp_multi_typed_anonymous_placeholders_bind_positionally() {
        let formals = vec!["user_id".to_string(), "post_slug".to_string()];
        let bindings = bind_rust_path_params(&formals, "/users/{u32}/posts/{String}");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[1].source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn warp_typed_anonymous_count_caps_positional_binding() {
        let formals = vec!["id".to_string(), "extra".to_string()];
        let bindings = bind_rust_path_params(&formals, "/users/{u32}");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[1].source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn warp_implicit_formals_skip_positional_binding() {
        let formals = vec!["req".to_string(), "id".to_string()];
        let bindings = bind_rust_path_params(&formals, "/users/{u32}");
        assert!(matches!(bindings[0].source, ParamSource::Implicit));
        assert!(matches!(bindings[1].source, ParamSource::PathSegment(_)));
    }
}

//! Shared JS/TS route adapter helpers (Phase 13 — Track L.11).
//!
//! The Express / Koa / NestJS / Fastify adapters all share a handful of
//! tree-sitter helpers: source-import sniffers, formal-name extractors,
//! callee-receiver normalisation, path-placeholder extraction, and a
//! per-formal binder that promotes `req` / `res` / `ctx` / `next` /
//! `reply` to [`ParamSource::Implicit`] and the rest to either
//! [`ParamSource::PathSegment`] or [`ParamSource::QueryParam`] depending
//! on whether a placeholder of the same name appears in the path
//! template.

use crate::dynamic::framework::{HttpMethod, ParamBinding, ParamSource};
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known Express import
/// stanzas (CommonJS or ESM).  Includes router-level imports
/// (`express.Router()`) so adapters can fire on files that only pull
/// in the router builder.
pub fn source_imports_express(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"require('express')",
            b"require(\"express\")",
            b"from 'express'",
            b"from \"express\"",
            b"express.Router(",
            b"express.Router()",
        ],
    )
}

/// True when `bytes` carries any of the well-known Koa import stanzas.
/// Covers Koa itself, `@koa/router`, and `koa-router`.
pub fn source_imports_koa(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"require('koa')",
            b"require(\"koa\")",
            b"from 'koa'",
            b"from \"koa\"",
            b"require('@koa/router')",
            b"require(\"@koa/router\")",
            b"from '@koa/router'",
            b"from \"@koa/router\"",
            b"require('koa-router')",
            b"require(\"koa-router\")",
            b"from 'koa-router'",
            b"from \"koa-router\"",
        ],
    )
}

/// True when `bytes` carries any of the well-known Fastify import
/// stanzas.
pub fn source_imports_fastify(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"require('fastify')",
            b"require(\"fastify\")",
            b"from 'fastify'",
            b"from \"fastify\"",
            b"fastify(",
        ],
    )
}

/// True when `bytes` carries any of the well-known NestJS import
/// stanzas.  NestJS is TypeScript-first so the markers include both the
/// decorator-import packages and the platform / factory entry points.
pub fn source_imports_nest(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"@nestjs/common",
            b"@nestjs/core",
            b"@nestjs/platform-express",
            b"@nestjs/platform-fastify",
            b"NestFactory",
            b"@Controller",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Extract the last segment of a member expression chain so
/// `app.get` / `router.get` / `fastify.get` all reduce to `"get"`.
/// Used by the per-framework adapters to classify the HTTP verb
/// regardless of the receiver alias.
pub fn last_segment(callee: &str) -> &str {
    callee.rsplit_once('.').map(|(_, s)| s).unwrap_or(callee)
}

/// Map a route-method name (`get` / `post` / `put` / `patch` /
/// `delete` / `options` / `head` / `all`) to an [`HttpMethod`].
/// Returns `None` for callees that do not look like an HTTP-verb
/// dispatch (so non-route `app.use(handler)` does not fire).
pub fn http_verb_from_method(name: &str) -> Option<HttpMethod> {
    match name.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::GET),
        "head" => Some(HttpMethod::HEAD),
        "post" => Some(HttpMethod::POST),
        "put" => Some(HttpMethod::PUT),
        "patch" => Some(HttpMethod::PATCH),
        "delete" | "del" => Some(HttpMethod::DELETE),
        "options" => Some(HttpMethod::OPTIONS),
        // `app.all` registers the handler against every verb — pick
        // GET as the canonical replay.
        "all" => Some(HttpMethod::GET),
        _ => None,
    }
}

/// Strip the surrounding quotes (`'`, `"`, or backticks) from a JS
/// string literal node's source text.  Returns the inner slice when
/// the literal is single-line and unquoted bytes only — multi-line
/// template literals fall back to the trimmed input.
pub fn strip_quotes(raw: &str) -> &str {
    let trimmed = raw.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
    {
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 2 {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

/// Find a top-level function declaration / function expression /
/// arrow function whose binding name equals `target`.  Returns the
/// `formal_parameters` (or `formal_parameter` for shorthand arrows)
/// node so callers can enumerate parameter names.
pub fn find_function_params<'a>(
    root: Node<'a>,
    bytes: &[u8],
    target: &str,
) -> Option<Node<'a>> {
    let mut hit: Option<Node<'a>> = None;
    walk_for_params(root, bytes, target, &mut hit);
    hit
}

fn walk_for_params<'a>(
    node: Node<'a>,
    bytes: &[u8],
    target: &str,
    out: &mut Option<Node<'a>>,
) {
    if out.is_some() {
        return;
    }
    match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok())
                && name == target
                && let Some(params) = node.child_by_field_name("parameters")
            {
                *out = Some(params);
                return;
            }
        }
        "method_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok())
                && name == target
                && let Some(params) = node.child_by_field_name("parameters")
            {
                *out = Some(params);
                return;
            }
        }
        "variable_declarator" | "assignment_expression" => {
            // `const name = function() {}`, `const name = (a,b) => ...`,
            // `name = function() {}`.
            let name_field = if node.kind() == "variable_declarator" {
                "name"
            } else {
                "left"
            };
            if let Some(name_node) = node.child_by_field_name(name_field)
                && let Some(name) = name_node.utf8_text(bytes).ok()
                && name == target
                && let Some(value) = node.child_by_field_name("value").or_else(|| {
                    if node.kind() == "assignment_expression" {
                        node.child_by_field_name("right")
                    } else {
                        None
                    }
                })
            {
                match value.kind() {
                    "function_expression"
                    | "function"
                    | "arrow_function"
                    | "generator_function" => {
                        if let Some(params) = value.child_by_field_name("parameters") {
                            *out = Some(params);
                            return;
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_for_params(child, bytes, target, out);
    }
}

/// Enumerate identifier names from a `formal_parameters` node.  Skips
/// the rest-element marker (`...`) and any destructuring wrappers so
/// the returned vector lines up with positional ordering of declared
/// parameters.
pub fn function_formal_names(params: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = params.walk();
    for child in params.named_children(&mut cur) {
        if let Some(name) = parameter_name(child, bytes) {
            out.push(name);
        }
    }
    out
}

fn parameter_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            node.utf8_text(bytes).ok().map(str::to_owned)
        }
        "assignment_pattern" | "required_parameter" | "optional_parameter" => {
            // `x = 1` / TypeScript `x: T` / `x?: T`
            if let Some(left) = node.child_by_field_name("left") {
                return parameter_name(left, bytes);
            }
            if let Some(pattern) = node.child_by_field_name("pattern") {
                return parameter_name(pattern, bytes);
            }
            let mut cur = node.walk();
            for c in node.named_children(&mut cur) {
                if c.kind() == "identifier" {
                    return c.utf8_text(bytes).ok().map(str::to_owned);
                }
                if let Some(n) = parameter_name(c, bytes) {
                    return Some(n);
                }
            }
            None
        }
        "rest_pattern" | "object_pattern" | "array_pattern" => {
            let mut cur = node.walk();
            for c in node.named_children(&mut cur) {
                if let Some(n) = parameter_name(c, bytes) {
                    return Some(n);
                }
            }
            None
        }
        _ => None,
    }
}

/// Bind formals to request slots given a route path template.
///
/// Accepts three placeholder syntaxes simultaneously: Express /
/// Fastify `:id`, FastAPI / Starlette `{id}`, and Hapi-style
/// `{id?}`.  A formal whose name matches a placeholder becomes a
/// [`ParamSource::PathSegment`]; the well-known framework context
/// formals (`req` / `request` / `res` / `response` / `reply` /
/// `ctx` / `context` / `next`) become
/// [`ParamSource::Implicit`]; everything else falls back to
/// [`ParamSource::QueryParam`] so downstream harness emitters have
/// a deterministic slot to populate.
pub fn bind_path_params(formals: &[String], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_path_placeholders(path);
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
    matches!(
        name,
        "req"
            | "request"
            | "res"
            | "response"
            | "reply"
            | "ctx"
            | "context"
            | "next"
            | "done"
    )
}

/// Extract placeholder names from a route path template.
///
/// Supports three placeholder syntaxes:
///   - Express / Fastify / NestJS: `/users/:id` → `id`,
///     `/users/:id(\\d+)` → `id` (anything inside `()` is dropped).
///   - FastAPI / Starlette mirrors: `/users/{id}` → `id`.
///   - Hapi-style optional: `/users/{id?}` → `id`.
///
/// Names are deduplicated while preserving first-occurrence order so a
/// single placeholder reused across the path does not double-bind a
/// formal.
pub fn extract_path_placeholders(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        let trimmed = name.trim_end_matches(['?', '*']).to_owned();
        if !trimmed.is_empty() && !out.iter().any(|n| n == &trimmed) {
            out.push(trimmed);
        }
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b':' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len()
                    && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
                {
                    j += 1;
                }
                if j > start {
                    push(path[start..j].to_owned());
                }
                // Skip a parenthesised regex constraint like `:id(\\d+)`.
                if j < bytes.len() && bytes[j] == b'(' {
                    let mut depth = 1usize;
                    j += 1;
                    while j < bytes.len() && depth > 0 {
                        match bytes[j] {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            _ => {}
                        }
                        j += 1;
                    }
                }
                i = j;
                continue;
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
            _ => {}
        }
        i += 1;
    }
    out
}

/// True when `view_arg` references `target` either directly
/// (`handler`) or as a member expression whose last segment is
/// `target` (`controller.handler` / `module.exports.handler`).
pub fn view_arg_references(view_arg: Node<'_>, bytes: &[u8], target: &str) -> bool {
    match view_arg.kind() {
        "identifier" => view_arg
            .utf8_text(bytes)
            .ok()
            .map(|t| t == target)
            .unwrap_or(false),
        "member_expression" => view_arg
            .utf8_text(bytes)
            .ok()
            .map(|t| last_segment(t) == target)
            .unwrap_or(false),
        _ => false,
    }
}

/// Walk `root` searching for a call expression `<receiver>.<verb>(<path>, ..., <handler>)`
/// or `<receiver>.<verb>({ method, url, handler })` (Fastify-style
/// options-object).  When the callee is one of the well-known HTTP
/// verbs, the receiver name is accepted by `receiver_accepts`, and one
/// of the positional arguments references `target`, returns the
/// `(method, path)` pair extracted from the first positional string
/// argument.
///
/// The receiver check uses a closure so each per-framework adapter
/// can accept its own canonical aliases (`app` / `router` for Express,
/// `fastify` / `server` for Fastify, etc.) without re-walking the
/// AST.  The handler position is permissive: any positional arg whose
/// identifier matches `target` (or whose last member-expression segment
/// matches) is accepted, so middleware-chained registrations
/// (`app.get('/x', authz, handler)`) bind correctly.
pub fn find_route_registration<'a>(
    root: Node<'a>,
    bytes: &[u8],
    target: &str,
    receiver_accepts: &dyn Fn(&str) -> bool,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    walk_for_registration(root, bytes, target, receiver_accepts, &mut hit);
    hit
}

fn walk_for_registration<'a>(
    node: Node<'a>,
    bytes: &[u8],
    target: &str,
    receiver_accepts: &dyn Fn(&str) -> bool,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(callee) = node.child_by_field_name("function")
        && callee.kind() == "member_expression"
        && let Some(object) = callee.child_by_field_name("object")
        && let Some(property) = callee.child_by_field_name("property")
        && let Some(object_text) = object.utf8_text(bytes).ok()
        && let Some(prop_text) = property.utf8_text(bytes).ok()
    {
        if let Some(method) = http_verb_from_method(prop_text)
            && receiver_accepts(last_segment(object_text))
            && let Some(args) = node.child_by_field_name("arguments")
            && call_args_reference_target(args, bytes, target)
                && let Some(path) = first_string_arg(args, bytes) {
                    *out = Some((method, path));
                    return;
                }
        // Fastify options-object: `fastify.route({ method, url, handler })`.
        if prop_text == "route"
            && receiver_accepts(last_segment(object_text))
            && let Some(args) = node.child_by_field_name("arguments")
            && let Some((method, path)) = parse_options_route(args, bytes, target)
        {
            *out = Some((method, path));
            return;
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_for_registration(child, bytes, target, receiver_accepts, out);
    }
}

/// True when any positional argument in `args` references `target` —
/// either as a bare identifier or as the last segment of a
/// `member_expression`.  Skips object literals (Fastify's options-form
/// is matched separately by [`parse_options_route`]).
fn call_args_reference_target(args: Node<'_>, bytes: &[u8], target: &str) -> bool {
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if view_arg_references(c, bytes, target) {
            return true;
        }
    }
    false
}

/// Find the first positional string-literal argument in an
/// `arguments` node.  Returns the literal's inner text with the
/// surrounding quotes stripped.
pub fn first_string_arg(args: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if c.kind() == "string" || c.kind() == "template_string" {
            let raw = c.utf8_text(bytes).ok()?;
            return Some(strip_quotes(raw).to_owned());
        }
    }
    None
}

/// Parse a Fastify options-object call `fastify.route({ method, url,
/// handler })` returning the bound `(method, url)` when the
/// `handler:` property references `target`.
fn parse_options_route(
    args: Node<'_>,
    bytes: &[u8],
    target: &str,
) -> Option<(HttpMethod, String)> {
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if c.kind() != "object" {
            continue;
        }
        let mut method: Option<HttpMethod> = None;
        let mut url: Option<String> = None;
        let mut handler_matches = false;
        let mut oc = c.walk();
        for pair in c.named_children(&mut oc) {
            if pair.kind() != "pair" {
                continue;
            }
            let Some(key) = pair.child_by_field_name("key").and_then(|n| n.utf8_text(bytes).ok())
            else {
                continue;
            };
            let Some(value) = pair.child_by_field_name("value") else {
                continue;
            };
            let key = key.trim_matches(['\'', '"', '`']);
            match key {
                "method" => {
                    let text = value.utf8_text(bytes).ok().unwrap_or("");
                    method = http_verb_from_method(strip_quotes(text));
                }
                "url" | "path" => {
                    let text = value.utf8_text(bytes).ok().unwrap_or("");
                    url = Some(strip_quotes(text).to_owned());
                }
                "handler" => {
                    if view_arg_references(value, bytes, target) {
                        handler_matches = true;
                    }
                }
                _ => {}
            }
        }
        if handler_matches
            && let Some(m) = method
            && let Some(u) = url
        {
            return Some((m, u));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn extract_express_placeholders() {
        assert_eq!(extract_path_placeholders("/users/:id"), vec!["id"]);
        assert_eq!(
            extract_path_placeholders("/u/:id/posts/:slug"),
            vec!["id", "slug"]
        );
    }

    #[test]
    fn extract_brace_placeholders() {
        assert_eq!(extract_path_placeholders("/users/{id}"), vec!["id"]);
        assert_eq!(extract_path_placeholders("/users/{id?}"), vec!["id"]);
    }

    #[test]
    fn last_segment_strips_receiver() {
        assert_eq!(last_segment("app.get"), "get");
        assert_eq!(last_segment("router.api.post"), "post");
        assert_eq!(last_segment("get"), "get");
    }

    #[test]
    fn verb_dispatch_handles_aliases() {
        assert_eq!(http_verb_from_method("GET"), Some(HttpMethod::GET));
        assert_eq!(http_verb_from_method("del"), Some(HttpMethod::DELETE));
        assert_eq!(http_verb_from_method("use"), None);
    }

    #[test]
    fn finds_function_declaration_params() {
        let src: &[u8] = b"function handler(req, res) {}\n";
        let tree = parse_js(src);
        let params = find_function_params(tree.root_node(), src, "handler").unwrap();
        let names = function_formal_names(params, src);
        assert_eq!(names, vec!["req", "res"]);
    }

    #[test]
    fn finds_const_arrow_params() {
        let src: &[u8] = b"const handler = (req, res, next) => {};\n";
        let tree = parse_js(src);
        let params = find_function_params(tree.root_node(), src, "handler").unwrap();
        let names = function_formal_names(params, src);
        assert_eq!(names, vec!["req", "res", "next"]);
    }

    #[test]
    fn bind_path_params_marks_implicit() {
        let formals = vec!["req".to_owned(), "res".to_owned(), "next".to_owned()];
        let bound = bind_path_params(&formals, "/x");
        for b in &bound {
            assert!(matches!(b.source, ParamSource::Implicit));
        }
    }

    #[test]
    fn find_route_registration_matches_app_get() {
        let src: &[u8] = b"app.get('/users/:id', handler);\n";
        let tree = parse_js(src);
        let recv = |n: &str| n == "app";
        let (method, path) =
            find_route_registration(tree.root_node(), src, "handler", &recv).unwrap();
        assert_eq!(method, HttpMethod::GET);
        assert_eq!(path, "/users/:id");
    }

    #[test]
    fn find_route_registration_matches_middleware_chain() {
        let src: &[u8] = b"app.post('/save', authz, validate, handler);\n";
        let tree = parse_js(src);
        let recv = |n: &str| n == "app";
        let (method, path) =
            find_route_registration(tree.root_node(), src, "handler", &recv).unwrap();
        assert_eq!(method, HttpMethod::POST);
        assert_eq!(path, "/save");
    }

    #[test]
    fn find_route_registration_matches_fastify_options_object() {
        let src: &[u8] =
            b"fastify.route({ method: 'PUT', url: '/users/:id', handler: handler });\n";
        let tree = parse_js(src);
        let recv = |n: &str| n == "fastify";
        let (method, path) =
            find_route_registration(tree.root_node(), src, "handler", &recv).unwrap();
        assert_eq!(method, HttpMethod::PUT);
        assert_eq!(path, "/users/:id");
    }
}

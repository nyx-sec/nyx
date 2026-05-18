//! NestJS [`super::super::FrameworkAdapter`] (Phase 13 — Track L.11).
//!
//! Recognises Nest's controller-class decorator surface:
//!   - `@Controller('users')` on the class establishes the route
//!     prefix.
//!   - `@Get(':id')` / `@Post()` / `@Put('/x')` / `@Patch()` /
//!     `@Delete()` / `@Head()` / `@Options()` / `@All()` on the
//!     method establishes the verb + sub-path; the full route is the
//!     concatenation `prefix + path`.
//!   - Parameter decorators (`@Param('id')`, `@Query('q')`,
//!     `@Body()`, `@Headers()`, `@Req()`, `@Res()`) bind individual
//!     formals to request slots.
//!
//! NestJS is TypeScript-first.  The adapter is registered under both
//! [`Lang::TypeScript`] and [`Lang::JavaScript`] so Babel-transpiled
//! Nest projects (still common in the wild) are not silently
//! skipped — JS Nest projects emit the same decorator syntax via
//! `experimentalDecorators` / `legacyDecorators`.  The lang-aware
//! tree-sitter parser is picked from `summary.lang`.

use crate::dynamic::framework::{
    FrameworkAdapter, FrameworkBinding, HttpMethod, ParamBinding, ParamSource, RouteShape,
};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::js_routes::{
    bind_path_params, extract_path_placeholders, function_formal_names, http_verb_from_method,
    source_imports_nest, strip_quotes,
};

pub struct JsNestAdapter;
pub struct TsNestAdapter;

const JS_ADAPTER_NAME: &str = "js-nest";
const TS_ADAPTER_NAME: &str = "ts-nest";

impl FrameworkAdapter for JsNestAdapter {
    fn name(&self) -> &'static str {
        JS_ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::JavaScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_nest(summary, ast, file_bytes, JS_ADAPTER_NAME)
    }
}

impl FrameworkAdapter for TsNestAdapter {
    fn name(&self) -> &'static str {
        TS_ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::TypeScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_nest(summary, ast, file_bytes, TS_ADAPTER_NAME)
    }
}

fn detect_nest(
    summary: &FuncSummary,
    ast: Node<'_>,
    file_bytes: &[u8],
    adapter_name: &'static str,
) -> Option<FrameworkBinding> {
    if !source_imports_nest(file_bytes) {
        return None;
    }
    let (class_node, method_node) =
        find_class_method(ast, file_bytes, &summary.name)?;
    let prefix = class_controller_prefix(class_node, file_bytes)?;
    let (method, sub_path) = method_verb_and_path(method_node, file_bytes)?;
    let full_path = join_paths(&prefix, &sub_path);
    let formals = method_node
        .child_by_field_name("parameters")
        .map(|p| function_formal_names(p, file_bytes))
        .unwrap_or_default();
    let mut request_params = bind_path_params(&formals, &full_path);
    refine_with_param_decorators(method_node, file_bytes, &mut request_params, &full_path);
    Some(FrameworkBinding {
        adapter: adapter_name.to_owned(),
        kind: EntryKind::HttpRoute,
        route: Some(RouteShape {
            method,
            path: full_path,
        }),
        request_params,
        response_writer: None,
        middleware: Vec::new(),
    })
}

/// Find `(class_declaration, method_definition)` where the method's
/// `name` field equals `target` and the enclosing class is decorated
/// with `@Controller(...)`.  Returns the first match in document
/// order.
fn find_class_method<'a>(
    root: Node<'a>,
    bytes: &[u8],
    target: &str,
) -> Option<(Node<'a>, Node<'a>)> {
    let mut hit: Option<(Node<'a>, Node<'a>)> = None;
    walk_for_class_method(root, bytes, target, &mut hit);
    hit
}

fn walk_for_class_method<'a>(
    node: Node<'a>,
    bytes: &[u8],
    target: &str,
    out: &mut Option<(Node<'a>, Node<'a>)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "class_declaration"
        && class_has_controller(node, bytes)
        && let Some(body) = node.child_by_field_name("body")
    {
        let mut cur = body.walk();
        for child in body.named_children(&mut cur) {
            if child.kind() == "method_definition"
                && let Some(name) = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                && name == target
            {
                *out = Some((node, child));
                return;
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_for_class_method(child, bytes, target, out);
    }
}

/// True when `class_node` is preceded by (or contains, depending on
/// grammar version) an `@Controller(...)` decorator.  The walk
/// inspects both the class's own `decorator` field children
/// (tree-sitter-typescript) and its preceding siblings in the parent
/// (tree-sitter-javascript with legacy decorator transform), so the
/// adapter fires regardless of the grammar's wrapping.
fn class_has_controller(class_node: Node<'_>, bytes: &[u8]) -> bool {
    if decorator_named(class_node, bytes, "Controller", &mut |_| {}) {
        return true;
    }
    let mut prev = class_node.prev_named_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "decorator" {
            if decorator_text_is(sib, bytes, "Controller") {
                return true;
            }
            prev = sib.prev_named_sibling();
            continue;
        }
        break;
    }
    false
}

/// Extract the controller-prefix string from a class's
/// `@Controller(<prefix>)` decorator.  Returns `Some("")` when the
/// decorator carries no argument (`@Controller()` is valid Nest — it
/// mounts the controller at root).
fn class_controller_prefix(class_node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut found: Option<String> = None;
    let mut catcher = |text: Option<&str>| {
        if let Some(t) = text {
            found = Some(t.to_owned());
        } else if found.is_none() {
            found = Some(String::new());
        }
    };
    if decorator_named(class_node, bytes, "Controller", &mut catcher) {
        return found;
    }
    let mut prev = class_node.prev_named_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "decorator" {
            if decorator_text_is(sib, bytes, "Controller") {
                let arg = decorator_first_string_arg(sib, bytes);
                return Some(arg.unwrap_or_default());
            }
            prev = sib.prev_named_sibling();
            continue;
        }
        break;
    }
    None
}

/// Return `Some((verb, sub_path))` when `method_node` is decorated
/// with one of the Nest verb decorators (`@Get`, `@Post`, ...).  The
/// `sub_path` is `""` when the decorator carries no argument
/// (`@Get()` mounts at the controller prefix root).
fn method_verb_and_path(
    method_node: Node<'_>,
    bytes: &[u8],
) -> Option<(HttpMethod, String)> {
    const VERBS: &[&str] = &[
        "Get", "Head", "Post", "Put", "Patch", "Delete", "Options", "All",
    ];
    for &verb in VERBS {
        if decorator_named(method_node, bytes, verb, &mut |_| {})
            && let Some(method) = http_verb_from_method(verb)
        {
            let path = method_decorator_path(method_node, bytes, verb);
            return Some((method, path));
        }
    }
    // Phase 13 v1: also accept preceding-sibling decorators for
    // grammar variants that hoist method decorators out of the
    // method_definition node.
    let mut prev = method_node.prev_named_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "decorator" {
            for &verb in VERBS {
                if decorator_text_is(sib, bytes, verb)
                    && let Some(method) = http_verb_from_method(verb)
                {
                    let path = decorator_first_string_arg(sib, bytes).unwrap_or_default();
                    return Some((method, path));
                }
            }
            prev = sib.prev_named_sibling();
            continue;
        }
        break;
    }
    None
}

fn method_decorator_path(method_node: Node<'_>, bytes: &[u8], verb: &str) -> String {
    let mut cur = method_node.walk();
    for d in method_node.children_by_field_name("decorator", &mut cur) {
        if decorator_text_is(d, bytes, verb) {
            return decorator_first_string_arg(d, bytes).unwrap_or_default();
        }
    }
    String::new()
}

/// Walk `node`'s `decorator` field children invoking `callback` for
/// each decorator named `name`.  Returns `true` when at least one
/// matching decorator was found.  `callback` receives the first
/// string argument (or `None` when the decorator carries no
/// arguments).
fn decorator_named(
    node: Node<'_>,
    bytes: &[u8],
    name: &str,
    callback: &mut dyn FnMut(Option<&str>),
) -> bool {
    let mut found = false;
    let mut cur = node.walk();
    for d in node.children_by_field_name("decorator", &mut cur) {
        if decorator_text_is(d, bytes, name) {
            found = true;
            let arg = decorator_first_string_arg(d, bytes);
            callback(arg.as_deref());
        }
    }
    found
}

fn decorator_text_is(decorator: Node<'_>, bytes: &[u8], name: &str) -> bool {
    let mut cur = decorator.walk();
    for c in decorator.children(&mut cur) {
        if c.kind() == "@" {
            continue;
        }
        let text = c.utf8_text(bytes).unwrap_or("");
        // Strip optional `(args)` so `@Get(':id')` matches the name `Get`.
        let head = text.split('(').next().unwrap_or(text).trim();
        if head == name {
            return true;
        }
    }
    false
}

fn decorator_first_string_arg(decorator: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = decorator.walk();
    for c in decorator.children(&mut cur) {
        if c.kind() == "call_expression"
            && let Some(args) = c.child_by_field_name("arguments")
        {
            let mut ac = args.walk();
            for a in args.named_children(&mut ac) {
                if a.kind() == "string" || a.kind() == "template_string" {
                    let raw = a.utf8_text(bytes).ok()?;
                    return Some(strip_quotes(raw).to_owned());
                }
            }
        }
    }
    None
}

/// Refine the per-formal binding shape using Nest's parameter
/// decorators (`@Param('id')`, `@Query('q')`, `@Body()`, `@Headers()`,
/// `@Req()` / `@Res()`).  A `@Body()` formal becomes
/// [`ParamSource::JsonBody`]; a `@Param('x')` formal becomes
/// [`ParamSource::PathSegment`]; `@Query('q')` keeps
/// [`ParamSource::QueryParam`]; `@Req()` / `@Res()` becomes
/// [`ParamSource::Implicit`].
fn refine_with_param_decorators(
    method_node: Node<'_>,
    bytes: &[u8],
    bindings: &mut [ParamBinding],
    full_path: &str,
) {
    let Some(params) = method_node.child_by_field_name("parameters") else {
        return;
    };
    let mut cur = params.walk();
    let placeholders = extract_path_placeholders(full_path);
    let formal_param_nodes: Vec<Node<'_>> = params.named_children(&mut cur).collect();
    for (idx, formal) in formal_param_nodes.iter().enumerate() {
        if let Some(refinement) = classify_param_decorator(*formal, bytes, &placeholders)
            && let Some(slot) = bindings.get_mut(idx)
        {
            slot.source = refinement;
        }
    }
}

fn classify_param_decorator(
    formal: Node<'_>,
    bytes: &[u8],
    placeholders: &[String],
) -> Option<ParamSource> {
    let mut cur = formal.walk();
    for d in formal.children_by_field_name("decorator", &mut cur) {
        if let Some(refinement) = decorator_to_param_source(d, bytes, placeholders) {
            return Some(refinement);
        }
    }
    // Some grammar variants attach the decorator as a preceding
    // sibling inside the parameter list.
    let mut prev = formal.prev_named_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "decorator" {
            if let Some(r) = decorator_to_param_source(sib, bytes, placeholders) {
                return Some(r);
            }
            prev = sib.prev_named_sibling();
            continue;
        }
        break;
    }
    None
}

fn decorator_to_param_source(
    decorator: Node<'_>,
    bytes: &[u8],
    placeholders: &[String],
) -> Option<ParamSource> {
    let arg = decorator_first_string_arg(decorator, bytes);
    if decorator_text_is(decorator, bytes, "Body") {
        return Some(ParamSource::JsonBody);
    }
    if decorator_text_is(decorator, bytes, "Param") {
        let name = arg.unwrap_or_else(|| {
            placeholders
                .first()
                .cloned()
                .unwrap_or_else(|| "id".to_owned())
        });
        return Some(ParamSource::PathSegment(name));
    }
    if decorator_text_is(decorator, bytes, "Query") {
        let name = arg.unwrap_or_else(|| "q".to_owned());
        return Some(ParamSource::QueryParam(name));
    }
    if decorator_text_is(decorator, bytes, "Headers") {
        let name = arg.unwrap_or_else(|| "x-nyx".to_owned());
        return Some(ParamSource::Header(name));
    }
    if decorator_text_is(decorator, bytes, "Req")
        || decorator_text_is(decorator, bytes, "Res")
        || decorator_text_is(decorator, bytes, "Request")
        || decorator_text_is(decorator, bytes, "Response")
        || decorator_text_is(decorator, bytes, "Next")
    {
        return Some(ParamSource::Implicit);
    }
    None
}

/// Join a controller prefix and method path segment per Nest's own
/// path normalisation: collapse any double-slash run to a single
/// slash, ensure the result starts with `/`, and trim a trailing
/// slash unless the path is `/` itself.
fn join_paths(prefix: &str, sub_path: &str) -> String {
    let mut combined = String::with_capacity(prefix.len() + sub_path.len() + 2);
    if !prefix.starts_with('/') {
        combined.push('/');
    }
    combined.push_str(prefix);
    if !prefix.ends_with('/') && !sub_path.is_empty() && !sub_path.starts_with('/') {
        combined.push('/');
    }
    combined.push_str(sub_path);
    let collapsed = collapse_slashes(&combined);
    if collapsed.is_empty() {
        return "/".to_owned();
    }
    collapsed
}

fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_slash = false;
    for c in s.chars() {
        if c == '/' {
            if !last_was_slash {
                out.push('/');
            }
            last_was_slash = true;
        } else {
            out.push(c);
            last_was_slash = false;
        }
    }
    if out.len() > 1 {
        while out.ends_with('/') {
            out.pop();
        }
    }
    if out.is_empty() {
        return "/".to_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ts(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang =
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str, lang: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: lang.into(),
            ..Default::default()
        }
    }

    #[test]
    fn collapse_slashes_normalises_join() {
        assert_eq!(join_paths("users", "id"), "/users/id");
        assert_eq!(join_paths("/users/", "/:id"), "/users/:id");
        assert_eq!(join_paths("", ""), "/");
        assert_eq!(join_paths("/", "/"), "/");
    }

    #[test]
    fn fires_on_controller_get_decorator() {
        let src: &[u8] = b"import { Controller, Get, Param } from '@nestjs/common';\n\
            @Controller('users')\n\
            export class UsersController {\n\
              @Get(':id')\n\
              getUser(@Param('id') id: string) { return id; }\n\
            }\n";
        let tree = parse_ts(src);
        let binding = TsNestAdapter
            .detect(&summary("getUser", "typescript"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ts-nest");
        let route = binding.route.as_ref().unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/:id");
        let id_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id_binding.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_body_decorator() {
        let src: &[u8] = b"import { Controller, Post, Body } from '@nestjs/common';\n\
            @Controller('items')\n\
            export class ItemsController {\n\
              @Post()\n\
              create(@Body() payload: any) { return payload; }\n\
            }\n";
        let tree = parse_ts(src);
        let binding = TsNestAdapter
            .detect(&summary("create", "typescript"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/items");
        let body_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "payload")
            .unwrap();
        assert!(matches!(body_binding.source, ParamSource::JsonBody));
    }

    #[test]
    fn fires_on_query_decorator() {
        let src: &[u8] = b"import { Controller, Get, Query } from '@nestjs/common';\n\
            @Controller()\n\
            export class SearchController {\n\
              @Get('search')\n\
              search(@Query('q') q: string) { return q; }\n\
            }\n";
        let tree = parse_ts(src);
        let binding = TsNestAdapter
            .detect(&summary("search", "typescript"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().path, "/search");
        let q_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "q")
            .unwrap();
        match &q_binding.source {
            ParamSource::QueryParam(name) => assert_eq!(name, "q"),
            other => panic!("expected QueryParam, got {other:?}"),
        }
    }

    #[test]
    fn skips_when_not_a_nest_controller() {
        let src: &[u8] = b"import { Injectable } from '@nestjs/common';\n\
            @Injectable()\n\
            export class HelperService {\n\
              compute(x: number) { return x + 1; }\n\
            }\n";
        let tree = parse_ts(src);
        assert!(TsNestAdapter
            .detect(&summary("compute", "typescript"), tree.root_node(), src)
            .is_none());
    }
}

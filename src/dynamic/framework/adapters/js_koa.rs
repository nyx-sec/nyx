//! Koa [`super::super::FrameworkAdapter`] (Phase 13 — Track L.11).
//!
//! Recognises `@koa/router` / `koa-router` route registrations
//! (`router.get('/path', handler)` etc.) plus bare `app.use(handler)`
//! middleware chains.  The Koa adapter accepts the `router` / `koa-router`
//! verb dispatch surface (`get` / `post` / `put` / `patch` / `delete` /
//! `head` / `options` / `all`) and also matches the legacy `app.use`
//! middleware shape which has no path template (route is recorded as
//! `"/"`).

use crate::dynamic::framework::{
    FrameworkAdapter, FrameworkBinding, HttpMethod, MiddlewareShape, RouteShape,
};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::js_routes::{
    bind_path_params, extract_route_middleware, find_function_params, find_route_registration,
    function_formal_names, last_segment, source_imports_koa, view_arg_references,
};

pub struct JsKoaAdapter;

const ADAPTER_NAME: &str = "js-koa";

fn receiver_looks_like_koa(name: &str) -> bool {
    matches!(
        name,
        "router" | "app" | "application" | "koaApp" | "koaRouter" | "api"
    ) || name.ends_with("Router")
        || name.ends_with("App")
        || name.ends_with("_router")
        || name.ends_with("_app")
}

/// Walk `root` looking for `app.use(handler)` middleware registrations
/// that reference `target`.  Returns the matched call node so callers
/// can stamp a middleware-shape binding when the verb-based dispatch
/// fails to fire.
fn find_use_middleware<'a>(root: Node<'a>, bytes: &[u8], target: &str) -> Option<Node<'a>> {
    let mut hit: Option<Node<'a>> = None;
    walk_for_use(root, bytes, target, &mut hit);
    hit
}

fn walk_for_use<'a>(node: Node<'a>, bytes: &[u8], target: &str, out: &mut Option<Node<'a>>) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(callee) = node.child_by_field_name("function")
        && callee.kind() == "member_expression"
        && let Some(prop) = callee.child_by_field_name("property")
        && let Some(prop_text) = prop.utf8_text(bytes).ok()
        && prop_text == "use"
        && let Some(object) = callee.child_by_field_name("object")
        && let Some(obj_text) = object.utf8_text(bytes).ok()
        && receiver_looks_like_koa(last_segment(obj_text))
        && let Some(args) = node.child_by_field_name("arguments")
    {
        let mut cur = args.walk();
        for c in args.named_children(&mut cur) {
            if view_arg_references(c, bytes, target) {
                *out = Some(node);
                return;
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_for_use(child, bytes, target, out);
    }
}

impl FrameworkAdapter for JsKoaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
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
        if !source_imports_koa(file_bytes) {
            return None;
        }
        let recv = receiver_looks_like_koa;
        let formals_for = |path: &str| {
            let formals = find_function_params(ast, file_bytes, &summary.name)
                .map(|p| function_formal_names(p, file_bytes))
                .unwrap_or_default();
            bind_path_params(&formals, path)
        };
        if let Some((method, path)) = find_route_registration(ast, file_bytes, &summary.name, &recv)
        {
            let request_params = formals_for(&path);
            let middleware = extract_route_middleware(ast, file_bytes, &summary.name, &recv);
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::HttpRoute,
                route: Some(RouteShape { method, path }),
                request_params,
                response_writer: None,
                middleware,
            });
        }
        // Fall back to `app.use(handler)` middleware registration.  No
        // verb / path information — record the binding so the harness
        // still drives the middleware via a synthetic ctx.
        if find_use_middleware(ast, file_bytes, &summary.name).is_some() {
            let request_params = formals_for("/");
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::HttpRoute,
                route: Some(RouteShape {
                    method: HttpMethod::GET,
                    path: "/".to_owned(),
                }),
                request_params,
                response_writer: None,
                middleware: vec![MiddlewareShape {
                    name: "koa.use".to_owned(),
                }],
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::ParamSource;

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "javascript".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_router_get() {
        let src: &[u8] = b"const Koa = require('koa');\n\
            const Router = require('@koa/router');\n\
            const app = new Koa();\n\
            const router = new Router();\n\
            async function getUser(ctx) { ctx.body = ctx.params.id; }\n\
            router.get('/users/:id', getUser);\n";
        let tree = parse_js(src);
        let binding = JsKoaAdapter
            .detect(&summary("getUser"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "js-koa");
        let route = binding.route.as_ref().unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/:id");
        assert!(
            binding
                .request_params
                .iter()
                .any(|p| p.name == "ctx" && matches!(p.source, ParamSource::Implicit))
        );
    }

    #[test]
    fn fires_on_app_use_middleware() {
        let src: &[u8] = b"const Koa = require('koa');\n\
            const app = new Koa();\n\
            async function logger(ctx, next) { await next(); }\n\
            app.use(logger);\n";
        let tree = parse_js(src);
        let binding = JsKoaAdapter
            .detect(&summary("logger"), tree.root_node(), src)
            .expect("middleware binding");
        assert_eq!(binding.middleware.len(), 1);
        assert_eq!(binding.middleware[0].name, "koa.use");
    }

    #[test]
    fn records_chained_middleware_and_global_app_use() {
        let src: &[u8] = b"const Koa = require('koa');\n\
            const Router = require('@koa/router');\n\
            const app = new Koa();\n\
            const router = new Router();\n\
            app.use(helmet());\n\
            app.use(logger);\n\
            async function authz(ctx, next) { await next(); }\n\
            async function validate(ctx, next) { await next(); }\n\
            async function handler(ctx) { ctx.body = 'ok'; }\n\
            router.post('/save', authz, validate, handler);\n";
        let tree = parse_js(src);
        let binding = JsKoaAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        let names: Vec<_> = binding.middleware.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["helmet", "logger", "authz", "validate"]);
    }

    #[test]
    fn middleware_empty_when_route_has_no_chain() {
        let src: &[u8] = b"const Koa = require('koa');\n\
            const Router = require('@koa/router');\n\
            const router = new Router();\n\
            async function handler(ctx) { ctx.body = 'ok'; }\n\
            router.get('/x', handler);\n";
        let tree = parse_js(src);
        let binding = JsKoaAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.is_empty());
    }

    #[test]
    fn skips_when_koa_not_imported() {
        let src: &[u8] = b"const express = require('express');\n\
            const router = express.Router();\n\
            function h(req, res) {}\n\
            router.get('/x', h);\n";
        let tree = parse_js(src);
        assert!(
            JsKoaAdapter
                .detect(&summary("h"), tree.root_node(), src)
                .is_none()
        );
    }
}

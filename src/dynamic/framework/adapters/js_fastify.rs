//! Fastify [`super::super::FrameworkAdapter`] (Phase 13 — Track L.11).
//!
//! Recognises three Fastify route-registration shapes:
//!   - Verb dispatch: `fastify.get('/path', handler)`,
//!     `fastify.post(...)`, `fastify.put(...)`, etc.
//!   - Options-object: `fastify.route({ method: 'GET', url: '/path',
//!     handler })`.
//!   - Plugin route table: `fastify.register(async (instance, opts) =>
//!     { instance.get('/path', handler); })` — Phase 13 v1 fires the
//!     inner verb dispatch directly (the outer plugin wrapper is
//!     opaque to the AST walk).
//!
//! Receiver aliases cover the canonical Fastify names (`fastify`,
//! `server`, `instance`, `app`) plus any name ending in `_fastify` /
//! `_server` / `Server` / `Fastify`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::js_routes::{
    JsFrameworkObject, bind_path_params, extract_route_middleware, find_function_params,
    find_route_registration, function_formal_names, receiver_origin_allows_framework,
    source_imports_fastify, ssa_receiver_allows_framework,
};

pub struct JsFastifyAdapter;

const ADAPTER_NAME: &str = "js-fastify";

fn receiver_looks_like_fastify(name: &str) -> bool {
    matches!(
        name,
        "fastify" | "server" | "instance" | "app" | "application"
    ) || name.ends_with("_fastify")
        || name.ends_with("_server")
        || name.ends_with("Server")
        || name.ends_with("Fastify")
}

impl FrameworkAdapter for JsFastifyAdapter {
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
        detect_fastify(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_fastify(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_fastify(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_fastify(file_bytes) {
        return None;
    }
    let recv = |name: &str| {
        receiver_looks_like_fastify(name)
            && receiver_origin_allows_framework(ast, file_bytes, name, JsFrameworkObject::Fastify)
            && ssa_receiver_allows_framework(
                summary,
                ssa_summary,
                name,
                "*",
                JsFrameworkObject::Fastify,
            )
    };
    let (method, path) = find_route_registration(ast, file_bytes, &summary.name, &recv)?;
    let formals = find_function_params(ast, file_bytes, &summary.name)
        .map(|p| function_formal_names(p, file_bytes))
        .unwrap_or_default();
    let request_params = bind_path_params(&formals, &path);
    let middleware = extract_route_middleware(ast, file_bytes, &summary.name, &recv);
    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::HttpRoute,
        route: Some(RouteShape::single(method, path)),
        request_params,
        response_writer: None,
        middleware,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::HttpMethod;

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
    fn fires_on_fastify_get() {
        let src: &[u8] = b"const fastify = require('fastify')();\n\
            async function getUser(request, reply) { reply.send(request.params.id); }\n\
            fastify.get('/users/:id', getUser);\n";
        let tree = parse_js(src);
        let binding = JsFastifyAdapter
            .detect(&summary("getUser"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "js-fastify");
        let route = binding.route.as_ref().unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/:id");
    }

    #[test]
    fn fires_on_options_object_route() {
        let src: &[u8] = b"const fastify = require('fastify')();\n\
            async function handler(request, reply) { reply.send('ok'); }\n\
            fastify.route({ method: 'POST', url: '/items', handler: handler });\n";
        let tree = parse_js(src);
        let binding = JsFastifyAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/items");
    }

    #[test]
    fn fires_on_plugin_inner_verb_dispatch() {
        // Phase 13 v1: the inner `instance.get(...)` registration is
        // recognised even though the surrounding `fastify.register`
        // plugin wrapper is opaque to the AST walk.  Fastify's
        // `instance` alias matches `receiver_looks_like_fastify`.
        let src: &[u8] = b"const fastify = require('fastify')();\n\
            async function handler(request, reply) { reply.send('ok'); }\n\
            fastify.register(async (instance, opts) => {\n\
                instance.get('/inner', handler);\n\
            });\n";
        let tree = parse_js(src);
        let binding = JsFastifyAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().path, "/inner");
    }

    #[test]
    fn records_chained_middleware_and_global_use() {
        let src: &[u8] = b"const fastify = require('fastify')();\n\
            fastify.use(helmet());\n\
            function authz(request, reply, done) { done(); }\n\
            function handler(request, reply) { reply.send('ok'); }\n\
            fastify.post('/save', authz, handler);\n";
        let tree = parse_js(src);
        let binding = JsFastifyAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        let names: Vec<_> = binding.middleware.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["helmet", "authz"]);
    }

    #[test]
    fn records_options_object_pre_handler_hooks() {
        let src: &[u8] = b"const fastify = require('fastify')();\n\
            async function handler(request, reply) { reply.send('ok'); }\n\
            fastify.route({\n\
                method: 'PUT',\n\
                url: '/items/:id',\n\
                onRequest: tokenAuth,\n\
                preHandler: [authz, validate],\n\
                handler: handler,\n\
            });\n";
        let tree = parse_js(src);
        let binding = JsFastifyAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.as_ref().unwrap().method, HttpMethod::PUT);
        let names: Vec<_> = binding.middleware.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["tokenAuth", "authz", "validate"]);
    }

    #[test]
    fn middleware_empty_when_route_has_no_chain() {
        let src: &[u8] = b"const fastify = require('fastify')();\n\
            function handler(request, reply) { reply.send('ok'); }\n\
            fastify.get('/x', handler);\n";
        let tree = parse_js(src);
        let binding = JsFastifyAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.is_empty());
    }

    #[test]
    fn skips_when_fastify_not_imported() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function h(req, res) {}\n\
            app.get('/x', h);\n";
        let tree = parse_js(src);
        assert!(
            JsFastifyAdapter
                .detect(&summary("h"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_route_registered_on_non_fastify_server_alias() {
        let src: &[u8] = b"const fastify = require('fastify');\n\
            const server = new Map();\n\
            async function handler(request, reply) { reply.send('ok'); }\n\
            server.get('/x', handler);\n";
        let tree = parse_js(src);
        assert!(
            JsFastifyAdapter
                .detect(&summary("handler"), tree.root_node(), src)
                .is_none()
        );
    }
}

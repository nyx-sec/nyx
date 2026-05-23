//! Express [`super::super::FrameworkAdapter`] (Phase 13 — Track L.11).
//!
//! Recognises `app.get('/path', handler)`, `app.post('/path', handler)`,
//! `router.put('/path', handler)`, and the rest of the Express verb
//! dispatch surface (`get` / `head` / `post` / `put` / `patch` /
//! `delete` / `del` / `options` / `all`).  Middleware-chained
//! registrations (`app.get('/x', authz, validate, handler)`) bind to
//! the last positional argument that references `summary.name`.
//!
//! Receiver aliases follow Express convention: bare `app`,
//! `application`, `router`, `api`, plus any name ending in `_router` /
//! `_app` / `Router` / `App`.  Source-import sniffing requires one of
//! the well-known Express stanzas before the AST walk runs.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::js_routes::{
    JsFrameworkObject, bind_path_params, extract_route_middleware, find_function_params,
    find_route_registration, function_formal_names, receiver_origin_allows_framework,
    source_imports_express, ssa_receiver_allows_framework,
};

pub struct JsExpressAdapter;

const ADAPTER_NAME: &str = "js-express";

fn receiver_looks_like_express(name: &str) -> bool {
    matches!(
        name,
        "app" | "application" | "router" | "api" | "expressApp" | "server"
    ) || name.ends_with("_router")
        || name.ends_with("_app")
        || name.ends_with("Router")
        || name.ends_with("App")
}

impl FrameworkAdapter for JsExpressAdapter {
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
        detect_express(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_express(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_express(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_express(file_bytes) {
        return None;
    }
    let recv = |name: &str| {
        receiver_looks_like_express(name)
            && receiver_origin_allows_framework(ast, file_bytes, name, JsFrameworkObject::Express)
            && ssa_receiver_allows_framework(
                summary,
                ssa_summary,
                name,
                "*",
                JsFrameworkObject::Express,
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
        route: Some(RouteShape { method, path }),
        request_params,
        response_writer: None,
        middleware,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::{HttpMethod, ParamSource};
    use crate::summary::CalleeSite;
    use crate::summary::ssa_summary::SsaFuncSummary;

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
    fn fires_on_app_get_with_named_handler() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function getUser(req, res) { res.send(req.params.id); }\n\
            app.get('/users/:id', getUser);\n";
        let tree = parse_js(src);
        let binding = JsExpressAdapter
            .detect(&summary("getUser"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "js-express");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.as_ref().unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/:id");
        assert!(
            binding
                .request_params
                .iter()
                .any(|p| p.name == "req" && matches!(p.source, ParamSource::Implicit))
        );
        assert!(
            binding
                .request_params
                .iter()
                .any(|p| p.name == "res" && matches!(p.source, ParamSource::Implicit))
        );
    }

    #[test]
    fn fires_on_post_via_router_alias() {
        let src: &[u8] = b"const express = require('express');\n\
            const apiRouter = express.Router();\n\
            function saveItem(req, res) { res.json(req.body); }\n\
            apiRouter.post('/items', saveItem);\n";
        let tree = parse_js(src);
        let binding = JsExpressAdapter
            .detect(&summary("saveItem"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.as_ref().unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn fires_on_middleware_chain() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function authz(req, res, next) { next(); }\n\
            function handler(req, res) { res.send('ok'); }\n\
            app.delete('/items/:id', authz, handler);\n";
        let tree = parse_js(src);
        let binding = JsExpressAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.as_ref().unwrap().method, HttpMethod::DELETE);
        let names: Vec<_> = binding.middleware.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["authz"]);
    }

    #[test]
    fn records_chained_middleware_and_global_app_use() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            app.use(helmet());\n\
            app.use(logger);\n\
            function authz(req, res, next) { next(); }\n\
            function validate(req, res, next) { next(); }\n\
            function handler(req, res) { res.send('ok'); }\n\
            app.post('/save', authz, validate, handler);\n";
        let tree = parse_js(src);
        let binding = JsExpressAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        let names: Vec<_> = binding.middleware.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["helmet", "logger", "authz", "validate"]);
    }

    #[test]
    fn middleware_empty_when_route_has_no_chain() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function handler(req, res) { res.send('ok'); }\n\
            app.get('/x', handler);\n";
        let tree = parse_js(src);
        let binding = JsExpressAdapter
            .detect(&summary("handler"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.is_empty());
    }

    #[test]
    fn skips_when_express_not_imported() {
        let src: &[u8] = b"const koa = require('koa');\n\
            const app = new koa();\n\
            function handler(ctx) { ctx.body = 'ok'; }\n\
            app.get('/x', handler);\n";
        let tree = parse_js(src);
        assert!(
            JsExpressAdapter
                .detect(&summary("handler"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_handler_name_does_not_match() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function other(req, res) { res.send('x'); }\n\
            app.get('/x', other);\n";
        let tree = parse_js(src);
        assert!(
            JsExpressAdapter
                .detect(&summary("missing"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_route_registered_on_local_collection_alias() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = new Map();\n\
            function handler(req, res) { res.send('ok'); }\n\
            app.get('/x', handler);\n";
        let tree = parse_js(src);
        assert!(
            JsExpressAdapter
                .detect(&summary("handler"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_incompatible_route_receiver() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = makeApp();\n\
            function handler(req, res) { res.send('ok'); }\n\
            app.get('/x', handler);\n";
        let tree = parse_js(src);
        let mut func = summary("handler");
        func.callees.push(CalleeSite {
            name: "app.get".to_owned(),
            receiver: Some("app".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let ssa = SsaFuncSummary {
            typed_call_receivers: vec![(0, "Map".to_owned())],
            ..Default::default()
        };
        assert!(
            JsExpressAdapter
                .detect_with_context(&func, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_express_container() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = makeApp();\n\
            function handler(req, res) { res.send('ok'); }\n\
            app.get('/x', handler);\n";
        let tree = parse_js(src);
        let mut func = summary("handler");
        func.callees.push(CalleeSite {
            name: "app.get".to_owned(),
            receiver: Some("app".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let ssa = SsaFuncSummary {
            typed_call_receivers: vec![(0, "ExpressApplication".to_owned())],
            ..Default::default()
        };
        assert!(
            JsExpressAdapter
                .detect_with_context(&func, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

//! Phase 21 (Track M.3) — Express middleware adapter (JS).
//!
//! Fires when the surrounding source imports Express and the function
//! under analysis is mounted via `app.use(<this_fn>)` /
//! `router.use(<this_fn>)`.  An anonymous-mount or callee-only signal
//! (`app.use(...)` with a non-matching function name) is no longer
//! enough on its own — that needle stole every Express setup file into
//! Middleware bindings regardless of which function the analyser was
//! looking at (Phase 21 binding-stealing audit).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareExpressAdapter;

const ADAPTER_NAME: &str = "middleware-express";

fn callee_is_express_mount(name: &str) -> bool {
    // `use` on Express's app/router registers middleware. Other Express
    // helpers like `json`/`urlencoded`/`static` are body-parser
    // factories that pair WITH `use` rather than identifying the
    // function itself as middleware, so they no longer count.
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    last == "use"
}

fn function_is_mounted_as_middleware(file_bytes: &[u8], name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let needles: [Vec<u8>; 2] = [
        format!("app.use({name})").into_bytes(),
        format!("router.use({name})").into_bytes(),
    ];
    needles
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == n.as_slice()))
}

fn function_has_middleware_signature(summary: &FuncSummary) -> bool {
    // Express middleware contract: (req, res, next).  Adapters cannot
    // rely on a generic mount-everything heuristic so the param shape
    // becomes the secondary signal when no explicit `app.use(<name>)`
    // line is present.
    let names: Vec<&str> = summary.param_names.iter().map(|s| s.as_str()).collect();
    matches!(names.as_slice(), ["req", "res", "next"])
        || matches!(names.as_slice(), ["request", "response", "next"])
}

impl FrameworkAdapter for MiddlewareExpressAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::JavaScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_express_middleware(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_express_middleware(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_express_middleware(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    let mounted_by_name = function_is_mounted_as_middleware(file_bytes, &summary.name);
    let has_mw_signature = function_has_middleware_signature(summary);
    let body_mounts = super::any_callee_matches(summary, callee_is_express_mount)
        && super::typed_receiver_facts_allow(
            summary,
            ssa_summary,
            callee_is_express_mount,
            typed_container_allows_express,
        );
    let binds = mounted_by_name || has_mw_signature || body_mounts;
    if !binds {
        return None;
    }
    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::Middleware {
            name: summary.name.clone(),
        },
        route: None,
        request_params: Vec::new(),
        response_writer: None,
        middleware: Vec::new(),
    })
}

fn typed_container_allows_express(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("express") || lc.contains("router")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_express_middleware() {
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function audit(req, res, next) { next(); }\n\
            app.use(audit);\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "audit".into(),
            ..Default::default()
        };
        let binding = MiddlewareExpressAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("express middleware binds");
        assert_eq!(binding.adapter, "middleware-express");
        if let EntryKind::Middleware { name } = binding.kind {
            assert_eq!(name, "audit");
        }
    }

    #[test]
    fn does_not_bind_unrelated_helper_in_express_setup() {
        // File mounts middleware `audit` but the analyser is asking
        // about an unrelated helper `loadConfig` in the same file.
        let src: &[u8] = b"const express = require('express');\n\
            const app = express();\n\
            function audit(req, res, next) { next(); }\n\
            function loadConfig() { return { port: 3000 }; }\n\
            app.use(audit);\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "loadConfig".into(),
            ..Default::default()
        };
        assert!(
            MiddlewareExpressAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "unrelated helper in an Express setup file must not bind as middleware",
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_non_express_use_collision() {
        let src: &[u8] = b"const express = require('express');\n\
            function helper() { cache.use('audit'); }\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "cache.use".to_owned(),
            receiver: Some("cache".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Map".to_owned()));
        assert!(
            MiddlewareExpressAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_express_use_receiver() {
        let src: &[u8] = b"const express = require('express');\n\
            function helper() { app.use(audit); }\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "app.use".to_owned(),
            receiver: Some("app".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((0, "express.Application".to_owned()));
        assert!(
            MiddlewareExpressAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

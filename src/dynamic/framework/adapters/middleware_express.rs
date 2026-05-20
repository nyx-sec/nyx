//! Phase 21 (Track M.3) — Express middleware adapter (JS).
//!
//! Fires when the surrounding source imports Express and declares a
//! middleware function — a `(req, res, next) => …` callable mounted
//! via `app.use(...)` / `router.use(...)`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareExpressAdapter;

const ADAPTER_NAME: &str = "middleware-express";

fn callee_is_express(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "use" | "next" | "json" | "urlencoded" | "static"
    )
}

fn source_imports_express(file_bytes: &[u8]) -> bool {
    // Phase 21 v1: require an explicit middleware-registration shape
    // (`app.use(` / `router.use(`), not the bare `require('express')`
    // import.  Many non-middleware Express fixtures import the framework
    // but never declare middleware; gating on the registration shape
    // keeps the adapter focused on the function the brief targets.
    const NEEDLES: &[&[u8]] = &[
        b"app.use(",
        b"router.use(",
        b"express.Router()",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_express);
        let matches_source = source_imports_express(file_bytes);
        if matches_call || matches_source {
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
        } else {
            None
        }
    }
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
}

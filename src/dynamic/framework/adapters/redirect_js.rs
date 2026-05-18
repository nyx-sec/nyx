//! JavaScript [`super::super::FrameworkAdapter`] matching
//! HTTP-redirect sink constructions (Express `res.redirect`,
//! Koa `ctx.redirect`, raw Node `res.writeHead(302, { Location })`).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one
//! of the canonical Node redirect entry points and the surrounding
//! source imports the matching framework module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectJsAdapter;

const ADAPTER_NAME: &str = "redirect-js";

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "redirect" | "writeHead")
}

fn source_imports_node_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('express')",
        b"require(\"express\")",
        b"from 'express'",
        b"from \"express\"",
        b"require('koa')",
        b"require(\"koa\")",
        b"require('http')",
        b"require(\"http\")",
        b"res.redirect",
        b"ctx.redirect",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectJsAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
        let matches_source = source_imports_node_web(file_bytes);
        if matches_call && matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
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
    fn fires_on_express_redirect() {
        let src: &[u8] = b"const express = require('express');\n\
            function run(req, res, v) { res.redirect(v); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("redirect")],
            ..Default::default()
        };
        assert!(RedirectJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(RedirectJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

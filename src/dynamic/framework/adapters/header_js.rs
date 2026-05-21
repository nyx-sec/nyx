//! JavaScript [`super::super::FrameworkAdapter`] matching HTTP
//! response-header CRLF-injection sink constructions
//! (`http.ServerResponse#setHeader`, Express `res.setHeader` /
//! `res.header`, Koa `ctx.set`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical Node response writers and the surrounding source
//! imports the matching framework module or `node:http`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderJsAdapter;

const ADAPTER_NAME: &str = "header-js";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "setHeader" | "header" | "set" | "writeHead" | "append"
    )
}

fn source_uses_node_http(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('http')",
        b"require(\"http\")",
        b"require('node:http')",
        b"from 'http'",
        b"from \"http\"",
        b"require('express')",
        b"require(\"express\")",
        b"from 'express'",
        b"from \"express\"",
        b"require('koa')",
        b"require(\"koa\")",
        b"require('fastify')",
        b"require(\"fastify\")",
        b"res.setHeader",
        b"res.header",
        b"ctx.set(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// header value through a canonical Node / browser URL-encoder.
fn value_routed_through_encoder(file_bytes: &[u8]) -> bool {
    const ENCODER_CALLS: &[&[u8]] = &[
        b"encodeURIComponent(",
        b"encodeURI(",
        b"querystring.escape(",
        b"qs.escape(",
    ];
    ENCODER_CALLS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderJsAdapter {
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
        if value_routed_through_encoder(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_header_setter);
        let matches_source = source_uses_node_http(file_bytes);
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
    fn fires_on_setheader() {
        let src: &[u8] = b"const http = require('http');\n\
            function run(res, value) { res.setHeader('Set-Cookie', value); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("setHeader")],
            ..Default::default()
        };
        assert!(
            HeaderJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            HeaderJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_value_url_encoded() {
        let src: &[u8] = b"const http = require('http');\n\
            function run(res, value) { res.setHeader('Set-Cookie', encodeURIComponent(value)); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("setHeader"),
                crate::summary::CalleeSite::bare("encodeURIComponent"),
            ],
            ..Default::default()
        };
        assert!(
            HeaderJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

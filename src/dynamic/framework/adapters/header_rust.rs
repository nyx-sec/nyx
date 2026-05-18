//! Rust [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions
//! (`axum`-style `headers_mut().insert`, `actix-web` `HttpResponse::
//! insert_header`, `hyper` `Response::headers_mut().insert`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical Rust HTTP response header writers and the
//! surrounding source imports `http`, `axum`, `actix_web`, or
//! `hyper`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderRustAdapter;

const ADAPTER_NAME: &str = "header-rust";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(last, "insert" | "append" | "insert_header" | "header")
}

fn source_imports_rust_http(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"use http::HeaderMap",
        b"use http::header",
        b"use axum::",
        b"use actix_web",
        b"use hyper::",
        b"HeaderMap::new",
        b"HeaderValue::from",
        b"headers_mut()",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderRustAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Rust
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_header_setter);
        let matches_source = source_imports_rust_http(file_bytes);
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

    fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_headers_insert() {
        let src: &[u8] = b"use axum::http::HeaderMap;\n\
            fn run(headers: &mut HeaderMap, value: &str) { headers.insert(\"set-cookie\", value.parse().unwrap()); }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("insert")],
            ..Default::default()
        };
        assert!(HeaderRustAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"fn add(a: i32, b: i32) -> i32 { a + b }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(HeaderRustAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

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

/// True when `receiver` looks like a Rust `HeaderMap` / response handle.
/// Filters out `BTreeMap::insert` / `HashMap::insert` / `Vec::insert`
/// collisions where the receiver is an unrelated local (`map`, `cache`,
/// `entries`, etc.).
///
/// Drilled forms covered:
///   * `headers` / `headers_mut` — canonical `axum` / `hyper` handles
///   * `response` / `resp` / `res` — `actix_web::HttpResponse` / hyper builder
///   * `builder` — `axum::http::Response::builder()` chain root
///   * Any expression containing `.headers_mut()` or `.headers()` —
///     chain accessor returning `&mut HeaderMap` / `&HeaderMap`.
fn receiver_is_rust_header_map(receiver: &str) -> bool {
    matches!(
        receiver,
        "headers" | "headers_mut" | "response" | "resp" | "res" | "builder"
    ) || receiver.contains(".headers_mut()")
        || receiver.contains(".headers()")
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

/// Returns `true` when the surrounding source visibly routes the
/// header value through a canonical Rust URL-encoder.
fn value_routed_through_encoder(file_bytes: &[u8]) -> bool {
    const ENCODER_CALLS: &[&[u8]] = &[
        b"utf8_percent_encode(",
        b"percent_encode(",
        b"urlencoding::encode(",
        b"form_urlencoded::byte_serialize(",
    ];
    ENCODER_CALLS
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
        if value_routed_through_encoder(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches_with_receiver(
            summary,
            callee_is_header_setter,
            receiver_is_rust_header_map,
        );
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
        assert!(
            HeaderRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"fn add(a: i32, b: i32) -> i32 { a + b }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            HeaderRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_btreemap_insert_collision() {
        // `map.insert(k, v)` on a `BTreeMap` / `HashMap` collides with
        // `headers.insert(k, v)` on `HeaderMap` at the bare callee name.
        // Receiver text `map` is not in the HeaderMap allowlist, so the
        // adapter rejects.  `headers_mut()` substring is present in the
        // file so source-import gate alone would fire.
        let src: &[u8] = b"use std::collections::BTreeMap;\nuse axum::http::HeaderMap;\n\
            fn run(headers: &mut HeaderMap, value: String) {\n\
                let mut map: BTreeMap<String, String> = BTreeMap::new();\n\
                map.insert(\"k\".into(), value);\n\
                let _ = headers.headers_mut();\n\
            }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "insert".into(),
                receiver: Some("map".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            HeaderRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn fires_on_headers_receiver() {
        // Receiver `headers` is in the HeaderMap allowlist.
        let src: &[u8] = b"use axum::http::HeaderMap;\n\
            fn run(headers: &mut HeaderMap, value: &str) { headers.insert(\"X\", value.parse().unwrap()); }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "insert".into(),
                receiver: Some("headers".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            HeaderRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_value_url_encoded() {
        let src: &[u8] = b"use axum::http::HeaderMap;\n\
            use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};\n\
            fn run(headers: &mut HeaderMap, value: &str) {\n\
                let safe = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();\n\
                headers.insert(\"set-cookie\", safe.parse().unwrap());\n\
            }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("insert"),
                crate::summary::CalleeSite::bare("utf8_percent_encode"),
            ],
            ..Default::default()
        };
        assert!(
            HeaderRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

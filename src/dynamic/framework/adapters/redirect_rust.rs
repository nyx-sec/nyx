//! Rust [`super::super::FrameworkAdapter`] matching HTTP-redirect
//! sink constructions (`axum::response::Redirect::to`, actix-web
//! `HttpResponse::Found().append_header(("Location", v))`).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one
//! of the canonical Rust web-framework redirect entry points and the
//! surrounding source imports the matching framework module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectRustAdapter;

const ADAPTER_NAME: &str = "redirect-rust";

fn callee_last_segment(name: &str) -> &str {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last)
}

fn receiver_looks_like_redirect(recv: &str) -> bool {
    // Real CFG-derived method calls populate receiver text; accept only
    // when the receiver visibly references a Redirect-shaped type
    // (`Redirect`, `axum::response::Redirect`, `HttpResponse::Found`).
    // None-receiver callees (synthetic test fixtures, free functions)
    // are handled by `any_callee_matches_with_receiver` itself and pass
    // through without consulting this predicate.
    recv.contains("Redirect") || recv.contains("Found")
}

fn source_imports_rust_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"use axum::",
        b"axum::response::Redirect",
        b"use actix_web::",
        b"use rocket::",
        b"use warp::",
        b"Redirect::to",
        b"Redirect::permanent",
        b"Redirect::temporary",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// redirect URL through a canonical host-allowlist / URL-validator.
fn url_routed_through_validator(file_bytes: &[u8]) -> bool {
    const VALIDATOR_TOKENS: &[&[u8]] = &[
        b"Url::parse(",
        b"allowed_hosts",
        b"AllowedHosts",
        b"allowlist",
        b"Allowlist",
        b".host_str()",
        b".host() ==",
    ];
    VALIDATOR_TOKENS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectRustAdapter {
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
        if url_routed_through_validator(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches_with_receiver(
            summary,
            |name| {
                matches!(
                    callee_last_segment(name),
                    "to" | "redirect" | "temporary" | "permanent" | "Found"
                )
            },
            receiver_looks_like_redirect,
        );
        let matches_source = source_imports_rust_web(file_bytes);
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
    fn fires_on_axum_redirect_to() {
        let src: &[u8] =
            b"use axum::response::Redirect;\n\nfn run(v: String) -> Redirect { Redirect::to(&v) }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("to")],
            ..Default::default()
        };
        assert!(
            RedirectRustAdapter
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
            RedirectRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_to_call_with_non_redirect_receiver() {
        // Axum import + a chain that calls `.to(...)` on a non-Redirect
        // value (e.g. `String::to_owned` collisions surface as
        // `.to(...)` on a `Cow<str>` receiver).  Receiver text on the
        // CalleeSite carries `Cow`, not `Redirect`, so the adapter must
        // skip.
        let src: &[u8] = b"use axum::response::Redirect;\n\
            use std::borrow::Cow;\n\n\
            fn run(v: Cow<str>) -> String { v.to(&\"target\".to_owned()) }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "to".into(),
                receiver: Some("v".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            RedirectRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn fires_on_redirect_receiver_text() {
        // Real CFG-derived receiver carries the type identifier; accept
        // when receiver text contains `Redirect` (e.g. `Redirect::to(v)`
        // resolves to a `Redirect`-prefixed root receiver after the
        // `root_member_receiver` drill-down).
        let src: &[u8] = b"use axum::response::Redirect;\n\
            fn run(v: String) -> Redirect { Redirect::to(&v) }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "to".into(),
                receiver: Some("Redirect".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            RedirectRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_url_validated_against_allowlist() {
        let src: &[u8] = b"use axum::response::Redirect;\n\
            use url::Url;\n\n\
            fn run(v: String) -> Option<Redirect> {\n\
                let u = Url::parse(&v).ok()?;\n\
                if u.host_str() != Some(\"example.com\") { return None; }\n\
                Some(Redirect::to(&v))\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("to"),
                crate::summary::CalleeSite::bare("parse"),
            ],
            ..Default::default()
        };
        assert!(
            RedirectRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

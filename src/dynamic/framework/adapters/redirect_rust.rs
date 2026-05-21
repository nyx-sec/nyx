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

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(last, "to" | "redirect" | "temporary" | "permanent" | "Found")
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
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
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
        assert!(RedirectRustAdapter
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
        assert!(RedirectRustAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
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
        assert!(RedirectRustAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

//! PHP [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions (`header()`,
//! Symfony / Laravel `Response::headers->set`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical PHP response writers and the surrounding source
//! either references the built-in `$_SERVER` request surface or
//! imports a Symfony / Laravel response helper.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderPhpAdapter;

const ADAPTER_NAME: &str = "header-php";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    let last = last.rsplit_once("->").map(|(_, s)| s).unwrap_or(last);
    matches!(last, "header" | "setRawHeader" | "headers" | "set" | "add")
}

fn source_uses_php_response(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"header(",
        b"$_SERVER",
        b"Symfony\\Component\\HttpFoundation",
        b"Illuminate\\Http\\Response",
        b"->headers->",
        b"response()->header",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// header value through a canonical PHP URL-encoder / HTML-escaper.
fn value_routed_through_encoder(file_bytes: &[u8]) -> bool {
    const ENCODER_CALLS: &[&[u8]] = &[
        b"urlencode(",
        b"rawurlencode(",
        b"htmlspecialchars(",
        b"htmlentities(",
    ];
    ENCODER_CALLS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderPhpAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
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
        let matches_source = source_uses_php_response(file_bytes);
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_header_call() {
        let src: &[u8] = b"<?php\nfunction run($v) { header('Set-Cookie: ' . $v); }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("header")],
            ..Default::default()
        };
        assert!(HeaderPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(HeaderPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_value_url_encoded() {
        let src: &[u8] =
            b"<?php\nfunction run($v) { header('Set-Cookie: ' . urlencode($v)); }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("header"),
                crate::summary::CalleeSite::bare("urlencode"),
            ],
            ..Default::default()
        };
        assert!(HeaderPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

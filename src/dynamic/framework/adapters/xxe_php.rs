//! PHP [`super::super::FrameworkAdapter`] matching XXE-prone XML
//! parser constructions.
//!
//! Phase 05 (Track J.3).  Fires when the function body invokes one of
//! the canonical PHP XML entry points (`simplexml_load_string`,
//! `simplexml_load_file`, `DOMDocument::loadXML`,
//! `DOMDocument::load`, `xml_parser_create`) and the surrounding
//! source mentions an XML / libxml symbol — the parser, by default
//! and under `libxml_disable_entity_loader(false)`, expands external
//! entities.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XxePhpAdapter;

const ADAPTER_NAME: &str = "xxe-php";

fn callee_is_xml_parser(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s)
        .or_else(|| name.rsplit_once('.').map(|(_, s)| s))
        .or_else(|| name.rsplit_once("->").map(|(_, s)| s))
        .unwrap_or(name);
    matches!(
        last,
        "simplexml_load_string"
            | "simplexml_load_file"
            | "loadXML"
            | "load"
            | "xml_parser_create"
            | "xml_parse"
    )
}

fn source_imports_xml(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"simplexml_load_string",
        b"simplexml_load_file",
        b"DOMDocument",
        b"xml_parser_create",
        b"libxml_disable_entity_loader",
        b"LIBXML_NOENT",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly hardens the
/// libxml-backed PHP parser against external-entity expansion.  PHP
/// 8.0+ disables the entity loader by default, so the absence of the
/// `LIBXML_NOENT` flag combined with `libxml_disable_entity_loader(true)`
/// (the canonical PHP < 8.0 hardener) or the `LIBXML_NONET` flag is
/// the canonical safe shape.
fn parser_is_hardened(file_bytes: &[u8]) -> bool {
    // If LIBXML_NOENT is explicitly used, the parser is *un*-hardened
    // (the flag asks libxml to substitute entities). Treat as unsafe
    // regardless of any other tokens.
    let mentions_noent = file_bytes
        .windows(b"LIBXML_NOENT".len())
        .any(|w| w == b"LIBXML_NOENT");
    if mentions_noent {
        return false;
    }
    const HARDENING_NEEDLES: &[&[u8]] = &[
        b"libxml_disable_entity_loader(true)",
        b"libxml_disable_entity_loader(TRUE)",
        b"libxml_disable_entity_loader( true",
        b"libxml_disable_entity_loader( TRUE",
        b"LIBXML_NONET",
        b"LIBXML_DTDLOAD",
    ];
    // LIBXML_DTDLOAD on its own is neutral but commonly paired with
    // explicit hardening; require at least one of the disable_entity
    // / NONET tokens for a hardening verdict.
    const STRONG: &[&[u8]] = &[
        b"libxml_disable_entity_loader(true)",
        b"libxml_disable_entity_loader(TRUE)",
        b"libxml_disable_entity_loader( true",
        b"libxml_disable_entity_loader( TRUE",
        b"LIBXML_NONET",
    ];
    let has_strong = STRONG
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n));
    let _ = HARDENING_NEEDLES; // retained for documentation of recognised tokens
    has_strong
}

impl FrameworkAdapter for XxePhpAdapter {
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
        if parser_is_hardened(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_xml_parser);
        let matches_source = source_imports_xml(file_bytes);
        if matches_call || matches_source {
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
    fn fires_on_simplexml_load_string() {
        let src: &[u8] = b"<?php\nfunction run($body) {\n    return simplexml_load_string($body);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("simplexml_load_string")],
            ..Default::default()
        };
        assert!(XxePhpAdapter
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
        assert!(XxePhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_disable_entity_loader_true() {
        let src: &[u8] = b"<?php\nfunction run($body) {\n\
            libxml_disable_entity_loader(true);\n\
            return simplexml_load_string($body);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("simplexml_load_string")],
            ..Default::default()
        };
        assert!(XxePhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_libxml_nonet_used() {
        let src: &[u8] = b"<?php\nfunction run($body) {\n\
            return simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NONET);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("simplexml_load_string")],
            ..Default::default()
        };
        assert!(XxePhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn still_fires_when_libxml_noent_present() {
        // LIBXML_NOENT explicitly enables entity substitution -- the
        // dangerous flag overrides any other apparent hardening.
        let src: &[u8] = b"<?php\nfunction run($body) {\n\
            libxml_disable_entity_loader(true);\n\
            return simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NOENT);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("simplexml_load_string")],
            ..Default::default()
        };
        assert!(XxePhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }
}

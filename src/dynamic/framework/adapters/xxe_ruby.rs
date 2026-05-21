//! Ruby [`super::super::FrameworkAdapter`] matching XXE-prone XML
//! parser constructions.
//!
//! Phase 05 (Track J.3).  Fires when the function body invokes one of
//! the canonical Ruby XML entry points
//! (`REXML::Document.new`, `Nokogiri::XML`, `Nokogiri::XML::Document.parse`,
//! `Ox.parse`) and the surrounding source mentions the matching
//! library.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XxeRubyAdapter;

const ADAPTER_NAME: &str = "xxe-ruby";

fn callee_is_xml_parser(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s)
        .or_else(|| name.rsplit_once('.').map(|(_, s)| s))
        .unwrap_or(name);
    matches!(last, "new" | "parse" | "XML" | "load")
}

fn source_imports_xml(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"REXML",
        b"rexml/document",
        b"Nokogiri",
        b"nokogiri",
        b"Ox.parse",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly hardens the
/// Ruby XML parser against external-entity expansion.  Canonical
/// hardeners: `REXML::Document.entity_expansion_limit = 0` (kills
/// entity expansion outright) and `Nokogiri::XML::ParseOptions::NONET`
/// (no network for entity resolution).
///
/// If `Nokogiri::XML::ParseOptions::NOENT` is present the parser is
/// explicitly *un*-hardened (the flag asks Nokogiri to expand
/// entities), so the hardening verdict is suppressed.
fn parser_is_hardened(file_bytes: &[u8]) -> bool {
    let mentions_noent = file_bytes
        .windows(b"ParseOptions::NOENT".len())
        .any(|w| w == b"ParseOptions::NOENT")
        || file_bytes
            .windows(b"::NOENT".len())
            .any(|w| w == b"::NOENT");
    if mentions_noent {
        return false;
    }
    const HARDENING_NEEDLES: &[&[u8]] = &[
        b"entity_expansion_limit = 0",
        b"entity_expansion_limit=0",
        b"entity_expansion_limit =0",
        b"entity_expansion_limit= 0",
        b"ParseOptions::NONET",
        b"Nokogiri::XML::ParseOptions::NONET",
    ];
    HARDENING_NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XxeRubyAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_rexml_document_new() {
        let src: &[u8] = b"require 'rexml/document'\n\
            def run(body)\n  REXML::Document.new(body)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("new")],
            ..Default::default()
        };
        assert!(XxeRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b)\n  a + b\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(XxeRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_entity_expansion_limit_zero() {
        let src: &[u8] = b"require 'rexml/document'\n\
            REXML::Document.entity_expansion_limit = 0\n\
            def run(body)\n  REXML::Document.new(body)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("new")],
            ..Default::default()
        };
        assert!(XxeRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_nokogiri_nonet_used() {
        let src: &[u8] = b"require 'nokogiri'\n\
            def run(body)\n  Nokogiri::XML(body) { |c| c.options = Nokogiri::XML::ParseOptions::NONET }\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("XML")],
            ..Default::default()
        };
        assert!(XxeRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn still_fires_when_nokogiri_noent_present() {
        let src: &[u8] = b"require 'nokogiri'\n\
            def run(body)\n  Nokogiri::XML(body) { |c| c.options = Nokogiri::XML::ParseOptions::NOENT | Nokogiri::XML::ParseOptions::DTDLOAD }\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("XML")],
            ..Default::default()
        };
        assert!(XxeRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }
}

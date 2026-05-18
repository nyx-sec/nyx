//! Python [`super::super::FrameworkAdapter`] matching XXE-prone XML
//! parser constructions.
//!
//! Phase 05 (Track J.3).  Fires when the function body invokes one of
//! the canonical lxml / stdlib XML entry points
//! (`lxml.etree.XMLParser`, `lxml.etree.parse`, `lxml.etree.fromstring`,
//! `xml.etree.ElementTree.parse`, `xml.sax.parse`,
//! `xml.dom.minidom.parseString`) and the surrounding source mentions
//! the matching module.  Callee matching is last-segment-aware so
//! receiver-prefixed calls (`etree.XMLParser`,
//! `ElementTree.fromstring`) hit the same predicate.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XxePythonAdapter;

const ADAPTER_NAME: &str = "xxe-python";

fn callee_is_xml_parser(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "XMLParser"
            | "parse"
            | "fromstring"
            | "parseString"
            | "XMLPullParser"
            | "iterparse"
    )
}

fn source_imports_xml(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"lxml.etree",
        b"lxml import",
        b"xml.etree",
        b"ElementTree",
        b"xml.sax",
        b"xml.dom",
        b"defusedxml",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XxePythonAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_lxml_etree_fromstring() {
        let src: &[u8] = b"from lxml import etree\n\
            def run(body):\n    return etree.fromstring(body)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("fromstring")],
            ..Default::default()
        };
        assert!(XxePythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(XxePythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

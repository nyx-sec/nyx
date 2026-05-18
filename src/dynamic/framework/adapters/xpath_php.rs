//! PHP [`super::super::FrameworkAdapter`] matching XPath expression-
//! injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes
//! `DOMXPath::query` / `DOMXPath::evaluate` and the surrounding
//! source pulls in the `DOMXPath` / `DOMDocument` family.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XpathPhpAdapter;

const ADAPTER_NAME: &str = "xpath-php";

fn callee_is_xpath_eval(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(last, "query" | "evaluate" | "xpath")
}

fn source_uses_domxpath(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"DOMXPath",
        b"DOMDocument",
        b"SimpleXMLElement",
        b"simplexml_load_string",
        b"->xpath(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XpathPhpAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_xpath_eval);
        let matches_source = source_uses_domxpath(file_bytes);
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
    fn fires_on_domxpath_query() {
        let src: &[u8] = b"<?php\n\
            function run($name) {\n\
                $doc = new DOMDocument();\n\
                $doc->load('xpath_corpus.xml');\n\
                $xp = new DOMXPath($doc);\n\
                return $xp->query(\"//user[@name='\" . $name . \"']\");\n\
            }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("query")],
            ..Default::default()
        };
        assert!(XpathPhpAdapter
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
        assert!(XpathPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

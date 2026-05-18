//! JavaScript [`super::super::FrameworkAdapter`] matching XPath
//! expression-injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes the
//! npm `xpath` package's `select` / `evaluate` entry points (or the
//! browser DOM's `document.evaluate`) and the surrounding source
//! imports / requires the `xpath` module or references
//! `XPathResult` / `document.evaluate`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XpathJsAdapter;

const ADAPTER_NAME: &str = "xpath-js";

fn callee_is_xpath_eval(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "select" | "select1" | "evaluate" | "parse")
}

fn source_imports_xpath(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('xpath')",
        b"require(\"xpath\")",
        b"from 'xpath'",
        b"from \"xpath\"",
        b"xpath.select",
        b"xpath.evaluate",
        b"XPathResult",
        b"document.evaluate",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XpathJsAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_xpath_eval);
        let matches_source = source_imports_xpath(file_bytes);
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
    fn fires_on_xpath_select() {
        let src: &[u8] = b"const xpath = require('xpath');\n\
            function run(name) {\n\
                return xpath.select(\"//user[@name='\" + name + \"']\", doc);\n\
            }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("select")],
            ..Default::default()
        };
        assert!(XpathJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\nmodule.exports = { add };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(XpathJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

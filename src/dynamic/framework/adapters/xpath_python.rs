//! Python [`super::super::FrameworkAdapter`] matching XPath expression-
//! injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes
//! `lxml.etree`'s XPath entry points (`Element.xpath`, `xpath`,
//! `XPath` evaluator) and the surrounding source imports `lxml`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XpathPythonAdapter;

const ADAPTER_NAME: &str = "xpath-python";

fn callee_is_xpath_eval(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "xpath" | "evaluate" | "find" | "findall" | "iterfind")
}

fn source_imports_lxml(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"from lxml",
        b"import lxml",
        b"lxml.etree",
        b"etree.XPath",
        b"etree.ElementTree",
        b"xml.etree.ElementTree",
        b"ElementTree.fromstring",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XpathPythonAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_xpath_eval);
        let matches_source = source_imports_lxml(file_bytes);
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
    fn fires_on_lxml_xpath() {
        let src: &[u8] = b"from lxml import etree\n\
            def run(name):\n\
                tree = etree.fromstring(open('xpath_corpus.xml').read())\n\
                return tree.xpath(\"//user[@name='\" + name + \"']\")\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("xpath")],
            ..Default::default()
        };
        assert!(XpathPythonAdapter
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
        assert!(XpathPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

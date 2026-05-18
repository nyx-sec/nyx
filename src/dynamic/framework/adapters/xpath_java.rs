//! Java [`super::super::FrameworkAdapter`] matching XPath expression-
//! injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes one of
//! the canonical `javax.xml.xpath` entry points
//! (`XPath.evaluate`, `XPath.compile`, `XPathExpression.evaluate`)
//! and the surrounding source pulls in one of the matching package
//! symbols — `javax.xml.xpath.*`, `XPathFactory`,
//! `XPathConstants.NODESET`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XpathJavaAdapter;

const ADAPTER_NAME: &str = "xpath-java";

fn callee_is_xpath_eval(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "evaluate" | "compile" | "selectNodes" | "selectSingleNode")
}

fn source_imports_xpath(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"javax.xml.xpath",
        b"XPathFactory",
        b"XPathExpression",
        b"XPathConstants",
        b"net.sf.saxon.s9api",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XpathJavaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
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
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            });
        }
        if matches_source
            && file_bytes
                .windows(b".evaluate(".len())
                .any(|w| w == b".evaluate(")
        {
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_xpath_evaluate() {
        let src: &[u8] = b"import javax.xml.xpath.XPathFactory;\n\
            public class V {\n  public Object run(String name) throws Exception {\n\
                javax.xml.xpath.XPath xp = XPathFactory.newInstance().newXPath();\n\
                return xp.evaluate(\"//user[@name='\" + name + \"']\", null);\n\
            }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("evaluate")],
            ..Default::default()
        };
        let binding = XpathJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("must fire on XPath.evaluate");
        assert_eq!(binding.adapter, ADAPTER_NAME);
        assert_eq!(binding.kind, EntryKind::Function);
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] =
            b"public class V { public static int add(int a, int b) { return a + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(XpathJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

//! Python [`super::super::FrameworkAdapter`] matching XPath expression-
//! injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes
//! `lxml.etree`'s XPath entry points (`Element.xpath`, `xpath`,
//! `XPath` evaluator) and the surrounding source imports `lxml`.
//!
//! Strengthened to walk the AST and only fire when the evaluator's
//! expression argument carries a tainted-param identifier in its
//! subtree.  Pre-bound parameterised queries
//! (`etree.XPath("//user[@name=$name]")(tree, name=name)`) keep the
//! template string literal-only, so the walker sees no tainted
//! identifier inside the call to `XPath` / `xpath` and the binding
//! is skipped.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct XpathPythonAdapter;

const ADAPTER_NAME: &str = "xpath-python";

fn callee_is_xpath_eval(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "xpath" | "evaluate" | "find" | "findall" | "iterfind" | "XPath"
    )
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

fn ast_confirms_tainted_xpath(root: Node<'_>, bytes: &[u8], summary: &FuncSummary) -> bool {
    let mut found = false;
    walk(root, bytes, summary, root, &mut found);
    found
}

fn walk<'a>(
    node: Node<'a>,
    bytes: &[u8],
    summary: &FuncSummary,
    scope: Node<'a>,
    found: &mut bool,
) {
    if *found {
        return;
    }
    if node.kind() == "call"
        && let Some(func) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_xpath_eval(func)
        && let Some(args) = node.child_by_field_name("arguments")
        && super::subtree_contains_tainted_param(args, bytes, summary, Some(scope))
    {
        *found = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, summary, scope, found);
    }
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_lxml(file_bytes) {
            return None;
        }
        if !super::any_callee_matches(summary, callee_is_xpath_eval) {
            return None;
        }
        if !ast_confirms_tainted_xpath(ast, file_bytes, summary) {
            return None;
        }
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::Function,
            route: None,
            request_params: Vec::new(),
            response_writer: None,
            middleware: Vec::new(),
        })
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

    fn summary_for(name: &str, params: &[&str], tainted: &[usize]) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            param_count: params.len(),
            param_names: params.iter().map(|s| (*s).to_owned()).collect(),
            tainted_sink_params: tainted.to_vec(),
            callees: vec![crate::summary::CalleeSite::bare("xpath")],
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_lxml_xpath() {
        let src: &[u8] = b"from lxml import etree\n\
            def run(name):\n\
                tree = etree.fromstring(open('xpath_corpus.xml').read())\n\
                return tree.xpath(\"//user[@name='\" + name + \"']\")\n";
        let tree = parse_python(src);
        let summary = summary_for("run", &["name"], &[0]);
        assert!(
            XpathPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            XpathPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_expression_uses_bound_variable() {
        let src: &[u8] = b"from lxml import etree\n\
            def run(name):\n\
                tree = etree.fromstring(open('xpath_corpus.xml').read())\n\
                q = etree.XPath(\"//user[@name=$name]\")\n\
                return q(tree, name=name)\n";
        let tree = parse_python(src);
        let summary = summary_for("run", &["name"], &[0]);
        assert!(
            XpathPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

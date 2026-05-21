//! JavaScript [`super::super::FrameworkAdapter`] matching XPath
//! expression-injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes the
//! npm `xpath` package's `select` / `evaluate` entry points (or the
//! browser DOM's `document.evaluate`) and the surrounding source
//! imports / requires the `xpath` module or references
//! `XPathResult` / `document.evaluate`.
//!
//! Strengthened to walk the AST and only fire when the selector's
//! expression argument carries a tainted-param identifier in its
//! subtree.  Bound queries that build the expression as a literal
//! and pass variables separately (`xpath.parse(expr).select({ vars
//! })`) leave the first arg literal-only and skip the binding.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

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
    if node.kind() == "call_expression"
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_xpath(file_bytes) {
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary_for(name: &str, params: &[&str], tainted: &[usize]) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            param_count: params.len(),
            param_names: params.iter().map(|s| (*s).to_owned()).collect(),
            tainted_sink_params: tainted.to_vec(),
            callees: vec![crate::summary::CalleeSite::bare("select")],
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_xpath_select() {
        let src: &[u8] = b"const xpath = require('xpath');\n\
            function run(name) {\n\
                return xpath.select(\"//user[@name='\" + name + \"']\", doc);\n\
            }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = summary_for("run", &["name"], &[0]);
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

    #[test]
    fn skips_when_expression_is_literal_only() {
        let src: &[u8] = b"const xpath = require('xpath');\n\
            function run(name) {\n\
                return xpath.select(\"//user[@id=1]\", doc);\n\
            }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = summary_for("run", &["name"], &[0]);
        assert!(XpathJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

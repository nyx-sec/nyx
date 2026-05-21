//! PHP [`super::super::FrameworkAdapter`] matching XPath expression-
//! injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes
//! `DOMXPath::query` / `DOMXPath::evaluate` and the surrounding
//! source pulls in the `DOMXPath` / `DOMDocument` family.
//!
//! Strengthened to walk the AST and only fire when the query call's
//! expression argument carries a tainted-param identifier in its
//! subtree.  Pure-literal expressions (`$xp->query("//user[@id=1]")`)
//! produce no tainted-identifier hit and the binding is skipped.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

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
    if matches!(
        node.kind(),
        "member_call_expression" | "scoped_call_expression" | "function_call_expression"
    ) && let Some(name) = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("function"))
        .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_xpath_eval(name)
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_uses_domxpath(file_bytes) {
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary_for(name: &str, params: &[&str], tainted: &[usize]) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            param_count: params.len(),
            param_names: params.iter().map(|s| (*s).to_owned()).collect(),
            tainted_sink_params: tainted.to_vec(),
            callees: vec![crate::summary::CalleeSite::bare("query")],
            ..Default::default()
        }
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
        let summary = summary_for("run", &["name"], &[0]);
        assert!(
            XpathPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            XpathPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_expression_is_literal_only() {
        let src: &[u8] = b"<?php\n\
            function run($name) {\n\
                $doc = new DOMDocument();\n\
                $doc->load('xpath_corpus.xml');\n\
                $xp = new DOMXPath($doc);\n\
                return $xp->query(\"//user[@id=1]\");\n\
            }\n";
        let tree = parse_php(src);
        let summary = summary_for("run", &["name"], &[0]);
        assert!(
            XpathPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

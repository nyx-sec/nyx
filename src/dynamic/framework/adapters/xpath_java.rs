//! Java [`super::super::FrameworkAdapter`] matching XPath expression-
//! injection sink constructions.
//!
//! Phase 07 (Track J.5).  Fires when the function body invokes one of
//! the canonical `javax.xml.xpath` entry points
//! (`XPath.evaluate`, `XPath.compile`, `XPathExpression.evaluate`)
//! and the surrounding source pulls in one of the matching package
//! symbols — `javax.xml.xpath.*`, `XPathFactory`,
//! `XPathConstants.NODESET`.
//!
//! Strengthened to walk the AST and only fire when the evaluator's
//! expression argument carries a tainted-param identifier in its
//! subtree.  Pre-bound parameterised queries (`xp.setVariable("name",
//! input)` + `xp.evaluate("//user[@name=$name]")`) leave the
//! expression as a string literal, so the walker sees no tainted
//! identifier and the binding is skipped.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

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
    if node.kind() == "method_invocation"
        && let Some(name) = node
            .child_by_field_name("name")
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary_for(name: &str, params: &[&str], tainted: &[usize]) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            param_count: params.len(),
            param_names: params.iter().map(|s| (*s).to_owned()).collect(),
            tainted_sink_params: tainted.to_vec(),
            callees: vec![crate::summary::CalleeSite::bare("evaluate")],
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_xpath_evaluate() {
        let src: &[u8] = b"import javax.xml.xpath.XPathFactory;\n\
            public class V {\n  public Object run(String name) throws Exception {\n\
                javax.xml.xpath.XPath xp = XPathFactory.newInstance().newXPath();\n\
                return xp.evaluate(\"//user[@name='\" + name + \"']\", null);\n\
            }\n}\n";
        let tree = parse_java(src);
        let summary = summary_for("run", &["name"], &[0]);
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

    #[test]
    fn skips_when_expression_uses_bound_variable() {
        // The expression is a literal containing `$name`; the actual
        // input is bound via `xp.setVariable`.  No tainted identifier
        // appears inside `evaluate`'s argument subtree.
        let src: &[u8] = b"import javax.xml.xpath.XPathFactory;\n\
            public class V {\n  public Object run(String name) throws Exception {\n\
                javax.xml.xpath.XPath xp = XPathFactory.newInstance().newXPath();\n\
                xp.setXPathVariableResolver(new Resolver(name));\n\
                return xp.evaluate(\"//user[@name=$name]\", null);\n\
            }\n}\n";
        let tree = parse_java(src);
        let summary = summary_for("run", &["name"], &[0]);
        assert!(XpathJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

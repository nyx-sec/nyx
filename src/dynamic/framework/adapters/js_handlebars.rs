//! JavaScript [`super::super::FrameworkAdapter`] matching Handlebars
//! SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes
//! `Handlebars.compile(<tainted>)` (matched by the last segment of the
//! callee — the call graph normaliser drops the receiver).
//!
//! Strengthened to walk the AST for a real `call_expression` whose
//! first positional argument names a parameter listed in
//! `summary.tainted_sink_params` or `summary.propagating_params`,
//! removing the comment-substring FP.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct JsHandlebarsAdapter;

const ADAPTER_NAME: &str = "js-handlebars";

fn callee_last_segment(name: &str) -> &str {
    name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name)
}

fn is_handlebars_entry(name: &str) -> bool {
    matches!(
        callee_last_segment(name),
        "compile" | "precompile" | "SafeString"
    )
}

fn ast_confirms_tainted_call(root: Node<'_>, bytes: &[u8], summary: &FuncSummary) -> bool {
    let mut found = false;
    walk(root, bytes, summary, &mut found);
    found
}

fn walk(node: Node<'_>, bytes: &[u8], summary: &FuncSummary, found: &mut bool) {
    if *found {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(func) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
        && is_handlebars_entry(func)
        && let Some(args) = node.child_by_field_name("arguments")
        && let Some(first) = first_positional_arg(args)
        && let Ok(text) = first.utf8_text(bytes)
        && super::arg_is_tainted_param(summary, text)
    {
        *found = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, summary, found);
    }
}

fn first_positional_arg<'a>(args: Node<'a>) -> Option<Node<'a>> {
    let mut cur = args.walk();
    for arg in args.named_children(&mut cur) {
        if arg.kind() == "spread_element" {
            continue;
        }
        return Some(arg);
    }
    None
}

impl FrameworkAdapter for JsHandlebarsAdapter {
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
        let cheap_filter = file_bytes
            .windows(b"handlebars".len())
            .any(|w| w.eq_ignore_ascii_case(b"handlebars"))
            || file_bytes
                .windows(b"Handlebars".len())
                .any(|w| w == b"Handlebars");
        if !cheap_filter {
            return None;
        }
        if !super::any_callee_matches(summary, is_handlebars_entry) {
            return None;
        }
        if !ast_confirms_tainted_call(ast, file_bytes, summary) {
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
            callees: vec![crate::summary::CalleeSite::bare("compile")],
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_handlebars_compile() {
        let src: &[u8] = b"const Handlebars = require('handlebars');\nfunction render(body) {\n  return Handlebars.compile(body)({});\n}\n";
        let tree = parse_js(src);
        let summary = summary_for("render", &["body"], &[0]);
        assert!(JsHandlebarsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(JsHandlebarsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_comment_substring_with_constant_arg() {
        let src: &[u8] = b"// uses Handlebars\nfunction render(body) {\n  return Handlebars.compile(\"static\")({});\n}\n";
        let tree = parse_js(src);
        let summary = summary_for("render", &["body"], &[0]);
        assert!(JsHandlebarsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_param_not_in_tainted_set() {
        let src: &[u8] = b"const Handlebars = require('handlebars');\nfunction render(body) {\n  return Handlebars.compile(body)({});\n}\n";
        let tree = parse_js(src);
        let summary = summary_for("render", &["body"], &[]);
        assert!(JsHandlebarsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

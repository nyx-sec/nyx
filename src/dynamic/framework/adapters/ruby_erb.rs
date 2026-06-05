//! Ruby [`super::super::FrameworkAdapter`] matching ERB SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes
//! `ERB.new(<tainted>).result` (or the equivalent `result_with_hash`
//! variant).  Callee matching is last-segment-aware so namespaced
//! receivers (`Erubi::Engine.new`) reduce to `new` + a string-level
//! check for the surrounding `ERB` / `Erubi` token in the source.
//!
//! Strengthened to require a real `call` node whose first positional
//! argument names a parameter listed in `summary.tainted_sink_params`
//! or `summary.propagating_params`, removing the comment-substring FP.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct RubyErbAdapter;

const ADAPTER_NAME: &str = "ruby-erb";

fn callee_last_segment(name: &str) -> &str {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    last.rsplit_once("::").map(|(_, s)| s).unwrap_or(last)
}

fn is_erb_entry(name: &str) -> bool {
    matches!(
        callee_last_segment(name),
        "result" | "result_with_hash" | "new"
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
    if matches!(node.kind(), "call" | "method_call")
        && let Some(method) = node
            .child_by_field_name("method")
            .and_then(|n| n.utf8_text(bytes).ok())
        && is_erb_entry(method)
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
        if matches!(
            arg.kind(),
            "pair" | "hash_splat_argument" | "block_argument"
        ) {
            continue;
        }
        return Some(arg);
    }
    None
}

impl FrameworkAdapter for RubyErbAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let cheap_filter = file_bytes
            .windows(b"ERB.new".len())
            .any(|w| w == b"ERB.new")
            || file_bytes
                .windows(b"require 'erb'".len())
                .any(|w| w == b"require 'erb'")
            || file_bytes
                .windows(b"require \"erb\"".len())
                .any(|w| w == b"require \"erb\"")
            || file_bytes.windows(b"Erubi".len()).any(|w| w == b"Erubi");
        if !cheap_filter {
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary_for(name: &str, params: &[&str], tainted: &[usize]) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            param_count: params.len(),
            param_names: params.iter().map(|s| (*s).to_owned()).collect(),
            tainted_sink_params: tainted.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_erb_new_result() {
        let src: &[u8] = b"require 'erb'\ndef render(body)\n  ERB.new(body).result\nend\n";
        let tree = parse_ruby(src);
        let summary = summary_for("render", &["body"], &[0]);
        assert!(
            RubyErbAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b)\n  a + b\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            RubyErbAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_comment_substring_with_constant_arg() {
        let src: &[u8] =
            b"# require 'erb' is mentioned\ndef render(body)\n  ERB.new(\"static\").result\nend\n";
        let tree = parse_ruby(src);
        let summary = summary_for("render", &["body"], &[0]);
        assert!(
            RubyErbAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_param_not_in_tainted_set() {
        let src: &[u8] = b"require 'erb'\ndef render(body)\n  ERB.new(body).result\nend\n";
        let tree = parse_ruby(src);
        let summary = summary_for("render", &["body"], &[]);
        assert!(
            RubyErbAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

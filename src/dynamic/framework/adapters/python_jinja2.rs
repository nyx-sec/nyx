//! Python [`super::super::FrameworkAdapter`] matching Jinja2 SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes one of
//! the canonical Jinja2 entry points with a tainted template body —
//! `Template(<tainted>)`, `Environment(...).from_string(<tainted>)`, or
//! `render_template_string(<tainted>)`.  Callee matching is
//! last-segment so receiver-prefixed calls (`env.from_string`,
//! `flask.render_template_string`) hit the same predicate.
//!
//! The cheap byte-grep on `jinja2` / `from_string` /
//! `render_template_string` is kept as an early filter, but the
//! binding only fires after a tree-sitter walk confirms a real call
//! node whose first argument names a function parameter listed in
//! `summary.tainted_sink_params` or `summary.propagating_params`.
//! That removes the comment-substring FP (a docstring mentioning
//! `jinja2.Template` plus an unrelated `Template(constant)` call no
//! longer trips the adapter).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct PythonJinja2Adapter;

const ADAPTER_NAME: &str = "python-jinja2";

fn callee_last_segment(name: &str) -> &str {
    name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name)
}

fn is_jinja2_entry(name: &str) -> bool {
    matches!(
        callee_last_segment(name),
        "Template" | "from_string" | "render_template_string"
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
    if node.kind() == "call"
        && let Some(func) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
        && is_jinja2_entry(func)
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
        if arg.kind() == "keyword_argument" {
            continue;
        }
        return Some(arg);
    }
    None
}

impl FrameworkAdapter for PythonJinja2Adapter {
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
        let cheap_filter = file_bytes
            .windows(b"jinja2".len())
            .any(|w| w == b"jinja2")
            || file_bytes
                .windows(b"from_string".len())
                .any(|w| w == b"from_string")
            || file_bytes
                .windows(b"render_template_string".len())
                .any(|w| w == b"render_template_string");
        if !cheap_filter {
            return None;
        }
        if !super::any_callee_matches(summary, is_jinja2_entry) {
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
            callees: vec![crate::summary::CalleeSite::bare("Template")],
            ..Default::default()
        }
    }

    #[test]
    fn fires_when_source_imports_jinja2() {
        let src: &[u8] =
            b"from jinja2 import Template\ndef render(body):\n    return Template(body).render()\n";
        let tree = parse_python(src);
        let summary = summary_for("render", &["body"], &[0]);
        assert!(PythonJinja2Adapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn fires_when_callee_is_render_template_string() {
        let src: &[u8] =
            b"from flask import render_template_string\ndef view(body):\n    return render_template_string(body)\n";
        let tree = parse_python(src);
        let mut summary = summary_for("view", &["body"], &[0]);
        summary.callees = vec![crate::summary::CalleeSite::bare("render_template_string")];
        assert!(PythonJinja2Adapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def run(x):\n    return x + 1\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(PythonJinja2Adapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_comment_substring_with_constant_arg() {
        // Docstring mentions jinja2; the actual call passes a string
        // literal — no parameter taint reaches the engine.
        let src: &[u8] = b"\"\"\"renders via jinja2.Template\"\"\"\ndef render(body):\n    return Template(\"hello\").render()\n";
        let tree = parse_python(src);
        let summary = summary_for("render", &["body"], &[0]);
        assert!(PythonJinja2Adapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_param_not_in_tainted_set() {
        // Engine never flagged `body` as tainted (no taint reached an
        // internal sink in pass 1); the adapter must not stamp.
        let src: &[u8] =
            b"from jinja2 import Template\ndef render(body):\n    return Template(body).render()\n";
        let tree = parse_python(src);
        let summary = summary_for("render", &["body"], &[]);
        assert!(PythonJinja2Adapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

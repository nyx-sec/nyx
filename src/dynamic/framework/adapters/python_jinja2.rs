//! Python [`super::super::FrameworkAdapter`] matching Jinja2 SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes one of
//! the canonical Jinja2 entry points with a tainted template body —
//! `Template(<tainted>)`, `Environment(...).from_string(<tainted>)`, or
//! `render_template_string(<tainted>)`.  Callee matching is
//! last-segment so receiver-prefixed calls (`env.from_string`,
//! `flask.render_template_string`) hit the same predicate.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct PythonJinja2Adapter;

const ADAPTER_NAME: &str = "python-jinja2";

fn callee_is_jinja2(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "Template" | "from_string" | "render_template_string"
    )
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_jinja2);
        let matches_source = file_bytes
            .windows(b"jinja2".len())
            .any(|w| w == b"jinja2")
            || file_bytes
                .windows(b"from_string".len())
                .any(|w| w == b"from_string")
            || file_bytes
                .windows(b"render_template_string".len())
                .any(|w| w == b"render_template_string");
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
    fn fires_when_source_imports_jinja2() {
        let src: &[u8] =
            b"from jinja2 import Template\ndef render(body):\n    return Template(body).render()\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "render".into(),
            callees: vec![crate::summary::CalleeSite::bare("Template")],
            ..Default::default()
        };
        assert!(PythonJinja2Adapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn fires_when_callee_is_render_template_string() {
        let src: &[u8] =
            b"from flask import render_template_string\ndef view(body):\n    return render_template_string(body)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "view".into(),
            callees: vec![crate::summary::CalleeSite::bare("render_template_string")],
            ..Default::default()
        };
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
}

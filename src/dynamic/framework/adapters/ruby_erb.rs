//! Ruby [`super::super::FrameworkAdapter`] matching ERB SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes
//! `ERB.new(<tainted>).result` (or the equivalent `result_with_hash`
//! variant).  Callee matching is last-segment-aware so namespaced
//! receivers (`Erubi::Engine.new`) reduce to `new` + a string-level
//! check for the surrounding `ERB` / `Erubi` token in the source.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RubyErbAdapter;

const ADAPTER_NAME: &str = "ruby-erb";

fn callee_is_erb(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "result" | "result_with_hash" | "new")
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_erb);
        let matches_source = file_bytes
            .windows(b"ERB.new".len())
            .any(|w| w == b"ERB.new")
            || file_bytes
                .windows(b"require 'erb'".len())
                .any(|w| w == b"require 'erb'")
            || file_bytes
                .windows(b"require \"erb\"".len())
                .any(|w| w == b"require \"erb\"")
            || file_bytes
                .windows(b"Erubi".len())
                .any(|w| w == b"Erubi");
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
                .windows(b".result".len())
                .any(|w| w == b".result")
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_erb_new_result() {
        let src: &[u8] = b"require 'erb'\ndef render(body)\n  ERB.new(body).result\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "render".into(),
            ..Default::default()
        };
        assert!(RubyErbAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b)\n  a + b\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(RubyErbAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

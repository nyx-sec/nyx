//! Ruby [`super::super::FrameworkAdapter`] matching `Marshal.load` /
//! `YAML.load` deserialization sinks.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RubyMarshalAdapter;

const ADAPTER_NAME: &str = "ruby-marshal";

fn callee_is_ruby_deserialize(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once("::").map(|(_, s)| s).unwrap_or(last);
    matches!(last, "load" | "restore" | "unsafe_load" | "load_documents")
        && (name.contains("Marshal") || name.contains("YAML"))
}

impl FrameworkAdapter for RubyMarshalAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_ruby_deserialize);
        let matches_source = file_bytes
            .windows(b"Marshal.load".len())
            .any(|w| w == b"Marshal.load")
            || file_bytes
                .windows(b"Marshal.restore".len())
                .any(|w| w == b"Marshal.restore")
            || file_bytes
                .windows(b"YAML.load".len())
                .any(|w| w == b"YAML.load")
            || file_bytes
                .windows(b"YAML.unsafe_load".len())
                .any(|w| w == b"YAML.unsafe_load");
        if matches_call || matches_source {
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_when_source_calls_marshal_load() {
        let src: &[u8] = b"def run(blob)\n  Marshal.load(blob)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            RubyMarshalAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def run(x)\n  x + 1\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            RubyMarshalAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

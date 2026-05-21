//! PHP [`super::super::FrameworkAdapter`] matching `unserialize` sinks.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct PhpUnserializeAdapter;

const ADAPTER_NAME: &str = "php-unserialize";

fn callee_is_php_deserialize(name: &str) -> bool {
    let last = name.rsplit_once('\\').map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once("::").map(|(_, s)| s).unwrap_or(last);
    matches!(last, "unserialize")
}

impl FrameworkAdapter for PhpUnserializeAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_php_deserialize);
        let matches_source = file_bytes
            .windows(b"unserialize".len())
            .any(|w| w == b"unserialize");
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_when_source_calls_unserialize() {
        let src: &[u8] = b"<?php\nfunction run($blob) { return unserialize($blob); }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            PhpUnserializeAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction run($x) { return strtoupper($x); }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            PhpUnserializeAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

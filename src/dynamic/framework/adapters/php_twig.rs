//! PHP [`super::super::FrameworkAdapter`] matching Twig SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes the
//! canonical Twig entry points with a tainted template body —
//! `Twig\Environment::createTemplate(<tainted>)` or
//! `$twig->render($tainted)`.  Callee matching is last-segment so
//! receiver-prefixed calls (`$env->render`,
//! `Twig\Environment::createTemplate`) hit the same predicate.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct PhpTwigAdapter;

const ADAPTER_NAME: &str = "php-twig";

fn callee_is_twig(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once("::").map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "createTemplate" | "render" | "renderBlock" | "display"
    )
}

impl FrameworkAdapter for PhpTwigAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_twig);
        let matches_source = file_bytes
            .windows(b"Twig\\Environment".len())
            .any(|w| w == b"Twig\\Environment")
            || file_bytes
                .windows(b"Twig_Environment".len())
                .any(|w| w == b"Twig_Environment")
            || file_bytes
                .windows(b"use Twig".len())
                .any(|w| w == b"use Twig")
            || file_bytes
                .windows(b"createTemplate".len())
                .any(|w| w == b"createTemplate");
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
        None
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
    fn fires_on_create_template() {
        let src: &[u8] = b"<?php\nuse Twig\\Environment;\nfunction render($body, $twig) {\n    $tpl = $twig->createTemplate($body);\n    return $tpl->render([]);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "render".into(),
            callees: vec![crate::summary::CalleeSite::bare("createTemplate")],
            ..Default::default()
        };
        assert!(PhpTwigAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(PhpTwigAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

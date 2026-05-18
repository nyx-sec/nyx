//! PHP [`super::super::FrameworkAdapter`] matching HTTP-redirect
//! sink constructions (`header("Location: ...")`,
//! Symfony `RedirectResponse`, Slim `Response::withHeader`).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one
//! of the canonical PHP redirect entry points and the surrounding
//! source imports a recognised framework / writes a `Location:`
//! header.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectPhpAdapter;

const ADAPTER_NAME: &str = "redirect-php";

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "redirect" | "withRedirect" | "RedirectResponse" | "header"
    )
}

fn source_imports_php_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"Symfony\\Component\\HttpFoundation",
        b"Slim\\Psr7",
        b"Psr\\Http\\Message",
        b"Location:",
        b"RedirectResponse",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectPhpAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
        let matches_source = source_imports_php_web(file_bytes);
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_header_location() {
        let src: &[u8] =
            b"<?php\nfunction run($v) { header(\"Location: \" . $v); exit; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("header")],
            ..Default::default()
        };
        assert!(RedirectPhpAdapter
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
        assert!(RedirectPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

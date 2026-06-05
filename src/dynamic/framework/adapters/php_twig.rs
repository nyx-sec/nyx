//! PHP [`super::super::FrameworkAdapter`] matching Twig SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes the
//! canonical Twig entry points with a tainted template body —
//! `Twig\Environment::createTemplate(<tainted>)` or
//! `$twig->render($tainted)`.  Callee matching is last-segment so
//! receiver-prefixed calls (`$env->render`,
//! `Twig\Environment::createTemplate`) hit the same predicate.
//!
//! Strengthened to walk the AST for a real `member_call_expression`
//! or `scoped_call_expression` whose first positional argument names
//! a parameter listed in `summary.tainted_sink_params` or
//! `summary.propagating_params`, removing the comment-substring FP.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct PhpTwigAdapter;

const ADAPTER_NAME: &str = "php-twig";

fn callee_is_twig(name: &str) -> bool {
    matches!(
        name,
        "createTemplate" | "render" | "renderBlock" | "display"
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
    if matches!(
        node.kind(),
        "member_call_expression" | "scoped_call_expression" | "function_call_expression"
    ) && let Some(name) = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("function"))
        .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_twig(name)
        && let Some(args) = node.child_by_field_name("arguments")
        && let Some(text) = first_positional_arg_text(args, bytes)
        && super::arg_is_tainted_param(summary, &text)
    {
        *found = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, summary, found);
    }
}

fn first_positional_arg_text(args: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = args.walk();
    for arg in args.named_children(&mut cur) {
        if arg.kind() != "argument" {
            continue;
        }
        if arg.child_by_field_name("name").is_some() {
            continue;
        }
        let value = arg.named_child(0)?;
        return value.utf8_text(bytes).ok().map(|s| s.to_owned());
    }
    None
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let cheap_filter = file_bytes
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
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
    fn fires_on_create_template() {
        let src: &[u8] = b"<?php\nuse Twig\\Environment;\nfunction render($body, $twig) {\n    $tpl = $twig->createTemplate($body);\n    return $tpl->render([]);\n}\n";
        let tree = parse_php(src);
        let summary = summary_for("render", &["body", "twig"], &[0]);
        assert!(
            PhpTwigAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            PhpTwigAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_comment_substring_with_constant_arg() {
        // The comment mentions `Twig\Environment` and the call uses a
        // literal — no tainted parameter reaches the engine.
        let src: &[u8] = b"<?php\n// Twig\\Environment is great\nfunction render($body, $twig) {\n    $tpl = $twig->createTemplate('static');\n    return $tpl->render([]);\n}\n";
        let tree = parse_php(src);
        let summary = summary_for("render", &["body", "twig"], &[0]);
        assert!(
            PhpTwigAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_param_not_in_tainted_set() {
        let src: &[u8] = b"<?php\nuse Twig\\Environment;\nfunction render($body, $twig) {\n    $tpl = $twig->createTemplate($body);\n    return $tpl->render([]);\n}\n";
        let tree = parse_php(src);
        let summary = summary_for("render", &["body", "twig"], &[]);
        assert!(
            PhpTwigAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

//! JavaScript [`super::super::FrameworkAdapter`] matching Handlebars
//! SSTI sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes
//! `Handlebars.compile(<tainted>)` (matched by the last segment of the
//! callee — the call graph normaliser drops the receiver).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct JsHandlebarsAdapter;

const ADAPTER_NAME: &str = "js-handlebars";

fn callee_is_handlebars(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "compile" | "precompile" | "SafeString")
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_handlebars);
        let matches_source = file_bytes
            .windows(b"handlebars".len())
            .any(|w| w.eq_ignore_ascii_case(b"handlebars"))
            || file_bytes
                .windows(b"Handlebars".len())
                .any(|w| w == b"Handlebars");
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_handlebars_compile() {
        let src: &[u8] = b"const Handlebars = require('handlebars');\nfunction render(body) {\n  return Handlebars.compile(body)({});\n}\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "render".into(),
            callees: vec![crate::summary::CalleeSite::bare("compile")],
            ..Default::default()
        };
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
}

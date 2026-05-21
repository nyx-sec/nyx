//! Go [`super::super::FrameworkAdapter`] matching XXE-prone
//! `encoding/xml` parser constructions.
//!
//! Phase 05 (Track J.3).  Fires when the function body invokes one of
//! the canonical `encoding/xml` entry points (`xml.NewDecoder`,
//! `xml.Unmarshal`, `Decoder.Decode`) and the surrounding source
//! mentions the `encoding/xml` import — the brief specifically calls
//! out `xml.Decoder` with `Strict: false` as the XXE-prone shape.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XxeGoAdapter;

const ADAPTER_NAME: &str = "xxe-go";

fn callee_is_xml_parser(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "NewDecoder" | "Unmarshal" | "Decode" | "DecodeElement"
    )
}

fn source_imports_xml(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"encoding/xml",
        b"xml.NewDecoder",
        b"xml.Unmarshal",
        b"xml.Decoder",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly pins
/// `encoding/xml`'s `Decoder.Strict` to `true` (Go's safe-by-default
/// XML parser does not resolve external entities, but the brief
/// flags `Strict = false` as the XXE-prone shape, so explicit
/// `Strict = true` declarations are the canonical hardening marker).
fn parser_is_hardened(file_bytes: &[u8]) -> bool {
    const HARDENING_NEEDLES: &[&[u8]] = &[
        b"Strict: true",
        b"Strict:true",
        b".Strict = true",
        b".Strict=true",
    ];
    HARDENING_NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XxeGoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if parser_is_hardened(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_xml_parser);
        let matches_source = source_imports_xml(file_bytes);
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

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_xml_new_decoder() {
        let src: &[u8] = b"package main\nimport (\"bytes\"; \"encoding/xml\")\n\
            func Run(body string) {\n\
                d := xml.NewDecoder(bytes.NewReader([]byte(body)))\n\
                d.Strict = false\n\
                _ = d.Decode(&struct{}{})\n\
            }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("NewDecoder")],
            ..Default::default()
        };
        assert!(XxeGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"package main\nfunc Add(a, b int) int { return a + b }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Add".into(),
            ..Default::default()
        };
        assert!(XxeGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_decoder_strict_pinned_true() {
        let src: &[u8] = b"package main\nimport (\"bytes\"; \"encoding/xml\")\n\
            func Run(body string) {\n\
                d := xml.NewDecoder(bytes.NewReader([]byte(body)))\n\
                d.Strict = true\n\
                _ = d.Decode(&struct{}{})\n\
            }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("NewDecoder")],
            ..Default::default()
        };
        assert!(XxeGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

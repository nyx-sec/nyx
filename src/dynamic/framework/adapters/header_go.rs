//! Go [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions
//! (`http.ResponseWriter.Header().Set` / `Add`, Gin `c.Header`,
//! Echo `c.Response().Header().Set`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical Go HTTP response writers and the surrounding
//! source imports `net/http` or one of the supported frameworks.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderGoAdapter;

const ADAPTER_NAME: &str = "header-go";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "Set" | "Add" | "Header" | "WriteHeader")
}

fn source_imports_go_http(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"\"net/http\"",
        b"net/http\"",
        b"github.com/gin-gonic/gin",
        b"github.com/labstack/echo",
        b"github.com/gofiber/fiber",
        b"github.com/go-chi/chi",
        b".Header().Set",
        b".Header().Add",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderGoAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_header_setter);
        let matches_source = source_imports_go_http(file_bytes);
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
    fn fires_on_header_set() {
        let src: &[u8] =
            b"package x\nimport \"net/http\"\nfunc Run(w http.ResponseWriter, v string) { w.Header().Set(\"Set-Cookie\", v) }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Set")],
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"package x\nfunc Add(a, b int) int { return a + b }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Add".into(),
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

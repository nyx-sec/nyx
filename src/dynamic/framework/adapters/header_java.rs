//! Java [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions
//! (`HttpServletResponse.setHeader` / `addHeader`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical servlet response-writer entry points and the
//! surrounding source imports a servlet API.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderJavaAdapter;

const ADAPTER_NAME: &str = "header-java";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "setHeader" | "addHeader" | "setDateHeader" | "addDateHeader" | "setIntHeader" | "addIntHeader")
}

fn source_imports_servlet(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"javax.servlet",
        b"jakarta.servlet",
        b"HttpServletResponse",
        b"ServerHttpResponse",
        b"org.springframework.http",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderJavaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_header_setter);
        let matches_source = source_imports_servlet(file_bytes);
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_setheader() {
        let src: &[u8] = b"import javax.servlet.http.HttpServletResponse;\n\
            class C { void run(HttpServletResponse r, String v) { r.setHeader(\"Set-Cookie\", v); } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("setHeader")],
            ..Default::default()
        };
        assert!(HeaderJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"class C { int add(int a, int b) { return a + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(HeaderJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

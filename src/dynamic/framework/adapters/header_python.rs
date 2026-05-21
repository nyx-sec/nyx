//! Python [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions
//! (`flask.Response.headers.__setitem__`, Django `HttpResponse.__setitem__`,
//! Starlette `headers.append`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical Python web framework response writers and the
//! surrounding source imports the matching framework module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderPythonAdapter;

const ADAPTER_NAME: &str = "header-python";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "__setitem__" | "set_header" | "setdefault" | "add_header" | "append"
    ) || matches!(name, "Response.headers.__setitem__" | "make_response" | "Response.headers.add")
}

fn source_imports_python_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"from flask",
        b"import flask",
        b"from django.http",
        b"from starlette",
        b"from fastapi",
        b"response.headers",
        b"resp.headers",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// header value through a canonical URL-encoder / HTML-escaper.
fn value_routed_through_encoder(file_bytes: &[u8]) -> bool {
    const ENCODER_CALLS: &[&[u8]] = &[
        b"urllib.parse.quote(",
        b"parse.quote(",
        b"urllib.parse.quote_plus(",
        b"parse.quote_plus(",
        b"quote_plus(",
        b"werkzeug.urls.url_quote(",
        b"url_quote(",
        b"urlencode(",
        b"html.escape(",
        b"markupsafe.escape(",
        b"escape_html(",
    ];
    ENCODER_CALLS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderPythonAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if value_routed_through_encoder(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_header_setter);
        let matches_source = source_imports_python_web(file_bytes);
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_flask_header_assignment() {
        let src: &[u8] = b"from flask import make_response\n\
            def run(value):\n    resp = make_response('hi')\n    resp.headers['Set-Cookie'] = value\n    return resp\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("__setitem__")],
            ..Default::default()
        };
        assert!(HeaderPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(HeaderPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_value_url_encoded() {
        let src: &[u8] = b"from flask import make_response\n\
            from urllib.parse import quote\n\
            def run(value):\n    resp = make_response('hi')\n    \
                resp.headers['Set-Cookie'] = quote_plus(value)\n    return resp\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("__setitem__"),
                crate::summary::CalleeSite::bare("quote_plus"),
            ],
            ..Default::default()
        };
        assert!(HeaderPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

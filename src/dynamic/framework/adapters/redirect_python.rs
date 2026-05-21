//! Python [`super::super::FrameworkAdapter`] matching HTTP-redirect
//! sink constructions (`flask.redirect`, Django
//! `HttpResponseRedirect`, FastAPI `RedirectResponse`).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one
//! of the canonical Python web-framework redirect entry points and
//! the surrounding source imports the matching framework module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectPythonAdapter;

const ADAPTER_NAME: &str = "redirect-python";

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "redirect" | "HttpResponseRedirect" | "RedirectResponse"
    )
}

fn source_imports_python_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"from flask",
        b"import flask",
        b"from django.http",
        b"from django.shortcuts",
        b"from starlette",
        b"from fastapi.responses",
        b"from werkzeug",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// redirect URL through a canonical host-allowlist / URL-validator.
fn url_routed_through_validator(file_bytes: &[u8]) -> bool {
    const VALIDATOR_TOKENS: &[&[u8]] = &[
        b"is_safe_url(",
        b"url_has_allowed_host_and_scheme(",
        b"allowed_hosts",
        b"ALLOWED_HOSTS",
        b"ALLOWLIST",
        b"allowlist",
        b".netloc in ",
        b".netloc.in_",
        b"urlparse(",
        b"url_parse(",
    ];
    VALIDATOR_TOKENS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectPythonAdapter {
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
        if url_routed_through_validator(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
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
    fn fires_on_flask_redirect() {
        let src: &[u8] = b"from flask import redirect\n\
            def run(value):\n    return redirect(value)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("redirect")],
            ..Default::default()
        };
        assert!(RedirectPythonAdapter
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
        assert!(RedirectPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_url_validated_against_allowlist() {
        let src: &[u8] = b"from flask import redirect\n\
            from django.utils.http import url_has_allowed_host_and_scheme\n\
            def run(value):\n    \
                if not url_has_allowed_host_and_scheme(value, allowed_hosts={'example.com'}):\n        \
                    return None\n    return redirect(value)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("redirect"),
                crate::summary::CalleeSite::bare("url_has_allowed_host_and_scheme"),
            ],
            ..Default::default()
        };
        assert!(RedirectPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

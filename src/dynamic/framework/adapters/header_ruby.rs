//! Ruby [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions
//! (`Rack::Response#set_header`, Rails `response.headers[]=`,
//! Sinatra `response['Set-Cookie']=`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical Ruby web framework response writers and the
//! surrounding source imports / mentions Rack / Rails / Sinatra.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderRubyAdapter;

const ADAPTER_NAME: &str = "header-ruby";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('#').map(|(_, s)| s).unwrap_or(last);
    matches!(last, "set_header" | "[]=" | "store" | "add_header")
}

fn source_uses_ruby_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"Rack::Response",
        b"require 'rack'",
        b"require \"rack\"",
        b"require 'sinatra'",
        b"require \"sinatra\"",
        b"ActionController",
        b"response.headers",
        b"response[",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// header value through a canonical Ruby URL-encoder / HTML-escaper.
fn value_routed_through_encoder(file_bytes: &[u8]) -> bool {
    const ENCODER_CALLS: &[&[u8]] = &[
        b"URI.encode_www_form_component(",
        b"encode_www_form_component(",
        b"CGI.escape(",
        b"CGI.escapeHTML(",
        b"ERB::Util.url_encode(",
        b"ERB::Util.h(",
        b"Rack::Utils.escape(",
    ];
    ENCODER_CALLS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderRubyAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
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
        let matches_source = source_uses_ruby_web(file_bytes);
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_set_header() {
        let src: &[u8] = b"require 'rack'\n\
            def run(value)\n  response = Rack::Response.new\n  response.set_header('Set-Cookie', value)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("set_header")],
            ..Default::default()
        };
        assert!(HeaderRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b)\n  a + b\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(HeaderRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_value_url_encoded() {
        let src: &[u8] = b"require 'rack'\nrequire 'uri'\n\
            def run(value)\n  response = Rack::Response.new\n  \
                response.set_header('Set-Cookie', URI.encode_www_form_component(value))\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("set_header"),
                crate::summary::CalleeSite::bare("encode_www_form_component"),
            ],
            ..Default::default()
        };
        assert!(HeaderRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

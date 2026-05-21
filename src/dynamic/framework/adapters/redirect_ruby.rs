//! Ruby [`super::super::FrameworkAdapter`] matching HTTP-redirect
//! sink constructions (Rails `redirect_to`, Sinatra `redirect`,
//! `Rack::Response#redirect`).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one
//! of the canonical Ruby web-framework redirect entry points and
//! the surrounding source imports / references a recognised
//! framework module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectRubyAdapter;

const ADAPTER_NAME: &str = "redirect-ruby";

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "redirect" | "redirect_to" | "redirect!" )
}

fn source_imports_ruby_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"Rack::Response",
        b"require 'rack",
        b"require \"rack",
        b"require 'sinatra",
        b"require \"sinatra",
        b"ActionController",
        b"Rails",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// redirect URL through a canonical host-allowlist / URL-validator.
fn url_routed_through_validator(file_bytes: &[u8]) -> bool {
    const VALIDATOR_TOKENS: &[&[u8]] = &[
        b"URI.parse(",
        b"URI(",
        b"allowed_hosts",
        b"ALLOWED_HOSTS",
        b"allowlist",
        b"ALLOWLIST",
        b".host ==",
        b".host?(",
    ];
    VALIDATOR_TOKENS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectRubyAdapter {
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
        if url_routed_through_validator(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
        let matches_source = source_imports_ruby_web(file_bytes);
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
    fn fires_on_rack_redirect() {
        let src: &[u8] = b"require 'rack'\n\
            def run(value)\n  resp = Rack::Response.new\n  resp.redirect(value)\n  resp\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("redirect")],
            ..Default::default()
        };
        assert!(RedirectRubyAdapter
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
        assert!(RedirectRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_url_validated_against_allowlist() {
        let src: &[u8] = b"require 'rack'\nrequire 'uri'\n\
            def run(value)\n  allowed_hosts = ['example.com']\n  \
                host = URI.parse(value).host\n  \
                return unless allowed_hosts.include?(host)\n  \
                resp = Rack::Response.new\n  resp.redirect(value)\n  resp\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("redirect"),
                crate::summary::CalleeSite::bare("parse"),
            ],
            ..Default::default()
        };
        assert!(RedirectRubyAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

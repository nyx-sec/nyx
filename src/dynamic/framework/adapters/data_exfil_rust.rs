//! Rust [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`reqwest::get`, `reqwest::blocking::get`,
//! `reqwest::Client::*`, `hyper::Client::request`, `ureq::get`,
//! `surf::get`, `isahc::get`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Rust HTTP-client entry points and the surrounding
//! source imports the matching crate.
//!
//! See sibling adapters
//! [`super::data_exfil_python::DataExfilPythonAdapter`],
//! [`super::data_exfil_js::DataExfilJsAdapter`],
//! [`super::data_exfil_go::DataExfilGoAdapter`],
//! [`super::data_exfil_ruby::DataExfilRubyAdapter`],
//! [`super::data_exfil_java::DataExfilJavaAdapter`], and
//! [`super::data_exfil_php::DataExfilPhpAdapter`] for the same shape
//! on other languages.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilRustAdapter;

const ADAPTER_NAME: &str = "data-exfil-rust";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "get"
            | "post"
            | "put"
            | "patch"
            | "delete"
            | "head"
            | "send"
            | "send_async"
            | "execute"
            | "fetch"
            | "request"
            | "call"
    ) || matches!(
        name,
        "reqwest::get"
            | "reqwest::blocking::get"
            | "reqwest::Client::get"
            | "reqwest::Client::post"
            | "reqwest::Client::execute"
            | "reqwest::blocking::Client::get"
            | "reqwest::blocking::Client::post"
            | "reqwest::blocking::Client::execute"
            | "reqwest::RequestBuilder::send"
            | "reqwest::blocking::RequestBuilder::send"
            | "hyper::Client::request"
            | "hyper::Client::get"
            | "ureq::get"
            | "ureq::post"
            | "ureq::request"
            | "surf::get"
            | "surf::post"
            | "isahc::get"
            | "isahc::post"
            | "isahc::send"
    )
}

fn source_imports_rust_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"use reqwest",
        b"reqwest::",
        b"use hyper",
        b"hyper::Client",
        b"use ureq",
        b"ureq::",
        b"use surf",
        b"surf::",
        b"use isahc",
        b"isahc::",
        b"use awc",
        b"awc::Client",
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
        b"\"127.0.0.1\"",
        b"\"localhost\"",
        b".contains(host)",
        b".contains(&host)",
        b".contains(\"localhost\")",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilRustAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Rust
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
        let matches_source = source_imports_rust_http_client(file_bytes);
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

    fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_reqwest_blocking_get() {
        let src: &[u8] = b"use reqwest;\npub fn run(host: &str) -> Result<(), Box<dyn std::error::Error>> {\n    let url = format!(\"http://{}/exfil\", host);\n    let _ = reqwest::blocking::get(&url)?;\n    Ok(())\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("reqwest::blocking::get")],
            ..Default::default()
        };
        assert!(
            DataExfilRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_reqwest_client_post() {
        let src: &[u8] = b"use reqwest::Client;\npub async fn run(host: &str) -> Result<(), Box<dyn std::error::Error>> {\n    let c = Client::new();\n    let _ = c.post(format!(\"http://{}/exfil\", host)).send().await?;\n    Ok(())\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("reqwest::Client::post"),
                crate::summary::CalleeSite::bare("reqwest::RequestBuilder::send"),
            ],
            ..Default::default()
        };
        assert!(
            DataExfilRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_ureq_get() {
        let src: &[u8] = b"use ureq;\npub fn run(host: &str) -> Result<(), ureq::Error> {\n    let _ = ureq::get(&format!(\"http://{}/exfil\", host)).call()?;\n    Ok(())\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("ureq::get"),
                crate::summary::CalleeSite::bare("call"),
            ],
            ..Default::default()
        };
        assert!(
            DataExfilRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_in_allowlist_literal() {
        let src: &[u8] = b"use reqwest;\npub fn run(host: &str) -> Result<(), Box<dyn std::error::Error>> {\n    if host != \"127.0.0.1\" { return Ok(()); }\n    let _ = reqwest::blocking::get(format!(\"http://{}/\", host))?;\n    Ok(())\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("reqwest::blocking::get")],
            ..Default::default()
        };
        assert!(
            DataExfilRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"pub fn add(a: i64, b: i64) -> i64 { a + b }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

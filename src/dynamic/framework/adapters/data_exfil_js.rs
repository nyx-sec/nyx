//! JavaScript [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`http.request`, `https.request`, `fetch`,
//! `axios.{get,post,put}`, `node-fetch`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Node HTTP-client entry points and the
//! surrounding source imports the matching client module (or uses
//! the global `fetch` API).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilJsAdapter;

const ADAPTER_NAME: &str = "data-exfil-js";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "request" | "get" | "post" | "put" | "patch" | "delete" | "fetch" | "send"
    ) || matches!(
        name,
        "http.request"
            | "https.request"
            | "http.get"
            | "https.get"
            | "axios.get"
            | "axios.post"
            | "axios.put"
            | "axios.patch"
            | "axios.delete"
            | "axios.request"
            | "fetch"
    )
}

fn source_imports_js_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('http')",
        b"require(\"http\")",
        b"require('https')",
        b"require(\"https\")",
        b"require('axios')",
        b"require(\"axios\")",
        b"require('node-fetch')",
        b"require(\"node-fetch\")",
        b"from 'axios'",
        b"from \"axios\"",
        b"from 'node-fetch'",
        b"from \"node-fetch\"",
        b"from 'http'",
        b"from \"http\"",
        b"from 'https'",
        b"from \"https\"",
        b"fetch(",
        b"globalThis.fetch",
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
        b"allowedHosts",
        b"['127.0.0.1'",
        b"[\"127.0.0.1\"",
        b"Set(['127.0.0.1'",
        b"Set([\"127.0.0.1\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilJsAdapter {
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
        if host_routed_through_allowlist(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_outbound_http);
        let matches_source = source_imports_js_http_client(file_bytes);
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_http_request() {
        let src: &[u8] = b"const http = require('http');\nfunction run(host) { const req = http.request({ host, path: '/exfil', method: 'POST' }); req.end(); }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("http.request")],
            ..Default::default()
        };
        assert!(
            DataExfilJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_axios_post() {
        let src: &[u8] = b"const axios = require('axios');\nasync function run(host) { await axios.post(`http://${host}/exfil`, { token: 'x' }); }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("axios.post")],
            ..Default::default()
        };
        assert!(
            DataExfilJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_routed_through_allowlist() {
        let src: &[u8] = b"const http = require('http');\nconst ALLOWLIST = new Set(['127.0.0.1', 'localhost']);\nfunction run(host) { if (!ALLOWLIST.has(host)) return; const req = http.request({ host, path: '/exfil' }); req.end(); }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("http.request")],
            ..Default::default()
        };
        assert!(
            DataExfilJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\nmodule.exports = { add };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

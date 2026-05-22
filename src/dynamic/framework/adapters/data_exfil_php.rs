//! PHP [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`curl_init` / `curl_exec`, `file_get_contents`
//! against a remote URL, `fopen`/`fsockopen`/`stream_socket_client`,
//! Guzzle).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical PHP HTTP-client entry points and the surrounding
//! source carries the `<?php` script-tag opener (PHP files always
//! open with a literal `<?php` tag in production code, mirroring the
//! [`super::crypto_php::CryptoPhpAdapter`] source-signal pattern).
//!
//! See sibling adapters
//! [`super::data_exfil_python::DataExfilPythonAdapter`],
//! [`super::data_exfil_js::DataExfilJsAdapter`],
//! [`super::data_exfil_go::DataExfilGoAdapter`],
//! [`super::data_exfil_ruby::DataExfilRubyAdapter`], and
//! [`super::data_exfil_java::DataExfilJavaAdapter`] for the same
//! shape on other languages.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilPhpAdapter;

const ADAPTER_NAME: &str = "data-exfil-php";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once('\\').map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once("::").map(|(_, s)| s).unwrap_or(last);
    let last = last.rsplit_once("->").map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "curl_init"
            | "curl_exec"
            | "curl_setopt"
            | "curl_multi_exec"
            | "file_get_contents"
            | "fopen"
            | "fsockopen"
            | "stream_socket_client"
            | "stream_context_create"
            | "get"
            | "post"
            | "put"
            | "delete"
            | "request"
            | "sendRequest"
            | "send"
    ) || matches!(
        name,
        "curl_init"
            | "curl_exec"
            | "file_get_contents"
            | "fopen"
            | "fsockopen"
            | "stream_socket_client"
            | "GuzzleHttp\\Client.get"
            | "GuzzleHttp\\Client.post"
            | "GuzzleHttp\\Client.request"
            | "GuzzleHttp\\Client.send"
            | "Symfony\\Component\\HttpClient\\HttpClient.create"
            | "Symfony\\Contracts\\HttpClient\\HttpClientInterface.request"
    )
}

fn source_imports_php_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"<?php",
        b"<?=",
        b"GuzzleHttp\\Client",
        b"GuzzleHttp\\Psr7",
        b"Symfony\\Component\\HttpClient",
        b"Symfony\\Contracts\\HttpClient",
        b"curl_init(",
        b"curl_exec(",
        b"file_get_contents(",
        b"fsockopen(",
        b"stream_socket_client(",
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
        b"in_array($host",
        b"isset($allow",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilPhpAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
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
        let matches_source = source_imports_php_http_client(file_bytes);
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_curl_init_exec() {
        let src: &[u8] = b"<?php\nfunction run($host) {\n    $ch = curl_init('http://' . $host . '/exfil');\n    curl_exec($ch);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("curl_init"),
                crate::summary::CalleeSite::bare("curl_exec"),
            ],
            ..Default::default()
        };
        assert!(
            DataExfilPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_file_get_contents_remote() {
        let src: &[u8] = b"<?php\nfunction run($host) {\n    return file_get_contents('http://' . $host . '/exfil');\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("file_get_contents")],
            ..Default::default()
        };
        assert!(
            DataExfilPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_guzzle_request() {
        let src: &[u8] = b"<?php\nuse GuzzleHttp\\Client;\nfunction run($host) {\n    $c = new Client();\n    $c->request('GET', 'http://' . $host);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("request")],
            ..Default::default()
        };
        assert!(
            DataExfilPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_in_allowlist_literal() {
        let src: &[u8] = b"<?php\nfunction run($host) {\n    if ($host !== '127.0.0.1') { return; }\n    $ch = curl_init('http://' . $host);\n    curl_exec($ch);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("curl_init")],
            ..Default::default()
        };
        assert!(
            DataExfilPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

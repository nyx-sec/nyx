//! Go [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`http.Get`, `http.Post`, `http.NewRequest`,
//! `http.DefaultClient.Do`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Go HTTP-client entry points and the
//! surrounding source imports `net/http`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilGoAdapter;

const ADAPTER_NAME: &str = "data-exfil-go";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "Get" | "Post" | "PostForm" | "Head" | "Do" | "NewRequest" | "NewRequestWithContext"
    ) || matches!(
        name,
        "http.Get"
            | "http.Post"
            | "http.PostForm"
            | "http.Head"
            | "http.NewRequest"
            | "http.NewRequestWithContext"
            | "http.DefaultClient.Do"
            | "http.Client.Do"
    )
}

fn source_imports_go_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"\"net/http\"",
        b"net/http\"",
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
        b"AllowedHosts",
        b"allowedHosts",
        b"\"127.0.0.1\"",
        b"\"localhost\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilGoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
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
        let matches_source = source_imports_go_http_client(file_bytes);
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

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_http_get() {
        let src: &[u8] = b"package vuln\nimport \"net/http\"\nfunc Run(host string) {\n    http.Get(\"http://\" + host + \"/exfil\")\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("http.Get")],
            ..Default::default()
        };
        assert!(
            DataExfilGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_http_post() {
        let src: &[u8] = b"package vuln\nimport (\n    \"net/http\"\n    \"strings\"\n)\nfunc Run(host string) {\n    http.Post(\"http://\" + host + \"/exfil\", \"application/json\", strings.NewReader(\"{}\"))\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("http.Post")],
            ..Default::default()
        };
        assert!(
            DataExfilGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_in_allowlist_literal() {
        let src: &[u8] = b"package vuln\nimport \"net/http\"\nfunc Run(host string) {\n    if host != \"127.0.0.1\" { return }\n    http.Get(\"http://\" + host + \"/exfil\")\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("http.Get")],
            ..Default::default()
        };
        assert!(
            DataExfilGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"package vuln\nfunc Add(a, b int) int { return a + b }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

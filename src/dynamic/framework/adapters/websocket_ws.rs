//! Phase 21 (Track M.3) — `ws` (Node WebSocket) adapter.
//!
//! Fires when the surrounding source requires/imports the `ws` package
//! and the function body is the `on('message', ...)` listener on a
//! `WebSocket.Server` / `WebSocketServer` instance.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct WebsocketWsAdapter;

const ADAPTER_NAME: &str = "websocket-ws";

fn callee_is_ws(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "WebSocket" | "WebSocketServer" | "Server" | "on" | "send"
    )
}

fn source_imports_ws(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('ws')",
        b"require(\"ws\")",
        b"from 'ws'",
        b"from \"ws\"",
        b"new WebSocketServer",
        b"new WebSocket.Server",
        b"WebSocket.Server",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_path(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["path: '", "path: \"", "path:'", "path:\""] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close = if needle.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = after.find(close) {
                return after[..end].to_owned();
            }
        }
    }
    "/".to_owned()
}

impl FrameworkAdapter for WebsocketWsAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_ws);
        let matches_source = source_imports_ws(file_bytes);
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::WebSocket {
                    path: extract_path(file_bytes),
                },
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
    fn fires_on_ws_server() {
        let src: &[u8] = b"const { WebSocketServer } = require('ws');\n\
            const wss = new WebSocketServer({ port: 0, path: '/feed' });\n\
            function onMessage(data) { }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "onMessage".into(),
            ..Default::default()
        };
        let binding = WebsocketWsAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("ws binds");
        assert_eq!(binding.adapter, "websocket-ws");
        if let EntryKind::WebSocket { path } = binding.kind {
            assert_eq!(path, "/feed");
        }
    }
}

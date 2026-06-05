//! Phase 21 (Track M.3) — `ws` (Node WebSocket) adapter.
//!
//! Fires when the surrounding source requires/imports the `ws` package
//! and the function body is the `on('message', ...)` listener on a
//! `WebSocket.Server` / `WebSocketServer` instance.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
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

fn name_registered_as_ws_message_handler(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for site in [
        ".on('message'",
        ".on(\"message\"",
        "on('message'",
        "on(\"message\"",
    ] {
        let mut cursor = 0;
        while let Some(idx) = text[cursor..].find(site) {
            let start = cursor + idx + site.len();
            let rest = &text[start..];
            let end = rest
                .find(['\n', ';'])
                .map(|n| start + n)
                .unwrap_or_else(|| text.len());
            let chunk = &text[start..end];
            if chunk
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '$')
                .any(|part| part == name)
            {
                return true;
            }
            cursor = end.min(text.len());
        }
    }
    false
}

fn typed_container_allows_ws(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("websocket") || lc == "ws" || lc == "wss"
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_ws(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_ws(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_ws(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_ws(file_bytes) {
        return None;
    }
    let registered = name_registered_as_ws_message_handler(&summary.name, file_bytes);
    let ws_call = super::any_callee_matches(summary, callee_is_ws)
        && super::typed_receiver_facts_allow(
            summary,
            ssa_summary,
            callee_is_ws,
            typed_container_allows_ws,
        );
    if !(registered || ws_call) {
        return None;
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

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
            function onMessage(data) { }\n\
            wss.on('connection', (socket) => socket.on('message', onMessage));\n";
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

    #[test]
    fn skips_unregistered_helper_in_ws_file() {
        let src: &[u8] = b"const { WebSocketServer } = require('ws');\n\
            const wss = new WebSocketServer({ port: 0, path: '/feed' });\n\
            function onMessage(data) { }\n\
            function formatMessage(data) { return String(data); }\n\
            wss.on('connection', (socket) => socket.on('message', onMessage));\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "formatMessage".into(),
            ..Default::default()
        };
        assert!(
            WebsocketWsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "ws import plus a message registration must not bind unrelated helpers",
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_non_ws_send_call() {
        let src: &[u8] = b"const { WebSocketServer } = require('ws');\n\
            function helper(data) { bus.send(data); }\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "bus.send".to_owned(),
            receiver: Some("bus".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let ssa = SsaFuncSummary {
            typed_call_receivers: vec![(0, "MessageBus".to_owned())],
            ..Default::default()
        };
        assert!(
            WebsocketWsAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_ws_send_call() {
        let src: &[u8] = b"const { WebSocketServer } = require('ws');\n\
            function helper(data) { socket.send(data); }\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "socket.send".to_owned(),
            receiver: Some("socket".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let ssa = SsaFuncSummary {
            typed_call_receivers: vec![(0, "WebSocket".to_owned())],
            ..Default::default()
        };
        assert!(
            WebsocketWsAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

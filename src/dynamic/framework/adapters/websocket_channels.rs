//! Phase 21 (Track M.3) — Django Channels WebSocket adapter (Python).
//!
//! Fires when the surrounding source imports Django Channels
//! (`channels.generic.websocket`, `AsyncWebsocketConsumer`) and the
//! function body sits inside a `WebsocketConsumer` subclass.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct WebsocketChannelsAdapter;

const ADAPTER_NAME: &str = "websocket-channels";

fn source_imports_channels(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"channels.generic.websocket",
        b"WebsocketConsumer",
        b"AsyncWebsocketConsumer",
        b"JsonWebsocketConsumer",
        b"AsyncJsonWebsocketConsumer",
        b"from channels",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_path(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["re_path(r'", "re_path('", "path('", "path(\""] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close: &[char] = &['\'', '"'];
            if let Some(end) = after.find(|c: char| close.contains(&c)) {
                return after[..end].to_owned();
            }
        }
    }
    "/ws/".to_owned()
}

fn name_is_channels_entry(name: &str) -> bool {
    matches!(
        name,
        "receive" | "receive_json" | "connect" | "disconnect" | "websocket_receive"
    )
}

impl FrameworkAdapter for WebsocketChannelsAdapter {
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
        if source_imports_channels(file_bytes) && name_is_channels_entry(&summary.name) {
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_channels_consumer() {
        let src: &[u8] = b"from channels.generic.websocket import WebsocketConsumer\n\
            class ChatConsumer(WebsocketConsumer):\n    def receive(self, text_data=None, bytes_data=None):\n        pass\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "receive".into(),
            ..Default::default()
        };
        let binding = WebsocketChannelsAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("channels binds");
        assert_eq!(binding.adapter, "websocket-channels");
        assert!(matches!(binding.kind, EntryKind::WebSocket { .. }));
    }

    #[test]
    fn skips_unrelated_helper_in_channels_file() {
        let src: &[u8] = b"from channels.generic.websocket import WebsocketConsumer\n\
            class ChatConsumer(WebsocketConsumer):\n    def receive(self, text_data=None):\n        pass\n\
            def normalize_frame(text_data):\n    return str(text_data)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "normalize_frame".into(),
            ..Default::default()
        };
        assert!(
            WebsocketChannelsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

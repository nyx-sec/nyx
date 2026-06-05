//! Phase 21 (Track M.3) — Rails ActionCable WebSocket adapter (Ruby).
//!
//! Fires when the surrounding source declares an `ApplicationCable` /
//! `ActionCable::Channel::Base` subclass and the function body sits on
//! a `receive` / `subscribed` / `unsubscribed` callback.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct WebsocketActionCableAdapter;

const ADAPTER_NAME: &str = "websocket-actioncable";

fn source_imports_actioncable(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"ApplicationCable::Channel",
        b"ActionCable::Channel::Base",
        b"< ApplicationCable",
        b"< ActionCable::Channel",
        b"require 'action_cable'",
        b"require \"action_cable\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_path(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [
        "stream_from '",
        "stream_from \"",
        "stream_for '",
        "stream_for \"",
    ] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close = if needle.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = after.find(close) {
                return after[..end].to_owned();
            }
        }
    }
    "/cable".to_owned()
}

fn name_is_actioncable_entry(name: &str) -> bool {
    matches!(name, "receive" | "subscribed" | "unsubscribed")
}

impl FrameworkAdapter for WebsocketActionCableAdapter {
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
        if source_imports_actioncable(file_bytes) && name_is_actioncable_entry(&summary.name) {
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_actioncable_channel() {
        let src: &[u8] = b"class ChatChannel < ApplicationCable::Channel\n  def subscribed\n    stream_from 'chat_room'\n  end\n  def receive(data)\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "receive".into(),
            ..Default::default()
        };
        let binding = WebsocketActionCableAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("action_cable binds");
        assert_eq!(binding.adapter, "websocket-actioncable");
        if let EntryKind::WebSocket { path } = binding.kind {
            assert_eq!(path, "chat_room");
        }
    }

    #[test]
    fn skips_unrelated_helper_in_actioncable_file() {
        let src: &[u8] = b"class ChatChannel < ApplicationCable::Channel\n  def receive(data)\n  end\n  def normalize(data)\n    data.to_s\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "normalize".into(),
            ..Default::default()
        };
        assert!(
            WebsocketActionCableAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

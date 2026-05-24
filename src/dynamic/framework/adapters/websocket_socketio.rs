//! Phase 21 (Track M.3) — Socket.IO WebSocket adapter (Python).
//!
//! Fires when the surrounding source imports `python-socketio` /
//! `socketio` and the function body is registered against an `on(...)`
//! event name.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct WebsocketSocketIoAdapter;

const ADAPTER_NAME: &str = "websocket-socketio";

fn source_imports_socketio(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"import socketio",
        b"from socketio",
        b"socketio.Server",
        b"socketio.AsyncServer",
        b"@sio.event",
        b"@sio.on(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_path(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["sio.on('", "sio.on(\"", "@sio.on('", "@sio.on(\""] {
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

fn name_registered_as_socketio_event(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let def_needle = format!("def {name}(");
    let Some(def_idx) = text.find(&def_needle) else {
        return false;
    };
    let before = &text[..def_idx];
    let since_prev_def = before
        .rfind("\ndef ")
        .map(|idx| &before[idx + 1..])
        .unwrap_or(before);
    since_prev_def.contains("@sio.event")
        || since_prev_def.contains("@socketio.event")
        || since_prev_def.contains(&format!("@sio.on('{name}'"))
        || since_prev_def.contains(&format!("@sio.on(\"{name}\""))
}

impl FrameworkAdapter for WebsocketSocketIoAdapter {
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
        let registered = name_registered_as_socketio_event(&summary.name, file_bytes);
        if source_imports_socketio(file_bytes) && registered {
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
    fn fires_on_socketio_event() {
        let src: &[u8] = b"import socketio\n\
            sio = socketio.Server()\n\
            @sio.on('message')\n\
            def message(sid, data):\n    pass\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "message".into(),
            ..Default::default()
        };
        let binding = WebsocketSocketIoAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("socketio binds");
        assert_eq!(binding.adapter, "websocket-socketio");
        if let EntryKind::WebSocket { path } = binding.kind {
            assert_eq!(path, "message");
        }
    }

    #[test]
    fn skips_unrelated_helper_in_socketio_file() {
        let src: &[u8] = b"import socketio\n\
            sio = socketio.Server()\n\
            @sio.on('message')\n\
            def message(sid, data):\n    pass\n\
            def normalize(data):\n    return str(data)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "normalize".into(),
            ..Default::default()
        };
        assert!(
            WebsocketSocketIoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

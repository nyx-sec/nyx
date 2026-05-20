//! Phase 20 (Track M.2) — Python RabbitMQ consumer adapter
//! (`pika.BlockingConnection`, `aio-pika`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RabbitPythonAdapter;

const ADAPTER_NAME: &str = "rabbit-python";

fn callee_is_rabbit(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "basic_consume" | "basic_get" | "handle" | "on_message" | "process"
    )
}

fn source_imports_rabbit(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"import pika",
        b"from pika",
        b"import aio_pika",
        b"from aio_pika",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_queue(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["queue=\"", "queue='", "queue_declare(\"", "queue_declare('"] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close = if needle.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = after.find(close) {
                return after[..end].to_owned();
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for RabbitPythonAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_rabbit);
        let matches_source = source_imports_rabbit(file_bytes);
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::MessageHandler {
                    queue: extract_queue(file_bytes),
                    message_schema: None,
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
    fn fires_on_pika_basic_consume() {
        let src: &[u8] = b"import pika\n\
            def on_message(ch, method, properties, body):\n    pass\n\
            chan = pika.BlockingConnection().channel()\n\
            chan.basic_consume(queue=\"work\", on_message_callback=on_message)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "on_message".into(),
            ..Default::default()
        };
        let binding = RabbitPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("pika binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "work");
        }
    }
}

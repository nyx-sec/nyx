//! Phase 20 (Track M.2) — Python Kafka consumer adapter.
//!
//! Fires when the surrounding source imports the canonical Python
//! Kafka clients (`kafka-python` or `confluent-kafka`) and the function
//! body invokes a consumer-shaped callee.  The binding's
//! [`EntryKind::MessageHandler`] is stamped with a best-effort `queue`
//! extracted from the source (a `KafkaConsumer('topic', ...)` /
//! `Consumer({"group.id": ..., "topics": ["t"]}).subscribe([...])`
//! literal); a missing topic falls back to the empty string.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct KafkaPythonAdapter;

const ADAPTER_NAME: &str = "kafka-python";

fn callee_is_kafka_consumer(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "KafkaConsumer" | "Consumer" | "subscribe" | "poll" | "consume" | "process_message"
    )
}

fn source_imports_kafka(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"from kafka",
        b"import kafka",
        b"from confluent_kafka",
        b"import confluent_kafka",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_topic_literal(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["KafkaConsumer(", ".subscribe(", "topic="] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            for (open, close) in [('"', '"'), ('\'', '\'')] {
                if let Some(o) = after.find(open) {
                    let rest = &after[o + 1..];
                    if let Some(c) = rest.find(close) {
                        return rest[..c].to_owned();
                    }
                }
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for KafkaPythonAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_kafka_consumer);
        let matches_source = source_imports_kafka(file_bytes);
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::MessageHandler {
                    queue: extract_topic_literal(file_bytes),
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
    fn fires_on_kafka_python_consumer() {
        let src: &[u8] = b"from kafka import KafkaConsumer\n\n\
            def handler(msg):\n    print(msg)\n\n\
            consumer = KafkaConsumer('orders', bootstrap_servers='broker:9092')\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        let binding = KafkaPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("kafka import binds");
        assert_eq!(binding.adapter, "kafka-python");
        assert!(matches!(binding.kind, EntryKind::MessageHandler { .. }));
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "orders");
        }
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
            KafkaPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

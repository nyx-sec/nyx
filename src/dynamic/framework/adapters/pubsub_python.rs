//! Phase 20 (Track M.2) — Python Google Pub/Sub subscriber adapter.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct PubsubPythonAdapter;

const ADAPTER_NAME: &str = "pubsub-python";

fn callee_is_pubsub(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "subscribe" | "pull" | "callback" | "process_message")
}

fn source_imports_pubsub(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"google.cloud.pubsub",
        b"from google.cloud import pubsub",
        b"google.cloud.pubsub_v1",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_topic(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    // Needles include the opening quote so we only need to find the
    // closing one — avoids picking up the next literal after a comma.
    for (needle, close) in [
        (".subscribe(\"", '"'),
        (".subscribe('", '\''),
        ("subscription_path(\"", '"'),
        ("subscription_path('", '\''),
    ] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find(close) {
                return after[..end].to_owned();
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for PubsubPythonAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_pubsub);
        let matches_source = source_imports_pubsub(file_bytes);
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::MessageHandler {
                    queue: extract_topic(file_bytes),
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
    fn fires_on_pubsub_v1_subscribe() {
        let src: &[u8] = b"from google.cloud import pubsub_v1\n\
            def callback(message):\n    pass\n\
            sub = pubsub_v1.SubscriberClient()\n\
            sub.subscribe(\"projects/p/subscriptions/s\", callback=callback)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "callback".into(),
            ..Default::default()
        };
        let binding = PubsubPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("pubsub_v1 binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "projects/p/subscriptions/s");
        }
    }
}

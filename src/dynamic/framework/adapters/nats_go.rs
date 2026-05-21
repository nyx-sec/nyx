//! Phase 20 (Track M.2) — Go NATS subscriber adapter (`nats.go`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct NatsGoAdapter;

const ADAPTER_NAME: &str = "nats-go";

fn callee_is_nats(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "Subscribe" | "QueueSubscribe" | "Publish" | "HandleMessage" | "OnMessage"
    )
}

fn source_imports_nats(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[b"github.com/nats-io/nats.go", b"nats.Connect", b"nats.Msg"];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_subject(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [".Subscribe(\"", ".QueueSubscribe(\""] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find('"') {
                return after[..end].to_owned();
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for NatsGoAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_nats);
        let matches_source = source_imports_nats(file_bytes);
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::MessageHandler {
                    queue: extract_subject(file_bytes),
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

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_nats_subscribe() {
        let src: &[u8] = b"package entry\nimport \"github.com/nats-io/nats.go\"\n\
            func OnMessage(msg *nats.Msg) {}\n\
            var nc = nats.Connect()\n\
            var sub, _ = nc.Subscribe(\"events\", OnMessage)\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "OnMessage".into(),
            ..Default::default()
        };
        let binding = NatsGoAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("nats.Subscribe binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "events");
        }
    }
}

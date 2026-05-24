//! Phase 20 (Track M.2) — Go Google Pub/Sub subscriber adapter
//! (`cloud.google.com/go/pubsub`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct PubsubGoAdapter;

const ADAPTER_NAME: &str = "pubsub-go";

fn callee_is_pubsub(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "Receive" | "Subscription" | "Pull" | "Handle" | "OnMessage"
    )
}

fn source_imports_pubsub(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"cloud.google.com/go/pubsub",
        b"pubsub.NewClient",
        b"pubsub.Message",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_topic(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [".Subscription(\"", "SubscriptionID(\"", "TopicID(\""] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find('"') {
                return after[..end].to_owned();
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for PubsubGoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_pubsub_go(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_pubsub_go(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_pubsub_go(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    let matches_call = super::any_callee_matches(summary, callee_is_pubsub);
    let matches_source = source_imports_pubsub(file_bytes);
    if !(matches_call || matches_source) {
        return None;
    }
    if !super::typed_receiver_facts_allow(
        summary,
        ssa_summary,
        callee_is_pubsub,
        typed_container_allows_pubsub,
    ) {
        return None;
    }
    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::MessageHandler {
            queue: extract_topic(file_bytes),
            message_schema: None,
        },
        route: None,
        request_params: Vec::new(),
        response_writer: None,
        middleware: super::collect_message_middleware(Lang::Go, ast, file_bytes),
    })
}

fn typed_container_allows_pubsub(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("pubsub") || lc.contains("subscription") || lc.contains("subscriber")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_pubsub_subscription() {
        let src: &[u8] = b"package entry\nimport \"cloud.google.com/go/pubsub\"\n\
            func Handle(msg *pubsub.Message) {}\n\
            var sub = pubsub.NewClient.Subscription(\"my-sub\")\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Handle".into(),
            ..Default::default()
        };
        let binding = PubsubGoAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("pubsub.Subscription binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "my-sub");
        }
    }

    #[test]
    fn ssa_receiver_type_rejects_non_pubsub_receive_collision() {
        let src: &[u8] = b"package entry\nimport \"cloud.google.com/go/pubsub\"\n\
            func Handle(msg *pubsub.Message) { inbox.Receive() }\n";
        let tree = parse_go(src);
        let mut summary = FuncSummary {
            name: "Handle".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "inbox.Receive".to_owned(),
            receiver: Some("inbox".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Inbox".to_owned()));
        assert!(
            PubsubGoAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_pubsub_subscription() {
        let src: &[u8] = b"package entry\nimport \"cloud.google.com/go/pubsub\"\n\
            func Handle(msg *pubsub.Message) { sub.Receive(ctx, cb) }\n";
        let tree = parse_go(src);
        let mut summary = FuncSummary {
            name: "Handle".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "sub.Receive".to_owned(),
            receiver: Some("sub".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((0, "pubsub.Subscription".to_owned()));
        assert!(
            PubsubGoAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

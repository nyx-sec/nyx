//! Phase 20 (Track M.2) — Node SQS consumer adapter (`@aws-sdk/client-sqs`,
//! `aws-sdk`, `sqs-consumer`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct SqsNodeAdapter;

const ADAPTER_NAME: &str = "sqs-node";

fn callee_is_sqs(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "receiveMessage" | "deleteMessage" | "handleMessage" | "send" | "Consumer"
    )
}

fn source_imports_sqs(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"@aws-sdk/client-sqs",
        b"aws-sdk/clients/sqs",
        b"require('sqs-consumer')",
        b"require(\"sqs-consumer\")",
        b"from 'sqs-consumer'",
        b"from \"sqs-consumer\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_queue(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["QueueUrl: \"", "QueueUrl: '", "queueUrl: \"", "queueUrl: '"] {
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

impl FrameworkAdapter for SqsNodeAdapter {
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
        detect_sqs_node(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_sqs_node(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_sqs_node(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    let matches_call = super::any_callee_matches(summary, callee_is_sqs);
    let matches_source = source_imports_sqs(file_bytes);
    if !(matches_call || matches_source) {
        return None;
    }
    if !sqs_receiver_facts_allow(summary, ssa_summary) {
        return None;
    }
    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::MessageHandler {
            queue: extract_queue(file_bytes),
            message_schema: None,
        },
        route: None,
        request_params: Vec::new(),
        response_writer: None,
        middleware: super::collect_message_middleware(Lang::JavaScript, ast, file_bytes),
    })
}

fn sqs_receiver_facts_allow(summary: &FuncSummary, ssa_summary: Option<&SsaFuncSummary>) -> bool {
    let Some(ssa_summary) = ssa_summary else {
        return true;
    };
    for site in &summary.callees {
        if !callee_is_sqs(&site.name) || site.receiver.is_none() {
            continue;
        }
        let Some(container) = ssa_summary
            .typed_call_receivers
            .iter()
            .find(|(ord, _)| *ord == site.ordinal)
            .map(|(_, container)| container.as_str())
        else {
            continue;
        };
        if !typed_container_allows_sqs(container) {
            return false;
        }
    }
    true
}

fn typed_container_allows_sqs(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("sqs") || lc.contains("queue") || lc == "consumer"
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
    fn fires_on_sqs_consumer() {
        let src: &[u8] = b"const { Consumer } = require('sqs-consumer');\n\
            module.exports.handler = function(env) {};\n\
            const c = Consumer.create({ queueUrl: 'http://localhost/q', handleMessage: handler });\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        let binding = SqsNodeAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("sqs-consumer binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "http://localhost/q");
        }
    }

    #[test]
    fn ssa_receiver_type_rejects_non_sqs_send_collision() {
        let src: &[u8] = b"const { SQSClient } = require('@aws-sdk/client-sqs');\n\
            function handler(env) {}\n\
            Promise.resolve().send(handler);\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "promise.send".to_owned(),
            receiver: Some("promise".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Promise".to_owned()));
        assert!(
            SqsNodeAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_sqs_client_send() {
        let src: &[u8] = b"const { SQSClient } = require('@aws-sdk/client-sqs');\n\
            function handler(env) {}\n\
            client.send(handler);\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "client.send".to_owned(),
            receiver: Some("client".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "SQSClient".to_owned()));
        assert!(
            SqsNodeAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

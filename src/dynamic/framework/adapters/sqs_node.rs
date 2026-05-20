//! Phase 20 (Track M.2) — Node SQS consumer adapter (`@aws-sdk/client-sqs`,
//! `aws-sdk`, `sqs-consumer`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_sqs);
        let matches_source = source_imports_sqs(file_bytes);
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
}

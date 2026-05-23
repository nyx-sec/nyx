//! Phase 20 (Track M.2) — Python SQS consumer adapter.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct SqsPythonAdapter;

const ADAPTER_NAME: &str = "sqs-python";

fn callee_is_sqs(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "receive_message" | "delete_message" | "process_message" | "handler"
    )
}

fn source_imports_sqs(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"boto3.client('sqs'",
        b"boto3.client(\"sqs\"",
        b"boto3.resource('sqs'",
        b"boto3.resource(\"sqs\"",
        b"@sqs_listener",
        b"from aws_lambda_powertools.utilities.batch import sqs_batch_processor",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_queue(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["QueueUrl=\"", "QueueUrl='", "QueueName=\"", "QueueName='"] {
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

impl FrameworkAdapter for SqsPythonAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_sqs_python(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_sqs_python(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_sqs_python(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    let matches_call = super::any_callee_matches(summary, callee_is_sqs);
    let matches_source = source_imports_sqs(file_bytes);
    if !(matches_call || matches_source) {
        return None;
    }
    if !super::typed_receiver_facts_allow(
        summary,
        ssa_summary,
        callee_is_sqs,
        typed_container_allows_sqs,
    ) {
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
        middleware: Vec::new(),
    })
}

fn typed_container_allows_sqs(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("sqs") || lc.contains("queue")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_boto3_sqs_receive() {
        let src: &[u8] = b"import boto3\n\
            sqs = boto3.client('sqs')\n\
            def handler(envelope):\n    pass\n\
            sqs.receive_message(QueueUrl=\"jobs\")\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        let binding = SqsPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("boto3 sqs binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "jobs");
        }
    }

    #[test]
    fn ssa_receiver_type_rejects_non_sqs_process_collision() {
        let src: &[u8] = b"import boto3\n\
            boto3.client('sqs')\n\
            def handler(envelope):\n    cache.process_message(envelope)\n";
        let tree = parse_python(src);
        let mut summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "cache.process_message".to_owned(),
            receiver: Some("cache".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Cache".to_owned()));
        assert!(
            SqsPythonAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_sqs_queue_receiver() {
        let src: &[u8] = b"import boto3\n\
            def handler(envelope):\n    queue.process_message(envelope)\n";
        let tree = parse_python(src);
        let mut summary = FuncSummary {
            name: "handler".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "queue.process_message".to_owned(),
            receiver: Some("queue".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((0, "SqsQueueClient".to_owned()));
        assert!(
            SqsPythonAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

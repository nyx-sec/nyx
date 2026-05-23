//! Phase 20 (Track M.2) — Java SQS consumer adapter.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct SqsJavaAdapter;

const ADAPTER_NAME: &str = "sqs-java";

fn callee_is_sqs(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "receiveMessage" | "deleteMessage" | "onMessage" | "handleMessage"
    )
}

fn source_imports_sqs(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"software.amazon.awssdk.services.sqs",
        b"com.amazonaws.services.sqs",
        b"@SqsListener",
        b"io.awspring.cloud.sqs",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_queue(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["@SqsListener(\"", "queueUrl(\"", "queueName(\""] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find('"') {
                return after[..end].to_owned();
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for SqsJavaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_sqs_java(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_sqs_java(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_sqs_java(
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_sqs_listener_annotation() {
        let src: &[u8] = b"import io.awspring.cloud.sqs.annotation.SqsListener;\n\
            public class Vuln {\n\
              @SqsListener(\"jobs\")\n\
              public void handleMessage(java.util.Map<String,String> env) {}\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "handleMessage".into(),
            ..Default::default()
        };
        let binding = SqsJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("@SqsListener binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "jobs");
        }
    }

    #[test]
    fn ssa_receiver_type_rejects_non_sqs_handle_collision() {
        let src: &[u8] = b"import io.awspring.cloud.sqs.annotation.SqsListener;\n\
            public class Vuln {\n\
              public void handleMessage(String env) { worker.handleMessage(env); }\n\
            }\n";
        let tree = parse_java(src);
        let mut summary = FuncSummary {
            name: "handleMessage".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "worker.handleMessage".to_owned(),
            receiver: Some("worker".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Worker".to_owned()));
        assert!(
            SqsJavaAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_sqs_client() {
        let src: &[u8] = b"import software.amazon.awssdk.services.sqs.SqsClient;\n\
            public class Vuln {\n\
              public void handleMessage(String env) { client.receiveMessage(); }\n\
            }\n";
        let tree = parse_java(src);
        let mut summary = FuncSummary {
            name: "handleMessage".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "client.receiveMessage".to_owned(),
            receiver: Some("client".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "SqsClient".to_owned()));
        assert!(
            SqsJavaAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

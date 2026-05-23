//! Phase 20 (Track M.2) — Java Kafka consumer adapter.
//!
//! Fires on Spring Kafka `@KafkaListener` annotations or
//! `org.apache.kafka.clients.consumer.KafkaConsumer` references.  Best-
//! effort topic extraction reads the literal that follows `topics =
//! "..."` / `topics = {"..."}` / `subscribe(Arrays.asList("..."))`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct KafkaJavaAdapter;

const ADAPTER_NAME: &str = "kafka-java";

fn callee_is_kafka(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "KafkaConsumer" | "subscribe" | "poll" | "onMessage" | "consume"
    )
}

fn source_imports_kafka(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"org.apache.kafka",
        b"org.springframework.kafka",
        b"@KafkaListener",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_topic(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [
        "topics = \"",
        "topics=\"",
        "topics = {\"",
        "subscribe(Arrays.asList(\"",
    ] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find('"') {
                return after[..end].to_owned();
            }
        }
    }
    String::new()
}

impl FrameworkAdapter for KafkaJavaAdapter {
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
        detect_kafka_java(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_kafka_java(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_kafka_java(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    let matches_call = super::any_callee_matches(summary, callee_is_kafka);
    let matches_source = source_imports_kafka(file_bytes);
    if !(matches_call || matches_source) {
        return None;
    }
    if !super::typed_receiver_facts_allow(
        summary,
        ssa_summary,
        callee_is_kafka,
        typed_container_allows_kafka,
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
        middleware: Vec::new(),
    })
}

fn typed_container_allows_kafka(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("kafka") || lc.contains("consumer")
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
    fn fires_on_spring_kafka_listener() {
        let src: &[u8] = b"import org.springframework.kafka.annotation.KafkaListener;\n\
            public class Vuln {\n\
              @KafkaListener(topics = \"orders\")\n\
              public void onMessage(String body) {}\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "onMessage".into(),
            ..Default::default()
        };
        let binding = KafkaJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("@KafkaListener binds");
        assert!(matches!(binding.kind, EntryKind::MessageHandler { .. }));
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "orders");
        }
    }

    #[test]
    fn ssa_receiver_type_rejects_non_kafka_poll_collision() {
        let src: &[u8] = b"import org.springframework.kafka.annotation.KafkaListener;\n\
            public class Vuln {\n\
              public void onMessage(String body) { timer.poll(); }\n\
            }\n";
        let tree = parse_java(src);
        let mut summary = FuncSummary {
            name: "onMessage".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "timer.poll".to_owned(),
            receiver: Some("timer".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Timer".to_owned()));
        assert!(
            KafkaJavaAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_kafka_consumer() {
        let src: &[u8] = b"import org.apache.kafka.clients.consumer.KafkaConsumer;\n\
            public class Vuln {\n\
              public void onMessage(String body) { consumer.poll(); }\n\
            }\n";
        let tree = parse_java(src);
        let mut summary = FuncSummary {
            name: "onMessage".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "consumer.poll".to_owned(),
            receiver: Some("consumer".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((0, "KafkaConsumer".to_owned()));
        assert!(
            KafkaJavaAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

//! Phase 20 (Track M.2) — Java RabbitMQ consumer adapter
//! (`com.rabbitmq.client.Channel.basicConsume`, Spring AMQP
//! `@RabbitListener`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RabbitJavaAdapter;

const ADAPTER_NAME: &str = "rabbit-java";

fn callee_is_rabbit(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "basicConsume" | "basicGet" | "handleDelivery" | "onMessage" | "receive"
    )
}

fn source_imports_rabbit(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"com.rabbitmq.client",
        b"org.springframework.amqp.rabbit",
        b"@RabbitListener",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_queue(file_bytes: &[u8]) -> String {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [
        "@RabbitListener(queues = \"",
        "@RabbitListener(queues=\"",
        "basicConsume(\"",
        "queueDeclare(\"",
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

impl FrameworkAdapter for RabbitJavaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_rabbit_listener_annotation() {
        let src: &[u8] = b"import org.springframework.amqp.rabbit.annotation.RabbitListener;\n\
            public class Vuln {\n\
              @RabbitListener(queues = \"work\")\n\
              public void onMessage(String mid, String body) {}\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "onMessage".into(),
            ..Default::default()
        };
        let binding = RabbitJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("@RabbitListener binds");
        if let EntryKind::MessageHandler { queue, .. } = binding.kind {
            assert_eq!(queue, "work");
        }
    }
}

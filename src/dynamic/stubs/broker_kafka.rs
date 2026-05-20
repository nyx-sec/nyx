//! Phase 20 (Track M.2) — Kafka broker loopback stub source-snippet provider.
//!
//! The Phase 20 acceptance gate runs every per-lang `MessageHandler` harness
//! inside an in-process loopback broker — no real Kafka cluster, no
//! external network — so the per-lang harness can publish the spec's
//! payload onto a topic and observe the handler under test receive it
//! synchronously.  Each `broker_kafka` source snippet declares a tiny
//! `NyxKafkaLoopback` type whose `publish(topic, payload)` immediately
//! routes the bytes through the subscriber callback the harness has
//! registered.  No threads, no sockets, no async runtime: a single
//! synchronous in-process dispatch keeps Phase 10's 500 ms boot budget
//! intact when `stubs_required` is empty.
//!
//! The snippet shape mirrors [`crate::dynamic::stubs::mocks::mock_source`] —
//! per-language inline source returned as a `&'static str` so the
//! generated harness can splice it verbatim into its own source.  The
//! per-language harness emitter is responsible for instantiating the
//! loopback and invoking the registered handler with the payload.

use crate::symbol::Lang;

/// Marker text the loopback emits on stdout when the harness publishes
/// a message.  Stable across languages so a future
/// `ProbeKind::BrokerPublish` predicate can pin the byte sequence.
pub const KAFKA_PUBLISH_MARKER: &str = "__NYX_BROKER_PUBLISH__:kafka";

/// Source snippet declaring an in-process Kafka loopback for `lang`.
/// Returns `""` when the language has no harness-level Kafka adapter
/// (everything outside Java / Python today).  The snippet does *not*
/// emit a publish marker by itself; the per-lang harness emitter calls
/// `publish(topic, payload)` and prints the marker once.
pub fn kafka_source(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => {
            r#"
class NyxKafkaLoopback:
    """In-process Kafka loopback — no socket, no thread, no broker."""
    def __init__(self):
        self._subs = {}
    def subscribe(self, topic, cb):
        self._subs.setdefault(topic, []).append(cb)
    def publish(self, topic, payload):
        for cb in self._subs.get(topic, []):
            cb(payload)
"#
        }
        Lang::Java => {
            r#"
    static class NyxKafkaLoopback {
        private final java.util.Map<String, java.util.List<java.util.function.Consumer<String>>> subs = new java.util.HashMap<>();
        public void subscribe(String topic, java.util.function.Consumer<String> cb) {
            subs.computeIfAbsent(topic, k -> new java.util.ArrayList<>()).add(cb);
        }
        public void publish(String topic, String payload) {
            for (java.util.function.Consumer<String> cb : subs.getOrDefault(topic, java.util.Collections.emptyList())) {
                cb.accept(payload);
            }
        }
    }
"#
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kafka_publish_marker_is_stable() {
        assert_eq!(KAFKA_PUBLISH_MARKER, "__NYX_BROKER_PUBLISH__:kafka");
    }

    #[test]
    fn python_snippet_declares_loopback_class() {
        let src = kafka_source(Lang::Python);
        assert!(src.contains("class NyxKafkaLoopback"));
        assert!(src.contains("def publish"));
        assert!(src.contains("def subscribe"));
    }

    #[test]
    fn java_snippet_declares_static_inner_class() {
        let src = kafka_source(Lang::Java);
        assert!(src.contains("static class NyxKafkaLoopback"));
        assert!(src.contains("public void publish"));
        assert!(src.contains("public void subscribe"));
    }

    #[test]
    fn unsupported_langs_return_empty_snippet() {
        for lang in [
            Lang::Go,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Php,
            Lang::Ruby,
            Lang::Rust,
            Lang::C,
            Lang::Cpp,
        ] {
            assert!(
                kafka_source(lang).is_empty(),
                "{lang:?} should not yet ship a Kafka loopback snippet"
            );
        }
    }
}

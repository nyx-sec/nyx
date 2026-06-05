//! Phase 20 (Track M.2) — Kafka broker loopback stub source-snippet provider.
//!
//! The Phase 20 acceptance gate runs every per-lang `MessageHandler` harness
//! inside an in-process loopback broker — no real Kafka cluster, no
//! external network — so the per-lang harness can publish the spec's
//! payload onto a topic, poll the topic, dispatch the record, and commit
//! the offset. No threads, no sockets, no async runtime: a single
//! synchronous publish/poll/commit cycle keeps Phase 10's 500 ms boot
//! budget intact when `stubs_required` is empty while still exercising
//! the consumer-loop shape real Kafka handlers depend on.
//!
//! The snippet shape mirrors [`crate::dynamic::stubs::mocks::mock_source`] —
//! per-language inline source returned as a `&'static str` so the
//! generated harness can splice it verbatim into its own source. The
//! per-language harness emitter is responsible for instantiating the
//! loopback, publishing, polling, and committing records.

use crate::symbol::Lang;

/// Marker text the loopback emits on stdout when the harness publishes
/// a message.  Stable across languages so a future
/// `ProbeKind::BrokerPublish` predicate can pin the byte sequence.
pub const KAFKA_PUBLISH_MARKER: &str = "__NYX_BROKER_PUBLISH__:kafka";

/// Source snippet declaring an in-process Kafka loopback for `lang`.
/// Returns `""` when the language has no harness-level Kafka adapter
/// (everything outside Java / Python today).  The snippet does *not*
/// emit a publish marker by itself; the per-lang harness emitter calls
/// `publish(topic, payload)`, polls, and prints the marker once.
pub fn kafka_source(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => {
            r#"
class NyxKafkaLoopback:
    """In-process Kafka loopback with publish/poll/commit semantics."""
    def __init__(self):
        self._subs = {}
        self._topics = {}
        self._offsets = {}
        self._committed = {}
    def subscribe(self, topic, cb):
        self._subs.setdefault(topic, []).append(cb)
    def _next_offset(self, topic):
        off = self._offsets.get(topic, 0)
        self._offsets[topic] = off + 1
        return off
    def publish(self, topic, payload):
        rec = NyxKafkaRecord(topic, payload, self._next_offset(topic))
        self._topics.setdefault(topic, []).append(rec)
        return rec
    def poll(self, topic, max_records=1, timeout_ms=0):
        _ = timeout_ms
        return list(self._topics.get(topic, [])[:max_records])
    def commit(self, record):
        self._committed[record.topic] = max(self._committed.get(record.topic, -1), record.offset)
        self._topics[record.topic] = [
            r for r in self._topics.get(record.topic, []) if r.offset > record.offset
        ]

class NyxKafkaRecord:
    def __init__(self, topic, value, offset):
        self.topic = topic
        self.value = value
        self.offset = offset
        self.key = None
    def __str__(self):
        return str(self.value)
"#
        }
        Lang::Java => {
            r#"
    static class NyxKafkaRecord {
        public final String topic;
        public final String value;
        public final long offset;
        NyxKafkaRecord(String topic, String value, long offset) {
            this.topic = topic;
            this.value = value;
            this.offset = offset;
        }
        public String toString() { return value; }
    }

    static class NyxKafkaLoopback {
        private final java.util.Map<String, java.util.List<java.util.function.Consumer<String>>> subs = new java.util.HashMap<>();
        private final java.util.Map<String, java.util.List<NyxKafkaRecord>> topics = new java.util.HashMap<>();
        private final java.util.Map<String, Long> offsets = new java.util.HashMap<>();
        private final java.util.Map<String, Long> committed = new java.util.HashMap<>();
        public void subscribe(String topic, java.util.function.Consumer<String> cb) {
            subs.computeIfAbsent(topic, k -> new java.util.ArrayList<>()).add(cb);
        }
        public NyxKafkaRecord publish(String topic, String payload) {
            long off = offsets.getOrDefault(topic, 0L);
            offsets.put(topic, off + 1L);
            NyxKafkaRecord rec = new NyxKafkaRecord(topic, payload, off);
            topics.computeIfAbsent(topic, k -> new java.util.ArrayList<>()).add(rec);
            return rec;
        }
        public java.util.List<NyxKafkaRecord> poll(String topic, int maxRecords) {
            java.util.List<NyxKafkaRecord> q = topics.getOrDefault(topic, java.util.Collections.emptyList());
            return new java.util.ArrayList<>(q.subList(0, Math.min(maxRecords, q.size())));
        }
        public void commit(NyxKafkaRecord rec) {
            committed.put(rec.topic, Math.max(committed.getOrDefault(rec.topic, -1L), rec.offset));
            java.util.List<NyxKafkaRecord> q = topics.getOrDefault(rec.topic, new java.util.ArrayList<>());
            q.removeIf(r -> r.offset <= rec.offset);
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
        assert!(src.contains("class NyxKafkaRecord"));
        assert!(src.contains("def publish"));
        assert!(src.contains("def poll"));
        assert!(src.contains("def commit"));
    }

    #[test]
    fn java_snippet_declares_static_inner_class() {
        let src = kafka_source(Lang::Java);
        assert!(src.contains("static class NyxKafkaRecord"));
        assert!(src.contains("static class NyxKafkaLoopback"));
        assert!(src.contains("public NyxKafkaRecord publish"));
        assert!(src.contains("public java.util.List<NyxKafkaRecord> poll"));
        assert!(src.contains("public void commit"));
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

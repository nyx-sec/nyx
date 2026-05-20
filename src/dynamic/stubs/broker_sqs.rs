//! Phase 20 (Track M.2) — SQS broker loopback stub source-snippet provider.
//!
//! Mirrors [`crate::dynamic::stubs::broker_kafka`] but mints SQS-shaped
//! envelopes (`MessageId`, `ReceiptHandle`, `Body`) the way `boto3.sqs` /
//! `software.amazon.awssdk.services.sqs` / the AWS Node SDK present
//! them.  The loopback never speaks the AWS protocol — it just calls
//! the registered handler synchronously with a single-message envelope.

use crate::symbol::Lang;

/// Stdout sentinel the per-lang harness prints once per publish.
pub const SQS_PUBLISH_MARKER: &str = "__NYX_BROKER_PUBLISH__:sqs";

/// Source snippet declaring an in-process SQS loopback for `lang`.
/// Java / Python / Node (JS+TS) carry concrete snippets; every other
/// lang returns `""`.
pub fn sqs_source(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => {
            r#"
class NyxSqsLoopback:
    """In-process SQS loopback — boto3-shaped envelopes."""
    def __init__(self):
        self._subs = {}
        self._mid = 0
    def subscribe(self, queue, cb):
        self._subs.setdefault(queue, []).append(cb)
    def publish(self, queue, payload):
        self._mid += 1
        envelope = {
            'MessageId': f'nyx-{self._mid:08d}',
            'ReceiptHandle': f'rh-nyx-{self._mid:08d}',
            'Body': payload,
        }
        for cb in self._subs.get(queue, []):
            cb(envelope)
"#
        }
        Lang::Java => {
            r#"
    static class NyxSqsLoopback {
        private final java.util.Map<String, java.util.List<java.util.function.Consumer<java.util.Map<String, String>>>> subs = new java.util.HashMap<>();
        private int mid = 0;
        public void subscribe(String queue, java.util.function.Consumer<java.util.Map<String, String>> cb) {
            subs.computeIfAbsent(queue, k -> new java.util.ArrayList<>()).add(cb);
        }
        public void publish(String queue, String payload) {
            mid += 1;
            java.util.Map<String, String> envelope = new java.util.HashMap<>();
            envelope.put("MessageId", "nyx-" + mid);
            envelope.put("ReceiptHandle", "rh-nyx-" + mid);
            envelope.put("Body", payload);
            for (java.util.function.Consumer<java.util.Map<String, String>> cb : subs.getOrDefault(queue, java.util.Collections.emptyList())) {
                cb.accept(envelope);
            }
        }
    }
"#
        }
        Lang::JavaScript | Lang::TypeScript => {
            r#"
class NyxSqsLoopback {
    constructor() { this._subs = new Map(); this._mid = 0; }
    subscribe(queue, cb) {
        if (!this._subs.has(queue)) this._subs.set(queue, []);
        this._subs.get(queue).push(cb);
    }
    publish(queue, payload) {
        this._mid += 1;
        const envelope = {
            MessageId: 'nyx-' + this._mid,
            ReceiptHandle: 'rh-nyx-' + this._mid,
            Body: payload,
        };
        for (const cb of (this._subs.get(queue) || [])) cb(envelope);
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
    fn marker_stable() {
        assert_eq!(SQS_PUBLISH_MARKER, "__NYX_BROKER_PUBLISH__:sqs");
    }

    #[test]
    fn python_carries_boto3_shape() {
        let src = sqs_source(Lang::Python);
        assert!(src.contains("class NyxSqsLoopback"));
        assert!(src.contains("MessageId"));
        assert!(src.contains("ReceiptHandle"));
        assert!(src.contains("Body"));
    }

    #[test]
    fn java_carries_envelope_map() {
        let src = sqs_source(Lang::Java);
        assert!(src.contains("static class NyxSqsLoopback"));
        assert!(src.contains("MessageId"));
        assert!(src.contains("Body"));
    }

    #[test]
    fn node_class_supports_subscribe_publish() {
        let src = sqs_source(Lang::JavaScript);
        assert!(src.contains("class NyxSqsLoopback"));
        assert!(src.contains("subscribe(queue"));
        assert!(src.contains("publish(queue"));
        let ts = sqs_source(Lang::TypeScript);
        assert_eq!(ts, src);
    }
}

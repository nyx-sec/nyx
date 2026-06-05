//! Phase 20 (Track M.2) — SQS broker loopback stub source-snippet provider.
//!
//! Mirrors [`crate::dynamic::stubs::broker_kafka`] but mints SQS-shaped
//! envelopes (`MessageId`, `ReceiptHandle`, `Body`) the way `boto3.sqs` /
//! `software.amazon.awssdk.services.sqs` / the AWS Node SDK present
//! them. The loopback never speaks the AWS protocol, but it does model
//! the shape the harness cares about: send, receive, receipt-handle
//! delete, and bounded redelivery for messages that are not acked.

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
    """In-process SQS loopback with receive/delete semantics."""
    def __init__(self):
        self._subs = {}
        self._mid = 0
        self._queues = {}
        self._inflight = {}
    def subscribe(self, queue, cb):
        self._subs.setdefault(queue, []).append(cb)
    def publish(self, queue, payload):
        self._mid += 1
        envelope = {
            'MessageId': f'nyx-{self._mid:08d}',
            'ReceiptHandle': f'rh-nyx-{self._mid:08d}',
            'Body': payload,
            'Attributes': {'ApproximateReceiveCount': '0'},
        }
        self._queues.setdefault(queue, []).append(envelope)
        return envelope
    def receive_message(self, queue, max_number=1, visibility_timeout=0):
        _ = visibility_timeout
        out = []
        pending = self._queues.setdefault(queue, [])
        while pending and len(out) < max_number:
            msg = pending.pop(0)
            count = int(msg.get('Attributes', {}).get('ApproximateReceiveCount', '0')) + 1
            msg.setdefault('Attributes', {})['ApproximateReceiveCount'] = str(count)
            self._inflight[msg['ReceiptHandle']] = (queue, msg)
            out.append(msg)
        return out
    def delete_message(self, queue, receipt_handle):
        _ = queue
        return self._inflight.pop(receipt_handle, None) is not None
    def replay_inflight(self, max_receive_count=3):
        for receipt, (queue, msg) in list(self._inflight.items()):
            count = int(msg.get('Attributes', {}).get('ApproximateReceiveCount', '0'))
            if count < max_receive_count:
                self._queues.setdefault(queue, []).append(msg)
            self._inflight.pop(receipt, None)
"#
        }
        Lang::Java => {
            r#"
    static class NyxSqsLoopback {
        private final java.util.Map<String, java.util.List<java.util.function.Consumer<java.util.Map<String, String>>>> subs = new java.util.HashMap<>();
        private final java.util.Map<String, java.util.List<java.util.Map<String, String>>> queues = new java.util.HashMap<>();
        private final java.util.Map<String, java.util.Map<String, String>> inflight = new java.util.HashMap<>();
        private int mid = 0;
        public void subscribe(String queue, java.util.function.Consumer<java.util.Map<String, String>> cb) {
            subs.computeIfAbsent(queue, k -> new java.util.ArrayList<>()).add(cb);
        }
        public java.util.Map<String, String> publish(String queue, String payload) {
            mid += 1;
            java.util.Map<String, String> envelope = new java.util.HashMap<>();
            envelope.put("MessageId", "nyx-" + mid);
            envelope.put("ReceiptHandle", "rh-nyx-" + mid);
            envelope.put("Body", payload);
            envelope.put("ApproximateReceiveCount", "0");
            queues.computeIfAbsent(queue, k -> new java.util.ArrayList<>()).add(envelope);
            return envelope;
        }
        public java.util.List<java.util.Map<String, String>> receiveMessage(String queue, int maxMessages) {
            java.util.List<java.util.Map<String, String>> pending = queues.computeIfAbsent(queue, k -> new java.util.ArrayList<>());
            java.util.List<java.util.Map<String, String>> out = new java.util.ArrayList<>();
            while (!pending.isEmpty() && out.size() < maxMessages) {
                java.util.Map<String, String> msg = pending.remove(0);
                int count = Integer.parseInt(msg.getOrDefault("ApproximateReceiveCount", "0")) + 1;
                msg.put("ApproximateReceiveCount", Integer.toString(count));
                inflight.put(msg.get("ReceiptHandle"), msg);
                out.add(msg);
            }
            return out;
        }
        public boolean deleteMessage(String queue, String receiptHandle) {
            return inflight.remove(receiptHandle) != null;
        }
    }
"#
        }
        Lang::JavaScript | Lang::TypeScript => {
            r#"
class NyxSqsLoopback {
    constructor() { this._subs = new Map(); this._mid = 0; this._queues = new Map(); this._inflight = new Map(); }
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
            Attributes: { ApproximateReceiveCount: '0' },
        };
        if (!this._queues.has(queue)) this._queues.set(queue, []);
        this._queues.get(queue).push(envelope);
        return envelope;
    }
    receiveMessage(queue, maxMessages = 1, visibilityTimeout = 0) {
        void visibilityTimeout;
        const pending = this._queues.get(queue) || [];
        const out = [];
        while (pending.length > 0 && out.length < maxMessages) {
            const msg = pending.shift();
            const count = Number((msg.Attributes && msg.Attributes.ApproximateReceiveCount) || '0') + 1;
            msg.Attributes = Object.assign({}, msg.Attributes || {}, { ApproximateReceiveCount: String(count) });
            this._inflight.set(msg.ReceiptHandle, { queue, msg });
            out.push(msg);
        }
        return out;
    }
    deleteMessage(queue, receiptHandle) {
        void queue;
        return this._inflight.delete(receiptHandle);
    }
    replayInflight(maxReceiveCount = 3) {
        for (const [receipt, item] of Array.from(this._inflight.entries())) {
            const count = Number((item.msg.Attributes && item.msg.Attributes.ApproximateReceiveCount) || '0');
            if (count < maxReceiveCount) {
                if (!this._queues.has(item.queue)) this._queues.set(item.queue, []);
                this._queues.get(item.queue).push(item.msg);
            }
            this._inflight.delete(receipt);
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
        assert!(src.contains("receive_message"));
        assert!(src.contains("delete_message"));
    }

    #[test]
    fn java_carries_envelope_map() {
        let src = sqs_source(Lang::Java);
        assert!(src.contains("static class NyxSqsLoopback"));
        assert!(src.contains("MessageId"));
        assert!(src.contains("Body"));
        assert!(src.contains("receiveMessage"));
        assert!(src.contains("deleteMessage"));
    }

    #[test]
    fn node_class_supports_subscribe_publish() {
        let src = sqs_source(Lang::JavaScript);
        assert!(src.contains("class NyxSqsLoopback"));
        assert!(src.contains("subscribe(queue"));
        assert!(src.contains("publish(queue"));
        assert!(src.contains("receiveMessage(queue"));
        assert!(src.contains("deleteMessage(queue"));
        let ts = sqs_source(Lang::TypeScript);
        assert_eq!(ts, src);
    }
}

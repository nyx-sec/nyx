//! Phase 20 (Track M.2) — RabbitMQ broker loopback stub.
//!
//! Mints `pika.BasicProperties` / `com.rabbitmq.client.Envelope`-shaped
//! envelopes for Python / Java handlers.

use crate::symbol::Lang;

/// Stdout sentinel printed once per publish.
pub const RABBIT_PUBLISH_MARKER: &str = "__NYX_BROKER_PUBLISH__:rabbit";

/// Source snippet declaring an in-process RabbitMQ loopback for `lang`.
pub fn rabbit_source(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => {
            r#"
class NyxRabbitProperties:
    def __init__(self, mid):
        self.message_id = mid
        self.delivery_mode = 2

class NyxRabbitMethod:
    def __init__(self, tag, routing_key):
        self.delivery_tag = tag
        self.routing_key = routing_key

class NyxRabbitChannel:
    def __init__(self):
        self._subs = {}
        self._tag = 0
    def basic_consume(self, queue, on_message_callback, **kw):
        self._subs.setdefault(queue, []).append(on_message_callback)
    def basic_publish(self, exchange, routing_key, body, properties=None):
        self._tag += 1
        method = NyxRabbitMethod(self._tag, routing_key)
        props = properties or NyxRabbitProperties(f'nyx-{self._tag:08d}')
        body_bytes = body if isinstance(body, (bytes, bytearray)) else body.encode('utf-8', 'replace')
        for cb in self._subs.get(routing_key, []):
            cb(self, method, props, body_bytes)
"#
        }
        Lang::Java => {
            r#"
    static class NyxRabbitChannel {
        private final java.util.Map<String, java.util.List<java.util.function.BiConsumer<String, String>>> subs = new java.util.HashMap<>();
        private long tag = 0;
        public void basicConsume(String queue, java.util.function.BiConsumer<String, String> cb) {
            subs.computeIfAbsent(queue, k -> new java.util.ArrayList<>()).add(cb);
        }
        public void basicPublish(String exchange, String routingKey, String body) {
            tag += 1;
            String mid = "nyx-" + tag;
            for (java.util.function.BiConsumer<String, String> cb : subs.getOrDefault(routingKey, java.util.Collections.emptyList())) {
                cb.accept(mid, body);
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
        assert_eq!(RABBIT_PUBLISH_MARKER, "__NYX_BROKER_PUBLISH__:rabbit");
    }

    #[test]
    fn python_carries_pika_shape() {
        let src = rabbit_source(Lang::Python);
        assert!(src.contains("class NyxRabbitChannel"));
        assert!(src.contains("basic_consume"));
        assert!(src.contains("basic_publish"));
        assert!(src.contains("delivery_tag"));
    }

    #[test]
    fn java_carries_static_inner_channel() {
        let src = rabbit_source(Lang::Java);
        assert!(src.contains("static class NyxRabbitChannel"));
        assert!(src.contains("basicConsume"));
        assert!(src.contains("basicPublish"));
    }
}

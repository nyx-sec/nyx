//! Phase 20 (Track M.2) — Google Pub/Sub broker loopback stub.
//!
//! Mints `google.cloud.pubsub_v1.subscriber.message.Message`-shaped
//! envelopes (`message_id`, `data`, `ack`, `nack`) for Python / Go.

use crate::symbol::Lang;

/// Stdout sentinel the per-lang harness prints once per publish.
pub const PUBSUB_PUBLISH_MARKER: &str = "__NYX_BROKER_PUBLISH__:pubsub";

/// Source snippet declaring an in-process Pub/Sub loopback for `lang`.
pub fn pubsub_source(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => {
            r#"
class NyxPubsubMessage:
    def __init__(self, mid, data):
        self.message_id = mid
        self.data = data if isinstance(data, (bytes, bytearray)) else data.encode('utf-8', 'replace')
        self.acked = False
        self.nacked = False
    def ack(self): self.acked = True
    def nack(self): self.nacked = True

class NyxPubsubLoopback:
    def __init__(self):
        self._subs = {}
        self._mid = 0
    def subscribe(self, topic, cb):
        self._subs.setdefault(topic, []).append(cb)
    def publish(self, topic, payload):
        self._mid += 1
        msg = NyxPubsubMessage(f'nyx-{self._mid:08d}', payload)
        for cb in self._subs.get(topic, []):
            cb(msg)
"#
        }
        Lang::Go => {
            r#"
type NyxPubsubMessage struct {
    ID    string
    Data  []byte
    Acked bool
}

func (m *NyxPubsubMessage) Ack()  { m.Acked = true }
func (m *NyxPubsubMessage) Nack() { m.Acked = false }

type NyxPubsubLoopback struct {
    subs map[string][]func(*NyxPubsubMessage)
    mid  int
}

func NewNyxPubsubLoopback() *NyxPubsubLoopback {
    return &NyxPubsubLoopback{subs: map[string][]func(*NyxPubsubMessage){}}
}

func (l *NyxPubsubLoopback) Subscribe(topic string, cb func(*NyxPubsubMessage)) {
    l.subs[topic] = append(l.subs[topic], cb)
}

func (l *NyxPubsubLoopback) Publish(topic string, payload string) {
    l.mid += 1
    msg := &NyxPubsubMessage{ID: fmt.Sprintf("nyx-%08d", l.mid), Data: []byte(payload)}
    for _, cb := range l.subs[topic] {
        cb(msg)
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
        assert_eq!(PUBSUB_PUBLISH_MARKER, "__NYX_BROKER_PUBLISH__:pubsub");
    }

    #[test]
    fn python_carries_ack_nack_surface() {
        let src = pubsub_source(Lang::Python);
        assert!(src.contains("class NyxPubsubMessage"));
        assert!(src.contains("def ack"));
        assert!(src.contains("def nack"));
        assert!(src.contains("message_id"));
    }

    #[test]
    fn go_carries_ack_nack_methods() {
        let src = pubsub_source(Lang::Go);
        assert!(src.contains("type NyxPubsubMessage struct"));
        assert!(src.contains("func (m *NyxPubsubMessage) Ack"));
        assert!(src.contains("NewNyxPubsubLoopback"));
    }
}

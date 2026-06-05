//! Phase 20 (Track M.2) — NATS broker loopback stub.
//!
//! Mints `nats.io/nats.go` style `*nats.Msg` envelopes (`Subject`,
//! `Data`, `Reply`) for Go handlers.

use crate::symbol::Lang;

/// Stdout sentinel printed once per publish.
pub const NATS_PUBLISH_MARKER: &str = "__NYX_BROKER_PUBLISH__:nats";

/// Source snippet declaring an in-process NATS loopback for `lang`.
pub fn nats_source(lang: Lang) -> &'static str {
    match lang {
        Lang::Go => {
            r#"
type NyxNatsMsg struct {
    Subject string
    Data    []byte
    Reply   string
}

type NyxNatsLoopback struct {
    subs map[string][]func(*NyxNatsMsg)
}

func NewNyxNatsLoopback() *NyxNatsLoopback {
    return &NyxNatsLoopback{subs: map[string][]func(*NyxNatsMsg){}}
}

func (l *NyxNatsLoopback) Subscribe(subject string, cb func(*NyxNatsMsg)) {
    l.subs[subject] = append(l.subs[subject], cb)
}

func (l *NyxNatsLoopback) Publish(subject string, payload string) {
    msg := &NyxNatsMsg{Subject: subject, Data: []byte(payload)}
    for _, cb := range l.subs[subject] {
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
        assert_eq!(NATS_PUBLISH_MARKER, "__NYX_BROKER_PUBLISH__:nats");
    }

    #[test]
    fn go_loopback_exposes_subject_data_reply() {
        let src = nats_source(Lang::Go);
        assert!(src.contains("type NyxNatsMsg struct"));
        assert!(src.contains("Subject string"));
        assert!(src.contains("Data    []byte"));
        assert!(src.contains("Reply   string"));
        assert!(src.contains("func NewNyxNatsLoopback"));
    }

    #[test]
    fn other_langs_return_empty_snippet() {
        for lang in [
            Lang::Python,
            Lang::Java,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Php,
            Lang::Ruby,
            Lang::Rust,
            Lang::C,
            Lang::Cpp,
        ] {
            assert!(nats_source(lang).is_empty());
        }
    }
}

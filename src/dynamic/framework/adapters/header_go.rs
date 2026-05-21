//! Go [`super::super::FrameworkAdapter`] matching HTTP response-
//! header CRLF-injection sink constructions
//! (`http.ResponseWriter.Header().Set` / `Add`, Gin `c.Header`,
//! Echo `c.Response().Header().Set`).
//!
//! Phase 08 (Track J.6).  Fires when the function body invokes one
//! of the canonical Go HTTP response writers and the surrounding
//! source imports `net/http` or one of the supported frameworks.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct HeaderGoAdapter;

const ADAPTER_NAME: &str = "header-go";

fn callee_is_header_setter(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "Set" | "Add" | "Header" | "WriteHeader")
}

/// True when `receiver` looks like a Go HTTP response-writer or framework
/// context expression.  Filters out `url.Values.Set` / `sync.Map.Store` /
/// `flag.FlagSet.Set` and similar map-like receivers whose `Set` / `Add`
/// names collide with `http.Header.Set` / `Add`.
///
/// Drilled forms (root_receiver_text reduces `w.Header().Set` to `w`):
///   * `w` / `rw` / `writer` — canonical `http.ResponseWriter` names
///   * `c` / `ctx` — gin / echo / fiber / chi context handles
///   * `resp` / `response` — common response-wrapper names
///   * `headers` — `Header` value handle
///
/// Non-drilled forms (raw text when drilling fails):
///   * Any expression containing `.Header()` or `.Headers()` —
///     canonical chain accessor returning `http.Header`.
fn receiver_is_go_response_writer(receiver: &str) -> bool {
    matches!(
        receiver,
        "w" | "rw" | "writer" | "c" | "ctx" | "resp" | "response" | "headers" | "header"
    ) || receiver.contains(".Header()")
        || receiver.contains(".Headers()")
}

fn source_imports_go_http(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"\"net/http\"",
        b"net/http\"",
        b"github.com/gin-gonic/gin",
        b"github.com/labstack/echo",
        b"github.com/gofiber/fiber",
        b"github.com/go-chi/chi",
        b".Header().Set",
        b".Header().Add",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// header value through a canonical Go URL-encoder / HTML-escaper.
fn value_routed_through_encoder(file_bytes: &[u8]) -> bool {
    const ENCODER_CALLS: &[&[u8]] = &[
        b"url.QueryEscape(",
        b"url.PathEscape(",
        b"template.HTMLEscapeString(",
        b"template.JSEscapeString(",
    ];
    ENCODER_CALLS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for HeaderGoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if value_routed_through_encoder(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches_with_receiver(
            summary,
            callee_is_header_setter,
            receiver_is_go_response_writer,
        );
        let matches_source = source_imports_go_http(file_bytes);
        if matches_call && matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
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

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_header_set() {
        let src: &[u8] =
            b"package x\nimport \"net/http\"\nfunc Run(w http.ResponseWriter, v string) { w.Header().Set(\"Set-Cookie\", v) }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Set")],
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"package x\nfunc Add(a, b int) int { return a + b }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Add".into(),
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_url_values_set_collision() {
        // `params.Set(k, v)` on a `url.Values` collides with `http.Header.Set`
        // on the bare callee name.  Real CFG-derived callees carry the
        // receiver text `params`, which is not in the response-writer
        // allowlist, so the adapter rejects.  Net/url is intentionally
        // imported here to ensure the source-import gate alone would fire.
        let src: &[u8] = b"package x\nimport (\"net/http\"; \"net/url\")\n\
            func Run(w http.ResponseWriter, v string) {\n\
                params := url.Values{}\n\
                params.Set(\"k\", v)\n\
                _ = params\n\
            }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "Set".into(),
                receiver: Some("params".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn fires_on_response_writer_receiver() {
        // Receiver-text discriminator accepts `w` (canonical
        // `http.ResponseWriter` shorthand).
        let src: &[u8] = b"package x\nimport \"net/http\"\n\
            func Run(w http.ResponseWriter, v string) { w.Header().Set(\"X\", v) }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "Set".into(),
                receiver: Some("w".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_when_value_url_encoded() {
        let src: &[u8] = b"package x\nimport (\"net/http\"; \"net/url\")\n\
            func Run(w http.ResponseWriter, v string) { w.Header().Set(\"X-Token\", url.QueryEscape(v)) }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("Set"),
                crate::summary::CalleeSite::bare("QueryEscape"),
            ],
            ..Default::default()
        };
        assert!(HeaderGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

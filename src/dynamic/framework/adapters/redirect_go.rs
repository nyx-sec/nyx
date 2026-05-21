//! Go [`super::super::FrameworkAdapter`] matching HTTP-redirect sink
//! constructions (`http.Redirect`, `gin.Context.Redirect`).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one of
//! the canonical Go HTTP redirect entry points and the surrounding
//! source imports `net/http` or the gin framework.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectGoAdapter;

const ADAPTER_NAME: &str = "redirect-go";

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "Redirect" | "Redirect302" | "Redirect301")
}

fn source_imports_go_web(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"net/http",
        b"github.com/gin-gonic/gin",
        b"github.com/labstack/echo",
        b"github.com/gofiber/fiber",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// redirect URL through a canonical host-allowlist / URL-validator.
fn url_routed_through_validator(file_bytes: &[u8]) -> bool {
    const VALIDATOR_TOKENS: &[&[u8]] = &[
        b"url.Parse(",
        b"allowedHosts",
        b"AllowedHosts",
        b"allowlist",
        b"Allowlist",
        b".Host ==",
        b".Hostname() ==",
    ];
    VALIDATOR_TOKENS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source looks like a mockgen-
/// generated mock (`gomock` / `EXPECT()` chains).  The `Redirect`
/// callee on those receivers is a recorded-call assertion, not an
/// HTTP redirect.
fn looks_like_mockgen(file_bytes: &[u8]) -> bool {
    const MOCK_TOKENS: &[&[u8]] = &[
        b"github.com/golang/mock/gomock",
        b"go.uber.org/mock/gomock",
        b".EXPECT().",
    ];
    MOCK_TOKENS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectGoAdapter {
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
        if looks_like_mockgen(file_bytes) || url_routed_through_validator(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
        let matches_source = source_imports_go_web(file_bytes);
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
    fn fires_on_gin_redirect() {
        let src: &[u8] = b"package vuln\n\nimport (\n\t\"net/http\"\n\t\"github.com/gin-gonic/gin\"\n)\n\
            func Run(c *gin.Context, v string) {\n\tc.Redirect(http.StatusFound, v)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Redirect")],
            ..Default::default()
        };
        assert!(RedirectGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"package vuln\n\nfunc Add(a, b int) int { return a + b }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Add".into(),
            ..Default::default()
        };
        assert!(RedirectGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_url_validated_against_allowlist() {
        let src: &[u8] = b"package vuln\n\nimport (\n\t\"net/http\"\n\t\"net/url\"\n\t\"github.com/gin-gonic/gin\"\n)\n\
            func Run(c *gin.Context, v string) {\n\t\
                u, err := url.Parse(v)\n\t\
                if err != nil || u.Hostname() != \"example.com\" { return }\n\t\
                c.Redirect(http.StatusFound, v)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("Redirect"),
                crate::summary::CalleeSite::bare("Parse"),
            ],
            ..Default::default()
        };
        assert!(RedirectGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_file_uses_gomock() {
        let src: &[u8] = b"package vuln\n\nimport (\n\t\"github.com/golang/mock/gomock\"\n)\n\
            func Run(m *MockRouter, v string) {\n\tm.EXPECT().Redirect(v)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Redirect")],
            ..Default::default()
        };
        assert!(RedirectGoAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

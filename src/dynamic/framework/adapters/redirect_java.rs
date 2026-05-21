//! Java [`super::super::FrameworkAdapter`] matching HTTP-redirect
//! sink constructions (`HttpServletResponse.sendRedirect`,
//! Spring `ResponseEntity` 302 builders).
//!
//! Phase 09 (Track J.7).  Fires when the function body invokes one
//! of the canonical servlet redirect entry points and the
//! surrounding source imports a servlet API.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct RedirectJavaAdapter;

const ADAPTER_NAME: &str = "redirect-java";

fn callee_is_redirect(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "sendRedirect" | "redirect")
}

fn source_imports_servlet(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"javax.servlet",
        b"jakarta.servlet",
        b"HttpServletResponse",
        b"org.springframework.http",
        b"org.springframework.web.servlet",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// redirect URL through a canonical host-allowlist / URL-validator
/// helper, so the redirect cannot reach an off-origin attacker host.
fn url_routed_through_validator(file_bytes: &[u8]) -> bool {
    const VALIDATOR_TOKENS: &[&[u8]] = &[
        b"UrlValidator",
        b".isValid(",
        b"allowedHosts",
        b"allowlist",
        b"allowList",
        b"WHITELIST",
        b"isAllowedHost",
        b"isAllowedRedirect",
    ];
    VALIDATOR_TOKENS
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for RedirectJavaAdapter {
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
        if url_routed_through_validator(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_redirect);
        let matches_source = source_imports_servlet(file_bytes);
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_send_redirect() {
        let src: &[u8] = b"import javax.servlet.http.HttpServletResponse;\n\
            class C { void run(HttpServletResponse r, String v) { r.sendRedirect(v); } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("sendRedirect")],
            ..Default::default()
        };
        assert!(RedirectJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"class C { int add(int a, int b) { return a + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(RedirectJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_url_validated_against_allowlist() {
        let src: &[u8] = b"import javax.servlet.http.HttpServletResponse;\n\
            import org.apache.commons.validator.routines.UrlValidator;\n\
            class C { void run(HttpServletResponse r, String v) throws Exception {\n\
                UrlValidator vd = new UrlValidator();\n\
                if (!vd.isValid(v)) return;\n\
                r.sendRedirect(v);\n\
            } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("sendRedirect"),
                crate::summary::CalleeSite::bare("isValid"),
            ],
            ..Default::default()
        };
        assert!(RedirectJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

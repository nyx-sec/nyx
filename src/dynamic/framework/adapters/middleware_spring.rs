//! Phase 21 (Track M.3) — Spring `HandlerInterceptor` middleware
//! adapter (Java).
//!
//! Fires when the surrounding source imports
//! `org.springframework.web.servlet.HandlerInterceptor` or `Filter` and
//! the function body is `preHandle` / `postHandle` / `doFilter`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareSpringAdapter;

const ADAPTER_NAME: &str = "middleware-spring";

fn callee_is_spring_middleware(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "preHandle" | "postHandle" | "afterCompletion" | "doFilter" | "addInterceptors"
    )
}

fn source_imports_spring_middleware(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"HandlerInterceptor",
        b"OncePerRequestFilter",
        b"javax.servlet.Filter",
        b"jakarta.servlet.Filter",
        b"WebMvcConfigurer",
        b"InterceptorRegistry",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for MiddlewareSpringAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_spring_middleware);
        let matches_source = source_imports_spring_middleware(file_bytes);
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Middleware {
                    name: summary.name.clone(),
                },
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
    fn fires_on_spring_interceptor() {
        let src: &[u8] = b"public class AuditInterceptor implements HandlerInterceptor {\n  public boolean preHandle(Object req, Object res, Object handler) { return true; }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "preHandle".into(),
            ..Default::default()
        };
        let binding = MiddlewareSpringAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("spring middleware binds");
        assert_eq!(binding.adapter, "middleware-spring");
        assert!(matches!(binding.kind, EntryKind::Middleware { .. }));
    }
}

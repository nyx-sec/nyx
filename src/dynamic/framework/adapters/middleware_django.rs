//! Phase 21 (Track M.3) — Django middleware adapter (Python).
//!
//! Fires when the surrounding source imports Django middleware base
//! classes (`MiddlewareMixin`) or declares a callable middleware whose
//! body defines `__call__(self, request)` / `process_request`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareDjangoAdapter;

const ADAPTER_NAME: &str = "middleware-django";

fn callee_is_django_middleware(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "process_request"
            | "process_response"
            | "process_view"
            | "process_exception"
            | "__call__"
    )
}

fn source_imports_django_middleware(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"django.utils.deprecation",
        b"MiddlewareMixin",
        b"def __call__(self, request",
        b"def process_request",
        b"django.middleware",
        b"MIDDLEWARE = [",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for MiddlewareDjangoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_django_middleware);
        let matches_source = source_imports_django_middleware(file_bytes);
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_django_middleware() {
        let src: &[u8] = b"from django.utils.deprecation import MiddlewareMixin\n\
            class AuditMiddleware(MiddlewareMixin):\n    def process_request(self, request):\n        pass\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "process_request".into(),
            ..Default::default()
        };
        let binding = MiddlewareDjangoAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("django middleware binds");
        assert_eq!(binding.adapter, "middleware-django");
        assert!(matches!(binding.kind, EntryKind::Middleware { .. }));
    }
}

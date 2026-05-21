//! Phase 21 (Track M.3) — Django middleware adapter (Python).
//!
//! Fires when the surrounding source imports Django middleware base
//! classes (`MiddlewareMixin`) or declares a callable middleware whose
//! body defines `__call__(self, request)` / `process_request`.
//!
//! Notably does NOT fire just because the file contains `MIDDLEWARE = [`
//! (typical of `settings.py`) — that needle stole every settings module
//! into Middleware bindings (Phase 21 binding-stealing audit).

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
        "process_request" | "process_response" | "process_view" | "process_exception"
    )
}

fn source_has_middleware_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"django.utils.deprecation",
        b"MiddlewareMixin",
        b"def __call__(self, request",
        b"def process_request",
        b"django.middleware",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn looks_like_settings_module(file_bytes: &[u8]) -> bool {
    // Heuristic: settings.py declares MIDDLEWARE / INSTALLED_APPS / DATABASES at
    // module scope.  A real middleware module declares none of these (it carries
    // a class with __call__ / process_*).
    let has_middleware_list = file_bytes
        .windows(b"MIDDLEWARE = [".len())
        .any(|w| w == b"MIDDLEWARE = [");
    let has_installed_apps = file_bytes
        .windows(b"INSTALLED_APPS".len())
        .any(|w| w == b"INSTALLED_APPS");
    let declares_middleware_class = file_bytes
        .windows(b"def __call__".len())
        .any(|w| w == b"def __call__")
        || file_bytes
            .windows(b"def process_request".len())
            .any(|w| w == b"def process_request");
    (has_middleware_list || has_installed_apps) && !declares_middleware_class
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
        if looks_like_settings_module(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_django_middleware);
        let matches_source = source_has_middleware_shape(file_bytes);
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

    #[test]
    fn does_not_bind_settings_module() {
        let src: &[u8] = b"INSTALLED_APPS = ['django.contrib.auth']\nMIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n]\nDATABASES = {}\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "some_helper".into(),
            ..Default::default()
        };
        assert!(
            MiddlewareDjangoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "settings.py-shaped module must not bind as middleware",
        );
    }
}

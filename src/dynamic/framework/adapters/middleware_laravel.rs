//! Phase 21 (Track M.3) — Laravel middleware adapter (PHP).
//!
//! Fires when the surrounding source declares a class with a `handle`
//! method whose signature matches Laravel's middleware contract
//! (`$request, Closure $next`).
//!
//! Notably does NOT fire just because the file imports
//! `Illuminate\Http\Request` or mentions `$middleware` — every typical
//! Laravel controller imports the request facade, and `$middleware`
//! appears in routes / kernel files unrelated to middleware classes
//! (Phase 21 binding-stealing audit).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareLaravelAdapter;

const ADAPTER_NAME: &str = "middleware-laravel";

fn callee_is_laravel_middleware(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "terminate" | "withMiddleware")
}

fn source_has_middleware_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"Illuminate\\Foundation\\Http\\Middleware",
        b"function handle($request, Closure $next",
        b"function handle(Request $request, Closure $next",
        b"function handle($request, $next",
        b"app/Http/Middleware",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_middleware_entry(name: &str) -> bool {
    matches!(name, "handle" | "terminate")
}

impl FrameworkAdapter for MiddlewareLaravelAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let has_shape = source_has_middleware_shape(file_bytes);
        let name_matches = name_is_middleware_entry(&summary.name);
        let body_mounts_middleware =
            has_shape && super::any_callee_matches(summary, callee_is_laravel_middleware);
        let binds = (name_matches && has_shape) || body_mounts_middleware;
        if !binds {
            return None;
        }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_laravel_handle() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Http\\Request;\nclass Audit {\n  public function handle($request, Closure $next) { return $next($request); }\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "handle".into(),
            ..Default::default()
        };
        let binding = MiddlewareLaravelAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("laravel middleware binds");
        assert_eq!(binding.adapter, "middleware-laravel");
        assert!(matches!(binding.kind, EntryKind::Middleware { .. }));
    }

    #[test]
    fn does_not_bind_laravel_controller_method() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Http\\Request;\nclass UserController {\n  public function show(Request $request) { return $request->all(); }\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "show".into(),
            ..Default::default()
        };
        assert!(
            MiddlewareLaravelAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "controller method must not bind as middleware just because the file imports Request",
        );
    }

    #[test]
    fn does_not_bind_with_middleware_call_without_contract_shape() {
        let src: &[u8] = b"<?php\nclass Bootstrapper {\n  public function configure($app) { return $app->withMiddleware([]); }\n}\n";
        let tree = parse_php(src);
        let mut summary = FuncSummary {
            name: "configure".into(),
            ..Default::default()
        };
        summary.callees.push(crate::summary::CalleeSite {
            name: "app.withMiddleware".to_owned(),
            receiver: Some("app".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        assert!(
            MiddlewareLaravelAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

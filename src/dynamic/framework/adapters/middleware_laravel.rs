//! Phase 21 (Track M.3) — Laravel middleware adapter (PHP).
//!
//! Fires when the surrounding source declares a class with a `handle`
//! method whose signature matches Laravel's middleware contract
//! (`$request, Closure $next`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareLaravelAdapter;

const ADAPTER_NAME: &str = "middleware-laravel";

fn callee_is_laravel_middleware(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "handle" | "terminate" | "next" | "withMiddleware")
}

fn source_imports_laravel_middleware(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"Illuminate\\Http\\Request",
        b"Illuminate\\Foundation\\Http\\Middleware",
        b"function handle($request, Closure $next",
        b"function handle(Request $request, Closure $next",
        b"app/Http/Middleware",
        b"$middleware",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
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
        let matches_call = super::any_callee_matches(summary, callee_is_laravel_middleware);
        let matches_source = source_imports_laravel_middleware(file_bytes);
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
}

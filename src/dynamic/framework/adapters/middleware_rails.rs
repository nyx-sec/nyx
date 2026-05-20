//! Phase 21 (Track M.3) — Rack / Rails middleware adapter (Ruby).
//!
//! Fires when the surrounding source defines a Rack-shaped middleware
//! (`def call(env)`) or registers a Rails before-action callback.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareRailsAdapter;

const ADAPTER_NAME: &str = "middleware-rails";

fn callee_is_rails_middleware(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "call" | "before_action" | "around_action" | "after_action" | "use"
    )
}

fn source_imports_rails_middleware(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"def call(env)",
        b"def call (env",
        b"before_action ",
        b"after_action ",
        b"around_action ",
        b"Rails.application.config.middleware",
        b"Rack::Builder",
        b"@app = app",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for MiddlewareRailsAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_rails_middleware);
        let matches_source = source_imports_rails_middleware(file_bytes);
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_rack_middleware_call() {
        let src: &[u8] = b"class AuditMiddleware\n  def initialize(app); @app = app; end\n  def call(env)\n    @app.call(env)\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "call".into(),
            ..Default::default()
        };
        let binding = MiddlewareRailsAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("rack middleware binds");
        assert_eq!(binding.adapter, "middleware-rails");
        assert!(matches!(binding.kind, EntryKind::Middleware { .. }));
    }
}

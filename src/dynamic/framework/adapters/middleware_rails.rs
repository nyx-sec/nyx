//! Phase 21 (Track M.3) — Rack / Rails middleware adapter (Ruby).
//!
//! Fires when the surrounding source defines a Rack-shaped middleware
//! (`def call(env)`) or wires one into the Rails middleware stack.
//!
//! Notably does NOT fire for Rails controller actions even when the file
//! contains `before_action :name` / `after_action :name` callback
//! registrations — those are class-level controller DSL hooks, not Rack
//! middleware definitions.  Older `before_action ` / `after_action ` /
//! `around_action ` source needles were dropped because every typical
//! Rails controller mentions them, which made the adapter bind every
//! controller action as middleware (Phase 21 binding-stealing audit).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct MiddlewareRailsAdapter;

const ADAPTER_NAME: &str = "middleware-rails";

fn callee_is_rails_middleware(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "call" | "use")
}

fn source_has_rack_middleware_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"def call(env)",
        b"def call (env",
        b"Rails.application.config.middleware",
        b"Rack::Builder",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn looks_like_rails_controller(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"< ApplicationController",
        b"<ApplicationController",
        b"< ActionController::Base",
        b"<ActionController::Base",
        b"< ActionController::API",
        b"<ActionController::API",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_rack_entry(name: &str) -> bool {
    name == "call"
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_rails_middleware(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_rails_middleware(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_rails_middleware(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if looks_like_rails_controller(file_bytes) {
        return None;
    }
    let has_middleware_shape = source_has_rack_middleware_shape(file_bytes);
    let name_matches = name_is_rack_entry(&summary.name);
    let receiver_facts_allow = super::typed_receiver_facts_allow(
        summary,
        ssa_summary,
        callee_is_rails_middleware,
        typed_container_allows_rack_middleware,
    );
    if !receiver_facts_allow {
        return None;
    }
    let body_mounts_middleware = super::any_callee_matches(summary, callee_is_rails_middleware);
    let binds = (name_matches && has_middleware_shape) || body_mounts_middleware;
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

fn typed_container_allows_rack_middleware(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("rack") || lc.contains("rails") || lc.ends_with("middleware") || lc == "app"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

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

    #[test]
    fn does_not_bind_rails_controller_action() {
        let src: &[u8] = b"class UsersController < ApplicationController\n  before_action :authenticate\n  def index\n    @users = User.all\n    render :index\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "index".into(),
            ..Default::default()
        };
        assert!(
            MiddlewareRailsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "controller action must not bind as Rack middleware",
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_proc_call_collision() {
        let src: &[u8] = b"def call(env)\n  proc = env['callback']\n  proc.call('x')\nend\n";
        let tree = parse_ruby(src);
        let mut summary = FuncSummary {
            name: "call".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "proc.call".into(),
            receiver: Some("proc".into()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Proc".to_owned()));
        assert!(
            MiddlewareRailsAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none(),
            "Proc#call must not bind as Rack middleware",
        );
    }

    #[test]
    fn ssa_receiver_type_allows_rack_middleware_call() {
        let src: &[u8] = b"def mount(app)\n  app.call({})\nend\n";
        let tree = parse_ruby(src);
        let mut summary = FuncSummary {
            name: "mount".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "app.call".into(),
            receiver: Some("app".into()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((0, "Rack::Builder".to_owned()));
        let binding = MiddlewareRailsAdapter
            .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
            .expect("Rack receiver should bind");
        assert_eq!(binding.adapter, "middleware-rails");
    }
}

//! Phase 21 (Track M.3) — Ruby Sidekiq worker / scheduled-job adapter.
//!
//! Fires when the surrounding source carries a Sidekiq shape marker
//! (`include Sidekiq::Worker` / `Sidekiq::Job` / `sidekiq_options` /
//! `require 'sidekiq'`) AND either the function under analysis is the
//! worker entry point (`perform` / `perform_async` / `perform_in`) or
//! its body schedules a Sidekiq job (calls `perform_async` /
//! `perform_in`).
//!
//! The previous version of this adapter matched the bare callee name
//! `set` as a scheduling signal, which collided with unrelated methods
//! like `Set#add` / `Hash#[]=` (Phase 21 binding-stealing audit
//! follow-up).  `set` is now recognised only as part of the Sidekiq
//! shape gate; binding additionally requires the function itself to be
//! a worker entry or to call the real scheduling callees.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct ScheduledSidekiqAdapter;

const ADAPTER_NAME: &str = "scheduled-sidekiq";

fn callee_schedules_sidekiq(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "perform_async" | "perform_in")
}

fn name_is_sidekiq_entry(name: &str) -> bool {
    matches!(name, "perform" | "perform_async" | "perform_in")
}

fn source_has_sidekiq_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"include Sidekiq::Worker",
        b"include Sidekiq::Job",
        b"Sidekiq::Worker",
        b"Sidekiq::Job",
        b"require 'sidekiq'",
        b"require \"sidekiq\"",
        b"sidekiq_options",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_schedule(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [
        "sidekiq_options queue: :",
        "sidekiq_options queue: \"",
        "sidekiq_options queue: '",
    ] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close: &[char] = if needle.ends_with(':') {
                &[',', '\n']
            } else if needle.ends_with('"') {
                &['"']
            } else {
                &['\'']
            };
            if let Some(end) = after.find(|c: char| close.contains(&c)) {
                let v = after[..end].trim();
                if !v.is_empty() {
                    return Some(v.to_owned());
                }
            }
        }
    }
    None
}

impl FrameworkAdapter for ScheduledSidekiqAdapter {
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
        let has_shape = source_has_sidekiq_shape(file_bytes);
        if !has_shape {
            return None;
        }
        let name_matches = name_is_sidekiq_entry(&summary.name);
        let body_schedules = super::any_callee_matches(summary, callee_schedules_sidekiq);
        if !(name_matches || body_schedules) {
            return None;
        }
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::ScheduledJob {
                schedule: extract_schedule(file_bytes),
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_sidekiq_worker() {
        let src: &[u8] = b"class TickWorker\n  include Sidekiq::Worker\n  def perform(payload)\n    puts payload\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "perform".into(),
            ..Default::default()
        };
        let binding = ScheduledSidekiqAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("sidekiq binds");
        assert_eq!(binding.adapter, "scheduled-sidekiq");
        assert!(matches!(binding.kind, EntryKind::ScheduledJob { .. }));
    }

    #[test]
    fn does_not_bind_set_method_in_non_sidekiq_file() {
        // Method named `set` on a class with no Sidekiq tokens anywhere
        // — used to bind because the prior `callee_is_sidekiq` matched
        // the bare callee `set`, colliding with `Set#add` / `Hash#[]=`.
        let src: &[u8] = b"class MySet\n  def set(key, val)\n    @h[key] = val\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "set".into(),
            ..Default::default()
        };
        assert!(
            ScheduledSidekiqAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "bare `set` method outside Sidekiq scope must not bind",
        );
    }

    #[test]
    fn does_not_bind_unrelated_method_inside_sidekiq_file() {
        // Sidekiq-flavoured file but the analyser is asking about an
        // unrelated helper that neither shares the worker entry name
        // nor calls `perform_async` / `perform_in`.
        let src: &[u8] = b"# include Sidekiq::Worker\nclass MySet\n  def set(key)\n    @s.add(key)\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "set".into(),
            ..Default::default()
        };
        assert!(
            ScheduledSidekiqAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "non-worker helper in a Sidekiq file must not bind",
        );
    }
}

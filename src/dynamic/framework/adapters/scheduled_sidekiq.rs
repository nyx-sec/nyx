//! Phase 21 (Track M.3) — Ruby Sidekiq worker / scheduled-job adapter.
//!
//! Fires when the surrounding source includes the Sidekiq worker
//! mixin (`include Sidekiq::Worker` / `Sidekiq::Job`) or invokes a
//! Sidekiq scheduling callee (`perform_async`, `perform_in`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct ScheduledSidekiqAdapter;

const ADAPTER_NAME: &str = "scheduled-sidekiq";

fn callee_is_sidekiq(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "perform_async" | "perform_in" | "perform" | "set"
    )
}

fn source_imports_sidekiq(file_bytes: &[u8]) -> bool {
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
        let matches_call = super::any_callee_matches(summary, callee_is_sidekiq);
        let matches_source = source_imports_sidekiq(file_bytes);
        if matches_call || matches_source {
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
}

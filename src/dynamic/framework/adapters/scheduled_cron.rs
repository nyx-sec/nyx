//! Phase 21 (Track M.3) — Node cron scheduled-job adapter.
//!
//! Fires when the surrounding source imports a JavaScript cron library
//! (`node-cron`, `cron`, `node-schedule`) and the function body invokes
//! a job-scheduling callee.  The binding's [`EntryKind::ScheduledJob`]
//! is stamped with a best-effort `schedule` extracted from the source
//! (a `cron.schedule('* * * * *', fn)` literal); a missing literal
//! falls back to `None`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct ScheduledCronAdapter;

const ADAPTER_NAME: &str = "scheduled-cron";

fn callee_is_cron(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "schedule" | "CronJob" | "scheduleJob" | "RecurrenceRule" | "job"
    )
}

fn source_imports_cron(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('node-cron')",
        b"require(\"node-cron\")",
        b"from 'node-cron'",
        b"from \"node-cron\"",
        b"require('cron')",
        b"require(\"cron\")",
        b"from 'cron'",
        b"from \"cron\"",
        b"require('node-schedule')",
        b"require(\"node-schedule\")",
        b"from 'node-schedule'",
        b"from \"node-schedule\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_schedule(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [
        "cron.schedule('",
        "cron.schedule(\"",
        "schedule.scheduleJob('",
        "schedule.scheduleJob(\"",
        "new CronJob('",
        "new CronJob(\"",
    ] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close = if needle.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = after.find(close) {
                return Some(after[..end].to_owned());
            }
        }
    }
    None
}

impl FrameworkAdapter for ScheduledCronAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::JavaScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_cron);
        let matches_source = source_imports_cron(file_bytes);
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_node_cron_schedule() {
        let src: &[u8] = b"const cron = require('node-cron');\n\
            function tick(payload) { console.log(payload); }\n\
            cron.schedule('*/5 * * * *', tick);\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "tick".into(),
            ..Default::default()
        };
        let binding = ScheduledCronAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("node-cron binds");
        assert_eq!(binding.adapter, "scheduled-cron");
        if let EntryKind::ScheduledJob { schedule } = binding.kind {
            assert_eq!(schedule.as_deref(), Some("*/5 * * * *"));
        } else {
            panic!("expected ScheduledJob");
        }
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(ScheduledCronAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

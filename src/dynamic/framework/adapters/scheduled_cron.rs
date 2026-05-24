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
use crate::summary::ssa_summary::SsaFuncSummary;
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

fn name_registered_as_cron_job(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    const SITES: &[&str] = &[
        "cron.schedule(",
        "schedule.scheduleJob(",
        "nodeSchedule.scheduleJob(",
        "new CronJob(",
    ];
    for site in SITES {
        let mut cursor = 0;
        while let Some(idx) = text[cursor..].find(site) {
            let start = cursor + idx + site.len();
            let rest = &text[start..];
            let end = rest
                .find(['\n', ';'])
                .map(|n| start + n)
                .unwrap_or_else(|| text.len());
            let chunk = &text[start..end];
            if chunk
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '$')
                .any(|part| part == name)
            {
                return true;
            }
            cursor = end.min(text.len());
        }
    }
    false
}

fn typed_container_allows_cron(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("cron") || lc.contains("schedule")
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_cron(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_cron(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_cron(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_cron(file_bytes) {
        return None;
    }
    let registered = name_registered_as_cron_job(&summary.name, file_bytes);
    let cron_call = super::any_callee_matches(summary, callee_is_cron)
        && super::typed_receiver_facts_allow(
            summary,
            ssa_summary,
            callee_is_cron,
            typed_container_allows_cron,
        );
    if !(registered || cron_call) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

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
        assert!(
            ScheduledCronAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_unregistered_helper_in_cron_file() {
        let src: &[u8] = b"const cron = require('node-cron');\n\
            function tick(payload) { console.log(payload); }\n\
            function formatPayload(payload) { return String(payload); }\n\
            cron.schedule('*/5 * * * *', tick);\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "formatPayload".into(),
            ..Default::default()
        };
        assert!(
            ScheduledCronAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "cron import plus a schedule call must not bind unrelated helpers",
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_non_cron_schedule_call() {
        let src: &[u8] = b"const cron = require('node-cron');\n\
            function setup(payload) { queue.schedule(payload); }\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "setup".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "queue.schedule".to_owned(),
            receiver: Some("queue".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let ssa = SsaFuncSummary {
            typed_call_receivers: vec![(0, "TaskQueue".to_owned())],
            ..Default::default()
        };
        assert!(
            ScheduledCronAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_keeps_cron_schedule_call() {
        let src: &[u8] = b"const cron = require('node-cron');\n\
            function setup(payload) { cron.schedule('* * * * *', tick); }\n";
        let tree = parse_js(src);
        let mut summary = FuncSummary {
            name: "setup".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "cron.schedule".to_owned(),
            receiver: Some("cron".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let ssa = SsaFuncSummary {
            typed_call_receivers: vec![(0, "NodeCron".to_owned())],
            ..Default::default()
        };
        assert!(
            ScheduledCronAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}

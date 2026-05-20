//! Phase 21 (Track M.3) — Java Quartz scheduled-job adapter.
//!
//! Fires when the surrounding source imports the Quartz scheduling API
//! (`org.quartz.*`, `@Scheduled` from Spring's task-scheduling package)
//! and the function body invokes / annotates a job-execution callee.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct ScheduledQuartzAdapter;

const ADAPTER_NAME: &str = "scheduled-quartz";

fn callee_is_quartz(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "execute" | "scheduleJob" | "newJob" | "newTrigger" | "JobBuilder" | "TriggerBuilder"
    )
}

fn source_imports_quartz(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"org.quartz",
        b"@Scheduled",
        b"org.springframework.scheduling",
        b"import org.quartz",
        b"implements Job",
        b"@DisallowConcurrentExecution",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_schedule(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in [
        "@Scheduled(cron = \"",
        "@Scheduled(cron=\"",
        "withSchedule(CronScheduleBuilder.cronSchedule(\"",
        "cronSchedule(\"",
    ] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find('"') {
                return Some(after[..end].to_owned());
            }
        }
    }
    None
}

impl FrameworkAdapter for ScheduledQuartzAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_quartz);
        let matches_source = source_imports_quartz(file_bytes);
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_quartz_job() {
        let src: &[u8] = b"import org.quartz.Job;\n\
            public class TickJob implements Job {\n\
                public void execute(JobExecutionContext ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "execute".into(),
            ..Default::default()
        };
        let binding = ScheduledQuartzAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("quartz binds");
        assert_eq!(binding.adapter, "scheduled-quartz");
        assert!(matches!(binding.kind, EntryKind::ScheduledJob { .. }));
    }

    #[test]
    fn extracts_spring_cron_schedule() {
        let src: &[u8] = b"@Scheduled(cron = \"0 0 12 * * ?\")\n\
            public void tick() { }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "tick".into(),
            ..Default::default()
        };
        let binding = ScheduledQuartzAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("scheduled binds");
        if let EntryKind::ScheduledJob { schedule } = binding.kind {
            assert_eq!(schedule.as_deref(), Some("0 0 12 * * ?"));
        }
    }
}

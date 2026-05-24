//! Phase 21 (Track M.3) — Java Quartz scheduled-job adapter.
//!
//! Fires when the surrounding source imports the Quartz scheduling API
//! (`org.quartz.*`, `@Scheduled` from Spring's task-scheduling package)
//! and the function body invokes / annotates a job-execution callee.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
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

fn name_is_quartz_entry(name: &str) -> bool {
    name == "execute"
}

fn name_annotated_as_scheduled(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for needle in [
        format!("void {name}("),
        format!("public void {name}("),
        format!("private void {name}("),
        format!("protected void {name}("),
    ] {
        if let Some(idx) = text.find(&needle) {
            let before = &text[..idx];
            let since_prev_method = before
                .rfind("\n    ")
                .map(|prev| &before[prev + 1..])
                .unwrap_or(before);
            if since_prev_method.contains("@Scheduled") {
                return true;
            }
        }
    }
    false
}

fn typed_container_allows_quartz(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("quartz")
        || lc.contains("scheduler")
        || lc.contains("jobbuilder")
        || lc.contains("triggerbuilder")
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
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_quartz(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_quartz(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_quartz(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_quartz(file_bytes) {
        return None;
    }
    let job_entry = name_is_quartz_entry(&summary.name);
    let scheduled_method = name_annotated_as_scheduled(&summary.name, file_bytes);
    let quartz_call = super::any_callee_matches(summary, callee_is_quartz)
        && super::typed_receiver_facts_allow(
            summary,
            ssa_summary,
            callee_is_quartz,
            typed_container_allows_quartz,
        );
    if !(job_entry || scheduled_method || quartz_call) {
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

    #[test]
    fn skips_unrelated_helper_in_quartz_file() {
        let src: &[u8] = b"import org.quartz.Job;\n\
            public class TickJob implements Job {\n\
                public void execute(JobExecutionContext ctx) { }\n\
                public String format(String payload) { return payload; }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "format".into(),
            ..Default::default()
        };
        assert!(
            ScheduledQuartzAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_non_quartz_schedule_collision() {
        let src: &[u8] = b"import org.quartz.Job;\n\
            public class TickJob implements Job {\n\
                public void enqueue(Object payload) { queue.scheduleJob(payload); }\n\
            }\n";
        let tree = parse_java(src);
        let mut summary = FuncSummary {
            name: "enqueue".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "queue.scheduleJob".to_owned(),
            receiver: Some("queue".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "MailQueue".to_owned()));
        assert!(
            ScheduledQuartzAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }
}

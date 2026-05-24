//! Phase 21 (Track M.3) — Python Celery scheduled-task adapter.
//!
//! Fires when the surrounding source imports Celery (`from celery`,
//! `import celery`) and the function body carries a `@app.task` /
//! `@shared_task` / `@celery.task` decorator or invokes a Celery
//! scheduling callee.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;

pub struct ScheduledCeleryAdapter;

const ADAPTER_NAME: &str = "scheduled-celery";

fn callee_is_celery(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "task" | "shared_task" | "apply_async" | "delay" | "add_periodic_task"
    )
}

fn source_imports_celery(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"from celery",
        b"import celery",
        b"@app.task",
        b"@celery.task",
        b"@shared_task",
        b"celery.schedules",
        b"crontab(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_schedule(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["crontab(", "schedule=crontab(", "'schedule': crontab("] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            if let Some(end) = after.find(')') {
                let inner = after[..end].trim();
                if !inner.is_empty() {
                    return Some(inner.to_owned());
                }
            }
        }
    }
    None
}

fn name_registered_as_celery_task(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let needle = format!("def {name}(");
    let Some(def_idx) = text.find(&needle) else {
        return false;
    };
    let before = &text[..def_idx];
    let since_prev_def = before
        .rfind("\ndef ")
        .map(|idx| &before[idx + 1..])
        .unwrap_or(before);
    since_prev_def.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.contains("@shared_task")
            || trimmed.contains("@app.task")
            || trimmed.contains("@celery.task")
    })
}

fn typed_container_allows_celery(container: &str) -> bool {
    let lc = container.to_ascii_lowercase();
    lc.contains("celery") || lc.contains("task") || lc.contains("signature")
}

impl FrameworkAdapter for ScheduledCeleryAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_celery(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_celery(summary, ssa_summary, ast, file_bytes)
    }
}

fn detect_celery(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    _ast: tree_sitter::Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_celery(file_bytes) {
        return None;
    }
    let registered = name_registered_as_celery_task(&summary.name, file_bytes);
    let celery_call = super::any_callee_matches(summary, callee_is_celery)
        && super::typed_receiver_facts_allow(
            summary,
            ssa_summary,
            callee_is_celery,
            typed_container_allows_celery,
        );
    if !(registered || celery_call) {
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_celery_shared_task() {
        let src: &[u8] = b"from celery import shared_task\n\
            @shared_task\n\
            def tick(payload):\n    print(payload)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "tick".into(),
            ..Default::default()
        };
        let binding = ScheduledCeleryAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("celery binds");
        assert_eq!(binding.adapter, "scheduled-celery");
        assert!(matches!(binding.kind, EntryKind::ScheduledJob { .. }));
    }

    #[test]
    fn skips_unregistered_helper_in_celery_file() {
        let src: &[u8] = b"from celery import shared_task\n\
            @shared_task\n\
            def tick(payload):\n    print(payload)\n\
            def format_payload(payload):\n    return str(payload)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "format_payload".into(),
            ..Default::default()
        };
        assert!(
            ScheduledCeleryAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_receiver_type_rejects_non_celery_delay_collision() {
        let src: &[u8] = b"from celery import shared_task\n\
            def enqueue(payload):\n    mailer.delay(payload)\n";
        let tree = parse_python(src);
        let mut summary = FuncSummary {
            name: "enqueue".into(),
            ..Default::default()
        };
        summary.callees.push(CalleeSite {
            name: "mailer.delay".to_owned(),
            receiver: Some("mailer".to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "Mailer".to_owned()));
        assert!(
            ScheduledCeleryAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }
}

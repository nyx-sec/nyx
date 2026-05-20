//! Phase 21 (Track M.3) — Python Celery scheduled-task adapter.
//!
//! Fires when the surrounding source imports Celery (`from celery`,
//! `import celery`) and the function body carries a `@app.task` /
//! `@shared_task` / `@celery.task` decorator or invokes a Celery
//! scheduling callee.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_celery);
        let matches_source = source_imports_celery(file_bytes);
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
}

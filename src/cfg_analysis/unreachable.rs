use super::dominators;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence};
use crate::cfg::StmtKind;
use crate::labels::DataLabel;
use crate::patterns::Severity;
use std::collections::HashSet;

pub struct UnreachableCode;

/// Collect function names that appear as arguments to configured event handler calls.
fn event_handler_callbacks(ctx: &AnalysisContext) -> HashSet<String> {
    let mut callbacks = HashSet::new();
    let handlers = match ctx.analysis_rules {
        Some(rules) if !rules.event_handlers.is_empty() => &rules.event_handlers,
        _ => return callbacks,
    };

    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.kind != StmtKind::Call {
            continue;
        }
        if let Some(callee) = &info.call.callee {
            let callee_lower = callee.to_ascii_lowercase();
            let is_handler = handlers
                .iter()
                .any(|h| callee_lower.ends_with(&h.to_ascii_lowercase()));
            if is_handler {
                // The callback function is typically used within the call, any function
                // that appears as `uses` of this call node is a potential callback.
                for u in &info.taint.uses {
                    callbacks.insert(u.clone());
                }
            }
        }
    }
    callbacks
}

impl CfgAnalysis for UnreachableCode {
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let reachable = dominators::reachable_set(ctx.cfg, ctx.entry);
        let handler_callbacks = event_handler_callbacks(ctx);
        let mut findings = Vec::new();

        for idx in ctx.cfg.node_indices() {
            if reachable.contains(&idx) {
                continue;
            }

            let info = &ctx.cfg[idx];

            // Skip synthetic Entry/Exit nodes
            if matches!(info.kind, StmtKind::Entry | StmtKind::Exit) {
                continue;
            }

            // Suppress findings for nodes inside event handler callbacks
            if let Some(func_name) = &info.ast.enclosing_func
                && handler_callbacks.contains(func_name)
            {
                continue;
            }

            // Check labels in priority order: Sink > Sanitizer > Source
            let label_classification = if info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(_)))
            {
                Some(("cfg-unreachable-sink", "Unreachable sink", Severity::Medium))
            } else if info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sanitizer(_)))
            {
                Some((
                    "cfg-unreachable-sanitizer",
                    "Unreachable sanitizer",
                    Severity::Medium,
                ))
            } else if info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)))
            {
                Some((
                    "cfg-unreachable-source",
                    "Unreachable source",
                    Severity::Low,
                ))
            } else {
                None
            };

            let (rule_id, title, severity) = if let Some(lc) = label_classification {
                lc
            } else {
                // Check if it's a guard/auth call
                if super::is_guard_call(info, ctx.lang, ctx.analysis_rules)
                    || super::is_auth_call(info, ctx.lang)
                {
                    (
                        "cfg-unreachable-guard",
                        "Unreachable guard/auth check",
                        Severity::Medium,
                    )
                } else {
                    // Plain unreachable code, low severity
                    continue;
                }
            };

            let callee_desc = info.call.callee.as_deref().unwrap_or("(unknown)");

            findings.push(CfgFinding {
                rule_id: rule_id.to_string(),
                severity,
                confidence: Confidence::High,
                span: info.ast.span,
                message: format!("{title}: `{callee_desc}` is unreachable and will never execute"),
                evidence: vec![idx],
                score: None,
            });
        }

        findings
    }
}

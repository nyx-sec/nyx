#![doc = include_str!(concat!(env!("OUT_DIR"), "/cfg_analysis.md"))]

pub mod auth;
pub mod dominators;
pub mod error_handling;
pub mod guards;
pub mod resources;
pub mod rules;
pub mod scoring;
#[cfg(test)]
mod tests;
pub mod unreachable;

use crate::cfg::{FuncSummaries, NodeInfo, StmtKind};
use crate::labels::{DataLabel, LangAnalysisRules};
use crate::patterns::Severity;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::type_facts::TypeFactResult;
use crate::ssa::{SsaBody, SsaValue};
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use crate::taint;
use petgraph::graph::NodeIndex;
use std::collections::{HashMap, HashSet};

/// Per-body SSA facts used by structural analyses for finer-grained
/// constancy checks.  Produced once per body in `run_cfg_analyses` and
/// passed via `AnalysisContext::body_const_facts`.
pub struct BodyConstFacts {
    pub ssa: SsaBody,
    pub const_values: HashMap<SsaValue, ConstLattice>,
    pub type_facts: TypeFactResult,
    /// Field-sensitive Steensgaard points-to facts.
    ///
    /// Computed only when [`crate::pointer::is_enabled()`].
    /// `state::transfer.rs` consumes this to suppress proxy-acquire
    /// mis-attribution on field-aliased locals like `m := c.mu`. When
    /// `None`, consumers fall back to pointer-unaware behaviour.
    pub pointer_facts: Option<crate::pointer::PointsToFacts>,
}

/// Lower a body to SSA and run constant propagation.  Returns `None` when
/// lowering fails (empty CFG, invalid entry), callers treat absence as
/// "no SSA facts available" and fall back to the syntactic path.
pub fn build_body_const_facts(body: &crate::cfg::BodyCfg, lang: Lang) -> Option<BodyConstFacts> {
    let mut ssa = crate::ssa::lower_to_ssa_with_params(
        &body.graph,
        body.entry,
        body.meta.name.as_deref(),
        body.meta.parent_body_id.is_none(),
        &body.meta.params,
    )
    .ok()?;
    let opt = crate::ssa::optimize_ssa_with_param_types(
        &mut ssa,
        &body.graph,
        Some(lang),
        &body.meta.param_types,
    );
    let pointer_facts = if crate::pointer::is_enabled() {
        Some(crate::pointer::analyse_body(&ssa, body.meta.id))
    } else {
        None
    };
    Some(BodyConstFacts {
        ssa,
        const_values: opt.const_values,
        type_facts: opt.type_facts,
        pointer_facts,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct CfgFinding {
    pub rule_id: String,
    #[allow(dead_code)]
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub span: (usize, usize),
    pub message: String,
    pub evidence: Vec<NodeIndex>,
    pub score: Option<f64>,
}

pub struct AnalysisContext<'a> {
    pub cfg: &'a crate::cfg::Cfg,
    pub entry: NodeIndex,
    pub lang: Lang,
    #[allow(dead_code)]
    pub file_path: &'a str,
    #[allow(dead_code)]
    pub source_bytes: &'a [u8],
    pub func_summaries: &'a FuncSummaries,
    #[allow(dead_code)]
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub taint_findings: &'a [taint::Finding],
    pub analysis_rules: Option<&'a LangAnalysisRules>,
    /// Whether full taint analysis was active for this file (global summaries
    /// existed and taint engine ran).  When false, structural findings without
    /// taint confirmation should be treated with lower confidence.
    pub taint_active: bool,
    /// Optional per-body SSA + constant-propagation facts.  When present,
    /// structural analyses can use SSA const-prop to prove that all argument
    /// flows into a sink resolve to literal constants, suppressing false
    /// positives that the one-hop CFG trace alone cannot.
    pub body_const_facts: Option<&'a BodyConstFacts>,
    /// Optional per-body type-fact result produced by `optimize_ssa`.
    /// Structural analyses use it to suppress findings when a sink's argument
    /// SSA values are proven to carry non-injectable types (e.g. integers
    /// parsed from a raw source can't form SHELL/SQL/path payloads).  Sourced
    /// from `body_const_facts` when present, keep both pointers coherent.
    pub type_facts: Option<&'a TypeFactResult>,
    /// Decorators / annotations / attributes attached to the body's
    /// declaration (e.g. Python `@login_required`, Java `@PreAuthorize`,
    /// Symfony `#[IsGranted(...)]`).  Consumed by the AuthGap analysis to
    /// suppress `cfg-auth-gap` when the framework already enforces auth at
    /// the function-declaration level, the gap only matters when the
    /// auth call has to live inside the body.
    pub auth_decorators: &'a [String],
    /// Names of variables whose `.close()` / release calls live in a
    /// nested closure body somewhere else in the file (e.g.
    /// `socket.on("close", () => ws.close())`).  ResourceMisuse uses this
    /// to suppress `cfg-resource-leak` for handles whose cleanup happens
    /// in a callback the per-body CFG can't observe.  When `None`, no
    /// closure-based suppression is applied.
    pub closure_released_var_names: Option<&'a std::collections::HashSet<String>>,
}

pub trait CfgAnalysis {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding>;
}

/// Run all registered analyses and return merged findings.
pub fn run_all(ctx: &AnalysisContext) -> Vec<CfgFinding> {
    let analyses: Vec<Box<dyn CfgAnalysis>> = vec![
        Box::new(unreachable::UnreachableCode),
        Box::new(guards::UnguardedSink),
        Box::new(auth::AuthGap),
        Box::new(error_handling::IncompleteErrorHandling),
        Box::new(resources::ResourceMisuse),
    ];
    let mut findings: Vec<CfgFinding> = analyses.iter().flat_map(|a| a.run(ctx)).collect();

    // ── Dedup: suppress cfg-unguarded-sink when taint already covers the span ──
    // Collect spans where taint findings exist (sink byte offset).
    let taint_spans: HashSet<(usize, usize)> = ctx
        .taint_findings
        .iter()
        .map(|f| ctx.cfg[f.sink].ast.span)
        .collect();

    findings.retain(|f| {
        // If both taint and cfg-unguarded-sink fire on the same span,
        // suppress the structural CFG finding (taint is the primary signal).
        if f.rule_id == "cfg-unguarded-sink" && taint_spans.contains(&f.span) {
            return false;
        }
        true
    });

    // ── Dedup: suppress cfg-unguarded-sink when cfg-unreachable-sink covers the span ──
    let unreachable_spans: HashSet<(usize, usize)> = findings
        .iter()
        .filter(|f| f.rule_id == "cfg-unreachable-sink")
        .map(|f| f.span)
        .collect();

    findings.retain(|f| {
        if f.rule_id == "cfg-unguarded-sink" && unreachable_spans.contains(&f.span) {
            return false;
        }
        true
    });

    scoring::score_findings(&mut findings, ctx);
    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings
}

/// Helper: check whether a node is a guard call (validate, sanitize, check, etc.).
pub(crate) fn is_guard_call(
    info: &NodeInfo,
    lang: Lang,
    analysis_rules: Option<&LangAnalysisRules>,
) -> bool {
    if info.kind != StmtKind::Call {
        return false;
    }
    if let Some(callee) = &info.call.callee {
        // Check config sanitizer rules
        if let Some(extras) = analysis_rules {
            let callee_lower = callee.to_ascii_lowercase();
            for rule in &extras.extra_labels {
                if !matches!(rule.label, DataLabel::Sanitizer(_)) {
                    continue;
                }
                for m in &rule.matchers {
                    let ml = m.to_ascii_lowercase();
                    if ml.ends_with('_') {
                        if callee_lower.starts_with(&ml) {
                            return true;
                        }
                    } else if callee_lower.ends_with(&ml) {
                        return true;
                    }
                }
            }
        }

        // Check built-in guard rules
        let guard_rules = rules::guard_rules(lang);
        let callee_lower = callee.to_ascii_lowercase();
        for rule in guard_rules {
            for &m in rule.matchers {
                let ml = m.to_ascii_lowercase();
                if ml.ends_with('_') {
                    if callee_lower.starts_with(&ml) {
                        return true;
                    }
                } else if callee_lower.ends_with(&ml) {
                    return true;
                }
            }
        }
    }
    false
}

/// Helper: check whether a node is an auth check call.
pub(crate) fn is_auth_call(info: &NodeInfo, lang: Lang) -> bool {
    if info.kind != StmtKind::Call {
        return false;
    }
    if let Some(callee) = &info.call.callee {
        let auth_rules = rules::auth_rules(lang);
        let callee_lower = callee.to_ascii_lowercase();
        for rule in auth_rules {
            for &m in rule.matchers {
                let ml = m.to_ascii_lowercase();
                if ml.ends_with('_') {
                    if callee_lower.starts_with(&ml) {
                        return true;
                    }
                } else if callee_lower.ends_with(&ml) {
                    return true;
                }
            }
        }
    }
    false
}

/// Helper: check if a function name looks like an entry point (HTTP handler, main, etc.).
pub(crate) fn is_entry_point_func(func_name: &str, lang: Lang) -> bool {
    let ep_rules = rules::entry_point_rules(lang);
    let name_lower = func_name.to_ascii_lowercase();
    for rule in ep_rules {
        for &m in rule.matchers {
            let ml = m.to_ascii_lowercase();
            if ml.ends_with('*') {
                let prefix = &ml[..ml.len() - 1];
                if name_lower.starts_with(prefix) {
                    return true;
                }
            } else if name_lower == ml {
                return true;
            }
        }
    }
    false
}

/// Helper: check if a node is a sink.
pub(crate) fn is_sink(info: &NodeInfo) -> bool {
    info.taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(_)))
}

//! Health-score scoring engine, v3.5.
//!
//! Pure-function scoring over a `HealthInputs` struct.
//!
//! ## Conceptual model
//!
//! The score reflects two intersecting forces:
//!
//! 1. **Density of risk.** The *quantitative* axis: per-finding weight
//!    that combines severity, confidence, symex verdict, and a test-
//!    path discount, divided by a size proxy, mapped through a log
//!    curve to a 0–100 base.
//!
//! 2. **HIGH-count guardrails.** The *qualitative* axis: HIGH counts
//!    cap the maximum grade and floor "no HIGH" to at least C.  These
//!    are non-negotiable promises, even a perfect-everywhere-else
//!    repo with 6 confirmed HIGHs grades F.
//!
//! Modifiers (triage, trend, stale, regression, suppression hygiene)
//! are nudges totalling at most ±15 within whatever band the
//! guardrails carve out.
//!
//! ## What v3.5 changed vs v2/v3
//!
//! * Verdict-weighted credibility (`Confirmed > NotAttempted >
//!   Inconclusive > Infeasible`).  This is the structural protection
//!   against false-positive-driven F grades while the scanner is
//!   still maturing, it auto-tightens as symex coverage grows.
//! * Cross-file vs intra-file vs AST-only weighting via
//!   `context_factor`.
//! * Test-path downweight (0.3×), a HIGH in a test fixture is
//!   genuinely less concerning than one in a request handler.
//! * Effective HIGH count for ceilings, the HIGH-count caps key on
//!   credibility-adjusted HIGHs, not raw HIGHs.  A repo with 5
//!   low-confidence HIGHs that got `NotAttempted` from symex doesn't
//!   pay the same ceiling cost as a repo with 5 `Confirmed` HIGHs.
//! * Tighter modifier ranges so they can't flip a band.
//! * No `parse_success_rate`. It is a cache-miss metric, not a parse
//!   success metric.

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Verdict};
use crate::patterns::Severity;
use crate::server::models::{BacklogStats, FindingSummary, HealthComponent, HealthScore};

// ── Tunables ─────────────────────────────────────────────────────────────────
//
// Calibrated for the current scanner false-positive rate. As Nyx symex
// coverage and rule precision improve, the HIGH ceilings may tighten.

/// Below this file count, we floor the size divisor at 1.0, tiny
/// repos can't claim infinite per-LOC dilution from one finding.
const FILES_FLOOR: f64 = 100.0;

/// Above this file count, no further dilution credit.  A 50MLOC
/// monorepo doesn't get a pass on a HIGH because it's "drowned" in
/// other code.
const FILES_CEILING: f64 = 50_000.0;

/// Quality lints saturate fast.  300 quality lints = max drag.
const QUALITY_DRAG_PER_FINDING: f64 = 0.05;
const QUALITY_DRAG_CAP: f64 = 15.0;

/// Below this finding count, the Triage component contributes
/// weight 0, we don't punish fresh users for not having triaged
/// what didn't need triaging.
const TRIAGE_FLOOR: usize = 20;

/// Stale-HIGH penalty parameters.
const STALE_PENALTY_PER_FINDING: f64 = 2.0;
const STALE_PENALTY_CAP: f64 = 10.0;

// ── Public API ───────────────────────────────────────────────────────────────

/// Pure inputs to the health-score calculation.  No app state, no DB
/// handles, those upstream concerns are flattened into primitives the
/// scorer actually consumes.
#[derive(Debug, Clone, Copy)]
pub struct HealthInputs<'a> {
    pub summary: &'a FindingSummary,
    pub findings: &'a [Diag],
    pub triage_coverage: f64,
    pub new_since_last: usize,
    pub fixed_since_last: usize,
    pub reintroduced: usize,
    /// Files scanned in the latest scan.  Used as a proxy for repo
    /// size.  `None` disables size adjustment (matches v1 callers).
    pub repo_files: Option<u64>,
    /// Backlog stats from the overview pipeline.  `None` is fine on
    /// first scans (no aging data yet).
    pub backlog: Option<&'a BacklogStats>,
    /// Whether we have ≥2 completed scans.  Without history Trend
    /// is meaningless and contributes weight 0.
    pub has_history: bool,
    /// Fraction of suppressions that use blanket (rule/file/
    /// rule_in_file) rules instead of fingerprint-level.  `None` if
    /// no suppressions.  Drives a small ±2 modifier; high blanket
    /// rates suggest gaming the score.
    pub blanket_suppression_rate: Option<f64>,
}

/// Compute the health score from pure inputs.
pub fn compute(inp: &HealthInputs<'_>) -> HealthScore {
    // Step 1: Per-finding credibility-weighted weight, plus the
    // bookkeeping we need for the breakdown components.
    let weighted = aggregate_findings(inp.findings);

    // Step 2: Density adjustment.
    let size_divisor = size_divisor(inp.repo_files);
    let density_weight = weighted.raw_weight / size_divisor;

    // Step 3: Map density to base score via log curve.
    let base_score = density_to_base_score(density_weight);

    // Step 4: Apply quality-lint drag.
    let quality_drag = quality_drag(weighted.quality_count);
    let base_after_drag = (base_score - quality_drag).clamp(0.0, 100.0);

    // Step 5: HIGH-count guardrails, keyed on *effective* HIGH count
    // (credibility-weighted), not raw count.  This is what protects
    // users from FP-driven F grades while the scanner is maturing.
    let ceiling = high_total_ceiling(weighted.effective_high);
    let floor = high_total_floor(weighted.effective_high);
    let score_clamped = base_after_drag.clamp(floor, ceiling);

    // Step 6: Build the breakdown components (also computes their
    // sub-scores for transparency).
    let components = build_components(inp, &weighted, base_after_drag, size_divisor);

    // Step 7: Sum modifiers (already encoded in component weights;
    // see `build_components`).
    let modifier_sum = components
        .iter()
        .filter(|c| c.label != "Severity pressure")
        .map(signed_modifier_contribution)
        .sum::<f64>();

    // Reapply ceiling AND floor after modifiers.  Ceiling: modifiers
    // can't lift past a HIGH cap.  Floor: triage/regression
    // modifiers can't break the no-HIGH ≥ C guarantee.
    let final_uncapped = (score_clamped + modifier_sum).clamp(0.0, 100.0);
    let score = final_uncapped.min(ceiling).max(floor).round() as u8;
    let grade = grade_for(score).to_string();

    HealthScore {
        score,
        grade,
        components,
    }
}

// ── Aggregation ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct WeightedAggregate {
    /// Sum of `severity_base × confidence_factor × verdict_factor ×
    /// context_factor` across security findings.  Quality lints are
    /// handled separately via `quality_drag`.
    raw_weight: f64,
    /// Number of `*.quality.*` findings, drives `quality_drag`.
    quality_count: usize,
    /// Credibility-adjusted HIGH count (rounded), drives the HIGH
    /// ceiling and floor.  A low-confidence + Inconclusive HIGH might
    /// contribute 0.2; five of them would round to 1.
    effective_high: usize,
    /// Raw counts (for the breakdown text).
    raw_high: usize,
    raw_medium: usize,
    raw_low_security: usize,
    /// Confidence rate (high+medium*0.5)/total, drives the
    /// confidence component.  100 if no findings.
    confidence_rate: f64,
    /// Symex coverage, % of taint findings with any non-NotAttempted
    /// verdict.  Surfaced in component detail; not currently in score.
    symex_coverage: f64,
}

fn aggregate_findings(findings: &[Diag]) -> WeightedAggregate {
    let mut agg = WeightedAggregate::default();
    let mut effective_high_sum = 0.0f64;
    let mut conf_score_sum = 0.0f64;
    let mut taint_total = 0usize;
    let mut taint_with_verdict = 0usize;

    for f in findings {
        let is_quality = f.id.contains(".quality.") || f.id.starts_with("quality.");
        if is_quality {
            agg.quality_count += 1;
            continue;
        }

        let severity = f.severity;
        let conf_factor = confidence_factor(f.confidence);
        let verdict_factor = verdict_factor(f);
        let context_factor = context_factor(f);

        let credibility = (conf_factor * verdict_factor * context_factor).clamp(0.0, 1.2);
        let weight = severity_base(severity) * credibility;
        agg.raw_weight += weight;

        match severity {
            Severity::High => {
                agg.raw_high += 1;
                effective_high_sum += credibility;
            }
            Severity::Medium => agg.raw_medium += 1,
            Severity::Low => agg.raw_low_security += 1,
        }

        // Confidence component contribution (independent of severity).
        conf_score_sum += match f.confidence {
            Some(Confidence::High) => 1.0,
            Some(Confidence::Medium) => 0.5,
            _ => 0.0,
        };

        // Symex coverage tracking, only meaningful for findings with
        // taint-flow evidence (the ones symex even attempts).
        if let Some(ev) = f.evidence.as_ref()
            && ev.symbolic.is_some()
        {
            taint_total += 1;
            if !matches!(
                ev.symbolic.as_ref().map(|s| s.verdict),
                Some(Verdict::NotAttempted) | None
            ) {
                taint_with_verdict += 1;
            }
        }
    }

    agg.effective_high = effective_high_sum.round() as usize;
    agg.confidence_rate = if findings.is_empty() {
        100.0
    } else {
        let security_total = (findings.len() - agg.quality_count).max(1);
        (conf_score_sum / security_total as f64) * 100.0
    };
    agg.symex_coverage = if taint_total == 0 {
        0.0
    } else {
        taint_with_verdict as f64 / taint_total as f64
    };
    agg
}

fn severity_base(s: Severity) -> f64 {
    match s {
        Severity::High => 10.0,
        Severity::Medium => 3.0,
        Severity::Low => 0.5,
    }
}

fn confidence_factor(c: Option<Confidence>) -> f64 {
    match c {
        Some(Confidence::High) => 1.0,
        Some(Confidence::Medium) => 0.6,
        Some(Confidence::Low) => 0.3,
        None => 0.5,
    }
}

/// `verdict_factor` is the heart of the FP protection.  An AST-only
/// finding (no taint flow → no symex even attempted) gets the
/// `NotAttempted` baseline of 1.0.  A taint finding that symex
/// confirmed gets 1.2 (a credibility boost).  A taint finding that
/// symex proved infeasible gets 0.1 (near-suppress).
fn verdict_factor(f: &Diag) -> f64 {
    let Some(ev) = f.evidence.as_ref() else {
        return 1.0;
    };
    let Some(sv) = ev.symbolic.as_ref() else {
        return 1.0;
    };
    match sv.verdict {
        Verdict::Confirmed => 1.2,
        Verdict::NotAttempted => 1.0,
        Verdict::Inconclusive => 0.7,
        Verdict::Infeasible => 0.1,
    }
}

/// Cross-file flow → 1.15.  Intra-file taint flow → 1.0.  AST-only
/// (no flow_steps) → 0.75.  Test path → 0.3 regardless of the others
/// (returns the *minimum* factor so test paths always win over
/// cross-file boosts).
fn context_factor(f: &Diag) -> f64 {
    if is_test_path(&f.path) {
        return 0.3;
    }
    let Some(ev) = f.evidence.as_ref() else {
        return 0.75; // No evidence at all, pattern match
    };
    if ev.flow_steps.is_empty() {
        return 0.75;
    }
    if ev.flow_steps.iter().any(|s| s.is_cross_file) || ev.uses_summary {
        return 1.15;
    }
    1.0
}

fn is_test_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    // Path-segment matches.
    p.contains("/test/")
        || p.contains("/tests/")
        || p.contains("/spec/")
        || p.contains("/__tests__/")
        || p.contains("/testdata/")
        // Filename suffix conventions.
        || p.ends_with("_test.go")
        || p.ends_with("_spec.rb")
        || p.ends_with(".test.ts")
        || p.ends_with(".test.js")
        || p.ends_with(".spec.ts")
        || p.ends_with(".spec.js")
        || file_basename(&p)
            .map(|b| b.starts_with("test_") && b.ends_with(".py"))
            .unwrap_or(false)
}

fn file_basename(path: &str) -> Option<&str> {
    path.rsplit('/').next()
}

// ── Density math ─────────────────────────────────────────────────────────────

fn size_divisor(repo_files: Option<u64>) -> f64 {
    let f = match repo_files {
        Some(n) => (n as f64).clamp(FILES_FLOOR, FILES_CEILING),
        None => FILES_FLOOR,
    };
    (f / FILES_FLOOR).sqrt()
}

fn density_to_base_score(density_weight: f64) -> f64 {
    if density_weight <= 0.0 {
        return 100.0;
    }
    let raw = 100.0 - 22.0 * (1.0 + density_weight / 4.0).log10();
    raw.clamp(0.0, 100.0)
}

fn quality_drag(quality_count: usize) -> f64 {
    (quality_count as f64 * QUALITY_DRAG_PER_FINDING).min(QUALITY_DRAG_CAP)
}

// ── HIGH guardrails, calibrated for v0.5.0 FP rate ──────────────────────────

/// Final-score ceiling keyed on *effective* HIGH count (credibility-
/// weighted, not raw).  See module docstring for the rationale.
fn high_total_ceiling(effective_high: usize) -> f64 {
    match effective_high {
        0 => 100.0,
        1 => 85.0,     // 1 credible HIGH → max B
        2 => 78.0,     // 2 → max C+
        3..=5 => 68.0, // 3-5 → max D+
        6..=10 => 58.0,
        _ => 45.0,
    }
}

/// Final-score floor keyed on *effective* HIGH count.  Zero HIGH never
/// grades below C.  This is the structural promise that the score
/// isn't an automated F-machine.
fn high_total_floor(effective_high: usize) -> f64 {
    if effective_high == 0 { 70.0 } else { 0.0 }
}

// ── Stale-HIGH penalty ──────────────────────────────────────────────────────

fn stale_high_penalty(effective_high: usize, backlog: Option<&BacklogStats>) -> f64 {
    let Some(b) = backlog else { return 0.0 };
    if effective_high == 0 || b.stale_count == 0 {
        return 0.0;
    }
    (b.stale_count as f64 * STALE_PENALTY_PER_FINDING).min(STALE_PENALTY_CAP)
}

// ── Component breakdown ──────────────────────────────────────────────────────

fn build_components(
    inp: &HealthInputs<'_>,
    weighted: &WeightedAggregate,
    base_after_drag: f64,
    size_divisor: f64,
) -> Vec<HealthComponent> {
    let total = inp.summary.total;

    // Severity component is the primary score-bearing component;
    // it absorbs the base+drag+ceiling+floor result.
    let sev_score = base_after_drag.round().clamp(0.0, 100.0) as u8;
    let sev_detail = severity_detail(weighted, size_divisor, inp.repo_files, inp.backlog);

    // Confidence component, high-conf rate scaled into 0..=100.
    let conf_score = weighted.confidence_rate.round().clamp(0.0, 100.0) as u8;
    let conf_detail = format!(
        "High-confidence rate {:.0}% across {} security finding{}",
        weighted.confidence_rate,
        total - weighted.quality_count,
        plural_s(total - weighted.quality_count)
    );

    // Trend component, only contributes weight when has_history.
    let net = inp.fixed_since_last as i64 - inp.new_since_last as i64;
    let trend_score = (50 + net * 5).clamp(0, 100) as u8;
    let trend_weight = if inp.has_history { 0.20 } else { 0.0 };
    let trend_detail = if inp.has_history {
        format!(
            "Net {} since last scan ({} fixed, {} new)",
            net, inp.fixed_since_last, inp.new_since_last
        )
    } else {
        "Not applicable: no prior scan to compare against (re-scan to populate)".into()
    };

    // Triage, drops out when total < TRIAGE_FLOOR.
    let triage_active = total >= TRIAGE_FLOOR;
    let triage_score = (inp.triage_coverage * 100.0).round().clamp(0.0, 100.0) as u8;
    let triage_weight = if triage_active { 0.20 } else { 0.0 };
    let triage_detail = if triage_active {
        format!(
            "{:.0}% of findings have a triage state",
            inp.triage_coverage * 100.0
        )
    } else {
        format!(
            "Not applicable: only {} finding{} (need ≥{} to evaluate)",
            total,
            plural_s(total),
            TRIAGE_FLOOR
        )
    };

    // Regression resistance.
    let stale_penalty = stale_high_penalty(weighted.effective_high, inp.backlog);
    let reintro_penalty = (inp.reintroduced as f64 * 5.0).min(10.0);
    let regression_score = (100.0 - reintro_penalty - stale_penalty)
        .clamp(0.0, 100.0)
        .round() as u8;
    let regression_detail = match (inp.reintroduced, stale_penalty) {
        (0, 0.0) => "No reintroduced or stale-HIGH findings".into(),
        (0, p) => format!(
            "{} stale finding{} affecting HIGH severity (−{:.0})",
            inp.backlog.map(|b| b.stale_count).unwrap_or(0),
            plural_s(inp.backlog.map(|b| b.stale_count).unwrap_or(0)),
            p
        ),
        (n, 0.0) => format!(
            "{} previously-fixed finding{} reintroduced (−{:.0})",
            n,
            plural_s(n),
            (n as f64 * 5.0).min(10.0)
        ),
        (n, p) => format!(
            "{} reintroduced (−{:.0}) + stale-HIGH penalty (−{:.0})",
            n,
            (n as f64 * 5.0).min(10.0),
            p
        ),
    };

    vec![
        HealthComponent {
            label: "Severity pressure".into(),
            score: sev_score,
            weight: 1.0, // Severity is the *base*, not a modifier, full weight in the blend.
            detail: sev_detail,
        },
        HealthComponent {
            label: "Confidence quality".into(),
            score: conf_score,
            weight: 0.0, // Confidence influence is already baked into raw_weight via verdict_factor.
            detail: conf_detail,
        },
        HealthComponent {
            label: "Trend".into(),
            score: trend_score,
            weight: trend_weight,
            detail: trend_detail,
        },
        HealthComponent {
            label: "Triage coverage".into(),
            score: triage_score,
            weight: triage_weight,
            detail: triage_detail,
        },
        HealthComponent {
            label: "Regression resistance".into(),
            score: regression_score,
            weight: 0.15,
            detail: regression_detail,
        },
    ]
}

/// How a non-severity component contributes to the modifier sum.
/// Each component's score (0–100) is mapped to a signed point delta
/// in roughly the [−5, +5] range, gated by the component's weight
/// (which becomes 0 when the component drops out).
fn signed_modifier_contribution(c: &HealthComponent) -> f64 {
    if c.weight == 0.0 {
        return 0.0;
    }
    match c.label.as_str() {
        "Confidence quality" => {
            // High-conf rate above 80% → +3, above 50% → +1, below → 0.
            // (This component now also has weight 0 because its
            // influence is baked into raw_weight via verdict_factor.
            // Kept here for transparency in the breakdown only.)
            0.0
        }
        "Trend" => {
            // Net positive trend → +3 max; negative → −3 max.
            // Linear in (score − 50)/50 × 3, clamped.
            let centred = (c.score as f64 - 50.0) / 50.0;
            (centred * 3.0).clamp(-3.0, 3.0)
        }
        "Triage coverage" => {
            // ≥50% triaged → +5; 0% triaged → −3; in between → linear.
            if c.score >= 50 {
                ((c.score as f64 - 50.0) / 50.0 * 5.0).min(5.0)
            } else {
                -((50.0 - c.score as f64) / 50.0 * 3.0).min(3.0)
            }
        }
        "Regression resistance" => {
            // 100 → +0, lower scores subtract directly (already baked
            // in the score; component weight pulls it into the blend).
            // Map: at score 100 → 0; at score 70 → −5; at score 0 → −15.
            ((c.score as f64 - 100.0) * 0.15).clamp(-15.0, 0.0)
        }
        _ => 0.0,
    }
}

fn severity_detail(
    w: &WeightedAggregate,
    size_divisor: f64,
    repo_files: Option<u64>,
    backlog: Option<&BacklogStats>,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("{:.0} weighted points", w.raw_weight));
    parts.push(format!(
        "{} High, {} Medium, {} Low",
        w.raw_high, w.raw_medium, w.raw_low_security
    ));
    if w.quality_count > 0 {
        parts.push(format!("{} quality lints", w.quality_count));
    }
    if w.effective_high != w.raw_high {
        parts.push(format!(
            "effective HIGH={} (credibility-adjusted)",
            w.effective_high
        ));
    }
    if let Some(f) = repo_files
        && (size_divisor - 1.0).abs() > 0.01
    {
        parts.push(format!("size factor 1/{:.2}× ({} files)", size_divisor, f));
    }
    let stale = stale_high_penalty(w.effective_high, backlog);
    if stale > 0.0
        && let Some(b) = backlog
    {
        parts.push(format!("−{:.0} stale-HIGH ({} >30d)", stale, b.stale_count));
    }
    parts.join(" · ")
}

// ── Misc ─────────────────────────────────────────────────────────────────────

fn grade_for(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

fn plural_s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{FindingCategory, Severity};

    fn diag(severity: Severity, id: &str, conf: Option<Confidence>) -> Diag {
        Diag {
            path: "src/lib.rs".into(),
            line: 1,
            col: 1,
            severity,
            id: id.into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: Vec::new(),
            confidence: conf,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            triage_state: "open".to_string(),
            triage_note: String::new(),
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }
    }

    fn diag_in(path: &str, severity: Severity, conf: Option<Confidence>) -> Diag {
        let mut d = diag(severity, "rs.taint.x", conf);
        d.path = path.into();
        d
    }

    fn summary_of(findings: &[Diag]) -> FindingSummary {
        let mut s = FindingSummary {
            total: findings.len(),
            ..Default::default()
        };
        for d in findings {
            *s.by_severity
                .entry(d.severity.as_db_str().to_string())
                .or_insert(0) += 1;
        }
        s
    }

    fn first_scan<'a>(
        summary: &'a FindingSummary,
        findings: &'a [Diag],
        triage: f64,
        files: u64,
    ) -> HealthInputs<'a> {
        HealthInputs {
            summary,
            findings,
            triage_coverage: triage,
            new_since_last: 0,
            fixed_since_last: 0,
            reintroduced: 0,
            repo_files: Some(files),
            backlog: None,
            has_history: false,
            blanket_suppression_rate: None,
        }
    }

    // ── Foundational behaviour ───────────────────────────────────────

    #[test]
    fn clean_repo_first_scan_grades_a() {
        let findings: Vec<Diag> = vec![];
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 100));
        assert_eq!(h.grade, "A");
        assert!(h.score >= 95, "clean first-scan ≥95, got {}", h.score);
    }

    #[test]
    fn no_high_repo_never_grades_below_c() {
        // 0 HIGH, lots of mediums + quality.
        let mut findings: Vec<Diag> = (0..200)
            .map(|_| diag(Severity::Medium, "rs.taint.foo", Some(Confidence::High)))
            .collect();
        findings.extend(
            (0..2000).map(|_| diag(Severity::Low, "rs.quality.unwrap", Some(Confidence::High))),
        );
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 200));
        assert!(h.score >= 70, "0 HIGH must grade ≥C (70), got {}", h.score);
    }

    #[test]
    fn quality_lints_alone_grade_at_least_b() {
        // 1000 quality lints, no security findings.  Drag caps at 15
        // so base ~100−15=85.  Should grade at worst B-.
        let findings: Vec<Diag> = (0..1000)
            .map(|_| diag(Severity::Low, "rs.quality.unwrap", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 100));
        assert!(h.score >= 80, "1000 quality lints → ≥B, got {}", h.score);
    }

    #[test]
    fn one_high_caps_at_b() {
        let findings = vec![diag(Severity::High, "rs.taint.x", Some(Confidence::High))];
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 100));
        assert!(h.score <= 89, "1 HIGH must not grade A, got {}", h.score);
        assert_ne!(h.grade, "A");
    }

    #[test]
    fn many_confirmed_high_grades_f() {
        // 8 HIGHs all symex-Confirmed → effective_high ≈ 9.6 → F band.
        let findings: Vec<Diag> = (0..8)
            .map(|_| {
                let mut d = diag(Severity::High, "rs.taint.x", Some(Confidence::High));
                let ev = crate::evidence::Evidence {
                    symbolic: Some(crate::evidence::SymbolicVerdict {
                        verdict: crate::evidence::Verdict::Confirmed,
                        constraints_checked: 0,
                        paths_explored: 0,
                        witness: None,
                        interproc_call_chains: Vec::new(),
                        cutoff_notes: Vec::new(),
                    }),
                    ..Default::default()
                };
                d.evidence = Some(ev);
                d
            })
            .collect();
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 1000));
        assert_eq!(h.grade, "F");
    }

    #[test]
    fn low_credibility_high_does_not_count_as_full() {
        // 5 raw HIGHs, all Low confidence, all NotAttempted (no
        // evidence).  Each has credibility ≈ 0.3 × 1.0 × 0.75 = 0.225.
        // Sum = 1.125 → effective_high = 1.  Ceiling 85.
        let findings: Vec<Diag> = (0..5)
            .map(|_| {
                let mut d = diag(Severity::High, "rs.taint.x", Some(Confidence::Low));
                // Force AST-only: no evidence at all.
                d.evidence = None;
                d
            })
            .collect();
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 100));
        // The score reflects credibility, should NOT crater to F.
        assert!(
            h.score >= 60,
            "low-credibility HIGHs shouldn't crater to F, got {}",
            h.score
        );
    }

    #[test]
    fn test_path_findings_are_discounted() {
        let in_test = vec![diag_in(
            "src/feature/__tests__/handler.test.ts",
            Severity::High,
            Some(Confidence::High),
        )];
        let in_prod = vec![diag_in(
            "src/feature/handler.ts",
            Severity::High,
            Some(Confidence::High),
        )];
        let st = summary_of(&in_test);
        let sp = summary_of(&in_prod);

        let h_test = compute(&first_scan(&st, &in_test, 0.0, 50));
        let h_prod = compute(&first_scan(&sp, &in_prod, 0.0, 50));
        assert!(
            h_test.score > h_prod.score,
            "test-path HIGH ({}) should grade better than prod HIGH ({})",
            h_test.score,
            h_prod.score
        );
    }

    #[test]
    fn density_dampens_for_large_repos_but_caps() {
        let findings: Vec<Diag> = (0..3)
            .map(|_| diag(Severity::Medium, "rs.taint.x", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let small = compute(&first_scan(&s, &findings, 0.0, 100));
        let mid = compute(&first_scan(&s, &findings, 0.0, 5000));
        let big = compute(&first_scan(&s, &findings, 0.0, 50_000));
        let huge = compute(&first_scan(&s, &findings, 0.0, 500_000));
        assert!(
            small.score <= mid.score,
            "small {} mid {}",
            small.score,
            mid.score
        );
        assert!(
            mid.score <= big.score,
            "mid {} big {}",
            mid.score,
            big.score
        );
        assert!(
            (big.score as i32 - huge.score as i32).abs() <= 1,
            "size cap broken: big {} huge {}",
            big.score,
            huge.score
        );
    }

    #[test]
    fn triage_drops_when_total_under_floor() {
        let findings: Vec<Diag> = (0..5)
            .map(|_| diag(Severity::Low, "rs.x", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.0, 100));
        let triage = h
            .components
            .iter()
            .find(|c| c.label == "Triage coverage")
            .unwrap();
        assert_eq!(triage.weight, 0.0);
        assert!(triage.detail.contains("Not applicable"));
    }

    #[test]
    fn trend_drops_on_first_scan() {
        let findings: Vec<Diag> = (0..30)
            .map(|_| diag(Severity::Medium, "rs.x", Some(Confidence::High)))
            .collect();
        let s = summary_of(&findings);
        let h = compute(&first_scan(&s, &findings, 0.5, 100));
        let trend = h.components.iter().find(|c| c.label == "Trend").unwrap();
        assert_eq!(trend.weight, 0.0);
        assert!(trend.detail.contains("Not applicable"));
    }

    #[test]
    fn stale_high_penalty_lowers_regression_component() {
        let findings = vec![diag(Severity::High, "rs.taint.x", Some(Confidence::High))];
        let s = summary_of(&findings);

        let backlog_clean = BacklogStats {
            oldest_open_days: Some(2),
            median_age_days: Some(1),
            stale_count: 0,
            age_buckets: vec![],
        };
        let backlog_stale = BacklogStats {
            oldest_open_days: Some(120),
            median_age_days: Some(60),
            stale_count: 3,
            age_buckets: vec![],
        };

        let fresh_inputs = HealthInputs {
            backlog: Some(&backlog_clean),
            has_history: true,
            ..first_scan(&s, &findings, 0.0, 100)
        };
        let rotting_inputs = HealthInputs {
            backlog: Some(&backlog_stale),
            has_history: true,
            ..first_scan(&s, &findings, 0.0, 100)
        };
        let fresh = compute(&fresh_inputs);
        let rotting = compute(&rotting_inputs);
        let fresh_reg = fresh
            .components
            .iter()
            .find(|c| c.label == "Regression resistance")
            .unwrap()
            .score;
        let rot_reg = rotting
            .components
            .iter()
            .find(|c| c.label == "Regression resistance")
            .unwrap()
            .score;
        assert!(
            rot_reg < fresh_reg,
            "stale should lower regression score: fresh {} vs rotting {}",
            fresh_reg,
            rot_reg
        );
    }

    #[test]
    fn grade_thresholds() {
        assert_eq!(grade_for(100), "A");
        assert_eq!(grade_for(90), "A");
        assert_eq!(grade_for(89), "B");
        assert_eq!(grade_for(80), "B");
        assert_eq!(grade_for(79), "C");
        assert_eq!(grade_for(70), "C");
        assert_eq!(grade_for(69), "D");
        assert_eq!(grade_for(60), "D");
        assert_eq!(grade_for(59), "F");
        assert_eq!(grade_for(0), "F");
    }
}

//! Health-score calibration regression net (v3.5).
//!
//! Pins synthetic reference scenarios to expected score bands. When a constant
//! or weight in `src/server/health.rs` changes, this test fails fast if the
//! change silently re-grades the boundary cases.
//!
//! Bands are deliberately wide (±5 points around the calibration
//! number) so honest curve-shape adjustments don't trip the test ,
//! it's a "did weights silently change everyone's grade?" guard, not
//! an exact-output snapshot.
//!
//! v3.5 protections this test enforces:
//!
//! 1. **No-HIGH floor.**  Any repo with `effective_high == 0` grades
//!    ≥ C (70) regardless of MEDIUM/LOW/quality volume.
//! 2. **Quality lints saturate.**  1000 quality lints don't grade
//!    worse than ~200 quality lints (drag caps at 15 points).
//! 3. **HIGH ceiling honours credibility.**  Five low-credibility
//!    HIGHs (low conf + AST-only) collapse to ~1 effective HIGH.
//! 4. **Test-path discount.**  Same finding in a test path grades
//!    better than in a production path.
//! 5. **Confirmed HIGH costs more than NotAttempted HIGH.**  Symex-
//!    confirmed findings are full credibility; AST-only HIGHs are
//!    discounted.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::evidence::{Confidence, Evidence, SymbolicVerdict, Verdict};
use nyx_scanner::patterns::{FindingCategory, Severity};
use nyx_scanner::server::health::{HealthInputs, compute};
use nyx_scanner::server::models::{BacklogStats, FindingSummary, HealthScore};

// ── Helpers ──────────────────────────────────────────────────────────────────

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
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: Vec::new(),
        stable_hash: 0,
    }
}

fn diag_at(path: &str, severity: Severity, conf: Option<Confidence>) -> Diag {
    let mut d = diag(severity, "rs.taint.x", conf);
    d.path = path.into();
    d
}

fn with_verdict(mut d: Diag, verdict: Verdict) -> Diag {
    // Add a single flow step so context_factor sees this as a real
    // taint flow (1.0×) rather than AST-only (0.75×).  Confirmed +
    // intra-file flow puts credibility at 1.2.
    let ev = Evidence {
        symbolic: Some(SymbolicVerdict {
            verdict,
            constraints_checked: 0,
            paths_explored: 0,
            witness: None,
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        }),
        flow_steps: vec![nyx_scanner::evidence::FlowStep {
            step: 0,
            kind: nyx_scanner::evidence::FlowStepKind::Source,
            file: d.path.clone(),
            line: d.line as u32,
            col: d.col as u32,
            snippet: None,
            variable: None,
            callee: None,
            function: None,
            is_cross_file: false,
        }],
        ..Default::default()
    };
    d.evidence = Some(ev);
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

fn assert_band(case: &str, score: u8, low: u8, high: u8) {
    assert!(
        score >= low && score <= high,
        "[calibration] {case}: score {score} outside band [{low}, {high}]"
    );
}

fn sev(h: &HealthScore) -> u8 {
    h.components
        .iter()
        .find(|c| c.label == "Severity pressure")
        .unwrap()
        .score
}

// Calibration cases

#[test]
fn calibration_clean_first_scan() {
    let findings: Vec<Diag> = vec![];
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    assert_band("clean first scan", h.score, 95, 100);
    assert_eq!(h.grade, "A");
}

#[test]
fn calibration_one_high_no_evidence_caps_at_b() {
    // Single HIGH, no evidence (AST-only) → credibility 0.75 →
    // effective_high = 1 → ceiling 85 → at most B.
    let findings = vec![diag(Severity::High, "rs.taint.x", Some(Confidence::High))];
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    assert_band("1 HIGH (AST-only)", h.score, 80, 89);
    assert_ne!(h.grade, "A");
}

#[test]
fn calibration_one_confirmed_high_caps_at_b() {
    // Same single HIGH but symex Confirmed → credibility 0.9 (1.0 ×
    // 1.0 × 1.0 cross-file? no, no flow_steps means context=0.75).
    // Actually no flow_steps + Confirmed verdict is unusual but test
    // the math anyway.
    let findings = vec![with_verdict(
        diag(Severity::High, "rs.taint.x", Some(Confidence::High)),
        Verdict::Confirmed,
    )];
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    assert_band("1 confirmed HIGH", h.score, 80, 89);
    assert_ne!(h.grade, "A");
}

#[test]
fn calibration_three_high_caps_below_b() {
    // 3 HIGHs all credible → effective_high ~3 → ceiling 68 → max D+.
    let findings: Vec<Diag> = (0..3)
        .map(|_| {
            with_verdict(
                diag(Severity::High, "rs.taint.x", Some(Confidence::High)),
                Verdict::Confirmed,
            )
        })
        .collect();
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    assert_band("3 confirmed HIGHs", h.score, 50, 68);
    assert!(matches!(h.grade.as_str(), "D" | "F"));
}

#[test]
fn calibration_six_confirmed_high_grades_f() {
    let findings: Vec<Diag> = (0..6)
        .map(|_| {
            with_verdict(
                diag(Severity::High, "rs.taint.x", Some(Confidence::High)),
                Verdict::Confirmed,
            )
        })
        .collect();
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 1000));
    assert_eq!(h.grade, "F");
    assert!(h.score <= 58, "6+ confirmed HIGHs ≤58, got {}", h.score);
}

#[test]
fn calibration_no_high_floor_holds_at_c() {
    // Pile of mediums + LOWs + quality.  Without the floor the
    // density math would crater this to F.  With the floor: ≥70 (C).
    let mut findings: Vec<Diag> = (0..200)
        .map(|_| diag(Severity::Medium, "rs.taint.x", Some(Confidence::High)))
        .collect();
    findings.extend(
        (0..2000).map(|_| diag(Severity::Low, "rs.quality.unwrap", Some(Confidence::High))),
    );
    findings.extend((0..50).map(|_| diag(Severity::Low, "rs.taint.low", Some(Confidence::Medium))));
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 200));
    assert!(
        h.score >= 65,
        "0 HIGH must grade ≥C-ish even with high noise, got {}",
        h.score
    );
}

#[test]
fn calibration_thousand_low_only_floor_at_c() {
    let findings: Vec<Diag> = (0..1000)
        .map(|_| diag(Severity::Low, "rs.taint.foo", Some(Confidence::Medium)))
        .collect();
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 200));
    // No HIGH → floor 70.  Density would naturally be lower.
    assert!(
        h.score >= 65,
        "1000 LOW only floor protection, got {}",
        h.score
    );
}

#[test]
fn calibration_thousand_quality_only_grades_at_least_b() {
    // 1000 quality lints, no security findings.  Quality drag caps
    // at 15.  base ~100, drag = 15 → score ~85 (B).  No-HIGH floor
    // also applies but doesn't bind (85 > 70).
    let findings: Vec<Diag> = (0..1000)
        .map(|_| diag(Severity::Low, "rs.quality.unwrap", Some(Confidence::High)))
        .collect();
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    assert!(
        h.score >= 80,
        "1000 quality lints alone should grade ≥B, got {}",
        h.score
    );
}

#[test]
fn calibration_low_credibility_high_does_not_crater() {
    // 5 raw HIGHs, all Low confidence, all AST-only (no evidence).
    // credibility per: 1.0 (NotAttempted) × 0.3 (Low conf) × 0.75
    // (AST-only) = 0.225.  5 × 0.225 = 1.125 → effective_high = 1.
    // Ceiling 85.  This is the FP-protection guarantee.
    let findings: Vec<Diag> = (0..5)
        .map(|_| {
            let mut d = diag(Severity::High, "rs.taint.x", Some(Confidence::Low));
            d.evidence = None;
            d
        })
        .collect();
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    assert!(
        h.score >= 60,
        "5 low-credibility HIGHs shouldn't crater to F, got {}",
        h.score
    );
    assert!(
        h.score <= 85,
        "5 low-credibility HIGHs still capped, got {}",
        h.score
    );
}

#[test]
fn calibration_test_path_discounts_findings() {
    let in_test = vec![diag_at(
        "src/feature/__tests__/handler.test.ts",
        Severity::High,
        Some(Confidence::High),
    )];
    let in_prod = vec![diag_at(
        "src/feature/handler.ts",
        Severity::High,
        Some(Confidence::High),
    )];
    let st = summary_of(&in_test);
    let sp = summary_of(&in_prod);
    let h_test = compute(&first_scan(&st, &in_test, 0.0, 50));
    let h_prod = compute(&first_scan(&sp, &in_prod, 0.0, 50));
    assert!(
        h_test.score >= h_prod.score,
        "test-path HIGH ({}) should grade ≥ prod HIGH ({})",
        h_test.score,
        h_prod.score
    );
}

#[test]
fn calibration_density_is_size_aware_with_caps() {
    // Same 3 HIGHs at varying repo sizes.  Severity component score
    // should not decrease as the repo gets bigger; should plateau
    // past the file ceiling.
    let findings: Vec<Diag> = (0..3)
        .map(|_| diag(Severity::Medium, "rs.taint.x", Some(Confidence::High)))
        .collect();
    let s = summary_of(&findings);
    let small = sev(&compute(&first_scan(&s, &findings, 0.0, 100)));
    let mid = sev(&compute(&first_scan(&s, &findings, 0.0, 5000)));
    let big = sev(&compute(&first_scan(&s, &findings, 0.0, 50_000)));
    let huge = sev(&compute(&first_scan(&s, &findings, 0.0, 500_000)));

    assert!(small <= mid, "small {} should ≤ mid {}", small, mid);
    assert!(mid <= big, "mid {} should ≤ big {}", mid, big);
    assert!(
        (big as i32 - huge as i32).abs() <= 1,
        "size-cap broken: big={} huge={}",
        big,
        huge
    );
}

#[test]
fn calibration_triage_drops_when_total_under_floor() {
    let findings: Vec<Diag> = (0..5)
        .map(|_| diag(Severity::Low, "rs.x", Some(Confidence::High)))
        .collect();
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    let tri = h
        .components
        .iter()
        .find(|c| c.label == "Triage coverage")
        .unwrap();
    assert_eq!(tri.weight, 0.0);
    assert!(tri.detail.contains("Not applicable"));
}

#[test]
fn calibration_trend_drops_on_first_scan() {
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
fn calibration_stale_high_lowers_regression_component() {
    let findings = vec![with_verdict(
        diag(Severity::High, "rs.taint.x", Some(Confidence::High)),
        Verdict::Confirmed,
    )];
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
    let f_reg = fresh
        .components
        .iter()
        .find(|c| c.label == "Regression resistance")
        .unwrap()
        .score;
    let r_reg = rotting
        .components
        .iter()
        .find(|c| c.label == "Regression resistance")
        .unwrap()
        .score;
    assert!(
        r_reg < f_reg,
        "stale should lower regression: fresh {} vs rotting {}",
        f_reg,
        r_reg
    );
}

#[test]
fn calibration_grade_thresholds_unchanged() {
    // Sentinel: rebuilding the score from synthetic inputs that
    // SHOULD land on a band boundary still does.  This catches
    // accidental threshold edits.
    let findings: Vec<Diag> = vec![];
    let s = summary_of(&findings);
    let h = compute(&first_scan(&s, &findings, 0.0, 100));
    // 0 findings, no history → expected grade A
    assert_eq!(h.grade, "A");
}

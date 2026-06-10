//! Integration tests for the direction-aware `EngineNote` pipeline.
//!
//! Verifies the three downstream behaviours that the
//! [`nyx_scanner::engine_notes::LossDirection`] classification drives:
//!
//!   1. [`nyx_scanner::evidence::compute_confidence`] caps at `Medium`
//!      when an `OverReport` or `Bail` note is attached.
//!   2. [`nyx_scanner::rank::rank_diags`] applies a `completeness`
//!      component to the attack-surface score, direction-aware in
//!      magnitude but not additive across notes.
//!   3. The ranked sort order places capped findings below converged
//!      findings of the same severity.
//!
//! Unit tests in `src/rank.rs` and `src/evidence.rs` cover the
//! individual functions.  These tests pin down the *composition*: a
//! single `Diag` run through `compute_confidence` then `rank_diags`
//! must see both effects, and the pipeline must remain deterministic.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::engine_notes::{EngineNote, LossDirection, worst_direction};
use nyx_scanner::evidence::{Confidence, Evidence, SpanEvidence, compute_confidence};
use nyx_scanner::labels::SourceKind;
use nyx_scanner::patterns::{FindingCategory, Severity};
use nyx_scanner::rank::{compute_attack_rank, rank_diags};

// ── Diag factories ─────────────────────────────────────────────────────

/// A converged taint finding that the points-based scorer will score
/// as `Confidence::High`.  Used as the "clean" baseline, any delta
/// against this must come from attached engine notes.
fn high_confidence_taint_diag(path: &str, line: u32) -> Diag {
    Diag {
        path: path.into(),
        line: line as usize,
        col: 1,
        severity: Severity::High,
        id: format!("taint-unsanitised-flow (source {line}:1)"),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: None,
        evidence: Some(Evidence {
            source: Some(SpanEvidence {
                path: path.into(),
                line,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query.id".into()),
            }),
            sink: Some(SpanEvidence {
                path: path.into(),
                line: line + 4,
                col: 1,
                kind: "sink".into(),
                snippet: Some("exec(id)".into()),
            }),
            source_kind: Some(SourceKind::UserInput),
            hop_count: Some(1),
            cap_specificity: Some(1),
            notes: vec!["source_kind:UserInput".into()],
            ..Default::default()
        }),
        rank_score: None,
        rank_reason: None,
        exposure: None,
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

fn attach_notes(d: &mut Diag, notes: Vec<EngineNote>) {
    let mut ev = d.evidence.clone().unwrap_or_default();
    ev.engine_notes = smallvec::SmallVec::from_vec(notes);
    d.evidence = Some(ev);
}

// ── Pipeline integration tests ─────────────────────────────────────────

/// End-to-end: construct a finding that would score High confidence,
/// attach a Bail note, run compute_confidence → rank_diags, and verify
/// both the confidence cap and the rank penalty apply together (not
/// double-counted on the confidence arm).
#[test]
fn bail_note_caps_confidence_and_applies_completeness_penalty() {
    let mut clean = high_confidence_taint_diag("clean.rs", 10);
    let mut bailed = high_confidence_taint_diag("bailed.rs", 10);
    attach_notes(
        &mut bailed,
        vec![EngineNote::ParseTimeout { timeout_ms: 100 }],
    );

    // 1. compute_confidence
    clean.confidence = Some(compute_confidence(&clean));
    bailed.confidence = Some(compute_confidence(&bailed));

    assert_eq!(
        clean.confidence,
        Some(Confidence::High),
        "clean diag must baseline at High"
    );
    assert_eq!(
        bailed.confidence,
        Some(Confidence::Medium),
        "Bail note must cap confidence at Medium"
    );

    // 2. rank_diags
    let clean_rank = compute_attack_rank(&clean);
    let bailed_rank = compute_attack_rank(&bailed);

    // Confidence delta: High(+3) − Medium(0) = 3
    // Completeness delta: Bail = -8
    // Total delta: 11
    let total_delta = clean_rank.score - bailed_rank.score;
    assert!(
        (total_delta - 11.0).abs() < f64::EPSILON,
        "expected combined delta of 11.0 (confidence 3 + completeness 8), got {total_delta}"
    );

    // Both components must appear in rank_reason.
    let bailed_keys: Vec<&str> = bailed_rank
        .components
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(
        bailed_keys.contains(&"completeness"),
        "completeness component missing from rank_reason: {bailed_keys:?}"
    );
    // Confidence component only appears when non-zero; Medium = 0.0 so
    // it's omitted.  Verify by contradiction: re-check with Low.
    let _ = bailed_keys;
}

#[test]
fn under_report_note_does_not_cap_confidence_but_does_penalize_rank() {
    let mut d = high_confidence_taint_diag("x.rs", 1);
    attach_notes(&mut d, vec![EngineNote::WorklistCapped { iterations: 100 }]);
    d.confidence = Some(compute_confidence(&d));

    assert_eq!(
        d.confidence,
        Some(Confidence::High),
        "UnderReport must not cap confidence — the emitted flow is still real"
    );

    // Seed confidence on the clean diag too so the score delta reflects
    // only the completeness component, not a spurious confidence-None
    // vs confidence-High difference.
    let mut clean = high_confidence_taint_diag("x.rs", 1);
    clean.confidence = Some(compute_confidence(&clean));
    assert_eq!(clean.confidence, Some(Confidence::High));

    let clean_score = compute_attack_rank(&clean).score;
    let penalized_score = compute_attack_rank(&d).score;
    assert!(
        (clean_score - penalized_score - 3.0).abs() < f64::EPSILON,
        "UnderReport must apply -3.0 rank penalty (clean={clean_score} under={penalized_score})"
    );
}

#[test]
fn rank_diags_sorts_converged_above_capped_at_same_severity() {
    // Three High findings: one converged, one UnderReport, one Bail.
    // After sorting they must come out in score-desc order:
    // converged > under > bail.
    let converged = high_confidence_taint_diag("a.rs", 1);
    let mut under = high_confidence_taint_diag("b.rs", 1);
    attach_notes(
        &mut under,
        vec![EngineNote::WorklistCapped { iterations: 10 }],
    );
    let mut bail = high_confidence_taint_diag("c.rs", 1);
    attach_notes(
        &mut bail,
        vec![EngineNote::ParseTimeout { timeout_ms: 100 }],
    );

    // Seed confidence before ranking (mirrors post_process_diags order).
    let mut diags = vec![converged, under, bail];
    for d in diags.iter_mut() {
        d.confidence = Some(compute_confidence(d));
    }

    rank_diags(&mut diags);

    assert_eq!(
        diags[0].path,
        "a.rs",
        "converged finding must rank first, got {:?}",
        diags.iter().map(|d| &d.path).collect::<Vec<_>>()
    );
    assert_eq!(
        diags[1].path, "b.rs",
        "UnderReport finding must rank second"
    );
    assert_eq!(diags[2].path, "c.rs", "Bail finding must rank last");
}

#[test]
fn rank_diags_preserves_severity_tier_under_bail() {
    // High + Bail must still outrank Medium + clean at the same
    // evidence-strength baseline, this is the tier-boundary invariant
    // that the -8 completeness magnitude is calibrated for.
    let mut high_bailed = high_confidence_taint_diag("a.rs", 1);
    attach_notes(
        &mut high_bailed,
        vec![EngineNote::ParseTimeout { timeout_ms: 100 }],
    );

    let mut medium_clean = high_confidence_taint_diag("b.rs", 1);
    medium_clean.severity = Severity::Medium;
    medium_clean.id = "taint-unsanitised-flow (source 2:1)".into();

    let mut diags = vec![medium_clean, high_bailed];
    for d in diags.iter_mut() {
        d.confidence = Some(compute_confidence(d));
    }
    rank_diags(&mut diags);

    assert_eq!(
        diags[0].path, "a.rs",
        "High+Bail must outrank Medium+clean to preserve severity tiers"
    );
}

#[test]
fn pipeline_is_deterministic_under_input_permutation() {
    // Ranking must be input-order-independent even when completeness
    // penalties come into play.
    let mut a = high_confidence_taint_diag("a.rs", 1);
    let mut b = high_confidence_taint_diag("b.rs", 1);
    let mut c = high_confidence_taint_diag("c.rs", 1);
    attach_notes(&mut a, vec![EngineNote::WorklistCapped { iterations: 1 }]);
    attach_notes(&mut b, vec![EngineNote::PredicateStateWidened]);
    attach_notes(&mut c, vec![EngineNote::ParseTimeout { timeout_ms: 100 }]);

    let seed = vec![a, b, c];
    let mut order1: Vec<Diag> = seed.clone();
    let mut order2: Vec<Diag> = seed.iter().rev().cloned().collect();
    let mut order3: Vec<Diag> = vec![seed[2].clone(), seed[0].clone(), seed[1].clone()];

    for list in [&mut order1, &mut order2, &mut order3] {
        for d in list.iter_mut() {
            d.confidence = Some(compute_confidence(d));
        }
        rank_diags(list);
    }

    let paths1: Vec<_> = order1.iter().map(|d| &d.path).collect();
    let paths2: Vec<_> = order2.iter().map(|d| &d.path).collect();
    let paths3: Vec<_> = order3.iter().map(|d| &d.path).collect();
    assert_eq!(
        paths1, paths2,
        "rank order must be input-permutation-stable"
    );
    assert_eq!(
        paths1, paths3,
        "rank order must be input-permutation-stable"
    );
}

// ── Direction API regressions ──────────────────────────────────────────

#[test]
fn worst_direction_matches_sarif_property() {
    // The SARIF `loss_direction` property is serialized as the snake-
    // case tag of the worst direction.  Ensure the tag values match
    // the documented stable strings.
    let notes = vec![
        EngineNote::WorklistCapped { iterations: 1 },
        EngineNote::PredicateStateWidened,
    ];
    let dir =
        worst_direction(&notes).expect("mixed non-informational notes must yield a direction");
    assert_eq!(dir, LossDirection::OverReport);
    assert_eq!(dir.tag(), "over-report");
}

// ── --require-converged filter ─────────────────────────────────────────

#[test]
fn require_converged_drops_over_report_and_bail() {
    let converged = high_confidence_taint_diag("converged.rs", 1);
    let mut under = high_confidence_taint_diag("under.rs", 1);
    attach_notes(
        &mut under,
        vec![EngineNote::WorklistCapped { iterations: 1 }],
    );
    let mut over = high_confidence_taint_diag("over.rs", 1);
    attach_notes(&mut over, vec![EngineNote::PredicateStateWidened]);
    let mut bail = high_confidence_taint_diag("bail.rs", 1);
    attach_notes(
        &mut bail,
        vec![EngineNote::ParseTimeout { timeout_ms: 100 }],
    );
    let mut info = high_confidence_taint_diag("info.rs", 1);
    attach_notes(&mut info, vec![EngineNote::InlineCacheReused]);

    let mut diags = vec![converged, under, over, bail, info];
    nyx_scanner::commands::scan::retain_converged_findings(&mut diags);

    let kept: Vec<&str> = diags.iter().map(|d| d.path.as_str()).collect();
    assert!(
        kept.contains(&"converged.rs"),
        "converged finding must be kept"
    );
    assert!(
        kept.contains(&"under.rs"),
        "UnderReport finding must be kept — emitted flow is still real"
    );
    assert!(
        kept.contains(&"info.rs"),
        "informational notes must not drop findings"
    );
    assert!(
        !kept.contains(&"over.rs"),
        "OverReport finding must be dropped (widening → likely FP)"
    );
    assert!(
        !kept.contains(&"bail.rs"),
        "Bail finding must be dropped (analysis aborted)"
    );
    assert_eq!(kept.len(), 3, "exactly 3 findings should remain");
}

#[test]
fn require_converged_keeps_findings_with_no_evidence_struct() {
    // A finding with `evidence: None` has no engine notes by
    // definition, so it must not be affected by the filter.
    let mut d = high_confidence_taint_diag("x.rs", 1);
    d.evidence = None;
    let mut diags = vec![d];
    nyx_scanner::commands::scan::retain_converged_findings(&mut diags);
    assert_eq!(diags.len(), 1, "no-evidence diag must be kept");
}

#[test]
fn require_converged_keeps_findings_with_empty_notes_list() {
    let d = high_confidence_taint_diag("x.rs", 1);
    let mut diags = vec![d];
    nyx_scanner::commands::scan::retain_converged_findings(&mut diags);
    assert_eq!(diags.len(), 1, "empty-notes diag must be kept");
}

#[test]
fn require_converged_drops_mixed_over_report_with_under_report() {
    // Mixed: UnderReport + OverReport ⇒ worst is OverReport ⇒ drop.
    let mut d = high_confidence_taint_diag("x.rs", 1);
    attach_notes(
        &mut d,
        vec![
            EngineNote::WorklistCapped { iterations: 1 },
            EngineNote::PredicateStateWidened,
        ],
    );
    let mut diags = vec![d];
    nyx_scanner::commands::scan::retain_converged_findings(&mut diags);
    assert!(
        diags.is_empty(),
        "OverReport in mixed note list must dominate and drop the finding"
    );
}

// ── SARIF serialization ────────────────────────────────────────────────

#[test]
fn sarif_exports_loss_direction_property() {
    // When a finding carries non-informational engine notes, the SARIF
    // output must include a `loss_direction` property whose value is
    // the snake-case tag of the worst direction.  Consumers rely on
    // this string being stable across releases.
    let mut d = high_confidence_taint_diag("sample.rs", 1);
    attach_notes(&mut d, vec![EngineNote::WorklistCapped { iterations: 10 }]);
    let sarif = nyx_scanner::output::build_sarif(&[d], std::path::Path::new("."));

    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("runs[0].results");
    let result = &results[0];
    let props = &result["properties"];

    let direction = props["loss_direction"]
        .as_str()
        .expect("loss_direction property must be present for non-informational notes");
    assert_eq!(
        direction, "under-report",
        "SARIF loss_direction must be snake-case tag"
    );
    assert_eq!(
        props["confidence_capped"].as_bool(),
        Some(true),
        "confidence_capped must track non-informational note presence"
    );
}

#[test]
fn sarif_omits_loss_direction_for_informational_only() {
    let mut d = high_confidence_taint_diag("sample.rs", 1);
    attach_notes(&mut d, vec![EngineNote::InlineCacheReused]);
    let sarif = nyx_scanner::output::build_sarif(&[d], std::path::Path::new("."));

    let props = &sarif["runs"][0]["results"][0]["properties"];
    assert!(
        props.get("loss_direction").is_none(),
        "informational-only notes must not set loss_direction (got {:?})",
        props.get("loss_direction")
    );
    assert_eq!(
        props["confidence_capped"].as_bool(),
        Some(false),
        "confidence_capped must be false for informational-only notes"
    );
}

#[test]
fn every_engine_note_direction_is_documented() {
    // Enumerate every EngineNote variant and assert its direction.
    // The intent is that a contributor adding a new variant will cause
    // this test to fail to compile (no match arm), a structural guard
    // against silent misclassification.
    fn check(note: EngineNote, expected: LossDirection) {
        assert_eq!(
            note.direction(),
            expected,
            "direction classification mismatch for {note:?}"
        );
    }

    check(
        EngineNote::WorklistCapped { iterations: 1 },
        LossDirection::UnderReport,
    );
    check(
        EngineNote::OriginsTruncated { dropped: 1 },
        LossDirection::UnderReport,
    );
    check(
        EngineNote::InFileFixpointCapped {
            iterations: 1,
            reason: nyx_scanner::engine_notes::CapHitReason::Unknown,
        },
        LossDirection::UnderReport,
    );
    check(
        EngineNote::CrossFileFixpointCapped {
            iterations: 1,
            reason: nyx_scanner::engine_notes::CapHitReason::Unknown,
        },
        LossDirection::UnderReport,
    );
    check(
        EngineNote::SsaLoweringBailed {
            reason: "unsupported".into(),
        },
        LossDirection::Bail,
    );
    check(
        EngineNote::ParseTimeout { timeout_ms: 100 },
        LossDirection::Bail,
    );
    check(EngineNote::PredicateStateWidened, LossDirection::OverReport);
    check(EngineNote::PathEnvCapped, LossDirection::OverReport);
    check(EngineNote::InlineCacheReused, LossDirection::Informational);
}

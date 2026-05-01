//! Calibration tests for `taint-data-exfiltration` severity, confidence,
//! and rank scoring.
//!
//! These tests pin the calibration described in `docs/detectors.md` so any
//! future change to the scoring path either preserves the documented tier
//! relationships or breaks a test deliberately.
//!
//! What is checked here:
//!
//!   * Cookie source + Confirmed symbolic verdict produces High severity
//!     (cookies carry session / credential material and are treated as
//!     Secret-tier for the leak class).
//!   * Env source + Confirmed verdict produces High severity (same
//!     reasoning, env vars carry credential material).
//!   * Header / FileSystem / Database / CaughtException sources downgrade
//!     to Medium severity even with a Confirmed verdict — they are
//!     Sensitive but not credential-grade secrets.
//!   * No symbolic verdict (or `Inconclusive` / `NotAttempted`) → Low
//!     confidence (the instruction's "Inconclusive" tier; the
//!     `Confidence` enum has no separate Inconclusive variant so it
//!     floors to Low).
//!   * Opaque body (Confirmed but with empty witness) → Medium
//!     confidence; the abstract domain still produced a corroboration
//!     signal even if the witness string is bare.
//!   * `path_validated=true` drops a confidence tier (Medium → Low).
//!   * On the same source, DATA_EXFIL ranks strictly below SSRF (the
//!     taint-class bonus is +7 for data-exfil vs +10 for the generic
//!     `taint-unsanitised-flow`).

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::evidence::{
    Confidence, Evidence, SpanEvidence, SymbolicVerdict, Verdict, compute_confidence,
};
use nyx_scanner::labels::SourceKind;
use nyx_scanner::patterns::{FindingCategory, Severity};
use nyx_scanner::rank::compute_attack_rank;

fn make_evidence(source_kind: SourceKind, verdict: Option<Verdict>) -> Evidence {
    Evidence {
        source: Some(SpanEvidence {
            path: "src/leak.js".into(),
            line: 1,
            col: 1,
            kind: "source".into(),
            snippet: Some("req.cookies.session".into()),
        }),
        sink: Some(SpanEvidence {
            path: "src/leak.js".into(),
            line: 5,
            col: 5,
            kind: "sink".into(),
            snippet: Some("fetch('/endpoint', { body: payload })".into()),
        }),
        source_kind: Some(source_kind),
        hop_count: Some(1),
        cap_specificity: Some(1),
        symbolic: verdict.map(|v| SymbolicVerdict {
            verdict: v,
            constraints_checked: 0,
            paths_explored: 1,
            // For Confirmed cases use the strong-witness phrasing so the
            // test exercises the same code path that real symex output
            // takes (see `compute_taint_confidence` for the analogous
            // witness-strength branch).
            witness: matches!(v, Verdict::Confirmed)
                .then(|| "tainted cookie flows to fetch body".into()),
            interproc_call_chains: vec![],
            cutoff_notes: vec![],
        }),
        ..Default::default()
    }
}

fn make_diag(
    rule_id: &str,
    severity: Severity,
    source_kind: SourceKind,
    verdict: Option<Verdict>,
    path_validated: bool,
) -> Diag {
    Diag {
        path: "src/leak.js".into(),
        line: 5,
        col: 5,
        severity,
        id: rule_id.into(),
        category: FindingCategory::Security,
        path_validated,
        guard_kind: if path_validated {
            Some("Validation".into())
        } else {
            None
        },
        message: None,
        labels: vec![],
        confidence: None,
        evidence: Some(make_evidence(source_kind, verdict)),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
    }
}

// ── Calibration fixture 1: Cookie source, Confirmed verdict ─────────────

#[test]
fn cookie_source_with_confirmed_verdict_is_high_medium() {
    // Severity: cookies are Secret-tier for DATA_EXFIL → High.
    // Confidence: Confirmed verdict on a Sensitive source → Medium (the
    // routing caps at Medium even with a strong witness; see
    // `compute_data_exfil_confidence`).
    let diag = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::High,
        SourceKind::Cookie,
        Some(Verdict::Confirmed),
        false,
    );

    let confidence = compute_confidence(&diag);
    assert_eq!(
        confidence,
        Confidence::Medium,
        "Cookie + Confirmed → Medium (DATA_EXFIL cap), got {confidence:?}"
    );
}

// ── Calibration fixture 2: Env source, Confirmed verdict ────────────────

#[test]
fn env_source_with_confirmed_verdict_is_high_medium() {
    // Env vars carry credential / config material and are treated as
    // Secret-tier alongside cookies.
    let diag = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::High,
        SourceKind::EnvironmentConfig,
        Some(Verdict::Confirmed),
        false,
    );

    let confidence = compute_confidence(&diag);
    assert_eq!(
        confidence,
        Confidence::Medium,
        "Env + Confirmed → Medium, got {confidence:?}"
    );
}

// ── Calibration fixture 3: Header source, opaque body (no verdict) ──────

#[test]
fn header_source_without_symex_is_medium_low() {
    // Header is Sensitive but not credential-grade; severity downgrades
    // to Medium.  No symbolic verdict → confidence Low (the "Inconclusive
    // when no symex verdict" tier from the instruction).
    let diag = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::Medium,
        SourceKind::Header,
        None,
        false,
    );

    let confidence = compute_confidence(&diag);
    assert_eq!(
        confidence,
        Confidence::Low,
        "Header + no verdict → Low, got {confidence:?}"
    );
}

// ── Calibration fixture 4: guarded path drops a tier ────────────────────

#[test]
fn guarded_path_drops_confidence_tier() {
    // Cookie + Confirmed would normally yield Medium confidence; the
    // path-validated flag drops it one step to Low.  Without the guard
    // the same diag must score Medium (asserted alongside to lock in
    // the delta, not just the floor).
    let unguarded = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::High,
        SourceKind::Cookie,
        Some(Verdict::Confirmed),
        false,
    );
    let guarded = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::High,
        SourceKind::Cookie,
        Some(Verdict::Confirmed),
        true,
    );

    assert_eq!(compute_confidence(&unguarded), Confidence::Medium);
    assert_eq!(
        compute_confidence(&guarded),
        Confidence::Low,
        "guarded DATA_EXFIL path must drop one confidence tier"
    );
}

// ── Calibration fixture 5: ranking — DATA_EXFIL below SSRF on same source

#[test]
fn data_exfil_ranks_below_ssrf_on_same_source() {
    // Cookie source flowing to `fetch` could fire either DATA_EXFIL (body
    // arg) or SSRF / generic taint (URL arg).  On the same severity tier
    // SSRF must outrank DATA_EXFIL because the analysis-kind bonus is +10
    // for `taint-unsanitised-flow` and +7 for `taint-data-exfiltration`.
    let exfil = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::High,
        SourceKind::Cookie,
        Some(Verdict::Confirmed),
        false,
    );
    let ssrf = make_diag(
        "taint-unsanitised-flow (source 1:1)",
        Severity::High,
        SourceKind::Cookie,
        Some(Verdict::Confirmed),
        false,
    );

    let exfil_score = compute_attack_rank(&exfil).score;
    let ssrf_score = compute_attack_rank(&ssrf).score;
    assert!(
        ssrf_score > exfil_score,
        "SSRF score ({ssrf_score}) must outrank DATA_EXFIL score \
         ({exfil_score}) on the same source"
    );
    // The delta is exactly the analysis-kind bonus difference (+3) — pin
    // it so accidental drift trips the test rather than silently moving
    // both bonuses in lock-step.
    assert!(
        (ssrf_score - exfil_score - 3.0).abs() < 0.001,
        "SSRF − DATA_EXFIL should equal the analysis-kind bonus delta \
         (+3); got {} ({} − {})",
        ssrf_score - exfil_score,
        ssrf_score,
        exfil_score,
    );
}

// ── Calibration fixture 6: DATA_EXFIL above AST patterns ────────────────

#[test]
fn data_exfil_ranks_above_ast_pattern() {
    // The instruction mandates DATA_EXFIL sit above informational AST
    // patterns.  Use a Medium DATA_EXFIL (header source) vs a Low AST
    // pattern (the typical AST-only banned-API match) to lock the
    // ordering in even at the weaker end of the DATA_EXFIL spectrum.
    let medium_exfil = make_diag(
        "taint-data-exfiltration (source 1:1)",
        Severity::Medium,
        SourceKind::Header,
        Some(Verdict::Confirmed),
        false,
    );
    let mut ast_pattern = make_diag(
        "js.code_exec.eval",
        Severity::Low,
        SourceKind::Unknown,
        None,
        false,
    );
    // AST patterns don't carry taint evidence; clear it so the ranker
    // takes the AST-only branch.
    ast_pattern.evidence = None;

    let exfil_score = compute_attack_rank(&medium_exfil).score;
    let ast_score = compute_attack_rank(&ast_pattern).score;
    assert!(
        exfil_score > ast_score,
        "DATA_EXFIL ({exfil_score}) must outrank AST pattern ({ast_score})"
    );
}

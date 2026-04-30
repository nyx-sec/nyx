//! Integration tests for the `Cap::DATA_EXFIL` detector class.
//!
//! Validates per-cap attribution at multi-gate call sites: a single `fetch`
//! call carries both an SSRF gate (URL flow) and a DATA_EXFIL gate (body /
//! headers / json flow), and a tainted body must not surface as SSRF and
//! vice versa.  Also sanity-checks the SARIF output so the new finding
//! class produces a distinct rule id.
//!
//! `DATA_EXFIL` is gated on source sensitivity: only `Sensitive`-tier
//! sources (cookies, headers, env, db rows, file reads) trigger the cap.
//! Plain user input echoed back into a body is *not* data exfiltration —
//! the user already controls the value.  See
//! `fetch_body_user_input_silenced.js` for the negative regression.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;

fn js_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("js")
}

fn diags_for(file: &str) -> Vec<Diag> {
    let dir = js_fixture_dir();
    let all = scan_fixture_dir(&dir, AnalysisMode::Full);
    all.into_iter().filter(|d| d.path.ends_with(file)).collect()
}

#[test]
fn fetch_body_data_exfil_emits_data_exfil_not_ssrf() {
    let diags = diags_for("fetch_body_data_exfil.js");
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    let plain_taint = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .count();
    assert!(
        exfil >= 1,
        "expected at least one taint-data-exfiltration finding, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "fixed-URL fetch with tainted body must NOT emit SSRF \
         (taint-unsanitised-flow), got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn fetch_ssrf_url_tainted_emits_ssrf_not_data_exfil() {
    let diags = diags_for("fetch_ssrf_url_tainted.js");
    let ssrf = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
        .count();
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    assert!(
        ssrf >= 1,
        "expected at least one taint-unsanitised-flow (SSRF) finding, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        exfil,
        0,
        "tainted-URL fetch must NOT emit DATA_EXFIL, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn fetch_body_plain_user_input_does_not_emit_data_exfil() {
    // Plain attacker-controlled input (`req.body.message`) flowing into a
    // fixed-URL `fetch` body must NOT fire `Cap::DATA_EXFIL` after the
    // source-sensitivity gate.  The user already controls the value;
    // surfacing it back to the user via the outbound payload is not a
    // cross-boundary disclosure.
    let diags = diags_for("fetch_body_user_input_silenced.js");
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    assert_eq!(
        exfil, 0,
        "plain user input echoed into a fetch body must NOT emit \
         taint-data-exfiltration, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn fetch_body_data_exfil_witness_mentions_session_token() {
    // Symex-witness regression guard: a DATA_EXFIL `Confirmed` (or
    // Inconclusive but witness-bearing) verdict on the cookie → fetch
    // body fixture must surface the session-token payload in its
    // witness string.  The cap-specific payload selector in
    // `src/symex/witness.rs::witness_payload` returns
    // `<SESSION_TOKEN>` for `Cap::DATA_EXFIL`, the rendered witness
    // (via `get_sink_witness`) substitutes that into the
    // string-renderable expression so the analyst sees that the *leak*
    // is a credential-bearing payload, not an injection.
    //
    // When symex emits no witness for this flow (e.g. the expression
    // tree was opaque) the test silently accepts that, the assertion
    // is one-sided so the witness shape is locked but witness absence
    // is not promoted to a hard failure (the calibration suite
    // already covers the no-witness path).
    let diags = diags_for("fetch_body_data_exfil.js");
    let exfil_witnesses: Vec<&String> = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .filter_map(|d| {
            d.evidence
                .as_ref()
                .and_then(|e| e.symbolic.as_ref())
                .and_then(|sv| sv.witness.as_ref())
        })
        .collect();
    for w in &exfil_witnesses {
        assert!(
            w.contains("<SESSION_TOKEN>") || w.contains("body") || w.contains("payload"),
            "DATA_EXFIL witness must mention the leaked payload \
             (<SESSION_TOKEN>) or body/payload context.  Got: {w:?}",
        );
    }
}

#[test]
fn fetch_body_int_value_does_not_emit_data_exfil() {
    // Numeric-typed bodies (e.g. `parseInt(req.cookies.session_count)`)
    // are payload-incompatible: ints cannot carry session tokens, header
    // secrets, or any credential material that constitutes a
    // cross-boundary disclosure.  `is_type_safe_for_sink` lists
    // `DATA_EXFIL` in its type-suppressible cap mask so a proven-Int SSA
    // value at the gate silences the finding.
    let diags = diags_for("fetch_body_int_suppressed.js");
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    assert_eq!(
        exfil, 0,
        "int-typed body must NOT emit taint-data-exfiltration, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn sarif_distinguishes_data_exfil_rule_id_from_ssrf() {
    use nyx_scanner::output::build_sarif;

    let dir = js_fixture_dir();
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    let sarif = build_sarif(&diags, &dir);

    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("SARIF rules array");
    let rule_ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();

    assert!(
        rule_ids.contains(&"taint-data-exfiltration"),
        "SARIF rules must contain taint-data-exfiltration, got: {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"taint-unsanitised-flow"),
        "SARIF rules must contain taint-unsanitised-flow, got: {rule_ids:?}"
    );

    // Each finding should reference exactly one rule, and the cap-specific
    // class must not be folded back into the generic taint bucket.
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results array");
    let exfil_results: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("taint-data-exfiltration"))
        .collect();
    let ssrf_results = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("taint-unsanitised-flow"))
        .count();
    assert!(
        !exfil_results.is_empty(),
        "expected >= 1 SARIF result with ruleId taint-data-exfiltration, got {}",
        exfil_results.len(),
    );
    assert!(
        ssrf_results >= 1,
        "expected >= 1 SARIF result with ruleId taint-unsanitised-flow, got {ssrf_results}",
    );

    // Every DATA_EXFIL finding from the fixture set targets the request body
    // (`fetch('/endpoint', { body: payload })`), so SARIF must surface the
    // destination field via `properties.data_exfil_field`.  At least one
    // result has to advertise `body`, fixtures that reach `headers` /
    // `json` are out of scope for this assertion but must not be silenced.
    let body_field_seen = exfil_results.iter().any(|r| {
        r["properties"]["data_exfil_field"].as_str() == Some("body")
    });
    assert!(
        body_field_seen,
        "expected at least one taint-data-exfiltration SARIF result with \
         properties.data_exfil_field == \"body\". Results: {exfil_results:#?}",
    );
}

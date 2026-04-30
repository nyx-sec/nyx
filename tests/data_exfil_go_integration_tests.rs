//! Integration tests for the Go bindings of the `Cap::DATA_EXFIL`
//! detector class.
//!
//! Mirrors the JS `fetch_data_exfil_integration_tests` shape: a single
//! outbound HTTP callee carries an SSRF gate (URL flow) and a DATA_EXFIL
//! gate (body / payload flow), and per-position cap attribution must
//! keep a tainted URL from surfacing as data exfiltration and a tainted
//! body from surfacing as SSRF.  Also validates the two-step
//! `http.NewRequest` → `http.DefaultClient.Do` idiom: NewRequest is
//! modeled as a body propagator (default arg → return propagation), so
//! body taint reaches the Do gate through the returned `*http.Request`.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn go_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("go")
}

fn diags_for(file: &str) -> Vec<Diag> {
    let dir = go_fixture_dir();
    let all = scan_fixture_dir(&dir, AnalysisMode::Full);
    all.into_iter().filter(|d| d.path.ends_with(file)).collect()
}

#[test]
fn http_post_body_data_exfil_emits_data_exfil_not_ssrf() {
    let diags = diags_for("data_exfil_http_post.go");
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
        "expected at least one taint-data-exfiltration finding for cookie → http.Post body, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "fixed-URL http.Post with tainted body must NOT emit SSRF \
         (taint-unsanitised-flow), got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn http_post_form_emits_data_exfil_not_ssrf() {
    let diags = diags_for("data_exfil_post_form.go");
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
        "expected at least one taint-data-exfiltration finding for header → http.PostForm data, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "fixed-URL http.PostForm with tainted form data must NOT emit SSRF, got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn new_request_do_two_step_emits_data_exfil() {
    // The two-step idiom: `req, _ := http.NewRequest(_, fixedURL, body);
    // http.DefaultClient.Do(req)`.  NewRequest is modeled as a body
    // propagator (default arg → return) so the request value carries
    // body taint into the DATA_EXFIL gate at Do.  SSRF must not fire
    // because the URL position at NewRequest is a hardcoded string.
    let diags = diags_for("data_exfil_new_request_do.go");
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
        "expected at least one taint-data-exfiltration finding for cookie → NewRequest → Do, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "two-step NewRequest → Do with hardcoded URL must NOT emit SSRF, got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn map_assign_data_exfil_emits_through_url_values() {
    // Container-taint DATA_EXFIL: cookies populate a `url.Values` map
    // across multiple keys, then the map flows into `http.PostForm`'s
    // form-data channel.  The Elements heap slot must round-trip the
    // cap from each `form.Set(k, v)` write to the sink-side load so
    // DATA_EXFIL fires on the body channel even though `form` itself is
    // not directly tainted by an Assign.  SSRF must NOT fire because
    // the destination URL is a hardcoded literal.
    let diags = diags_for("data_exfil_map_assign.go");
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
        "expected at least one taint-data-exfiltration finding for map_assign cookies → http.PostForm, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "fixed-URL http.PostForm with tainted map must NOT emit SSRF, got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn ssrf_url_tainted_emits_ssrf_not_data_exfil() {
    // Tainted query param flows into NewRequest's URL position with a
    // hardcoded body; SSRF must fire on the URL flow and DATA_EXFIL
    // must NOT fire (no Sensitive source reaches the body).
    let diags = diags_for("ssrf_url_tainted.go");
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
        "tainted-URL NewRequest → Do must NOT emit DATA_EXFIL, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn http_post_plain_user_input_does_not_emit_data_exfil() {
    // Plain attacker-controlled input (`r.FormValue`) flowing into a
    // fixed-URL `http.Post` body must NOT fire `Cap::DATA_EXFIL` after
    // the source-sensitivity gate strips the cap for Plain sources.
    let diags = diags_for("data_exfil_user_input_silenced.go");
    let exfil = diags
        .iter()
        .filter(|d| d.id.starts_with("taint-data-exfiltration"))
        .count();
    assert_eq!(
        exfil,
        0,
        "plain user input echoed into a Go http.Post body must NOT emit \
         taint-data-exfiltration, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn cross_file_go_data_exfil_split() {
    // A wrapper whose two parameters target distinct gated-sink classes
    // on a single inner two-step (`url` flows to NewRequest's SSRF gate;
    // `body` flows through NewRequest → Do's DATA_EXFIL gate).  Each
    // caller taints exactly one parameter and must surface only the cap
    // class corresponding to that parameter's gate.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cross_file_go_data_exfil");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

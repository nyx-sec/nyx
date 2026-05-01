//! Integration tests for the Java bindings of the `Cap::DATA_EXFIL`
//! detector class.
//!
//! Mirrors the JS `fetch_data_exfil_integration_tests` and Go
//! `data_exfil_go_integration_tests` shapes.  Each chained-API HTTP
//! client (java.net.http, Spring RestTemplate / WebClient, OkHttp,
//! Apache HttpClient) gets its own fixture: a Sensitive source flows
//! through the body-binding chain into a fixed-URL outbound call, and
//! the regression fixture proves SSRF still fires on a tainted URL
//! without leaking into DATA_EXFIL.
//!
//! Body-binding chain propagators (`BodyPublishers.ofString`,
//! `RequestBody.create`, `StringEntity` ctor, builder `.uri()` /
//! `.POST()` / `.bodyValue()`) carry taint through the chain via the
//! transfer engine's default arg → return smear, so no per-callee
//! propagator rules are needed; the sink at the network call sees the
//! end-of-chain request value carrying body taint.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;

fn java_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("java")
}

fn diags_for(file: &str) -> Vec<Diag> {
    let dir = java_fixture_dir();
    let all = scan_fixture_dir(&dir, AnalysisMode::Full);
    all.into_iter().filter(|d| d.path.ends_with(file)).collect()
}

fn assert_data_exfil_fires_no_ssrf(file: &str) {
    let diags = diags_for(file);
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
        "{file}: expected at least one taint-data-exfiltration finding, got 0.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        plain_taint,
        0,
        "{file}: fixed-URL call with tainted body must NOT emit SSRF \
         (taint-unsanitised-flow), got {plain_taint}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

#[test]
fn jdk_http_client_chain_emits_data_exfil_not_ssrf() {
    // java.net.http: cookie → BodyPublishers.ofString → builder chain →
    // client.send(req).  Type-qualified resolution rewrites
    // client.send → HttpClient.send so the new flat DATA_EXFIL rule
    // and the existing flat SSRF rule both attach; only DATA_EXFIL
    // should surface because the URL is hardcoded.
    assert_data_exfil_fires_no_ssrf("data_exfil_jdk_httpclient.java");
}

#[test]
fn rest_template_post_for_object_emits_data_exfil_not_ssrf() {
    // Spring RestTemplate: header → restTemplate.postForObject(url,
    // body, type).  RestTemplate subtypes HttpClient via the
    // JAVA_HIERARCHY so type-qualified resolution finds the same flat
    // rule that the JDK client uses.
    assert_data_exfil_fires_no_ssrf("data_exfil_resttemplate.java");
}

#[test]
fn web_client_body_value_emits_data_exfil_not_ssrf() {
    // Spring WebClient: env var → webClient.post().uri(u).bodyValue(p)
    // .retrieve().  The body-bind step `bodyValue` carries a flat
    // DATA_EXFIL sink rule — a bare-name suffix matcher independent of
    // receiver typing, since the chain receiver type is RequestBodySpec.
    assert_data_exfil_fires_no_ssrf("data_exfil_webclient.java");
}

#[test]
fn ok_http_new_call_execute_emits_data_exfil_not_ssrf() {
    // OkHttp two-step: session attribute → RequestBody.create →
    // builder chain → client.newCall(req).execute().  Chain
    // normalization strips `()` between dots so the suffix
    // `newCall.execute` matches.
    assert_data_exfil_fires_no_ssrf("data_exfil_okhttp.java");
}

#[test]
fn apache_http_client_execute_emits_data_exfil_not_ssrf() {
    // Apache HttpClient: cookie → StringEntity → HttpPost.setEntity →
    // httpClient.execute(req).  CloseableHttpClient subtypes HttpClient
    // so type-qualified resolution rewrites client.execute →
    // HttpClient.execute and reuses the same flat rule.
    assert_data_exfil_fires_no_ssrf("data_exfil_apache_httpclient.java");
}

#[test]
fn ssrf_url_only_emits_ssrf_not_data_exfil() {
    // Tainted URL with hardcoded body: SSRF must fire on the URL flow,
    // DATA_EXFIL must NOT fire because no Sensitive source reaches the
    // body.  Guards against the new flat DATA_EXFIL rule over-firing.
    let diags = diags_for("ssrf_url_only_no_data_exfil.java");
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
        "tainted-URL HttpClient.send must NOT emit DATA_EXFIL, got {exfil}.\n\
         Diags: {:#?}",
        diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
    );
}

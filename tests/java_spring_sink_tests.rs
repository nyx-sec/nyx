//! Java sink rules that depend on a Spring manifest being present.
//!
//! `fixtures/java_spring_sinks/` has a `pom.xml` that pulls in spring-boot, so
//! the scan runs with the Spring framework context on.  That context used to
//! add a bare `send` SSRF sink, which turned every Kafka, SSE, mail and
//! in-house `send(..)` into a finding.  The JDK client's `send` is a typed
//! sink instead, reached through the receiver's constructor or declaration.

mod common;

use common::scan_fixture_dir;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::PathBuf;

fn flow_lines(file: &str) -> Vec<usize> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("java_spring_sinks");
    let mut lines: Vec<usize> = scan_fixture_dir(&dir, AnalysisMode::Full)
        .into_iter()
        .filter(|d| d.path.ends_with(file) && d.id.starts_with("taint-"))
        .map(|d| d.line)
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

#[test]
fn spring_project_send_is_an_ssrf_sink_only_on_the_jdk_http_client() {
    // 27 kafkaTemplate.send, 28 notifier.send and 35 emitter.send carry a
    // request parameter but do not make an outbound HTTP request.  43, 49
    // and 56 are `HttpClient.send` through a local built with
    // `newHttpClient()`, a field initialised the same way, and a local built
    // with `newBuilder().build()`.
    assert_eq!(flow_lines("SendController.java"), vec![43, 49, 56]);
}

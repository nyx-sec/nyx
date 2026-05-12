//! Python verdict-parity test (§8.3).
//!
//! Verifies that the M2 Python fixture set produces identical verdicts when
//! run through `SandboxBackend::Docker` versus `SandboxBackend::Process`.
//!
//! Identical means: same `VerifyStatus` AND same `InconclusiveReason` /
//! `UnsupportedReason` (the `reason` strings match for `Inconclusive` /
//! `Unsupported`). The exact payload that triggered `Confirmed` may differ
//! if Docker isolation changes observable output, but the status must agree.
//!
//! Tests skip when docker is absent (`docker info` fails). CI gate: the
//! `linux-with-docker` matrix row is authoritative for this suite.
//!
//! Run with: `cargo nextest run --features dynamic --test dynamic_parity`

#[cfg(feature = "dynamic")]
mod parity_tests {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::evidence::{Confidence, Evidence, FlowStep, FlowStepKind, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::time::Duration;

    fn docker_available() -> bool {
        std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn source_step(file: &str, function: &str) -> FlowStep {
        FlowStep {
            step: 1,
            kind: FlowStepKind::Source,
            file: file.into(),
            line: 1,
            col: 0,
            snippet: None,
            variable: Some("x".into()),
            callee: None,
            function: Some(function.into()),
            is_cross_file: false,
        }
    }

    fn sink_step(file: &str, line: u32) -> FlowStep {
        FlowStep {
            step: 2,
            kind: FlowStepKind::Sink,
            file: file.into(),
            line,
            col: 0,
            snippet: None,
            variable: None,
            callee: None,
            function: None,
            is_cross_file: false,
        }
    }

    fn python_diag(fixture_path: &str, function: &str, sink_line: u32, cap: Cap) -> Diag {
        Diag {
            path: fixture_path.into(),
            line: sink_line as usize,
            col: 0,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(Evidence {
                flow_steps: vec![
                    source_step(fixture_path, function),
                    sink_step(fixture_path, sink_line),
                ],
                sink_caps: cap.bits(),
                ..Default::default()
            }),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        }
    }

    fn process_opts() -> VerifyOptions {
        VerifyOptions {
            sandbox: SandboxOptions {
                backend: SandboxBackend::Process,
                timeout: Duration::from_secs(10),
                ..SandboxOptions::default()
            },
            project_root: None,
            db_path: None,
        }
    }

    fn docker_opts() -> VerifyOptions {
        VerifyOptions {
            sandbox: SandboxOptions {
                backend: SandboxBackend::Docker,
                timeout: Duration::from_secs(30),
                ..SandboxOptions::default()
            },
            project_root: None,
            db_path: None,
        }
    }

    /// Assert two verdicts agree on status (and on reason for non-Confirmed).
    fn assert_parity(fixture: &str, process_result: &nyx_scanner::evidence::VerifyResult,
                     docker_result: &nyx_scanner::evidence::VerifyResult) {
        // If docker backend is unavailable, docker result will be Unsupported.
        // That's acceptable — we can't compare when docker is missing.
        if docker_result.status == VerifyStatus::Unsupported {
            if let Some(ref r) = docker_result.reason {
                if format!("{r:?}").contains("BackendUnavailable") {
                    return; // Docker absent — skip comparison.
                }
            }
        }

        assert_eq!(
            process_result.status, docker_result.status,
            "fixture {fixture}: status mismatch: process={:?} docker={:?}\n\
             process detail: {:?}\ndocker detail: {:?}",
            process_result.status, docker_result.status,
            process_result.detail, docker_result.detail,
        );

        // For non-Confirmed statuses, the reason must also match.
        if process_result.status != VerifyStatus::Confirmed {
            assert_eq!(
                process_result.reason, docker_result.reason,
                "fixture {fixture}: reason mismatch: process={:?} docker={:?}",
                process_result.reason, docker_result.reason,
            );
        }
    }

    // ── M2 Python fixture parity tests ────────────────────────────────────────

    /// Helper: run a fixture through both backends and assert parity.
    fn parity_check(fixture: &str, function: &str, sink_line: u32, cap: Cap) {
        if !docker_available() { return; }

        let diag = python_diag(fixture, function, sink_line, cap);
        let process_result = verify_finding(&diag, &process_opts());
        let docker_result = verify_finding(&diag, &docker_opts());
        assert_parity(fixture, &process_result, &docker_result);
    }

    #[test]
    fn parity_sqli_positive() {
        parity_check(
            "tests/dynamic_fixtures/python/sqli_positive.py",
            "login",
            7,
            Cap::SQL_QUERY,
        );
    }

    #[test]
    fn parity_sqli_negative() {
        parity_check(
            "tests/dynamic_fixtures/python/sqli_negative.py",
            "safe_login",
            8,
            Cap::SQL_QUERY,
        );
    }

    #[test]
    fn parity_cmdi_positive() {
        parity_check(
            "tests/dynamic_fixtures/python/cmdi_positive.py",
            "run_command",
            5,
            Cap::CODE_EXEC,
        );
    }

    #[test]
    fn parity_cmdi_negative() {
        parity_check(
            "tests/dynamic_fixtures/python/cmdi_negative.py",
            "safe_command",
            6,
            Cap::CODE_EXEC,
        );
    }

    #[test]
    fn parity_fileio_positive() {
        parity_check(
            "tests/dynamic_fixtures/python/fileio_positive.py",
            "read_file",
            5,
            Cap::FILE_IO,
        );
    }

    #[test]
    fn parity_fileio_negative() {
        parity_check(
            "tests/dynamic_fixtures/python/fileio_negative.py",
            "safe_read_file",
            6,
            Cap::FILE_IO,
        );
    }

    #[test]
    fn parity_xss_positive() {
        parity_check(
            "tests/dynamic_fixtures/python/xss_positive.py",
            "render_page",
            5,
            Cap::HTML_ESCAPE,
        );
    }

    #[test]
    fn parity_xss_negative() {
        parity_check(
            "tests/dynamic_fixtures/python/xss_negative.py",
            "safe_render",
            6,
            Cap::HTML_ESCAPE,
        );
    }

    #[test]
    fn parity_ssrf_positive() {
        parity_check(
            "tests/dynamic_fixtures/python/ssrf_positive.py",
            "fetch_url",
            5,
            Cap::SSRF,
        );
    }

    /// Cross-backend status must agree for Unsupported fixtures (no corpus).
    #[test]
    fn parity_sqli_unsupported() {
        parity_check(
            "tests/dynamic_fixtures/python/sqli_unsupported.py",
            "unsupported_fn",
            5,
            Cap::SQL_QUERY,
        );
    }

    /// Rust finding (lang unsupported) must return same status on both backends.
    #[test]
    fn parity_rust_lang_unsupported() {
        if !docker_available() { return; }

        let diag = python_diag("src/handler.rs", "handle_request", 10, Cap::SQL_QUERY);
        let process_result = verify_finding(&diag, &process_opts());
        let docker_result = verify_finding(&diag, &docker_opts());
        assert_parity("src/handler.rs (rust)", &process_result, &docker_result);
    }
}

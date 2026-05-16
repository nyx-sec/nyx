//! Java fixture integration tests (Phase 05 acceptance gate + Phase 14
//! per-shape acceptance).
//!
//! Phase 05 surface: runs `verify_finding` against each legacy
//! `tests/dynamic_fixtures/java/<name>.java` (entry class `Entry`,
//! `public static void <fn>(String)`) and asserts the expected verdict.
//!
//! Phase 14 surface (`#[cfg(feature = "dynamic")] mod phase14_shape_tests`):
//! for each [`nyx_scanner::dynamic::lang::java::JavaShape`] asserts
//! `Confirmed` on the vuln fixture and `NotConfirmed` on the benign
//! fixture under the `tests/dynamic_fixtures/java/<shape>/` directory.
//!
//! Prerequisites: `requires: docker-or-jdk17` — the suite skips cleanly
//! when `javac` / `java` is unavailable on the host (Phase 29 will wire
//! the structured prereq system; for now the suite checks
//! `java --version` exit status and returns early on failure).
//!
//! Run with: `cargo nextest run --features dynamic --test java_fixtures`

mod common;

#[cfg(feature = "dynamic")]
mod java_fixture_tests {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::evidence::{
        Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, UnsupportedReason,
        VerifyStatus,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tempfile::TempDir;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn java_available() -> bool {
        std::process::Command::new("java")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/java")
            .join(name)
    }

    fn run_fixture(
        fixture: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
    ) -> nyx_scanner::evidence::VerifyResult {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !java_available() {
            return nyx_scanner::evidence::VerifyResult {
                finding_id: String::new(),
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason: Some(UnsupportedReason::BackendUnavailable),
                inconclusive_reason: None,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
                differential: None,
                replay_stable: None,
                wrong: None,
                hardening_outcome: None,
            };
        }

        let path = fixture_path(fixture);
        let tmp = TempDir::new().unwrap();

        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var(
                "NYX_TELEMETRY_PATH",
                tmp.path().join("events.jsonl").to_str().unwrap(),
            );
        }

        let diag = make_diag(&path, func, cap, sink_line);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        result
    }

    // ── SQLi fixtures ────────────────────────────────────────────────────────

    #[test]
    fn java_sqli_positive_is_confirmed() {
        let result = run_fixture("sqli_positive.java", "login", Cap::SQL_QUERY, 9);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "sqli_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn java_sqli_negative_is_not_confirmed() {
        let result = run_fixture("sqli_negative.java", "login", Cap::SQL_QUERY, 10);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "sqli_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn java_sqli_adversarial_is_oracle_collision() {
        let result = run_fixture("sqli_adversarial.java", "login", Cap::SQL_QUERY, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn java_sqli_unsupported_is_confidence_too_low() {
        let path = fixture_path("sqli_unsupported.java");
        let mut d = make_diag(&path, "findUser", Cap::SQL_QUERY, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── Command injection fixtures ───────────────────────────────────────────

    #[test]
    fn java_cmdi_positive_is_confirmed() {
        let result = run_fixture("cmdi_positive.java", "runPing", Cap::CODE_EXEC, 10);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn java_cmdi_negative_is_not_confirmed() {
        let result = run_fixture("cmdi_negative.java", "runPing", Cap::CODE_EXEC, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "cmdi_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn java_cmdi_adversarial_is_oracle_collision() {
        let result = run_fixture("cmdi_adversarial.java", "runPing", Cap::CODE_EXEC, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn java_cmdi_unsupported_is_confidence_too_low() {
        let path = fixture_path("cmdi_unsupported.java");
        let mut d = make_diag(&path, "execute", Cap::CODE_EXEC, 9);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── File I/O fixtures ────────────────────────────────────────────────────

    #[test]
    fn java_fileio_positive_is_confirmed() {
        let result = run_fixture("fileio_positive.java", "readFile", Cap::FILE_IO, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "fileio_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn java_fileio_negative_is_not_confirmed() {
        let result = run_fixture("fileio_negative.java", "readFile", Cap::FILE_IO, 20);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "fileio_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn java_fileio_adversarial_is_oracle_collision() {
        let result = run_fixture("fileio_adversarial.java", "readFile", Cap::FILE_IO, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn java_fileio_unsupported_is_confidence_too_low() {
        let path = fixture_path("fileio_unsupported.java");
        let mut d = make_diag(&path, "serve", Cap::FILE_IO, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── SSRF fixtures ────────────────────────────────────────────────────────

    #[test]
    fn java_ssrf_positive_is_confirmed() {
        let result = run_fixture("ssrf_positive.java", "fetchUrl", Cap::SSRF, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "ssrf_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn java_ssrf_negative_is_not_confirmed() {
        let result = run_fixture("ssrf_negative.java", "fetchUrl", Cap::SSRF, 17);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "ssrf_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn java_ssrf_adversarial_is_oracle_collision() {
        let result = run_fixture("ssrf_adversarial.java", "fetchUrl", Cap::SSRF, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn java_ssrf_unsupported_is_confidence_too_low() {
        let path = fixture_path("ssrf_unsupported.java");
        let mut d = make_diag(&path, "fetch", Cap::SSRF, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── XSS fixtures ─────────────────────────────────────────────────────────

    #[test]
    fn java_xss_positive_is_confirmed() {
        let result = run_fixture("xss_positive.java", "renderPage", Cap::HTML_ESCAPE, 8);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "xss_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn java_xss_negative_is_not_confirmed() {
        let result = run_fixture("xss_negative.java", "renderPage", Cap::HTML_ESCAPE, 17);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "xss_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn java_xss_adversarial_is_oracle_collision() {
        let result = run_fixture("xss_adversarial.java", "renderPage", Cap::HTML_ESCAPE, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn java_xss_unsupported_is_confidence_too_low() {
        let path = fixture_path("xss_unsupported.java");
        let mut d = make_diag(&path, "render", Cap::HTML_ESCAPE, 7);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn make_diag(path: &Path, func: &str, cap: Cap, sink_line: u32) -> Diag {
        let path_str = path.to_string_lossy().into_owned();
        let evidence = Evidence {
            flow_steps: vec![
                FlowStep {
                    step: 1,
                    kind: FlowStepKind::Source,
                    file: path_str.clone(),
                    line: 1,
                    col: 0,
                    snippet: None,
                    variable: Some("payload".into()),
                    callee: None,
                    function: Some(func.to_owned()),
                    is_cross_file: false,
                },
                FlowStep {
                    step: 2,
                    kind: FlowStepKind::Sink,
                    file: path_str.clone(),
                    line: sink_line,
                    col: 4,
                    snippet: None,
                    variable: None,
                    callee: None,
                    function: None,
                    is_cross_file: false,
                },
            ],
            sink_caps: cap.bits(),
            ..Default::default()
        };
        Diag {
            path: path_str,
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
            evidence: Some(evidence),
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
}

// ── Phase 14: per-shape acceptance ───────────────────────────────────────────

#[cfg(feature = "dynamic")]
mod phase14_shape_tests {
    use crate::common::fixture_harness::{run_shape_fixture_lang_or_skip, Prerequisite};
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    fn assert_confirmed(shape: &str, result: &VerifyResult) {
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/vuln: expected Confirmed, got {:?} ({:?})",
            result.status,
            result.detail,
        );
    }

    fn assert_not_confirmed(shape: &str, result: &VerifyResult) {
        assert!(
            matches!(
                result.status,
                VerifyStatus::NotConfirmed | VerifyStatus::Inconclusive
            ),
            "{shape}/benign: expected NotConfirmed (or Inconclusive), got {:?} ({:?})",
            result.status,
            result.detail,
        );
        assert_ne!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/benign: must not confirm",
        );
    }

    fn run(
        shape: &str,
        file: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
        kind: EntryKind,
        slot: PayloadSlot,
    ) -> Option<VerifyResult> {
        // Phase 29 (Track I): replace the bespoke `java_available()` +
        // per-test `eprintln!("SKIP ..."); return;` blocks with the
        // structured `Prerequisite::CommandAvailable("javac"|"java")`
        // gate.  The helper emits the same SKIP line and returns `None`
        // so each test can short-circuit via `let Some(r) = run(...)
        // else { return; };`.
        run_shape_fixture_lang_or_skip(
            &[
                Prerequisite::CommandAvailable("javac"),
                Prerequisite::CommandAvailable("java"),
            ],
            Lang::Java, "java", shape, file, func, cap, sink_line, kind, slot,
        )
    }

    // ── static_method ────────────────────────────────────────────────────────

    #[test]
    fn static_method_vuln_is_confirmed() {
        let Some(r) = run(
            "static_method", "Vuln.java", "processInput", Cap::CODE_EXEC, 12,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("static_method", &r);
    }

    #[test]
    fn static_method_benign_not_confirmed() {
        let Some(r) = run(
            "static_method", "Benign.java", "processInput", Cap::CODE_EXEC, 13,
            EntryKind::Function, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("static_method", &r);
    }

    // ── static_main ──────────────────────────────────────────────────────────

    #[test]
    fn static_main_vuln_is_confirmed() {
        let Some(r) = run(
            "static_main", "Vuln.java", "main", Cap::CODE_EXEC, 13,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_confirmed("static_main", &r);
    }

    #[test]
    fn static_main_benign_not_confirmed() {
        let Some(r) = run(
            "static_main", "Benign.java", "main", Cap::CODE_EXEC, 12,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_not_confirmed("static_main", &r);
    }

    // ── servlet_doget ────────────────────────────────────────────────────────

    #[test]
    fn servlet_doget_vuln_is_confirmed() {
        let Some(r) = run(
            "servlet_doget", "Vuln.java", "doGet", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("payload".into()),
        ) else {
            return;
        };
        assert_confirmed("servlet_doget", &r);
    }

    #[test]
    fn servlet_doget_benign_not_confirmed() {
        let Some(r) = run(
            "servlet_doget", "Benign.java", "doGet", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("payload".into()),
        ) else {
            return;
        };
        assert_not_confirmed("servlet_doget", &r);
    }

    // ── servlet_dopost ───────────────────────────────────────────────────────

    #[test]
    fn servlet_dopost_vuln_is_confirmed() {
        let Some(r) = run(
            "servlet_dopost", "Vuln.java", "doPost", Cap::CODE_EXEC, 13,
            EntryKind::HttpRoute, PayloadSlot::HttpBody,
        ) else {
            return;
        };
        assert_confirmed("servlet_dopost", &r);
    }

    #[test]
    fn servlet_dopost_benign_not_confirmed() {
        let Some(r) = run(
            "servlet_dopost", "Benign.java", "doPost", Cap::CODE_EXEC, 12,
            EntryKind::HttpRoute, PayloadSlot::HttpBody,
        ) else {
            return;
        };
        assert_not_confirmed("servlet_dopost", &r);
    }

    // ── spring_controller ────────────────────────────────────────────────────

    #[test]
    fn spring_controller_vuln_is_confirmed() {
        let Some(r) = run(
            "spring_controller", "Vuln.java", "run", Cap::CODE_EXEC, 16,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("spring_controller", &r);
    }

    #[test]
    fn spring_controller_benign_not_confirmed() {
        let Some(r) = run(
            "spring_controller", "Benign.java", "run", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("spring_controller", &r);
    }

    // ── junit_test ───────────────────────────────────────────────────────────

    #[test]
    fn junit_test_vuln_is_confirmed() {
        let Some(r) = run(
            "junit_test", "Vuln.java", "testRun", Cap::CODE_EXEC, 17,
            EntryKind::Function, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_confirmed("junit_test", &r);
    }

    #[test]
    fn junit_test_benign_not_confirmed() {
        let Some(r) = run(
            "junit_test", "Benign.java", "testRun", Cap::CODE_EXEC, 15,
            EntryKind::Function, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_not_confirmed("junit_test", &r);
    }

    // ── quarkus_route ────────────────────────────────────────────────────────

    #[test]
    fn quarkus_route_vuln_is_confirmed() {
        let Some(r) = run(
            "quarkus_route", "Vuln.java", "run", Cap::CODE_EXEC, 17,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("quarkus_route", &r);
    }

    #[test]
    fn quarkus_route_benign_not_confirmed() {
        let Some(r) = run(
            "quarkus_route", "Benign.java", "run", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("quarkus_route", &r);
    }

    // ── Phase 09 staging assertion (Spring transitive dep pick-up) ──────────

    /// Verify the Phase 09 staging path identifies Spring when the
    /// source carries an `@Autowired`-style import line.  This is the
    /// literal Phase 14 acceptance bullet: "Spring fixture exercises
    /// `@Autowired` to validate the Phase 09 staging picks up
    /// transitive deps."
    ///
    /// The Spring fixture itself uses default-package stubs at runtime
    /// (so plain `javac` can compile it) — this test exercises the
    /// import-extraction path against a Spring-shaped source snippet
    /// independent of the runtime path.
    #[test]
    fn phase09_staging_picks_up_spring_autowired_imports() {
        use nyx_scanner::dynamic::environment::capture_project_dependencies;
        use nyx_scanner::dynamic::lang::java::materialize_java;
        use nyx_scanner::dynamic::spec::{
            EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy,
        };
        use std::io::Write;

        let project_root = tempfile::TempDir::new().expect("tempdir");
        let entry_path = project_root.path().join("App.java");
        {
            let mut f = std::fs::File::create(&entry_path).unwrap();
            f.write_all(
                br#"import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/run")
public class App {
    @Autowired
    private CommandRunner runner;
}
"#,
            )
            .unwrap();
        }
        let spec = HarnessSpec {
            finding_id: "phase14staging00".into(),
            entry_file: "App.java".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::Java,
            toolchain_id: "java-17".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "App.java".into(),
            sink_line: 8,
            spec_hash: "phase14staging00".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        };

        let captured = capture_project_dependencies(project_root.path(), &spec);
        assert!(
            captured.direct_deps.iter().any(|d| d == "org"),
            "capture_project_dependencies must surface the `org` segment \
             from Spring imports; got {:?}",
            captured.direct_deps,
        );

        // Stage to a workdir + materialize the manifest to round-trip
        // the dep through the Phase 09 emitter chain.  Note: the
        // current `is_java_stdlib` filter rejects `org` / `com` /
        // `jakarta` because the Phase 09 import extractor only retains
        // the first dotted segment, which is ambiguous between JDK and
        // third-party.  Phase 14's contract is "staging picks up the
        // dep" — the dep landing in `env.direct_deps` is the
        // observable promise; promoting it to a real `<groupId>` lives
        // behind the richer-registry follow-up in deferred.md.
        let workdir = tempfile::TempDir::new().expect("tempdir");
        let env = nyx_scanner::dynamic::environment::stage_workdir_full(
            &captured,
            workdir.path(),
            &spec.spec_hash,
            Lang::Java,
        )
        .expect("stage_workdir_full");
        assert!(
            env.direct_deps.iter().any(|d| d == "org"),
            "env.direct_deps must carry the captured `org` segment; got {:?}",
            env.direct_deps,
        );
        let artifacts = materialize_java(&env);
        let pom = artifacts
            .files
            .iter()
            .find(|(p, _)| p == "pom.xml")
            .expect("materialize_java emits pom.xml");
        assert!(
            pom.1.contains("<project"),
            "pom.xml must be well-formed XML; got: {}",
            pom.1,
        );
    }
}

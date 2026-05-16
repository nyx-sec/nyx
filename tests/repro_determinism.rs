//! Repro determinism test (§18.2).
//!
//! For every `Confirmed` fixture: the repro artifact `expected/outcome.json`
//! produced during verification must be byte-identical when regenerated from
//! the repro bundle.
//!
//! Tests are gated on `#[cfg(feature = "dynamic")]` and Python availability.
//! They are also skipped if no `Confirmed` fixtures have been produced yet
//! (trivially passes — zero assertions).

#[cfg(feature = "dynamic")]
mod repro_determinism_tests {
    use nyx_scanner::dynamic::repro;
    use nyx_scanner::dynamic::sandbox::{SandboxOptions, SandboxOutcome};
    use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use nyx_scanner::evidence::{AttemptSummary, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;
    use std::time::Duration;
    use tempfile::TempDir;

    fn make_confirmed_spec(spec_hash: &str) -> HarnessSpec {
        HarnessSpec {
            finding_id: "determinism00001".into(),
            entry_file: "app.py".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "python-3".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "app.py".into(),
            sink_line: 10,
            spec_hash: spec_hash.to_owned(),
            derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    fn make_confirmed_outcome() -> SandboxOutcome {
        SandboxOutcome {
            exit_code: Some(0),
            stdout: b"NYX_SQL_CONFIRMED\nsome extra output".to_vec(),
            stderr: vec![],
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: true,
            duration: Duration::from_millis(150),
            hardening_outcome: None,
        }
    }

    fn make_confirmed_verdict(finding_id: &str) -> VerifyResult {
        VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Confirmed,
            triggered_payload: Some("sqli-union-nyx".into()),
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![AttemptSummary {
                payload_label: "sqli-union-nyx".into(),
                exit_code: Some(0),
                timed_out: false,
                triggered: true,
                sink_hit: true,
            }],
            toolchain_match: Some("exact".into()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }
    }

    /// Write a repro bundle and verify it round-trips correctly.
    #[test]
    fn confirmed_repro_is_deterministic() {
        let dir = TempDir::new().unwrap();
        // Override repro base to temp dir.
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_spec("determ0000000001");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("determinism00001");

        // Write repro bundle (first time).
        let artifact1 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "# harness source v1\n",
            "def login(x): pass\n",
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
            "sqli-union-nyx",
            None,
        ).expect("first repro write must succeed");

        let outcome_json_1 =
            std::fs::read_to_string(artifact1.root.join("expected/outcome.json"))
            .expect("outcome.json must exist after first write");

        // Write repro bundle (second time, same inputs).
        // Remove existing dir first (simulate fresh run).
        std::fs::remove_dir_all(&artifact1.root).unwrap();

        let artifact2 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "# harness source v1\n",
            "def login(x): pass\n",
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
            "sqli-union-nyx",
            None,
        ).expect("second repro write must succeed");

        let outcome_json_2 =
            std::fs::read_to_string(artifact2.root.join("expected/outcome.json"))
            .expect("outcome.json must exist after second write");

        assert_eq!(
            outcome_json_1, outcome_json_2,
            "outcome.json must be byte-identical across two runs with the same inputs"
        );

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    /// Verify that redacted outcome.json does not contain the secret.
    #[test]
    fn outcome_json_secrets_are_redacted() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_spec("determ0000000002");
        let opts = SandboxOptions::default();
        let mut outcome = make_confirmed_outcome();
        // Inject a fake AWS key into stdout.
        outcome.stdout = b"AKIAFAKETEST00000000 result ok NYX_SQL_CONFIRMED".to_vec();
        let verdict = make_confirmed_verdict("determinism00002");

        let artifact = repro::write(
            &spec, &opts, &outcome, &verdict,
            "# harness", "# entry", b"payload", "label", None,
        ).expect("repro write must succeed");

        let outcome_json =
            std::fs::read_to_string(artifact.root.join("expected/outcome.json")).unwrap();

        assert!(
            !outcome_json.contains("AKIAFAKETEST00000000"),
            "AWS key must be redacted from outcome.json; got: {outcome_json}"
        );

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    // ── Rust repro tests ─────────────────────────────────────────────────────

    fn make_confirmed_rust_spec(spec_hash: &str) -> HarnessSpec {
        HarnessSpec {
            finding_id: "rust_determ00001".into(),
            entry_file: "src/entry.rs".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Rust,
            toolchain_id: "rust-stable".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/entry.rs".into(),
            sink_line: 18,
            spec_hash: spec_hash.to_owned(),
            derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    fn make_confirmed_rust_harness_source() -> String {
        r#"mod entry;
fn main() {
    let payload = std::env::var("NYX_PAYLOAD").unwrap_or_default();
    entry::run(&payload);
}
"#
        .into()
    }

    /// Rust repro bundle has the correct layout.
    ///
    /// For Rust, harness is at `harness/src/main.rs` and `harness/Cargo.toml`
    /// is also written (unlike Python which uses `harness/harness.py`).
    #[test]
    fn rust_repro_layout_is_correct() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_rust_spec("rust_determ00001");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("rust_determ00001");
        let harness_src = make_confirmed_rust_harness_source();

        let artifact = repro::write(
            &spec,
            &opts,
            &outcome,
            &verdict,
            &harness_src,
            "pub fn run(payload: &str) { println!(\"{}\", payload); }\n",
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
            "sqli-union-nyx",
            None,
        )
        .expect("Rust repro write must succeed");

        // Rust-specific layout: harness lives under harness/src/main.rs.
        assert!(
            artifact.root.join("harness/src/main.rs").exists(),
            "Rust harness must be at harness/src/main.rs"
        );
        assert!(
            artifact.root.join("harness/Cargo.toml").exists(),
            "Rust harness must include harness/Cargo.toml"
        );
        // Common layout.
        assert!(artifact.root.join("manifest.json").exists());
        assert!(artifact.root.join("entry/extracted_source.rs").exists());
        assert!(artifact.root.join("payload/payload.bin").exists());
        assert!(artifact.root.join("expected/outcome.json").exists());
        assert!(artifact.root.join("expected/verdict.json").exists());
        assert!(artifact.root.join("reproduce.sh").exists());

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    /// Rust repro outcome.json is byte-identical across two writes.
    #[test]
    fn rust_repro_outcome_is_deterministic() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_rust_spec("rust_determ00002");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("rust_determ00002");
        let harness_src = make_confirmed_rust_harness_source();
        let entry_src = "pub fn run(payload: &str) { println!(\"{}\", payload); }\n";

        let artifact1 = repro::write(
            &spec,
            &opts,
            &outcome,
            &verdict,
            &harness_src,
            entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
            "sqli-union-nyx",
            None,
        )
        .expect("first Rust repro write");
        let json1 =
            std::fs::read_to_string(artifact1.root.join("expected/outcome.json")).unwrap();

        std::fs::remove_dir_all(&artifact1.root).unwrap();

        let artifact2 = repro::write(
            &spec,
            &opts,
            &outcome,
            &verdict,
            &harness_src,
            entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
            "sqli-union-nyx",
            None,
        )
        .expect("second Rust repro write");
        let json2 =
            std::fs::read_to_string(artifact2.root.join("expected/outcome.json")).unwrap();

        assert_eq!(
            json1, json2,
            "Rust outcome.json must be byte-identical across two writes"
        );

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    // ── JS repro tests ───────────────────────────────────────────────────────

    fn make_confirmed_js_spec(spec_hash: &str) -> HarnessSpec {
        HarnessSpec {
            finding_id: "js_determ000001".into(),
            entry_file: "tests/dynamic_fixtures/js/sqli_positive.js".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::JavaScript,
            toolchain_id: "node-20".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "tests/dynamic_fixtures/js/sqli_positive.js".into(),
            sink_line: 8,
            spec_hash: spec_hash.to_owned(),
            derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    #[test]
    fn js_repro_outcome_is_deterministic() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_js_spec("js_determ000001a");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("js_determ000001");
        let entry_src = "function login(username) { console.log(username); }\n";

        let artifact1 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "// harness js\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("first JS repro write");
        let json1 =
            std::fs::read_to_string(artifact1.root.join("expected/outcome.json")).unwrap();

        std::fs::remove_dir_all(&artifact1.root).unwrap();

        let artifact2 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "// harness js\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("second JS repro write");
        let json2 =
            std::fs::read_to_string(artifact2.root.join("expected/outcome.json")).unwrap();

        assert_eq!(json1, json2, "JS outcome.json must be byte-identical across two writes");

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    // ── Go repro tests ───────────────────────────────────────────────────────

    fn make_confirmed_go_spec(spec_hash: &str) -> HarnessSpec {
        HarnessSpec {
            finding_id: "go_determ000001".into(),
            entry_file: "tests/dynamic_fixtures/go/sqli_positive.go".into(),
            entry_name: "Login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Go,
            toolchain_id: "go-1.21".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "tests/dynamic_fixtures/go/sqli_positive.go".into(),
            sink_line: 12,
            spec_hash: spec_hash.to_owned(),
            derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    #[test]
    fn go_repro_outcome_is_deterministic() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_go_spec("go_determ000001a");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("go_determ000001");
        let entry_src = "package entry\nfunc Login(username string) {}\n";

        let artifact1 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "// harness go\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("first Go repro write");
        let json1 =
            std::fs::read_to_string(artifact1.root.join("expected/outcome.json")).unwrap();

        std::fs::remove_dir_all(&artifact1.root).unwrap();

        let artifact2 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "// harness go\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("second Go repro write");
        let json2 =
            std::fs::read_to_string(artifact2.root.join("expected/outcome.json")).unwrap();

        assert_eq!(json1, json2, "Go outcome.json must be byte-identical across two writes");

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    // ── Java repro tests ─────────────────────────────────────────────────────

    fn make_confirmed_java_spec(spec_hash: &str) -> HarnessSpec {
        HarnessSpec {
            finding_id: "java_determ00001".into(),
            entry_file: "tests/dynamic_fixtures/java/sqli_positive.java".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Java,
            toolchain_id: "java-21".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "tests/dynamic_fixtures/java/sqli_positive.java".into(),
            sink_line: 9,
            spec_hash: spec_hash.to_owned(),
            derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    #[test]
    fn java_repro_outcome_is_deterministic() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_java_spec("java_determ00001a");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("java_determ00001");
        let entry_src = "public class Entry { public static void login(String u) {} }\n";

        let artifact1 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "// NyxHarness.java\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("first Java repro write");
        let json1 =
            std::fs::read_to_string(artifact1.root.join("expected/outcome.json")).unwrap();

        std::fs::remove_dir_all(&artifact1.root).unwrap();

        let artifact2 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "// NyxHarness.java\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("second Java repro write");
        let json2 =
            std::fs::read_to_string(artifact2.root.join("expected/outcome.json")).unwrap();

        assert_eq!(json1, json2, "Java outcome.json must be byte-identical across two writes");

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    // ── PHP repro tests ──────────────────────────────────────────────────────

    fn make_confirmed_php_spec(spec_hash: &str) -> HarnessSpec {
        HarnessSpec {
            finding_id: "php_determ000001".into(),
            entry_file: "tests/dynamic_fixtures/php/sqli_positive.php".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Php,
            toolchain_id: "php-8".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "tests/dynamic_fixtures/php/sqli_positive.php".into(),
            sink_line: 9,
            spec_hash: spec_hash.to_owned(),
            derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
        }
    }

    #[test]
    fn php_repro_outcome_is_deterministic() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_php_spec("php_determ000001a");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("php_determ000001");
        let entry_src = "<?php\nfunction login($username) {}\n";

        let artifact1 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "<?php // harness\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("first PHP repro write");
        let json1 =
            std::fs::read_to_string(artifact1.root.join("expected/outcome.json")).unwrap();

        std::fs::remove_dir_all(&artifact1.root).unwrap();

        let artifact2 = repro::write(
            &spec, &opts, &outcome, &verdict,
            "<?php // harness\n", entry_src,
            b"' UNION SELECT 'NYX_SQL_CONFIRMED'--", "sqli-union-nyx", None,
        ).expect("second PHP repro write");
        let json2 =
            std::fs::read_to_string(artifact2.root.join("expected/outcome.json")).unwrap();

        assert_eq!(json1, json2, "PHP outcome.json must be byte-identical across two writes");

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    /// Verify verdict.json is correctly structured.
    #[test]
    fn verdict_json_is_valid() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_confirmed_spec("determ0000000003");
        let opts = SandboxOptions::default();
        let outcome = make_confirmed_outcome();
        let verdict = make_confirmed_verdict("determinism00003");

        let artifact = repro::write(
            &spec, &opts, &outcome, &verdict,
            "# harness", "# entry", b"payload", "label", None,
        ).expect("repro write must succeed");

        let verdict_json =
            std::fs::read_to_string(artifact.root.join("expected/verdict.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&verdict_json).unwrap();

        assert_eq!(parsed["status"], "Confirmed");
        assert_eq!(parsed["finding_id"], "determinism00003");

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }
}

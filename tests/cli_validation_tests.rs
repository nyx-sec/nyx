//! CLI argument validation regression tests.
//!
//! Nyx's surface is a `clap` parser plus a handful of downstream validators
//! (`SeverityFilter::parse`, `Severity::from_str`, `Confidence::from_str`,
//! `apply_profile`).  These tests lock in the user-visible contract that
//! bad input exits non-zero with a message that names the offending flag ,
//! a scanner that silently accepts a typo'd severity and returns zero
//! findings is a footgun in CI.
//!
//! The scanner binary reads its configuration from a platform-dependent
//! project directory (macOS: `$HOME/Library/Application Support/nyx`;
//! Linux: `$XDG_CONFIG_HOME/nyx`).  Each test redirects both env vars to a
//! tempdir so the developer's real config is never touched and runs are
//! reproducible.

use assert_cmd::Command;
use nyx_scanner::commands::scan::Diag;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::path::PathBuf;

/// Build a scan command with a fresh config dir and a writable tempdir as
/// the scan target.  The caller layers extra args on top.
fn scan_cmd(tmp_home: &std::path::Path, scan_target: &std::path::Path) -> (Command, PathBuf) {
    let mut cmd = Command::cargo_bin("nyx").expect("nyx binary must exist");
    cmd.env("HOME", tmp_home)
        .env("XDG_CONFIG_HOME", tmp_home.join(".config"))
        .env("XDG_DATA_HOME", tmp_home.join(".local/share"))
        // Avoid the welcome banner / animation from interfering with exit codes.
        .env("NO_COLOR", "1");
    cmd.arg("scan").arg(scan_target);
    (cmd, scan_target.to_path_buf())
}

/// Prepare a scan tempdir with a single clean file so the scanner has a
/// valid target and only the flag being tested should produce an error.
fn prepare_scan_target() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ok.js"), b"var x = 1;\n").unwrap();
    dir
}

/// Nonexistent scan path: `Path::new(path).canonicalize()?` in `scan::handle`
/// returns an io::Error, which NyxError wraps and the process exits non-zero.
#[test]
fn scan_with_nonexistent_path_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let fake = home.path().join("does/not/exist/anywhere");
    let (mut cmd, _) = scan_cmd(home.path(), &fake);

    cmd.assert().failure().stderr(
        predicate::str::contains(fake.to_string_lossy().as_ref()).or(
            // On some platforms the error wraps the path inside an IO error
            // message; accept either direct mention or a canonicalize-shaped
            // error so the assertion isn't brittle to errno text. Windows
            // reports ERROR_PATH_NOT_FOUND as "cannot find the path specified".
            predicate::str::contains("canonicalize")
                .or(predicate::str::contains("No such file"))
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("cannot find")),
        ),
    );
}

/// Clap enforces `ValueEnum` for `--format`; an unknown value fails at parse
/// time with a usage message that lists the valid enum values.
#[test]
fn scan_with_unknown_format_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--format").arg("unknown-format-xyz");

    cmd.assert().failure().stderr(
        predicate::str::contains("format").and(
            predicate::str::contains("unknown-format-xyz")
                .or(predicate::str::contains("possible values")
                    .or(predicate::str::contains("invalid value"))),
        ),
    );
}

/// Clap enforces `ValueEnum` for `--mode`; an unknown value fails at parse
/// time.
#[test]
fn scan_with_unknown_mode_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--mode").arg("bogus-mode-xyz");

    cmd.assert()
        .failure()
        .stderr(
            predicate::str::contains("mode").and(
                predicate::str::contains("bogus-mode-xyz")
                    .or(predicate::str::contains("invalid value")),
            ),
        );
}

/// `--severity BOGUS` fails at `SeverityFilter::parse` with a message naming
/// the flag.
#[test]
fn scan_with_invalid_severity_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--severity").arg("BOGUSSEV");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("severity"));
}

/// `--fail-on BOGUS` fails at `Severity::from_str`.
#[test]
fn scan_with_invalid_fail_on_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--fail-on").arg("BOGUSSEV");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("fail-on").or(predicate::str::contains("severity")));
}

/// `--min-confidence bogus` fails at `Confidence::from_str`.
#[test]
fn scan_with_invalid_min_confidence_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--min-confidence").arg("ultra-extreme");

    cmd.assert().failure().stderr(
        predicate::str::contains("min-confidence").or(predicate::str::contains("confidence")),
    );
}

/// `--profile nonexistent-profile` fails at `config.apply_profile` which
/// errors with "unknown profile".
#[test]
fn scan_with_unknown_profile_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--profile").arg("not-a-real-profile-xyz");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("profile"));
}

/// Sanity check: the scan command with no flags on a valid target succeeds.
/// Guards against a regression where the redirected `HOME` / `XDG_CONFIG_HOME`
/// setup breaks scans (which would invalidate every negative test above).
#[test]
fn scan_with_no_extra_flags_on_clean_target_succeeds() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--format").arg("json");

    cmd.assert().success();
}

fn assert_stdout_is_json_from_byte_zero(output: &[u8], context: &str) -> Value {
    assert_eq!(
        output.first().copied(),
        Some(b'{'),
        "{context}: stdout must start with a JSON object, got prefix {:?}",
        String::from_utf8_lossy(&output[..output.len().min(80)])
    );
    serde_json::from_slice(output).unwrap_or_else(|e| {
        panic!(
            "{context}: stdout did not parse as JSON: {e}\n--- stdout prefix ---\n{}",
            String::from_utf8_lossy(&output[..output.len().min(400)])
        )
    })
}

#[test]
fn scan_json_stdout_is_machine_clean_when_tracing_warns() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.env("RUST_LOG", "warn")
        .args(["--format", "json", "--no-index", "--parse-timeout-ms", "0"]);

    let assert = cmd.assert().success();
    let value =
        assert_stdout_is_json_from_byte_zero(&assert.get_output().stdout, "nyx scan --format json");
    assert!(
        value.get("findings").is_some(),
        "JSON scan payload missing findings"
    );
}

#[test]
fn scan_respects_committed_triage_file_for_cli_output_and_fail_on() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join("app.js"),
        b"const q = req.query.x;\neval(q);\n",
    )
    .unwrap();
    let canonical_target = target.path().canonicalize().unwrap();

    let scan_args = [
        "--format",
        "json",
        "--quiet",
        "--index",
        "off",
        "--no-verify",
        "--all",
        "--include-quality",
        "--parse-timeout-ms",
        "0",
    ];
    let (mut first_cmd, _) = scan_cmd(home.path(), target.path());
    first_cmd.args(scan_args);
    let first = first_cmd.assert().success();
    let first_json = assert_stdout_is_json_from_byte_zero(
        &first.get_output().stdout,
        "initial nyx scan --format json",
    );
    let findings = first_json["findings"]
        .as_array()
        .expect("scan JSON must include findings");
    assert!(
        !findings.is_empty(),
        "fixture should emit at least one finding"
    );

    let decisions: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let diag: Diag = serde_json::from_value(finding.clone()).unwrap();
            json!({
                "fingerprint": nyx_scanner::server::models::compute_portable_fingerprint(
                    &diag,
                    &canonical_target,
                ),
                "state": "false_positive",
                "note": "fixture triaged by committed file",
                "rule_id": diag.id,
                "path": diag.path.strip_prefix(canonical_target.to_string_lossy().as_ref())
                    .unwrap_or(&diag.path)
                    .trim_start_matches('/')
            })
        })
        .collect();

    let nyx_dir = target.path().join(".nyx");
    std::fs::create_dir(&nyx_dir).unwrap();
    std::fs::write(
        nyx_dir.join("triage.json"),
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "decisions": decisions,
            "suppression_rules": []
        }))
        .unwrap(),
    )
    .unwrap();

    let (mut second_cmd, _) = scan_cmd(home.path(), target.path());
    second_cmd.args(scan_args).args(["--fail-on", "HIGH"]);
    let second = second_cmd.assert().success();
    let second_json = assert_stdout_is_json_from_byte_zero(
        &second.get_output().stdout,
        "triaged nyx scan --format json",
    );

    assert_eq!(
        second_json["findings"].as_array().unwrap().len(),
        0,
        "terminal triage decisions from .nyx/triage.json should be hidden by default"
    );
}

#[test]
fn scan_sarif_stdout_is_machine_clean_when_tracing_warns() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.env("RUST_LOG", "warn").args([
        "--format",
        "sarif",
        "--no-index",
        "--parse-timeout-ms",
        "0",
    ]);

    let assert = cmd.assert().success();
    let value = assert_stdout_is_json_from_byte_zero(
        &assert.get_output().stdout,
        "nyx scan --format sarif",
    );
    assert_eq!(value["version"], "2.1.0", "SARIF version missing");
}

#[test]
fn scan_quiet_suppresses_tracing_warnings() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.env("RUST_LOG", "warn").args([
        "--format",
        "json",
        "--quiet",
        "--no-index",
        "--parse-timeout-ms",
        "0",
    ]);

    let assert = cmd.assert().success();
    assert_stdout_is_json_from_byte_zero(
        &assert.get_output().stdout,
        "nyx scan --format json --quiet",
    );
    assert!(
        assert.get_output().stderr.is_empty(),
        "--quiet should suppress tracing/status stderr, got:\n{}",
        String::from_utf8_lossy(&assert.get_output().stderr)
    );
}

/// `--explain-engine` short-circuits the scan path and prints the resolved
/// engine configuration to stdout.  Exit code 0, non-empty stdout, and the
/// "Effective engine configuration" header present.
#[test]
fn scan_with_explain_engine_prints_config_and_exits_zero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--explain-engine");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Effective engine configuration"))
        .stdout(predicate::str::contains("Abstract interpretation"))
        .stdout(predicate::str::contains("Parse timeout"));
}

/// `--engine-profile` is a `ValueEnum`; valid values parse, invalid values
/// fail at the clap layer.
#[test]
fn scan_with_valid_engine_profile_succeeds() {
    for prof in &["fast", "balanced", "deep"] {
        let home = tempfile::tempdir().unwrap();
        let target = prepare_scan_target();
        let (mut cmd, _) = scan_cmd(home.path(), target.path());
        cmd.arg("--engine-profile").arg(prof);
        cmd.arg("--explain-engine");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(*prof));
    }
}

#[test]
fn scan_with_unknown_engine_profile_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--engine-profile").arg("bogus-profile-xyz");

    cmd.assert()
        .failure()
        .stderr(
            predicate::str::contains("engine-profile").and(
                predicate::str::contains("possible values")
                    .or(predicate::str::contains("invalid value")),
            ),
        );
}

/// Engine-profile + individual flag layering: `--engine-profile fast` turns
/// backwards analysis off, but a later `--backwards-analysis` flag wins.
#[test]
fn scan_engine_profile_is_overridden_by_individual_flag() {
    let home = tempfile::tempdir().unwrap();
    let target = prepare_scan_target();
    let (mut cmd, _) = scan_cmd(home.path(), target.path());
    cmd.arg("--engine-profile").arg("fast");
    cmd.arg("--backwards-analysis");
    cmd.arg("--explain-engine");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Backwards taint:         on"));
}

/// Scanning a directory that contains a C file emits the Preview-tier
/// banner on stderr.  Banner text is asserted loosely to tolerate future
/// wording changes without going brittle on the exact letter-for-letter
/// string.
#[test]
fn scan_c_file_emits_preview_tier_banner() {
    let home = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("hello.c"),
        b"#include <stdio.h>\nint main(void) { puts(\"hi\"); return 0; }\n",
    )
    .unwrap();

    let (mut cmd, _) = scan_cmd(home.path(), dir.path());
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Preview for C/C++").and(
            predicate::str::contains("Pointer aliasing").or(predicate::str::contains("clang-tidy")),
        ));
}

/// `--quiet` must suppress the Preview-tier banner along with the rest of
/// the status output.  Separate test so a regression in quiet-handling
/// surfaces clearly.
#[test]
fn scan_quiet_suppresses_preview_banner() {
    let home = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.c"), b"int main(void){return 0;}\n").unwrap();

    let (mut cmd, _) = scan_cmd(home.path(), dir.path());
    cmd.arg("--quiet");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Preview for C/C++").not());
}

/// JSON output format must not print the Preview banner either, machine-
/// readable output has to stay clean on both stdout and stderr.
#[test]
fn scan_json_format_suppresses_preview_banner() {
    let home = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.c"), b"int main(void){return 0;}\n").unwrap();

    let (mut cmd, _) = scan_cmd(home.path(), dir.path());
    cmd.arg("--format").arg("json");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Preview for C/C++").not());
}

//! End-to-end chain-composer regression test.
//!
//! Drives the built `nyx` binary against fixture projects crafted to
//! exercise the chain composer and asserts the JSON output carries at
//! least one entry in the top-level `chains` array.  Complements the
//! synthetic-input integration tests under `tests/chain_emission.rs` and
//! `tests/chain_reverify.rs` (which drive `find_chains` / `compose_chain`
//! directly) by closing the wire-format loop: a chain that drops out of
//! `find_chains` must still land in the scan command's output.
//!
//! Fixture acceptance contract (one per language under
//! `tests/dynamic_fixtures/chain_composer/<lang>/<scenario>/`):
//!
//! - The scanner must produce at least one `findings[]` entry.
//! - The scanner must produce at least one `chains[]` entry.
//! - The top chain's `severity` must be `critical` or `high`.
//! - The top chain's `members` array must be non-empty.
//!
//! New scenarios drop their root directory into [`SCENARIOS`] below.

use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;

struct Scenario {
    /// Path relative to `tests/dynamic_fixtures/chain_composer/`.
    rel_path: &'static str,
    /// Required `implied_impact` value on at least one emitted chain.
    /// `None` skips the impact assertion (kept as an escape hatch for
    /// future scenarios where the lattice match is intentionally a
    /// different category).
    required_impact: Option<&'static str>,
}

const SCENARIOS: &[Scenario] = &[Scenario {
    rel_path: "python/flask_eval",
    required_impact: Some("rce"),
}];

fn fixture_root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dynamic_fixtures/chain_composer")
        .join(rel)
}

fn run_scan_json(root: &PathBuf) -> Value {
    let assert = Command::cargo_bin("nyx")
        .expect("nyx binary")
        .args(["scan", "--format", "json"])
        .arg(root)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())
        .expect("nyx scan stdout is valid UTF-8");
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "nyx scan --format json produced invalid JSON for {}: {e}\n--- stdout ---\n{}\n",
            root.display(),
            stdout
        )
    })
}

#[test]
fn every_chain_composer_scenario_emits_at_least_one_chain() {
    assert!(
        !SCENARIOS.is_empty(),
        "SCENARIOS table must list at least one fixture"
    );

    for scenario in SCENARIOS {
        let root = fixture_root(scenario.rel_path);
        assert!(
            root.is_dir(),
            "fixture root missing for scenario {}: {}",
            scenario.rel_path,
            root.display()
        );
        let value = run_scan_json(&root);

        let findings = value
            .get("findings")
            .and_then(Value::as_array)
            .unwrap_or_else(|| {
                panic!(
                    "scenario {}: `findings` array missing from scan output",
                    scenario.rel_path
                )
            });
        assert!(
            !findings.is_empty(),
            "scenario {}: expected at least one finding, got 0.  Scan output:\n{}",
            scenario.rel_path,
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );

        let chains = value
            .get("chains")
            .and_then(Value::as_array)
            .unwrap_or_else(|| {
                panic!(
                    "scenario {}: `chains` array missing from scan output",
                    scenario.rel_path
                )
            });
        assert!(
            !chains.is_empty(),
            "scenario {}: expected at least one composed chain, got 0.  \
             Scan output:\n{}",
            scenario.rel_path,
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );

        let top = &chains[0];
        let severity = top
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        assert!(
            matches!(severity, "critical" | "high"),
            "scenario {}: top chain severity must be critical or high, \
             got {severity:?}.  Chain:\n{}",
            scenario.rel_path,
            serde_json::to_string_pretty(top).unwrap_or_default()
        );

        let members = top
            .get("members")
            .and_then(Value::as_array)
            .unwrap_or_else(|| {
                panic!(
                    "scenario {}: top chain has no `members` array",
                    scenario.rel_path
                )
            });
        assert!(
            !members.is_empty(),
            "scenario {}: top chain must have at least one member",
            scenario.rel_path
        );

        if let Some(expected) = scenario.required_impact {
            let any_match = chains.iter().any(|c| {
                c.get("implied_impact")
                    .and_then(Value::as_str)
                    .is_some_and(|v| v == expected)
            });
            assert!(
                any_match,
                "scenario {}: no chain carried implied_impact={expected:?}.  \
                 Chains:\n{}",
                scenario.rel_path,
                serde_json::to_string_pretty(chains).unwrap_or_default()
            );
        }
    }
}

/// Locks the scan-pipeline wiring contract: when dynamic verification is
/// enabled (default), the composite chain re-verifier runs after the
/// chain-composition pass and stamps each top-N chain's
/// `dynamic_verdict` so downstream consumers (`build_findings_json`,
/// `build_sarif_with_chains`, console renderer) see a populated field.
///
/// The verdict's *status* depends on the host's Python toolchain: when
/// `python3 -m venv` succeeds and the per-language chain-step harness
/// runs, the verdict resolves to `Confirmed`; when the toolchain is
/// missing it falls through to `Inconclusive(BackendInsufficient)`.
/// This test asserts only the wiring contract — that the field is
/// populated and the detail string reports coverage — so it stays green
/// on any host with a working `nyx` binary.
///
/// Gated on `feature = "dynamic"` because the reverifier lives behind
/// that flag.
#[cfg(feature = "dynamic")]
#[test]
fn flask_eval_chain_reverify_populates_dynamic_verdict() {
    let root = fixture_root("python/flask_eval");
    let value = run_scan_json(&root);

    let chains = value
        .get("chains")
        .and_then(Value::as_array)
        .expect("`chains` array missing from scan output");
    assert!(!chains.is_empty(), "expected at least one composed chain");

    let top = &chains[0];
    let dv = top
        .get("dynamic_verdict")
        .expect("`dynamic_verdict` key missing from top chain");
    assert!(
        !dv.is_null(),
        "top chain `dynamic_verdict` was null; wiring did not fire. Chain:\n{}",
        serde_json::to_string_pretty(top).unwrap_or_default()
    );

    let status = dv
        .get("status")
        .and_then(Value::as_str)
        .expect("verdict missing `status`");
    assert!(
        matches!(status, "Confirmed" | "Inconclusive" | "Unsupported"),
        "unexpected verdict status: {status:?}"
    );

    let detail = dv
        .get("detail")
        .and_then(Value::as_str)
        .expect("verdict missing `detail`");
    for segment in ["derived", "built", "ran"] {
        assert!(
            detail.contains(segment),
            "verdict detail missing `{segment}` coverage segment: {detail:?}"
        );
    }
}

/// Mirror of the above: with `--no-verify` the chain-reverify pass is
/// skipped and `dynamic_verdict` stays `null`.  Locks the cost-control
/// contract: users who opt out of dynamic verification do not pay the
/// per-chain build / sandbox cost.
#[cfg(feature = "dynamic")]
#[test]
fn flask_eval_chain_dynamic_verdict_is_null_when_verify_disabled() {
    let root = fixture_root("python/flask_eval");
    let assert = Command::cargo_bin("nyx")
        .expect("nyx binary")
        .args(["scan", "--no-verify", "--format", "json"])
        .arg(&root)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())
        .expect("nyx scan stdout is valid UTF-8");
    let value: Value = serde_json::from_str(&stdout)
        .expect("nyx scan --format json produced invalid JSON");

    let chains = value
        .get("chains")
        .and_then(Value::as_array)
        .expect("`chains` array missing");
    assert!(!chains.is_empty());

    let top = &chains[0];
    let dv = top.get("dynamic_verdict");
    assert!(
        matches!(dv, None | Some(Value::Null)),
        "top chain `dynamic_verdict` should be absent or null under --no-verify; got {dv:?}"
    );
}

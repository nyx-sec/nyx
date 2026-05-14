//! Phase 11 — Track D.4: deterministic secret derivation acceptance.
//!
//! Asserts:
//!
//! 1. [`derive_secret`] is byte-for-byte deterministic across runs with
//!    identical (`spec_hash`, `env_var_name`) inputs.
//! 2. Distinct env-var names produce distinct values under the same
//!    spec.
//! 3. Distinct spec hashes produce distinct values for the same env-var
//!    name (no cross-spec aliasing).
//! 4. Every value carries the `nyx-stub-` prefix so a leaked harness
//!    credential is recognisable.
//! 5. [`extract_env_var_references`] picks up every supported per-lang
//!    env access pattern for the languages currently in scope.
//! 6. [`build_secret_bag`] returns one entry per literally-referenced
//!    env var.
//! 7. End-to-end: the Phase 11 Flask fixture, when its captured env bag
//!    is injected as process env vars, boots without raising
//!    `KeyError: 'FLASK_SECRET'` (skipped on hosts without
//!    `python3 -c 'import flask'`).

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::environment::{
    build_secret_bag, derive_secret, extract_env_var_references, SECRET_VALUE_PREFIX,
};
use nyx_scanner::symbol::Lang;
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("dynamic_fixtures")
        .join("secret_injection")
        .join("flask_secret")
}

#[test]
fn derive_secret_is_deterministic() {
    let a = derive_secret("spec0001abcd1234", "FLASK_SECRET");
    let b = derive_secret("spec0001abcd1234", "FLASK_SECRET");
    assert_eq!(a, b, "same inputs must yield same output");
}

#[test]
fn derive_secret_has_stub_prefix() {
    let v = derive_secret("any-spec-hash", "ANY_VAR");
    assert!(
        v.as_str().starts_with(SECRET_VALUE_PREFIX),
        "missing nyx-stub- prefix: {v}"
    );
    // 32 hex chars after the prefix.
    assert_eq!(v.as_str().len(), SECRET_VALUE_PREFIX.len() + 32);
}

#[test]
fn derive_secret_distinguishes_env_var_names() {
    let a = derive_secret("specA", "FLASK_SECRET");
    let b = derive_secret("specA", "API_TOKEN");
    assert_ne!(a, b, "different env var names must produce distinct values");
}

#[test]
fn derive_secret_distinguishes_spec_hashes() {
    let a = derive_secret("specA", "FLASK_SECRET");
    let b = derive_secret("specB", "FLASK_SECRET");
    assert_ne!(a, b, "different spec hashes must produce distinct values");
}

#[test]
fn extract_env_var_references_python_patterns() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("app.py");
    std::fs::write(
        &path,
        r#"
import os
SECRET = os.environ["FLASK_SECRET"]
DB = os.environ.get("DATABASE_URL")
PORT = os.getenv("PORT", "8000")
DYNAMIC = os.environ.get(some_dynamic_var)  # skipped (non-literal)
"#,
    )
    .unwrap();
    let refs = extract_env_var_references(&path, Lang::Python);
    assert!(refs.contains(&"FLASK_SECRET".to_owned()), "refs = {refs:?}");
    assert!(refs.contains(&"DATABASE_URL".to_owned()), "refs = {refs:?}");
    assert!(refs.contains(&"PORT".to_owned()), "refs = {refs:?}");
    // Dynamic arg must be skipped.
    assert!(!refs.iter().any(|r| r == "some_dynamic_var"));
}

#[test]
fn extract_env_var_references_js_patterns() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("app.js");
    std::fs::write(
        &path,
        r#"
const a = process.env.NODE_ENV;
const b = process.env["DATABASE_URL"];
"#,
    )
    .unwrap();
    let refs = extract_env_var_references(&path, Lang::JavaScript);
    assert!(refs.contains(&"NODE_ENV".to_owned()), "refs = {refs:?}");
    assert!(refs.contains(&"DATABASE_URL".to_owned()), "refs = {refs:?}");
}

#[test]
fn extract_env_var_references_java_patterns() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("App.java");
    std::fs::write(
        &path,
        r#"
public class App {
    public static void main(String[] args) {
        String s = System.getenv("JWT_SECRET");
    }
}
"#,
    )
    .unwrap();
    let refs = extract_env_var_references(&path, Lang::Java);
    assert!(refs.contains(&"JWT_SECRET".to_owned()), "refs = {refs:?}");
}

#[test]
fn extract_env_var_references_rust_patterns() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("main.rs");
    std::fs::write(
        &path,
        r#"
fn main() {
    let s = std::env::var("HOME").unwrap();
    let t = env::var("PATH").unwrap_or_default();
}
"#,
    )
    .unwrap();
    let refs = extract_env_var_references(&path, Lang::Rust);
    assert!(refs.contains(&"HOME".to_owned()), "refs = {refs:?}");
    assert!(refs.contains(&"PATH".to_owned()), "refs = {refs:?}");
}

#[test]
fn extract_env_var_references_go_patterns() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("main.go");
    std::fs::write(
        &path,
        r#"
package main

import "os"

func main() {
    s := os.Getenv("HOME")
    t, _ := os.LookupEnv("PATH")
    _ = s
    _ = t
}
"#,
    )
    .unwrap();
    let refs = extract_env_var_references(&path, Lang::Go);
    assert!(refs.contains(&"HOME".to_owned()), "refs = {refs:?}");
    assert!(refs.contains(&"PATH".to_owned()), "refs = {refs:?}");
}

#[test]
fn build_secret_bag_returns_one_entry_per_var() {
    let path = fixture_root().join("app.py");
    let bag = build_secret_bag(&path, Lang::Python, "specphase11test1");

    // FLASK_SECRET (bare index) + API_TOKEN (.get with literal arg).
    let names: Vec<&str> = bag.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"FLASK_SECRET"), "bag = {bag:?}");
    assert!(names.contains(&"API_TOKEN"), "bag = {bag:?}");

    // Every value bears the stub prefix.
    for (_, v) in &bag {
        assert!(
            v.starts_with(SECRET_VALUE_PREFIX),
            "leaked unprefixed value: {v}"
        );
    }
}

/// End-to-end acceptance: the Phase 11 Flask fixture boots without
/// raising `KeyError: 'FLASK_SECRET'` once the derived secret bag is set
/// as process env vars.
///
/// Skipped on hosts where `python3 -c 'import flask'` fails — the
/// dynamic verifier itself is gated on the same precondition (see
/// `tests/env_capture_flask.rs`).
#[test]
fn flask_fixture_boots_with_derived_secret_env() {
    let has_python3 = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_python3 {
        eprintln!("python3 not on PATH — Phase 11 boot check skipped");
        return;
    }
    let has_flask = std::process::Command::new("python3")
        .args(["-c", "import flask"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_flask {
        eprintln!("flask not installed on host — Phase 11 boot check skipped");
        return;
    }

    let fixture = fixture_root();
    let app_py = fixture.join("app.py");
    let bag = build_secret_bag(&app_py, Lang::Python, "phase11specabcd1");
    assert!(
        bag.iter().any(|(n, _)| n == "FLASK_SECRET"),
        "fixture scan missed FLASK_SECRET: bag = {bag:?}"
    );

    // Spawn python3 in the fixture directory, env-clear, layer the bag
    // on top, and confirm the module imports without raising.
    let mut cmd = std::process::Command::new("python3");
    cmd.args(["-c", "import sys; sys.path.insert(0, '.'); import app; print('OK')"]);
    cmd.current_dir(&fixture);
    cmd.env_clear();
    // PATH is required so python3 can re-locate its stdlib; the
    // verifier's process backend preserves it via env_passthrough.
    if let Ok(p) = std::env::var("PATH") {
        cmd.env("PATH", p);
    }
    for (k, v) in &bag {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("invoke python3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fixture did not boot with derived secret env: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("OK"), "missing OK marker: {stdout}");
    assert!(
        !stderr.contains("KeyError"),
        "Phase 11 acceptance violated — KeyError raised: {stderr}"
    );
}

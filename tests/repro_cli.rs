#![cfg(feature = "dynamic")]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use std::path::{Path, PathBuf};

fn nyx_cmd(home: &Path, repro_base: &Path) -> Command {
    let mut cmd = Command::cargo_bin("nyx").expect("nyx binary must exist");
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("NYX_REPRO_BASE", repro_base)
        .env("NO_COLOR", "1");
    cmd
}

fn write_bundle(base: &Path, spec_hash: &str, finding_id: &str, script: &str) -> PathBuf {
    let root = base.join(spec_hash);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "corpus_version": 17,
            "entry_file": "/fixture/app.js",
            "entry_name": "handler",
            "finding_id": finding_id,
            "lang": "javascript",
            "sink_file": "/fixture/app.js",
            "sink_line": 7,
            "spec_format_version": 2,
            "spec_hash": spec_hash,
            "toolchain_id": "node-20"
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("reproduce.sh"), script).unwrap();
    root
}

#[test]
fn repro_by_finding_replays_matching_bundle() {
    let home = tempfile::tempdir().unwrap();
    let repro = tempfile::tempdir().unwrap();
    write_bundle(
        repro.path(),
        "specaaaaaaaaaaaa",
        "findaaaaaaaaaaaa",
        "#!/bin/sh\necho replay-ok\nexit 0\n",
    );

    let mut cmd = nyx_cmd(home.path(), repro.path());
    cmd.args(["repro", "--finding", "findaaaaaaaaaaaa"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Repro bundle:"))
        .stdout(predicate::str::contains("Finding: findaaaaaaaaaaaa"))
        .stdout(predicate::str::contains("replay-ok"))
        .stdout(predicate::str::contains("Replay result: pass"));
}

#[test]
fn repro_print_path_resolves_finding_without_replaying() {
    let home = tempfile::tempdir().unwrap();
    let repro = tempfile::tempdir().unwrap();
    let bundle = write_bundle(
        repro.path(),
        "specbbbbbbbbbbbb",
        "findbbbbbbbbbbbb",
        "#!/bin/sh\necho should-not-run\nexit 7\n",
    );

    let mut cmd = nyx_cmd(home.path(), repro.path());
    cmd.args(["repro", "--finding", "findbbbbbbbbbbbb", "--print-path"]);

    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("{}\n", bundle.display())))
        .stdout(predicate::str::contains("should-not-run").not());
}

#[test]
fn repro_by_spec_hash_replays_exact_cache_bundle() {
    let home = tempfile::tempdir().unwrap();
    let repro = tempfile::tempdir().unwrap();
    write_bundle(
        repro.path(),
        "speccccccccccccc",
        "findcccccccccccc",
        "#!/bin/sh\necho spec-replay-ok\nexit 0\n",
    );

    let mut cmd = nyx_cmd(home.path(), repro.path());
    cmd.args(["repro", "--spec-hash", "speccccccccccccc"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Spec: speccccccccccccc"))
        .stdout(predicate::str::contains("spec-replay-ok"));
}

#[test]
fn repro_missing_finding_exits_with_actionable_error() {
    let home = tempfile::tempdir().unwrap();
    let repro = tempfile::tempdir().unwrap();

    let mut cmd = nyx_cmd(home.path(), repro.path());
    cmd.args(["repro", "--finding", "missingffffffff", "--print-path"]);

    cmd.assert().failure().stderr(
        predicate::str::contains("no repro bundle found")
            .and(predicate::str::contains("missingffffffff"))
            .and(predicate::str::contains("nyx scan --verify")),
    );
}

#[test]
fn repro_preserves_script_exit_code_for_infra_failures() {
    let home = tempfile::tempdir().unwrap();
    let repro = tempfile::tempdir().unwrap();
    let bundle = write_bundle(
        repro.path(),
        "specdddddddddddd",
        "finddddddddddddd",
        "#!/bin/sh\necho docker nope >&2\nexit 2\n",
    );

    let mut cmd = nyx_cmd(home.path(), repro.path());
    cmd.arg("repro").arg("--bundle").arg(bundle).arg("--docker");

    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains("docker nope"))
        .stderr(predicate::str::contains("docker unavailable"));
}

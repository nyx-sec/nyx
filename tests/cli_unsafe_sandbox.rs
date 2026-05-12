//! CLI validation tests for --unsafe-sandbox and --backend flag interactions.
//!
//! Guards against regressions in the mutual-exclusion check between
//! `--unsafe-sandbox` and `--backend docker`.  The validation only fires when
//! the binary is built with `--features dynamic`; without it both flags are
//! silently accepted (no-op).

#[cfg(feature = "dynamic")]
mod dynamic_sandbox_cli {
    use assert_cmd::Command;
    use predicates::prelude::*;

    fn scan_cmd_with_fresh_env() -> Command {
        let home = tempfile::tempdir().expect("tempdir");
        let mut cmd = Command::cargo_bin("nyx").expect("nyx binary");
        cmd.env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join(".config"))
            .env("XDG_DATA_HOME", home.path().join(".local/share"))
            .env("NO_COLOR", "1");
        // Scan a non-existent path; the backend validation runs before any
        // filesystem work so the path doesn't need to exist for these tests.
        cmd.args(["scan", "/dev/null/nonexistent"]);
        cmd
    }

    /// `--unsafe-sandbox --backend docker` must be rejected with a clear error.
    #[test]
    fn unsafe_sandbox_with_docker_backend_is_rejected() {
        let mut cmd = scan_cmd_with_fresh_env();
        cmd.args(["--unsafe-sandbox", "--backend", "docker"]);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains(
                "--unsafe-sandbox and --backend docker are mutually exclusive",
            ));
    }

    /// `--unsafe-sandbox` alone (no explicit --backend) must NOT trigger the
    /// mutual-exclusion error.  It may fail for other reasons (path not found,
    /// no findings, etc.) but not with the mutex message.
    #[test]
    fn unsafe_sandbox_alone_does_not_trigger_mutex_error() {
        let mut cmd = scan_cmd_with_fresh_env();
        cmd.arg("--unsafe-sandbox");
        cmd.assert().stderr(
            predicate::str::contains(
                "--unsafe-sandbox and --backend docker are mutually exclusive",
            )
            .not(),
        );
    }
}

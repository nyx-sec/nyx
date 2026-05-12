//! Repro artifact writer (§18.1).
//!
//! Emits a self-contained repro bundle at:
//!   `~/.cache/nyx/dynamic/repro/{spec_hash}/`
//!
//! Layout:
//! ```text
//! {spec_hash}/
//!   manifest.json
//!   entry/
//!     extracted_source.{ext}
//!   harness/
//!     harness.py           (language-specific)
//!     Dockerfile.harness
//!   payload/
//!     payload.bin
//!     payload.meta.json
//!   sandbox/
//!     options.json
//!     env.allowlist.json
//!   expected/
//!     outcome.json         (redacted SandboxOutcome)
//!     verdict.json
//!   reproduce.sh
//!   README.md
//! ```

use crate::dynamic::sandbox::{SandboxOptions, SandboxOutcome};
use crate::dynamic::spec::HarnessSpec;
use crate::evidence::VerifyResult;
use crate::utils::redact;
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};

/// Emitted by [`write`] on success.
#[derive(Debug, Clone)]
pub struct ReproArtifact {
    /// Absolute path to the repro bundle root.
    pub root: PathBuf,
    /// Relative symlink from the project cache directory.
    pub symlink: Option<PathBuf>,
}

#[derive(Debug)]
pub enum ReproError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl From<std::io::Error> for ReproError {
    fn from(e: std::io::Error) -> Self {
        ReproError::Io(e)
    }
}

impl From<serde_json::Error> for ReproError {
    fn from(e: serde_json::Error) -> Self {
        ReproError::Json(e)
    }
}

impl std::fmt::Display for ReproError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReproError::Io(e) => write!(f, "I/O: {e}"),
            ReproError::Json(e) => write!(f, "JSON: {e}"),
        }
    }
}

/// Write the repro bundle for a verified finding.
///
/// `harness_source` is the generated harness source code.
/// `entry_source` is the extracted entry-point source (may be empty).
pub fn write(
    spec: &HarnessSpec,
    opts: &SandboxOptions,
    outcome: &SandboxOutcome,
    verdict: &VerifyResult,
    harness_source: &str,
    entry_source: &str,
    payload_bytes: &[u8],
    payload_label: &str,
    project_root: Option<&Path>,
) -> Result<ReproArtifact, ReproError> {
    let root = repro_root(&spec.spec_hash)?;

    // Create directory tree
    for sub in &["entry", "harness", "payload", "sandbox", "expected"] {
        fs::create_dir_all(root.join(sub))?;
    }

    // manifest.json
    let manifest = serde_json::json!({
        "spec_hash": spec.spec_hash,
        "finding_id": spec.finding_id,
        "lang": format!("{:?}", spec.lang).to_ascii_lowercase(),
        "toolchain_id": spec.toolchain_id,
        "entry_file": spec.entry_file,
        "entry_name": spec.entry_name,
        "sink_file": spec.sink_file,
        "sink_line": spec.sink_line,
        "spec_format_version": crate::dynamic::spec::SPEC_FORMAT_VERSION,
        "corpus_version": crate::dynamic::corpus::CORPUS_VERSION,
    });
    write_json(&root.join("manifest.json"), &manifest)?;

    // entry/extracted_source.<ext>
    let ext = source_ext_for_lang(&spec.lang);
    let entry_path = root.join("entry").join(format!("extracted_source.{ext}"));
    fs::write(&entry_path, entry_source.as_bytes())?;

    // harness/harness.{ext} (or for Rust: harness/src/main.rs)
    use crate::symbol::Lang;
    let harness_path = if matches!(spec.lang, Lang::Rust) {
        let src_dir = root.join("harness").join("src");
        fs::create_dir_all(&src_dir)?;
        // Also write Cargo.toml for Rust repro bundles.
        let cargo_content = crate::dynamic::lang::rust::generate_cargo_toml(spec.expected_cap);
        fs::write(root.join("harness").join("Cargo.toml"), cargo_content.as_bytes())?;
        src_dir.join("main.rs")
    } else {
        root.join("harness").join(format!("harness.{ext}"))
    };
    fs::write(&harness_path, harness_source.as_bytes())?;

    // harness/Dockerfile.harness
    let dockerfile = dockerfile_for_spec(spec);
    fs::write(root.join("harness").join("Dockerfile.harness"), dockerfile.as_bytes())?;

    // payload/payload.bin + payload.meta.json
    fs::write(root.join("payload").join("payload.bin"), payload_bytes)?;
    let payload_meta = serde_json::json!({
        "label": payload_label,
        "len": payload_bytes.len(),
        "encoding": "raw",
    });
    write_json(&root.join("payload").join("payload.meta.json"), &payload_meta)?;

    // sandbox/options.json
    let sandbox_opts = serde_json::json!({
        "timeout_secs": opts.timeout.as_secs_f64(),
        "memory_mib": opts.memory_mib,
        "backend": format!("{:?}", opts.backend),
    });
    write_json(&root.join("sandbox").join("options.json"), &sandbox_opts)?;

    // sandbox/env.allowlist.json
    let env_list: Vec<&str> = opts.env_passthrough.iter().map(|s| s.as_str()).collect();
    write_json(&root.join("sandbox").join("env.allowlist.json"), &serde_json::json!(env_list))?;

    // expected/outcome.json — redacted
    let redacted_stdout = redact::redact(&outcome.stdout);
    let redacted_stderr = redact::redact(&outcome.stderr);
    // duration_ms is omitted from the persisted outcome so that outcome.json is
    // byte-identical when regenerated from the repro bundle (§18.2 determinism).
    // Wall-clock timing goes to telemetry only.
    let outcome_json = serde_json::json!({
        "exit_code": outcome.exit_code,
        "stdout": String::from_utf8_lossy(&redacted_stdout),
        "stderr": String::from_utf8_lossy(&redacted_stderr),
        "timed_out": outcome.timed_out,
        "oob_callback_seen": outcome.oob_callback_seen,
        "sink_hit": outcome.sink_hit,
    });
    write_json(&root.join("expected").join("outcome.json"), &outcome_json)?;

    // expected/verdict.json
    write_json(&root.join("expected").join("verdict.json"), verdict)?;

    // reproduce.sh
    let reproduce_sh = reproduce_script(spec, payload_label);
    let reproduce_path = root.join("reproduce.sh");
    fs::write(&reproduce_path, reproduce_sh.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&reproduce_path, fs::Permissions::from_mode(0o755))?;
    }

    // README.md
    let readme = repro_readme(spec, verdict);
    fs::write(root.join("README.md"), readme.as_bytes())?;

    // Per-project symlink (§12 Q1)
    let symlink = if let Some(proj_root) = project_root {
        let link_dir = proj_root.join(".nyx").join("dynamic-cache").join("symlinks");
        let _ = fs::create_dir_all(&link_dir);
        let link_path = link_dir.join(&spec.spec_hash);
        let _ = create_symlink(&root, &link_path);
        Some(link_path)
    } else {
        None
    };

    Ok(ReproArtifact { root, symlink })
}

fn repro_root(spec_hash: &str) -> Result<PathBuf, ReproError> {
    // Respect test override.
    let base = if let Ok(p) = std::env::var("NYX_REPRO_BASE") {
        PathBuf::from(p)
    } else {
        let dirs = ProjectDirs::from("", "", "nyx")
            .ok_or_else(|| ReproError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot determine cache dir",
            )))?;
        dirs.cache_dir().join("dynamic").join("repro")
    };

    let root = base.join(spec_hash);
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(root)
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), ReproError> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json.as_bytes())?;
    Ok(())
}

fn source_ext_for_lang(lang: &crate::symbol::Lang) -> &'static str {
    use crate::symbol::Lang;
    match lang {
        Lang::Python => "py",
        Lang::JavaScript | Lang::TypeScript => "js",
        Lang::Rust => "rs",
        Lang::Go => "go",
        Lang::Java => "java",
        Lang::Php => "php",
        Lang::Ruby => "rb",
        Lang::C => "c",
        Lang::Cpp => "cpp",
    }
}

fn dockerfile_for_spec(spec: &HarnessSpec) -> String {
    use crate::symbol::Lang;
    match spec.lang {
        Lang::Rust => {
            let toolchain = spec.toolchain_id.strip_prefix("rust-").unwrap_or("stable");
            // Multi-stage: build with Rust, run the binary directly.
            format!(
                "FROM rust:{toolchain}-slim AS builder\n\
                 WORKDIR /harness\n\
                 COPY Cargo.toml Cargo.lock* ./\n\
                 COPY src/ src/\n\
                 RUN cargo build --release\n\n\
                 FROM debian:bookworm-slim\n\
                 WORKDIR /harness\n\
                 COPY --from=builder /harness/target/release/nyx_harness .\n\
                 CMD [\"/harness/nyx_harness\"]\n"
            )
        }
        Lang::Python => {
            let image = format!("python:{}", spec.toolchain_id.strip_prefix("python-").unwrap_or("3"));
            format!(
                "FROM {image}\nWORKDIR /harness\nCOPY harness.py .\nCMD [\"python3\", \"harness.py\"]\n"
            )
        }
        _ => {
            format!("# Unsupported language: {:?}\nFROM ubuntu:latest\n", spec.lang)
        }
    }
}

fn reproduce_script(spec: &HarnessSpec, payload_label: &str) -> String {
    use crate::symbol::Lang;
    let run_cmd = match spec.lang {
        Lang::Rust => {
            "NYX_PAYLOAD=\"$(cat payload/payload.bin)\" ./harness/nyx_harness".to_owned()
        }
        _ => {
            "NYX_PAYLOAD=\"$(cat payload/payload.bin)\" python3 harness/harness.py".to_owned()
        }
    };
    format!(
        "#!/bin/sh\n\
         # Repro script for finding {finding_id} ({payload_label})\n\
         set -e\n\
         SCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n\
         cd \"$SCRIPT_DIR\"\n\
         {run_cmd}\n",
        finding_id = spec.finding_id,
        payload_label = payload_label,
        run_cmd = run_cmd,
    )
}

fn repro_readme(spec: &HarnessSpec, verdict: &VerifyResult) -> String {
    format!(
        "# Nyx Dynamic Repro — {finding_id}\n\n\
         **Status**: {status:?}  \n\
         **Cap**: {cap}  \n\
         **Entry**: `{entry}`  \n\n\
         ## Reproduce\n\n\
         ```sh\n./reproduce.sh\n```\n\n\
         The expected outcome is in `expected/outcome.json`.\n",
        finding_id = spec.finding_id,
        status = verdict.status,
        cap = format!("{:?}", spec.expected_cap),
        entry = spec.entry_name,
    )
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    if link.exists() {
        fs::remove_file(link)?;
    }
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::sandbox::SandboxBackend;
    use crate::dynamic::spec::{EntryKind, PayloadSlot};
    use crate::evidence::{AttemptSummary, VerifyStatus};
    use crate::labels::Cap;
    use crate::symbol::Lang;
    use std::time::Duration;
    use tempfile::TempDir;

    fn make_spec() -> HarnessSpec {
        HarnessSpec {
            finding_id: "0000000000000002".into(),
            entry_file: "app.py".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "python-3.11".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "app.py".into(),
            sink_line: 10,
            spec_hash: "cafecafecafe0001".into(),
        }
    }

    fn make_outcome() -> SandboxOutcome {
        SandboxOutcome {
            exit_code: Some(0),
            stdout: b"__NYX_SINK_HIT__\nquery: SELECT 1=1".to_vec(),
            stderr: vec![],
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: true,
            duration: Duration::from_millis(250),
        }
    }

    fn make_verdict() -> VerifyResult {
        VerifyResult {
            finding_id: "0000000000000002".into(),
            status: VerifyStatus::Confirmed,
            triggered_payload: Some("sqli-or-1".into()),
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![AttemptSummary {
                payload_label: "sqli-or-1".into(),
                exit_code: Some(0),
                timed_out: false,
                triggered: true,
                sink_hit: true,
            }],
            toolchain_match: Some("exact".into()),
        }
    }

    #[test]
    fn write_creates_expected_layout() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_spec();
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..Default::default()
        };
        let outcome = make_outcome();
        let verdict = make_verdict();

        let artifact = write(
            &spec,
            &opts,
            &outcome,
            &verdict,
            "import sys\n# harness code\n",
            "def login(x): pass\n",
            b"' OR 1=1-- NYX",
            "sqli-or-1",
            None,
        )
        .unwrap();

        assert!(artifact.root.join("manifest.json").exists());
        assert!(artifact.root.join("entry/extracted_source.py").exists());
        assert!(artifact.root.join("harness/harness.py").exists());
        assert!(artifact.root.join("payload/payload.bin").exists());
        assert!(artifact.root.join("expected/outcome.json").exists());
        assert!(artifact.root.join("expected/verdict.json").exists());
        assert!(artifact.root.join("reproduce.sh").exists());

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    #[test]
    fn outcome_json_redacts_secrets() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };

        let spec = make_spec();
        let opts = SandboxOptions::default();
        let mut outcome = make_outcome();
        outcome.stdout = b"key=AKIAFAKETEST00000000 result=ok".to_vec();
        let verdict = make_verdict();

        let artifact = write(
            &spec, &opts, &outcome, &verdict,
            "# harness", "# entry", b"payload", "label", None,
        ).unwrap();

        let outcome_json = std::fs::read_to_string(artifact.root.join("expected/outcome.json")).unwrap();
        assert!(!outcome_json.contains("AKIAFAKETEST00000000"), "AWS key must be redacted in outcome.json");

        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }
}

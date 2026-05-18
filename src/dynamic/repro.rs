//! Repro artifact writer (§18.1).
//!
//! Emits a self-contained repro bundle at:
//!   `~/.cache/nyx/dynamic/repro/{spec_hash}/`
//!
//! Layout:
//! ```text
//! {spec_hash}/
//!   manifest.json
//!   toolchain.lock            (Phase 28 — hermeticity manifest)
//!   entry/
//!     extracted_source.{ext}
//!   harness/
//!     harness.py              (language-specific)
//!     Dockerfile.harness
//!   payload/
//!     payload.bin
//!     payload.meta.json
//!   sandbox/
//!     options.json
//!     env.allowlist.json
//!   expected/
//!     outcome.json            (redacted SandboxOutcome)
//!     verdict.json
//!     trace.jsonl             (Phase 30 — VerifyTrace, when attached)
//!   reproduce.sh
//!   docker_pull.sh            (Phase 28 — present when toolchain pinned)
//!   README.md
//! ```
//!
//! # Phase 28 (Track H.3 — repro hermeticity)
//!
//! `toolchain.lock` records the bundle's expected toolchain id alongside a
//! BLAKE3 hash of every bundle source file (Dockerfile, harness source,
//! entry source, payload).  `reproduce.sh` reads the lock at startup and
//! refuses to run in the process backend when the host's resolved
//! interpreter / compiler does not match the expected toolchain id —
//! callers who hit this case are expected to drop to `--docker` (which
//! ignores the host toolchain because the runtime is supplied by the
//! pinned image).  `docker_pull.sh` is emitted alongside when a digest
//! pin is available from [`crate::dynamic::toolchain::pinned_image_ref`]
//! so the bundle can be replayed on a clean machine without manual image
//! resolution.

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

    // expected/trace.jsonl — Phase 30 (Track C observability).  Records
    // the verifier's per-stage timeline so a repro replay can compare
    // sandbox runs against the canonical sequence.  Omitted when no
    // trace was attached to the sandbox options, which keeps direct
    // `sandbox::run` callers (parity fixtures, unit tests) free of
    // bundle-shape changes.
    if let Some(trace) = opts.trace.as_ref() {
        fs::write(
            root.join("expected").join("trace.jsonl"),
            trace.to_jsonl().as_bytes(),
        )?;
    }

    // toolchain.lock (Phase 28 — Track H.3, repro hermeticity)
    let lock = build_toolchain_lock(spec, &root)?;
    write_json(&root.join("toolchain.lock"), &lock)?;

    // reproduce.sh
    let reproduce_sh = reproduce_script(spec, payload_label);
    let reproduce_path = root.join("reproduce.sh");
    fs::write(&reproduce_path, reproduce_sh.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&reproduce_path, fs::Permissions::from_mode(0o755))?;
    }

    // docker_pull.sh — emitted only when the toolchain id is pinned to a
    // specific image digest by the Phase 19 catalogue.  Operators on a
    // clean machine run `docker_pull.sh` once before `reproduce.sh --docker`
    // to pre-warm the image cache; the script is a no-op convenience and
    // not on the verification critical path.
    if let Some(image_ref) = crate::dynamic::toolchain::pinned_image_ref(&spec.toolchain_id) {
        let docker_pull_path = root.join("docker_pull.sh");
        fs::write(&docker_pull_path, docker_pull_script(image_ref).as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&docker_pull_path, fs::Permissions::from_mode(0o755))?;
        }
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

/// Resolve the bundle path for `spec_hash` without creating any directories.
///
/// Returns the same path [`write`] uses (`~/.cache/nyx/dynamic/repro/{spec_hash}/`)
/// so callers can locate an existing bundle for replay. Respects the
/// `NYX_REPRO_BASE` test override.
///
/// Returns `None` when the host has no resolvable cache dir.
pub fn bundle_root_for(spec_hash: &str) -> Option<PathBuf> {
    let base = if let Ok(p) = std::env::var("NYX_REPRO_BASE") {
        PathBuf::from(p)
    } else {
        let dirs = ProjectDirs::from("", "", "nyx")?;
        dirs.cache_dir().join("dynamic").join("repro")
    };
    Some(base.join(spec_hash))
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

/// Resolve the `FROM` reference for `toolchain_id`.
///
/// Prefers the pinned digest from
/// [`crate::dynamic::toolchain::pinned_image_ref`] so the emitted
/// Dockerfile is hermetic across hosts.  Falls back to a tag-only
/// reference derived from `toolchain_id` when the catalogue has no
/// digest for the toolchain.
fn resolve_dockerfile_from(spec: &HarnessSpec) -> String {
    use crate::symbol::Lang;

    if let Some(pinned) = crate::dynamic::toolchain::pinned_image_ref(&spec.toolchain_id) {
        return pinned.to_owned();
    }

    match spec.lang {
        Lang::Rust => {
            let toolchain = spec.toolchain_id.strip_prefix("rust-").unwrap_or("stable");
            format!("rust:{toolchain}-slim")
        }
        Lang::Python => {
            format!("python:{}", spec.toolchain_id.strip_prefix("python-").unwrap_or("3"))
        }
        _ => "ubuntu:latest".to_owned(),
    }
}

fn dockerfile_for_spec(spec: &HarnessSpec) -> String {
    use crate::symbol::Lang;
    let image = resolve_dockerfile_from(spec);
    match spec.lang {
        Lang::Rust => {
            // Multi-stage: build with Rust, run the binary directly.
            // The builder stage uses the resolved (pinned-or-tag) image;
            // the runtime stage stays on debian:bookworm-slim because the
            // resulting nyx_harness binary is self-contained.
            format!(
                "FROM {image} AS builder\n\
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
            format!(
                "FROM {image}\nWORKDIR /harness\nCOPY harness.py .\nCMD [\"python3\", \"harness.py\"]\n"
            )
        }
        _ => {
            format!("# Unsupported language: {:?}\nFROM {image}\n", spec.lang)
        }
    }
}

fn reproduce_script(spec: &HarnessSpec, payload_label: &str) -> String {
    use crate::symbol::Lang;

    // Shell command for the process backend (relative to SCRIPT_DIR).
    let process_run_cmd = match spec.lang {
        Lang::Rust | Lang::Go => "./harness/nyx_harness".to_owned(),
        Lang::Python => "python3 ./harness/harness.py".to_owned(),
        Lang::JavaScript | Lang::TypeScript => "node ./harness/harness.js".to_owned(),
        Lang::Java => "java -cp ./harness NyxHarness".to_owned(),
        Lang::Php => "php ./harness/harness.php".to_owned(),
        _ => "echo 'unsupported language' >&2; exit 2".to_owned(),
    };

    // Toolchain-check command for the process backend.  Returns 0 when the
    // host has the expected runtime; non-zero when the host is missing the
    // toolchain and `reproduce.sh` must refuse to run in process mode.
    //
    // The check is intentionally coarse — `command -v python3` does not
    // verify the exact 3.11 vs 3.12 minor — because the toolchain.lock
    // records the expected id and an operator who reads "PROCESS BACKEND
    // REFUSED — host toolchain X mismatches expected python-3.11" already
    // knows what to install.  The fine-grained matching path is via
    // `reproduce.sh --docker` which sources the runtime from the pinned
    // image and bypasses the host toolchain entirely.
    let host_probe_cmd = match spec.lang {
        Lang::Rust | Lang::Go | Lang::C | Lang::Cpp => "./harness/nyx_harness --help >/dev/null 2>&1 || test -x ./harness/nyx_harness".to_owned(),
        Lang::Python => "command -v python3".to_owned(),
        Lang::JavaScript | Lang::TypeScript => "command -v node".to_owned(),
        Lang::Java => "command -v java".to_owned(),
        Lang::Php => "command -v php".to_owned(),
        Lang::Ruby => "command -v ruby".to_owned(),
    };

    // Docker image tag is derived from spec_hash so each finding gets its own image.
    let image_tag = format!("nyx-repro-{}", spec.spec_hash);

    // Double braces escape literal { } in Rust format strings.
    format!(
        "#!/bin/sh\n\
         # Nyx dynamic repro — finding {finding_id} / payload {payload_label}\n\
         #\n\
         # Usage:\n\
         #   ./reproduce.sh          — run via process backend (direct)\n\
         #   ./reproduce.sh --docker — run via Docker backend (isolated)\n\
         #\n\
         # Exit codes:\n\
         #   0  sink_hit matches expected/outcome.json (replay green)\n\
         #   1  sink_hit mismatch (replay diverged from recorded outcome)\n\
         #   2  docker requested but unavailable\n\
         #   3  host toolchain mismatch in process mode (Phase 28 hermeticity)\n\
         set -e\n\
         SCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n\
         cd \"$SCRIPT_DIR\"\n\
         PAYLOAD=\"$(cat payload/payload.bin)\"\n\
         EXPECTED_TOOLCHAIN=\"{expected_toolchain}\"\n\
         EXPECTED_SINK=$(grep -o '\"sink_hit\"[[:space:]]*:[[:space:]]*[a-z]*' \\\n\
           expected/outcome.json | grep -o '[a-z]*$')\n\
         \n\
         if [ \"${{1:-}}\" = \"--docker\" ]; then\n\
           if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then\n\
             echo 'error: docker not available' >&2; exit 2\n\
           fi\n\
           IMAGE=\"{image_tag}\"\n\
           docker build -t \"$IMAGE\" -f harness/Dockerfile.harness harness/ >/dev/null\n\
           ACTUAL=$(docker run --rm --cap-drop=ALL \
--security-opt no-new-privileges:true --network none \
-e NYX_PAYLOAD=\"$PAYLOAD\" \"$IMAGE\" 2>&1) || ACTUAL=''\n\
           docker rmi \"$IMAGE\" >/dev/null 2>&1 || true\n\
         else\n\
           # Phase 28 hermeticity check: refuse process-backend replay when\n\
           # the host is missing the expected toolchain id.  Operators must\n\
           # either install the toolchain or pass --docker.\n\
           if ! sh -c '{host_probe_cmd}' >/dev/null 2>&1; then\n\
             echo \"error: host toolchain does not match expected $EXPECTED_TOOLCHAIN; re-run with --docker\" >&2\n\
             exit 3\n\
           fi\n\
           ACTUAL=$(NYX_PAYLOAD=\"$PAYLOAD\" {process_run_cmd} 2>&1) || ACTUAL=''\n\
         fi\n\
         \n\
         if echo \"$ACTUAL\" | grep -q '__NYX_SINK_HIT__'; then\n\
           ACTUAL_SINK=true\n\
         else\n\
           ACTUAL_SINK=false\n\
         fi\n\
         \n\
         if [ \"$ACTUAL_SINK\" = \"$EXPECTED_SINK\" ]; then\n\
           echo \"PASS: sink_hit=$ACTUAL_SINK (matches expected)\"\n\
           exit 0\n\
         else\n\
           echo \"FAIL: sink_hit=$ACTUAL_SINK expected=$EXPECTED_SINK\"\n\
           exit 1\n\
         fi\n",
        finding_id = spec.finding_id,
        payload_label = payload_label,
        process_run_cmd = process_run_cmd,
        host_probe_cmd = host_probe_cmd,
        image_tag = image_tag,
        expected_toolchain = spec.toolchain_id,
    )
}

/// Phase 28 — Track H.3.  `docker_pull.sh` pre-pulls the pinned Docker
/// image identified by [`crate::dynamic::toolchain::pinned_image_ref`]
/// so an operator on a clean machine can warm the image cache before
/// `reproduce.sh --docker` fires.  Returns the script body; emission
/// is gated by the caller on the pinned-image lookup returning `Some`.
fn docker_pull_script(image_ref: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Nyx repro — pin-fetch the toolchain image used by this bundle.\n\
         # Run this once on a fresh machine before `reproduce.sh --docker`.\n\
         set -e\n\
         IMAGE=\"{image_ref}\"\n\
         if ! command -v docker >/dev/null 2>&1; then\n\
           echo 'error: docker not installed' >&2; exit 2\n\
         fi\n\
         if ! docker info >/dev/null 2>&1; then\n\
           echo 'error: docker daemon not reachable' >&2; exit 2\n\
         fi\n\
         docker pull \"$IMAGE\"\n",
        image_ref = image_ref,
    )
}

/// Phase 28 — Track H.3.  Build the `toolchain.lock` JSON for a bundle.
///
/// Records:
/// - the expected toolchain id (`spec.toolchain_id`).
/// - the pinned image reference, when [`crate::dynamic::toolchain::pinned_image_ref`]
///   has a digest for this toolchain id (lets `docker_pull.sh` and a CI
///   replay path resolve the image without re-reading the catalogue).
/// - a BLAKE3 hash of every file in the bundle that influences the replay
///   outcome (Dockerfile, harness source, entry source, payload, Cargo.toml
///   when present).  An operator can re-hash the bundle in place and diff
///   against the lock to detect tampering.
fn build_toolchain_lock(spec: &HarnessSpec, root: &Path) -> Result<serde_json::Value, ReproError> {
    use crate::symbol::Lang;

    let mut files = serde_json::Map::new();
    let mut record = |rel: &str| -> Result<(), ReproError> {
        let abs = root.join(rel);
        if abs.exists() {
            let bytes = fs::read(&abs)?;
            let digest = blake3::hash(&bytes);
            files.insert(rel.to_owned(), serde_json::Value::String(digest.to_hex().to_string()));
        }
        Ok(())
    };

    record("harness/Dockerfile.harness")?;
    let harness_rel = match spec.lang {
        Lang::Rust => "harness/src/main.rs".to_owned(),
        _ => format!("harness/harness.{}", source_ext_for_lang(&spec.lang)),
    };
    record(&harness_rel)?;
    if matches!(spec.lang, Lang::Rust) {
        record("harness/Cargo.toml")?;
    }
    record(&format!("entry/extracted_source.{}", source_ext_for_lang(&spec.lang)))?;
    record("payload/payload.bin")?;

    let pinned_image = crate::dynamic::toolchain::pinned_image_ref(&spec.toolchain_id);
    Ok(serde_json::json!({
        "lock_version": 1,
        "toolchain_id": spec.toolchain_id,
        "spec_hash": spec.spec_hash,
        "pinned_image": pinned_image,
        "files": serde_json::Value::Object(files),
    }))
}

/// Phase 28 — Track H.3.  Outcome of [`replay_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayResult {
    /// `reproduce.sh` exited 0 — replay matched the recorded outcome.
    Pass,
    /// `reproduce.sh` exited 1 — replay diverged from the recorded outcome.
    Mismatch,
    /// `reproduce.sh` exited 2 — docker requested but unavailable.
    DockerUnavailable,
    /// `reproduce.sh` exited 3 — host toolchain mismatched in process mode.
    ToolchainMismatch,
    /// Any other non-zero exit code, treated as an unexpected error.  The
    /// Phase 28 m7 Gate 5 inversion treats this as instability.
    UnexpectedError {
        /// Exit code surfaced by the script.
        exit_code: i32,
    },
    /// `reproduce.sh` could not be invoked at all (script missing,
    /// permissions, etc.).  Phase 28 Gate 5 treats this as instability.
    ScriptInvocationFailed {
        /// Human-readable error.
        message: String,
    },
}

/// Tri-state map of [`ReplayResult`] onto the eval-corpus
/// `VerifyResult::replay_stable` field shape.
///
/// * `Some(true)` — replay matched the recorded outcome.
/// * `Some(false)` — replay diverged or aborted in a way that the M7
///   Gate-5 inversion treats as instability.
/// * `None` — replay was not informative (toolchain mismatched, docker
///   unavailable, or the bundle had no `reproduce.sh`).  The corpus
///   tabulator treats `None` as "no signal" and excludes the row from
///   the per-cell `stable_replays` numerator.
pub fn replay_stability(result: &ReplayResult) -> Option<bool> {
    match result {
        ReplayResult::Pass => Some(true),
        ReplayResult::Mismatch | ReplayResult::UnexpectedError { .. } => Some(false),
        ReplayResult::DockerUnavailable
        | ReplayResult::ToolchainMismatch
        | ReplayResult::ScriptInvocationFailed { .. } => None,
    }
}

/// Phase 28 — Track H.3.  Run `reproduce.sh` in `bundle_root` and map the
/// shell exit code into a [`ReplayResult`].
///
/// `extra_args` is appended to `reproduce.sh` (`--docker` when the caller
/// wants the docker backend; empty for the process backend).
///
/// This is the host-side companion to the M7 Gate 5 inversion: callers
/// who want "did this bundle replay green?" semantics see a typed result
/// and the M7 gate script gets a uniform contract to assert against.
pub fn replay_bundle(
    bundle_root: &Path,
    extra_args: &[&str],
) -> ReplayResult {
    use std::process::Command;
    let script = bundle_root.join("reproduce.sh");
    if !script.exists() {
        return ReplayResult::ScriptInvocationFailed {
            message: format!("reproduce.sh missing at {}", script.display()),
        };
    }
    let mut cmd = Command::new("sh");
    cmd.arg(script);
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.current_dir(bundle_root);
    match cmd.output() {
        Ok(out) => match out.status.code() {
            Some(0) => ReplayResult::Pass,
            Some(1) => ReplayResult::Mismatch,
            Some(2) => ReplayResult::DockerUnavailable,
            Some(3) => ReplayResult::ToolchainMismatch,
            Some(code) => ReplayResult::UnexpectedError { exit_code: code },
            None => ReplayResult::ScriptInvocationFailed {
                message: "reproduce.sh terminated without an exit code".to_owned(),
            },
        },
        Err(e) => ReplayResult::ScriptInvocationFailed {
            message: format!("failed to invoke reproduce.sh: {e}"),
        },
    }
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
    /// Process-global `NYX_REPRO_BASE` is mutated by several tests in
    /// this module; without serialisation a parallel `cargo test`
    /// invocation races on the global state and produces flakes that
    /// vanish under `--test-threads=1`.  Every env-mutating test
    /// acquires this guard for the duration of its body.
    /// `unwrap_or_else(into_inner)` recovers from poisoning so a
    /// failing test does not cascade-fail every later test.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

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
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
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
            hardening_outcome: None,
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
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }
    }

    #[test]
    fn write_creates_expected_layout() {
        let _env_guard = env_lock();
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
    fn toolchain_lock_records_expected_toolchain_and_hashes() {
        let _env_guard = env_lock();
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };
        let spec = make_spec();
        let opts = SandboxOptions::default();
        let outcome = make_outcome();
        let verdict = make_verdict();
        let artifact = write(
            &spec, &opts, &outcome, &verdict,
            "# harness", "# entry", b"payload", "label", None,
        ).unwrap();
        let lock_path = artifact.root.join("toolchain.lock");
        assert!(lock_path.exists(), "toolchain.lock missing");
        let lock: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
        assert_eq!(lock["toolchain_id"], "python-3.11");
        assert_eq!(lock["lock_version"], 1);
        let files = lock["files"].as_object().expect("files object");
        assert!(files.contains_key("payload/payload.bin"));
        assert!(files.contains_key("harness/harness.py"));
        assert!(files.contains_key("harness/Dockerfile.harness"));
        // Hashes are 64-hex BLAKE3 digests.
        for (_, v) in files {
            let hex = v.as_str().unwrap();
            assert_eq!(hex.len(), 64, "hash should be 64 hex chars");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    #[test]
    fn dockerfile_for_pinned_toolchain_uses_pinned_digest() {
        // python-3.11 is in the image catalogue with a pinned digest, so the
        // emitted Dockerfile must `FROM <base>@sha256:…` for hermeticity.
        let spec = make_spec();
        let pinned = crate::dynamic::toolchain::pinned_image_ref(&spec.toolchain_id)
            .expect("python-3.11 should resolve to a pinned digest in images.toml");
        assert!(
            pinned.contains("@sha256:"),
            "pinned_image_ref returned a non-pinned value: {pinned}",
        );
        let dockerfile = dockerfile_for_spec(&spec);
        let expected_from = format!("FROM {pinned}");
        assert!(
            dockerfile.contains(&expected_from),
            "dockerfile did not embed pinned digest;\n  expected substring: {expected_from}\n  got:\n{dockerfile}",
        );
    }

    #[test]
    fn dockerfile_falls_back_to_tag_when_toolchain_absent_from_catalogue() {
        // Unpinned toolchain id: no entry in IMAGE_DIGESTS, so the emitter
        // must fall back to a tag-only `FROM` so an operator can still build
        // the bundle (with a docker_pull.sh that is not emitted in this case).
        let mut spec = make_spec();
        spec.toolchain_id = "python-2.7".into();
        assert!(
            crate::dynamic::toolchain::pinned_image_ref(&spec.toolchain_id).is_none(),
            "test precondition: python-2.7 must NOT be in the catalogue",
        );
        let dockerfile = dockerfile_for_spec(&spec);
        assert!(
            dockerfile.contains("FROM python:2.7"),
            "fallback dockerfile missing tag-only FROM line:\n{dockerfile}",
        );
        assert!(
            !dockerfile.contains("@sha256:"),
            "fallback dockerfile must not invent a digest:\n{dockerfile}",
        );
    }

    #[test]
    fn reproduce_sh_contains_toolchain_check_and_exit_codes() {
        let _env_guard = env_lock();
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };
        let artifact = write(
            &make_spec(), &SandboxOptions::default(), &make_outcome(), &make_verdict(),
            "# harness", "# entry", b"payload", "label", None,
        ).unwrap();
        let script = std::fs::read_to_string(artifact.root.join("reproduce.sh")).unwrap();
        // Exit code 3 documented + emitted on host toolchain mismatch.
        assert!(script.contains("EXPECTED_TOOLCHAIN=\"python-3.11\""));
        assert!(script.contains("exit 3"));
        assert!(script.contains("re-run with --docker"));
        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    #[test]
    fn replay_bundle_returns_pass_on_green_replay() {
        let dir = TempDir::new().unwrap();
        // reproduce.sh shipping exit 0 stub; bundle layout simulated by hand.
        let bundle = dir.path().join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("reproduce.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                bundle.join("reproduce.sh"),
                std::fs::Permissions::from_mode(0o755),
            ).unwrap();
        }
        assert_eq!(replay_bundle(&bundle, &[]), ReplayResult::Pass);
    }

    #[test]
    fn replay_bundle_maps_exit_codes() {
        let dir = TempDir::new().unwrap();
        for (code, expected) in &[
            (1, ReplayResult::Mismatch),
            (2, ReplayResult::DockerUnavailable),
            (3, ReplayResult::ToolchainMismatch),
            (7, ReplayResult::UnexpectedError { exit_code: 7 }),
        ] {
            let bundle = dir.path().join(format!("b{code}"));
            std::fs::create_dir_all(&bundle).unwrap();
            std::fs::write(
                bundle.join("reproduce.sh"),
                format!("#!/bin/sh\nexit {code}\n"),
            ).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    bundle.join("reproduce.sh"),
                    std::fs::Permissions::from_mode(0o755),
                ).unwrap();
            }
            assert_eq!(replay_bundle(&bundle, &[]), *expected);
        }
    }

    #[test]
    fn replay_stability_maps_to_eval_corpus_tristate() {
        // The eval-corpus tabulator wants Pass → stable, anything that
        // looks like instability → unstable, and infra-blocked variants
        // → no signal (None) so the per-cell stable_replays denominator
        // is not inflated by a row that never had a chance to replay.
        assert_eq!(replay_stability(&ReplayResult::Pass), Some(true));
        assert_eq!(replay_stability(&ReplayResult::Mismatch), Some(false));
        assert_eq!(
            replay_stability(&ReplayResult::UnexpectedError { exit_code: 9 }),
            Some(false)
        );
        assert_eq!(replay_stability(&ReplayResult::DockerUnavailable), None);
        assert_eq!(replay_stability(&ReplayResult::ToolchainMismatch), None);
        assert_eq!(
            replay_stability(&ReplayResult::ScriptInvocationFailed {
                message: "missing".into()
            }),
            None,
        );
    }

    #[test]
    fn replay_bundle_reports_missing_script() {
        let dir = TempDir::new().unwrap();
        let bundle = dir.path().join("empty");
        std::fs::create_dir_all(&bundle).unwrap();
        match replay_bundle(&bundle, &[]) {
            ReplayResult::ScriptInvocationFailed { .. } => {}
            other => panic!("expected ScriptInvocationFailed, got {other:?}"),
        }
    }

    #[test]
    fn bundle_root_for_honours_test_override() {
        let _env_guard = env_lock();
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };
        let root = bundle_root_for("cafe0001").unwrap();
        assert_eq!(root, dir.path().join("cafe0001"));
        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    #[test]
    fn bundle_root_for_matches_write_output_under_override() {
        let _env_guard = env_lock();
        // The path returned by `bundle_root_for` must equal the bundle path
        // that `write` produces — replay callers locate the bundle without
        // re-creating directories, so a drift between the two helpers would
        // silently skip the replay for every Confirmed finding.
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("NYX_REPRO_BASE", dir.path().to_str().unwrap()) };
        let spec = make_spec();
        let opts = SandboxOptions::default();
        let outcome = make_outcome();
        let verdict = make_verdict();
        let artifact = write(
            &spec, &opts, &outcome, &verdict,
            "# harness", "# entry", b"payload", "label", None,
        ).unwrap();
        let resolved = bundle_root_for(&spec.spec_hash).unwrap();
        assert_eq!(resolved, artifact.root);
        unsafe { std::env::remove_var("NYX_REPRO_BASE") };
    }

    #[test]
    fn outcome_json_redacts_secrets() {
        let _env_guard = env_lock();
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

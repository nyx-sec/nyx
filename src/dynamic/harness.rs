//! Harness code generation.
//!
//! Given a [`HarnessSpec`], emit a small program that:
//!
//! 1. Imports/loads the target module from the project tree.
//! 2. Reads the payload from a known channel (env var `NYX_PAYLOAD`).
//! 3. Invokes the entry point with the payload routed to the right slot.
//! 4. Instruments the sink call site with a `sys.settrace` probe
//!    (`__NYX_SINK_HIT__` sentinel on stdout).
//! 5. Lets the sink either fire or not — the oracle observes from outside.
//!
//! One generator per [`Lang`]. Each emits source plus a build command.
//! Build artefacts are staged inside the sandbox working dir, never the
//! user's tree.

use crate::dynamic::lang;
use crate::dynamic::spec::HarnessSpec;
use crate::evidence::UnsupportedReason;
use std::fs;
use std::path::PathBuf;

/// A built harness ready to hand off to the sandbox.
#[derive(Debug, Clone)]
pub struct BuiltHarness {
    /// Working directory containing the harness source + any build output.
    pub workdir: PathBuf,
    /// Command to invoke (e.g. `["python3", "harness.py"]`).
    pub command: Vec<String>,
    /// Environment variables to set when running.
    pub env: Vec<(String, String)>,
    /// Generated harness source code (for repro artifacts).
    pub source: String,
    /// Entry-point source extracted from the project (may be empty if not found).
    pub entry_source: String,
}

/// Build a harness from a spec. Returns the artifact + run command.
pub fn build(spec: &HarnessSpec) -> Result<BuiltHarness, HarnessError> {
    // Emit source via the language-specific emitter.
    let harness_src = lang::emit(spec).map_err(HarnessError::Unsupported)?;

    // Stage in a temporary workdir.
    let workdir = stage_harness(spec, &harness_src)?;

    // Extract entry source for repro artifacts (best-effort; not fatal).
    let entry_source = extract_entry_source(spec);

    Ok(BuiltHarness {
        workdir,
        command: harness_src.command,
        env: vec![],
        source: harness_src.source,
        entry_source,
    })
}

/// Write the harness source to a temporary working directory.
///
/// On Unix we prefer `/tmp/nyx-harness/{spec_hash}` over `env::temp_dir()`
/// because macOS' `$TMPDIR` resolves to `/var/folders/.../T/` — deep enough
/// that traversal payloads like `../../../../etc/passwd` cannot escape to
/// `/` from the workdir, which masks path-traversal verdicts. `/tmp` is
/// shallow (resolves to `/private/tmp` on macOS, `/tmp` on Linux) and keeps
/// payload depth assumptions portable.
fn stage_harness(
    spec: &HarnessSpec,
    harness_src: &lang::HarnessSource,
) -> Result<PathBuf, HarnessError> {
    let base_dir = if cfg!(unix) {
        PathBuf::from("/tmp/nyx-harness")
    } else {
        std::env::temp_dir().join("nyx-harness")
    };
    let workdir = base_dir.join(&spec.spec_hash);
    fs::create_dir_all(&workdir)?;

    // Write harness source (create parent dir if needed, e.g. "src/main.rs").
    let harness_path = workdir.join(&harness_src.filename);
    if let Some(parent) = harness_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&harness_path, harness_src.source.as_bytes())?;

    // Write any extra files (e.g. Cargo.toml for Rust).
    for (rel_path, content) in &harness_src.extra_files {
        let dest = workdir.join(rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, content.as_bytes())?;
    }

    // Copy the entry file into the workdir so the harness can import/include it.
    copy_entry_file(spec, &workdir, harness_src.entry_subpath.as_deref());

    Ok(workdir)
}

/// Copy the entry source file to the workdir.
///
/// `entry_subpath` controls the destination:
/// - `None` → `workdir/{filename}` (Python default: import by module name).
/// - `Some("src/entry.rs")` → `workdir/src/entry.rs` (Rust: `mod entry;`).
///
/// Always overwrites the destination so the per-language build hash
/// (`compute_*_source_hash`) reflects the current on-disk source.  Leaving a
/// stale destination in place would let the build cache return class files
/// built from a previous fixture revision even after the source on disk has
/// changed.
///
/// Best-effort: silently skips if the file cannot be found or copied.
fn copy_entry_file(spec: &HarnessSpec, workdir: &PathBuf, entry_subpath: Option<&str>) {
    let candidates = [
        PathBuf::from(&spec.entry_file),
        PathBuf::from(".").join(&spec.entry_file),
    ];
    for src in &candidates {
        if src.exists() {
            let dst = if let Some(subpath) = entry_subpath {
                let dest = workdir.join(subpath);
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                dest
            } else {
                let fname = match src.file_name() {
                    Some(f) => f,
                    None => return,
                };
                workdir.join(fname)
            };
            let _ = fs::copy(src, &dst);
            return;
        }
    }
}

/// Extract the source of the entry file (for repro bundles). Best-effort.
fn extract_entry_source(spec: &HarnessSpec) -> String {
    let candidates = [
        PathBuf::from(&spec.entry_file),
        PathBuf::from(".").join(&spec.entry_file),
    ];
    for path in &candidates {
        if let Ok(s) = fs::read_to_string(path) {
            return s;
        }
    }
    String::new()
}

#[derive(Debug)]
pub enum HarnessError {
    Unsupported(UnsupportedReason),
    BuildFailed(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for HarnessError {
    fn from(e: std::io::Error) -> Self {
        HarnessError::Io(e)
    }
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessError::Unsupported(r) => write!(f, "unsupported: {r:?}"),
            HarnessError::BuildFailed(msg) => write!(f, "build failed: {msg}"),
            HarnessError::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    #[test]
    fn build_unsupported_entry_kind_returns_err() {
        // The Python emitter advertises a specific entry-kind set; an
        // unsupported entry kind short-circuits with
        // [`UnsupportedReason::EntryKindUnsupported`] before any harness
        // source is generated.
        let spec = HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: "src/app.py".into(),
            entry_name: "handler".into(),
            entry_kind: EntryKind::LibraryApi,
            lang: Lang::Python,
            toolchain_id: "python-3".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.py".into(),
            sink_line: 5,
            spec_hash: "0000000000000000".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
        };
        let err = build(&spec).unwrap_err();
        assert!(matches!(err, HarnessError::Unsupported(_)));
    }

    #[test]
    fn build_python_creates_workdir() {
        let spec = HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: "src/app.py".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "python-3".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.py".into(),
            sink_line: 10,
            spec_hash: "test0000abcd1234".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
        };
        let harness = build(&spec).unwrap();
        assert!(harness.workdir.join("harness.py").exists());
        assert!(!harness.source.is_empty());
    }
}

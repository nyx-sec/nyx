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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static WORKDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

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
/// On Unix we prefer `/tmp/nyx-harness/{spec_hash}-p{pid}-r{seq}-t{time}`
/// over `env::temp_dir()`
/// because macOS' `$TMPDIR` resolves to `/var/folders/.../T/` — deep enough
/// that traversal payloads like `../../../../etc/passwd` cannot escape to
/// `/` from the workdir, which masks path-traversal verdicts. `/tmp` is
/// shallow (resolves to `/private/tmp` on macOS, `/tmp` on Linux) and keeps
/// payload depth assumptions portable.
///
/// The per-run suffix is intentional: the workdir contains mutable build
/// products, probe channels, and sometimes a long-lived Docker container
/// mount.  Reusing `/tmp/nyx-harness/{spec_hash}` across concurrent
/// verifier processes lets one run overwrite or delete another run's Java
/// classes while the JVM is starting.
fn stage_harness(
    spec: &HarnessSpec,
    harness_src: &lang::HarnessSource,
) -> Result<PathBuf, HarnessError> {
    let base_dir = if cfg!(unix) {
        PathBuf::from("/tmp/nyx-harness")
    } else {
        std::env::temp_dir().join("nyx-harness")
    };
    let workdir = unique_workdir(&base_dir, &spec.spec_hash);
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
    copy_java_sibling_sources(spec, &workdir);

    Ok(workdir)
}

fn unique_workdir(base_dir: &Path, spec_hash: &str) -> PathBuf {
    let seq = WORKDIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    base_dir.join(format!(
        "{}-p{pid}-r{seq:016x}-t{nanos:x}",
        safe_workdir_component(spec_hash)
    ))
}

fn safe_workdir_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len().max(1));
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(b as char);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    if out.len() > 80 {
        let digest = blake3::hash(input.as_bytes());
        let hex = digest.to_hex();
        out = format!("{}-{}", &out[..80], &hex[..16]);
    }
    out
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
fn copy_entry_file(spec: &HarnessSpec, workdir: &Path, entry_subpath: Option<&str>) {
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
            if spec.lang == crate::symbol::Lang::Go
                && entry_subpath == Some("entry/entry.go")
                && let Ok(content) = fs::read_to_string(src)
            {
                let rewritten = rewrite_go_package(&content, "entry");
                let _ = fs::write(&dst, rewritten.as_bytes());
                return;
            }
            let _ = fs::copy(src, &dst);
            return;
        }
    }
}

fn rewrite_go_package(src: &str, target: &str) -> String {
    let mut out = String::with_capacity(src.len() + target.len());
    let mut replaced = false;
    for chunk in src.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        let (body, newline) = if chunk.ends_with('\n') {
            (line, "\n")
        } else {
            (line, "")
        };
        let (body_no_cr, cr) = body
            .strip_suffix('\r')
            .map(|s| (s, "\r"))
            .unwrap_or((body, ""));
        if !replaced && body_no_cr.trim_start().starts_with("package ") {
            let indent_len = body_no_cr.len() - body_no_cr.trim_start().len();
            out.push_str(&body_no_cr[..indent_len]);
            out.push_str("package ");
            out.push_str(target);
            out.push_str(cr);
            out.push_str(newline);
            replaced = true;
        } else {
            out.push_str(chunk);
        }
    }
    if replaced { out } else { src.to_owned() }
}

/// Java shape fixtures often keep helper sources and a build manifest next to
/// `Vuln.java` or `Benign.java`. Stage those siblings with the entry file so
/// each unique workdir is self-contained, while skipping the opposite fixture
/// variant to avoid duplicate public-class declarations in corpus tests.
fn copy_java_sibling_sources(spec: &HarnessSpec, workdir: &Path) {
    if spec.lang != crate::symbol::Lang::Java {
        return;
    }
    let entry = PathBuf::from(&spec.entry_file);
    let Some(parent) = entry.parent() else {
        return;
    };
    let Some(entry_name) = entry.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let alt_name = match entry_name {
        "Vuln.java" => "Benign.java",
        "Benign.java" => "Vuln.java",
        _ => return,
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for item in entries.flatten() {
        let p = item.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "pom.xml" {
            let _ = fs::copy(&p, workdir.join(name));
            continue;
        }
        if !p.extension().map(|e| e == "java").unwrap_or(false) {
            continue;
        }
        if name == entry_name || name == alt_name {
            continue;
        }
        let _ = fs::copy(&p, workdir.join(name));
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
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
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
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        };
        let harness = build(&spec).unwrap();
        assert!(harness.workdir.join("harness.py").exists());
        assert!(!harness.source.is_empty());
    }

    #[test]
    fn build_uses_unique_flat_workdir_for_same_spec_hash() {
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
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        };
        let first = build(&spec).unwrap();
        let second = build(&spec).unwrap();
        assert_ne!(first.workdir, second.workdir);
        assert_eq!(first.workdir.parent(), second.workdir.parent());
    }

    #[test]
    fn build_java_stages_sibling_stubs_without_alt_fixture() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vuln = tmp.path().join("Vuln.java");
        fs::write(&vuln, "public class Vuln {}\n").unwrap();
        fs::write(tmp.path().join("Helper.java"), "class Helper {}\n").unwrap();
        fs::write(tmp.path().join("Benign.java"), "public class Benign {}\n").unwrap();
        fs::write(tmp.path().join("pom.xml"), "<project />\n").unwrap();

        let spec = HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: vuln.to_string_lossy().into_owned(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Java,
            toolchain_id: "java-21".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::XXE,
            constraint_hints: vec![],
            sink_file: vuln.to_string_lossy().into_owned(),
            sink_line: 1,
            spec_hash: "javatest00000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        };

        let harness = build(&spec).unwrap();
        assert!(harness.workdir.join("Vuln.java").exists());
        assert!(harness.workdir.join("Helper.java").exists());
        assert!(harness.workdir.join("pom.xml").exists());
        assert!(!harness.workdir.join("Benign.java").exists());
    }
}

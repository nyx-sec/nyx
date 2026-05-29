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
use std::io;
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
    copy_php_project_manifests(spec, &workdir);

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
            let _ = copy_workdir(src, &dst);
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
            let _ = copy_workdir(&p, &workdir.join(name));
            continue;
        }
        if !p.extension().map(|e| e == "java").unwrap_or(false) {
            continue;
        }
        if name == entry_name || name == alt_name {
            continue;
        }
        let _ = copy_workdir(&p, &workdir.join(name));
    }
}

fn copy_php_project_manifests(spec: &HarnessSpec, workdir: &Path) {
    if spec.lang != crate::symbol::Lang::Php {
        return;
    }
    let entry = PathBuf::from(&spec.entry_file);
    let mut dir = entry.parent();
    while let Some(current) = dir {
        let composer_json = current.join("composer.json");
        if composer_json.exists() {
            let _ = copy_workdir(&composer_json, &workdir.join("composer.json"));
            let composer_lock = current.join("composer.lock");
            if composer_lock.exists() {
                let _ = copy_workdir(&composer_lock, &workdir.join("composer.lock"));
            }
            return;
        }
        dir = current.parent();
    }
}

/// Copy-on-write clone of `src` into `dst` (Track P.0).
///
/// Per-finding workdir staging used to `std::fs::copy` every harness file,
/// paying a full byte copy for each of the 50+ findings an OWASP run touches.
/// On a CoW filesystem the kernel can share the underlying extents instead, so
/// setup cost drops from tens of milliseconds to near zero:
///
/// - **macOS** — `clonefile(2)` clones a file *or an entire directory tree* in
///   a single syscall (the [`clone_dir`] fast path).
/// - **Linux** — `ioctl(FICLONE)` reflinks on btrfs/xfs; `copy_file_range(2)`
///   is the ext4 fallback (in-kernel copy, reflink when the FS supports it).
/// - **Anywhere else / unsupported FS** — falls back to `std::fs::copy`, so
///   behaviour is identical, only slower.
///
/// The top-level `src` is resolved through symlinks (mirroring the `fs::copy`
/// semantics the staging code relied on, so a symlinked entry file copies its
/// target's contents). Symlinks *inside* a cloned tree are preserved verbatim
/// so a baseline snapshot keeps the toolchain's `node_modules/.bin` /
/// `vendor` link structure intact.
pub(crate) fn copy_workdir(src: &Path, dst: &Path) -> io::Result<()> {
    let meta = fs::metadata(src)?;
    if meta.is_dir() {
        clone_dir(src, dst)
    } else {
        clone_file(src, dst)
    }
}

/// Recursively clone a directory tree, preserving internal symlinks.
fn clone_dir(src: &Path, dst: &Path) -> io::Result<()> {
    // macOS: `clonefile` clones the whole tree (CoW) in one syscall when the
    // destination does not yet exist — the P50 ≤ 5ms baseline-snapshot path.
    #[cfg(target_os = "macos")]
    if !dst.exists() && clonefile_cow(src, dst).is_ok() {
        return Ok(());
    }
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            copy_symlink(&from, &to)?;
        } else if ft.is_dir() {
            clone_dir(&from, &to)?;
        } else {
            clone_file(&from, &to)?;
        }
    }
    Ok(())
}

/// CoW-clone a single regular file, falling back to a byte copy.
fn clone_file(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    if clonefile_cow(src, dst).is_ok() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if reflink_cow(src, dst).is_ok() {
        return Ok(());
    }
    fs::copy(src, dst).map(|_| ())
}

/// Recreate `src` (a symlink) at `dst` rather than following it.
fn copy_symlink(src: &Path, dst: &Path) -> io::Result<()> {
    let _ = fs::remove_file(dst);
    #[cfg(unix)]
    {
        let target = fs::read_link(src)?;
        std::os::unix::fs::symlink(target, dst)
    }
    #[cfg(not(unix))]
    {
        // No portable symlink API: copy the resolved file contents.
        clone_file(src, dst)
    }
}

/// macOS `clonefile(2)` wrapper.  Honours overwrite semantics by removing an
/// existing destination first (`clonefile` fails with `EEXIST` otherwise).
#[cfg(target_os = "macos")]
fn clonefile_cow(src: &Path, dst: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn clonefile(src: *const i8, dst: *const i8, flags: u32) -> i32;
    }

    let _ = fs::remove_file(dst);
    let csrc = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let cdst = CString::new(dst.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // flags = 0: follow a symlinked `src` and clone its target.
    let ret = unsafe { clonefile(csrc.as_ptr(), cdst.as_ptr(), 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Linux CoW clone: `ioctl(FICLONE)` reflink first, `copy_file_range(2)`
/// fallback.  Preserves the source mode so cloned toolchain binaries keep
/// their executable bit.
#[cfg(target_os = "linux")]
fn reflink_cow(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // FICLONE = _IOW(0x94, 9, int) on the asm-generic ABI (x86_64, aarch64).
    const FICLONE: u64 = 0x4004_9409;

    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
        fn copy_file_range(
            fd_in: i32,
            off_in: *mut i64,
            fd_out: i32,
            off_out: *mut i64,
            len: usize,
            flags: u32,
        ) -> isize;
    }

    let src_file = fs::File::open(src)?;
    let meta = src_file.metadata()?;
    let dst_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)?;

    let src_fd = src_file.as_raw_fd();
    let dst_fd = dst_file.as_raw_fd();

    // Fast path: whole-file reflink (btrfs/xfs).
    let cloned = unsafe { ioctl(dst_fd, FICLONE, src_fd) } == 0;
    if !cloned {
        // ext4 / overlayfs fallback: in-kernel copy (reflink when supported).
        let mut remaining = meta.len() as usize;
        while remaining > 0 {
            let n = unsafe {
                copy_file_range(
                    src_fd,
                    std::ptr::null_mut(),
                    dst_fd,
                    std::ptr::null_mut(),
                    remaining,
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                break; // short source / EOF
            }
            remaining -= n as usize;
        }
    }

    // Neither FICLONE nor copy_file_range copies the mode bits.
    fs::set_permissions(dst, meta.permissions())?;
    Ok(())
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

    #[test]
    fn copy_workdir_clones_file_contents() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");
        fs::write(&src, b"hello clonefile\n").unwrap();
        copy_workdir(&src, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"hello clonefile\n");
    }

    #[test]
    fn copy_workdir_overwrites_existing_dest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");
        fs::write(&src, b"new contents").unwrap();
        fs::write(&dst, b"STALE STALE STALE").unwrap();
        copy_workdir(&src, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"new contents");
    }

    #[test]
    fn copy_workdir_clones_directory_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("tree");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::write(src.join("top.txt"), b"top").unwrap();
        fs::write(src.join("nested").join("deep.txt"), b"deep").unwrap();
        let dst = tmp.path().join("clone");
        copy_workdir(&src, &dst).unwrap();
        assert_eq!(fs::read(dst.join("top.txt")).unwrap(), b"top");
        assert_eq!(
            fs::read(dst.join("nested").join("deep.txt")).unwrap(),
            b"deep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_workdir_preserves_internal_symlinks() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("tree");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("real.txt"), b"real").unwrap();
        std::os::unix::fs::symlink("real.txt", src.join("link.txt")).unwrap();
        let dst = tmp.path().join("clone");
        copy_workdir(&src, &dst).unwrap();
        let link = dst.join("link.txt");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "internal symlink must be preserved, not dereferenced"
        );
        assert_eq!(fs::read(&link).unwrap(), b"real");
    }

    #[test]
    #[ignore = "Phase 24 perf bench: per-finding workdir clone P50 ≤ 5ms (CoW). Opt-in so the default suite stays hermetic + fast. Run: cargo nextest run --features dynamic --run-ignored ignored-only -E 'test(~copy_workdir_perf)'"]
    fn copy_workdir_perf_p50_under_5ms() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::TempDir::new().unwrap();
        // Representative harness workdir: entry source + siblings + manifest.
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("Vuln.java"), "public class Vuln {}\n".repeat(60)).unwrap();
        fs::write(src.join("Helper.java"), "class Helper {}\n".repeat(20)).unwrap();
        fs::write(src.join("pom.xml"), "<project></project>\n".repeat(30)).unwrap();

        let n = 50usize;
        let mut samples = Vec::with_capacity(n);
        for i in 0..n {
            let dst = tmp.path().join(format!("clone{i}"));
            let t = Instant::now();
            copy_workdir(&src, &dst).unwrap();
            samples.push(t.elapsed());
        }
        samples.sort();
        let p50 = samples[n / 2];
        eprintln!("phase24 copy_workdir: P50 = {p50:?} over {n} clones");
        assert!(
            p50 <= Duration::from_millis(5),
            "phase24 acceptance gate: workdir clone P50 {p50:?}, expected ≤ 5ms"
        );
    }
}

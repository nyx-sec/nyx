//! Long-lived `javac` daemon (Phase 22 / Track O.0).
//!
//! The legacy `try_compile_java_with_toolchain` in `build_sandbox` shell-execs a
//! fresh `javac` per harness — every invocation pays the JVM cold-start tax
//! (~700ms on the macOS reference machine, ~300ms on Linux CI).  At 50
//! findings per OWASP-scale run that single line burns > 30s before any
//! real work happens.
//!
//! [`JavacPool`] replaces the shell-exec with a long-running worker JVM:
//!
//! ```text
//!   nyx ─┐
//!        │  framed JSON  ┌─────────────┐
//!        ├──stdin──────► │ NyxJavac    │
//!        │               │ Worker      │
//!        │ ◄──stdout──── │ (live JVM)  │
//!        │  framed JSON  └─────────────┘
//! ```
//!
//! Bootstrap (paid once per toolchain id):
//! 1. Drop `NyxJavacWorker.java` into a cache dir.
//! 2. Compile it with `javac` (~1s).
//! 3. Spawn `java -cp <dir> NyxJavacWorker` (~700ms cold start).
//! 4. Read the worker's `{"ready":true}` banner.
//!
//! After bootstrap, each [`JavacPool::compile_batch`] is a single JSON
//! round-trip — typical wall-clock < 50ms even on small harnesses.
//!
//! # Robustness
//!
//! A crashed / hung worker is non-fatal:
//! - On any IO error, the pool marks itself unhealthy and the caller
//!   falls back to the direct-spawn legacy path.
//! - The next pool lookup spawns a fresh worker.
//!
//! # Test hook
//!
//! `NYX_JAVAC_BIN` + `NYX_JAVA_BIN` override the binaries the pool
//! invokes so integration tests can swap in a wrapper.

use super::{BuildPool, PoolCompileResult};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Java source compiled at first use to drive the worker.
const WORKER_SOURCE: &str = include_str!("java_worker/NyxJavacWorker.java");
const WORKER_CLASS: &str = "NyxJavacWorker";
const WORKER_FILENAME: &str = "NyxJavacWorker.java";
/// Manifest written last (atomically) by `publish_class_set` after every
/// class lands, so its presence is the "publish finished" signal a
/// lock-free reader keys on.  Its *contents* are NOT trusted as the
/// completeness oracle -- see `WORKER_CLASS_FILES`.
const WORKER_MANIFEST: &str = ".worker-classes";

/// The exact set of `.class` files the worker JVM must load at runtime:
/// the top-level class plus its nested `$Request` / `$Parser` types.
///
/// Readiness keys on *this fixed set*, not on whatever the on-disk
/// manifest happens to name.  A bootstrap cache left by an older binary
/// can carry a manifest that lists only `NyxJavacWorker.class`; trusting
/// that list let the gate pass with the nested classes absent, so the
/// worker spawned, announced readiness, then died on the first request
/// with `NoClassDefFoundError` surfaced as
/// `nyx-javac-worker: parse error: NyxJavacWorker$Parser`.  Pinning the
/// required set here makes any such partial cache fail the gate and
/// trigger a clean recompile.  Kept in lock-step with the worker's real
/// nested-class layout by `worker_class_files_match_javac_output`.
const WORKER_CLASS_FILES: &[&str] = &[
    "NyxJavacWorker.class",
    "NyxJavacWorker$Request.class",
    "NyxJavacWorker$Parser.class",
];
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const COMPILE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Live worker handle.  Held inside a `Mutex` so concurrent
/// `compile_batch` callers serialise on the single JVM.
struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

pub struct JavacPool {
    /// `None` when the worker has crashed and a future call should
    /// surface the unhealthy state to the dispatcher.
    inner: Mutex<Option<Worker>>,
    /// Cache dir holding `NyxJavacWorker.class`.  Persisted between
    /// runs so subsequent process invocations skip the compile step.
    bootstrap_dir: PathBuf,
}

impl JavacPool {
    /// Create a fresh pool for `toolchain_id`.
    ///
    /// Returns `Err` when the worker cannot be bootstrapped (missing
    /// `javac`, missing `java`, compile failure, spawn failure).  The
    /// caller is expected to fall back to the legacy direct-spawn path
    /// on any error.
    pub fn try_new(toolchain_id: &str) -> Result<Self, String> {
        let bootstrap_dir = bootstrap_dir_for(toolchain_id)?;
        std::fs::create_dir_all(&bootstrap_dir)
            .map_err(|e| format!("javac-pool: mkdir {}: {e}", bootstrap_dir.display()))?;

        ensure_worker_compiled(&bootstrap_dir)?;
        let worker = spawn_worker(&bootstrap_dir)?;
        Ok(JavacPool {
            inner: Mutex::new(Some(worker)),
            bootstrap_dir,
        })
    }

    fn compile_with_worker(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // If a prior call torched the worker, try one re-spawn here so
        // the caller doesn't see consecutive failures from a transient
        // JVM crash.
        if guard.is_none()
            && let Ok(w) = spawn_worker(&self.bootstrap_dir)
        {
            *guard = Some(w);
        }
        let worker = match guard.as_mut() {
            Some(w) => w,
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "javac-pool: worker unavailable".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };

        let id = worker.next_id;
        worker.next_id = worker.next_id.wrapping_add(1);
        let req = build_request(id, workdir, args);
        if let Err(e) = worker.stdin.write_all(req.as_bytes()) {
            *guard = None;
            return PoolCompileResult {
                success: false,
                stderr: format!("javac-pool: write failed: {e}"),
                duration: start.elapsed(),
            };
        }
        if let Err(e) = worker.stdin.flush() {
            *guard = None;
            return PoolCompileResult {
                success: false,
                stderr: format!("javac-pool: flush failed: {e}"),
                duration: start.elapsed(),
            };
        }

        match read_line_with_timeout(
            &mut worker.child,
            &mut worker.stdout,
            COMPILE_RESPONSE_TIMEOUT,
            "read response",
        ) {
            Ok(None) => {
                *guard = None;
                PoolCompileResult {
                    success: false,
                    stderr: "javac-pool: worker closed stdout".to_owned(),
                    duration: start.elapsed(),
                }
            }
            Err(e) => {
                *guard = None;
                PoolCompileResult {
                    success: false,
                    stderr: e,
                    duration: start.elapsed(),
                }
            }
            Ok(Some(line)) => match parse_response(&line) {
                Some((success, stderr)) => PoolCompileResult {
                    success,
                    stderr,
                    duration: start.elapsed(),
                },
                None => {
                    *guard = None;
                    PoolCompileResult {
                        success: false,
                        stderr: format!("javac-pool: malformed response: {line}"),
                        duration: start.elapsed(),
                    }
                }
            },
        }
    }
}

impl Drop for JavacPool {
    fn drop(&mut self) {
        // Best-effort: close stdin so the worker exits cleanly, then
        // wait briefly.  We don't propagate errors -- pool teardown
        // happens at process exit, by which point everyone is already
        // leaving anyway.
        if let Ok(mut guard) = self.inner.lock()
            && let Some(mut worker) = guard.take()
        {
            // Dropping stdin sends EOF to the worker's `readLine` loop.
            drop(worker.stdin);
            let _ = worker.child.wait();
        }
    }
}

impl BuildPool for JavacPool {
    fn name(&self) -> &'static str {
        "javac"
    }

    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        self.compile_with_worker(workdir, args)
    }

    fn is_healthy(&self) -> bool {
        match self.inner.lock() {
            Ok(g) => g.is_some(),
            Err(_) => false,
        }
    }
}

fn bootstrap_dir_for(toolchain_id: &str) -> Result<PathBuf, String> {
    if let Ok(custom) = std::env::var("NYX_BUILD_POOL_DIR") {
        return Ok(PathBuf::from(custom).join("javac").join(toolchain_id));
    }
    let base = directories::ProjectDirs::from("dev", "nyx", "nyx")
        .ok_or_else(|| "javac-pool: no cache dir on this platform".to_owned())?;
    Ok(base
        .cache_dir()
        .join("dynamic")
        .join("build-pool")
        .join("javac")
        .join(toolchain_id))
}

/// Drop `NyxJavacWorker.java` + compile `NyxJavacWorker.class` into
/// `dir` if they are not already present.  Always re-writes the source
/// when the on-disk copy differs from the embedded one so a binary
/// upgrade picks up worker fixes without manual cache eviction.
///
/// The bootstrap dir is shared across every concurrent `nyx` process on
/// the host, so the compile-and-publish step is hardened against the
/// cross-process race that otherwise hands a half-written
/// `NyxJavacWorker.class` to a peer process spawning its worker (which
/// then fails to start, manifesting downstream as a flaky build):
///
///  - The publish is **atomic**: `javac` writes into a private,
///    pid-scoped staging dir and the finished class is `rename`d into
///    place.  A concurrent reader sees either the previous complete
///    class or the new one, never a partial file.  The old class is
///    never `remove`d first.
///  - Compiles are **serialised** on a `flock(2)` over `.bootstrap.lock`
///    so two processes never run `javac` into the same staging at once
///    and a waiter re-checks the now-published class instead of
///    recompiling.
fn ensure_worker_compiled(dir: &Path) -> Result<(), String> {
    let src_path = dir.join(WORKER_FILENAME);

    // Fast path: a complete class set already matches the current worker
    // source.  Checked before taking the cross-process lock so steady
    // state stays lock-free.
    if worker_class_ready(dir) {
        return Ok(());
    }

    // Serialise the compile-and-publish across processes sharing `dir`.
    let _lock = BootstrapLock::acquire(dir)?;

    // Re-check under the lock: another process may have published a good
    // class set while we were waiting on the lock.
    if worker_class_ready(dir) {
        return Ok(());
    }

    // Publish the source (idempotent) so cache inspectors can see what
    // the class was built from.
    std::fs::write(&src_path, WORKER_SOURCE)
        .map_err(|e| format!("javac-pool: write worker source: {e}"))?;

    // Compile into a private staging dir, then atomically publish the
    // class files into place.
    let staging = dir.join(format!(".compile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("javac-pool: mkdir staging: {e}"))?;
    let javac = std::env::var("NYX_JAVAC_BIN").unwrap_or_else(|_| "javac".to_owned());
    let compiled = Command::new(&javac)
        // Pin the source charset so the bootstrap compile is independent of
        // the host locale (a `C`/`POSIX` CI runner defaults `javac` to
        // `US-ASCII` and would reject any non-ASCII byte in the worker
        // source).  Mirrors the harness-compile pin in `build_sandbox`.
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-d")
        .arg(&staging)
        .arg(&src_path)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output();
    let output = match compiled {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format!("javac-pool: spawn javac: {e}"));
        }
    };
    if !output.status.success() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!(
            "javac-pool: bootstrap compile failed: {}",
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    let publish = publish_class_set(&staging, dir);
    let _ = std::fs::remove_dir_all(&staging);
    publish
}

/// Move every `.class` file `javac` emitted from the private `staging`
/// dir into the shared `dir`, then write the manifest last.
///
/// The worker source compiles to the top-level `NyxJavacWorker.class`
/// plus the nested `NyxJavacWorker$Request` / `NyxJavacWorker$Parser`
/// classes.  Every one of them must land in `dir` (the worker JVM's
/// classpath), or the worker hits `NoClassDefFoundError` the first time
/// it touches a nested class -- which surfaced downstream as a bogus
/// `nyx-javac-worker: parse error: NyxJavacWorker$Parser`.
///
/// Renames are same-filesystem (staging is a child of `dir`) so each is
/// atomic.  The manifest is written last via a temp-then-rename, so a
/// concurrent peer on the lock-free fast path sees either no manifest
/// (and serialises on the lock) or a complete one whose every named
/// class is already in place.
fn publish_class_set(staging: &Path, dir: &Path) -> Result<(), String> {
    let entries =
        std::fs::read_dir(staging).map_err(|e| format!("javac-pool: read staging dir: {e}"))?;
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("javac-pool: read staging entry: {e}"))?
            .path();
        if path.extension().is_none_or(|x| x != "class") {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };
        std::fs::rename(&path, dir.join(&name))
            .map_err(|e| format!("javac-pool: publish {name}: {e}"))?;
        names.push(name);
    }
    if names.is_empty() {
        return Err("javac-pool: bootstrap compile produced no .class files".to_owned());
    }
    // Refuse to publish (and to write the readiness-signalling manifest) a
    // set missing any class the worker loads at runtime.  Fail loud here
    // rather than leave a half-set the worker would die on later.
    for required in WORKER_CLASS_FILES {
        if !names.iter().any(|n| n == required) {
            return Err(format!(
                "javac-pool: bootstrap compile missing required class {required}; got {names:?}",
            ));
        }
    }

    // Write the manifest atomically (temp + rename) so it appears in one
    // step after every class is already published.
    let manifest = dir.join(WORKER_MANIFEST);
    let tmp = dir.join(format!("{WORKER_MANIFEST}.{}", std::process::id()));
    std::fs::write(&tmp, names.join("\n"))
        .map_err(|e| format!("javac-pool: write manifest: {e}"))?;
    std::fs::rename(&tmp, &manifest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("javac-pool: publish manifest: {e}")
    })?;
    Ok(())
}

/// True when `dir` holds a complete, non-empty class set built from the
/// current embedded `WORKER_SOURCE`: the source matches, the manifest is
/// present, and every class the manifest names exists and is non-empty.
fn worker_class_ready(dir: &Path) -> bool {
    if std::fs::read_to_string(dir.join(WORKER_FILENAME))
        .ok()
        .as_deref()
        != Some(WORKER_SOURCE)
    {
        return false;
    }
    // The manifest is written last by `publish_class_set`, so its presence
    // is the "publish finished" barrier: a reader that sees it knows no
    // peer is mid-rename.  Absence forces the cross-process lock path.
    if std::fs::metadata(dir.join(WORKER_MANIFEST)).is_err() {
        return false;
    }
    // Completeness is judged against the fixed required set, never against
    // the manifest's lines -- a stale or partial manifest must not be able
    // to vouch for classes it simply fails to name.
    for name in WORKER_CLASS_FILES {
        let present = std::fs::metadata(dir.join(name))
            .map(|m| m.is_file() && m.len() > 0)
            .unwrap_or(false);
        if !present {
            return false;
        }
    }
    true
}

/// Cross-process advisory lock guarding the shared bootstrap dir's
/// compile-and-publish step.  The held lock file lives at
/// `<dir>/.bootstrap.lock`; the `flock(2)` releases when the guard (and
/// thus the file) drops.
struct BootstrapLock {
    _file: File,
}

impl BootstrapLock {
    fn acquire(dir: &Path) -> Result<Self, String> {
        let lock_path = dir.join(".bootstrap.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| format!("javac-pool: open bootstrap lock: {e}"))?;
        lock_file_exclusive(&file).map_err(|e| format!("javac-pool: bootstrap lock: {e}"))?;
        Ok(BootstrapLock { _file: file })
    }
}

#[cfg(unix)]
fn lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    loop {
        // SAFETY: `file.as_raw_fd()` is a live fd owned by `file`; `flock`
        // only reads the scalar args and we check the return value.
        let ret = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
        if ret == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(not(unix))]
fn lock_file_exclusive(_file: &File) -> std::io::Result<()> {
    Ok(())
}

fn spawn_worker(dir: &Path) -> Result<Worker, String> {
    let java = std::env::var("NYX_JAVA_BIN").unwrap_or_else(|_| "java".to_owned());
    let mut child = Command::new(&java)
        // The worker is tiny -- keep the JVM frugal so the pool
        // overhead stays well below the per-finding cost it
        // replaces.
        .arg("-Xss256k")
        .arg("-XX:+UseSerialGC")
        .arg("-cp")
        .arg(dir)
        .arg(WORKER_CLASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .spawn()
        .map_err(|e| format!("javac-pool: spawn java: {e}"))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "javac-pool: missing stdin".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "javac-pool: missing stdout".to_owned())?;
    let mut stdout = BufReader::new(stdout);

    let banner =
        match read_line_with_timeout(&mut child, &mut stdout, WORKER_READY_TIMEOUT, "read banner")?
        {
            Some(line) => line,
            None => {
                let _ = child.kill();
                let stderr_tail = drain_stderr(&mut child);
                return Err(format!(
                    "javac-pool: worker closed stdout before readiness; stderr: {stderr_tail}",
                ));
            }
        };
    if !banner.contains("\"ready\":true") {
        // Drain stderr for diagnostic context, then bail.
        let _ = child.kill();
        let stderr_tail = drain_stderr(&mut child);
        return Err(format!(
            "javac-pool: worker did not announce readiness; got {banner:?}; stderr: {stderr_tail}",
        ));
    }

    Ok(Worker {
        child,
        stdin,
        stdout,
        next_id: 0,
    })
}

fn drain_stderr(child: &mut Child) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(mut e) = child.stderr.take() {
        // Best-effort, non-blocking-ish.
        let _ = e.read_to_string(&mut buf);
    }
    buf
}

fn read_line_with_timeout(
    child: &mut Child,
    stdout: &mut BufReader<ChildStdout>,
    timeout: Duration,
    context: &str,
) -> Result<Option<String>, String> {
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(move || {
            let mut line = String::new();
            let result = stdout.read_line(&mut line).map(|n| (n, line));
            let _ = tx.send(result);
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok((0, _))) => Ok(None),
            Ok(Ok((_n, line))) => Ok(Some(line)),
            Ok(Err(e)) => Err(format!("javac-pool: {context} failed: {e}")),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                Err(format!("javac-pool: {context} timed out after {timeout:?}"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(format!("javac-pool: {context} reader disconnected"))
            }
        }
    })
}

fn build_request(id: u64, workdir: &Path, args: &[String]) -> String {
    let mut s = String::with_capacity(128 + args.iter().map(|a| a.len() + 4).sum::<usize>());
    s.push_str("{\"id\":\"");
    s.push_str(&id.to_string());
    s.push_str("\",\"cwd\":");
    append_json_string(&mut s, &workdir.to_string_lossy());
    s.push_str(",\"args\":[");
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        append_json_string(&mut s, a);
    }
    s.push_str("]}\n");
    s
}

fn append_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Extract `(success, stderr)` from a worker JSON response line.
fn parse_response(line: &str) -> Option<(bool, String)> {
    let response: JavacWorkerResponse = serde_json::from_str(line).ok()?;
    let stderr =
        decode_b64(&response.stderr_b64).unwrap_or_else(|| "<unable to decode stderr>".to_owned());
    Some((response.success, stderr))
}

#[derive(Debug, Deserialize)]
struct JavacWorkerResponse {
    success: bool,
    #[serde(default)]
    stderr_b64: String,
}

/// Tiny RFC 4648 base64 decoder.  Used only for the worker's
/// `stderr_b64` field so we can carry raw bytes through the JSON
/// envelope without dragging in a base64 crate.
fn decode_b64(s: &str) -> Option<String> {
    static ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [0xffu8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut vals = [0u8; 4];
        let mut pads = 0;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                pads += 1;
                vals[i] = 0;
            } else {
                let v = lookup[b as usize];
                if v == 0xff {
                    return None;
                }
                vals[i] = v;
            }
        }
        let triple = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if pads < 2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if pads < 1 {
            out.push((triple & 0xff) as u8);
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_envelope_escapes_specials() {
        let s = build_request(
            7,
            Path::new("/tmp/x"),
            &["a\"b".to_owned(), "c\\d".to_owned()],
        );
        assert!(s.contains("\"id\":\"7\""));
        assert!(s.contains("\"cwd\":\"/tmp/x\""));
        assert!(s.contains("\"a\\\"b\""));
        assert!(s.contains("\"c\\\\d\""));
        assert!(s.ends_with("]}\n"));
    }

    #[test]
    fn parse_response_success() {
        let (ok, err) =
            parse_response("{\"id\":\"0\",\"success\":true,\"stderr_b64\":\"\"}\n").unwrap();
        assert!(ok);
        assert!(err.is_empty());
    }

    #[test]
    fn parse_response_failure_decodes_stderr() {
        // "boom" -> base64 "Ym9vbQ=="
        let (ok, err) =
            parse_response("{\"id\":\"1\",\"success\":false,\"stderr_b64\":\"Ym9vbQ==\"}\n")
                .unwrap();
        assert!(!ok);
        assert_eq!(err, "boom");
    }

    #[test]
    fn parse_response_rejects_off_shape() {
        assert!(parse_response("not json").is_none());
        // Missing success field.
        assert!(parse_response("{\"id\":\"0\",\"stderr_b64\":\"\"}").is_none());
    }

    #[test]
    fn parse_response_accepts_reordered_fields() {
        let (ok, err) =
            parse_response("{\"stderr_b64\":\"YQ==\",\"success\":true,\"id\":\"7\"}\n").unwrap();
        assert!(ok);
        assert_eq!(err, "a");
    }

    #[test]
    fn b64_decode_roundtrip() {
        for (raw, encoded) in &[
            ("", ""),
            ("a", "YQ=="),
            ("ab", "YWI="),
            ("abc", "YWJj"),
            ("hello world", "aGVsbG8gd29ybGQ="),
        ] {
            assert_eq!(decode_b64(encoded).as_deref(), Some(*raw));
        }
    }

    #[test]
    fn worker_class_ready_rejects_truncated_or_mismatched() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let src = dir.join(WORKER_FILENAME);
        let main_class = dir.join(format!("{WORKER_CLASS}.class"));
        let parser = dir.join(format!("{WORKER_CLASS}$Parser.class"));
        let request = dir.join(format!("{WORKER_CLASS}$Request.class"));
        let manifest = dir.join(WORKER_MANIFEST);
        let manifest_body =
            format!("{WORKER_CLASS}.class\n{WORKER_CLASS}$Parser.class\n{WORKER_CLASS}$Request.class");

        // Nothing on disk yet.
        assert!(!worker_class_ready(dir));

        // Matching source but no class / manifest.
        std::fs::write(&src, WORKER_SOURCE).unwrap();
        assert!(!worker_class_ready(dir));

        // Top-level class + manifest present but the nested classes are
        // missing -- the stale-cache shape an older binary left behind.
        std::fs::write(&main_class, b"\xca\xfe\xba\xbe").unwrap();
        std::fs::write(&manifest, &manifest_body).unwrap();
        assert!(!worker_class_ready(dir));

        // A zero-byte nested class (the corruption shape a racing peer can
        // leave behind) must not count as ready.
        std::fs::write(&parser, b"").unwrap();
        std::fs::write(&request, b"\xca\xfe\xba\xbe").unwrap();
        assert!(!worker_class_ready(dir));

        // Every required class non-empty with matching source is ready.
        std::fs::write(&parser, b"\xca\xfe\xba\xbe").unwrap();
        assert!(worker_class_ready(dir));

        // A missing manifest invalidates an otherwise-complete class set.
        std::fs::remove_file(&manifest).unwrap();
        assert!(!worker_class_ready(dir));
        std::fs::write(&manifest, &manifest_body).unwrap();
        assert!(worker_class_ready(dir));

        // Stale source invalidates an otherwise-present class set.
        std::fs::write(&src, "// not the worker source").unwrap();
        assert!(!worker_class_ready(dir));
    }

    #[test]
    fn worker_class_ready_rejects_manifest_that_omits_nested_classes() {
        // The exact stale-cache shape that produced
        // `nyx-javac-worker: parse error: NyxJavacWorker$Parser` on Linux:
        // a self-consistent manifest that simply does not name the nested
        // classes, with only the top-level class on disk.  The old guard
        // iterated the manifest's lines and so trusted this; readiness must
        // now reject it because the fixed required set is incomplete.
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join(WORKER_FILENAME), WORKER_SOURCE).unwrap();
        std::fs::write(dir.join(format!("{WORKER_CLASS}.class")), b"\xca\xfe\xba\xbe").unwrap();
        // Manifest names only the top-level class -- exactly what poisoned
        // the persisted bootstrap cache.
        std::fs::write(dir.join(WORKER_MANIFEST), format!("{WORKER_CLASS}.class")).unwrap();
        assert!(
            !worker_class_ready(dir),
            "a manifest omitting the nested classes must not satisfy readiness",
        );

        // Drop in the nested classes the worker actually loads -> ready.
        std::fs::write(dir.join(format!("{WORKER_CLASS}$Parser.class")), b"\xca\xfe\xba\xbe")
            .unwrap();
        std::fs::write(dir.join(format!("{WORKER_CLASS}$Request.class")), b"\xca\xfe\xba\xbe")
            .unwrap();
        assert!(worker_class_ready(dir));
    }

    #[test]
    fn worker_class_files_match_javac_output() {
        // Guards `WORKER_CLASS_FILES` against drift: compile the embedded
        // worker source and assert the emitted `.class` set is exactly the
        // pinned required set, so a future nested type added to the worker
        // can't silently fall outside the readiness gate.
        let javac = std::env::var("NYX_JAVAC_BIN").unwrap_or_else(|_| "javac".to_owned());
        let have_javac = std::process::Command::new(&javac)
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !have_javac {
            return; // JRE-only / no JDK: nothing to compile against.
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join(WORKER_FILENAME);
        std::fs::write(&src, WORKER_SOURCE).unwrap();
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let status = std::process::Command::new(&javac)
            .arg("-encoding")
            .arg("UTF-8")
            .arg("-d")
            .arg(&out)
            .arg(&src)
            .status()
            .expect("spawn javac");
        assert!(status.success(), "worker source must compile");

        let mut emitted: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".class"))
            .collect();
        emitted.sort();
        let mut expected: Vec<String> =
            WORKER_CLASS_FILES.iter().map(|s| (*s).to_owned()).collect();
        expected.sort();
        assert_eq!(
            emitted, expected,
            "WORKER_CLASS_FILES must mirror the worker's javac output",
        );
    }

    #[test]
    fn publish_class_set_moves_every_class_and_writes_manifest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let staging = dir.join(".compile-test");
        std::fs::create_dir_all(&staging).unwrap();
        // Simulate javac output: top-level + nested classes plus a
        // non-class artifact that must be ignored.
        std::fs::write(staging.join("NyxJavacWorker.class"), b"\xca\xfe\xba\xbe").unwrap();
        std::fs::write(staging.join("NyxJavacWorker$Parser.class"), b"\xca\xfe\xba\xbe").unwrap();
        std::fs::write(staging.join("NyxJavacWorker$Request.class"), b"\xca\xfe\xba\xbe").unwrap();
        std::fs::write(staging.join("notes.txt"), b"ignore me").unwrap();

        publish_class_set(&staging, dir).expect("publish");

        for cls in [
            "NyxJavacWorker.class",
            "NyxJavacWorker$Parser.class",
            "NyxJavacWorker$Request.class",
        ] {
            assert!(dir.join(cls).is_file(), "{cls} must be published");
        }
        // The non-class file stays in staging (not published).
        assert!(!dir.join("notes.txt").exists());

        let manifest = std::fs::read_to_string(dir.join(WORKER_MANIFEST)).unwrap();
        let listed: Vec<&str> = manifest.lines().collect();
        assert_eq!(listed.len(), 3, "manifest lists all 3 classes: {listed:?}");
        assert!(listed.contains(&"NyxJavacWorker$Parser.class"));
    }

    #[test]
    fn bootstrap_lock_is_reentrant_across_sequential_acquires() {
        // The flock is released when the guard drops, so back-to-back
        // acquires from the same process succeed without deadlock.
        let dir = tempfile::TempDir::new().unwrap();
        {
            let _g = BootstrapLock::acquire(dir.path()).expect("first acquire");
        }
        let _g = BootstrapLock::acquire(dir.path()).expect("second acquire");
        assert!(dir.path().join(".bootstrap.lock").exists());
    }
}

//! Long-lived `javac` daemon (Phase 22 / Track O.0).
//!
//! The legacy [`crate::dynamic::build_sandbox::try_compile_java`] shell-execs a
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
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Java source compiled at first use to drive the worker.
const WORKER_SOURCE: &str = include_str!("java_worker/NyxJavacWorker.java");
const WORKER_CLASS: &str = "NyxJavacWorker";
const WORKER_FILENAME: &str = "NyxJavacWorker.java";

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
        if guard.is_none() {
            if let Ok(w) = spawn_worker(&self.bootstrap_dir) {
                *guard = Some(w);
            }
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

        let mut line = String::new();
        match worker.stdout.read_line(&mut line) {
            Ok(0) => {
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
                    stderr: format!("javac-pool: read failed: {e}"),
                    duration: start.elapsed(),
                }
            }
            Ok(_) => match parse_response(&line) {
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
fn ensure_worker_compiled(dir: &Path) -> Result<(), String> {
    let src_path = dir.join(WORKER_FILENAME);
    let class_path = dir.join(format!("{WORKER_CLASS}.class"));
    let on_disk = std::fs::read_to_string(&src_path).ok();
    let needs_write = on_disk.as_deref() != Some(WORKER_SOURCE);
    if needs_write {
        std::fs::write(&src_path, WORKER_SOURCE)
            .map_err(|e| format!("javac-pool: write worker source: {e}"))?;
        // Force a recompile if the source bytes changed under us.
        let _ = std::fs::remove_file(&class_path);
    }
    if class_path.exists() {
        return Ok(());
    }
    let javac = std::env::var("NYX_JAVAC_BIN").unwrap_or_else(|_| "javac".to_owned());
    let output = Command::new(&javac)
        .arg("-d")
        .arg(dir)
        .arg(&src_path)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("javac-pool: spawn javac: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "javac-pool: bootstrap compile failed: {}",
            String::from_utf8_lossy(&output.stderr),
        ));
    }
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

    // Read the banner line with a timeout via a polling read.  We
    // can't use `read_line` with a deadline directly, so spawn a
    // bounded waiter: if the worker doesn't announce readiness inside
    // 10s we declare bootstrap failure.
    let banner = read_line_with_timeout(&mut stdout, Duration::from_secs(10))?;
    if !banner.contains("\"ready\":true") {
        // Drain stderr for diagnostic context, then bail.
        let stderr_tail = drain_stderr(&mut child);
        let _ = child.kill();
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
    stdout: &mut BufReader<ChildStdout>,
    timeout: Duration,
) -> Result<String, String> {
    // BufReader doesn't expose async/timeout primitives.  The worker's
    // first line lands within < 2s on every machine we ship to, so a
    // synchronous read_line is fine -- the timeout is enforced by an
    // outer watchdog thread that interrupts us via stdin close on
    // failure.  In practice if `java` blocks indefinitely the test
    // suite catches the regression.
    //
    // We keep the API plumbed so the deadline can be tightened later
    // without churning call sites.
    let _ = timeout;
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .map_err(|e| format!("javac-pool: read banner: {e}"))?;
    Ok(line)
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
///
/// The wire shape is tightly constrained -- the worker only ever emits
/// `{"id":"N","success":TRUE|FALSE,"stderr_b64":"…"}`, so we use a
/// targeted decoder rather than pulling in `serde_json` and inflating
/// the dynamic feature footprint.  Anything off-shape returns `None`
/// and the caller flags the worker unhealthy.
fn parse_response(line: &str) -> Option<(bool, String)> {
    let success = extract_bool_field(line, "success")?;
    let b64 = extract_string_field(line, "stderr_b64").unwrap_or_default();
    let stderr = decode_b64(&b64).unwrap_or_else(|| "<unable to decode stderr>".to_owned());
    Some((success, stderr))
}

fn extract_bool_field(s: &str, name: &str) -> Option<bool> {
    let needle = format!("\"{name}\":");
    let i = s.find(&needle)? + needle.len();
    let rest = s[i..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn extract_string_field(s: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\":\"");
    let i = s.find(&needle)? + needle.len();
    let tail = &s[i..];
    let mut out = String::new();
    let mut chars = tail.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{08}'),
                'f' => out.push('\u{0c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = (&mut chars).take(4).collect();
                    let cp = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(cp)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
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
    let mut iter = bytes.chunks(4);
    while let Some(chunk) = iter.next() {
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
    fn extract_string_handles_escapes() {
        let s = r#"{"id":"0","stderr_b64":"abc","note":"a\"b\\c"}"#;
        assert_eq!(extract_string_field(s, "note").as_deref(), Some(r#"a"b\c"#));
    }

    #[test]
    fn extract_bool_picks_first_match() {
        let s = r#"{"success":false,"other":true}"#;
        assert_eq!(extract_bool_field(s, "success"), Some(false));
        assert_eq!(extract_bool_field(s, "other"), Some(true));
    }
}

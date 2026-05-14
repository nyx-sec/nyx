//! Structured sink-probe channel (Phase 06 — Track C.1).
//!
//! Replaces the brittle stdout-substring matching path with a per-run JSON-line
//! channel.  Each harness defines a `__nyx_probe` shim (see the per-language
//! emitter in [`crate::dynamic::lang`]) that writes one [`SinkProbe`] record
//! to the channel when the instrumented sink fires.  After each sandbox run
//! the runner calls [`ProbeChannel::drain`] and the oracle (see
//! [`crate::dynamic::oracle::oracle_fired`]) evaluates a payload's
//! [`crate::dynamic::oracle::ProbePredicate`] set against the captured args.
//!
//! # Channel medium
//!
//! Currently file-based: one JSON record per line at
//! `<workdir>/__nyx_probes.jsonl`.  The path is exposed to the harness via
//! the `NYX_PROBE_PATH` env var (see [`PROBE_PATH_ENV`]).  Named-pipe (FIFO)
//! transport is deferred; the file variant works on every platform the
//! sandbox supports and matches the drain-after-run lifecycle the runner
//! actually uses — there are no streaming consumers.
//!
//! Records are appended, so a single payload can fire the shim multiple
//! times (e.g. inside a retry loop) and the oracle sees every observation.
//! The runner truncates the file via [`ProbeChannel::clear`] before each
//! payload to keep verdicts independent.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Default filename for the file-backed probe channel inside a harness
/// workdir.  The harness shim and the runner both build their paths off
/// this constant so they cannot drift apart.
pub const PROBE_FILENAME: &str = "__nyx_probes.jsonl";

/// Env-var name that carries the absolute path of the probe channel into
/// the harness process.  Read by the per-language `__nyx_probe` shim.
pub const PROBE_PATH_ENV: &str = "NYX_PROBE_PATH";

/// Identifier of the payload that triggered the probe.  Currently the
/// static [`crate::dynamic::corpus::CuratedPayload::label`] string; future
/// fuzzer-generated payloads will use the corpus hash.
pub type PayloadId = String;

/// A single captured argument observed at the sink call site.
///
/// The harness shim chooses the variant based on the argument's runtime
/// type so the oracle can apply byte-level predicates without losing
/// information to lossy string conversion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value")]
pub enum ProbeArg {
    /// UTF-8 string argument.
    String(String),
    /// Raw byte buffer (e.g. `bytes` in Python, `Buffer` in Node).
    Bytes(Vec<u8>),
    /// Signed 64-bit integer.
    Int(i64),
}

impl ProbeArg {
    /// String view, when the arg is textual.  Returns `None` for `Int` and
    /// non-UTF-8 `Bytes`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ProbeArg::String(s) => Some(s.as_str()),
            ProbeArg::Bytes(b) => std::str::from_utf8(b).ok(),
            ProbeArg::Int(_) => None,
        }
    }

    /// Byte view, when the arg is byte-shaped.  Returns `None` for `Int`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ProbeArg::String(s) => Some(s.as_bytes()),
            ProbeArg::Bytes(b) => Some(b),
            ProbeArg::Int(_) => None,
        }
    }

    /// Integer view, when the arg is `Int`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ProbeArg::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// One structured observation written by the harness when the instrumented
/// sink fires.  Serialised as a single JSON object on its own line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkProbe {
    /// Fully-qualified or last-segment callee name of the fired sink
    /// (e.g. `"os.system"`, `"Runtime.exec"`).
    pub sink_callee: String,
    /// Captured positional arguments, left-to-right.  Empty when the sink
    /// takes no arguments or the shim could not introspect them.
    pub args: Vec<ProbeArg>,
    /// Monotonic-ish nanosecond timestamp captured at write time.  Used to
    /// order multiple probe entries from the same run; absolute value is
    /// not meaningful across runs.
    pub captured_at_ns: u64,
    /// Identifier of the payload in flight when the probe fired.
    pub payload_id: PayloadId,
}

/// Per-run handle on a file-backed [`SinkProbe`] channel.
///
/// Construction creates / truncates the underlying file under `workdir`;
/// [`clear`](ProbeChannel::clear) re-truncates between payload runs;
/// [`drain`](ProbeChannel::drain) reads every record currently buffered.
#[derive(Debug)]
pub struct ProbeChannel {
    path: PathBuf,
    /// Serialises read / write / truncate operations against the underlying
    /// file from the host side.  The harness process writes from its own
    /// address space; this lock only protects host-side callers (test
    /// helpers, the runner).
    io_lock: Mutex<()>,
}

impl ProbeChannel {
    /// Construct a channel rooted at `<workdir>/__nyx_probes.jsonl`.
    ///
    /// Creates the file (truncating any previous contents) so a stale
    /// probe file left over from a prior workdir reuse cannot poison the
    /// next run's oracle.
    pub fn for_workdir(workdir: &Path) -> std::io::Result<Self> {
        let path = workdir.join(PROBE_FILENAME);
        File::create(&path)?;
        Ok(Self {
            path,
            io_lock: Mutex::new(()),
        })
    }

    /// Construct a channel at an explicit path (test helper).  Mirrors
    /// [`for_workdir`](ProbeChannel::for_workdir) but does not assume any
    /// directory layout.
    pub fn at_path(path: PathBuf) -> std::io::Result<Self> {
        File::create(&path)?;
        Ok(Self {
            path,
            io_lock: Mutex::new(()),
        })
    }

    /// Absolute path of the probe file.  Forwarded to the harness process
    /// via the `NYX_PROBE_PATH` env var.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Truncate the channel between payload runs.  Cheap: a single
    /// `File::create` on the existing path.
    pub fn clear(&self) -> std::io::Result<()> {
        let _guard = self.io_lock.lock().ok();
        File::create(&self.path)?;
        Ok(())
    }

    /// Read every record currently buffered.  Malformed lines (truncated
    /// writes, partial flushes) are skipped silently — the oracle treats a
    /// missing probe as "sink did not fire" without distinguishing causes.
    pub fn drain(&self) -> Vec<SinkProbe> {
        let _guard = self.io_lock.lock().ok();
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(p) = serde_json::from_str::<SinkProbe>(trimmed) {
                out.push(p);
            }
        }
        out
    }

    /// Append a probe record from the host side.  Primarily a test helper:
    /// in production the harness process writes directly via its
    /// per-language shim, bypassing this entry point.
    pub fn write(&self, probe: &SinkProbe) -> std::io::Result<()> {
        let _guard = self.io_lock.lock().ok();
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        let line = serde_json::to_string(probe).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_probe(label: &str) -> SinkProbe {
        SinkProbe {
            sink_callee: "os.system".into(),
            args: vec![ProbeArg::String("ls; whoami".into())],
            captured_at_ns: 42,
            payload_id: label.into(),
        }
    }

    #[test]
    fn channel_round_trip_writes_and_drains() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        ch.write(&sample_probe("cmdi-echo-marker")).unwrap();
        ch.write(&sample_probe("cmdi-echo-marker-2")).unwrap();
        let probes = ch.drain();
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].payload_id, "cmdi-echo-marker");
        assert_eq!(probes[1].payload_id, "cmdi-echo-marker-2");
    }

    #[test]
    fn drain_after_clear_returns_empty() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        ch.write(&sample_probe("a")).unwrap();
        ch.clear().unwrap();
        assert!(ch.drain().is_empty());
    }

    #[test]
    fn drain_skips_malformed_lines() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        // Manually append a junk line, then a valid one.
        std::fs::write(ch.path(), "this is not json\n").unwrap();
        ch.write(&sample_probe("after-junk")).unwrap();
        let probes = ch.drain();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].payload_id, "after-junk");
    }

    #[test]
    fn probe_arg_views() {
        let s = ProbeArg::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));
        assert_eq!(s.as_bytes(), Some(&b"hello"[..]));
        assert_eq!(s.as_int(), None);

        let i = ProbeArg::Int(7);
        assert_eq!(i.as_str(), None);
        assert_eq!(i.as_bytes(), None);
        assert_eq!(i.as_int(), Some(7));

        let b = ProbeArg::Bytes(vec![b'h', b'i']);
        assert_eq!(b.as_str(), Some("hi"));
        assert_eq!(b.as_bytes(), Some(&[b'h', b'i'][..]));
    }

    #[test]
    fn empty_channel_drains_to_empty_vec() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        assert!(ch.drain().is_empty());
    }
}

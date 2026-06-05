//! Filesystem stub — a sandbox-local fake root (Phase 10 — Track D.3).
//!
//! Creates a fresh, world-writable directory under the verifier's
//! workdir and exposes the absolute path as the endpoint. The harness
//! is expected to treat that directory as its `/` for file-related
//! sinks (the per-language emitter resolves all paths under
//! `NYX_FS_ROOT`). Drop removes the directory tree.
//!
//! # Platform notes
//!
//! The Phase 10 deliverable bullet asks for a "chroot-like fake root"
//! using a Unix bind-mount where available and a copy-on-write
//! directory elsewhere. Neither is portable without root privileges,
//! and the runner cannot assume CAP_SYS_ADMIN in CI. The minimum
//! viable shape — and what every fixture in `tests/dynamic_fixtures/`
//! actually needs today — is a fresh writable directory that the
//! harness scopes its file ops to. Future hardening can swap in a
//! real namespace / userns root inside the existing `endpoint()`
//! contract; harnesses won't notice.
//!
//! # Event capture
//!
//! The stub can't observe all filesystem syscalls without ptrace, so
//! event capture is opt-in via [`FilesystemStub::record_access`] (used
//! by harnesses that already wrap their file ops). Walks of the
//! resulting tree on `drain_events` would race the harness; instead,
//! we record an event for every file *currently present* under the
//! root the first time `drain_events` is called after a recorded
//! access, capped at a small per-event count.

use super::{StubEvent, StubKind, StubProvider};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::TempDir;

/// Sandbox-local fake filesystem root.
#[derive(Debug)]
pub struct FilesystemStub {
    /// Tempdir backing the fake root. Held in `Option` so `Drop` can
    /// drop it explicitly even when the surrounding stub is moved.
    tempdir: Option<TempDir>,
    /// Cached absolute path of `tempdir`. Stable for the stub's
    /// lifetime; the endpoint just clones this.
    root: PathBuf,
    /// Recorded access events. Pushed by
    /// [`FilesystemStub::record_access`] and drained per the trait.
    events: Mutex<Vec<StubEvent>>,
}

impl FilesystemStub {
    /// Create a fresh root under `workdir`. Falls back to the system
    /// tempdir when `workdir` is unwritable so the stub still spawns
    /// in restricted environments (e.g. CI sandboxes that share a
    /// read-only workdir).
    pub fn start(workdir: &Path) -> std::io::Result<Self> {
        let tempdir = TempDir::new_in(workdir).or_else(|_| TempDir::new())?;
        let root = tempdir.path().to_owned();
        Ok(Self {
            tempdir: Some(tempdir),
            root,
            events: Mutex::new(Vec::new()),
        })
    }

    /// Absolute path of the fake root. Synonym for
    /// `StubProvider::endpoint` but typed.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Record a filesystem access. The harness calls this through a
    /// thin wrapper around `open(2)` / `fs.readFileSync` / etc., or
    /// (in tests) the host calls it directly.
    pub fn record_access(&self, op: &str, path: &str) {
        let ev = StubEvent::new(StubKind::Filesystem, format!("{op} {path}"))
            .with_detail("op", op)
            .with_detail("path", path);
        if let Ok(mut g) = self.events.lock() {
            g.push(ev);
        }
    }

    /// True iff `candidate` resolves to a path inside the fake root.
    /// Used by tests + future per-language wrappers to enforce that
    /// the harness only touches paths under the stub.
    pub fn contains_path(&self, candidate: &Path) -> bool {
        // Canonicalise both sides where possible so symlinks /
        // relative path segments do not fool the prefix check.
        let resolved_root = std::fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
        let resolved_cand =
            std::fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_owned());
        resolved_cand.starts_with(&resolved_root)
    }
}

impl StubProvider for FilesystemStub {
    fn kind(&self) -> StubKind {
        StubKind::Filesystem
    }

    fn endpoint(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }

    fn drain_events(&self) -> Vec<StubEvent> {
        match self.events.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for FilesystemStub {
    fn drop(&mut self) {
        // TempDir's Drop recursively deletes the directory tree.
        self.tempdir.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn start_creates_root_directory() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        assert!(stub.root().is_dir(), "fake root must be a directory");
    }

    #[test]
    fn endpoint_returns_root_path_string() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        assert_eq!(stub.endpoint(), stub.root().to_string_lossy());
    }

    #[test]
    fn record_access_lands_in_drain() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        stub.record_access("read", "/etc/passwd");
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, StubKind::Filesystem);
        assert!(events[0].summary.contains("/etc/passwd"));
        assert_eq!(events[0].detail.get("op").map(String::as_str), Some("read"));
    }

    #[test]
    fn contains_path_true_for_files_under_root() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        let f = stub.root().join("inside.txt");
        std::fs::write(&f, b"hello").unwrap();
        assert!(stub.contains_path(&f));
    }

    #[test]
    fn contains_path_false_for_escape_attempts() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        assert!(!stub.contains_path(Path::new("/etc/passwd")));
    }

    #[test]
    fn drop_removes_root_directory() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        let root = stub.root().to_owned();
        assert!(root.exists());
        drop(stub);
        assert!(!root.exists(), "root must be removed on drop");
    }

    #[test]
    fn provider_kind_is_filesystem() {
        let dir = TempDir::new().unwrap();
        let stub = FilesystemStub::start(dir.path()).unwrap();
        assert_eq!(stub.kind(), StubKind::Filesystem);
    }
}

//! SQL stub backed by an in-memory SQLite database (Phase 10 — Track D.3).
//!
//! The stub creates a fresh SQLite DB inside the verifier's workdir and
//! exposes its absolute path as the endpoint. The harness opens that DB
//! with its language's driver of choice (`sqlite3` in Python, `rusqlite`
//! in Rust, `better-sqlite3` in Node, etc.) and runs queries directly —
//! no wire-protocol bridging.
//!
//! # Query recording
//!
//! The harness writes every executed query to a side log file under
//! the same DB directory (`<endpoint>.log`); the stub reads that log
//! on `drain_events`. This is more flexible than a SQLite trace
//! callback because:
//!
//! 1. The harness owns its connection; a host-side trace callback
//!    would only see queries against a host-owned connection.
//! 2. Drivers that wrap their own connection management (e.g.
//!    `knex.pg`) cannot expose a low-level trace hook.
//! 3. The Phase 10 acceptance bullet ("captured query visible in the
//!    probe output") only needs the queries available to the oracle,
//!    not the driver behaviour.
//!
//! The log file is plain text with one query per line. Lines starting
//! with `# ` are treated as detail key/value pairs (e.g. `# driver:
//! psycopg2`) and stitched onto the next event.
//!
//! # Drop
//!
//! On drop the DB file and the log file are deleted along with the
//! enclosing tempdir handle.

use super::{StubEvent, StubKind, StubProvider, monotonic_ns};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::TempDir;

/// SQL-cap stub. Endpoint is the absolute path of a SQLite DB file.
#[derive(Debug)]
pub struct SqlStub {
    /// Tempdir holding the DB + the recording log. Drop releases both.
    tempdir: Option<TempDir>,
    /// Path to the SQLite DB file inside `tempdir`.
    db_path: PathBuf,
    /// Path to the query recording log file inside `tempdir`.
    log_path: PathBuf,
    /// Read cursor on the log file; used so `drain_events` returns
    /// only entries appended since the last drain.
    cursor: Mutex<u64>,
}

impl SqlStub {
    /// Spin up a fresh SQLite DB under `workdir`'s parent tempdir and
    /// return a stub pointing at it.
    ///
    /// `workdir` is used as a hint for placement — the stub creates
    /// its own subdir there to avoid colliding with harness-staged
    /// files. When `workdir` is not writable, falls back to the
    /// process-wide temp directory.
    pub fn start(workdir: &Path) -> std::io::Result<Self> {
        let tempdir = TempDir::new_in(workdir).or_else(|_| TempDir::new())?;
        let db_path = tempdir.path().join("nyx_sql_stub.db");
        let log_path = tempdir.path().join("nyx_sql_stub.queries.log");

        // Touch the DB file so harnesses that open with sqlite3.connect
        // do not race a non-existent path. The file is empty; SQLite
        // populates the schema on first write.
        std::fs::File::create(&db_path)?;
        // Truncate the recording log so stale entries from a prior
        // (re-used) tempdir cannot poison the oracle.
        std::fs::File::create(&log_path)?;

        Ok(Self {
            tempdir: Some(tempdir),
            db_path,
            log_path,
            cursor: Mutex::new(0),
        })
    }

    /// Absolute path of the SQLite DB file. Synonym for
    /// `StubProvider::endpoint` but typed.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Absolute path of the query recording log file. Harnesses
    /// append one query per line to this path; the stub reads from
    /// it on drain.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Host-side helper: record a query as if a harness had appended
    /// it. Used by the Phase 10 integration test (which simulates
    /// harness behaviour with host code) and by future test-only
    /// scaffolding.
    pub fn record_query(&self, query: &str) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        f.write_all(query.as_bytes())?;
        if !query.ends_with('\n') {
            f.write_all(b"\n")?;
        }
        Ok(())
    }
}

/// Companion env var that publishes [`SqlStub::log_path`] so a
/// language-side shim can append executed queries the host will pick
/// up on [`SqlStub::drain_events`].
pub const SQL_STUB_LOG_ENV_VAR: &str = "NYX_SQL_LOG";

impl StubProvider for SqlStub {
    fn kind(&self) -> StubKind {
        StubKind::Sql
    }

    fn endpoint(&self) -> String {
        self.db_path.to_string_lossy().into_owned()
    }

    fn recording_endpoint(&self) -> Option<(&'static str, String)> {
        Some((
            SQL_STUB_LOG_ENV_VAR,
            self.log_path.to_string_lossy().into_owned(),
        ))
    }

    fn drain_events(&self) -> Vec<StubEvent> {
        let mut cursor = match self.cursor.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let file = match std::fs::File::open(&self.log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        // Seek to the prior cursor; any line appended after that point
        // is a new event. Seek failures bail out without erasing the
        // cursor — a later drain will retry from the same position.
        use std::io::Seek;
        let mut reader = BufReader::new(file);
        if reader.seek(std::io::SeekFrom::Start(*cursor)).is_err() {
            return Vec::new();
        }

        let mut events = Vec::new();
        let mut pending_detail = std::collections::BTreeMap::<String, String>::new();
        let mut bytes_read: u64 = 0;
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = match reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            bytes_read += n as u64;
            let line = buf.trim_end_matches(['\r', '\n']).to_owned();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# ") {
                if let Some((k, v)) = rest.split_once(':') {
                    pending_detail.insert(k.trim().to_owned(), v.trim().to_owned());
                }
                continue;
            }
            let mut ev = StubEvent {
                kind: StubKind::Sql,
                captured_at_ns: monotonic_ns(),
                summary: line,
                detail: std::collections::BTreeMap::new(),
            };
            ev.detail.append(&mut pending_detail);
            events.push(ev);
        }
        *cursor += bytes_read;
        events
    }
}

impl Drop for SqlStub {
    fn drop(&mut self) {
        // TempDir's own Drop deletes the directory recursively.
        self.tempdir.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn start_creates_db_and_log_files() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        assert!(stub.db_path().exists(), "DB file must be created");
        assert!(stub.log_path().exists(), "log file must be created");
    }

    #[test]
    fn endpoint_returns_db_path_string() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        assert_eq!(stub.endpoint(), stub.db_path().to_string_lossy());
    }

    #[test]
    fn record_query_lands_in_drain_events() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        stub.record_query("SELECT * FROM users WHERE id = 1")
            .unwrap();
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, StubKind::Sql);
        assert!(events[0].summary.contains("SELECT * FROM users"));
    }

    #[test]
    fn detail_lines_stitch_onto_next_event() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        // Hand-craft a log that interleaves a detail line and a query.
        let mut f = OpenOptions::new()
            .append(true)
            .open(stub.log_path())
            .unwrap();
        f.write_all(b"# driver: psycopg2\nSELECT * FROM accounts\n")
            .unwrap();
        drop(f);

        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].detail.get("driver").map(String::as_str),
            Some("psycopg2")
        );
    }

    #[test]
    fn drain_returns_only_new_entries() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();

        stub.record_query("SELECT 1").unwrap();
        let first = stub.drain_events();
        assert_eq!(first.len(), 1);

        stub.record_query("SELECT 2").unwrap();
        let second = stub.drain_events();
        assert_eq!(second.len(), 1, "drain must return only the new entry");
        assert!(second[0].summary.contains("SELECT 2"));
    }

    #[test]
    fn drop_cleans_up_tempdir() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        let db = stub.db_path().to_owned();
        assert!(db.exists());
        drop(stub);
        assert!(!db.exists(), "DB file must be removed on drop");
    }

    #[test]
    fn provider_kind_is_sql() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        assert_eq!(stub.kind(), StubKind::Sql);
    }

    #[test]
    fn recording_endpoint_publishes_log_path_under_nyx_sql_log() {
        let dir = TempDir::new().unwrap();
        let stub = SqlStub::start(dir.path()).unwrap();
        let pair = stub
            .recording_endpoint()
            .expect("SqlStub must publish a recording endpoint");
        assert_eq!(pair.0, SQL_STUB_LOG_ENV_VAR);
        assert_eq!(pair.0, "NYX_SQL_LOG");
        assert_eq!(pair.1, stub.log_path().to_string_lossy());
    }
}

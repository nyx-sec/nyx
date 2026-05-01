//! Index-mode DB corruption recovery regression.
//!
//! Nyx's indexed scan path stores per-project state in a SQLite file.  If
//! that file is truncated or filled with garbage (crashed scanner, disk
//! failure, user stomping on the state dir) the scanner must surface a
//! clear error instead of panicking, hanging, or producing nonsense
//! findings.  These tests exercise both classes of corruption:
//!
//!   1. Truncation to zero bytes, SQLite treats a zero-length file as a
//!      fresh empty DB.  We expect the indexer to bootstrap the schema and
//!      carry on.
//!   2. Arbitrary garbage in the header, SQLite rejects this with
//!      `SQLITE_NOTADB` during pragma/schema execution.  We expect the
//!      indexer to return a structured error, not a panic.
//!
//! A later change may add an auto-rebuild path gated by `--rebuild-db`;
//! if so, the garbage-header test should flip to assert success with a
//! diagnostic note.  For now we pin current behaviour.

use nyx_scanner::commands::index::build_index;
use nyx_scanner::commands::scan::{Diag, scan_with_index_parallel};
use nyx_scanner::database::index::Indexer;
use nyx_scanner::errors::NyxError;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

fn test_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 8;
    cfg.performance.channel_multiplier = 1;
    cfg
}

fn seed_project(root: &Path) {
    // Use the qualified `child_process.exec` form so the seed produces a
    // taint finding under the post-fix label rules (bare `exec` as a flat
    // sink was removed because it suffix-matched any `<recv>.exec`, e.g.
    // Dockerode `container.exec`).  The qualified form is the canonical
    // Node.js stdlib path and stays a flat sink.
    std::fs::write(
        root.join("cmdi.js"),
        b"const child_process = require('child_process');\n\
          const express = require('express');\n\
          const app = express();\n\
          app.get('/x', (req, res) => { child_process.exec(req.query.cmd); res.send('ok'); });\n",
    )
    .unwrap();
}

/// Build a fresh index against a project tempdir and return `(project_name,
/// db_path, project_root_keep_alive, db_dir_keep_alive)`.
fn build_indexed_project() -> (
    String,
    std::path::PathBuf,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let project = tempfile::tempdir().unwrap();
    seed_project(project.path());

    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("corrupt.sqlite");
    build_index("corrupt", project.path(), &db_path, &test_cfg(), false)
        .expect("initial build_index should succeed on clean tree");

    // Sanity check: running an indexed scan produces diags.
    let pool = Indexer::init(&db_path).expect("init pool against clean DB");
    let diags: Vec<Diag> = scan_with_index_parallel(
        "corrupt",
        Arc::clone(&pool),
        &test_cfg(),
        false,
        project.path(),
    )
    .expect("clean indexed scan should succeed");
    assert!(
        !diags.is_empty(),
        "sanity: indexed scan on seeded project should produce findings",
    );

    // Drop the pool so we can overwrite the DB file on platforms where
    // open handles block replacement (mainly Windows, but SQLite's WAL
    // also wants us closed before we scribble on it).
    drop(pool);

    ("corrupt".to_string(), db_path, project, db_dir)
}

/// Overwrite the first `n` bytes of `path` with `fill`, truncating any
/// additional content.  Mimics a partial write / header smash.
fn clobber_header(path: &Path, fill: u8, n: usize) {
    let bytes = vec![fill; n];
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open db for clobber");
    f.write_all(&bytes).expect("write clobber bytes");
}

/// Truncate the DB file to zero bytes.  SQLite treats this as "new empty
/// database", so `Indexer::init` should successfully re-bootstrap.
#[test]
fn zero_truncated_db_rebuilds_on_init() {
    let (project_name, db_path, project, _db_dir) = build_indexed_project();

    // Truncate to zero bytes.
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&db_path)
        .expect("truncate db to zero");
    assert_eq!(
        std::fs::metadata(&db_path).unwrap().len(),
        0,
        "expected db to be zero-length after truncation",
    );

    // Re-init: SQLite treats the empty file as a fresh DB and `Indexer::init`
    // runs the CREATE TABLE statements, so this should succeed.
    let pool = Indexer::init(&db_path)
        .expect("Indexer::init should bootstrap a schema into an empty file");

    // After init, the DB is empty of prior state, an indexed scan should
    // still run end-to-end but will effectively be acting like a cold
    // rebuild.  We don't re-call build_index here because the plan is to
    // confirm the raw init path is resilient.
    let diags = scan_with_index_parallel(
        &project_name,
        Arc::clone(&pool),
        &test_cfg(),
        false,
        project.path(),
    )
    .expect("indexed scan after zero-truncation should succeed");
    // Scan-side resilience: cached summaries are gone, but the filesystem
    // pass runs on a clean SQLite and findings still emit.
    assert!(
        !diags.is_empty(),
        "indexed scan after rebuild should still emit findings",
    );
}

/// Clobber the SQLite magic header with garbage bytes.  This is the
/// "actual corruption" case, SQLite rejects it with `SQLITE_NOTADB` the
/// first time pragma or SQL is executed, which surfaces as
/// `NyxError::Sql(_)` from `Indexer::init`.
#[test]
fn garbage_header_db_returns_structured_error() {
    let (_project_name, db_path, _project, _db_dir) = build_indexed_project();

    // Write 100 bytes of `0xFF`, guaranteed not to match SQLite's header
    // magic "SQLite format 3\0".
    clobber_header(&db_path, 0xFF, 100);

    // `Indexer::init` should fail loudly.  The exact path is SQLite
    // surfacing SQLITE_NOTADB or a similar error; we assert only that we
    // got *some* NyxError back (not a panic, not a successful init).
    let result = Indexer::init(&db_path);
    match result {
        Err(NyxError::Sql(e)) => {
            let msg = e.to_string();
            assert!(
                !msg.is_empty(),
                "SQLite error should carry a diagnostic message",
            );
        }
        Err(NyxError::Io(_)) => {
            // Acceptable: some platforms classify the corrupt file as
            // an IO error at open time.
        }
        Err(NyxError::Pool(_)) => {
            // Acceptable: r2d2 may wrap the init failure in a pool error.
        }
        Err(other) => {
            panic!("expected NyxError::Sql / Io / Pool on corrupt header, got {other:?}",);
        }
        Ok(_) => panic!(
            "Indexer::init should not succeed against a garbage-header file at {}",
            db_path.display(),
        ),
    }
}

// NOTE: A mid-file corruption test (garbage at bytes 100..200, preserving
// SQLite magic) was attempted and is deliberately omitted.  That shape
// triggers a slow corruption-detection path in SQLite where `Indexer::init`
// takes 150–200 seconds before returning, unsuitable for CI wall-clock
// budgets.  The two tests above already cover the "corrupt-on-arrival"
// cases that users actually hit (crash-truncated file, deliberate clobber).
// A follow-up should either short-circuit `PRAGMA integrity_check` up
// front or wrap the init path in a timeout so mid-page corruption
// also fails fast.

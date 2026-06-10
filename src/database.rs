//! SQLite connection pool and schema for the incremental index.
//!
//! The index stores file content hashes, per-file scan results, and function
//! summaries so subsequent scans can skip files whose content has not changed.
//! The pool is backed by [`r2d2`] with WAL journaling, `synchronous=NORMAL`,
//! and memory-mapped I/O tuned for large codebases.
//!
//! Tables: `files`, `issues`, `function_summaries`, `ssa_function_summaries`.
//! SSA-specific persistence lives in [`crate::summary::ssa_summary`]; routines
//! here cover function summaries and file-level hash bookkeeping.

pub mod index {
    #![allow(clippy::too_many_arguments, clippy::type_complexity)]

    use crate::commands::scan::Diag;
    use crate::errors::{NyxError, NyxResult};
    use crate::patterns::Severity;
    use r2d2::{Pool, PooledConnection};
    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
    use std::fs;
    use std::io::Read;
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// How long each SQLite connection waits for the single writer slot.
    ///
    /// Indexed scans can have dozens of Rayon workers finishing analysis at
    /// once. SQLite still permits only one writer, so a timeout here turns that
    /// burst into short backpressure instead of surfacing SQLITE_BUSY.
    const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(60);

    /// DB schema (foreign‑keys enabled).
    const SCHEMA: &str = r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            path TEXT NOT NULL,
            hash BLOB NOT NULL,
            mtime INTEGER NOT NULL,
            scanned_at INTEGER NOT NULL,
            UNIQUE(project, path)
        );

        CREATE TABLE IF NOT EXISTS issues (file_id INTEGER NOT NULL
                              REFERENCES files(id)
                              ON DELETE CASCADE,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            line INTEGER NOT NULL,
            col INTEGER NOT NULL,
            PRIMARY KEY (file_id, rule_id, line, col));

        CREATE TABLE IF NOT EXISTS function_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            name TEXT NOT NULL,
            arity INTEGER NOT NULL DEFAULT -1,
            lang TEXT NOT NULL,
            container TEXT NOT NULL DEFAULT '',
            disambig INTEGER,
            kind TEXT NOT NULL DEFAULT 'fn',
            summary TEXT NOT NULL,
            entry_kind TEXT,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path, name, container, arity, disambig, kind)
        );

        CREATE TABLE IF NOT EXISTS ssa_function_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            name TEXT NOT NULL,
            arity INTEGER NOT NULL DEFAULT -1,
            lang TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT '',
            container TEXT NOT NULL DEFAULT '',
            disambig INTEGER,
            kind TEXT NOT NULL DEFAULT 'fn',
            summary TEXT NOT NULL,
            entry_kind TEXT,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path, name, container, arity, disambig, kind)
        );

        CREATE TABLE IF NOT EXISTS auth_check_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            name TEXT NOT NULL,
            arity INTEGER NOT NULL DEFAULT -1,
            lang TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT '',
            container TEXT NOT NULL DEFAULT '',
            disambig INTEGER,
            kind TEXT NOT NULL DEFAULT 'fn',
            summary TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path, name, container, arity, disambig, kind)
        );

        CREATE TABLE IF NOT EXISTS ssa_function_bodies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            name TEXT NOT NULL,
            arity INTEGER NOT NULL DEFAULT -1,
            lang TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT '',
            container TEXT NOT NULL DEFAULT '',
            disambig INTEGER,
            kind TEXT NOT NULL DEFAULT 'fn',
            body BLOB NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path, name, container, arity, disambig, kind)
        );

        CREATE TABLE IF NOT EXISTS cross_package_imports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            namespace TEXT NOT NULL,
            imports BLOB NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            scan_root TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            duration_secs REAL,
            engine_version TEXT,
            languages TEXT,
            files_scanned INTEGER,
            files_skipped INTEGER,
            finding_count INTEGER,
            findings_json TEXT,
            timing_json TEXT,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_metrics (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
            cfg_nodes INTEGER,
            call_edges INTEGER,
            functions_analyzed INTEGER,
            summaries_reused INTEGER,
            unresolved_calls INTEGER
        );

        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            file_path TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scan_logs_scan ON scan_logs(scan_id);

        CREATE TABLE IF NOT EXISTS triage_states (
            fingerprint TEXT PRIMARY KEY,
            state TEXT NOT NULL DEFAULT 'open',
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS triage_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            action TEXT NOT NULL,
            previous_state TEXT NOT NULL,
            new_state TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_triage_audit_fp ON triage_audit_log(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_triage_audit_ts ON triage_audit_log(timestamp);

        CREATE TABLE IF NOT EXISTS nyx_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS triage_suppression_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suppress_by TEXT NOT NULL,
            match_value TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'suppressed',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(suppress_by, match_value)
        );

        -- First time we observed each finding fingerprint. Lazy-populated by the
        -- overview endpoint when computing backlog age — INSERT OR IGNORE means
        -- only the earliest scan that mentioned a fingerprint sticks.
        CREATE TABLE IF NOT EXISTS finding_first_seen (
            fingerprint TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL
        );

        -- Dynamic verdict cache (§12 Q5).
        -- Keyed on (spec_hash, entry_content_hash, transitive_import_digest).
        -- Invalidation: any of entry content, import digest, toolchain_id,
        -- corpus_version, or spec_format_version change → DELETE row → re-run.
        CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            spec_hash TEXT NOT NULL,
            entry_content_hash TEXT NOT NULL,
            transitive_import_digest TEXT NOT NULL,
            toolchain_id TEXT NOT NULL,
            corpus_version INTEGER NOT NULL,
            spec_format_version INTEGER NOT NULL,
            verdict_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                   toolchain_id, corpus_version, spec_format_version)
        );

        CREATE INDEX IF NOT EXISTS idx_dynamic_verdict_cache_spec_hash
            ON dynamic_verdict_cache(spec_hash);

        -- Phase 21: persisted attack-surface map.  One row per project.
        -- Stored as canonical JSON so the round-trip is byte-identical
        -- across rescans (see `SurfaceMap::to_json`).
        CREATE TABLE IF NOT EXISTS surface_map (
            project TEXT PRIMARY KEY,
            map_json BLOB NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- Indexes on (project, file_path) for the per-file replace_* paths.
        -- Without these, every DELETE WHERE project=? AND file_path=? does a
        -- full table scan, which dominates indexing time as the cache grows.
        CREATE INDEX IF NOT EXISTS idx_function_summaries_project_file
            ON function_summaries(project, file_path);
        CREATE INDEX IF NOT EXISTS idx_ssa_function_summaries_project_file
            ON ssa_function_summaries(project, file_path);
        CREATE INDEX IF NOT EXISTS idx_ssa_function_bodies_project_file
            ON ssa_function_bodies(project, file_path);
        CREATE INDEX IF NOT EXISTS idx_auth_check_summaries_project_file
            ON auth_check_summaries(project, file_path);
        CREATE INDEX IF NOT EXISTS idx_cross_package_imports_project_file
            ON cross_package_imports(project, file_path);
    "#;

    /// Engine version used to detect stale caches across upgrades.
    pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

    /// On-disk schema version for cached analysis data.
    ///
    /// Bumped independently of `ENGINE_VERSION` whenever the serialized
    /// layout or identity of a cached artefact changes in an incompatible
    /// way, e.g. a `FuncKey` field semantic change that would cause old
    /// summaries to misbehave when rehydrated.
    ///
    /// History:
    /// * `"1"`, initial.
    /// * `"2"`, 0.5.0: `FuncKey.disambig` changed from the function-node
    ///   byte offset to a depth-first structural index.  Pre-0.5.0 caches
    ///   store byte-offset disambigs and would fail to match bodies built
    ///   by the new engine, so they are silently rebuilt on open.
    /// * `"3"`, `ssa_function_bodies.body` changed from JSON TEXT to
    ///   bincode BLOB.  Old JSON payloads cannot be deserialised by the
    ///   new engine, so they are silently rebuilt on open.
    /// * `"4"`, `Cap` widened from u16 to u32 to accommodate cap bits
    ///   ≥ 14 (LDAP_INJECTION, XPATH_INJECTION, HEADER_INJECTION,
    ///   OPEN_REDIRECT, SSTI, XXE, PROTOTYPE_POLLUTION).  The `Cap`
    ///   deserialiser accepts both u16- and u32-width JSON values, so
    ///   pre-bump caches load without crashing, but the cached
    ///   `source_caps` / `sanitizer_caps` / `sink_caps` blobs were
    ///   produced before any of these caps could appear and would
    ///   underreport rules that emit them.  Bumping forces a rescan so
    ///   newly-emitted gates and sinks land in the cache with the wider
    ///   footprint.
    pub const SCHEMA_VERSION: &str = "4";

    /// A single issue row, ready for insertion.
    #[derive(Debug, Clone)]
    pub struct IssueRow<'a> {
        pub rule_id: &'a str,
        pub severity: &'a str,
        pub line: i64,
        pub col: i64,
    }

    type IndexWriteJob = Box<dyn FnOnce(&mut Indexer) -> NyxResult<()> + Send + 'static>;

    #[derive(Default)]
    struct IndexWriteReport {
        error_count: usize,
        samples: Vec<String>,
    }

    impl IndexWriteReport {
        fn record(&mut self, err: impl ToString) {
            self.error_count += 1;
            if self.samples.len() < 8 {
                self.samples.push(err.to_string());
            }
        }
    }

    /// Bounded handle for submitting persisted-index writes.
    ///
    /// The scanner can keep parsing in parallel while this sender applies
    /// backpressure when SQLite's single writer falls behind.
    #[derive(Clone)]
    pub(crate) struct IndexWriteSender {
        tx: crossbeam_channel::Sender<IndexWriteJob>,
    }

    impl IndexWriteSender {
        pub(crate) fn enqueue<F>(&self, job: F) -> NyxResult<()>
        where
            F: FnOnce(&mut Indexer) -> NyxResult<()> + Send + 'static,
        {
            self.tx
                .send(Box::new(job))
                .map_err(|_| NyxError::Msg("database writer stopped before accepting write".into()))
        }
    }

    /// Single-writer queue for project index mutations.
    ///
    /// SQLite permits many readers but only one writer. Parallel scans should
    /// therefore submit analyzed file results here instead of letting every
    /// Rayon worker compete for the writer lock.
    pub(crate) struct IndexWriteQueue {
        tx: IndexWriteSender,
        handle: std::thread::JoinHandle<IndexWriteReport>,
    }

    impl IndexWriteQueue {
        pub(crate) fn start(
            project: impl Into<String>,
            pool: Arc<Pool<SqliteConnectionManager>>,
        ) -> Self {
            let capacity = std::env::var("NYX_INDEX_WRITE_QUEUE_MAX")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n >= 1)
                .unwrap_or_else(|| (num_cpus::get() * 2).max(64));
            Self::start_with_capacity(project, pool, capacity)
        }

        pub(crate) fn start_with_capacity(
            project: impl Into<String>,
            pool: Arc<Pool<SqliteConnectionManager>>,
            capacity: usize,
        ) -> Self {
            let project = project.into();
            let (tx, rx) = crossbeam_channel::bounded::<IndexWriteJob>(capacity.max(1));
            let handle = std::thread::spawn(move || {
                let mut report = IndexWriteReport::default();
                let mut idx = match Indexer::from_pool(&project, &pool) {
                    Ok(idx) => idx,
                    Err(err) => {
                        report.record(format!("writer init: {err}"));
                        return report;
                    }
                };

                for job in rx {
                    if let Err(err) = job(&mut idx) {
                        report.record(err);
                    }
                }

                report
            });

            Self {
                tx: IndexWriteSender { tx },
                handle,
            }
        }

        pub(crate) fn sender(&self) -> IndexWriteSender {
            self.tx.clone()
        }

        pub(crate) fn finish(self, stage: &str) -> NyxResult<()> {
            let Self { tx, handle } = self;
            drop(tx);
            let report = handle
                .join()
                .map_err(|_| NyxError::Msg(format!("{stage} database writer panicked")))?;
            if report.error_count == 0 {
                return Ok(());
            }

            let mut details = report.samples;
            if report.error_count > details.len() {
                details.push(format!(
                    "... and {} more",
                    report.error_count - details.len()
                ));
            }

            Err(NyxError::Msg(format!(
                "{stage} failed to persist scan state: {}",
                details.join("; ")
            )))
        }
    }

    /// A scan record for DB persistence.
    #[derive(Debug, Clone)]
    pub struct ScanRecord {
        pub id: String,
        pub status: String,
        pub scan_root: String,
        pub started_at: Option<String>,
        pub finished_at: Option<String>,
        pub duration_secs: Option<f64>,
        pub engine_version: Option<String>,
        pub languages: Option<String>,
        pub files_scanned: Option<i64>,
        pub files_skipped: Option<i64>,
        pub finding_count: Option<i64>,
        pub findings_json: Option<String>,
        pub timing_json: Option<String>,
        pub error: Option<String>,
    }

    /// A triage audit log entry.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct AuditEntry {
        pub id: i64,
        pub fingerprint: String,
        pub action: String,
        pub previous_state: String,
        pub new_state: String,
        pub note: String,
        pub timestamp: String,
    }

    /// A pattern-based suppression rule.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct SuppressionRule {
        pub id: i64,
        pub suppress_by: String,
        pub match_value: String,
        pub state: String,
        pub note: String,
        pub created_at: String,
    }

    pub struct Indexer {
        conn: PooledConnection<SqliteConnectionManager>,
        project: String,
    }

    /// SQLite database files start with this 16-byte ASCII magic.
    const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

    /// Reject obviously non-SQLite files before handing them to the
    /// connection pool, where the same rejection costs minutes instead of
    /// microseconds on some corruption shapes.
    ///
    /// Returns `Ok(())` when:
    ///   * the file does not exist (the pool will `CREATE` it),
    ///   * the file is zero-length (SQLite treats this as a fresh DB),
    ///   * the first 16 bytes match the SQLite magic header,
    ///   * the file is shorter than the magic but non-empty (extremely
    ///     unusual; we defer to SQLite rather than gating arbitrarily).
    ///
    /// Returns `Err(NyxError::Sql(...))` carrying `SQLITE_NOTADB` when the
    /// header is present but does not match.
    fn preflight_header(database_path: &Path) -> NyxResult<()> {
        let Ok(meta) = fs::metadata(database_path) else {
            return Ok(());
        };
        if !meta.is_file() {
            return Ok(());
        }
        if meta.len() < SQLITE_MAGIC.len() as u64 {
            return Ok(());
        }
        let mut head = [0u8; 16];
        let mut f = fs::File::open(database_path)?;
        f.read_exact(&mut head)?;
        if &head != SQLITE_MAGIC {
            return Err(NyxError::Sql(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
                Some(format!(
                    "file at {} is not a SQLite database (header magic mismatch)",
                    database_path.display(),
                )),
            )));
        }
        Ok(())
    }

    impl Indexer {
        pub fn init(database_path: &Path) -> NyxResult<Arc<Pool<SqliteConnectionManager>>> {
            let _span = tracing::info_span!("db_init", path = %database_path.display()).entered();

            // Fast-fail when the existing file is clearly not a SQLite
            // database.  Without this guard, certain corruption shapes
            // (truncated header, header overwritten with arbitrary bytes,
            // mid-page damage that preserves magic) can keep SQLite busy
            // for 150-200 seconds inside the PRAGMA / schema execution
            // below before it surfaces SQLITE_NOTADB or SQLITE_CORRUPT.
            // A zero-length file is treated as a fresh DB by SQLite, so we
            // only validate when the file is large enough to hold the
            // 16-byte magic header.
            preflight_header(database_path)?;

            // NO_MUTEX is safe because r2d2 ensures each pooled connection
            // is only ever used by one thread at a time.  Combined with WAL
            // mode this allows concurrent readers + a single writer without
            // the global serialization that FULL_MUTEX causes.
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            {
                let conn = Self::open_configured_connection(database_path, flags)?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.execute_batch(SCHEMA)?;

                // Migrate: if the function_summaries table is missing any required
                // column (arity for older schemas; container/disambig/kind for the
                // richer FuncKey identity), drop and recreate it so the data layout
                // matches the current model.
                let fn_cols: std::collections::HashSet<String> = conn
                    .prepare("PRAGMA table_info(function_summaries)")
                    .and_then(|mut s| {
                        let cols: Vec<String> = s
                            .query_map([], |r| r.get::<_, String>(1))?
                            .filter_map(Result::ok)
                            .collect();
                        Ok(cols.into_iter().collect())
                    })
                    .unwrap_or_default();

                let fn_ok = fn_cols.contains("arity")
                    && fn_cols.contains("container")
                    && fn_cols.contains("disambig")
                    && fn_cols.contains("kind");

                if !fn_ok {
                    tracing::info!(
                        "migrating function_summaries: recreating table with identity columns"
                    );
                    conn.execute_batch("DROP TABLE IF EXISTS function_summaries;")?;
                    conn.execute_batch(SCHEMA)?;
                }

                // Migrate: verify SSA tables carry namespace + container/disambig/kind.
                let ssa_cols: std::collections::HashSet<String> = conn
                    .prepare("PRAGMA table_info(ssa_function_summaries)")
                    .and_then(|mut s| {
                        let cols: Vec<String> = s
                            .query_map([], |r| r.get::<_, String>(1))?
                            .filter_map(Result::ok)
                            .collect();
                        Ok(cols.into_iter().collect())
                    })
                    .unwrap_or_default();

                let ssa_ok = ssa_cols.contains("namespace")
                    && ssa_cols.contains("container")
                    && ssa_cols.contains("disambig")
                    && ssa_cols.contains("kind");

                if !ssa_ok {
                    tracing::info!("migrating ssa_function_summaries: recreating tables");
                    conn.execute_batch("DROP TABLE IF EXISTS ssa_function_summaries;")?;
                    conn.execute_batch("DROP TABLE IF EXISTS ssa_function_bodies;")?;
                    conn.execute_batch(SCHEMA)?;
                }

                // ssa_function_bodies may have been created with the old column set
                // even when ssa_function_summaries is current (e.g. partial
                // migrations).  Check and recreate independently.
                let body_cols: std::collections::HashSet<String> = conn
                    .prepare("PRAGMA table_info(ssa_function_bodies)")
                    .and_then(|mut s| {
                        let cols: Vec<String> = s
                            .query_map([], |r| r.get::<_, String>(1))?
                            .filter_map(Result::ok)
                            .collect();
                        Ok(cols.into_iter().collect())
                    })
                    .unwrap_or_default();

                let body_ok = body_cols.contains("namespace")
                    && body_cols.contains("container")
                    && body_cols.contains("disambig")
                    && body_cols.contains("kind");

                if !body_ok {
                    tracing::info!("migrating ssa_function_bodies: recreating table");
                    conn.execute_batch("DROP TABLE IF EXISTS ssa_function_bodies;")?;
                    conn.execute_batch(SCHEMA)?;
                }

                // Phase 10 — `entry_kind` column on (ssa_)function_summaries.
                // Non-destructive `ALTER TABLE ... ADD COLUMN` so existing
                // rows survive the upgrade.  The column is nullable; the
                // INSERT paths write the JSON-encoded `EntryKind` text or
                // NULL when the function is not an entry point.
                Self::ensure_column(&conn, "function_summaries", "entry_kind", "TEXT")?;
                Self::ensure_column(&conn, "ssa_function_summaries", "entry_kind", "TEXT")?;

                // Ensure the auth_check_summaries table exists for DBs
                // created before this column set was introduced.  The
                // `CREATE TABLE IF NOT EXISTS` in SCHEMA handles new DBs;
                // this branch only fires when the table is missing
                // entirely from a pre-existing DB.
                let auth_exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = 'auth_check_summaries'",
                        [],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !auth_exists {
                    tracing::info!("creating auth_check_summaries table");
                    conn.execute_batch(SCHEMA)?;
                }

                // Phase 09 indexed-mode parity: ensure the
                // `cross_package_imports` table exists for DBs created
                // before this column set was introduced.  `CREATE TABLE
                // IF NOT EXISTS` in SCHEMA handles new DBs; this branch
                // only fires when the table is missing entirely from a
                // pre-existing DB.
                let cpi_exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = 'cross_package_imports'",
                        [],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !cpi_exists {
                    tracing::info!("creating cross_package_imports table");
                    conn.execute_batch(SCHEMA)?;
                }

                // Phase 21: ensure the `surface_map` table exists on
                // DBs created before this column set was introduced.
                let surface_exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = 'surface_map'",
                        [],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !surface_exists {
                    tracing::info!("creating surface_map table");
                    conn.execute_batch(SCHEMA)?;
                }

                // Schema version check: invalidate cached summary tables
                // when the on-disk artefact layout has changed in an
                // incompatible way, independently of the engine version.
                // Runs before `check_engine_version` so the engine-version
                // branch below does not race with a stale schema.
                Self::check_schema_version(&conn)?;

                // Engine version check: invalidate all caches when the scanner
                // version changes so stale serialized data cannot be loaded.
                Self::check_engine_version(&conn)?;
            }

            let manager = SqliteConnectionManager::file(database_path)
                .with_flags(flags)
                .with_init(Self::configure_connection);
            // r2d2's default `max_size` is 10, which can stall rayon
            // workers on machines with more cores than that during the
            // parallel indexing pass.  Size the pool to comfortably hold
            // a connection per rayon thread plus a small slack.
            //
            // `NYX_INDEX_POOL_MAX` overrides the auto-sized default. Use it in
            // fd-constrained environments (test sandboxes, containers with low
            // ulimit) where many parallel indexed scans would otherwise exhaust
            // EMFILE: each pooled SQLite WAL connection costs ~3 fds (db + -wal
            // + -shm), so 30 parallel scans × 16 conns × 3 fds = 1440 fds.
            let max_conns = std::env::var("NYX_INDEX_POOL_MAX")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|n| *n >= 1)
                .unwrap_or_else(|| (num_cpus::get() as u32 + 4).max(16));
            let pool = Arc::new(Pool::builder().max_size(max_conns).build(manager)?);
            Ok(pool)
        }

        fn open_configured_connection(
            database_path: &Path,
            flags: OpenFlags,
        ) -> rusqlite::Result<Connection> {
            let mut conn = Connection::open_with_flags(database_path, flags)?;
            Self::configure_connection(&mut conn)?;
            Ok(conn)
        }

        fn configure_connection(conn: &mut Connection) -> rusqlite::Result<()> {
            conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            conn.pragma_update(None, "cache_size", -8000i64)?; // 8 MB
            conn.pragma_update(None, "temp_store", "MEMORY")?;
            conn.pragma_update(None, "mmap_size", 268_435_456i64)?; // 256 MB
            Ok(())
        }

        /// Add a column to an existing table when it is missing.
        ///
        /// Non-destructive: leaves all existing rows untouched, populating
        /// the new column with NULL.  Used to thread additive schema
        /// changes (Phase 10's `entry_kind`) into pre-existing databases
        /// without forcing a full cache rebuild.
        fn ensure_column(
            conn: &Connection,
            table: &str,
            column: &str,
            sqlite_type: &str,
        ) -> NyxResult<()> {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let cols: std::collections::HashSet<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .filter_map(Result::ok)
                .collect();
            if cols.contains(column) {
                return Ok(());
            }
            tracing::info!("adding column {column} to {table}");
            conn.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {sqlite_type}"
            ))?;
            Ok(())
        }

        /// Check stored schema version against the compiled-in value.
        ///
        /// On mismatch (including first-time open), wipe the cached
        /// summary tables so pre-schema-bump artefacts cannot be
        /// rehydrated against the current engine.  Intentionally does
        /// not drop `files`, `scans`, or triage data: those are not
        /// layout-sensitive across this bump.
        fn check_schema_version(conn: &Connection) -> NyxResult<()> {
            let stored: Option<String> = conn
                .query_row(
                    "SELECT value FROM nyx_metadata WHERE key = 'schema_version'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;

            let current = SCHEMA_VERSION;

            match stored {
                Some(ref v) if v == current => {
                    // Schema version matches, nothing to do.
                }
                _ => {
                    let old = stored.as_deref().unwrap_or("<none>");
                    tracing::info!(
                        "db schema version changed ({old} → {current}), clearing summary caches"
                    );
                    // Drop ssa_function_bodies entirely: column type changed
                    // to BLOB in v3 and `CREATE TABLE IF NOT EXISTS` will
                    // not migrate the column on an existing table.
                    conn.execute_batch(
                        "DROP TABLE IF EXISTS ssa_function_bodies;
                         DELETE FROM function_summaries;
                         DELETE FROM ssa_function_summaries;
                         DELETE FROM auth_check_summaries;
                         DELETE FROM files;
                         DROP TABLE IF EXISTS cross_package_imports;",
                    )?;
                    conn.execute_batch(SCHEMA)?;
                    conn.execute(
                        "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES ('schema_version', ?1)",
                        params![current],
                    )?;
                }
            }
            Ok(())
        }

        /// Check stored engine version against the running binary.
        /// On mismatch (or missing row), wipe all cached analysis data so
        /// every file is rescanned with the new engine.
        fn check_engine_version(conn: &Connection) -> NyxResult<()> {
            let stored: Option<String> = conn
                .query_row(
                    "SELECT value FROM nyx_metadata WHERE key = 'engine_version'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;

            let current = ENGINE_VERSION;

            match stored {
                Some(ref v) if v == current => {
                    // Version matches, nothing to do.
                }
                _ => {
                    let old = stored.as_deref().unwrap_or("<none>");
                    tracing::info!("engine version changed ({old} → {current}), rebuilding index");

                    // Wipe all cached summaries and file hashes so everything
                    // gets rescanned.
                    conn.execute_batch(
                        "DELETE FROM function_summaries;
                         DELETE FROM ssa_function_summaries;
                         DELETE FROM ssa_function_bodies;
                         DELETE FROM auth_check_summaries;
                         DELETE FROM files;",
                    )?;

                    conn.execute(
                        "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES ('engine_version', ?1)",
                        params![current],
                    )?;
                }
            }
            Ok(())
        }

        /// Persist the current engine version into metadata.
        ///
        /// Called after a successful scan to ensure the metadata row exists
        /// even for a freshly created database.
        pub fn write_engine_version(pool: &Pool<SqliteConnectionManager>) -> NyxResult<()> {
            let conn = pool.get()?;
            conn.execute(
                "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES ('engine_version', ?1)",
                params![ENGINE_VERSION],
            )?;
            Ok(())
        }

        /// Force a specific engine version into the metadata table.
        /// Used by tests to simulate version mismatch scenarios.
        #[cfg(test)]
        pub fn set_engine_version(
            pool: &Pool<SqliteConnectionManager>,
            version: &str,
        ) -> NyxResult<()> {
            let conn = pool.get()?;
            conn.execute(
                "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES ('engine_version', ?1)",
                params![version],
            )?;
            Ok(())
        }

        /// Read the stored engine version from metadata. Returns None if not set.
        #[cfg(test)]
        pub fn get_stored_engine_version(
            pool: &Pool<SqliteConnectionManager>,
        ) -> NyxResult<Option<String>> {
            let conn = pool.get()?;
            let v: Option<String> = conn
                .query_row(
                    "SELECT value FROM nyx_metadata WHERE key = 'engine_version'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(v)
        }

        /// Count rows in a table for a given project. Test helper.
        #[cfg(test)]
        pub fn count_rows(
            pool: &Pool<SqliteConnectionManager>,
            table: &str,
            project: &str,
        ) -> NyxResult<i64> {
            let conn = pool.get()?;
            // table name can't be parameterized; this is test-only code with trusted inputs.
            let sql = format!("SELECT COUNT(*) FROM {table} WHERE project = ?1");
            let count: i64 = conn.query_row(&sql, params![project], |r| r.get(0))?;
            Ok(count)
        }

        /// Create a pool with init (schema + migrations + version check) for testing.
        /// This is `init()` but exposed under a clearer name for tests.
        #[cfg(test)]
        pub fn init_for_test(
            database_path: &Path,
        ) -> NyxResult<Arc<Pool<SqliteConnectionManager>>> {
            Self::init(database_path)
        }

        pub fn from_pool(project: &str, pool: &Pool<SqliteConnectionManager>) -> NyxResult<Self> {
            let conn = pool.get()?;
            Ok(Self {
                conn,
                project: project.to_owned(),
            })
        }

        // helper so code below can treat PooledConnection like &Connection
        fn c(&self) -> &Connection {
            self.conn.deref()
        }

        /// Return true when the file *content* or *mtime* changed since the last scan.
        ///
        /// Short-circuits on mtime: if the stored mtime matches the
        /// filesystem mtime, the file is assumed unchanged (skip hash).
        /// Production scans use `should_scan_with_hash`, which avoids the
        /// redundant `digest_file` read; this variant exists for tests.
        #[cfg(test)]
        pub fn should_scan(&self, path: &Path) -> NyxResult<bool> {
            let meta = fs::metadata(path)?;
            let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;

            let row: Option<(Vec<u8>, i64)> = self
                .conn
                .query_row(
                    "SELECT hash, mtime FROM files WHERE project = ?1 AND path = ?2",
                    params![self.project, path.to_string_lossy()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            Ok(match row {
                Some((stored_hash, stored_mtime)) => {
                    if stored_mtime != mtime {
                        // mtime changed, must re-scan
                        true
                    } else {
                        // mtime matches, compare hash only if cheap
                        // (the caller already read the file and can use
                        // should_scan_with_hash instead for full accuracy)
                        let digest = Self::digest_file(path)?;
                        stored_hash != digest
                    }
                }
                None => true,
            })
        }

        /// Like `should_scan` but accepts a pre-computed hash to avoid
        /// redundant file reads.
        pub fn should_scan_with_hash(&self, path: &Path, hash: &[u8]) -> NyxResult<bool> {
            let row: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT hash FROM files WHERE project = ?1 AND path = ?2",
                    params![self.project, path.to_string_lossy()],
                    |r| r.get(0),
                )
                .optional()?;

            Ok(match row {
                Some(stored_hash) => stored_hash != hash,
                None => true,
            })
        }

        /// Insert or update the `files` row and return its id.
        pub fn upsert_file(&self, path: &Path) -> NyxResult<i64> {
            let bytes = fs::read(path)?;
            let hash = Self::digest_bytes(&bytes);
            self.upsert_file_with_hash(path, &hash)
        }

        /// Insert or update the `files` row using a pre-computed hash.
        /// Avoids redundant file reads when the caller already has the hash.
        pub fn upsert_file_with_hash(&self, path: &Path, hash: &[u8]) -> NyxResult<i64> {
            let meta = fs::metadata(path)?;
            let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let scanned_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let path_str = path.to_string_lossy();

            // Use a single statement: upsert then query the id.
            self.c().execute(
                "INSERT INTO files (project, path, hash, mtime, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(project,path) DO UPDATE
                 SET hash = excluded.hash,
                     mtime = excluded.mtime,
                     scanned_at = excluded.scanned_at",
                params![self.project, path_str, hash, mtime, scanned_at],
            )?;

            let id: i64 = self.c().query_row(
                "SELECT id FROM files WHERE project = ?1 AND path = ?2",
                params![self.project, path_str],
                |r| r.get(0),
            )?;
            Ok(id)
        }

        /// Replace all issues for `file_id` with the supplied set.
        ///
        /// Dedups rows by the same PRIMARY KEY the `issues` table enforces
        /// (`file_id, rule_id, line, col`) to defend against upstream bugs
        /// that produce same-keyed diagnostics with differing severity or
        /// cosmetic fields. The first-seen row wins; upstream
        /// `ParsedSource::finalize_diags` sorts so that high
        /// severity comes first, and this fallback preserves that ordering.
        pub fn replace_issues<'a>(
            &mut self,
            file_id: i64,
            issues: impl IntoIterator<Item = IssueRow<'a>>,
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            tx.execute("DELETE FROM issues WHERE file_id = ?", params![file_id])?;

            {
                let mut stmt = tx.prepare(
                    "INSERT INTO issues (file_id, rule_id, severity, line, col)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                let mut seen: std::collections::HashSet<(String, i64, i64)> =
                    std::collections::HashSet::new();
                for iss in issues {
                    if !seen.insert((iss.rule_id.to_string(), iss.line, iss.col)) {
                        continue;
                    }
                    stmt.execute(params![
                        file_id,
                        iss.rule_id,
                        iss.severity,
                        iss.line,
                        iss.col
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        }

        /// Gets the issues for a specific file so we don't have to rescan
        pub fn get_issues_from_file(&self, path: &Path) -> NyxResult<Vec<Diag>> {
            let file_id: i64 = self.c().query_row(
                "SELECT id FROM files WHERE project = ?1 AND path = ?2",
                params![self.project, path.to_string_lossy()],
                |r| r.get(0),
            )?;

            let mut stmt = self.c().prepare(
                "SELECT rule_id, severity, line, col
         FROM issues
         WHERE file_id = ?1",
            )?;

            let issue_iter = stmt.query_map([file_id], |row| {
                let sev_str: String = row.get(1)?;
                let severity = Severity::from_str(&sev_str).unwrap_or_else(|_| {
                    tracing::warn!(
                        severity = %sev_str,
                        "unknown severity in DB row; defaulting to Medium"
                    );
                    Severity::Medium
                });
                Ok(Diag {
                    path: path.to_string_lossy().to_string(),
                    id: row.get::<_, String>(0)?, // rule_id
                    line: row.get::<_, i64>(2)? as usize,
                    col: row.get::<_, i64>(3)? as usize,
                    severity,
                    category: crate::patterns::FindingCategory::Security,
                    path_validated: false,
                    guard_kind: None,
                    message: None,
                    labels: vec![],
                    confidence: None,
                    evidence: None,
                    rank_score: None,
                    rank_reason: None,
                    exposure: None,
                    suppressed: false,
                    suppression: None,
                    triage_state: "open".to_string(),
                    triage_note: String::new(),
                    rollup: None,
                    finding_id: String::new(),
                    alternative_finding_ids: Vec::new(),
                    stable_hash: 0,
                })
            })?;

            Ok(issue_iter.filter_map(Result::ok).collect())
        }

        /// Atomically replace all function summaries for a single file.
        ///
        /// Deletes every existing summary row for `(project, file_path)` then
        /// inserts the new set.  This keeps the table in sync when a file is
        /// re‑parsed and its functions change.
        pub fn replace_summaries_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            summaries: &[crate::summary::FuncSummary],
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            tx.execute(
                "DELETE FROM function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;

            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO function_summaries
                        (project, file_path, file_hash, name, arity, lang,
                         container, disambig, kind, summary, entry_kind, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )?;

                for s in summaries {
                    let json = serde_json::to_string(s)
                        .map_err(|e| NyxError::Msg(format!("summary serialise: {e}")))?;
                    let disambig_sql = s.disambig.map(|d| d as i64);
                    let entry_kind_sql = s
                        .entry_kind
                        .as_ref()
                        .map(|ek| serde_json::to_string(ek).unwrap_or_else(|_| String::new()))
                        .filter(|s| !s.is_empty());
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        s.name,
                        s.param_count as i64,
                        s.lang,
                        s.container,
                        disambig_sql,
                        s.kind.as_str(),
                        json,
                        entry_kind_sql,
                        now
                    ])?;
                }
            }

            tx.commit()?;
            Ok(())
        }

        /// Atomically replace all SSA function summaries for a single file.
        ///
        /// The input tuple is
        /// `(name, arity, lang, namespace, container, disambig, kind, summary)` ,
        /// matching the fields required to reconstruct a full [`crate::symbol::FuncKey`]
        /// on load.
        pub fn replace_ssa_summaries_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            summaries: &[(
                String,
                usize,
                String,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::summary::ssa_summary::SsaFuncSummary,
            )],
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            tx.execute(
                "DELETE FROM ssa_function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;

            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO ssa_function_summaries
                        (project, file_path, file_hash, name, arity, lang, namespace,
                         container, disambig, kind, summary, entry_kind, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                )?;

                for (name, arity, lang, namespace, container, disambig, kind, summary) in summaries
                {
                    let json = serde_json::to_string(summary)
                        .map_err(|e| NyxError::Msg(format!("SSA summary serialise: {e}")))?;
                    let disambig_sql = disambig.map(|d| d as i64);
                    let entry_kind_sql = summary
                        .entry_kind
                        .as_ref()
                        .map(|ek| serde_json::to_string(ek).unwrap_or_else(|_| String::new()))
                        .filter(|s| !s.is_empty());
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        container,
                        disambig_sql,
                        kind.as_str(),
                        json,
                        entry_kind_sql,
                        now
                    ])?;
                }
            }

            tx.commit()?;
            Ok(())
        }

        /// Load every function summary for this project.
        ///
        /// Reads all JSON strings from SQLite in one pass, then
        /// deserializes them in parallel with rayon for large result sets.
        pub fn load_all_summaries(&self) -> NyxResult<Vec<crate::summary::FuncSummary>> {
            let mut stmt = self
                .c()
                .prepare("SELECT summary FROM function_summaries WHERE project = ?1")?;

            let jsons: Vec<String> = stmt
                .query_map([&self.project], |row| row.get::<_, String>(0))?
                .filter_map(|r| match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("failed to read summary row: {e}");
                        None
                    }
                })
                .collect();

            // Parallel JSON deserialization for large sets
            if jsons.len() > 256 {
                use rayon::prelude::*;
                let results: Vec<_> = jsons
                    .par_iter()
                    .filter_map(|json| {
                        serde_json::from_str::<crate::summary::FuncSummary>(json)
                            .map_err(|e| {
                                tracing::warn!("failed to deserialize summary JSON: {e}");
                                e
                            })
                            .ok()
                    })
                    .collect();
                Ok(results)
            } else {
                let mut out = Vec::with_capacity(jsons.len());
                for json in &jsons {
                    match serde_json::from_str::<crate::summary::FuncSummary>(json) {
                        Ok(s) => out.push(s),
                        Err(e) => {
                            tracing::warn!("failed to deserialize summary JSON: {e}");
                        }
                    }
                }
                Ok(out)
            }
        }

        /// Load every SSA function summary for this project.
        ///
        /// Returns rows with full metadata for `FuncKey` reconstruction:
        /// `(file_path, name, lang, arity, namespace, container, disambig, kind, SsaFuncSummary)`.
        pub fn load_all_ssa_summaries(
            &self,
        ) -> NyxResult<
            Vec<(
                String,
                String,
                String,
                i64,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::summary::ssa_summary::SsaFuncSummary,
            )>,
        > {
            let mut stmt = self.c().prepare(
                "SELECT file_path, name, lang, arity, namespace,
                        container, disambig, kind, summary
                 FROM ssa_function_summaries WHERE project = ?1",
            )?;

            let rows: Vec<(
                String,
                String,
                String,
                i64,
                String,
                String,
                Option<i64>,
                String,
                String,
            )> = stmt
                .query_map([&self.project], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                })?
                .filter_map(|r| match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("failed to read SSA summary row: {e}");
                        None
                    }
                })
                .collect();

            if rows.len() > 256 {
                use rayon::prelude::*;
                let results: Vec<_> = rows
                    .par_iter()
                    .filter_map(
                        |(fp, name, lang, arity, ns, container, disambig, kind, json)| {
                            serde_json::from_str::<crate::summary::ssa_summary::SsaFuncSummary>(
                                json,
                            )
                            .map_err(|e| {
                                tracing::warn!("failed to deserialize SSA summary JSON: {e}");
                                e
                            })
                            .ok()
                            .map(|s| {
                                (
                                    fp.clone(),
                                    name.clone(),
                                    lang.clone(),
                                    *arity,
                                    ns.clone(),
                                    container.clone(),
                                    disambig.map(|d| d as u32),
                                    crate::symbol::FuncKind::from_slug(kind),
                                    s,
                                )
                            })
                        },
                    )
                    .collect();
                Ok(results)
            } else {
                let mut out = Vec::with_capacity(rows.len());
                for (fp, name, lang, arity, ns, container, disambig, kind, json) in &rows {
                    match serde_json::from_str::<crate::summary::ssa_summary::SsaFuncSummary>(json)
                    {
                        Ok(s) => {
                            out.push((
                                fp.clone(),
                                name.clone(),
                                lang.clone(),
                                *arity,
                                ns.clone(),
                                container.clone(),
                                disambig.map(|d| d as u32),
                                crate::symbol::FuncKind::from_slug(kind),
                                s,
                            ));
                        }
                        Err(e) => {
                            tracing::warn!("failed to deserialize SSA summary JSON: {e}");
                        }
                    }
                }
                Ok(out)
            }
        }

        /// Load symbol metadata (name, arity, lang, namespace, container, kind)
        /// for a single file.
        ///
        /// Lighter than `load_all_ssa_summaries`, skips JSON deserialization of
        /// the full summary body and filters by file_path in the query.  `kind`
        /// is the [`crate::symbol::FuncKind`] slug (`"fn"`, `"method"`,
        /// `"closure"`, ...) so consumers can distinguish anonymous functions
        /// from named ones.
        pub fn load_ssa_summaries_for_file(
            &self,
            file_path: &str,
        ) -> NyxResult<Vec<(String, i64, String, String, String, String)>> {
            let mut stmt = self.c().prepare(
                "SELECT name, arity, lang, namespace, container, kind
                 FROM ssa_function_summaries
                 WHERE project = ?1 AND file_path = ?2",
            )?;
            let rows: Vec<(String, i64, String, String, String, String)> = stmt
                .query_map(rusqlite::params![self.project, file_path], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
                .filter_map(Result::ok)
                .collect();
            Ok(rows)
        }

        /// Atomically replace all SSA callee bodies for a single file.
        ///
        /// Persists cross-file callee bodies for interprocedural symex.
        /// Bodies are serialized as MessagePack (rmp-serde, named-field
        /// encoding) BLOBs, JSON proved too costly at indexing time on
        /// large SSA structures, and bincode's positional format trips
        /// over the `#[serde(skip_serializing_if = ...)]` attributes
        /// scattered through `OptimizeResult` and friends.
        /// Input tuple: `(name, arity, lang, namespace, container, disambig, kind, body)`.
        pub fn replace_ssa_bodies_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            bodies: &[(
                String,
                usize,
                String,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::taint::ssa_transfer::CalleeSsaBody,
            )],
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            tx.execute(
                "DELETE FROM ssa_function_bodies WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;

            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO ssa_function_bodies
                        (project, file_path, file_hash, name, arity, lang, namespace,
                         container, disambig, kind, body, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )?;

                for (name, arity, lang, namespace, container, disambig, kind, body) in bodies {
                    let blob = rmp_serde::to_vec_named(body)
                        .map_err(|e| NyxError::Msg(format!("SSA body serialise: {e}")))?;
                    let disambig_sql = disambig.map(|d| d as i64);
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        container,
                        disambig_sql,
                        kind.as_str(),
                        blob,
                        now
                    ])?;
                }
            }

            tx.commit()?;
            Ok(())
        }

        /// Load every SSA callee body for this project.
        ///
        /// Returns rows with full metadata for `FuncKey` reconstruction:
        /// `(file_path, name, lang, arity, namespace, container, disambig, kind, CalleeSsaBody)`.
        pub fn load_all_ssa_bodies(
            &self,
        ) -> NyxResult<
            Vec<(
                String,
                String,
                String,
                i64,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::taint::ssa_transfer::CalleeSsaBody,
            )>,
        > {
            let mut stmt = self.c().prepare(
                "SELECT file_path, name, lang, arity, namespace,
                        container, disambig, kind, body
                 FROM ssa_function_bodies WHERE project = ?1",
            )?;

            let rows: Vec<(
                String,
                String,
                String,
                i64,
                String,
                String,
                Option<i64>,
                String,
                Vec<u8>,
            )> = stmt
                .query_map([&self.project], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                    ))
                })?
                .filter_map(|r| match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("failed to read SSA body row: {e}");
                        None
                    }
                })
                .collect();

            if rows.len() > 256 {
                use rayon::prelude::*;
                let results: Vec<_> = rows
                    .par_iter()
                    .filter_map(
                        |(fp, name, lang, arity, ns, container, disambig, kind, blob)| {
                            rmp_serde::from_slice::<crate::taint::ssa_transfer::CalleeSsaBody>(blob)
                                .map_err(|e| {
                                    tracing::warn!("failed to deserialize SSA body: {e}");
                                    e
                                })
                                .ok()
                                .map(|mut b| {
                                    // Rehydrate a proxy Cfg from node_meta so
                                    // the taint engine's cross-file inline path can index
                                    // `cfg[inst.cfg_node]` uniformly.  No-op for intra-file
                                    // bodies that carry node_meta empty.
                                    crate::taint::ssa_transfer::rebuild_body_graph(&mut b);
                                    (
                                        fp.clone(),
                                        name.clone(),
                                        lang.clone(),
                                        *arity,
                                        ns.clone(),
                                        container.clone(),
                                        disambig.map(|d| d as u32),
                                        crate::symbol::FuncKind::from_slug(kind),
                                        b,
                                    )
                                })
                        },
                    )
                    .collect();
                Ok(results)
            } else {
                let mut out = Vec::with_capacity(rows.len());
                for (fp, name, lang, arity, ns, container, disambig, kind, blob) in &rows {
                    match rmp_serde::from_slice::<crate::taint::ssa_transfer::CalleeSsaBody>(blob) {
                        Ok(mut b) => {
                            // See note in parallel branch above.
                            crate::taint::ssa_transfer::rebuild_body_graph(&mut b);
                            out.push((
                                fp.clone(),
                                name.clone(),
                                lang.clone(),
                                *arity,
                                ns.clone(),
                                container.clone(),
                                disambig.map(|d| d as u32),
                                crate::symbol::FuncKind::from_slug(kind),
                                b,
                            ));
                        }
                        Err(e) => {
                            tracing::warn!("failed to deserialize SSA body: {e}");
                        }
                    }
                }
                Ok(out)
            }
        }

        /// Atomically replace all `AuthCheckSummary` rows for a single file.
        ///
        /// Mirrors [`Self::replace_ssa_summaries_for_file`].  Each input tuple
        /// is `(name, arity, lang, namespace, container, disambig, kind, summary)`
        ///, the full identity needed to reconstruct the callee's
        /// [`crate::symbol::FuncKey`] on load.
        pub fn replace_auth_summaries_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            summaries: &[(
                String,
                usize,
                String,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::auth_analysis::model::AuthCheckSummary,
            )],
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            tx.execute(
                "DELETE FROM auth_check_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;

            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO auth_check_summaries
                        (project, file_path, file_hash, name, arity, lang, namespace,
                         container, disambig, kind, summary, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )?;

                for (name, arity, lang, namespace, container, disambig, kind, summary) in summaries
                {
                    let json = serde_json::to_string(summary)
                        .map_err(|e| NyxError::Msg(format!("auth summary serialise: {e}")))?;
                    let disambig_sql = disambig.map(|d| d as i64);
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        container,
                        disambig_sql,
                        kind.as_str(),
                        json,
                        now
                    ])?;
                }
            }

            tx.commit()?;
            Ok(())
        }

        /// Atomically replace all four per-file caches in a single
        /// transaction.  Equivalent in effect to calling
        /// [`Self::replace_summaries_for_file`],
        /// [`Self::replace_ssa_summaries_for_file`],
        /// [`Self::replace_ssa_bodies_for_file`] and
        /// [`Self::replace_auth_summaries_for_file`] in sequence, but
        /// issues a single fsync at commit instead of four, the
        /// dominant cost on large scans.
        ///
        /// Behaviour parity with the four-call sequence:
        /// * function and auth summaries: DELETE-then-INSERT regardless
        ///   of input length, so emptying a file's summaries clears
        ///   stale rows.
        /// * SSA summaries and bodies: only touched when the input is
        ///   non-empty, matching the existing scan path.
        #[allow(clippy::too_many_arguments)]
        pub fn replace_all_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            func_summaries: &[crate::summary::FuncSummary],
            ssa_summaries: &[(
                String,
                usize,
                String,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::summary::ssa_summary::SsaFuncSummary,
            )],
            ssa_bodies: &[(
                String,
                usize,
                String,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::taint::ssa_transfer::CalleeSsaBody,
            )],
            auth_summaries: &[(
                String,
                usize,
                String,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::auth_analysis::model::AuthCheckSummary,
            )],
            cross_package_imports: Option<(
                &str,
                &std::collections::HashMap<String, crate::symbol::FuncKey>,
            )>,
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            // function_summaries, always replace.
            tx.execute(
                "DELETE FROM function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;
            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO function_summaries
                        (project, file_path, file_hash, name, arity, lang,
                         container, disambig, kind, summary, entry_kind, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )?;
                for s in func_summaries {
                    let json = serde_json::to_string(s)
                        .map_err(|e| NyxError::Msg(format!("summary serialise: {e}")))?;
                    let disambig_sql = s.disambig.map(|d| d as i64);
                    let entry_kind_sql = s
                        .entry_kind
                        .as_ref()
                        .map(|ek| serde_json::to_string(ek).unwrap_or_else(|_| String::new()))
                        .filter(|s| !s.is_empty());
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        s.name,
                        s.param_count as i64,
                        s.lang,
                        s.container,
                        disambig_sql,
                        s.kind.as_str(),
                        json,
                        entry_kind_sql,
                        now
                    ])?;
                }
            }

            // ssa_function_summaries, only touched when non-empty.
            if !ssa_summaries.is_empty() {
                tx.execute(
                    "DELETE FROM ssa_function_summaries
                     WHERE project = ?1 AND file_path = ?2",
                    params![self.project, path_str],
                )?;
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO ssa_function_summaries
                        (project, file_path, file_hash, name, arity, lang, namespace,
                         container, disambig, kind, summary, entry_kind, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                )?;
                for (name, arity, lang, namespace, container, disambig, kind, summary) in
                    ssa_summaries
                {
                    let json = serde_json::to_string(summary)
                        .map_err(|e| NyxError::Msg(format!("SSA summary serialise: {e}")))?;
                    let disambig_sql = disambig.map(|d| d as i64);
                    let entry_kind_sql = summary
                        .entry_kind
                        .as_ref()
                        .map(|ek| serde_json::to_string(ek).unwrap_or_else(|_| String::new()))
                        .filter(|s| !s.is_empty());
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        container,
                        disambig_sql,
                        kind.as_str(),
                        json,
                        entry_kind_sql,
                        now
                    ])?;
                }
            }

            // ssa_function_bodies, only touched when non-empty.
            if !ssa_bodies.is_empty() {
                tx.execute(
                    "DELETE FROM ssa_function_bodies
                     WHERE project = ?1 AND file_path = ?2",
                    params![self.project, path_str],
                )?;
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO ssa_function_bodies
                        (project, file_path, file_hash, name, arity, lang, namespace,
                         container, disambig, kind, body, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )?;
                for (name, arity, lang, namespace, container, disambig, kind, body) in ssa_bodies {
                    let blob = rmp_serde::to_vec_named(body)
                        .map_err(|e| NyxError::Msg(format!("SSA body serialise: {e}")))?;
                    let disambig_sql = disambig.map(|d| d as i64);
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        container,
                        disambig_sql,
                        kind.as_str(),
                        blob,
                        now
                    ])?;
                }
            }

            // auth_check_summaries, always replace, even when empty,
            // so a helper that lost its ownership check no longer
            // leaks lifts into subsequent pass-2 runs.
            tx.execute(
                "DELETE FROM auth_check_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;
            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO auth_check_summaries
                        (project, file_path, file_hash, name, arity, lang, namespace,
                         container, disambig, kind, summary, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )?;
                for (name, arity, lang, namespace, container, disambig, kind, summary) in
                    auth_summaries
                {
                    let json = serde_json::to_string(summary)
                        .map_err(|e| NyxError::Msg(format!("auth summary serialise: {e}")))?;
                    let disambig_sql = disambig.map(|d| d as i64);
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        container,
                        disambig_sql,
                        kind.as_str(),
                        json,
                        now
                    ])?;
                }
            }

            // cross_package_imports: replace this file's row, even with
            // an empty input, so a file that lost its imports does not
            // leave stale resolutions in the cache.
            tx.execute(
                "DELETE FROM cross_package_imports WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;
            if let Some((namespace, map)) = cross_package_imports
                && !map.is_empty()
            {
                let blob = rmp_serde::to_vec_named(map)
                    .map_err(|e| NyxError::Msg(format!("cross_package_imports serialise: {e}")))?;
                tx.execute(
                    "INSERT OR REPLACE INTO cross_package_imports
                        (project, file_path, file_hash, namespace, imports, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![self.project, path_str, file_hash, namespace, blob, now],
                )?;
            }

            tx.commit()?;
            Ok(())
        }

        /// Load every `AuthCheckSummary` for this project.
        ///
        /// Returns rows with full metadata for `FuncKey` reconstruction:
        /// `(file_path, name, lang, arity, namespace, container, disambig, kind, AuthCheckSummary)`.
        pub fn load_all_auth_summaries(
            &self,
        ) -> NyxResult<
            Vec<(
                String,
                String,
                String,
                i64,
                String,
                String,
                Option<u32>,
                crate::symbol::FuncKind,
                crate::auth_analysis::model::AuthCheckSummary,
            )>,
        > {
            let mut stmt = self.c().prepare(
                "SELECT file_path, name, lang, arity, namespace,
                        container, disambig, kind, summary
                 FROM auth_check_summaries WHERE project = ?1",
            )?;

            let rows: Vec<(
                String,
                String,
                String,
                i64,
                String,
                String,
                Option<i64>,
                String,
                String,
            )> = stmt
                .query_map([&self.project], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                })?
                .filter_map(|r| match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("failed to read auth summary row: {e}");
                        None
                    }
                })
                .collect();

            let mut out = Vec::with_capacity(rows.len());
            for (fp, name, lang, arity, ns, container, disambig, kind, json) in &rows {
                match serde_json::from_str::<crate::auth_analysis::model::AuthCheckSummary>(json) {
                    Ok(s) => {
                        out.push((
                            fp.clone(),
                            name.clone(),
                            lang.clone(),
                            *arity,
                            ns.clone(),
                            container.clone(),
                            disambig.map(|d| d as u32),
                            crate::symbol::FuncKind::from_slug(kind),
                            s,
                        ));
                    }
                    Err(e) => {
                        tracing::warn!("failed to deserialize auth summary JSON: {e}");
                    }
                }
            }
            Ok(out)
        }

        /// Load every persisted per-file Phase-09 cross-package import map
        /// for this project.
        ///
        /// Returns rows as `(file_path, namespace, imports_map)`.  Used by
        /// pass 2 of indexed scans to populate
        /// `GlobalSummaries::cross_package_imports_by_namespace`, recovering
        /// the per-file import view that
        /// [`crate::taint::ssa_transfer::CalleeSsaBody::cross_package_imports`]
        /// loses across SQLite round-trip (`#[serde(skip)]`).
        pub fn load_all_cross_package_imports(
            &self,
        ) -> NyxResult<
            Vec<(
                String,
                String,
                std::collections::HashMap<String, crate::symbol::FuncKey>,
            )>,
        > {
            let mut stmt = self.c().prepare(
                "SELECT file_path, namespace, imports
                 FROM cross_package_imports WHERE project = ?1",
            )?;

            let rows: Vec<(String, String, Vec<u8>)> = stmt
                .query_map([&self.project], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?
                .filter_map(|r| match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("failed to read cross_package_imports row: {e}");
                        None
                    }
                })
                .collect();

            let mut out = Vec::with_capacity(rows.len());
            for (fp, ns, blob) in rows {
                match rmp_serde::from_slice::<
                    std::collections::HashMap<String, crate::symbol::FuncKey>,
                >(&blob)
                {
                    Ok(map) => out.push((fp, ns, map)),
                    Err(e) => {
                        tracing::warn!("failed to deserialize cross_package_imports blob: {e}");
                    }
                }
            }
            Ok(out)
        }

        /// Persist a [`crate::surface::SurfaceMap`] for this project.
        ///
        /// Replaces any previously-persisted map; the table holds one row
        /// per project.  The map is canonicalised before serialisation so
        /// `replace_surface_map` + `load_surface_map` round-trip is
        /// byte-identical for structurally identical maps.
        pub fn replace_surface_map(&mut self, map: &crate::surface::SurfaceMap) -> NyxResult<()> {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let mut canon = map.clone();
            let bytes = canon
                .to_json()
                .map_err(|e| NyxError::Msg(format!("surface map serialise: {e}")))?;
            self.c().execute(
                "INSERT OR REPLACE INTO surface_map (project, map_json, updated_at)
                 VALUES (?1, ?2, ?3)",
                params![self.project, bytes, now],
            )?;
            Ok(())
        }

        /// Load the persisted [`crate::surface::SurfaceMap`] for this
        /// project, or `None` when no map has been written.
        pub fn load_surface_map(&self) -> NyxResult<Option<crate::surface::SurfaceMap>> {
            let row: Option<Vec<u8>> = self
                .c()
                .query_row(
                    "SELECT map_json FROM surface_map WHERE project = ?1",
                    params![self.project],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            let Some(bytes) = row else {
                return Ok(None);
            };
            let map = crate::surface::SurfaceMap::from_json(&bytes)
                .map_err(|e| NyxError::Msg(format!("surface map deserialise: {e}")))?;
            Ok(Some(map))
        }

        /// Return the raw JSON bytes stored for the surface map without
        /// deserialising.  Used by the round-trip parity tests so they
        /// can compare on-disk bytes across rescans.
        pub fn load_surface_map_bytes(&self) -> NyxResult<Option<Vec<u8>>> {
            let row: Option<Vec<u8>> = self
                .c()
                .query_row(
                    "SELECT map_json FROM surface_map WHERE project = ?1",
                    params![self.project],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            Ok(row)
        }

        /// Remove a file and all derived persisted state for this project.
        ///
        /// This deletes the file row, issues, and all persisted summary rows so
        /// incremental scans can prune deleted files from the index cleanly.
        pub fn remove_file_and_related(&mut self, path: &Path) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = path.to_string_lossy();

            let file_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM files WHERE project = ?1 AND path = ?2",
                    params![self.project, path_str.as_ref()],
                    |r| r.get(0),
                )
                .optional()?;

            if let Some(file_id) = file_id {
                tx.execute("DELETE FROM issues WHERE file_id = ?1", params![file_id])?;
                tx.execute("DELETE FROM files WHERE id = ?1", params![file_id])?;
            }

            tx.execute(
                "DELETE FROM function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str.as_ref()],
            )?;
            tx.execute(
                "DELETE FROM ssa_function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str.as_ref()],
            )?;
            tx.execute(
                "DELETE FROM ssa_function_bodies WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str.as_ref()],
            )?;
            tx.execute(
                "DELETE FROM auth_check_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str.as_ref()],
            )?;
            tx.execute(
                "DELETE FROM cross_package_imports WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str.as_ref()],
            )?;

            tx.commit()?;
            Ok(())
        }

        /// gets files from the database
        pub fn get_files(&self, project: &str) -> NyxResult<Vec<PathBuf>> {
            let mut stmt = self.c().prepare(
                "SELECT path
         FROM files
         WHERE project = ?1",
            )?;

            let file_iter = stmt.query_map([project], |row| row.get::<_, String>(0))?;

            Ok(file_iter
                .map(|p| p.map(PathBuf::from))
                .collect::<Result<_, _>>()?)
        }

        // Scan persistence

        /// Insert a new scan record.
        pub fn insert_scan(&self, record: &ScanRecord) -> NyxResult<()> {
            self.c().execute(
                "INSERT OR REPLACE INTO scans (id, status, scan_root, started_at, finished_at,
                 duration_secs, engine_version, languages, files_scanned, files_skipped,
                 finding_count, findings_json, timing_json, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    record.id,
                    record.status,
                    record.scan_root,
                    record.started_at,
                    record.finished_at,
                    record.duration_secs,
                    record.engine_version,
                    record.languages,
                    record.files_scanned,
                    record.files_skipped,
                    record.finding_count,
                    record.findings_json,
                    record.timing_json,
                    record.error,
                ],
            )?;
            Ok(())
        }

        /// Update a scan record status and completion fields.
        pub fn update_scan(
            &self,
            id: &str,
            status: &str,
            finished_at: Option<&str>,
            duration_secs: Option<f64>,
            finding_count: Option<i64>,
            findings_json: Option<&str>,
            timing_json: Option<&str>,
            error: Option<&str>,
            files_scanned: Option<i64>,
            files_skipped: Option<i64>,
            languages: Option<&str>,
        ) -> NyxResult<()> {
            self.c().execute(
                "UPDATE scans SET status = ?2, finished_at = ?3, duration_secs = ?4,
                 finding_count = ?5, findings_json = ?6, timing_json = ?7, error = ?8,
                 files_scanned = ?9, files_skipped = ?10, languages = ?11
                 WHERE id = ?1",
                params![
                    id,
                    status,
                    finished_at,
                    duration_secs,
                    finding_count,
                    findings_json,
                    timing_json,
                    error,
                    files_scanned,
                    files_skipped,
                    languages,
                ],
            )?;
            Ok(())
        }

        /// Get a single scan record by ID.
        pub fn get_scan(&self, id: &str) -> NyxResult<Option<ScanRecord>> {
            let result = self
                .c()
                .query_row(
                    "SELECT id, status, scan_root, started_at, finished_at, duration_secs,
                     engine_version, languages, files_scanned, files_skipped, finding_count,
                     findings_json, timing_json, error
                     FROM scans WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok(ScanRecord {
                            id: row.get(0)?,
                            status: row.get(1)?,
                            scan_root: row.get(2)?,
                            started_at: row.get(3)?,
                            finished_at: row.get(4)?,
                            duration_secs: row.get(5)?,
                            engine_version: row.get(6)?,
                            languages: row.get(7)?,
                            files_scanned: row.get(8)?,
                            files_skipped: row.get(9)?,
                            finding_count: row.get(10)?,
                            findings_json: row.get(11)?,
                            timing_json: row.get(12)?,
                            error: row.get(13)?,
                        })
                    },
                )
                .optional()?;
            Ok(result)
        }

        /// List scan records, most recent first, up to `limit`.
        pub fn list_scans(&self, limit: i64) -> NyxResult<Vec<ScanRecord>> {
            let mut stmt = self.c().prepare(
                "SELECT id, status, scan_root, started_at, finished_at, duration_secs,
                 engine_version, languages, files_scanned, files_skipped, finding_count,
                 findings_json, timing_json, error
                 FROM scans ORDER BY started_at DESC LIMIT ?1",
            )?;
            let rows = stmt
                .query_map(params![limit], |row| {
                    Ok(ScanRecord {
                        id: row.get(0)?,
                        status: row.get(1)?,
                        scan_root: row.get(2)?,
                        started_at: row.get(3)?,
                        finished_at: row.get(4)?,
                        duration_secs: row.get(5)?,
                        engine_version: row.get(6)?,
                        languages: row.get(7)?,
                        files_scanned: row.get(8)?,
                        files_skipped: row.get(9)?,
                        finding_count: row.get(10)?,
                        findings_json: row.get(11)?,
                        timing_json: row.get(12)?,
                        error: row.get(13)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect();
            Ok(rows)
        }

        /// Delete a scan and its associated metrics/logs (FK CASCADE).
        pub fn delete_scan(&self, id: &str) -> NyxResult<usize> {
            let rows = self
                .c()
                .execute("DELETE FROM scans WHERE id = ?1", params![id])?;
            Ok(rows)
        }

        /// Insert scan metrics for a completed scan.
        pub fn insert_scan_metrics(
            &self,
            scan_id: &str,
            metrics: &crate::server::progress::ScanMetricsSnapshot,
        ) -> NyxResult<()> {
            self.c().execute(
                "INSERT OR REPLACE INTO scan_metrics (scan_id, cfg_nodes, call_edges,
                 functions_analyzed, summaries_reused, unresolved_calls)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    scan_id,
                    metrics.cfg_nodes as i64,
                    metrics.call_edges as i64,
                    metrics.functions_analyzed as i64,
                    metrics.summaries_reused as i64,
                    metrics.unresolved_calls as i64,
                ],
            )?;
            Ok(())
        }

        /// Get scan metrics by scan ID.
        pub fn get_scan_metrics(
            &self,
            scan_id: &str,
        ) -> NyxResult<Option<crate::server::progress::ScanMetricsSnapshot>> {
            let result = self
                .c()
                .query_row(
                    "SELECT cfg_nodes, call_edges, functions_analyzed,
                     summaries_reused, unresolved_calls
                     FROM scan_metrics WHERE scan_id = ?1",
                    params![scan_id],
                    |row| {
                        Ok(crate::server::progress::ScanMetricsSnapshot {
                            cfg_nodes: row.get::<_, i64>(0)? as u64,
                            call_edges: row.get::<_, i64>(1)? as u64,
                            functions_analyzed: row.get::<_, i64>(2)? as u64,
                            summaries_reused: row.get::<_, i64>(3)? as u64,
                            unresolved_calls: row.get::<_, i64>(4)? as u64,
                        })
                    },
                )
                .optional()?;
            Ok(result)
        }

        /// Insert scan log entries.
        pub fn insert_scan_logs(
            &self,
            scan_id: &str,
            logs: &[crate::server::scan_log::ScanLogEntry],
        ) -> NyxResult<()> {
            let mut stmt = self.c().prepare(
                "INSERT INTO scan_logs (scan_id, timestamp, level, message, file_path, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for log in logs {
                stmt.execute(params![
                    scan_id,
                    log.timestamp.to_rfc3339(),
                    log.level.to_string(),
                    log.message,
                    log.file_path,
                    log.detail,
                ])?;
            }
            Ok(())
        }

        /// Get scan logs, optionally filtered by level.
        pub fn get_scan_logs(
            &self,
            scan_id: &str,
            level_filter: Option<&str>,
        ) -> NyxResult<Vec<crate::server::scan_log::ScanLogEntry>> {
            let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
                if let Some(level) = level_filter {
                    (
                        "SELECT timestamp, level, message, file_path, detail
                         FROM scan_logs WHERE scan_id = ?1 AND level = ?2
                         ORDER BY id ASC",
                        vec![Box::new(scan_id.to_string()), Box::new(level.to_string())],
                    )
                } else {
                    (
                        "SELECT timestamp, level, message, file_path, detail
                         FROM scan_logs WHERE scan_id = ?1
                         ORDER BY id ASC",
                        vec![Box::new(scan_id.to_string())],
                    )
                };

            let mut stmt = self.c().prepare(sql)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    let ts_str: String = row.get(0)?;
                    let level_str: String = row.get(1)?;
                    Ok((
                        ts_str,
                        level_str,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                })?
                .filter_map(Result::ok)
                .filter_map(|(ts_str, level_str, message, file_path, detail)| {
                    let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
                        .ok()?
                        .with_timezone(&chrono::Utc);
                    let level = level_str.parse().ok()?;
                    Some(crate::server::scan_log::ScanLogEntry {
                        timestamp,
                        level,
                        message,
                        file_path,
                        detail,
                    })
                })
                .collect();
            Ok(rows)
        }

        // Triage state management

        /// Get the triage state for a single finding fingerprint.
        /// Returns (state, note, updated_at) or None if no triage state exists.
        #[allow(dead_code)]
        pub fn get_triage_state(
            &self,
            fingerprint: &str,
        ) -> NyxResult<Option<(String, String, String)>> {
            let result = self
                .c()
                .query_row(
                    "SELECT state, note, updated_at FROM triage_states WHERE fingerprint = ?1",
                    params![fingerprint],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            Ok(result)
        }

        /// Set the triage state for a single finding. Upserts the state and
        /// appends an audit log entry. Returns the previous state (or "open").
        pub fn set_triage_state(
            &self,
            fingerprint: &str,
            state: &str,
            note: &str,
            action: &str,
        ) -> NyxResult<String> {
            let now = chrono::Utc::now().to_rfc3339();
            let prev: String = self
                .c()
                .query_row(
                    "SELECT state FROM triage_states WHERE fingerprint = ?1",
                    params![fingerprint],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| "open".to_string());

            self.c().execute(
                "INSERT INTO triage_states (fingerprint, state, note, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(fingerprint) DO UPDATE
                 SET state = excluded.state, note = excluded.note, updated_at = excluded.updated_at",
                params![fingerprint, state, note, now],
            )?;

            self.c().execute(
                "INSERT INTO triage_audit_log (fingerprint, action, previous_state, new_state, note, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![fingerprint, action, prev, state, note, now],
            )?;

            Ok(prev)
        }

        /// Bulk set triage state. Returns vec of (fingerprint, previous_state).
        pub fn set_triage_states_bulk(
            &self,
            fingerprints: &[String],
            state: &str,
            note: &str,
            action: &str,
        ) -> NyxResult<Vec<(String, String)>> {
            let now = chrono::Utc::now().to_rfc3339();
            let mut results = Vec::with_capacity(fingerprints.len());

            // Read all previous states first
            let mut prev_stmt = self
                .c()
                .prepare("SELECT state FROM triage_states WHERE fingerprint = ?1")?;

            for fp in fingerprints {
                let prev: String = prev_stmt
                    .query_row(params![fp], |row| row.get(0))
                    .optional()?
                    .unwrap_or_else(|| "open".to_string());
                results.push((fp.clone(), prev));
            }
            drop(prev_stmt);

            // Upsert all states
            let mut upsert_stmt = self.c().prepare(
                "INSERT INTO triage_states (fingerprint, state, note, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(fingerprint) DO UPDATE
                 SET state = excluded.state, note = excluded.note, updated_at = excluded.updated_at",
            )?;
            for fp in fingerprints {
                upsert_stmt.execute(params![fp, state, note, now])?;
            }
            drop(upsert_stmt);

            // Insert audit log entries
            let mut audit_stmt = self.c().prepare(
                "INSERT INTO triage_audit_log (fingerprint, action, previous_state, new_state, note, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (fp, prev) in &results {
                audit_stmt.execute(params![fp, action, prev, state, note, now])?;
            }

            Ok(results)
        }

        /// Load all triage states as a map: fingerprint → (state, note, updated_at).
        pub fn get_all_triage_states(
            &self,
        ) -> NyxResult<std::collections::HashMap<String, (String, String, String)>> {
            let mut stmt = self
                .c()
                .prepare("SELECT fingerprint, state, note, updated_at FROM triage_states")?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .filter_map(Result::ok)
                .map(|(fp, state, note, updated)| (fp, (state, note, updated)))
                .collect();
            Ok(rows)
        }

        /// List triage states with optional state filter, paginated.
        /// Returns (entries, total_count).
        pub fn list_triage_states(
            &self,
            state_filter: Option<&str>,
            limit: i64,
            offset: i64,
        ) -> NyxResult<(Vec<(String, String, String, String)>, i64)> {
            let (sql, count_sql, params_vec): (&str, &str, Vec<Box<dyn rusqlite::types::ToSql>>) =
                if let Some(state) = state_filter {
                    (
                        "SELECT fingerprint, state, note, updated_at FROM triage_states
                         WHERE state = ?1 ORDER BY updated_at DESC LIMIT ?2 OFFSET ?3",
                        "SELECT COUNT(*) FROM triage_states WHERE state = ?1",
                        vec![
                            Box::new(state.to_string()),
                            Box::new(limit),
                            Box::new(offset),
                        ],
                    )
                } else {
                    (
                        "SELECT fingerprint, state, note, updated_at FROM triage_states
                         ORDER BY updated_at DESC LIMIT ?1 OFFSET ?2",
                        "SELECT COUNT(*) FROM triage_states",
                        vec![Box::new(limit), Box::new(offset)],
                    )
                };

            let total: i64 = if let Some(state) = state_filter {
                self.c()
                    .query_row(count_sql, params![state], |row| row.get(0))?
            } else {
                self.c().query_row(count_sql, [], |row| row.get(0))?
            };

            let mut stmt = self.c().prepare(sql)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .filter_map(Result::ok)
                .collect();
            Ok((rows, total))
        }

        /// Get the audit log, optionally filtered by fingerprint, paginated.
        /// Returns (entries, total_count).
        pub fn get_audit_log(
            &self,
            fingerprint_filter: Option<&str>,
            limit: i64,
            offset: i64,
        ) -> NyxResult<(Vec<AuditEntry>, i64)> {
            let (sql, count_sql, params_vec): (&str, &str, Vec<Box<dyn rusqlite::types::ToSql>>) =
                if let Some(fp) = fingerprint_filter {
                    (
                        "SELECT id, fingerprint, action, previous_state, new_state, note, timestamp
                         FROM triage_audit_log WHERE fingerprint = ?1
                         ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3",
                        "SELECT COUNT(*) FROM triage_audit_log WHERE fingerprint = ?1",
                        vec![Box::new(fp.to_string()), Box::new(limit), Box::new(offset)],
                    )
                } else {
                    (
                        "SELECT id, fingerprint, action, previous_state, new_state, note, timestamp
                         FROM triage_audit_log ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2",
                        "SELECT COUNT(*) FROM triage_audit_log",
                        vec![Box::new(limit), Box::new(offset)],
                    )
                };

            let total: i64 = if let Some(fp) = fingerprint_filter {
                self.c()
                    .query_row(count_sql, params![fp], |row| row.get(0))?
            } else {
                self.c().query_row(count_sql, [], |row| row.get(0))?
            };

            let mut stmt = self.c().prepare(sql)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    Ok(AuditEntry {
                        id: row.get(0)?,
                        fingerprint: row.get(1)?,
                        action: row.get(2)?,
                        previous_state: row.get(3)?,
                        new_state: row.get(4)?,
                        note: row.get(5)?,
                        timestamp: row.get(6)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect();
            Ok((rows, total))
        }

        /// Add a pattern-based suppression rule.
        pub fn add_suppression_rule(
            &self,
            suppress_by: &str,
            match_value: &str,
            state: &str,
            note: &str,
        ) -> NyxResult<i64> {
            let now = chrono::Utc::now().to_rfc3339();
            self.c().execute(
                "INSERT OR REPLACE INTO triage_suppression_rules
                 (suppress_by, match_value, state, note, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![suppress_by, match_value, state, note, now],
            )?;
            Ok(self.c().last_insert_rowid())
        }

        /// Get all suppression rules.
        pub fn get_suppression_rules(&self) -> NyxResult<Vec<SuppressionRule>> {
            let mut stmt = self.c().prepare(
                "SELECT id, suppress_by, match_value, state, note, created_at
                 FROM triage_suppression_rules ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(SuppressionRule {
                        id: row.get(0)?,
                        suppress_by: row.get(1)?,
                        match_value: row.get(2)?,
                        state: row.get(3)?,
                        note: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect();
            Ok(rows)
        }

        /// Record the first time a finding fingerprint was observed. Idempotent ,
        /// the earliest call wins via INSERT OR IGNORE. Used by the overview
        /// backlog-age computation; ts should be the originating scan's
        /// `started_at` (RFC-3339).
        pub fn record_finding_first_seen(&self, fingerprint: &str, ts: &str) -> NyxResult<()> {
            self.c().execute(
                "INSERT OR IGNORE INTO finding_first_seen (fingerprint, first_seen_at) VALUES (?1, ?2)",
                params![fingerprint, ts],
            )?;
            Ok(())
        }

        /// Bulk variant. Inserts ignoring conflicts.
        pub fn record_finding_first_seen_bulk(
            &self,
            entries: &[(String, String)],
        ) -> NyxResult<()> {
            if entries.is_empty() {
                return Ok(());
            }
            let conn = self.c();
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT OR IGNORE INTO finding_first_seen (fingerprint, first_seen_at) VALUES (?1, ?2)",
                )?;
                for (fp, ts) in entries {
                    stmt.execute(params![fp, ts])?;
                }
            }
            tx.commit()?;
            Ok(())
        }

        /// Look up first-seen timestamps for a set of fingerprints. Missing
        /// entries are simply absent from the returned map.
        pub fn get_first_seen_map(
            &self,
            fingerprints: &[String],
        ) -> NyxResult<std::collections::HashMap<String, String>> {
            if fingerprints.is_empty() {
                return Ok(std::collections::HashMap::new());
            }
            // SQLite IN-clause cap is high but parameter count is bounded, chunk
            // for safety with large fingerprint sets.
            let mut out = std::collections::HashMap::with_capacity(fingerprints.len());
            let conn = self.c();
            for chunk in fingerprints.chunks(500) {
                let placeholders = (1..=chunk.len())
                    .map(|i| format!("?{i}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let sql = format!(
                    "SELECT fingerprint, first_seen_at FROM finding_first_seen WHERE fingerprint IN ({placeholders})"
                );
                let mut stmt = conn.prepare(&sql)?;
                let params: Vec<&dyn rusqlite::ToSql> =
                    chunk.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                let rows = stmt.query_map(params.as_slice(), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                for r in rows.flatten() {
                    out.insert(r.0, r.1);
                }
            }
            Ok(out)
        }

        /// Get a single metadata value by key. Returns None if absent.
        pub fn get_metadata(&self, key: &str) -> NyxResult<Option<String>> {
            let conn = self.c();
            let mut stmt = conn.prepare("SELECT value FROM nyx_metadata WHERE key = ?1")?;
            let mut rows = stmt.query(params![key])?;
            if let Some(row) = rows.next()? {
                Ok(Some(row.get(0)?))
            } else {
                Ok(None)
            }
        }

        /// Set a metadata value (insert-or-replace).
        pub fn set_metadata(&self, key: &str, value: &str) -> NyxResult<()> {
            self.c().execute(
                "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
            Ok(())
        }

        /// Remove a metadata key. Returns true if a row was deleted.
        pub fn delete_metadata(&self, key: &str) -> NyxResult<bool> {
            let n = self
                .c()
                .execute("DELETE FROM nyx_metadata WHERE key = ?1", params![key])?;
            Ok(n > 0)
        }

        /// Delete a suppression rule by ID. Returns true if a row was deleted.
        pub fn delete_suppression_rule(&self, id: i64) -> NyxResult<bool> {
            let count = self.c().execute(
                "DELETE FROM triage_suppression_rules WHERE id = ?1",
                params![id],
            )?;
            Ok(count > 0)
        }

        // Maintenance utilities
        pub fn clear(&self) -> NyxResult<()> {
            self.c().execute_batch(
                r#"
        PRAGMA foreign_keys = OFF;

        DROP TABLE IF EXISTS issues;
        DROP TABLE IF EXISTS files;
        DROP TABLE IF EXISTS function_summaries;
        DROP TABLE IF EXISTS ssa_function_summaries;

        PRAGMA foreign_keys = ON;
        VACUUM;
        "#,
            )?;

            self.c().execute_batch(SCHEMA)?;
            Ok(())
        }

        pub fn vacuum(&self) -> NyxResult<()> {
            self.c().execute("VACUUM;", [])?;
            Ok(())
        }

        // Helpers
        #[cfg(test)]
        fn digest_file(path: &Path) -> NyxResult<Vec<u8>> {
            let mut hasher = blake3::Hasher::new();
            let mut file = fs::File::open(path)?;
            std::io::copy(&mut file, &mut hasher)?;
            Ok(hasher.finalize().as_bytes().to_vec())
        }

        /// Hash already-read bytes without re-reading from disk.
        pub fn digest_bytes(bytes: &[u8]) -> Vec<u8> {
            let mut hasher = blake3::Hasher::new();
            hasher.update(bytes);
            hasher.finalize().as_bytes().to_vec()
        }
    }
}

#[test]
fn indexer_should_scan_and_upsert_logic() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let file = td.path().join("sample.rs");
    std::fs::write(&file, "fn main() {}").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();

    // first time: nothing in DB → must scan
    assert!(idx.should_scan(&file).unwrap());

    // after upsert: no changes → should *not* scan
    idx.upsert_file(&file).unwrap();
    assert!(!idx.should_scan(&file).unwrap());

    // modify contents
    std::thread::sleep(std::time::Duration::from_millis(25)); // ensure mtime tick
    std::fs::write(&file, "fn main() { /* changed */ }").unwrap();
    assert!(idx.should_scan(&file).unwrap());
}

#[test]
fn replace_issues_and_query_back() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let file = td.path().join("code.go");
    std::fs::write(&file, "package main").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let fid = idx.upsert_file(&file).unwrap();

    let issues = [
        index::IssueRow {
            rule_id: "X1",
            severity: "High",
            line: 3,
            col: 7,
        },
        index::IssueRow {
            rule_id: "X2",
            severity: "Low",
            line: 4,
            col: 1,
        },
    ];
    idx.replace_issues(fid, issues.clone()).unwrap();

    let stored = idx.get_issues_from_file(&file).unwrap();
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .any(|d| d.id == "X1" && d.severity == crate::patterns::Severity::High)
    );
    assert!(
        stored
            .iter()
            .any(|d| d.id == "X2" && d.severity == crate::patterns::Severity::Low)
    );
}

#[test]
fn clear_and_vacuum_reset_tables() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("f.rs");
    std::fs::write(&f, "//").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    idx.upsert_file(&f).unwrap();

    assert!(!idx.get_files("proj").unwrap().is_empty());
    idx.clear().unwrap();
    idx.vacuum().unwrap();
    assert!(idx.get_files("proj").unwrap().is_empty());
}

#[test]
fn clear_preserves_scan_history_tables() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("_scans", &pool).unwrap();
    idx.insert_scan(&index::ScanRecord {
        id: "scan-1".to_string(),
        status: "completed".to_string(),
        scan_root: td.path().display().to_string(),
        started_at: Some("2026-03-25T12:00:00Z".to_string()),
        finished_at: Some("2026-03-25T12:00:01Z".to_string()),
        duration_secs: Some(1.0),
        engine_version: Some("test".to_string()),
        languages: None,
        files_scanned: Some(1),
        files_skipped: Some(0),
        finding_count: Some(0),
        findings_json: Some("[]".to_string()),
        timing_json: None,
        error: None,
    })
    .unwrap();

    let proj_idx = index::Indexer::from_pool("proj", &pool).unwrap();
    proj_idx.clear().unwrap();

    let loaded = idx
        .get_scan("scan-1")
        .unwrap()
        .expect("scan history should survive index clears");
    assert_eq!(loaded.status, "completed");
}

#[test]
fn ssa_summaries_round_trip() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("app.py");
    std::fs::write(&f, "def process(data): return data").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"def process(data): return data");
    let summaries = vec![
        (
            "process".to_string(),
            1_usize,
            "python".to_string(),
            "app.py".to_string(),
            String::new(),
            None,
            crate::symbol::FuncKind::Function,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                validated_params_to_return: smallvec::SmallVec::new(),
                param_to_gate_filters: vec![],
                entry_kind: None,
            },
        ),
        (
            "sanitize".to_string(),
            1_usize,
            "python".to_string(),
            "app.py".to_string(),
            String::new(),
            None,
            crate::symbol::FuncKind::Function,
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
                param_to_sink: vec![(
                    0,
                    smallvec::smallvec![crate::summary::SinkSite::cap_only(Cap::SQL_QUERY)],
                )],
                source_caps: Cap::ENV_VAR,
                param_to_sink_param: vec![],
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                validated_params_to_return: smallvec::SmallVec::new(),
                param_to_gate_filters: vec![],
                entry_kind: None,
            },
        ),
    ];

    idx.replace_ssa_summaries_for_file(&f, &hash, &summaries)
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 2);

    // Check first summary
    let (_, name1, lang1, arity1, ns1, _, _, _, sum1) = loaded
        .iter()
        .find(|(_, n, _, _, _, _, _, _, _)| n == "process")
        .unwrap();
    assert_eq!(name1, "process");
    assert_eq!(lang1, "python");
    assert_eq!(*arity1, 1);
    assert_eq!(ns1, "app.py");
    assert_eq!(sum1.param_to_return, vec![(0, TaintTransform::Identity)]);
    assert!(sum1.param_to_sink.is_empty());

    // Check second summary
    let (_, name2, _, _, _, _, _, _, sum2) = loaded
        .iter()
        .find(|(_, n, _, _, _, _, _, _, _)| n == "sanitize")
        .unwrap();
    assert_eq!(name2, "sanitize");
    assert_eq!(
        sum2.param_to_return,
        vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))]
    );
    assert_eq!(sum2.param_to_sink_caps(), vec![(0, Cap::SQL_QUERY)]);
    assert_eq!(sum2.source_caps, Cap::ENV_VAR);
}

/// Round-trip test for [`crate::summary::ssa_summary::PathFactReturnEntry`]:
/// asserts that `return_path_facts` survive serialise → SQLite persist →
/// load → deserialise.  Regression guard for the per-return-path PathFact
/// decomposition that closes the rs-safe-014 / tar-rs / rs-safe-016 FP
/// cluster, without this round-trip working, cross-file callers lose
/// the per-arm narrowing and inline-only callees regain the joined-fact
/// dilution.
#[test]
fn ssa_summaries_round_trip_preserves_return_path_facts() {
    use crate::abstract_interp::PathFact;
    use crate::summary::ssa_summary::{PathFactReturnEntry, SsaFuncSummary, TaintTransform};
    use smallvec::smallvec;

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("sanitize.rs");
    std::fs::write(&f, "// sanitizer body").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"// sanitizer body");
    let return_path_facts = smallvec![
        PathFactReturnEntry {
            predicate_hash: 0,
            known_true: 0,
            known_false: 0,
            path_fact: PathFact::top(),
            variant_inner_fact: None,
        },
        PathFactReturnEntry {
            predicate_hash: 17,
            known_true: 0,
            known_false: 0,
            path_fact: PathFact::top(),
            variant_inner_fact: Some(
                PathFact::top()
                    .with_dotdot_cleared()
                    .with_absolute_cleared(),
            ),
        },
    ];
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        return_path_facts: return_path_facts.clone(),
        ..Default::default()
    };
    let row = (
        "sanitize_path".to_string(),
        1_usize,
        "rust".to_string(),
        "sanitize.rs".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        summary,
    );

    idx.replace_ssa_summaries_for_file(&f, &hash, &[row])
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 1);
    let (_, name, _, _, _, _, _, _, sum) = &loaded[0];
    assert_eq!(name, "sanitize_path");
    assert_eq!(
        sum.return_path_facts.len(),
        2,
        "two distinct return paths must round-trip"
    );
    // Find each entry by predicate hash so order doesn't matter.
    let none_arm = sum
        .return_path_facts
        .iter()
        .find(|e| e.predicate_hash == 0)
        .expect("unguarded entry");
    assert!(none_arm.path_fact.is_top());
    assert!(none_arm.variant_inner_fact.is_none());
    let some_arm = sum
        .return_path_facts
        .iter()
        .find(|e| e.predicate_hash == 17)
        .expect("guarded entry");
    let inner = some_arm
        .variant_inner_fact
        .as_ref()
        .expect("inner fact survives round-trip");
    assert!(
        inner.is_path_safe(),
        "Some arm's inner fact stays path-safe"
    );
}

#[test]
fn ssa_summaries_hash_rescan_replaces_stale() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("lib.py");
    std::fs::write(&f, "v1").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash_v1 = index::Indexer::digest_bytes(b"v1");
    let sums_v1 = vec![(
        "old_func".to_string(),
        1_usize,
        "python".to_string(),
        "lib.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::Identity)],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],

            receiver_to_return: None,

            receiver_to_sink: Cap::empty(),

            abstract_transfer: vec![],
            param_return_paths: vec![],
            points_to: Default::default(),
            field_points_to: Default::default(),
            return_path_facts: smallvec::SmallVec::new(),
            typed_call_receivers: vec![],
            validated_params_to_return: smallvec::SmallVec::new(),
            param_to_gate_filters: vec![],
            entry_kind: None,
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash_v1, &sums_v1)
        .unwrap();

    // Simulate file change: different function, different hash
    let hash_v2 = index::Indexer::digest_bytes(b"v2");
    let sums_v2 = vec![(
        "new_func".to_string(),
        2_usize,
        "python".to_string(),
        "lib.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::StripBits(Cap::SHELL_ESCAPE))],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],

            receiver_to_return: None,

            receiver_to_sink: Cap::empty(),

            abstract_transfer: vec![],
            param_return_paths: vec![],
            points_to: Default::default(),
            field_points_to: Default::default(),
            return_path_facts: smallvec::SmallVec::new(),
            typed_call_receivers: vec![],
            validated_params_to_return: smallvec::SmallVec::new(),
            param_to_gate_filters: vec![],
            entry_kind: None,
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash_v2, &sums_v2)
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(
        loaded.len(),
        1,
        "old summary should be replaced, not duplicated"
    );
    assert_eq!(loaded[0].1, "new_func");
}

#[test]
fn clear_drops_ssa_summaries_table() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("test.py");
    std::fs::write(&f, "x").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"x");
    let sums = vec![(
        "f".to_string(),
        1_usize,
        "python".to_string(),
        "test.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::Identity)],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],

            receiver_to_return: None,

            receiver_to_sink: Cap::empty(),

            abstract_transfer: vec![],
            param_return_paths: vec![],
            points_to: Default::default(),
            field_points_to: Default::default(),
            return_path_facts: smallvec::SmallVec::new(),
            typed_call_receivers: vec![],
            validated_params_to_return: smallvec::SmallVec::new(),
            param_to_gate_filters: vec![],
            entry_kind: None,
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash, &sums)
        .unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 1);

    idx.clear().unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 0);
}

// ── CalleeSsaBody persistence tests ──────────────────────────────────────

/// Helper: build a minimal CalleeSsaBody for DB tests.
#[cfg(test)]
fn make_test_callee_body(
    num_blocks: usize,
    param_count: usize,
) -> crate::taint::ssa_transfer::CalleeSsaBody {
    use crate::ssa::ir::*;
    use smallvec::smallvec;

    let mut blocks = Vec::new();
    for i in 0..num_blocks {
        blocks.push(SsaBlock {
            id: BlockId(i as u32),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(i as u32),
                op: SsaOp::Const(Some(format!("{i}"))),
                cfg_node: petgraph::graph::NodeIndex::new(0),
                var_name: None,
                span: (0, 0),
            }],
            terminator: Terminator::Return(Some(SsaValue(0))),
            preds: smallvec![],
            succs: smallvec![],
        });
    }

    let value_defs: Vec<ValueDef> = (0..num_blocks)
        .map(|i| ValueDef {
            var_name: None,
            cfg_node: petgraph::graph::NodeIndex::new(0),
            block: BlockId(i as u32),
        })
        .collect();

    crate::taint::ssa_transfer::CalleeSsaBody {
        ssa: SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs,
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::new(),
            field_writes: std::collections::HashMap::new(),
            synthetic_externals: std::collections::HashSet::new(),
            slot_scoped_assigns: std::collections::HashSet::new(),
        },
        opt: crate::ssa::OptimizeResult {
            const_values: std::collections::HashMap::new(),
            type_facts: crate::ssa::type_facts::TypeFactResult {
                facts: std::collections::HashMap::new(),
            },
            xml_parser_config: crate::ssa::xml_config::XmlParserConfigResult::default(),
            xpath_config: crate::ssa::xpath_config::XPathConfigResult::default(),
            alias_result: crate::ssa::alias::BaseAliasResult::empty(),
            points_to: crate::ssa::heap::PointsToResult::empty(),
            module_aliases: std::collections::HashMap::new(),
            branches_pruned: 0,
            copies_eliminated: 0,
            dead_defs_removed: 0,
        },
        param_count,
        node_meta: std::collections::HashMap::new(),
        body_graph: None,
        cross_package_imports: std::sync::Arc::new(std::collections::HashMap::new()),
    }
}

#[test]
fn cross_package_imports_round_trip_via_replace_all_for_file() {
    use crate::symbol::{FuncKey, FuncKind, Lang};
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("caller.ts");
    std::fs::write(&f, "import { escape } from '@scope/util';").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let hash = index::Indexer::digest_bytes(b"caller content");

    let mut imports: std::collections::HashMap<String, FuncKey> = std::collections::HashMap::new();
    imports.insert(
        "escape".to_string(),
        FuncKey {
            lang: Lang::TypeScript,
            namespace: "packages/util/src/escape.ts".to_string(),
            container: String::new(),
            name: "escape".to_string(),
            arity: None,
            disambig: None,
            kind: FuncKind::Function,
        },
    );

    idx.replace_all_for_file(&f, &hash, &[], &[], &[], &[], Some(("caller.ts", &imports)))
        .unwrap();

    let loaded = idx.load_all_cross_package_imports().unwrap();
    assert_eq!(loaded.len(), 1);
    let (fp, ns, map) = &loaded[0];
    assert_eq!(fp, &f.to_string_lossy().to_string());
    assert_eq!(ns, "caller.ts");
    assert_eq!(map.len(), 1);
    let key = map
        .get("escape")
        .expect("escape binding survives round-trip");
    assert_eq!(key.namespace, "packages/util/src/escape.ts");
    assert_eq!(key.name, "escape");
    assert_eq!(key.lang, Lang::TypeScript);

    // Empty input on rescan should drop the row.
    idx.replace_all_for_file(&f, &hash, &[], &[], &[], &[], None)
        .unwrap();
    assert!(idx.load_all_cross_package_imports().unwrap().is_empty());
}

#[test]
fn ssa_bodies_round_trip() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("helper.py");
    std::fs::write(&f, "def transform(val): return val").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let hash = index::Indexer::digest_bytes(b"def transform(val): return val");

    let body = make_test_callee_body(3, 1);
    let bodies = vec![(
        "transform".to_string(),
        1_usize,
        "python".to_string(),
        "helper.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        body,
    )];

    idx.replace_ssa_bodies_for_file(&f, &hash, &bodies).unwrap();

    let loaded = idx.load_all_ssa_bodies().unwrap();
    assert_eq!(loaded.len(), 1);

    let (fp, name, lang, arity, ns, _, _, _, loaded_body) = &loaded[0];
    assert_eq!(fp, &f.to_string_lossy().to_string());
    assert_eq!(name, "transform");
    assert_eq!(lang, "python");
    assert_eq!(*arity, 1);
    assert_eq!(ns, "helper.py");
    assert_eq!(loaded_body.param_count, 1);
    assert_eq!(loaded_body.ssa.blocks.len(), 3);
}

#[test]
fn ssa_bodies_replace_on_rescan() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("helper.py");
    std::fs::write(&f, "v1").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    // Store v1 with 2 blocks
    let hash1 = index::Indexer::digest_bytes(b"v1");
    let bodies1 = vec![(
        "func".to_string(),
        1_usize,
        "python".to_string(),
        "h.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_callee_body(2, 1),
    )];
    idx.replace_ssa_bodies_for_file(&f, &hash1, &bodies1)
        .unwrap();
    assert_eq!(idx.load_all_ssa_bodies().unwrap().len(), 1);
    assert_eq!(idx.load_all_ssa_bodies().unwrap()[0].8.ssa.blocks.len(), 2);

    // Store v2 with 5 blocks, should replace, not accumulate
    let hash2 = index::Indexer::digest_bytes(b"v2");
    let bodies2 = vec![(
        "func".to_string(),
        1_usize,
        "python".to_string(),
        "h.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_callee_body(5, 1),
    )];
    idx.replace_ssa_bodies_for_file(&f, &hash2, &bodies2)
        .unwrap();

    let loaded = idx.load_all_ssa_bodies().unwrap();
    assert_eq!(loaded.len(), 1, "should replace, not accumulate");
    assert_eq!(loaded[0].8.ssa.blocks.len(), 5);
}

#[test]
fn ssa_bodies_with_node_meta_round_trip() {
    use crate::cfg::{NodeInfo, TaintMeta};
    use crate::labels::{Cap, DataLabel};
    use crate::taint::ssa_transfer::CrossFileNodeMeta;

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("helper.py");
    std::fs::write(&f, "code").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let hash = index::Indexer::digest_bytes(b"code");

    let mut body = make_test_callee_body(1, 0);
    body.node_meta.insert(
        0,
        CrossFileNodeMeta {
            info: NodeInfo {
                bin_op: Some(crate::cfg::BinOp::Add),
                taint: TaintMeta {
                    labels: smallvec::smallvec![DataLabel::Sink(Cap::SQL_QUERY)],
                    ..Default::default()
                },
                ..Default::default()
            },
        },
    );

    let bodies = vec![(
        "f".to_string(),
        0_usize,
        "python".to_string(),
        "h.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        body,
    )];
    idx.replace_ssa_bodies_for_file(&f, &hash, &bodies).unwrap();

    let loaded = idx.load_all_ssa_bodies().unwrap();
    assert_eq!(loaded.len(), 1);

    let meta = &loaded[0].8.node_meta;
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[&0].info.bin_op, Some(crate::cfg::BinOp::Add));
    assert!(matches!(meta[&0].info.taint.labels[0], DataLabel::Sink(cap) if cap == Cap::SQL_QUERY));
}

#[test]
fn ssa_bodies_removed_on_file_delete() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("helper.py");
    std::fs::write(&f, "code").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let hash = index::Indexer::digest_bytes(b"code");

    // Register file first so remove_file_and_related has something to find
    idx.upsert_file(&f).unwrap();

    let bodies = vec![(
        "f".to_string(),
        0_usize,
        "python".to_string(),
        "h.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_callee_body(1, 0),
    )];
    idx.replace_ssa_bodies_for_file(&f, &hash, &bodies).unwrap();
    assert_eq!(idx.load_all_ssa_bodies().unwrap().len(), 1);

    // Delete file, should also remove bodies
    idx.remove_file_and_related(&f).unwrap();
    assert_eq!(idx.load_all_ssa_bodies().unwrap().len(), 0);
}

// ── Persistence hardening tests ─────────────────────────────────────────────

/// Helper: build a minimal SsaFuncSummary for persistence tests.
#[cfg(test)]
fn make_test_ssa_summary() -> crate::summary::ssa_summary::SsaFuncSummary {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};
    SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
        source_to_callback: vec![],

        receiver_to_return: None,

        receiver_to_sink: Cap::empty(),

        abstract_transfer: vec![],
        param_return_paths: vec![],
        points_to: Default::default(),
        field_points_to: Default::default(),
        return_path_facts: smallvec::SmallVec::new(),
        typed_call_receivers: vec![],
        validated_params_to_return: smallvec::SmallVec::new(),
        param_to_gate_filters: vec![],
        entry_kind: None,
    }
}

/// Helper: insert a fake summary + SSA summary + file row for a project.
#[cfg(test)]
fn populate_project(
    pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    project: &str,
    dir: &std::path::Path,
) {
    let f = dir.join("app.py");
    std::fs::write(&f, "# code").unwrap();

    let mut idx = index::Indexer::from_pool(project, pool).unwrap();
    idx.upsert_file(&f).unwrap();

    let hash = index::Indexer::digest_bytes(b"# code");

    // Insert a FuncSummary
    let func_summary = crate::summary::FuncSummary {
        name: "do_stuff".to_string(),
        file_path: f.to_string_lossy().to_string(),
        param_count: 1,
        param_names: vec!["data".to_string()],
        lang: "python".to_string(),
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![0],
        propagates_taint: true,
        tainted_sink_params: vec![],
        callees: vec![],
        ..Default::default()
    };
    idx.replace_summaries_for_file(&f, &hash, &[func_summary])
        .unwrap();

    // Insert an SSA summary
    let ssa_sums = vec![(
        "do_stuff".to_string(),
        1_usize,
        "python".to_string(),
        "app.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash, &ssa_sums)
        .unwrap();

    // Insert an SSA body
    let bodies = vec![(
        "do_stuff".to_string(),
        1_usize,
        "python".to_string(),
        "app.py".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_callee_body(1, 1),
    )];
    idx.replace_ssa_bodies_for_file(&f, &hash, &bodies).unwrap();
}

// ── 1. Engine Version Tests ─────────────────────────────────────────────────

#[test]
fn version_match_no_reset() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // First init: creates DB and sets version
    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "proj", td.path());

    // Verify data exists
    assert_eq!(
        index::Indexer::count_rows(&pool, "function_summaries", "proj").unwrap(),
        1
    );
    assert_eq!(
        index::Indexer::count_rows(&pool, "ssa_function_summaries", "proj").unwrap(),
        1
    );
    assert_eq!(
        index::Indexer::count_rows(&pool, "ssa_function_bodies", "proj").unwrap(),
        1
    );

    // Second init with same version: data should be preserved
    drop(pool);
    let pool2 = index::Indexer::init(&db).unwrap();

    assert_eq!(
        index::Indexer::count_rows(&pool2, "function_summaries", "proj").unwrap(),
        1
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_summaries", "proj").unwrap(),
        1
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_bodies", "proj").unwrap(),
        1
    );

    let stored = index::Indexer::get_stored_engine_version(&pool2).unwrap();
    assert_eq!(stored.as_deref(), Some(index::ENGINE_VERSION));
}

#[test]
fn version_mismatch_triggers_reset() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // First init
    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "proj", td.path());

    // Simulate an old version
    index::Indexer::set_engine_version(&pool, "0.0.1-old").unwrap();

    // Verify data is populated
    assert_eq!(
        index::Indexer::count_rows(&pool, "function_summaries", "proj").unwrap(),
        1
    );

    // Reopen, version mismatch should trigger full wipe
    drop(pool);
    let pool2 = index::Indexer::init(&db).unwrap();

    assert_eq!(
        index::Indexer::count_rows(&pool2, "function_summaries", "proj").unwrap(),
        0
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_summaries", "proj").unwrap(),
        0
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_bodies", "proj").unwrap(),
        0
    );

    // files table should also be cleared (forces rescan)
    let idx = index::Indexer::from_pool("proj", &pool2).unwrap();
    assert!(idx.get_files("proj").unwrap().is_empty());

    // Version should now be updated
    let stored = index::Indexer::get_stored_engine_version(&pool2).unwrap();
    assert_eq!(stored.as_deref(), Some(index::ENGINE_VERSION));
}

#[test]
fn missing_version_triggers_reset() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // Init the DB
    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "proj", td.path());

    // Remove the metadata row to simulate a pre-version DB
    {
        let conn = pool.get().unwrap();
        conn.execute("DELETE FROM nyx_metadata WHERE key = 'engine_version'", [])
            .unwrap();
    }

    // Reopen
    drop(pool);
    let pool2 = index::Indexer::init(&db).unwrap();

    // All caches should be wiped
    assert_eq!(
        index::Indexer::count_rows(&pool2, "function_summaries", "proj").unwrap(),
        0
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_summaries", "proj").unwrap(),
        0
    );

    // Version should now be set
    let stored = index::Indexer::get_stored_engine_version(&pool2).unwrap();
    assert_eq!(stored.as_deref(), Some(index::ENGINE_VERSION));
}

#[test]
fn multiple_opens_no_repeated_resets() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // First open
    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "proj", td.path());
    drop(pool);

    // Second open, should preserve data
    let pool2 = index::Indexer::init(&db).unwrap();
    assert_eq!(
        index::Indexer::count_rows(&pool2, "function_summaries", "proj").unwrap(),
        1
    );

    // Re-populate after second open
    populate_project(&pool2, "proj2", td.path());
    drop(pool2);

    // Third open, should still preserve both projects
    let pool3 = index::Indexer::init(&db).unwrap();
    assert_eq!(
        index::Indexer::count_rows(&pool3, "function_summaries", "proj").unwrap(),
        1
    );
    assert_eq!(
        index::Indexer::count_rows(&pool3, "function_summaries", "proj2").unwrap(),
        1
    );
}

#[test]
fn write_engine_version_on_scan_completion() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    let pool = index::Indexer::init(&db).unwrap();

    // Simulate writing version after scan
    index::Indexer::write_engine_version(&pool).unwrap();

    let stored = index::Indexer::get_stored_engine_version(&pool).unwrap();
    assert_eq!(stored.as_deref(), Some(index::ENGINE_VERSION));
}

// ── 2. Migration Tests ──────────────────────────────────────────────────────

#[test]
fn fresh_db_no_migration_needed() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // Should not panic and tables should exist
    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();

    // Verify tables are accessible
    assert!(idx.load_all_summaries().unwrap().is_empty());
    assert!(idx.load_all_ssa_summaries().unwrap().is_empty());
    assert!(idx.load_all_ssa_bodies().unwrap().is_empty());
    assert!(idx.get_files("proj").unwrap().is_empty());
}

#[test]
fn init_applies_busy_timeout_to_every_pooled_connection() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let pool = index::Indexer::init(&db).unwrap();

    // Hold several connections at once so r2d2 must hand out distinct pooled
    // handles. The timeout is connection-local, so configuring only the schema
    // setup connection would leave later worker connections at rusqlite's
    // default.
    let conns: Vec<_> = (0..4).map(|_| pool.get().unwrap()).collect();
    for conn in &conns {
        let timeout_ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(timeout_ms, 60_000);
    }
}

#[test]
fn index_write_queue_serializes_parallel_writes() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let pool = index::Indexer::init(&db).unwrap();
    let project = "proj";
    let writer =
        index::IndexWriteQueue::start_with_capacity(project, std::sync::Arc::clone(&pool), 2);
    let tx = writer.sender();

    let mut handles = Vec::new();
    for i in 0..16 {
        let path = td.path().join(format!("file_{i}.rs"));
        let source = format!("fn f_{i}() {{}}\n");
        std::fs::write(&path, &source).unwrap();
        let hash = index::Indexer::digest_bytes(source.as_bytes());
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            tx.enqueue(move |idx| {
                let file_id = idx.upsert_file_with_hash(&path, &hash)?;
                let issue_rows = [(String::from("test-rule"), String::from("LOW"), 1_i64, 0_i64)];
                idx.replace_issues(
                    file_id,
                    issue_rows
                        .iter()
                        .map(|(rule_id, severity, line, col)| index::IssueRow {
                            rule_id: rule_id.as_str(),
                            severity: severity.as_str(),
                            line: *line,
                            col: *col,
                        }),
                )?;
                Ok(())
            })
            .unwrap();
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
    drop(tx);
    writer.finish("test").unwrap();

    let idx = index::Indexer::from_pool(project, &pool).unwrap();
    let files = idx.get_files(project).unwrap();
    assert_eq!(files.len(), 16);
    for path in files {
        assert_eq!(idx.get_issues_from_file(&path).unwrap().len(), 1);
    }
}

#[test]
fn missing_ssa_namespace_column_triggers_recreate() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // Create DB with an outdated SSA table (no namespace column)
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL, path TEXT NOT NULL,
                hash BLOB NOT NULL, mtime INTEGER NOT NULL,
                scanned_at INTEGER NOT NULL, UNIQUE(project, path)
            );
            CREATE TABLE IF NOT EXISTS function_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL, file_path TEXT NOT NULL,
                file_hash BLOB NOT NULL, name TEXT NOT NULL,
                arity INTEGER NOT NULL DEFAULT -1, lang TEXT NOT NULL,
                summary TEXT NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(project, file_path, name, arity)
            );
            CREATE TABLE IF NOT EXISTS ssa_function_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL, file_path TEXT NOT NULL,
                file_hash BLOB NOT NULL, name TEXT NOT NULL,
                arity INTEGER NOT NULL DEFAULT -1, lang TEXT NOT NULL,
                summary TEXT NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(project, file_path, name, arity)
            );",
        )
        .unwrap();
    }

    // Open via init, should detect missing namespace and recreate
    let pool = index::Indexer::init(&db).unwrap();

    // Verify the table now has the namespace column by inserting with it
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let f = td.path().join("test.py");
    std::fs::write(&f, "x").unwrap();
    let hash = index::Indexer::digest_bytes(b"x");
    let sums = vec![(
        "func".to_string(),
        1_usize,
        "python".to_string(),
        "ns".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    // This would fail if the namespace column doesn't exist
    idx.replace_ssa_summaries_for_file(&f, &hash, &sums)
        .unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 1);
}

/// Phase 10 migration test.  Build a database whose
/// `(ssa_)function_summaries` tables are at the post-Phase 09 shape
/// (namespace + container + disambig + kind columns present, but no
/// `entry_kind` column).  Insert a row directly so the migration must
/// preserve it.  After `init`, the column should exist on both tables
/// without dropping the pre-existing data.
#[test]
fn entry_kind_column_added_in_place_without_data_loss() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // Hand-build a pre-Phase-10 schema (no `entry_kind` column).
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL, path TEXT NOT NULL,
                hash BLOB NOT NULL, mtime INTEGER NOT NULL,
                scanned_at INTEGER NOT NULL, UNIQUE(project, path)
            );
            CREATE TABLE function_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL, file_path TEXT NOT NULL,
                file_hash BLOB NOT NULL, name TEXT NOT NULL,
                arity INTEGER NOT NULL DEFAULT -1, lang TEXT NOT NULL,
                container TEXT NOT NULL DEFAULT '',
                disambig INTEGER,
                kind TEXT NOT NULL DEFAULT 'fn',
                summary TEXT NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(project, file_path, name, container, arity, disambig, kind)
            );
            CREATE TABLE ssa_function_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL, file_path TEXT NOT NULL,
                file_hash BLOB NOT NULL, name TEXT NOT NULL,
                arity INTEGER NOT NULL DEFAULT -1, lang TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT '',
                container TEXT NOT NULL DEFAULT '',
                disambig INTEGER,
                kind TEXT NOT NULL DEFAULT 'fn',
                summary TEXT NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(project, file_path, name, container, arity, disambig, kind)
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO function_summaries
                (project, file_path, file_hash, name, arity, lang,
                 container, disambig, kind, summary, updated_at)
             VALUES ('proj', 'lib.py', X'00', 'old_func', 1, 'python',
                     '', NULL, 'fn', '{}', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ssa_function_summaries
                (project, file_path, file_hash, name, arity, lang,
                 namespace, container, disambig, kind, summary, updated_at)
             VALUES ('proj', 'lib.py', X'00', 'old_func', 1, 'python',
                     '', '', NULL, 'fn', '{}', 0)",
            [],
        )
        .unwrap();
        // Pre-populate the metadata so `check_schema_version` and
        // `check_engine_version` consider the database current and do
        // not wipe the rows we just inserted.  The point of this test
        // is the in-place `ALTER TABLE`; the version checks are a
        // separate concern.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS nyx_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES ('schema_version', ?1)",
            rusqlite::params![index::SCHEMA_VERSION],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO nyx_metadata (key, value) VALUES ('engine_version', ?1)",
            rusqlite::params![index::ENGINE_VERSION],
        )
        .unwrap();
    }

    // Open via init — should non-destructively ALTER both tables to
    // add `entry_kind`, leaving the seeded rows intact.
    let pool = index::Indexer::init(&db).unwrap();

    let conn = pool.get().unwrap();
    let cols_for = |table: &str| {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let v: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        v
    };
    assert!(
        cols_for("function_summaries")
            .iter()
            .any(|c| c == "entry_kind"),
        "function_summaries.entry_kind missing after migration"
    );
    assert!(
        cols_for("ssa_function_summaries")
            .iter()
            .any(|c| c == "entry_kind"),
        "ssa_function_summaries.entry_kind missing after migration"
    );

    // Pre-existing rows survive the migration.
    let func_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM function_summaries WHERE project = 'proj'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(func_rows, 1, "pre-existing function_summaries row was lost");
    let ssa_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ssa_function_summaries WHERE project = 'proj'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        ssa_rows, 1,
        "pre-existing ssa_function_summaries row was lost"
    );

    // Existing rows have NULL entry_kind by default.
    let entry_kind_value: Option<String> = conn
        .query_row(
            "SELECT entry_kind FROM function_summaries WHERE project = 'proj'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(entry_kind_value.is_none());
}

#[test]
fn valid_schema_no_recreate() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // First init, creates all tables
    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "proj", td.path());
    drop(pool);

    // Second init, schema is valid, should NOT drop/recreate
    let pool2 = index::Indexer::init(&db).unwrap();
    // Data survives because schema was already correct
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_summaries", "proj").unwrap(),
        1
    );
}

// ── 3. Deserialization Failure Tests ────────────────────────────────────────

#[test]
fn invalid_json_skipped_in_load_summaries() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let pool = index::Indexer::init(&db).unwrap();

    // Insert corrupted JSON directly
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO function_summaries (project, file_path, file_hash, name, arity, lang, summary, updated_at)
             VALUES ('proj', 'bad.py', X'00', 'bad', 1, 'python', '{not valid json!!!', 0)",
            [],
        ).unwrap();
    }

    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    // Should not panic; invalid row is skipped
    let loaded = idx.load_all_summaries().unwrap();
    assert_eq!(loaded.len(), 0);
}

#[test]
fn invalid_json_skipped_in_load_ssa_summaries() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let pool = index::Indexer::init(&db).unwrap();

    // Insert corrupted JSON directly
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO ssa_function_summaries (project, file_path, file_hash, name, arity, lang, namespace, summary, updated_at)
             VALUES ('proj', 'bad.py', X'00', 'bad', 1, 'python', '', 'CORRUPTED', 0)",
            [],
        ).unwrap();
    }

    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 0);
}

#[test]
fn invalid_json_skipped_in_load_ssa_bodies() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let pool = index::Indexer::init(&db).unwrap();

    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO ssa_function_bodies (project, file_path, file_hash, name, arity, lang, namespace, body, updated_at)
             VALUES ('proj', 'bad.py', X'00', 'bad', 1, 'python', '', '{{{{broken', 0)",
            [],
        ).unwrap();
    }

    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let loaded = idx.load_all_ssa_bodies().unwrap();
    assert_eq!(loaded.len(), 0);
}

#[test]
fn partial_failure_does_not_drop_valid_rows() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let pool = index::Indexer::init(&db).unwrap();

    // Insert one valid SSA summary via the normal API
    let f = td.path().join("good.py");
    std::fs::write(&f, "ok").unwrap();
    let hash = index::Indexer::digest_bytes(b"ok");
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let sums = vec![(
        "good_func".to_string(),
        1_usize,
        "python".to_string(),
        "".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash, &sums)
        .unwrap();

    // Insert a corrupted row directly
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO ssa_function_summaries (project, file_path, file_hash, name, arity, lang, namespace, summary, updated_at)
             VALUES ('proj', 'bad.py', X'00', 'bad_func', 1, 'python', '', 'NOT_JSON', 0)",
            [],
        ).unwrap();
    }

    // Load: should get exactly the 1 valid row
    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].1, "good_func");
}

// ── 4. Integration / Round-Trip Tests ───────────────────────────────────────

#[test]
fn scan_persist_reload_cycle() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "myproject", td.path());

    // Write version as scan completion would
    index::Indexer::write_engine_version(&pool).unwrap();

    // Reload from a fresh pool
    drop(pool);
    let pool2 = index::Indexer::init(&db).unwrap();

    let idx = index::Indexer::from_pool("myproject", &pool2).unwrap();
    assert_eq!(idx.load_all_summaries().unwrap().len(), 1);
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 1);
    assert_eq!(idx.load_all_ssa_bodies().unwrap().len(), 1);
    assert_eq!(idx.get_files("myproject").unwrap().len(), 1);
}

#[test]
fn version_bump_forces_reindex_behavior() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    // Simulate a previous engine version
    let pool = index::Indexer::init(&db).unwrap();
    populate_project(&pool, "proj", td.path());
    index::Indexer::set_engine_version(&pool, "0.1.0-alpha").unwrap();
    drop(pool);

    // Reopen: version bump should force full invalidation
    let pool2 = index::Indexer::init(&db).unwrap();

    // Everything should be wiped
    let idx = index::Indexer::from_pool("proj", &pool2).unwrap();
    assert!(idx.load_all_summaries().unwrap().is_empty());
    assert!(idx.load_all_ssa_summaries().unwrap().is_empty());
    assert!(idx.load_all_ssa_bodies().unwrap().is_empty());
    assert!(idx.get_files("proj").unwrap().is_empty());

    // After wiping, we can re-populate and it persists
    populate_project(&pool2, "proj", td.path());
    assert_eq!(idx.load_all_summaries().unwrap().len(), 1);
}

// ── 5. Edge Cases ───────────────────────────────────────────────────────────

#[test]
fn empty_db_file_works() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("empty.sqlite");

    // Create empty file
    std::fs::write(&db, "").unwrap();

    // init should handle this (SQLite will overwrite the empty file)
    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    assert!(idx.load_all_summaries().unwrap().is_empty());
}

#[test]
fn multiple_projects_isolated() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    let pool = index::Indexer::init(&db).unwrap();

    // Populate two different projects
    let f1 = td.path().join("proj1_file.py");
    let f2 = td.path().join("proj2_file.py");
    std::fs::write(&f1, "p1").unwrap();
    std::fs::write(&f2, "p2").unwrap();

    let mut idx1 = index::Indexer::from_pool("project_a", &pool).unwrap();
    idx1.upsert_file(&f1).unwrap();
    let hash1 = index::Indexer::digest_bytes(b"p1");
    let sums1 = vec![(
        "func_a".to_string(),
        0_usize,
        "python".to_string(),
        "".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    idx1.replace_ssa_summaries_for_file(&f1, &hash1, &sums1)
        .unwrap();

    let mut idx2 = index::Indexer::from_pool("project_b", &pool).unwrap();
    idx2.upsert_file(&f2).unwrap();
    let hash2 = index::Indexer::digest_bytes(b"p2");
    let sums2 = vec![(
        "func_b".to_string(),
        0_usize,
        "python".to_string(),
        "".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    idx2.replace_ssa_summaries_for_file(&f2, &hash2, &sums2)
        .unwrap();

    // Each project sees only its own summaries
    assert_eq!(idx1.load_all_ssa_summaries().unwrap().len(), 1);
    assert_eq!(idx1.load_all_ssa_summaries().unwrap()[0].1, "func_a");

    assert_eq!(idx2.load_all_ssa_summaries().unwrap().len(), 1);
    assert_eq!(idx2.load_all_ssa_summaries().unwrap()[0].1, "func_b");

    // Files are project-scoped too (get_files queries by its argument)
    assert_eq!(idx1.get_files("project_a").unwrap().len(), 1);
    assert_eq!(idx2.get_files("project_b").unwrap().len(), 1);
    // Cross-project: project_a should have no project_b files
    assert_eq!(idx1.get_files("nonexistent_project").unwrap().len(), 0);
}

#[test]
fn version_reset_wipes_all_projects() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    let pool = index::Indexer::init(&db).unwrap();

    // Populate two projects
    let f1 = td.path().join("a.py");
    let f2 = td.path().join("b.py");
    std::fs::write(&f1, "a").unwrap();
    std::fs::write(&f2, "b").unwrap();

    let mut idx1 = index::Indexer::from_pool("proj_x", &pool).unwrap();
    idx1.upsert_file(&f1).unwrap();
    let hash1 = index::Indexer::digest_bytes(b"a");
    let sums1 = vec![(
        "fx".to_string(),
        0_usize,
        "python".to_string(),
        "".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    idx1.replace_ssa_summaries_for_file(&f1, &hash1, &sums1)
        .unwrap();

    let mut idx2 = index::Indexer::from_pool("proj_y", &pool).unwrap();
    idx2.upsert_file(&f2).unwrap();
    let hash2 = index::Indexer::digest_bytes(b"b");
    let sums2 = vec![(
        "fy".to_string(),
        0_usize,
        "python".to_string(),
        "".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        make_test_ssa_summary(),
    )];
    idx2.replace_ssa_summaries_for_file(&f2, &hash2, &sums2)
        .unwrap();

    // Simulate version mismatch
    index::Indexer::set_engine_version(&pool, "0.0.0-stale").unwrap();
    drop(pool);

    let pool2 = index::Indexer::init(&db).unwrap();

    // Both projects' data should be gone (version check is global, not per-project)
    assert_eq!(
        index::Indexer::count_rows(&pool2, "function_summaries", "proj_x").unwrap(),
        0
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_summaries", "proj_x").unwrap(),
        0
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "function_summaries", "proj_y").unwrap(),
        0
    );
    assert_eq!(
        index::Indexer::count_rows(&pool2, "ssa_function_summaries", "proj_y").unwrap(),
        0
    );
}

#[test]
fn metadata_table_survives_clear() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");

    let pool = index::Indexer::init(&db).unwrap();
    index::Indexer::write_engine_version(&pool).unwrap();

    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    idx.clear().unwrap();

    // Metadata should survive clear (clear only drops analysis tables)
    let stored = index::Indexer::get_stored_engine_version(&pool).unwrap();
    assert_eq!(stored.as_deref(), Some(index::ENGINE_VERSION));
}

/// field_points_to round-trips through
/// the SsaFuncSummary SQLite blob.  Pin that the new field_points_to
/// records preserve param_field_reads, param_field_writes, the
/// receiver sentinel (`u32::MAX`), the container-element marker
/// (`<elem>`), and the `overflow` flag across serialise → store →
/// load → deserialise.  This is the strict-additive contract for
/// older blobs without field_points_to (default-empty deserialises cleanly) and the
/// completeness check for the W3 cross-call resolver.
#[test]
fn ssa_summaries_round_trip_preserves_field_points_to() {
    use crate::summary::points_to::FieldPointsToSummary;
    use crate::summary::ssa_summary::SsaFuncSummary;

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("store.rs");
    std::fs::write(&f, "// helper that writes obj.cache").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"// helper that writes obj.cache");

    // Build a summary with one read on param 0 ("name"), one write on
    // param 1 ("cache"), one read on the receiver sentinel ("kind"),
    // and an ELEM marker on param 0.  Round-trip must preserve all
    // four channels.
    let mut fpt = FieldPointsToSummary::empty();
    fpt.add_read(0, "name");
    fpt.add_write(1, "cache");
    fpt.add_read(u32::MAX, "kind");
    fpt.add_write(0, "<elem>");

    let summary = SsaFuncSummary {
        field_points_to: fpt.clone(),
        ..Default::default()
    };
    let row = (
        "store".to_string(),
        2_usize,
        "rust".to_string(),
        "store.rs".to_string(),
        String::new(),
        None,
        crate::symbol::FuncKind::Function,
        summary,
    );
    idx.replace_ssa_summaries_for_file(&f, &hash, &[row])
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 1, "single summary stored, single returned");
    let (_, name, _, _, _, _, _, _, sum) = &loaded[0];
    assert_eq!(name, "store");
    assert_eq!(
        sum.field_points_to, fpt,
        "field_points_to must round-trip byte-equal",
    );

    // Spot-check sentinel + ELEM marker channels.
    let recv_read = sum
        .field_points_to
        .param_field_reads
        .iter()
        .find(|(p, _)| *p == u32::MAX)
        .expect("receiver read at u32::MAX sentinel");
    assert!(recv_read.1.iter().any(|s| s == "kind"));

    let elem_write = sum
        .field_points_to
        .param_field_writes
        .iter()
        .find(|(p, _)| *p == 0)
        .expect("param 0 writes recorded");
    assert!(
        elem_write.1.iter().any(|s| s == "<elem>"),
        "<elem> marker must survive round-trip without conversion",
    );
    assert!(!sum.field_points_to.overflow);
}

/// Older blob compatibility: a summary serialised without
/// `field_points_to` deserialises with the empty default, no
/// migration needed because the field is `#[serde(default)]`.
#[test]
fn ssa_summaries_legacy_blob_decodes_with_empty_field_points_to() {
    use crate::summary::ssa_summary::SsaFuncSummary;

    // Hand-craft JSON without the `field_points_to` key.
    let legacy_json = r#"{
        "param_to_return": [],
        "param_to_sink": [],
        "source_caps": 0,
        "param_to_sink_param": [],
        "param_container_to_return": [],
        "param_to_container_store": [],
        "return_type": null,
        "return_abstract": null,
        "source_to_callback": [],
        "receiver_to_return": null,
        "receiver_to_sink": 0,
        "abstract_transfer": [],
        "param_return_paths": [],
        "return_path_facts": [],
        "typed_call_receivers": []
    }"#;
    let sum: SsaFuncSummary = serde_json::from_str(legacy_json).unwrap();
    assert!(
        sum.field_points_to.is_empty(),
        "missing field_points_to must default to empty",
    );
}

/// Pre-`param_to_gate_filters` blob compatibility: a summary serialised
/// before this field existed deserialises with the empty default.
/// `#[serde(default)]` on the field means old SQLite blobs round-trip
/// without a schema migration, the new field is stored inside the JSON
/// `summary` column so SQL-level columns are unchanged.
#[test]
fn ssa_summaries_pre_gate_filters_blob_decodes_with_empty_param_to_gate_filters() {
    use crate::summary::ssa_summary::SsaFuncSummary;

    // Hand-craft JSON without the `param_to_gate_filters` key.
    let pre_gate_filters_json = r#"{
        "param_to_return": [],
        "param_to_sink": [],
        "source_caps": 0,
        "param_to_sink_param": [],
        "param_container_to_return": [],
        "param_to_container_store": [],
        "return_type": null,
        "return_abstract": null,
        "source_to_callback": [],
        "receiver_to_return": null,
        "receiver_to_sink": 0,
        "abstract_transfer": [],
        "param_return_paths": [],
        "return_path_facts": [],
        "typed_call_receivers": []
    }"#;
    let sum: SsaFuncSummary = serde_json::from_str(pre_gate_filters_json).unwrap();
    assert!(
        sum.param_to_gate_filters.is_empty(),
        "missing param_to_gate_filters must default to empty",
    );
}

/// Round-trip: a summary with a populated `param_to_gate_filters`
/// survives JSON serialise + deserialise, including the per-position
/// cap-mask values needed to preserve SSRF-vs-DATA_EXFIL splits across
/// the function-summary boundary.
#[test]
fn ssa_summaries_param_to_gate_filters_round_trip() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::SsaFuncSummary;

    let mut sum = SsaFuncSummary::default();
    sum.param_to_gate_filters.push((0, Cap::SSRF));
    sum.param_to_gate_filters.push((1, Cap::DATA_EXFIL));

    let json = serde_json::to_string(&sum).expect("serialize");
    let restored: SsaFuncSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        restored.param_to_gate_filters,
        vec![(0, Cap::SSRF), (1, Cap::DATA_EXFIL)],
        "per-position cap masks must round-trip exactly",
    );
}

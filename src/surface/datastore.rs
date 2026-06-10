//! Data-store detection.
//!
//! Walks the post-pass-2 [`GlobalSummaries`] looking for callees whose
//! name is a known database / cache / blob-store driver entry point,
//! and emits one [`SurfaceNode::DataStore`] per resolved store.
//!
//! The detector is name-based on purpose: the receiver's full type is
//! often unknown after pass 2, but the leaf name of a driver call
//! (`psycopg2.connect`, `mysql.createConnection`, `gorm.Open`,
//! `Eloquent::find`, `ActiveRecord::Base.connection`) carries enough
//! signal for surface-level chain composition.  False positives here
//! are forgiving — the surface map is informational, not a finding
//! that fires on its own.

use super::{AccessMode, DataStore, DataStoreKind, SourceLocation, SurfaceNode, namespace_file};
use crate::labels::Cap;
use crate::summary::GlobalSummaries;

/// One detection rule: leaf-name pattern → store kind + label.  Stored
/// as a flat list so adding a new ORM / driver is a one-line edit.
struct DriverRule {
    /// Substring to match against the callee's leaf name (case-insensitive).
    leaf: &'static str,
    kind: DataStoreKind,
    /// Human-readable label attached to the emitted node.  Used by the
    /// chain composer and the `nyx surface` CLI tree.
    label: &'static str,
}

const DRIVER_RULES: &[DriverRule] = &[
    // Python — relational
    DriverRule {
        leaf: "psycopg2.connect",
        kind: DataStoreKind::Sql,
        label: "PostgreSQL (psycopg2)",
    },
    DriverRule {
        leaf: "psycopg.connect",
        kind: DataStoreKind::Sql,
        label: "PostgreSQL (psycopg3)",
    },
    DriverRule {
        leaf: "mysql.connector.connect",
        kind: DataStoreKind::Sql,
        label: "MySQL (mysql.connector)",
    },
    DriverRule {
        leaf: "MySQLdb.connect",
        kind: DataStoreKind::Sql,
        label: "MySQL (MySQLdb)",
    },
    DriverRule {
        leaf: "pymysql.connect",
        kind: DataStoreKind::Sql,
        label: "MySQL (PyMySQL)",
    },
    DriverRule {
        leaf: "sqlite3.connect",
        kind: DataStoreKind::Sql,
        label: "SQLite (sqlite3)",
    },
    DriverRule {
        leaf: "sqlalchemy.create_engine",
        kind: DataStoreKind::Sql,
        label: "SQLAlchemy",
    },
    DriverRule {
        leaf: "django.db.connection",
        kind: DataStoreKind::Sql,
        label: "Django ORM",
    },
    // Python — kv / doc
    DriverRule {
        leaf: "redis.Redis",
        kind: DataStoreKind::KeyValue,
        label: "Redis",
    },
    DriverRule {
        leaf: "redis.from_url",
        kind: DataStoreKind::KeyValue,
        label: "Redis",
    },
    DriverRule {
        leaf: "pymongo.MongoClient",
        kind: DataStoreKind::Document,
        label: "MongoDB",
    },
    DriverRule {
        leaf: "boto3.client",
        kind: DataStoreKind::BlobStore,
        label: "AWS (boto3)",
    },
    DriverRule {
        leaf: "boto3.resource",
        kind: DataStoreKind::BlobStore,
        label: "AWS (boto3)",
    },
    // JavaScript / TypeScript — relational
    DriverRule {
        leaf: "knex",
        kind: DataStoreKind::Sql,
        label: "Knex.js",
    },
    DriverRule {
        leaf: "createConnection",
        kind: DataStoreKind::Sql,
        label: "MySQL/Postgres (mysql/pg)",
    },
    DriverRule {
        leaf: "Sequelize",
        kind: DataStoreKind::Sql,
        label: "Sequelize",
    },
    DriverRule {
        leaf: "TypeORM.createConnection",
        kind: DataStoreKind::Sql,
        label: "TypeORM",
    },
    DriverRule {
        leaf: "PrismaClient",
        kind: DataStoreKind::Sql,
        label: "Prisma",
    },
    DriverRule {
        leaf: "pool.query",
        kind: DataStoreKind::Sql,
        label: "pg/mysql pool",
    },
    DriverRule {
        leaf: "client.query",
        kind: DataStoreKind::Sql,
        label: "pg client",
    },
    DriverRule {
        leaf: "db.query",
        kind: DataStoreKind::Sql,
        label: "Generic SQL driver",
    },
    // JS — kv / doc
    DriverRule {
        leaf: "redis.createClient",
        kind: DataStoreKind::KeyValue,
        label: "Redis (node-redis)",
    },
    DriverRule {
        leaf: "ioredis",
        kind: DataStoreKind::KeyValue,
        label: "ioredis",
    },
    DriverRule {
        leaf: "MongoClient.connect",
        kind: DataStoreKind::Document,
        label: "MongoDB (node)",
    },
    DriverRule {
        leaf: "AWS.S3",
        kind: DataStoreKind::BlobStore,
        label: "AWS S3",
    },
    // Java — JDBC / Hibernate
    DriverRule {
        leaf: "DriverManager.getConnection",
        kind: DataStoreKind::Sql,
        label: "JDBC",
    },
    DriverRule {
        leaf: "JdbcTemplate",
        kind: DataStoreKind::Sql,
        label: "Spring JdbcTemplate",
    },
    DriverRule {
        leaf: "EntityManager",
        kind: DataStoreKind::Sql,
        label: "JPA EntityManager",
    },
    DriverRule {
        leaf: "SessionFactory.openSession",
        kind: DataStoreKind::Sql,
        label: "Hibernate",
    },
    DriverRule {
        leaf: "Jedis",
        kind: DataStoreKind::KeyValue,
        label: "Jedis (Redis)",
    },
    DriverRule {
        leaf: "MongoClients.create",
        kind: DataStoreKind::Document,
        label: "MongoDB (java-driver)",
    },
    // Go — sql + ORM
    DriverRule {
        leaf: "sql.Open",
        kind: DataStoreKind::Sql,
        label: "database/sql",
    },
    DriverRule {
        leaf: "gorm.Open",
        kind: DataStoreKind::Sql,
        label: "GORM",
    },
    DriverRule {
        leaf: "sqlx.Connect",
        kind: DataStoreKind::Sql,
        label: "sqlx",
    },
    DriverRule {
        leaf: "sqlx.Open",
        kind: DataStoreKind::Sql,
        label: "sqlx",
    },
    DriverRule {
        leaf: "redis.NewClient",
        kind: DataStoreKind::KeyValue,
        label: "go-redis",
    },
    DriverRule {
        leaf: "mongo.Connect",
        kind: DataStoreKind::Document,
        label: "MongoDB (go-driver)",
    },
    // PHP — Eloquent / PDO
    DriverRule {
        leaf: "PDO",
        kind: DataStoreKind::Sql,
        label: "PDO",
    },
    DriverRule {
        leaf: "Eloquent::find",
        kind: DataStoreKind::Sql,
        label: "Laravel Eloquent",
    },
    DriverRule {
        leaf: "Eloquent::where",
        kind: DataStoreKind::Sql,
        label: "Laravel Eloquent",
    },
    DriverRule {
        leaf: "DB::connection",
        kind: DataStoreKind::Sql,
        label: "Laravel DB",
    },
    DriverRule {
        leaf: "Doctrine",
        kind: DataStoreKind::Sql,
        label: "Doctrine ORM",
    },
    // Ruby — ActiveRecord
    DriverRule {
        leaf: "ActiveRecord::Base.connection",
        kind: DataStoreKind::Sql,
        label: "ActiveRecord",
    },
    DriverRule {
        leaf: "ActiveRecord::Base.find",
        kind: DataStoreKind::Sql,
        label: "ActiveRecord",
    },
    DriverRule {
        leaf: ".find_by_sql",
        kind: DataStoreKind::Sql,
        label: "ActiveRecord raw SQL",
    },
    // Rust — sqlx / diesel
    DriverRule {
        leaf: "sqlx::query",
        kind: DataStoreKind::Sql,
        label: "sqlx",
    },
    DriverRule {
        leaf: "sqlx::query_as",
        kind: DataStoreKind::Sql,
        label: "sqlx",
    },
    DriverRule {
        leaf: "diesel::sql_query",
        kind: DataStoreKind::Sql,
        label: "Diesel",
    },
    DriverRule {
        leaf: "PgConnection::establish",
        kind: DataStoreKind::Sql,
        label: "Diesel",
    },
    // Type-qualified — fires when the SSA type-fact engine resolves a
    // receiver to `TypeKind::DatabaseConnection` regardless of the bare
    // callee name (e.g. `conn = psycopg2.connect(); conn.cursor()` →
    // typed_call_receivers maps the `.cursor` ordinal to "DatabaseConnection").
    DriverRule {
        leaf: "DatabaseConnection.cursor",
        kind: DataStoreKind::Sql,
        label: "Database connection",
    },
    DriverRule {
        leaf: "DatabaseConnection.execute",
        kind: DataStoreKind::Sql,
        label: "Database connection",
    },
    DriverRule {
        leaf: "DatabaseConnection.query",
        kind: DataStoreKind::Sql,
        label: "Database connection",
    },
    DriverRule {
        leaf: "DatabaseConnection.exec",
        kind: DataStoreKind::Sql,
        label: "Database connection",
    },
    DriverRule {
        leaf: "DatabaseConnection.prepare",
        kind: DataStoreKind::Sql,
        label: "Database connection",
    },
    DriverRule {
        leaf: "DatabaseConnection.commit",
        kind: DataStoreKind::Sql,
        label: "Database connection",
    },
    DriverRule {
        leaf: "FileHandle.read",
        kind: DataStoreKind::Filesystem,
        label: "Filesystem",
    },
    DriverRule {
        leaf: "FileHandle.write",
        kind: DataStoreKind::Filesystem,
        label: "Filesystem",
    },
    DriverRule {
        leaf: "FileHandle.close",
        kind: DataStoreKind::Filesystem,
        label: "Filesystem",
    },
    // Filesystem (best-effort: language-agnostic open()-family)
    DriverRule {
        leaf: "open",
        kind: DataStoreKind::Filesystem,
        label: "Filesystem",
    },
];

/// Walk every function summary's callee list and emit one
/// [`SurfaceNode::DataStore`] per matched driver call.  De-duped on
/// `(file, line, label)`.
///
/// When the bare callee name does not hit a rule, the type-fact engine's
/// per-call `typed_call_receivers` map (read off the matching
/// [`crate::summary::ssa_summary::SsaFuncSummary`]) is consulted: a callee whose
/// receiver was resolved to `TypeKind::DatabaseConnection` or
/// `TypeKind::FileHandle` is retried under the type-qualified name
/// `"DatabaseConnection.<method>"` / `"FileHandle.<method>"`, picking up
/// the bound-receiver call shapes (`conn.cursor()` after
/// `conn = psycopg2.connect()`) that the name-only matcher misses.
pub fn detect_data_stores(summaries: &GlobalSummaries) -> Vec<SurfaceNode> {
    let mut out: Vec<SurfaceNode> = Vec::new();
    let mut seen: std::collections::HashSet<(String, u32, String)> =
        std::collections::HashSet::new();
    for (key, summary) in summaries.iter() {
        // Project-relative POSIX file, keyed off the FuncKey namespace so a
        // data-store node and the entry-point that reaches it agree on file
        // identity (FuncSummary.file_path is an absolute path).
        let file = namespace_file(&key.namespace).to_string();
        let owner = key.qualified_name();
        let typed = summaries
            .get_ssa(key)
            .map(|s| s.typed_call_receivers.as_slice());
        let mut matched_for_fn = false;
        for callee in &summary.callees {
            let rule = match_rule(&callee.name).or_else(|| {
                typed
                    .and_then(|t| container_for_ordinal(t, callee.ordinal))
                    .and_then(|c| match_rule(&qualify(c, &callee.name)))
            });
            let Some(rule) = rule else { continue };
            matched_for_fn = true;
            let location = call_site_location(&file, callee.span);
            let dedup = (location.file.clone(), location.line, rule.label.to_string());
            if !seen.insert(dedup) {
                continue;
            }
            out.push(SurfaceNode::DataStore(DataStore {
                location,
                kind: rule.kind,
                label: rule.label.to_string(),
                owner: owner.clone(),
                access: classify_access(leaf_segment(&callee.name)),
            }));
        }

        // Cap-driven fallback: a function whose own `sink_caps` include
        // SQL_QUERY / FILE_IO is a data-store access site even when no
        // direct callee matched the driver table (custom DAO wrapper,
        // cross-file-resolved execute).  Mirrors external.rs's SSRF
        // fallback.  Skipped when a named driver already fired so the
        // precise label wins.
        if !matched_for_fn {
            let caps = summary.sink_caps();
            let fallback = if caps.contains(Cap::SQL_QUERY) {
                Some((DataStoreKind::Sql, "SQL query"))
            } else if caps.contains(Cap::FILE_IO) {
                Some((DataStoreKind::Filesystem, "File access"))
            } else {
                None
            };
            if let Some((kind, label)) = fallback {
                let dedup = (file.clone(), 0, label.to_string());
                if seen.insert(dedup) {
                    out.push(SurfaceNode::DataStore(DataStore {
                        location: call_site_location(&file, None),
                        kind,
                        label: label.to_string(),
                        owner: owner.clone(),
                        // Cap bits carry no operation direction; a raw
                        // SQL_QUERY / FILE_IO sink can be either.
                        access: AccessMode::ReadWrite,
                    }));
                }
            }
        }
    }
    out
}

/// Classify the operation direction of a data-store access from the
/// callee's leaf name.  Whole-prefix match on a lowercase verb table —
/// `findOne` / `find_by_id` / `findAll` all classify as reads via the
/// `find` prefix.  Connect-/client-construction sites and unrecognised
/// verbs stay [`AccessMode::Unknown`] so reachability keeps emitting
/// the conservative `ReadsFrom` edge for them.
fn classify_access(leaf: &str) -> AccessMode {
    const READ: &[&str] = &[
        "find",
        "get",
        "query",
        "select",
        "read",
        "fetch",
        "scan",
        "count",
        "exists",
        "aggregate",
        "lrange",
        "smembers",
        "hget",
        "mget",
        "keys",
        "first",
        "pluck",
        "all",
    ];
    const WRITE: &[&str] = &[
        "insert", "update", "delete", "save", "create", "set", "put", "write", "remove", "drop",
        "truncate", "upsert", "persist", "destroy", "del", "hset", "lpush", "rpush", "sadd",
        "zadd", "append", "rename", "unlink", "mkdir", "rmdir", "incr", "decr", "expire",
    ];
    const READ_WRITE: &[&str] = &[
        "execute",
        "executemany",
        "executescript",
        "exec",
        "run",
        "batch",
        "transaction",
        "pipeline",
    ];
    let l = leaf.trim();
    // Verb-prefix match with a word boundary: the verb must be the whole
    // leaf, or be followed by `_` (snake_case), an uppercase letter
    // (camelCase), or a digit.  `findOne` / `find_by_id` → read;
    // `settings` does NOT match `set`.
    let has_prefix = |verbs: &[&str]| {
        verbs.iter().any(|v| {
            l.get(..v.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(v))
                && l.get(v.len()..)
                    .is_some_and(|rest| match rest.chars().next() {
                        None => true,
                        Some(c) => c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit(),
                    })
        })
    };
    // Order matters: WRITE before READ so `setex`-style verbs with a
    // read-looking suffix do not misclassify; READ_WRITE checked first
    // because `execute` would otherwise never match.
    if has_prefix(READ_WRITE) {
        AccessMode::ReadWrite
    } else if has_prefix(WRITE) {
        AccessMode::Write
    } else if has_prefix(READ) {
        AccessMode::Read
    } else {
        AccessMode::Unknown
    }
}

/// Last segment of a callee text after the final `.` or `::`.
fn leaf_segment(name: &str) -> &str {
    let after_colon = name.rsplit("::").next().unwrap_or(name);
    after_colon.rsplit('.').next().unwrap_or(after_colon)
}

/// Build a type-qualified callee name (`"{container}.{method}"`) for
/// retry-matching when the bare callee text did not hit any rule.
fn qualify(container: &str, callee_name: &str) -> String {
    format!("{}.{}", container, leaf_segment(callee_name))
}

/// Linear-scan helper since `typed_call_receivers` is a small
/// `Vec<(ordinal, container)>` per function. Typical lengths are 0 to a
/// few dozen; a HashMap-per-summary would be wasteful.
fn container_for_ordinal(typed: &[(u32, String)], ordinal: u32) -> Option<&str> {
    typed
        .iter()
        .find(|(o, _)| *o == ordinal)
        .map(|(_, c)| c.as_str())
}

fn match_rule(callee: &str) -> Option<&'static DriverRule> {
    let cl = callee.trim().to_ascii_lowercase();
    // Normalize `::` → `.` so segment-split treats both as separators.
    let cl_segments = cl.replace("::", ".");
    DRIVER_RULES.iter().find(|r| {
        let rl = r.leaf.to_ascii_lowercase();
        if r.leaf.contains('.') || r.leaf.contains("::") {
            // Qualified pattern (e.g. `psycopg2.connect`, `Eloquent::find`):
            // substring on the full callee text.  Qualified shapes are
            // unambiguous so substring is precise enough.
            cl.contains(&rl)
        } else {
            // Bare leaf (e.g. `open`, `fetch`, `PrismaClient`): require a
            // whole-segment match.  Prevents `fopen` / `OpenSearch` /
            // `getPrismaClient` from FP-matching short bare leaves.
            cl_segments.split('.').any(|seg| seg == rl)
        }
    })
}

/// Source location of a call site in the project-relative `file`.  Reads
/// the 1-based `(line, col)` recorded on the [`CalleeSite`] at CFG-build
/// time when `span` is `Some`; for legacy summaries loaded from SQLite
/// with no span (and the cap-driven fallback path) falls back to line 0.
fn call_site_location(file: &str, span: Option<(u32, u32)>) -> SourceLocation {
    let (line, col) = span.unwrap_or((0, 0));
    SourceLocation {
        file: file.to_string(),
        line,
        col,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::{CalleeSite, FuncSummary};
    use crate::symbol::{FuncKey, Lang};

    fn summary_with_callees(name: &str, file: &str, callees: &[&str]) -> (FuncKey, FuncSummary) {
        let key = FuncKey::new_function(Lang::Python, file, name, None);
        let summary = FuncSummary {
            name: name.to_string(),
            file_path: file.to_string(),
            lang: "python".to_string(),
            param_count: 0,
            callees: callees
                .iter()
                .map(|c| CalleeSite::bare(c.to_string()))
                .collect(),
            ..Default::default()
        };
        (key, summary)
    }

    #[test]
    fn classify_access_verb_boundaries() {
        assert_eq!(classify_access("findOne"), AccessMode::Read);
        assert_eq!(classify_access("find_by_id"), AccessMode::Read);
        assert_eq!(classify_access("get"), AccessMode::Read);
        assert_eq!(classify_access("insertMany"), AccessMode::Write);
        assert_eq!(classify_access("save"), AccessMode::Write);
        assert_eq!(classify_access("deleteOne"), AccessMode::Write);
        assert_eq!(classify_access("execute"), AccessMode::ReadWrite);
        assert_eq!(classify_access("executemany"), AccessMode::ReadWrite);
        assert_eq!(classify_access("Exec"), AccessMode::ReadWrite);
        // Boundary safety: a lowercase continuation is NOT a verb match.
        assert_eq!(classify_access("settings"), AccessMode::Unknown);
        assert_eq!(classify_access("allocate"), AccessMode::Unknown);
        assert_eq!(classify_access("connect"), AccessMode::Unknown);
    }

    #[test]
    fn detected_store_carries_access_mode() {
        // `connect`-style driver match → Unknown access; the node still
        // surfaces and reachability treats it as a conservative read.
        let mut gs = GlobalSummaries::new();
        let (key, summary) = summary_with_callees("init", "db.py", &["psycopg2.connect"]);
        gs.insert(key, summary);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.access, AccessMode::Unknown);

        // `pool.query` driver match → leaf `query` classifies as Read.
        let mut gs = GlobalSummaries::new();
        let (key, summary) = summary_with_callees("run", "db.js", &["pool.query"]);
        gs.insert(key, summary);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.access, AccessMode::Read);
    }

    #[test]
    fn datastore_carries_callee_span_when_present() {
        // When the CFG populates `CalleeSite.span`, the detected datastore
        // node's `SourceLocation` must reflect that 1-based `(line, col)`
        // — not the legacy `(0, 0)` fallback.
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "app.py", "init", None);
        let mut callee = CalleeSite::bare("psycopg2.connect");
        callee.span = Some((42, 13));
        let summary = FuncSummary {
            name: "init".into(),
            file_path: "app.py".into(),
            lang: "python".into(),
            param_count: 0,
            callees: vec![callee],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.location.line, 42);
        assert_eq!(ds.location.col, 13);
    }

    #[test]
    fn cap_fallback_emits_sql_store_with_owner() {
        // A custom DAO wrapper: no callee matches DRIVER_RULES, but the
        // function's own sink_caps carry SQL_QUERY.  The cap-driven fallback
        // surfaces a generic Sql node carrying the owning function name.
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "dao.py", "run_query", None);
        let summary = FuncSummary {
            name: "run_query".into(),
            file_path: "dao.py".into(),
            lang: "python".into(),
            sink_caps: Cap::SQL_QUERY.bits(),
            callees: vec![CalleeSite::bare("self._exec")],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1, "got {nodes:?}");
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.kind, DataStoreKind::Sql);
        assert_eq!(ds.label, "SQL query");
        assert_eq!(ds.owner, "run_query");
        assert_eq!(ds.location.file, "dao.py");
    }

    #[test]
    fn named_driver_suppresses_cap_fallback() {
        // When a named driver call already fired, the precise label wins and
        // the generic cap fallback does not double-emit.
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "dao.py", "init", None);
        let summary = FuncSummary {
            name: "init".into(),
            file_path: "dao.py".into(),
            lang: "python".into(),
            sink_caps: Cap::SQL_QUERY.bits(),
            callees: vec![CalleeSite::bare("psycopg2.connect")],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.label, "PostgreSQL (psycopg2)");
    }

    #[test]
    fn detects_psycopg2_connect() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_callees("init", "app.py", &["psycopg2.connect"]);
        gs.insert(k, s);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.kind, DataStoreKind::Sql);
        assert_eq!(ds.label, "PostgreSQL (psycopg2)");
    }

    #[test]
    fn detects_gorm_open() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_callees("init", "main.go", &["gorm.Open"]);
        gs.insert(k, s);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.label, "GORM");
    }

    #[test]
    fn dedup_collapses_repeats_in_same_file() {
        let mut gs = GlobalSummaries::new();
        let (k, s) =
            summary_with_callees("init", "app.py", &["psycopg2.connect", "psycopg2.connect"]);
        gs.insert(k, s);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn bare_open_rule_does_not_match_fopen_or_opensearch() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_callees(
            "init",
            "app.py",
            &[
                "fopen",
                "popen",
                "OpenSearch",
                "openssl_encrypt",
                "MongoClient.openSession",
            ],
        );
        gs.insert(k, s);
        let nodes = detect_data_stores(&gs);
        assert!(
            nodes.is_empty(),
            "bare `open` rule should not FP on {nodes:?}",
        );
    }

    #[test]
    fn bare_open_rule_still_matches_real_open() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_callees("loader", "app.py", &["open"]);
        gs.insert(k, s);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.kind, DataStoreKind::Filesystem);

        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_callees("loader", "app.py", &["builtins.open"]);
        gs.insert(k, s);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn typed_receiver_database_connection_resolves_bound_cursor() {
        // `conn = psycopg2.connect(); conn.cursor()` — the bare callee
        // `conn.cursor` is not in DRIVER_RULES, but the SSA type-fact
        // engine populates `typed_call_receivers` with
        // `(ordinal, "DatabaseConnection")` for the `.cursor` ordinal.
        // The detector retries under `DatabaseConnection.cursor` and
        // emits a Sql datastore node.
        use crate::summary::ssa_summary::SsaFuncSummary;
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "app.py", "load", None);
        let summary = FuncSummary {
            name: "load".into(),
            file_path: "app.py".into(),
            lang: "python".into(),
            param_count: 0,
            callees: vec![{
                let mut c = CalleeSite::bare("conn.cursor");
                c.ordinal = 7;
                c.span = Some((4, 8));
                c
            }],
            ..Default::default()
        };
        gs.insert(key.clone(), summary);
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((7, "DatabaseConnection".into()));
        gs.insert_ssa(key, ssa);
        let nodes = detect_data_stores(&gs);
        assert_eq!(nodes.len(), 1, "expected typed retry to hit; got {nodes:?}");
        let SurfaceNode::DataStore(ds) = &nodes[0] else {
            panic!()
        };
        assert_eq!(ds.kind, DataStoreKind::Sql);
        assert_eq!(ds.label, "Database connection");
        assert_eq!(ds.location.line, 4);
    }

    #[test]
    fn typed_receiver_without_ssa_summary_falls_through() {
        // No SsaFuncSummary inserted → bare `client.cursor` does not match
        // any rule and `typed_call_receivers` is unreachable. Detector
        // emits zero nodes (no panic on missing SSA side).
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_callees("load", "app.py", &["client.cursor"]);
        gs.insert(k, s);
        assert!(detect_data_stores(&gs).is_empty());
    }
}

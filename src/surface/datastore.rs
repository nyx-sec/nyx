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

use super::{DataStore, DataStoreKind, SourceLocation, SurfaceNode};
use crate::summary::{FuncSummary, GlobalSummaries};

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
    DriverRule { leaf: "psycopg2.connect", kind: DataStoreKind::Sql, label: "PostgreSQL (psycopg2)" },
    DriverRule { leaf: "psycopg.connect",  kind: DataStoreKind::Sql, label: "PostgreSQL (psycopg3)" },
    DriverRule { leaf: "mysql.connector.connect", kind: DataStoreKind::Sql, label: "MySQL (mysql.connector)" },
    DriverRule { leaf: "MySQLdb.connect",  kind: DataStoreKind::Sql, label: "MySQL (MySQLdb)" },
    DriverRule { leaf: "pymysql.connect",  kind: DataStoreKind::Sql, label: "MySQL (PyMySQL)" },
    DriverRule { leaf: "sqlite3.connect",  kind: DataStoreKind::Sql, label: "SQLite (sqlite3)" },
    DriverRule { leaf: "sqlalchemy.create_engine", kind: DataStoreKind::Sql, label: "SQLAlchemy" },
    DriverRule { leaf: "django.db.connection", kind: DataStoreKind::Sql, label: "Django ORM" },
    // Python — kv / doc
    DriverRule { leaf: "redis.Redis",      kind: DataStoreKind::KeyValue, label: "Redis" },
    DriverRule { leaf: "redis.from_url",   kind: DataStoreKind::KeyValue, label: "Redis" },
    DriverRule { leaf: "pymongo.MongoClient", kind: DataStoreKind::Document, label: "MongoDB" },
    DriverRule { leaf: "boto3.client",     kind: DataStoreKind::BlobStore, label: "AWS (boto3)" },
    DriverRule { leaf: "boto3.resource",   kind: DataStoreKind::BlobStore, label: "AWS (boto3)" },

    // JavaScript / TypeScript — relational
    DriverRule { leaf: "knex",             kind: DataStoreKind::Sql, label: "Knex.js" },
    DriverRule { leaf: "createConnection", kind: DataStoreKind::Sql, label: "MySQL/Postgres (mysql/pg)" },
    DriverRule { leaf: "Sequelize",        kind: DataStoreKind::Sql, label: "Sequelize" },
    DriverRule { leaf: "TypeORM.createConnection", kind: DataStoreKind::Sql, label: "TypeORM" },
    DriverRule { leaf: "PrismaClient",     kind: DataStoreKind::Sql, label: "Prisma" },
    DriverRule { leaf: "pool.query",       kind: DataStoreKind::Sql, label: "pg/mysql pool" },
    DriverRule { leaf: "client.query",     kind: DataStoreKind::Sql, label: "pg client" },
    DriverRule { leaf: "db.query",         kind: DataStoreKind::Sql, label: "Generic SQL driver" },
    // JS — kv / doc
    DriverRule { leaf: "redis.createClient", kind: DataStoreKind::KeyValue, label: "Redis (node-redis)" },
    DriverRule { leaf: "ioredis",          kind: DataStoreKind::KeyValue, label: "ioredis" },
    DriverRule { leaf: "MongoClient.connect", kind: DataStoreKind::Document, label: "MongoDB (node)" },
    DriverRule { leaf: "AWS.S3",           kind: DataStoreKind::BlobStore, label: "AWS S3" },

    // Java — JDBC / Hibernate
    DriverRule { leaf: "DriverManager.getConnection", kind: DataStoreKind::Sql, label: "JDBC" },
    DriverRule { leaf: "JdbcTemplate",     kind: DataStoreKind::Sql, label: "Spring JdbcTemplate" },
    DriverRule { leaf: "EntityManager",    kind: DataStoreKind::Sql, label: "JPA EntityManager" },
    DriverRule { leaf: "SessionFactory.openSession", kind: DataStoreKind::Sql, label: "Hibernate" },
    DriverRule { leaf: "Jedis",            kind: DataStoreKind::KeyValue, label: "Jedis (Redis)" },
    DriverRule { leaf: "MongoClients.create", kind: DataStoreKind::Document, label: "MongoDB (java-driver)" },

    // Go — sql + ORM
    DriverRule { leaf: "sql.Open",         kind: DataStoreKind::Sql, label: "database/sql" },
    DriverRule { leaf: "gorm.Open",        kind: DataStoreKind::Sql, label: "GORM" },
    DriverRule { leaf: "sqlx.Connect",     kind: DataStoreKind::Sql, label: "sqlx" },
    DriverRule { leaf: "sqlx.Open",        kind: DataStoreKind::Sql, label: "sqlx" },
    DriverRule { leaf: "redis.NewClient",  kind: DataStoreKind::KeyValue, label: "go-redis" },
    DriverRule { leaf: "mongo.Connect",    kind: DataStoreKind::Document, label: "MongoDB (go-driver)" },

    // PHP — Eloquent / PDO
    DriverRule { leaf: "PDO",              kind: DataStoreKind::Sql, label: "PDO" },
    DriverRule { leaf: "Eloquent::find",   kind: DataStoreKind::Sql, label: "Laravel Eloquent" },
    DriverRule { leaf: "Eloquent::where",  kind: DataStoreKind::Sql, label: "Laravel Eloquent" },
    DriverRule { leaf: "DB::connection",   kind: DataStoreKind::Sql, label: "Laravel DB" },
    DriverRule { leaf: "Doctrine",         kind: DataStoreKind::Sql, label: "Doctrine ORM" },

    // Ruby — ActiveRecord
    DriverRule { leaf: "ActiveRecord::Base.connection", kind: DataStoreKind::Sql, label: "ActiveRecord" },
    DriverRule { leaf: "ActiveRecord::Base.find",       kind: DataStoreKind::Sql, label: "ActiveRecord" },
    DriverRule { leaf: ".find_by_sql",     kind: DataStoreKind::Sql, label: "ActiveRecord raw SQL" },

    // Rust — sqlx / diesel
    DriverRule { leaf: "sqlx::query",      kind: DataStoreKind::Sql, label: "sqlx" },
    DriverRule { leaf: "sqlx::query_as",   kind: DataStoreKind::Sql, label: "sqlx" },
    DriverRule { leaf: "diesel::sql_query", kind: DataStoreKind::Sql, label: "Diesel" },
    DriverRule { leaf: "PgConnection::establish", kind: DataStoreKind::Sql, label: "Diesel" },

    // Filesystem (best-effort: language-agnostic open()-family)
    DriverRule { leaf: "open",             kind: DataStoreKind::Filesystem, label: "Filesystem" },
];

/// Walk every function summary's callee list and emit one
/// [`SurfaceNode::DataStore`] per matched driver call.  De-duped on
/// `(file, line, label)`.
pub fn detect_data_stores(summaries: &GlobalSummaries) -> Vec<SurfaceNode> {
    let mut out: Vec<SurfaceNode> = Vec::new();
    let mut seen: std::collections::HashSet<(String, u32, String)> =
        std::collections::HashSet::new();
    for (key, summary) in summaries.iter() {
        for callee in &summary.callees {
            let Some(rule) = match_rule(&callee.name) else {
                continue;
            };
            let location = call_site_location(summary, callee.ordinal);
            let dedup = (
                location.file.clone(),
                location.line,
                rule.label.to_string(),
            );
            if !seen.insert(dedup) {
                continue;
            }
            let _ = key;
            out.push(SurfaceNode::DataStore(DataStore {
                location,
                kind: rule.kind,
                label: rule.label.to_string(),
            }));
        }
    }
    out
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

/// Best-effort source location for a call site.  We only have file +
/// (sometimes) sink-attribution metadata on `FuncSummary`, so the
/// location falls back to the function's file with line 0 when no
/// finer-grained data is available.
fn call_site_location(summary: &FuncSummary, _ordinal: u32) -> SourceLocation {
    SourceLocation {
        file: summary.file_path.clone(),
        line: 0,
        col: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;
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
        let (k, s) = summary_with_callees(
            "init",
            "app.py",
            &["psycopg2.connect", "psycopg2.connect"],
        );
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
}

//! golang-migrate migration adapter (Go).
//!
//! Fires when the surrounding source imports the
//! `github.com/golang-migrate/migrate` driver and the function under
//! analysis is the canonical migration runner (drives `m.Up()` /
//! `m.Down()` / `m.Steps(n)` / `m.Migrate(version)` against a
//! `migrate.Migrate` instance) or itself names one of those entry
//! verbs.
//!
//! Notably does NOT fire just because a helper function is named
//! `Up` / `Down` in a file that has no golang-migrate import marker.
//! The source-shape needle plus the entry-name / driver-callee gate
//! mirror the Phase 21 binding-stealing audit applied to
//! `migration_rails` and `migration_flyway`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationGoMigrateAdapter;

const ADAPTER_NAME: &str = "migration-go-migrate";

fn callee_is_go_migrate(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "Up" | "Down" | "Steps" | "Migrate" | "Force" | "Drop")
}

fn source_imports_go_migrate(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"github.com/golang-migrate/migrate",
        b"migrate.New(",
        b"migrate.NewWithDatabaseInstance(",
        b"migrate.NewWithSourceInstance(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "Up" | "Down" | "Steps" | "Migrate" | "Force")
}

/// golang-migrate uses filename-encoded versions (`000001_init.up.sql`
/// / `000001_init.down.sql`); the Go-side runner only carries the
/// numeric version when `m.Migrate(<n>)` is called. Scan for the
/// argument to a `Migrate(` call as a best-effort version hint.
fn extract_version(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    let needle = ".Migrate(";
    let idx = text.find(needle)?;
    let after = &text[idx + needle.len()..];
    let end = after.find(')')?;
    let raw = after[..end].trim();
    if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(raw.to_owned())
}

impl FrameworkAdapter for MigrationGoMigrateAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let has_shape = source_imports_go_migrate(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_driver = super::any_callee_matches(summary, callee_is_go_migrate);
        let binds = has_shape && (name_matches || body_runs_driver);
        if !binds {
            return None;
        }
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::Migration {
                version: extract_version(file_bytes),
            },
            route: None,
            request_params: Vec::new(),
            response_writer: None,
            middleware: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_go_migrate_up_runner() {
        let src: &[u8] = b"package entry\n\
            import \"github.com/golang-migrate/migrate/v4\"\n\
            func RunMigrations() {\n\
                m, _ := migrate.New(\"file://./migrations\", \"postgres://x\")\n\
                m.Up()\n\
            }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "RunMigrations".into(),
            callees: vec![CalleeSite::bare("m.Up")],
            ..Default::default()
        };
        let binding = MigrationGoMigrateAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("golang-migrate runner binds");
        assert_eq!(binding.adapter, "migration-go-migrate");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }

    #[test]
    fn fires_on_entry_named_up() {
        let src: &[u8] = b"package entry\n\
            import \"github.com/golang-migrate/migrate/v4\"\n\
            func Up(m *migrate.Migrate) error { return m.Up() }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Up".into(),
            ..Default::default()
        };
        assert!(
            MigrationGoMigrateAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some(),
            "function named Up in a golang-migrate file must bind",
        );
    }

    #[test]
    fn skips_helper_named_up_without_go_migrate_import() {
        let src: &[u8] = b"package entry\nfunc Up() {}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Up".into(),
            ..Default::default()
        };
        assert!(
            MigrationGoMigrateAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper named Up without golang-migrate import must not bind",
        );
    }

    #[test]
    fn skips_unrelated_method_in_go_migrate_file() {
        let src: &[u8] = b"package entry\n\
            import \"github.com/golang-migrate/migrate/v4\"\n\
            func helper() {}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            MigrationGoMigrateAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper without driver callee must not bind in a golang-migrate file",
        );
    }

    #[test]
    fn extracts_numeric_version_from_migrate_call() {
        let src: &[u8] = b"package entry\n\
            import \"github.com/golang-migrate/migrate/v4\"\n\
            func RunTo() {\n\
                m, _ := migrate.New(\"file://./m\", \"postgres://x\")\n\
                m.Migrate(42)\n\
            }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "RunTo".into(),
            callees: vec![CalleeSite::bare("m.Migrate")],
            ..Default::default()
        };
        let binding = MigrationGoMigrateAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("binds");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("42"));
        } else {
            panic!("expected Migration entry kind");
        }
    }
}

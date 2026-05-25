//! sqlx migration adapter (Rust).
//!
//! Fires when the surrounding source invokes `sqlx::migrate!()` or
//! imports the `sqlx-cli` migration runner and the function under
//! analysis is the canonical migration runner.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationSqlxAdapter;

const ADAPTER_NAME: &str = "migration-sqlx";

fn callee_is_sqlx_migration(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(last, "migrate" | "run" | "run_direct" | "run_migration")
}

fn source_imports_sqlx_migration(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"sqlx::migrate!",
        b"use sqlx::migrate",
        b"use sqlx_cli",
        b"sqlx_cli::migrate",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "migrate" | "run" | "run_migration")
}

impl FrameworkAdapter for MigrationSqlxAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Rust
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let has_shape = source_imports_sqlx_migration(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_runner = super::any_callee_matches(summary, callee_is_sqlx_migration);
        if !(has_shape && (name_matches || body_runs_runner)) {
            return None;
        }
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::Migration { version: None },
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

    fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_sqlx_migrate_macro() {
        let src: &[u8] = b"async fn migrate(pool: &PgPool) -> sqlx::Result<()> {\n\
                sqlx::migrate!(\"./migrations\").run(pool).await\n\
            }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "migrate".into(),
            callees: vec![CalleeSite::bare("run")],
            ..Default::default()
        };
        let binding = MigrationSqlxAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("sqlx migration binds");
        assert_eq!(binding.adapter, "migration-sqlx");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }

    #[test]
    fn skips_helper_named_migrate_without_sqlx_marker() {
        let src: &[u8] = b"pub fn migrate() {}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "migrate".into(),
            ..Default::default()
        };
        assert!(
            MigrationSqlxAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper named migrate without sqlx marker must not bind",
        );
    }

    #[test]
    fn skips_unrelated_helper_in_sqlx_file() {
        let src: &[u8] = b"async fn migrate(pool: &PgPool) -> sqlx::Result<()> {\n\
                sqlx::migrate!(\"./migrations\").run(pool).await\n\
            }\n\
            pub fn helper() {}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            MigrationSqlxAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "unrelated helper in sqlx migration file must not bind",
        );
    }
}

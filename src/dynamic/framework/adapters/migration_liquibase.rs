//! Liquibase migration adapter (Java).
//!
//! Fires when the surrounding source declares a Java class implementing
//! `liquibase.change.custom.CustomTaskChange` /
//! `liquibase.change.custom.CustomSqlChange` (the canonical
//! programmatic-changeset interfaces) and the function under analysis
//! is the canonical `execute(Database)` / `generateStatements(Database)`
//! entry point or runs JDBC DDL through the supplied database handle.
//!
//! Notably does NOT fire just because a helper method is named
//! `execute` in a file that has no Liquibase import marker. The
//! source-shape needle plus the entry-name / DDL-callee gate together
//! mirror the Phase 21 binding-stealing audit applied to
//! `migration_flyway` and `migration_rails`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationLiquibaseAdapter;

const ADAPTER_NAME: &str = "migration-liquibase";

fn callee_is_liquibase_ddl(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "execute"
            | "executeUpdate"
            | "executeStatement"
            | "executeQuery"
            | "executeLargeUpdate"
            | "prepareStatement"
            | "createStatement"
            | "getJdbcExecutor"
            | "addBatch"
            | "executeBatch"
    )
}

fn source_has_liquibase_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"liquibase.change.custom.CustomTaskChange",
        b"liquibase.change.custom.CustomSqlChange",
        b"liquibase.database.Database",
        b"liquibase.statement.SqlStatement",
        b"implements CustomTaskChange",
        b"implements CustomSqlChange",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "execute" | "generateStatements")
}

/// Liquibase changeset IDs travel in the surrounding XML / YAML / SQL
/// metadata, not in the Java changeset class itself. The closest
/// in-source signal is a `@DatabaseChange(name = "<id>", ...)`
/// annotation on the change-class declaration. Scan for it; absent
/// annotation, return `None` so the verifier can fall back to filename
/// derivation later in the pipeline.
fn extract_version(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    let needle = "@DatabaseChange(";
    let idx = text.find(needle)?;
    let after = &text[idx + needle.len()..];
    let name_key = "name";
    let name_idx = after.find(name_key)?;
    let tail = &after[name_idx + name_key.len()..];
    let eq = tail.find('=')?;
    let quoted = tail[eq + 1..].trim_start();
    let quote = quoted.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let body = &quoted[1..];
    let end = body.find(quote)?;
    let raw = body[..end].trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_owned())
    }
}

impl FrameworkAdapter for MigrationLiquibaseAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let has_shape = source_has_liquibase_shape(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_ddl = super::any_callee_matches(summary, callee_is_liquibase_ddl);
        let binds = has_shape && (name_matches || body_runs_ddl);
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_custom_task_change() {
        let src: &[u8] = b"import liquibase.change.custom.CustomTaskChange;\n\
            import liquibase.database.Database;\n\
            public class AddIndex implements CustomTaskChange {\n\
                public void execute(Database database) throws Exception { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "execute".into(),
            ..Default::default()
        };
        let binding = MigrationLiquibaseAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("liquibase migration binds");
        assert_eq!(binding.adapter, "migration-liquibase");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }

    #[test]
    fn fires_on_custom_sql_change_generate_statements() {
        let src: &[u8] = b"import liquibase.change.custom.CustomSqlChange;\n\
            public class SeedRows implements CustomSqlChange {\n\
                public SqlStatement[] generateStatements(Database db) { return null; }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "generateStatements".into(),
            ..Default::default()
        };
        assert!(
            MigrationLiquibaseAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some(),
            "CustomSqlChange.generateStatements must bind",
        );
    }

    #[test]
    fn skips_helper_named_execute_without_liquibase_import() {
        let src: &[u8] = b"public class Helper {\n\
                public void execute(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "execute".into(),
            ..Default::default()
        };
        assert!(
            MigrationLiquibaseAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper named `execute` without Liquibase import must not bind",
        );
    }

    #[test]
    fn skips_unrelated_method_in_liquibase_file() {
        let src: &[u8] = b"import liquibase.change.custom.CustomTaskChange;\n\
            public class AddIndex implements CustomTaskChange {\n\
                public void helper() { }\n\
                public void execute(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            MigrationLiquibaseAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper method that does not run DDL must not bind even inside a Liquibase file",
        );
    }

    #[test]
    fn extracts_changeset_name_from_database_change_annotation() {
        let src: &[u8] = b"import liquibase.change.custom.CustomTaskChange;\n\
            @DatabaseChange(name = \"add-users-index\", description = \"x\")\n\
            public class AddIndex implements CustomTaskChange {\n\
                public void execute(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "execute".into(),
            ..Default::default()
        };
        let binding = MigrationLiquibaseAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("binds");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("add-users-index"));
        } else {
            panic!("expected Migration entry kind");
        }
    }
}

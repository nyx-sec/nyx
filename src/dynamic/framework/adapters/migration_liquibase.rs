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

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, FrameworkDetectionContext};
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

fn source_class_names(file_bytes: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    let package = parse_package_name(text);
    let mut out = Vec::new();
    for marker in [" class ", " interface ", " enum "] {
        let mut rest = text;
        while let Some(idx) = rest.find(marker) {
            let after = &rest[idx + marker.len()..];
            let Some(name) = java_ident_prefix(after) else {
                rest = after;
                continue;
            };
            out.push(name.to_owned());
            if let Some(pkg) = package.as_deref() {
                out.push(format!("{pkg}.{name}"));
            }
            rest = &after[name.len()..];
        }
    }
    out.sort();
    out.dedup();
    out
}

fn parse_package_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("package ") {
            continue;
        }
        let rest = trimmed["package ".len()..].trim_start();
        let end = rest.find(';')?;
        let pkg = rest[..end].trim();
        if !pkg.is_empty() {
            return Some(pkg.to_owned());
        }
    }
    None
}

fn java_ident_prefix(text: &str) -> Option<&str> {
    let mut end = 0usize;
    for (idx, ch) in text.char_indices() {
        let valid = if idx == 0 {
            ch == '_' || ch == '$' || ch.is_ascii_alphabetic()
        } else {
            ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
        };
        if !valid {
            break;
        }
        end = idx + ch.len_utf8();
    }
    if end == 0 { None } else { Some(&text[..end]) }
}

fn project_liquibase_changeset_for_class(
    context: FrameworkDetectionContext<'_>,
    file_bytes: &[u8],
) -> Option<Option<String>> {
    let names = source_class_names(file_bytes);
    if names.is_empty() {
        return None;
    }
    for rel in LIQUIBASE_CHANGELOG_PATHS {
        let Some(bytes) = context.project_files.get(rel) else {
            continue;
        };
        let text = std::str::from_utf8(bytes).unwrap_or("");
        if !changelog_mentions_liquibase(text) {
            continue;
        }
        for name in &names {
            if changelog_references_class(text, name) {
                return Some(extract_changelog_id_for_class(text, name));
            }
        }
    }
    None
}

const LIQUIBASE_CHANGELOG_PATHS: &[&str] = &[
    "changelog.xml",
    "changelog.yaml",
    "changelog.yml",
    "changelog.json",
    "db/changelog/db.changelog-master.xml",
    "db/changelog/db.changelog-master.yaml",
    "db/changelog/db.changelog-master.yml",
    "db/changelog/db.changelog-master.json",
    "src/main/resources/db/changelog/db.changelog-master.xml",
    "src/main/resources/db/changelog/db.changelog-master.yaml",
    "src/main/resources/db/changelog/db.changelog-master.yml",
    "src/main/resources/db/changelog/db.changelog-master.json",
];

fn changelog_mentions_liquibase(text: &str) -> bool {
    text.contains("databaseChangeLog")
        || text.contains("changeSet")
        || text.contains("customChange")
        || text.contains("customChange:")
}

fn changelog_references_class(text: &str, class_name: &str) -> bool {
    text.contains(&format!("class=\"{class_name}\""))
        || text.contains(&format!("class='{class_name}'"))
        || text.contains(&format!("class: {class_name}"))
        || text.contains(&format!("class: \"{class_name}\""))
        || text.contains(&format!("class: '{class_name}'"))
        || text.contains(&format!("\"class\": \"{class_name}\""))
        || text.contains(&format!("\"class\":\"{class_name}\""))
}

fn extract_changelog_id_for_class(text: &str, class_name: &str) -> Option<String> {
    let class_idx = text.find(class_name)?;
    let before = &text[..class_idx];
    extract_last_attr_value(before, "id")
        .or_else(|| extract_last_yaml_value(before, "id"))
        .or_else(|| extract_last_json_value(before, "id"))
}

fn extract_last_attr_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let idx = text.rfind(&needle)?;
    let quoted = text[idx + needle.len()..].trim_start();
    let quote = quoted.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let body = &quoted[1..];
    let end = body.find(quote)?;
    non_empty(body[..end].trim())
}

fn extract_last_yaml_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&needle) {
            continue;
        }
        let raw = trimmed[needle.len()..].trim().trim_matches(['"', '\'']);
        if let Some(value) = non_empty(raw) {
            return Some(value);
        }
    }
    None
}

fn extract_last_json_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let idx = text.rfind(&needle)?;
    let tail = &text[idx + needle.len()..];
    let colon = tail.find(':')?;
    let quoted = tail[colon + 1..].trim_start();
    let quote = quoted.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let body = &quoted[1..];
    let end = body.find(quote)?;
    non_empty(body[..end].trim())
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
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
        detect_liquibase(summary, file_bytes, None)
    }

    fn detect_with_project_context(
        &self,
        summary: &FuncSummary,
        context: FrameworkDetectionContext<'_>,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_liquibase(summary, file_bytes, Some(context))
    }
}

fn detect_liquibase(
    summary: &FuncSummary,
    file_bytes: &[u8],
    context: Option<FrameworkDetectionContext<'_>>,
) -> Option<FrameworkBinding> {
    let project_changeset =
        context.and_then(|ctx| project_liquibase_changeset_for_class(ctx, file_bytes));
    let has_shape = source_has_liquibase_shape(file_bytes);
    let name_matches = name_is_migration_entry(&summary.name);
    let body_runs_ddl = super::any_callee_matches(summary, callee_is_liquibase_ddl);
    let binds = (has_shape || project_changeset.is_some()) && (name_matches || body_runs_ddl);
    if !binds {
        return None;
    }
    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::Migration {
            version: project_changeset
                .flatten()
                .or_else(|| extract_version(file_bytes)),
        },
        route: None,
        request_params: Vec::new(),
        response_writer: None,
        middleware: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::ProjectFileIndex;
    use crate::summary::CalleeSite;

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

    #[test]
    fn binds_custom_change_from_xml_changelog() {
        let src: &[u8] = b"package app.migrations;\n\
            public class AddUsersIndex {\n\
                public void execute(Object database) { }\n\
            }\n";
        let tree = parse_java(src);
        let mut project_files = ProjectFileIndex::new();
        project_files.insert(
            "src/main/resources/db/changelog/db.changelog-master.xml",
            br#"<databaseChangeLog>
                <changeSet id="20260525-add-users-index" author="nyx">
                    <customChange class="app.migrations.AddUsersIndex"/>
                </changeSet>
            </databaseChangeLog>"#,
        );
        let context = FrameworkDetectionContext {
            ssa_summary: None,
            project_files: &project_files,
        };
        let summary = FuncSummary {
            name: "execute".into(),
            ..Default::default()
        };
        let binding = MigrationLiquibaseAdapter
            .detect_with_project_context(&summary, context, tree.root_node(), src)
            .expect("xml changelog should bind custom change class");
        assert_eq!(binding.adapter, "migration-liquibase");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("20260525-add-users-index"));
        } else {
            panic!("expected Migration entry kind");
        }
    }

    #[test]
    fn binds_custom_change_from_yaml_changelog_with_ddl_body() {
        let src: &[u8] = b"public class AddAuditTable {\n\
                void helper(Connection c) throws Exception { c.createStatement().execute(\"create table audit(id int)\"); }\n\
            }\n";
        let tree = parse_java(src);
        let mut project_files = ProjectFileIndex::new();
        project_files.insert(
            "db/changelog/db.changelog-master.yaml",
            b"databaseChangeLog:\n\
              - changeSet:\n\
                  id: audit-table\n\
                  changes:\n\
                    - customChange:\n\
                        class: AddAuditTable\n",
        );
        let context = FrameworkDetectionContext {
            ssa_summary: None,
            project_files: &project_files,
        };
        let summary = FuncSummary {
            name: "helper".into(),
            callees: vec![CalleeSite::bare("stmt.execute")],
            ..Default::default()
        };
        let binding = MigrationLiquibaseAdapter
            .detect_with_project_context(&summary, context, tree.root_node(), src)
            .expect("yaml changelog plus DDL body should bind");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("audit-table"));
        } else {
            panic!("expected Migration entry kind");
        }
    }

    #[test]
    fn skips_project_changelog_when_class_does_not_match() {
        let src: &[u8] = b"public class Unrelated {\n\
                public void execute(Object database) { }\n\
            }\n";
        let tree = parse_java(src);
        let mut project_files = ProjectFileIndex::new();
        project_files.insert(
            "changelog.json",
            br#"{"databaseChangeLog":[{"changeSet":{"id":"x","changes":[{"customChange":{"class":"OtherChange"}}]}}]}"#,
        );
        let context = FrameworkDetectionContext {
            ssa_summary: None,
            project_files: &project_files,
        };
        let summary = FuncSummary {
            name: "execute".into(),
            ..Default::default()
        };
        assert!(
            MigrationLiquibaseAdapter
                .detect_with_project_context(&summary, context, tree.root_node(), src)
                .is_none(),
            "project changelog must not bind every execute method in the project",
        );
    }
}

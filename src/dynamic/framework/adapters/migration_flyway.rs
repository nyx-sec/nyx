//! Flyway migration adapter (Java).
//!
//! Fires when the surrounding source declares a Java class extending
//! `BaseJavaMigration` or implementing `JavaMigration` from the
//! `org.flywaydb.core.api.migration` package, and the function under
//! analysis is the canonical `migrate(Context)` entry point or runs
//! JDBC DDL through the context-supplied connection.
//!
//! Notably does NOT fire just because a helper method is named
//! `migrate` in a file that has no Flyway import marker. The
//! source-shape needle plus the entry-name / DDL-callee gate together
//! mirror the Phase 21 binding-stealing audit applied to
//! `migration_rails` and `migration_django`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationFlywayAdapter;

const ADAPTER_NAME: &str = "migration-flyway";

fn callee_is_flyway_ddl(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "execute"
            | "executeUpdate"
            | "executeQuery"
            | "executeLargeUpdate"
            | "prepareStatement"
            | "createStatement"
            | "addBatch"
            | "executeBatch"
    )
}

fn source_has_flyway_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"org.flywaydb.core.api.migration.BaseJavaMigration",
        b"org.flywaydb.core.api.migration.JavaMigration",
        b"org.flywaydb.core.api.migration.Context",
        b"extends BaseJavaMigration",
        b"implements JavaMigration",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "migrate")
}

/// Pull the version out of the Flyway filename convention. Real
/// Flyway parses the version from the class name (`V1_2_3__Add_users`
/// → `1.2.3`) using the same rule documented at
/// <https://documentation.red-gate.com/fd/migrations-184127470.html>.
/// We approximate by scanning the file bytes for a `class V<ver>__`
/// declaration; if missing, return `None` so the verifier can fall
/// back to filename-based version derivation later in the pipeline.
fn extract_version(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for marker in ["class V", "public class V"] {
        if let Some(idx) = text.find(marker) {
            let after = &text[idx + marker.len()..];
            if let Some(sep) = after.find("__") {
                let raw = &after[..sep];
                let normalised: String = raw
                    .chars()
                    .map(|c| if c == '_' { '.' } else { c })
                    .collect();
                if !normalised.is_empty()
                    && normalised.chars().all(|c| c.is_ascii_digit() || c == '.')
                {
                    return Some(normalised);
                }
            }
        }
    }
    None
}

impl FrameworkAdapter for MigrationFlywayAdapter {
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
        let has_shape = source_has_flyway_shape(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_ddl = super::any_callee_matches(summary, callee_is_flyway_ddl);
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
    fn fires_on_base_java_migration_subclass() {
        let src: &[u8] = b"import org.flywaydb.core.api.migration.BaseJavaMigration;\n\
            import org.flywaydb.core.api.migration.Context;\n\
            public class V1_2_3__Add_users extends BaseJavaMigration {\n\
                public void migrate(Context context) throws Exception { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "migrate".into(),
            ..Default::default()
        };
        let binding = MigrationFlywayAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("flyway migration binds");
        assert_eq!(binding.adapter, "migration-flyway");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("1.2.3"));
        } else {
            panic!("expected Migration entry kind");
        }
    }

    #[test]
    fn fires_when_implementing_java_migration_interface() {
        let src: &[u8] = b"import org.flywaydb.core.api.migration.JavaMigration;\n\
            public class Boot implements JavaMigration {\n\
                public void migrate(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "migrate".into(),
            ..Default::default()
        };
        assert!(
            MigrationFlywayAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some(),
            "interface-based Flyway migration must bind",
        );
    }

    #[test]
    fn skips_helper_named_migrate_without_flyway_import() {
        let src: &[u8] = b"public class Helper {\n\
                public void migrate(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "migrate".into(),
            ..Default::default()
        };
        assert!(
            MigrationFlywayAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper named `migrate` without Flyway import must not bind",
        );
    }

    #[test]
    fn skips_unrelated_method_in_flyway_file() {
        let src: &[u8] = b"import org.flywaydb.core.api.migration.BaseJavaMigration;\n\
            public class V1__Init extends BaseJavaMigration {\n\
                public void helper() { }\n\
                public void migrate(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            MigrationFlywayAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper method that does not run DDL must not bind even inside a Flyway file",
        );
    }

    #[test]
    fn extracts_dotted_version_from_filename_class() {
        let src: &[u8] = b"import org.flywaydb.core.api.migration.BaseJavaMigration;\n\
            public class V2_0__Seed extends BaseJavaMigration {\n\
                public void migrate(Object ctx) { }\n\
            }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "migrate".into(),
            ..Default::default()
        };
        let binding = MigrationFlywayAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("binds");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("2.0"));
        } else {
            panic!("expected Migration entry kind");
        }
    }
}

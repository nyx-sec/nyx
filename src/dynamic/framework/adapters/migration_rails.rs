//! Phase 21 (Track M.3) — Rails ActiveRecord migration adapter (Ruby).
//!
//! Fires when the surrounding source declares a class inheriting from
//! `ActiveRecord::Migration[...]` or carries the canonical migration
//! marker the fixture uses (`# class Foo < ActiveRecord::Migration[…]`).
//!
//! Notably does NOT fire just because the file mentions `create_table` /
//! `add_column` / `drop_table` — those tokens also appear in
//! `db/schema.rb` snapshots, helper modules, and SQL ddl bodies that are
//! not themselves migration classes (Phase 21 binding-stealing audit).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationRailsAdapter;

const ADAPTER_NAME: &str = "migration-rails";

fn callee_is_rails_migration(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "create_table"
            | "add_column"
            | "remove_column"
            | "drop_table"
            | "rename_column"
            | "execute"
    )
}

fn source_has_migration_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[b"ActiveRecord::Migration", b"< ActiveRecord::Migration"];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "up" | "down" | "change")
}

fn extract_version(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    let needle = "ActiveRecord::Migration[";
    if let Some(idx) = text.find(needle) {
        let after = &text[idx + needle.len()..];
        if let Some(end) = after.find(']') {
            return Some(after[..end].trim().to_owned());
        }
    }
    None
}

impl FrameworkAdapter for MigrationRailsAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let has_shape = source_has_migration_shape(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_ddl = super::any_callee_matches(summary, callee_is_rails_migration);
        let binds = (name_matches || body_runs_ddl) && has_shape;
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_rails_migration() {
        let src: &[u8] = b"class AddIndex < ActiveRecord::Migration[7.0]\n  def up\n    add_column :users, :name, :string\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "up".into(),
            ..Default::default()
        };
        let binding = MigrationRailsAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("rails migration binds");
        assert_eq!(binding.adapter, "migration-rails");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("7.0"));
        }
    }

    #[test]
    fn does_not_bind_schema_dump() {
        let src: &[u8] = b"ActiveRecord::Schema.define(version: 2024_01_01_000000) do\n  create_table :users do |t|\n    t.string :name\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "define".into(),
            ..Default::default()
        };
        assert!(
            MigrationRailsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "db/schema.rb dump must not bind as migration",
        );
    }
}

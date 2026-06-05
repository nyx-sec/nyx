//! Phase 21 (Track M.3) — Sequelize migration adapter (JS).
//!
//! Fires when the surrounding source declares `module.exports = { up, down }`
//! whose `up` formal is `(queryInterface, Sequelize)` — Sequelize's
//! canonical migration shape — or imports the `sequelize` package.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationSequelizeAdapter;

const ADAPTER_NAME: &str = "migration-sequelize";

fn source_imports_sequelize_migration(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('sequelize')",
        b"require(\"sequelize\")",
        b"from 'sequelize'",
        b"from \"sequelize\"",
        b"queryInterface.createTable",
        b"queryInterface.addColumn",
        b"queryInterface.bulkInsert",
        b"sequelize-cli",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_sequelize_migration_entry(name: &str) -> bool {
    matches!(name, "up" | "down")
}

impl FrameworkAdapter for MigrationSequelizeAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::JavaScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_source = source_imports_sequelize_migration(file_bytes);
        if matches_source && name_is_sequelize_migration_entry(&summary.name) {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Migration { version: None },
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_sequelize_migration() {
        let src: &[u8] = b"module.exports = {\n  async up(queryInterface, Sequelize) { await queryInterface.createTable('users', {}); },\n  async down(queryInterface, Sequelize) { await queryInterface.dropTable('users'); }\n};\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "up".into(),
            ..Default::default()
        };
        let binding = MigrationSequelizeAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("sequelize migration binds");
        assert_eq!(binding.adapter, "migration-sequelize");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }

    #[test]
    fn skips_unrelated_helper_in_sequelize_migration_file() {
        let src: &[u8] = b"module.exports = {\n  async up(queryInterface, Sequelize) { await queryInterface.createTable('users', {}); },\n};\nfunction normalizeName(name) { return String(name); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "normalizeName".into(),
            ..Default::default()
        };
        assert!(
            MigrationSequelizeAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

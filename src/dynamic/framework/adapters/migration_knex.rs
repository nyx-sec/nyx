//! Knex.js migration adapter (JS).
//!
//! Fires when the surrounding source declares the canonical Knex
//! migration export pair (`exports.up` / `exports.down` against a
//! `knex` instance) or imports the `knex` package directly. The
//! source-shape needle plus the entry-name / DDL-callee gate mirror
//! the Phase 21 binding-stealing audit applied to
//! `migration_sequelize` and `migration_flyway`.
//!
//! Notably does NOT collide with Sequelize migration files (which use
//! `(queryInterface, Sequelize)` formals and live in
//! `migration_sequelize.rs`).  Knex migration files use the bare
//! `knex` argument and call into `knex.schema.*` builders or
//! `knex.raw(...)` for DDL.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationKnexAdapter;

const ADAPTER_NAME: &str = "migration-knex";

fn callee_is_knex_ddl(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "createTable"
            | "createTableIfNotExists"
            | "dropTable"
            | "dropTableIfExists"
            | "alterTable"
            | "renameTable"
            | "hasTable"
            | "hasColumn"
            | "raw"
            | "schema"
    )
}

fn source_imports_knex(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('knex')",
        b"require(\"knex\")",
        b"from 'knex'",
        b"from \"knex\"",
        b"knex.schema.createTable",
        b"knex.schema.dropTable",
        b"knex.schema.alterTable",
        b"knex.raw(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "up" | "down")
}

impl FrameworkAdapter for MigrationKnexAdapter {
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
        let has_shape = source_imports_knex(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_ddl = super::any_callee_matches(summary, callee_is_knex_ddl);
        let binds = has_shape && (name_matches || body_runs_ddl);
        if !binds {
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_knex_up_export() {
        let src: &[u8] = b"exports.up = function(knex) {\n\
              return knex.schema.createTable('users', function (table) { table.string('name'); });\n\
            };\n\
            exports.down = function(knex) { return knex.schema.dropTable('users'); };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "up".into(),
            callees: vec![CalleeSite::bare("knex.schema.createTable")],
            ..Default::default()
        };
        let binding = MigrationKnexAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("knex migration binds");
        assert_eq!(binding.adapter, "migration-knex");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }

    #[test]
    fn fires_on_knex_raw_runner() {
        let src: &[u8] = b"const knex = require('knex');\n\
            exports.up = async function(knex) { await knex.raw('CREATE TABLE u(id int)'); };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "up".into(),
            callees: vec![CalleeSite::bare("knex.raw")],
            ..Default::default()
        };
        assert!(
            MigrationKnexAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some(),
            "knex.raw DDL must bind",
        );
    }

    #[test]
    fn skips_helper_named_up_without_knex_import() {
        let src: &[u8] = b"exports.up = function(ctx) { return ctx; };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "up".into(),
            ..Default::default()
        };
        assert!(
            MigrationKnexAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper named `up` without knex import must not bind",
        );
    }

    #[test]
    fn skips_unrelated_method_in_knex_file() {
        let src: &[u8] = b"const knex = require('knex');\n\
            function helper() {}\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            MigrationKnexAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper without DDL callee must not bind in a knex file",
        );
    }
}

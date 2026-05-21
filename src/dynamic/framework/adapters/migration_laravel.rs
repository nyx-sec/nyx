//! Phase 21 (Track M.3) — Laravel migration adapter (PHP).
//!
//! Fires when the surrounding source extends `Illuminate\\Database\\Migrations\\Migration`
//! and declares an `up()` / `down()` method whose body invokes
//! `Schema::create` / `Schema::table` / `DB::statement`.
//!
//! Notably does NOT fire just because the file mentions `DB::statement`
//! or the bare `Illuminate\\Database\\Schema` namespace — those tokens
//! appear in plenty of model helpers, query objects, and database
//! drivers that are not themselves migration classes (Phase 21
//! binding-stealing audit).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationLaravelAdapter;

const ADAPTER_NAME: &str = "migration-laravel";

fn callee_is_laravel_migration_ddl(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "create" | "table" | "drop" | "statement" | "unprepared")
}

fn source_has_migration_shape(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"Illuminate\\Database\\Migrations\\Migration",
        b"Schema::create",
        b"Schema::table",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "up" | "down")
}

impl FrameworkAdapter for MigrationLaravelAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let has_shape = source_has_migration_shape(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_ddl = super::any_callee_matches(summary, callee_is_laravel_migration_ddl);
        let binds = (name_matches || body_runs_ddl) && has_shape;
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_laravel_migration() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Database\\Migrations\\Migration;\nclass AddUsers extends Migration { public function up() { Schema::create('users', function($t){}); } }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "up".into(),
            ..Default::default()
        };
        let binding = MigrationLaravelAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("laravel migration binds");
        assert_eq!(binding.adapter, "migration-laravel");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }
}

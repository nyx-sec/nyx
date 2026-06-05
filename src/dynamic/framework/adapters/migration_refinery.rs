//! refinery migration adapter (Rust).
//!
//! Fires when the surrounding source imports the `refinery` crate or
//! invokes the `embed_migrations!` macro, and the function under
//! analysis is the canonical migration runner (drives
//! `runner().run(&mut conn)` / `runner().run_async(&mut conn).await`
//! against the macro-generated module) or itself names one of those
//! entry verbs.
//!
use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationRefineryAdapter;

const ADAPTER_NAME: &str = "migration-refinery";

fn callee_is_refinery(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "run" | "run_async" | "runner" | "embed_migrations" | "migrate"
    )
}

fn source_imports_refinery(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"use refinery",
        b"refinery::embed_migrations",
        b"embed_migrations!",
        b"refinery::Runner",
        b"refinery::Migration",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_is_migration_entry(name: &str) -> bool {
    matches!(name, "run" | "run_async" | "runner" | "migrate")
}

impl FrameworkAdapter for MigrationRefineryAdapter {
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
        let has_shape = source_imports_refinery(file_bytes);
        let name_matches = name_is_migration_entry(&summary.name);
        let body_runs_runner = super::any_callee_matches(summary, callee_is_refinery);
        let binds = has_shape && (name_matches || body_runs_runner);
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

    fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_refinery_runner() {
        let src: &[u8] = b"use refinery::embed_migrations;\n\
            embed_migrations!(\"./migrations\");\n\
            pub fn run(conn: &mut postgres::Client) {\n\
                migrations::runner().run(conn).unwrap();\n\
            }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![CalleeSite::bare("migrations::runner")],
            ..Default::default()
        };
        let binding = MigrationRefineryAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("refinery runner binds");
        assert_eq!(binding.adapter, "migration-refinery");
        assert!(matches!(binding.kind, EntryKind::Migration { .. }));
    }

    #[test]
    fn skips_helper_named_run_without_refinery_import() {
        let src: &[u8] = b"pub fn run() {}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            MigrationRefineryAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper named `run` without refinery import must not bind",
        );
    }

    #[test]
    fn skips_unrelated_method_in_refinery_file() {
        let src: &[u8] = b"use refinery::embed_migrations;\n\
            pub fn helper() {}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            MigrationRefineryAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "helper without runner callee must not bind in a refinery file",
        );
    }
}

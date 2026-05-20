//! Phase 21 (Track M.3) — Flask-Migrate / Alembic migration adapter
//! (Python).
//!
//! Fires when the surrounding source imports `alembic` / `flask_migrate`
//! and declares an `upgrade()` / `downgrade()` revision function.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct MigrationFlaskAdapter;

const ADAPTER_NAME: &str = "migration-flask";

fn callee_is_flask_migration(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "upgrade"
            | "downgrade"
            | "execute"
            | "create_table"
            | "add_column"
            | "drop_table"
            | "alter_column"
    )
}

fn source_imports_flask_migration(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"from alembic",
        b"import alembic",
        b"flask_migrate",
        b"op.create_table",
        b"op.add_column",
        b"op.execute",
        b"revision = '",
        b"revision = \"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_version(file_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for needle in ["revision = '", "revision = \""] {
        if let Some(idx) = text.find(needle) {
            let after = &text[idx + needle.len()..];
            let close = if needle.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = after.find(close) {
                return Some(after[..end].to_owned());
            }
        }
    }
    None
}

impl FrameworkAdapter for MigrationFlaskAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_flask_migration);
        let matches_source = source_imports_flask_migration(file_bytes);
        if matches_call || matches_source {
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
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_alembic_revision() {
        let src: &[u8] = b"from alembic import op\nrevision = 'abc123'\n\
            def upgrade():\n    op.create_table('users')\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "upgrade".into(),
            ..Default::default()
        };
        let binding = MigrationFlaskAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("alembic binds");
        assert_eq!(binding.adapter, "migration-flask");
        if let EntryKind::Migration { version } = binding.kind {
            assert_eq!(version.as_deref(), Some("abc123"));
        }
    }
}

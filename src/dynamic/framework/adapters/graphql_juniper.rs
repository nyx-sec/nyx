//! Phase 21 (Track M.3) — Juniper (Rust) GraphQL resolver adapter.
//!
//! Fires when the surrounding source imports the `juniper` crate and
//! the function body sits inside a `#[graphql_object]` impl block.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct GraphqlJuniperAdapter;

const ADAPTER_NAME: &str = "graphql-juniper";

fn callee_is_juniper(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "RootNode" | "EmptyMutation" | "EmptySubscription" | "execute" | "execute_sync"
    )
}

fn source_imports_juniper(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"use juniper",
        b"juniper::",
        b"#[graphql_object",
        b"#[derive(GraphQLObject)]",
        b"juniper::EmptyMutation",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_resolver(summary: &FuncSummary) -> (String, String) {
    ("Query".to_owned(), summary.name.clone())
}

fn name_is_juniper_resolver(name: &str, file_bytes: &[u8]) -> bool {
    if name.starts_with("resolve_") {
        return true;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let needle = format!("fn {name}(");
    let mut search_from = 0;
    while let Some(rel_idx) = text[search_from..].find(&needle) {
        let fn_idx = search_from + rel_idx;
        let before = &text[..fn_idx];
        let Some(impl_idx) = before.rfind("impl ") else {
            search_from = fn_idx + needle.len();
            continue;
        };
        if before[impl_idx..].contains('}') {
            search_from = fn_idx + needle.len();
            continue;
        }
        let scope_start = before[..impl_idx]
            .rfind('}')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        if before[scope_start..impl_idx].contains("#[graphql_object") {
            return true;
        }
        search_from = fn_idx + needle.len();
    }
    false
}

impl FrameworkAdapter for GraphqlJuniperAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_juniper);
        let matches_source = source_imports_juniper(file_bytes);
        if matches_source && (name_is_juniper_resolver(&summary.name, file_bytes) || matches_call) {
            let (type_name, field) = extract_resolver(summary);
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::GraphQLResolver { type_name, field },
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

    fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_juniper_graphql_object() {
        let src: &[u8] = b"use juniper::graphql_object;\n\
            pub struct Query;\n\
            #[graphql_object]\n\
            impl Query {\n    fn user(&self, id: String) -> String { id }\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "user".into(),
            ..Default::default()
        };
        let binding = GraphqlJuniperAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("juniper binds");
        assert_eq!(binding.adapter, "graphql-juniper");
        assert!(matches!(binding.kind, EntryKind::GraphQLResolver { .. }));
    }

    #[test]
    fn skips_unrelated_helper_in_juniper_file() {
        let src: &[u8] = b"use juniper::RootNode;\n\
            pub fn normalize_id(id: &str) -> String { id.to_string() }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "normalize_id".into(),
            ..Default::default()
        };
        assert!(
            GraphqlJuniperAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_free_helper_next_to_graphql_object_impl() {
        let src: &[u8] = b"use juniper::graphql_object;\n\
            pub struct Query;\n\
            #[graphql_object]\n\
            impl Query {\n    fn user(&self, id: String) -> String { id }\n}\n\
            pub fn normalize_id(id: &str) -> String { id.to_string() }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "normalize_id".into(),
            ..Default::default()
        };
        assert!(
            GraphqlJuniperAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

//! Phase 21 (Track M.3) — Graphene (Python) GraphQL resolver adapter.
//!
//! Fires when the surrounding source imports `graphene` and the
//! function body sits inside a `graphene.ObjectType` with a
//! `resolve_<field>` definition.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct GraphqlGrapheneAdapter;

const ADAPTER_NAME: &str = "graphql-graphene";

fn callee_is_graphene(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "Schema" | "ObjectType" | "Field" | "String" | "Int" | "List"
    )
}

fn source_imports_graphene(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"import graphene",
        b"from graphene",
        b"graphene.ObjectType",
        b"graphene.Schema",
        b"graphene.Field",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_resolver(summary: &FuncSummary) -> (String, String) {
    // `resolve_user` → ("Query", "user").  Best-effort.
    if let Some(field) = summary.name.strip_prefix("resolve_") {
        return ("Query".to_owned(), field.to_owned());
    }
    ("Query".to_owned(), summary.name.clone())
}

impl FrameworkAdapter for GraphqlGrapheneAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_graphene);
        let matches_source = source_imports_graphene(file_bytes);
        if matches_call || matches_source {
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_graphene_resolver() {
        let src: &[u8] = b"import graphene\n\
            class Query(graphene.ObjectType):\n    user = graphene.String()\n    def resolve_user(self, info, id):\n        return id\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "resolve_user".into(),
            ..Default::default()
        };
        let binding = GraphqlGrapheneAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("graphene binds");
        assert_eq!(binding.adapter, "graphql-graphene");
        if let EntryKind::GraphQLResolver { type_name, field } = binding.kind {
            assert_eq!(type_name, "Query");
            assert_eq!(field, "user");
        }
    }
}

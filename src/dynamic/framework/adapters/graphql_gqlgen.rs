//! Phase 21 (Track M.3) — gqlgen (Go) GraphQL resolver adapter.
//!
//! Fires when the surrounding source imports the gqlgen runtime or
//! declares a resolver method on a `*queryResolver` / `*mutationResolver`
//! receiver — the canonical shape gqlgen generates.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct GraphqlGqlgenAdapter;

const ADAPTER_NAME: &str = "graphql-gqlgen";

fn callee_is_gqlgen(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "NewExecutableSchema" | "handler" | "Playground" | "GraphQL" | "Recover"
    )
}

fn source_imports_gqlgen(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"github.com/99designs/gqlgen",
        b"gqlgen/graphql",
        b"queryResolver",
        b"mutationResolver",
        b"Resolver) Query(",
        b"Resolver) Mutation(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_resolver(summary: &FuncSummary) -> (String, String) {
    ("Query".to_owned(), summary.name.clone())
}

impl FrameworkAdapter for GraphqlGqlgenAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_gqlgen);
        let matches_source = source_imports_gqlgen(file_bytes);
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

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_gqlgen_query_resolver() {
        let src: &[u8] = b"package graph\n\
            import \"github.com/99designs/gqlgen/graphql\"\n\
            type queryResolver struct{}\n\
            func (r *queryResolver) User(ctx context.Context, id string) (string, error) { return id, nil }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "User".into(),
            ..Default::default()
        };
        let binding = GraphqlGqlgenAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("gqlgen binds");
        assert_eq!(binding.adapter, "graphql-gqlgen");
        assert!(matches!(binding.kind, EntryKind::GraphQLResolver { .. }));
    }
}

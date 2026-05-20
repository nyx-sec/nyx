//! Phase 21 (Track M.3) — Apollo GraphQL resolver adapter (JS).
//!
//! Fires when the surrounding source imports `@apollo/server` / the
//! legacy `apollo-server` / `apollo-server-express` package, or the
//! function body sits inside a `Query` / `Mutation` resolver map.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct GraphqlApolloAdapter;

const ADAPTER_NAME: &str = "graphql-apollo";

fn callee_is_apollo(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "ApolloServer" | "startStandaloneServer" | "gql" | "applyMiddleware" | "expressMiddleware"
    )
}

fn source_imports_apollo(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"@apollo/server",
        b"apollo-server",
        b"require('apollo-server')",
        b"require(\"apollo-server\")",
        b"from 'apollo-server",
        b"from \"apollo-server",
        b"new ApolloServer",
        b"const resolvers",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_resolver(summary: &FuncSummary) -> (String, String) {
    // Best-effort: split a fully-qualified name like `Query.user` into
    // `("Query", "user")`.  Falls back to ("Query", name) so the
    // binding always carries some type_name + field.
    if let Some((parent, field)) = summary.name.rsplit_once('.') {
        return (parent.to_owned(), field.to_owned());
    }
    ("Query".to_owned(), summary.name.clone())
}

impl FrameworkAdapter for GraphqlApolloAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_apollo);
        let matches_source = source_imports_apollo(file_bytes);
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_apollo_resolver() {
        let src: &[u8] = b"const { ApolloServer } = require('@apollo/server');\n\
            const resolvers = { Query: { user: (_, { id }) => id } };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "user".into(),
            ..Default::default()
        };
        let binding = GraphqlApolloAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("apollo binds");
        assert_eq!(binding.adapter, "graphql-apollo");
        if let EntryKind::GraphQLResolver { type_name, field } = binding.kind {
            assert_eq!(type_name, "Query");
            assert_eq!(field, "user");
        }
    }
}

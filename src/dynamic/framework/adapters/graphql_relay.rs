//! Phase 21 (Track M.3) — Relay GraphQL resolver adapter (JS).
//!
//! Relay is the Facebook GraphQL client + spec; on the server side
//! `graphql-relay` provides node-id / connection helpers wrapped around
//! the standard `graphql-js` resolver shape.  Fires when the source
//! imports `graphql-relay` / declares a node-id resolver or a
//! `mutationWithClientMutationId` helper.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct GraphqlRelayAdapter;

const ADAPTER_NAME: &str = "graphql-relay";

fn callee_is_relay(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "nodeDefinitions"
            | "mutationWithClientMutationId"
            | "connectionDefinitions"
            | "globalIdField"
            | "fromGlobalId"
    )
}

fn source_imports_relay(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"graphql-relay",
        b"require('graphql-relay')",
        b"require(\"graphql-relay\")",
        b"from 'graphql-relay'",
        b"from \"graphql-relay\"",
        b"nodeDefinitions",
        b"mutationWithClientMutationId",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn extract_resolver(summary: &FuncSummary) -> (String, String) {
    if let Some((parent, field)) = summary.name.rsplit_once('.') {
        return (parent.to_owned(), field.to_owned());
    }
    ("Node".to_owned(), summary.name.clone())
}

impl FrameworkAdapter for GraphqlRelayAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_relay);
        let matches_source = source_imports_relay(file_bytes);
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
    fn fires_on_relay_node_definitions() {
        let src: &[u8] = b"const { nodeDefinitions, fromGlobalId } = require('graphql-relay');\n\
            function resolveUser(globalId) { return fromGlobalId(globalId); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "resolveUser".into(),
            ..Default::default()
        };
        let binding = GraphqlRelayAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("relay binds");
        assert_eq!(binding.adapter, "graphql-relay");
        assert!(matches!(binding.kind, EntryKind::GraphQLResolver { .. }));
    }
}

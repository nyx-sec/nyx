//! Phase 21 (Track M.3) — Apollo GraphQL resolver adapter (JS).
//!
//! Fires when the surrounding source imports `@apollo/server` / the
//! legacy `apollo-server` / `apollo-server-express` package AND the
//! function under analysis looks like a resolver: either its name is
//! a key inside a `Query: { … }` / `Mutation: { … }` / `Subscription:
//! { … }` literal block, or its declaration carries the canonical
//! `(parent, args, context, info?)` formal signature.
//!
//! The previous version of this adapter accepted the bare source
//! needle `const resolvers`, which bound every function inside any
//! file that happened to declare such a variable (Phase 21
//! binding-stealing audit follow-up).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct GraphqlApolloAdapter;

const ADAPTER_NAME: &str = "graphql-apollo";

fn source_imports_apollo(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"@apollo/server",
        b"apollo-server",
        b"require('apollo-server')",
        b"require(\"apollo-server\")",
        b"from 'apollo-server",
        b"from \"apollo-server",
        b"new ApolloServer",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn name_in_resolver_block(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with("Query.")
        || name.starts_with("Mutation.")
        || name.starts_with("Subscription.")
    {
        return true;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bytes = text.as_bytes();
    for opener in ["Query:", "Mutation:", "Subscription:"] {
        let mut cursor = 0;
        while let Some(idx) = text[cursor..].find(opener) {
            let after_open = cursor + idx + opener.len();
            let rest = &text[after_open..];
            let trimmed = rest.trim_start();
            if !trimmed.starts_with('{') {
                cursor = after_open;
                continue;
            }
            let body_start = after_open + (rest.len() - trimmed.len()) + 1;
            let mut depth = 1i32;
            let mut i = body_start;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            let inner_end = i.saturating_sub(1).min(bytes.len());
            let inner = &text[body_start..inner_end];
            let key_colon = format!("{name}:");
            let key_paren = format!("{name}(");
            if inner.contains(&key_colon) || inner.contains(&key_paren) {
                return true;
            }
            cursor = inner_end;
        }
    }
    false
}

fn has_resolver_signature(name: &str, file_bytes: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let text = match std::str::from_utf8(file_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    const PARENTS: &[&str] = &["parent", "root", "obj", "_"];
    const ARGS: &[&str] = &["args", "input", "_args", "params", "variables"];
    for p in PARENTS {
        for a in ARGS {
            let pairs = [
                format!("function {name}({p}, {a}"),
                format!("function {name}({p},{a}"),
                format!("{name} = function({p}, {a}"),
                format!("{name} = function({p},{a}"),
                format!("{name} = ({p}, {a}"),
                format!("{name} = ({p},{a}"),
                format!("{name}: function({p}, {a}"),
                format!("{name}: function({p},{a}"),
                format!("{name}: ({p}, {a}"),
                format!("{name}: ({p},{a}"),
                format!("{name}({p}, {a}"),
                format!("{name}({p},{a}"),
            ];
            if pairs.iter().any(|p| text.contains(p.as_str())) {
                return true;
            }
        }
    }
    false
}

fn extract_resolver(summary: &FuncSummary) -> (String, String) {
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
        if !source_imports_apollo(file_bytes) {
            return None;
        }
        let in_block = name_in_resolver_block(&summary.name, file_bytes);
        let has_sig = has_resolver_signature(&summary.name, file_bytes);
        if !(in_block || has_sig) {
            return None;
        }
        let (type_name, field) = extract_resolver(summary);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::GraphQLResolver { type_name, field },
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

    #[test]
    fn fires_on_resolver_signature_outside_query_block() {
        // Real-world resolver declared as a standalone function with the
        // canonical (parent, args, context) signature, exported for use
        // in the schema.  Matches the dynamic fixture shape.
        let src: &[u8] = b"const _NYX_ADAPTER_MARKER = \"require('@apollo/server')\";\n\
            function resolveUser(parent, args, ctx) { return args.id; }\n\
            module.exports = { resolveUser };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "resolveUser".into(),
            ..Default::default()
        };
        let binding = GraphqlApolloAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("standalone resolver binds via signature");
        assert_eq!(binding.adapter, "graphql-apollo");
    }

    #[test]
    fn does_not_bind_unrelated_helper_in_apollo_file() {
        // File imports Apollo and declares a `Query` block on a
        // different field, but the analyser is asking about an unrelated
        // helper that neither sits in the resolver block nor has the
        // canonical (parent, args) shape.
        let src: &[u8] = b"const { ApolloServer } = require('@apollo/server');\n\
            function loadConfig() { return { port: 3000 }; }\n\
            const resolvers = { Query: { user: () => 'x' } };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "loadConfig".into(),
            ..Default::default()
        };
        assert!(
            GraphqlApolloAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "unrelated helper in an Apollo file must not bind as a resolver",
        );
    }

    #[test]
    fn does_not_bind_bare_const_resolvers_outside_apollo() {
        // File declares `const resolvers = …` without any Apollo import.
        // The old needle `const resolvers` bound this; the tightened
        // adapter requires a real Apollo source token first.
        let src: &[u8] = b"const resolvers = { foo: () => 'bar' };\n\
            function helper() { return 1; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "helper".into(),
            ..Default::default()
        };
        assert!(
            GraphqlApolloAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none(),
            "`const resolvers` alone must not bind without an Apollo import",
        );
    }
}

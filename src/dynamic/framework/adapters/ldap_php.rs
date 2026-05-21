//! PHP [`super::super::FrameworkAdapter`] matching LDAP filter-injection
//! sink constructions.
//!
//! Phase 06 (Track J.4).  Fires when the function body invokes one of
//! the canonical PHP directory-client entry points (`ldap_search`,
//! `ldap_list`, `ldap_read`) and the surrounding source mentions the
//! matching `ldap_*` API surface.
//!
//! Strengthened to walk the AST and reject the binding when any of
//! the search call's argument subtrees flows through PHP's
//! `ldap_escape` filter encoder.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct LdapPhpAdapter;

const ADAPTER_NAME: &str = "ldap-php";

fn callee_last_segment(name: &str) -> &str {
    name.rsplit_once("::")
        .map(|(_, s)| s)
        .or_else(|| name.rsplit_once('.').map(|(_, s)| s))
        .or_else(|| name.rsplit_once("->").map(|(_, s)| s))
        .unwrap_or(name)
}

fn callee_is_ldap_search(name: &str) -> bool {
    matches!(
        callee_last_segment(name),
        "ldap_search" | "ldap_list" | "ldap_read"
    )
}

fn callee_is_ldap_sanitiser(name: &str) -> bool {
    matches!(callee_last_segment(name), "ldap_escape")
}

fn source_imports_ldap(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"ldap_connect",
        b"ldap_bind",
        b"ldap_search",
        b"ldap_list",
        b"ldap_read",
        b"ldap_escape",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn ast_confirms_unsanitised_search(root: Node<'_>, bytes: &[u8]) -> bool {
    let mut found_unsanitised = false;
    let mut saw_any_search = false;
    walk(root, bytes, &mut found_unsanitised, &mut saw_any_search);
    found_unsanitised || !saw_any_search
}

fn walk(node: Node<'_>, bytes: &[u8], unsanitised: &mut bool, saw_any: &mut bool) {
    if *unsanitised {
        return;
    }
    if matches!(
        node.kind(),
        "function_call_expression" | "member_call_expression" | "scoped_call_expression"
    ) && let Some(name) = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("name"))
        .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_ldap_search(name)
    {
        *saw_any = true;
        if let Some(args) = node.child_by_field_name("arguments")
            && !args_contain_sanitiser(args, bytes)
        {
            *unsanitised = true;
            return;
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, unsanitised, saw_any);
    }
}

fn args_contain_sanitiser(args: Node<'_>, bytes: &[u8]) -> bool {
    let mut hit = false;
    scan_for_sanitiser(args, bytes, &mut hit);
    hit
}

fn scan_for_sanitiser(node: Node<'_>, bytes: &[u8], hit: &mut bool) {
    if *hit {
        return;
    }
    if matches!(
        node.kind(),
        "function_call_expression" | "member_call_expression" | "scoped_call_expression"
    ) && let Some(name) = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("name"))
        .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_ldap_sanitiser(name)
    {
        *hit = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        scan_for_sanitiser(child, bytes, hit);
    }
}

impl FrameworkAdapter for LdapPhpAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_ldap(file_bytes) {
            return None;
        }
        if !super::any_callee_matches(summary, callee_is_ldap_search) {
            return None;
        }
        if !ast_confirms_unsanitised_search(ast, file_bytes) {
            return None;
        }
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::Function,
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
    fn fires_on_ldap_search() {
        let src: &[u8] = b"<?php\nfunction run($uid) {\n\
            $c = ldap_connect('127.0.0.1');\n\
            return ldap_search($c, 'ou=people', '(uid=' . $uid . ')');\n\
        }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("ldap_search")],
            ..Default::default()
        };
        assert!(
            LdapPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            LdapPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_filter_arg_is_sanitised() {
        let src: &[u8] = b"<?php\nfunction run($uid) {\n\
            $c = ldap_connect('127.0.0.1');\n\
            return ldap_search($c, 'ou=people', '(uid=' . ldap_escape($uid, '', LDAP_ESCAPE_FILTER) . ')');\n\
        }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("ldap_search")],
            ..Default::default()
        };
        assert!(
            LdapPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

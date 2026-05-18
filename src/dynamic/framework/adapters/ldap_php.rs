//! PHP [`super::super::FrameworkAdapter`] matching LDAP filter-injection
//! sink constructions.
//!
//! Phase 06 (Track J.4).  Fires when the function body invokes one of
//! the canonical PHP directory-client entry points (`ldap_search`,
//! `ldap_list`, `ldap_read`) and the surrounding source mentions the
//! matching `ldap_*` API surface.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct LdapPhpAdapter;

const ADAPTER_NAME: &str = "ldap-php";

fn callee_is_ldap_search(name: &str) -> bool {
    let last = name
        .rsplit_once("::")
        .map(|(_, s)| s)
        .or_else(|| name.rsplit_once('.').map(|(_, s)| s))
        .or_else(|| name.rsplit_once("->").map(|(_, s)| s))
        .unwrap_or(name);
    matches!(last, "ldap_search" | "ldap_list" | "ldap_read")
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_ldap_search);
        let matches_source = source_imports_ldap(file_bytes);
        if matches_call && matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
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
        assert!(LdapPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(LdapPhpAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

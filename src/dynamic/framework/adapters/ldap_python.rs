//! Python [`super::super::FrameworkAdapter`] matching LDAP filter-injection
//! sink constructions.
//!
//! Phase 06 (Track J.4).  Fires when the function body invokes one of
//! the canonical `python-ldap` / `ldap3` entry points
//! (`ldap.search_s`, `ldap.search_ext_s`, `ldap.search`,
//! `Connection.search`) and the surrounding source mentions the
//! matching client module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct LdapPythonAdapter;

const ADAPTER_NAME: &str = "ldap-python";

fn callee_is_ldap_search(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "search_s" | "search_ext_s" | "search" | "search_st" | "search_subtree_s"
    )
}

fn source_imports_ldap(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"import ldap",
        b"from ldap",
        b"ldap3",
        b"python-ldap",
        b"ldap.initialize",
        b"ldap.SCOPE",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for LdapPythonAdapter {
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_ldap_search_s() {
        let src: &[u8] = b"import ldap\n\
            def run(uid):\n\
                con = ldap.initialize('ldap://127.0.0.1')\n\
                return con.search_s('ou=people', ldap.SCOPE_SUBTREE, '(uid=' + uid + ')')\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("search_s")],
            ..Default::default()
        };
        assert!(LdapPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(LdapPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

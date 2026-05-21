//! Python [`super::super::FrameworkAdapter`] matching LDAP filter-injection
//! sink constructions.
//!
//! Phase 06 (Track J.4).  Fires when the function body invokes one of
//! the canonical `python-ldap` / `ldap3` entry points
//! (`ldap.search_s`, `ldap.search_ext_s`, `ldap.search`,
//! `Connection.search`) and the surrounding source mentions the
//! matching client module.
//!
//! Strengthened to walk the AST and reject the binding when any of
//! the search call's argument subtrees flows through a known LDAP
//! filter encoder (`ldap.filter.escape_filter_chars`,
//! `escape_filter_chars`, `ldap.dn.escape_dn_chars`).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct LdapPythonAdapter;

const ADAPTER_NAME: &str = "ldap-python";

fn callee_last_segment(name: &str) -> &str {
    name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name)
}

fn callee_is_ldap_search(name: &str) -> bool {
    matches!(
        callee_last_segment(name),
        "search_s" | "search_ext_s" | "search" | "search_st" | "search_subtree_s"
    )
}

fn callee_is_ldap_sanitiser(name: &str) -> bool {
    matches!(
        callee_last_segment(name),
        "escape_filter_chars" | "escape_dn_chars"
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
    if node.kind() == "call"
        && let Some(func) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_ldap_search(func)
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
    if node.kind() == "call"
        && let Some(func) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
        && callee_is_ldap_sanitiser(func)
    {
        *hit = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        scan_for_sanitiser(child, bytes, hit);
    }
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

    #[test]
    fn skips_when_filter_arg_is_sanitised() {
        let src: &[u8] = b"import ldap\nfrom ldap.filter import escape_filter_chars\n\
            def run(uid):\n\
                con = ldap.initialize('ldap://127.0.0.1')\n\
                return con.search_s('ou=people', ldap.SCOPE_SUBTREE, '(uid=' + escape_filter_chars(uid) + ')')\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("search_s")],
            ..Default::default()
        };
        assert!(LdapPythonAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

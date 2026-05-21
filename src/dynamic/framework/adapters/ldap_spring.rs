//! Java [`super::super::FrameworkAdapter`] matching LDAP filter-injection
//! sink constructions.
//!
//! Phase 06 (Track J.4).  Fires when the function body invokes one of
//! the canonical Java directory-client entry points
//! (`LdapTemplate.search`, `LdapTemplate.find`, `DirContext.search`,
//! `InitialDirContext.search`, `LdapContext.search`) and the
//! surrounding source pulls in one of the matching package symbols —
//! `org.springframework.ldap.*`, `javax.naming.directory.*`,
//! `com.unboundid.ldap.*`.
//!
//! Strengthened to walk the AST and reject the binding when any of
//! the search call's argument subtrees flows through a known LDAP
//! filter encoder (`LdapEncoder.filterEncode`, `Filter.encodeValue`,
//! `LdapUtils.encodeForLDAP`, `encodeForLdapFilter`).  That removes
//! the FP where the developer already wrapped the user input in a
//! sanitiser but the adapter still stamped a binding.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct LdapSpringAdapter;

const ADAPTER_NAME: &str = "ldap-spring";

fn callee_is_ldap_search(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "search" | "find" | "findAll" | "findOne" | "lookup" | "searchAll"
    )
}

fn callee_is_ldap_sanitiser(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "filterEncode"
            | "encodeValue"
            | "encodeForLDAP"
            | "encodeForLdapFilter"
            | "forLDAPFilter"
            | "forLDAP"
    )
}

fn source_imports_ldap(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"org.springframework.ldap",
        b"LdapTemplate",
        b"javax.naming.directory",
        b"InitialDirContext",
        b"DirContext",
        b"LdapContext",
        b"com.unboundid.ldap",
        b"SearchControls",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// True when any `method_invocation` in the file is a recognised LDAP
/// search whose argument list does NOT pass through a known LDAP
/// filter encoder.  Bare-search calls (no encoder anywhere) keep
/// firing; pre-sanitised calls bail out.
fn ast_confirms_unsanitised_search(root: Node<'_>, bytes: &[u8]) -> bool {
    let mut found_unsanitised = false;
    let mut saw_any_search = false;
    walk(root, bytes, &mut found_unsanitised, &mut saw_any_search);
    // Conservative: when no AST search call was found at all, fall
    // through and let the cheap-filter / callee branch decide.  When
    // AST search calls were seen, require at least one without a
    // sanitiser wrap.
    found_unsanitised || !saw_any_search
}

fn walk(node: Node<'_>, bytes: &[u8], unsanitised: &mut bool, saw_any: &mut bool) {
    if *unsanitised {
        return;
    }
    if node.kind() == "method_invocation"
        && let Some(name) = node
            .child_by_field_name("name")
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
    if node.kind() == "method_invocation"
        && let Some(name) = node
            .child_by_field_name("name")
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

impl FrameworkAdapter for LdapSpringAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
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
        let matches_call = super::any_callee_matches(summary, callee_is_ldap_search)
            || file_bytes
                .windows(b".search(".len())
                .any(|w| w == b".search(");
        if !matches_call {
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_ldap_template_search() {
        let src: &[u8] = b"import org.springframework.ldap.core.LdapTemplate;\n\
            public class V {\n  public Object run(String uid, LdapTemplate t) {\n\
                return t.search(\"ou=people\", \"(uid=\" + uid + \")\", null);\n\
            }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("search")],
            ..Default::default()
        };
        let binding = LdapSpringAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("must fire on LdapTemplate.search");
        assert_eq!(binding.adapter, ADAPTER_NAME);
        assert_eq!(binding.kind, EntryKind::Function);
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] =
            b"public class V { public static int add(int a, int b) { return a + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(LdapSpringAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_filter_arg_is_sanitised() {
        // The user input is wrapped in LdapEncoder.filterEncode before
        // it reaches LdapTemplate.search; the binding must not fire.
        let src: &[u8] = b"import org.springframework.ldap.core.LdapTemplate;\n\
            import org.springframework.ldap.support.LdapEncoder;\n\
            public class V {\n  public Object run(String uid, LdapTemplate t) {\n\
                return t.search(\"ou=people\", \"(uid=\" + LdapEncoder.filterEncode(uid) + \")\", null);\n\
            }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("search")],
            ..Default::default()
        };
        assert!(LdapSpringAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}

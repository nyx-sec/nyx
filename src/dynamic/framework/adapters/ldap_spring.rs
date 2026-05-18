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

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct LdapSpringAdapter;

const ADAPTER_NAME: &str = "ldap-spring";

fn callee_is_ldap_search(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "search" | "find" | "findAll" | "findOne" | "lookup" | "searchAll"
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_ldap_search);
        let matches_source = source_imports_ldap(file_bytes);
        if matches_call && matches_source {
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            });
        }
        if matches_source
            && file_bytes
                .windows(b".search(".len())
                .any(|w| w == b".search(")
        {
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            });
        }
        None
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
}

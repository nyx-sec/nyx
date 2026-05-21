//! Canonical XML document staged in the harness workdir for
//! `Cap::XPATH_INJECTION` runs (Phase 07 — Track J.5).
//!
//! The brief lists this file under `src/dynamic/sandbox/stubs/`; the
//! existing stub layer landed at `src/dynamic/stubs/` (matching the
//! SQL / HTTP / Redis / Filesystem / LDAP stubs already shipped under
//! [`crate::dynamic::stubs`]).  The path discrepancy is tracked in
//! `.pitboss/play/deferred.md` alongside the Phase 06 LDAP-server
//! stub relocation note.  If Track P later moves the stub layer
//! under `sandbox/`, this module moves with the rest of the pack.
//!
//! Unlike the LDAP server stub (a real loopback service) this XPath
//! stub is purely a staged file: the per-language harness emitter
//! adds the [`XPATH_CORPUS_FILENAME`] entry to its `HarnessSource.
//! extra_files` and the synthetic XPath evaluator inside the harness
//! reads the file at runtime to count matching nodes.  No network
//! socket is bound; no [`super::StubKind`] variant is registered.
//!
//! # Document shape
//!
//! The staged XML carries three `<user>` records (mirroring the
//! three LDAP server users) so the differential rule sees the same
//! 1-vs-3 split: the originally-intended username matches exactly
//! one node, the canonical `' or '1'='1` payload matches all three.

/// Workdir-relative filename the per-language harnesses look up.
///
/// Stable: a future change requires a coordinated update across every
/// XPath harness emitter (`src/dynamic/lang/{java,python,php,js_shared}.rs`).
pub const XPATH_CORPUS_FILENAME: &str = "xpath_corpus.xml";

/// Bytes of the canonical XML document staged in every XPath harness
/// workdir.  Three records carry stable string attributes the
/// differential rule pins.
pub const XPATH_CORPUS_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<users>\n\
  <user name=\"alice\" role=\"admin\"/>\n\
  <user name=\"bob\" role=\"user\"/>\n\
  <user name=\"carol\" role=\"user\"/>\n\
</users>\n";

/// Number of `<user>` nodes the staged document carries.  Pinned so a
/// corpus change cannot silently shift the differential threshold
/// below `QueryResultCountGreaterThan { n: 1 }`.
pub const XPATH_CORPUS_NODE_COUNT: u32 = 3;

/// `(filename, bytes)` pair the harness emitter folds into its
/// [`crate::dynamic::lang::HarnessSource::extra_files`].
pub fn extra_file_pair() -> (String, String) {
    (
        XPATH_CORPUS_FILENAME.to_owned(),
        XPATH_CORPUS_XML.to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_xml_carries_exactly_three_users() {
        let n = XPATH_CORPUS_XML.matches("<user ").count();
        assert_eq!(n as u32, XPATH_CORPUS_NODE_COUNT);
    }

    #[test]
    fn corpus_xml_names_canonical_users() {
        for needle in ["alice", "bob", "carol"] {
            assert!(
                XPATH_CORPUS_XML.contains(needle),
                "staged XML must list canonical user {needle}",
            );
        }
    }

    #[test]
    fn extra_file_pair_returns_known_filename() {
        let (name, body) = extra_file_pair();
        assert_eq!(name, XPATH_CORPUS_FILENAME);
        assert_eq!(body, XPATH_CORPUS_XML);
    }
}

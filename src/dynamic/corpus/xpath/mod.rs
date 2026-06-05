//! XPath expression injection (`Cap::XPATH_INJECTION`) per-language
//! payload slices.
//!
//! Phase 07 (Track J.5) carves XPath injection across the four
//! most-common XPath evaluator stacks: Java
//! (`javax.xml.xpath.XPath.evaluate`), Python (`lxml.etree.xpath`),
//! PHP (`DOMXPath::query`), and Node.js (`xpath` npm package's
//! `select`).  Every vuln payload appends the canonical
//! `' or '1'='1` quote-escape break — once the host code substitutes
//! the attacker bytes into its XPath template the synthesized
//! expression selects every node the in-workdir
//! [`crate::dynamic::stubs::xpath_document`] XML carries (three
//! users).  The paired benign control quotes the same bytes through
//! the per-language escape helper, leaving the expression pinned to
//! the originally-intended single node.
//!
//! The oracle's
//! [`crate::dynamic::oracle::ProbePredicate::QueryResultCountGreaterThan`]
//! checks the per-payload `ProbeKind::Xpath.nodes_returned` against
//! `n = 1` — vuln passes (3 nodes), benign clears (1 node),
//! fulfilling the §4.1 differential rule.  The same predicate also
//! satisfies LDAP probes (`ProbeKind::Ldap.entries_returned`); the
//! Phase 06 → Phase 07 rename from `LdapResultCountGreaterThan` to
//! `QueryResultCountGreaterThan` captures the shared shape.

pub mod java;
pub mod js;
pub mod php;
pub mod python;

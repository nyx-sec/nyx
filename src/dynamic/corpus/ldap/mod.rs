//! LDAP filter injection (`Cap::LDAP_INJECTION`) per-language payload
//! slices.
//!
//! Phase 06 (Track J.4) carves LDAP filter injection across the three
//! most-common directory clients: Java (`LdapTemplate.search` /
//! `DirContext.search`), Python (`ldap.search_s`), and PHP
//! (`ldap_search`).  Every vuln payload appends the canonical
//! `*)(uid=*` quote-escape break — once the host code substitutes the
//! attacker bytes into its filter template the synthesized LDAP
//! filter matches every entry the directory carries (the
//! [`crate::dynamic::stubs::ldap_server`] stub returns its three
//! provisioned users).  The paired benign control quotes the same
//! bytes through `EscapeDN` / `ldap.dn.escape_filter_chars` /
//! `ldap_escape`, leaving the filter pinned to the originally
//! intended single user.
//!
//! The oracle's
//! [`crate::dynamic::oracle::ProbePredicate::LdapResultCountGreaterThan`]
//! checks the per-payload `ProbeKind::Ldap.entries_returned` against
//! `n = 1` — vuln passes (3 entries), benign clears (1 entry),
//! fulfilling the §4.1 differential rule.
//!
//! C# is intentionally omitted: the [`crate::symbol::Lang`] enum has
//! no `CSharp` variant, so the corpus has nowhere to register it.
//! Tracked in `.pitboss/play/deferred.md` alongside the Phase 05
//! Lang::CSharp gap.

pub mod java;
pub mod php;
pub mod python;

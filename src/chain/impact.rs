//! Phase 24 — impact lattice for the exploit-chain composer.
//!
//! Each [`ImpactRule`] is a `(source_cap, adjacent_cap, result)` triple
//! drawn from the design doc's lattice:
//!
//! | Rule                          | Result                  |
//! |-------------------------------|-------------------------|
//! | `CODE_EXEC`                   | `Rce`                   |
//! | `DESERIALIZE`                 | `Rce`                   |
//! | `SSRF`                        | `InternalNetworkAccess` |
//! | `OPEN_REDIRECT + UNAUTHORIZED_ID` | `SessionHijack`     |
//! | `HEADER_INJECTION + CODE_EXEC`   | `BrowserToLocalRce` |
//! | `FILE_IO + DATA_EXFIL`        | `InfoDisclosure`        |
//!
//! The doc spells some lattice nodes with surface-level handles
//! (`UserSession`, `Cors`, `NoAuth`, `LocalListener`,
//! `SensitiveFileIo`, `PathTraversal`).  Those nodes do not map 1:1
//! onto [`Cap`] bits, so the table above uses the closest [`Cap`]
//! approximations:
//!
//! - `UserSession` → [`Cap::UNAUTHORIZED_ID`] (request-bound caller
//!   identifier carrier)
//! - `Cors + NoAuth` → [`Cap::HEADER_INJECTION`] (the CORS-relaxing
//!   header is the structural marker; the no-auth side is folded into
//!   Phase 25's surface-property check on [`crate::surface::EntryPoint::auth_required`])
//! - `LocalListener` → no cap; folded into Phase 25's surface check
//!   ([`crate::surface::DataStoreKind::Sql`] /
//!   [`crate::surface::ExternalServiceKind::HttpApi`] etc.)
//! - `SensitiveFileIo` → [`Cap::DATA_EXFIL`] (egress-of-sensitive-data
//!   carrier)
//! - `PathTraversal` → [`Cap::FILE_IO`]
//!
//! # Exhaustiveness
//!
//! Pattern-matching exhaustively on [`Cap`] is impossible — it is a
//! `bitflags!` struct over `u32`, not a closed enum.  This module
//! adopts the [`crate::dynamic::corpus`] pattern instead: every Cap
//! bit belongs to exactly one of [`IMPACT_LATTICE_COVERED`] or
//! [`IMPACT_LATTICE_UNCOVERED`], with a const assertion that the
//! union equals [`Cap::all`].  Adding a new `Cap` bit without
//! updating one of those constants fails to compile.

use crate::labels::Cap;
use serde::{Deserialize, Serialize};

/// Impact category produced by a successful chain composition.
///
/// Phase 24 enumerates the categories the doc's lattice produces.
/// Phase 25's scoring pass attaches a severity to each category and
/// folds them into the final [`crate::chain::ChainGraph`] output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactCategory {
    /// Remote code execution.
    Rce,
    /// Browser-mediated path to local code execution (e.g. permissive
    /// CORS plus an unauthenticated endpoint that hands off to a
    /// `CODE_EXEC` sink).
    BrowserToLocalRce,
    /// Session-token hijack via an attacker-controlled redirect that
    /// keeps the user's auth identity in the request flow.
    SessionHijack,
    /// SSRF that lands on an internal/local listener.
    InternalNetworkAccess,
    /// Sensitive data egress through a path-traversal-like primitive.
    InfoDisclosure,
}

/// One rule in the impact lattice.
///
/// `adjacent_cap` is `None` for self-sufficient rules
/// (`CODE_EXEC → Rce`, `DESERIALIZE → Rce`, `SSRF → InternalNetworkAccess`)
/// and `Some(cap)` for rules that need a second co-located finding
/// (`OPEN_REDIRECT + UNAUTHORIZED_ID → SessionHijack`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactRule {
    pub source_cap: Cap,
    pub adjacent_cap: Option<Cap>,
    pub result: ImpactCategory,
}

/// The default impact lattice from the design doc.
///
/// Order matters for [`lookup_impact`]: more specific rules
/// (`adjacent_cap.is_some()`) appear before the broader fallbacks so a
/// `CODE_EXEC + ...` finding pair is classified as
/// `BrowserToLocalRce` before the standalone `CODE_EXEC → Rce`
/// fallback fires.
pub static IMPACT_LATTICE: &[ImpactRule] = &[
    // ── 2-cap rules (most specific first) ─────────────────────────
    ImpactRule {
        source_cap: Cap::OPEN_REDIRECT,
        adjacent_cap: Some(Cap::UNAUTHORIZED_ID),
        result: ImpactCategory::SessionHijack,
    },
    ImpactRule {
        source_cap: Cap::HEADER_INJECTION,
        adjacent_cap: Some(Cap::CODE_EXEC),
        result: ImpactCategory::BrowserToLocalRce,
    },
    ImpactRule {
        source_cap: Cap::FILE_IO,
        adjacent_cap: Some(Cap::DATA_EXFIL),
        result: ImpactCategory::InfoDisclosure,
    },
    // ── 1-cap rules ───────────────────────────────────────────────
    ImpactRule {
        source_cap: Cap::CODE_EXEC,
        adjacent_cap: None,
        result: ImpactCategory::Rce,
    },
    ImpactRule {
        source_cap: Cap::DESERIALIZE,
        adjacent_cap: None,
        result: ImpactCategory::Rce,
    },
    ImpactRule {
        source_cap: Cap::SSRF,
        adjacent_cap: None,
        result: ImpactCategory::InternalNetworkAccess,
    },
];

/// Caps that participate in at least one impact rule (either as
/// `source_cap` or as `adjacent_cap`).  Update when adding a rule.
pub const IMPACT_LATTICE_COVERED: u32 = Cap::CODE_EXEC.bits()
    | Cap::DESERIALIZE.bits()
    | Cap::SSRF.bits()
    | Cap::OPEN_REDIRECT.bits()
    | Cap::UNAUTHORIZED_ID.bits()
    | Cap::HEADER_INJECTION.bits()
    | Cap::FILE_IO.bits()
    | Cap::DATA_EXFIL.bits();

/// Caps that do not participate in any impact rule today.  Adding a
/// rule that consumes one of these caps requires moving it into
/// [`IMPACT_LATTICE_COVERED`] above.
pub const IMPACT_LATTICE_UNCOVERED: u32 = Cap::ENV_VAR.bits()
    | Cap::HTML_ESCAPE.bits()
    | Cap::SHELL_ESCAPE.bits()
    | Cap::URL_ENCODE.bits()
    | Cap::JSON_PARSE.bits()
    | Cap::FMT_STRING.bits()
    | Cap::SQL_QUERY.bits()
    | Cap::CRYPTO.bits()
    | Cap::LDAP_INJECTION.bits()
    | Cap::XPATH_INJECTION.bits()
    | Cap::SSTI.bits()
    | Cap::XXE.bits()
    | Cap::PROTOTYPE_POLLUTION.bits();

const _: () = assert!(
    IMPACT_LATTICE_COVERED | IMPACT_LATTICE_UNCOVERED == Cap::all().bits(),
    "Cap bit missing from impact lattice coverage; \
     add to IMPACT_LATTICE_COVERED or IMPACT_LATTICE_UNCOVERED and decide \
     whether it should participate in a chain rule",
);

const _: () = assert!(
    IMPACT_LATTICE_COVERED & IMPACT_LATTICE_UNCOVERED == 0,
    "Cap bit appears in both IMPACT_LATTICE_COVERED and IMPACT_LATTICE_UNCOVERED",
);

/// Union of every cap bit referenced by an [`IMPACT_LATTICE`] rule, as
/// `source_cap` or `adjacent_cap`.  Computed at compile time.
#[allow(dead_code)] // Called from a const assertion; MSRV lints may miss const-eval uses.
const fn rule_coverage_bits() -> u32 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i < IMPACT_LATTICE.len() {
        let rule = IMPACT_LATTICE[i];
        acc |= rule.source_cap.bits();
        acc |= match rule.adjacent_cap {
            Some(a) => a.bits(),
            None => 0,
        };
        i += 1;
    }
    acc
}

const _: () = assert!(
    rule_coverage_bits() == IMPACT_LATTICE_COVERED,
    "IMPACT_LATTICE_COVERED claims a cap bit that no IMPACT_LATTICE rule references; \
     drop it from IMPACT_LATTICE_COVERED or add a rule that consumes it",
);

/// Precomputed standalone-rule table indexed by `Cap` bit position.
///
/// Built once at compile time from [`IMPACT_LATTICE`].  `Cap` is a
/// `bitflags!` u32, so each cap occupies one bit position 0..32; the
/// table stores the standalone [`ImpactCategory`] (if any) for that
/// position.  [`lookup_impact`] uses this to short-circuit its
/// second-pass and third-pass walks in O(1).
static STANDALONE_BY_BIT: [Option<ImpactCategory>; 32] = build_standalone_table();

const fn build_standalone_table() -> [Option<ImpactCategory>; 32] {
    let mut table = [None; 32];
    let mut i = 0;
    while i < IMPACT_LATTICE.len() {
        let rule = IMPACT_LATTICE[i];
        if rule.adjacent_cap.is_none() {
            let bit = rule.source_cap.bits().trailing_zeros() as usize;
            table[bit] = Some(rule.result);
        }
        i += 1;
    }
    table
}

fn standalone_lookup(cap: Cap) -> Option<ImpactCategory> {
    let bits = cap.bits();
    if bits == 0 || bits.count_ones() != 1 {
        return None;
    }
    STANDALONE_BY_BIT[bits.trailing_zeros() as usize]
}

/// Look up an [`ImpactCategory`] for a (source, adjacent) cap pair.
///
/// `adjacent` is `None` when the caller has not yet found a partner
/// finding.  Returns the most-specific matching rule.
///
/// Phase 25's path search calls this once per candidate path with the
/// path's primary and secondary caps; multiple cap matches choose the
/// first rule in [`IMPACT_LATTICE`] order (specific before fallback).
///
/// The standalone-rule walks (second + third pass) are O(1) via
/// [`STANDALONE_BY_BIT`].  The two-cap walk (first pass) stays linear
/// because the 2-cap subset is small (today: three rules); promote
/// to a sorted-pair binary search if the lattice grows past ~16
/// pair-rules.
pub fn lookup_impact(source: Cap, adjacent: Option<Cap>) -> Option<ImpactCategory> {
    // First pass: exact source + matching adjacency (or both ways).
    if let Some(adj) = adjacent {
        for rule in IMPACT_LATTICE {
            if let Some(rule_adj) = rule.adjacent_cap {
                let direct = rule.source_cap == source && rule_adj == adj;
                let swapped = rule.source_cap == adj && rule_adj == source;
                if direct || swapped {
                    return Some(rule.result);
                }
            }
        }
    }
    // Second pass: standalone rule on source_cap (O(1) table lookup).
    if let Some(cat) = standalone_lookup(source) {
        return Some(cat);
    }
    // Third pass: if `adjacent` is given but the pair didn't hit,
    // try the standalone rule on adjacent_cap so a CODE_EXEC + UNRELATED
    // pair still reaches `Rce`.
    if let Some(adj) = adjacent
        && let Some(cat) = standalone_lookup(adj)
    {
        return Some(cat);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdi_alone_maps_to_rce() {
        assert_eq!(
            lookup_impact(Cap::CODE_EXEC, None),
            Some(ImpactCategory::Rce)
        );
    }

    #[test]
    fn deserialize_alone_maps_to_rce() {
        assert_eq!(
            lookup_impact(Cap::DESERIALIZE, None),
            Some(ImpactCategory::Rce)
        );
    }

    #[test]
    fn ssrf_alone_maps_to_internal_network_access() {
        assert_eq!(
            lookup_impact(Cap::SSRF, None),
            Some(ImpactCategory::InternalNetworkAccess)
        );
    }

    #[test]
    fn open_redirect_plus_user_session_maps_to_session_hijack() {
        assert_eq!(
            lookup_impact(Cap::OPEN_REDIRECT, Some(Cap::UNAUTHORIZED_ID)),
            Some(ImpactCategory::SessionHijack)
        );
        // Argument order should not matter.
        assert_eq!(
            lookup_impact(Cap::UNAUTHORIZED_ID, Some(Cap::OPEN_REDIRECT)),
            Some(ImpactCategory::SessionHijack)
        );
    }

    #[test]
    fn cors_plus_codeexec_maps_to_browser_local_rce() {
        assert_eq!(
            lookup_impact(Cap::HEADER_INJECTION, Some(Cap::CODE_EXEC)),
            Some(ImpactCategory::BrowserToLocalRce)
        );
    }

    #[test]
    fn path_traversal_plus_sensitive_io_maps_to_info_disclosure() {
        assert_eq!(
            lookup_impact(Cap::FILE_IO, Some(Cap::DATA_EXFIL)),
            Some(ImpactCategory::InfoDisclosure)
        );
    }

    #[test]
    fn unknown_cap_returns_none() {
        assert_eq!(lookup_impact(Cap::HTML_ESCAPE, None), None);
        assert_eq!(lookup_impact(Cap::CRYPTO, None), None);
    }

    #[test]
    fn pair_with_uncovered_adjacency_falls_through_to_standalone() {
        // CODE_EXEC + CRYPTO: CRYPTO has no rule, so we fall back to
        // the standalone CODE_EXEC → Rce rule.
        assert_eq!(
            lookup_impact(Cap::CODE_EXEC, Some(Cap::CRYPTO)),
            Some(ImpactCategory::Rce)
        );
    }
}

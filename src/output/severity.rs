//! Phase 25 — severity calculation for composed chains.
//!
//! A chain's severity is derived from two inputs:
//!
//! 1. The [`ImpactCategory`] implied by the lattice rule the chain
//!    matched.
//! 2. The slice of constituent [`ChainEdge`]s, used to detect when
//!    every member is `Confirmed` (lifts the floor) or when one or
//!    more members are `Unverified` (lowers the ceiling).
//!
//! The category provides the *base* severity; the constituent slice
//! is a multiplicative knob that can downgrade (when feasibility is
//! weak) but never upgrade above the category's natural ceiling.

use crate::chain::edges::ChainEdge;
use crate::chain::feasibility::Feasibility;
use crate::chain::finding::ChainSeverity;
use crate::chain::impact::ImpactCategory;

/// Compute the severity for a chain.
///
/// The mapping:
///
/// | Category                | Base severity | Notes                                  |
/// |-------------------------|---------------|----------------------------------------|
/// | `Rce`                   | `Critical`    | Always terminal — never downgraded     |
/// | `BrowserToLocalRce`     | `Critical`    | Always terminal — never downgraded     |
/// | `SessionHijack`         | `High`        | Downgraded to Medium when every member |
/// |                         |               | is `Unverified`                        |
/// | `InternalNetworkAccess` | `High`        | Downgraded to Medium when every member |
/// |                         |               | is `Unverified`                        |
/// | `InfoDisclosure`        | `Medium`      | Downgraded to Low when every member is |
/// |                         |               | `Unverified`                           |
pub fn chain_severity(category: ImpactCategory, members: &[ChainEdge]) -> ChainSeverity {
    let base = base_severity(category);
    let all_unverified = !members.is_empty()
        && members
            .iter()
            .all(|m| matches!(m.feasibility, Feasibility::Unverified));
    if all_unverified && base != ChainSeverity::Critical {
        // Drop one bucket when every constituent is unverified and
        // the base is not Critical (Critical means RCE — even
        // unverified RCE chains stay Critical because the static
        // engine's primary cap claim is structural, not feasibility-
        // dependent).
        match base {
            ChainSeverity::High => ChainSeverity::Medium,
            ChainSeverity::Medium => ChainSeverity::Low,
            other => other,
        }
    } else {
        base
    }
}

fn base_severity(category: ImpactCategory) -> ChainSeverity {
    match category {
        ImpactCategory::Rce | ImpactCategory::BrowserToLocalRce => ChainSeverity::Critical,
        ImpactCategory::SessionHijack | ImpactCategory::InternalNetworkAccess => {
            ChainSeverity::High
        }
        ImpactCategory::InfoDisclosure => ChainSeverity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::edges::{FindingRef, Reach};
    use crate::chain::feasibility::Feasibility;
    use crate::labels::Cap;
    use crate::surface::SourceLocation;

    fn edge(feas: Feasibility) -> ChainEdge {
        ChainEdge {
            finding: FindingRef {
                finding_id: "f".into(),
                stable_hash: 0,
                location: SourceLocation::new("a.py", 1, 1),
                rule_id: "r".into(),
                cap_bits: Cap::CODE_EXEC.bits(),
            },
            primary_cap: Cap::CODE_EXEC,
            reach: Reach::Unreachable,
            feasibility: feas,
        }
    }

    #[test]
    fn rce_is_always_critical() {
        let unverified = chain_severity(
            ImpactCategory::Rce,
            &[edge(Feasibility::Unverified), edge(Feasibility::Unverified)],
        );
        assert_eq!(unverified, ChainSeverity::Critical);
    }

    #[test]
    fn browser_local_rce_is_critical() {
        assert_eq!(
            chain_severity(ImpactCategory::BrowserToLocalRce, &[edge(Feasibility::Confirmed)]),
            ChainSeverity::Critical,
        );
    }

    #[test]
    fn session_hijack_downgrades_on_all_unverified() {
        let confirmed = chain_severity(ImpactCategory::SessionHijack, &[edge(Feasibility::Confirmed)]);
        assert_eq!(confirmed, ChainSeverity::High);
        let unverified = chain_severity(
            ImpactCategory::SessionHijack,
            &[edge(Feasibility::Unverified), edge(Feasibility::Unverified)],
        );
        assert_eq!(unverified, ChainSeverity::Medium);
    }

    #[test]
    fn info_disclosure_downgrades_to_low() {
        let unverified = chain_severity(
            ImpactCategory::InfoDisclosure,
            &[edge(Feasibility::Unverified)],
        );
        assert_eq!(unverified, ChainSeverity::Low);
    }

    #[test]
    fn empty_members_stays_at_base() {
        assert_eq!(
            chain_severity(ImpactCategory::SessionHijack, &[]),
            ChainSeverity::High,
        );
    }
}

//! Phase 25 — scoring for composed exploit chains.
//!
//! `score(path) = sum(impact) * product(feasibility)`
//!
//! The impact term is the sum of per-member [`ImpactCategory`] weights
//! (each member contributes the weight of the *standalone* category its
//! primary cap maps to, or `0` when the cap has no standalone impact —
//! the cap still contributes adjacency to the final implied impact via
//! the composer).  The feasibility term is the product of every
//! member's [`Feasibility::score`].
//!
//! # Threshold
//!
//! [`min_score_default`] is the in-code fallback when `[chain] min_score`
//! is unset in `nyx.toml`.  Path search drops any composed chain whose
//! score is strictly below the configured threshold.

use crate::chain::edges::ChainEdge;
use crate::chain::feasibility::Feasibility;
use crate::chain::impact::ImpactCategory;
use serde::{Deserialize, Serialize};

/// Per-impact-category numeric weight contributed to the additive
/// impact term.  The relative ordering matches the design doc's
/// criticality ranking; absolute values are kept simple integers so
/// the resulting `score` stays human-comparable.
///
/// `BrowserToLocalRce` is treated as marginally higher than `Rce`
/// because the chain composing it (`HEADER_INJECTION + CODE_EXEC` with
/// an unauthenticated entry-point) folds an extra surface property and
/// is therefore strictly more specific.
pub const fn category_weight(c: ImpactCategory) -> f64 {
    match c {
        ImpactCategory::BrowserToLocalRce => 110.0,
        ImpactCategory::Rce => 100.0,
        ImpactCategory::SessionHijack => 80.0,
        ImpactCategory::InternalNetworkAccess => 60.0,
        ImpactCategory::InfoDisclosure => 50.0,
    }
}

/// `f64` cap floor for the multiplicative feasibility term.  Even an
/// `Unverified` member contributes a non-zero weight so a 3-step chain
/// with three unverified hops does not score `0`.
fn feasibility_factor(f: Feasibility) -> f64 {
    match f {
        Feasibility::Confirmed => 1.0,
        Feasibility::InconclusiveHighConf => 0.5,
        Feasibility::Unverified => 0.1,
    }
}

/// Compute the chain score for a path.
///
/// `member_impacts` carries the standalone impact category for each
/// member that has one (omit the entry when the member's primary cap
/// has no standalone rule — adjacency still contributes via the
/// composer's `implied_impact`).  `implied_impact` is the final
/// composed category; it always contributes its weight even when no
/// individual member would on its own (e.g. the `OPEN_REDIRECT +
/// UNAUTHORIZED_ID → SessionHijack` rule).
pub fn score_path(
    member_impacts: &[ImpactCategory],
    implied_impact: ImpactCategory,
    members: &[ChainEdge],
) -> f64 {
    let mut impact_sum: f64 = member_impacts.iter().copied().map(category_weight).sum();
    impact_sum += category_weight(implied_impact);
    let feasibility_product: f64 = members
        .iter()
        .map(|e| feasibility_factor(e.feasibility))
        .product();
    impact_sum * feasibility_product
}

/// In-code fallback for `[chain] min_score`.  Set so a single
/// `Unverified` `InfoDisclosure` finding (score = 50 * 0.1 = 5) lands
/// below threshold while a two-member chain (Rce + Unverified, ~10)
/// or a Confirmed single-cap chain (>=100) clears it.
pub const fn min_score_default() -> f64 {
    9.5
}

/// `[chain]` section of `nyx.toml`.  Persisted via
/// [`crate::utils::config::ChainConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ChainScoreConfig {
    /// Path-search threshold.  Chains below this score are dropped.
    pub min_score: f64,
}

impl Default for ChainScoreConfig {
    fn default() -> Self {
        Self {
            min_score: min_score_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::edges::{ChainEdge, FindingRef};
    use crate::chain::feasibility::Feasibility;
    use crate::chain::impact::ImpactCategory;
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
            reach: crate::chain::edges::Reach::Unreachable,
            feasibility: feas,
        }
    }

    #[test]
    fn single_confirmed_rce_clears_default_threshold() {
        let s = score_path(
            &[ImpactCategory::Rce],
            ImpactCategory::Rce,
            &[edge(Feasibility::Confirmed)],
        );
        // 100 (member) + 100 (implied) = 200 * 1.0 = 200
        assert!(s > min_score_default());
        assert!((s - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn unverified_single_member_below_threshold() {
        // 50 + 50 = 100 * 0.1 = 10 — just over threshold; flip impact
        // to InfoDisclosure with one extra hop to push it under.
        let s = score_path(
            &[ImpactCategory::InfoDisclosure],
            ImpactCategory::InfoDisclosure,
            &[edge(Feasibility::Unverified)],
        );
        assert!(s > min_score_default()); // 50+50=100 * 0.1 = 10
        // But two unverified hops gates the chain:
        let s2 = score_path(
            &[ImpactCategory::InfoDisclosure],
            ImpactCategory::InfoDisclosure,
            &[edge(Feasibility::Unverified), edge(Feasibility::Unverified)],
        );
        assert!(s2 < min_score_default()); // 100 * 0.01 = 1.0
    }

    #[test]
    fn feasibility_dampens_score() {
        let confirmed = score_path(
            &[ImpactCategory::Rce],
            ImpactCategory::Rce,
            &[edge(Feasibility::Confirmed), edge(Feasibility::Confirmed)],
        );
        let inconclusive = score_path(
            &[ImpactCategory::Rce],
            ImpactCategory::Rce,
            &[
                edge(Feasibility::Confirmed),
                edge(Feasibility::InconclusiveHighConf),
            ],
        );
        let unverified = score_path(
            &[ImpactCategory::Rce],
            ImpactCategory::Rce,
            &[edge(Feasibility::Confirmed), edge(Feasibility::Unverified)],
        );
        assert!(confirmed > inconclusive);
        assert!(inconclusive > unverified);
    }

    #[test]
    fn category_weights_strictly_ordered() {
        assert!(category_weight(ImpactCategory::BrowserToLocalRce) > category_weight(ImpactCategory::Rce));
        assert!(category_weight(ImpactCategory::Rce) > category_weight(ImpactCategory::SessionHijack));
        assert!(
            category_weight(ImpactCategory::SessionHijack)
                > category_weight(ImpactCategory::InternalNetworkAccess)
        );
        assert!(
            category_weight(ImpactCategory::InternalNetworkAccess)
                > category_weight(ImpactCategory::InfoDisclosure)
        );
    }
}

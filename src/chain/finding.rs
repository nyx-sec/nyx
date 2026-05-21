//! Phase 25 — chain finding emitted by the composer.
//!
//! A [`ChainFinding`] is the externally-visible artefact produced by
//! Track G: a sequence of static findings whose composition implies a
//! higher-level [`ImpactCategory`] than any single member.  The chain
//! has its own [`ChainSeverity`] (a strict superset of the per-finding
//! [`crate::patterns::Severity`] axis, with `Critical` reserved for
//! chains so default-severity gates do not accidentally fire on a
//! chained-only impact).
//!
//! # Determinism
//!
//! `stable_hash` is the BLAKE3-truncated digest of the chain member
//! hashes joined with the implied impact byte.  Two scans of the same
//! source produce the same `stable_hash` regardless of DFS visitation
//! order.
//!
//! # Suppressing constituents in default output
//!
//! Phase 25 keeps individual constituent findings on the wire — they
//! still travel inside `Diag` form — but the JSON / SARIF emitters
//! gate their visibility on [`crate::utils::config::OutputConfig::show_chain_constituents`].
//! See `crate::output::filter_constituents` for the gating.

use crate::chain::edges::FindingRef;
use crate::chain::impact::ImpactCategory;
use crate::evidence::{VerifyResult, VerifyStatus};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity bucket assigned to a [`ChainFinding`].
///
/// Distinct from [`crate::patterns::Severity`] so that chain output
/// (which is, by construction, a composition of *several* findings)
/// does not collide with the per-finding axis.  `Critical` is the
/// highest grade and is reserved for chains whose impact is
/// terminal RCE (`Rce`, `BrowserToLocalRce`).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ChainSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChainSeverity::Low => "LOW",
            ChainSeverity::Medium => "MEDIUM",
            ChainSeverity::High => "HIGH",
            ChainSeverity::Critical => "CRITICAL",
        })
    }
}

impl ChainSeverity {
    /// Phase 26 — drop one severity bucket.  Used by composite
    /// re-verification when the chain's dynamic verdict is
    /// `Inconclusive`: the chain stays on the wire but its severity
    /// loses one notch so triagers see the verification gap.
    ///
    /// `Low` is the floor — calling `downgraded()` on `Low` returns
    /// `Low` so the helper is idempotent.
    pub fn downgraded(self) -> Self {
        match self {
            ChainSeverity::Critical => ChainSeverity::High,
            ChainSeverity::High => ChainSeverity::Medium,
            ChainSeverity::Medium => ChainSeverity::Low,
            ChainSeverity::Low => ChainSeverity::Low,
        }
    }
}

/// One member of a [`ChainFinding`].
///
/// Wraps a [`FindingRef`] so the chain output can name each constituent
/// without duplicating the finding's evidence; consumers join back to
/// the `findings: [...]` array via [`FindingRef::finding_id`] /
/// [`FindingRef::stable_hash`].
pub type ChainMember = FindingRef;

/// A composed exploit chain.
///
/// Phase 25 emits these from [`crate::chain::search::find_chains`].
/// Phase 26 will populate `dynamic_verdict` from a composite
/// re-verification pass; Phase 25 always leaves it as `None`.
///
/// `PartialEq` is omitted because [`crate::evidence::VerifyResult`] is
/// not `PartialEq`.  Equality checks at the test layer compare on
/// `stable_hash` instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFinding {
    /// BLAKE3 of `(member.stable_hash for member in members) || implied_impact`,
    /// truncated to 64 bits.  Stable across scans for the same chain.
    pub stable_hash: u64,
    /// Constituent findings, in path order (entry-adjacent first,
    /// sink-adjacent last).
    pub members: Vec<ChainMember>,
    /// The dangerous-local sink terminating the chain.  Carries the
    /// callee function name and cap bits so consumers can describe
    /// the chain without re-walking the SurfaceMap.
    pub sink: ChainSink,
    /// Composed impact category derived from member caps + adjacency.
    pub implied_impact: ImpactCategory,
    /// Chain severity, computed in [`crate::output::severity`].
    pub severity: ChainSeverity,
    /// Numeric score from [`crate::chain::score::score_path`].
    /// Carried verbatim for JSON output so consumers can re-sort.
    pub score: f64,
    /// Composite dynamic verification verdict.  `None` until Phase 26's
    /// `reverify_chain` runs over the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_verdict: Option<VerifyResult>,
    /// Phase 26 — Track G.3: human-readable reason when composite
    /// re-verification altered the chain's outcome.  Populated when
    /// `dynamic_verdict.status` is `Inconclusive` and the severity was
    /// downgraded; `None` when the verdict either confirmed the chain
    /// or left the severity untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverify_reason: Option<String>,
}

/// Sink terminus of a [`ChainFinding`].  Mirrors the
/// [`crate::surface::DangerousLocal`] node the path ends at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSink {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub function_name: String,
    pub cap_bits: u32,
}

impl ChainFinding {
    /// Compute the stable hash from a member list + impact category.
    /// Exposed so callers that build a `ChainFinding` outside
    /// [`crate::chain::search`] (tests, future composers) stay in sync
    /// with the canonical hash formula.
    pub fn compute_stable_hash(members: &[ChainMember], implied_impact: ImpactCategory) -> u64 {
        let mut h = blake3::Hasher::new();
        for m in members {
            h.update(&m.stable_hash.to_le_bytes());
        }
        h.update(&[impact_byte(implied_impact)]);
        let out = h.finalize();
        let bytes = out.as_bytes();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    /// Phase 26 — Track G.3: attach a composite verdict + apply the
    /// `Inconclusive → severity downgrade` rule.
    ///
    /// - `Confirmed` / `NotConfirmed` / `Unsupported`: severity stays
    ///   put; `reverify_reason` cleared.
    /// - `Inconclusive`: severity drops one bucket
    ///   ([`ChainSeverity::downgraded`]) and `reverify_reason` is set
    ///   from the verdict's typed inconclusive reason (with a fallback
    ///   to a generic "inconclusive composite verification" string when
    ///   the verdict has no typed reason).
    pub fn apply_dynamic_verdict(&mut self, verdict: VerifyResult) {
        if verdict.status == VerifyStatus::Inconclusive {
            self.severity = self.severity.downgraded();
            let reason = match &verdict.inconclusive_reason {
                Some(r) => format!("composite reverification inconclusive: {r}"),
                None => match verdict.detail.as_deref() {
                    Some(d) if !d.is_empty() => {
                        format!("composite reverification inconclusive: {d}")
                    }
                    _ => "composite reverification inconclusive".to_owned(),
                },
            };
            self.reverify_reason = Some(reason);
        } else {
            self.reverify_reason = None;
        }
        self.dynamic_verdict = Some(verdict);
    }
}

/// Stable byte tag for each [`ImpactCategory`].  Used by
/// [`ChainFinding::compute_stable_hash`] so adding an impact variant
/// does not silently shift every other chain's hash.
const fn impact_byte(c: ImpactCategory) -> u8 {
    match c {
        ImpactCategory::Rce => 1,
        ImpactCategory::BrowserToLocalRce => 2,
        ImpactCategory::SessionHijack => 3,
        ImpactCategory::InternalNetworkAccess => 4,
        ImpactCategory::InfoDisclosure => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::edges::FindingRef;
    use crate::surface::SourceLocation;

    fn member(hash: u64) -> ChainMember {
        FindingRef {
            finding_id: format!("f-{hash}"),
            stable_hash: hash,
            location: SourceLocation::new("a.py", 1, 1),
            rule_id: "test".into(),
            cap_bits: 0,
        }
    }

    #[test]
    fn stable_hash_changes_with_member_order() {
        let a = ChainFinding::compute_stable_hash(&[member(1), member(2)], ImpactCategory::Rce);
        let b = ChainFinding::compute_stable_hash(&[member(2), member(1)], ImpactCategory::Rce);
        assert_ne!(a, b);
    }

    #[test]
    fn stable_hash_changes_with_impact() {
        let a = ChainFinding::compute_stable_hash(&[member(1), member(2)], ImpactCategory::Rce);
        let b = ChainFinding::compute_stable_hash(
            &[member(1), member(2)],
            ImpactCategory::BrowserToLocalRce,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn stable_hash_deterministic_across_calls() {
        let h1 = ChainFinding::compute_stable_hash(
            &[member(1), member(2), member(3)],
            ImpactCategory::Rce,
        );
        let h2 = ChainFinding::compute_stable_hash(
            &[member(1), member(2), member(3)],
            ImpactCategory::Rce,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn severity_ordering_is_critical_top() {
        assert!(ChainSeverity::Critical > ChainSeverity::High);
        assert!(ChainSeverity::High > ChainSeverity::Medium);
        assert!(ChainSeverity::Medium > ChainSeverity::Low);
    }
}

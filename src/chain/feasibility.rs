//! Phase 24 — feasibility scoring for chain edges.
//!
//! Each edge produced by [`crate::chain::edges::findings_to_edges`]
//! carries a feasibility weight in `[0.0, 1.0]`.  The weight enters
//! Phase 25's path score as the multiplicative factor in
//! `score(path) = sum(impact) * product(feasibility)`, so a single
//! low-feasibility hop dampens the entire chain.
//!
//! # Buckets
//!
//! | Bucket                  | Weight | Trigger                                                     |
//! |-------------------------|--------|-------------------------------------------------------------|
//! | [`Confirmed`]           | `1.0`  | dynamic [`VerifyStatus::Confirmed`]                         |
//! | [`InconclusiveHighConf`]| `0.5`  | dynamic [`VerifyStatus::Inconclusive`] + static `High`      |
//! | [`Unverified`]          | `0.1`  | everything else (no verdict, `NotConfirmed`, `Unsupported`, |
//! |                         |        | or `Inconclusive` without a high static confidence)         |
//!
//! [`Confirmed`]: Feasibility::Confirmed
//! [`InconclusiveHighConf`]: Feasibility::InconclusiveHighConf
//! [`Unverified`]: Feasibility::Unverified
//! [`VerifyStatus::Confirmed`]: crate::evidence::VerifyStatus::Confirmed
//! [`VerifyStatus::Inconclusive`]: crate::evidence::VerifyStatus::Inconclusive

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, VerifyResult, VerifyStatus};
use serde::{Deserialize, Serialize};

/// Discrete feasibility bucket for a chain edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feasibility {
    /// Dynamic verification fired the sink probe.
    Confirmed,
    /// Dynamic verification was Inconclusive but the static engine's
    /// confidence in the finding is `High`.  Used for findings that
    /// the verifier could not exercise (build failure, sandbox refuse)
    /// but where the static evidence is strong.
    InconclusiveHighConf,
    /// Everything else — no dynamic verification, dynamic verdict was
    /// `NotConfirmed`/`Unsupported`, or dynamic was `Inconclusive` but
    /// static confidence is not `High`.
    Unverified,
}

impl Feasibility {
    /// Multiplicative weight contributed to Phase 25's path score.
    pub const fn score(self) -> f32 {
        match self {
            Feasibility::Confirmed => 1.0,
            Feasibility::InconclusiveHighConf => 0.5,
            Feasibility::Unverified => 0.1,
        }
    }

    /// Translate a dynamic [`VerifyResult`] into a feasibility weight.
    ///
    /// This is the literal signature the design doc specifies.  It
    /// cannot distinguish `Inconclusive` with high static confidence
    /// from `Inconclusive` with low static confidence (the static
    /// confidence is carried on the [`Diag`], not on the
    /// [`VerifyResult`]); use [`Feasibility::for_finding`] when both
    /// halves of the input are available.
    pub fn from_verdict(verdict: Option<&VerifyResult>) -> f32 {
        Self::bucket_from_verdict(verdict, None).score()
    }

    /// Same as [`from_verdict`](Self::from_verdict) but consults the
    /// static `Diag.confidence` so the `Inconclusive_HighConf` bucket
    /// in the doc's table can fire.  Phase 25's scoring pass uses this
    /// flavour.
    pub fn for_finding(diag: &Diag) -> Feasibility {
        let verdict = diag.evidence.as_ref().and_then(|e| e.dynamic_verdict.as_ref());
        Self::bucket_from_verdict(verdict, diag.confidence)
    }

    /// Discrete-bucket flavour of [`from_verdict`](Self::from_verdict).
    /// Exposed for callers that want the bucket (e.g. for telemetry or
    /// UI badges) before reducing to an `f32`.
    pub fn bucket_from_verdict(
        verdict: Option<&VerifyResult>,
        static_confidence: Option<Confidence>,
    ) -> Feasibility {
        match verdict.map(|v| v.status) {
            Some(VerifyStatus::Confirmed) => Feasibility::Confirmed,
            Some(VerifyStatus::Inconclusive)
                if static_confidence == Some(Confidence::High) =>
            {
                Feasibility::InconclusiveHighConf
            }
            _ => Feasibility::Unverified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::VerifyResult;

    fn verdict(status: VerifyStatus) -> VerifyResult {
        VerifyResult {
            finding_id: "f".into(),
            status,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
        }
    }

    #[test]
    fn confirmed_returns_one() {
        let v = verdict(VerifyStatus::Confirmed);
        assert_eq!(Feasibility::from_verdict(Some(&v)), 1.0);
    }

    #[test]
    fn inconclusive_without_confidence_returns_unverified() {
        let v = verdict(VerifyStatus::Inconclusive);
        assert_eq!(Feasibility::from_verdict(Some(&v)), 0.1);
    }

    #[test]
    fn inconclusive_with_high_confidence_returns_half() {
        let v = verdict(VerifyStatus::Inconclusive);
        let b = Feasibility::bucket_from_verdict(Some(&v), Some(Confidence::High));
        assert_eq!(b, Feasibility::InconclusiveHighConf);
        assert_eq!(b.score(), 0.5);
    }

    #[test]
    fn not_confirmed_returns_unverified() {
        let v = verdict(VerifyStatus::NotConfirmed);
        assert_eq!(Feasibility::from_verdict(Some(&v)), 0.1);
    }

    #[test]
    fn unsupported_returns_unverified() {
        let v = verdict(VerifyStatus::Unsupported);
        assert_eq!(Feasibility::from_verdict(Some(&v)), 0.1);
    }

    #[test]
    fn no_verdict_returns_unverified() {
        assert_eq!(Feasibility::from_verdict(None), 0.1);
    }
}

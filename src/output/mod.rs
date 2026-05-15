//! Finding serialization and output routing.
//!
//! Phase 25 splits the original `output.rs` into a module:
//!
//! - [`sarif`] — SARIF v2.1.0 emission, with chains attached to
//!   `runs[0].properties.chains` (SARIF has no first-class chain
//!   concept).  Re-exported as [`build_sarif`] (unchanged signature)
//!   plus [`build_sarif_with_chains`].
//! - [`json`] — JSON output that includes `findings` and `chains`
//!   top-level arrays plus per-finding `chain_member_of`.
//! - [`severity`] — chain severity calculation.
//!
//! Default-output behaviour for constituent findings is gated on
//! [`crate::utils::config::OutputConfig::show_chain_constituents`].
//! See [`filter_constituents`].

pub mod json;
pub mod sarif;
pub mod severity;

pub use json::build_findings_json;
pub use sarif::{build_sarif, build_sarif_with_chains};

use crate::chain::finding::ChainFinding;
use crate::commands::scan::Diag;
use std::collections::HashSet;

/// Apply the `[output] show_chain_constituents` gate.
///
/// When `show_chain_constituents == false`, drop every `Diag` whose
/// `stable_hash` appears as a member of any composed chain.  The
/// chains themselves carry the member list so consumers that want
/// per-constituent context can still reach it through `chains[].members`.
///
/// When `show_chain_constituents == true` (or there are no chains),
/// pass `diags` through verbatim.
pub fn filter_constituents(
    diags: Vec<Diag>,
    chains: &[ChainFinding],
    show_chain_constituents: bool,
) -> Vec<Diag> {
    if show_chain_constituents || chains.is_empty() {
        return diags;
    }
    let member_hashes: HashSet<u64> = chains
        .iter()
        .flat_map(|c| c.members.iter().map(|m| m.stable_hash))
        .filter(|h| *h != 0)
        .collect();
    if member_hashes.is_empty() {
        return diags;
    }
    diags
        .into_iter()
        .filter(|d| !(d.stable_hash != 0 && member_hashes.contains(&d.stable_hash)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::edges::FindingRef;
    use crate::chain::finding::{ChainFinding, ChainSeverity, ChainSink};
    use crate::chain::impact::ImpactCategory;
    use crate::commands::scan::Diag;
    use crate::patterns::{FindingCategory, Severity};
    use crate::surface::SourceLocation;

    fn diag(hash: u64) -> Diag {
        Diag {
            path: "a.py".into(),
            line: 1,
            col: 1,
            severity: Severity::High,
            id: "test".into(),
            category: FindingCategory::Security,
            stable_hash: hash,
            ..Diag::default()
        }
    }

    fn chain(member_hash: u64) -> ChainFinding {
        ChainFinding {
            stable_hash: 1,
            members: vec![FindingRef {
                finding_id: "f".into(),
                stable_hash: member_hash,
                location: SourceLocation::new("a.py", 1, 1),
                rule_id: "test".into(),
                cap_bits: 0,
            }],
            sink: ChainSink {
                file: "a.py".into(),
                line: 5,
                col: 1,
                function_name: "sink".into(),
                cap_bits: 0,
            },
            implied_impact: ImpactCategory::Rce,
            severity: ChainSeverity::Critical,
            score: 200.0,
            dynamic_verdict: None,
            reverify_reason: None,
        }
    }

    #[test]
    fn filter_drops_chain_members_when_disabled() {
        let d = diag(42);
        let c = chain(42);
        let out = filter_constituents(vec![d], &[c], false);
        assert!(out.is_empty());
    }

    #[test]
    fn filter_keeps_non_members() {
        let d = diag(99);
        let c = chain(42);
        let out = filter_constituents(vec![d], &[c], false);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_keeps_all_when_enabled() {
        let d = diag(42);
        let c = chain(42);
        let out = filter_constituents(vec![d], &[c], true);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_keeps_all_when_no_chains() {
        let d = diag(42);
        let out = filter_constituents(vec![d], &[], false);
        assert_eq!(out.len(), 1);
    }
}

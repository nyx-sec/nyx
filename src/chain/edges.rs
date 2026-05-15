//! Phase 24 — convert per-finding [`Diag`]s into chain-graph edges.
//!
//! Each call to [`findings_to_edges`] emits exactly one [`ChainEdge`]
//! per input finding.  The edge is *typed* by:
//!
//! - the primary [`Cap`] bit picked from [`Evidence::sink_caps`]
//!   (the lowest-bit set, chosen deterministically), and
//! - the *reach* — the surface [`EntryPoint`] in the same file as the
//!   finding, when one exists, otherwise [`Reach::Unreachable`].
//!
//! Phase 25's path search composes these edges with the SurfaceMap's
//! `Reaches` edges into full chains.  Phase 24 does not run any path
//! search or do call-graph traversal: edges are emitted at finding
//! granularity and carry only the file-local reach hint.

use crate::commands::scan::Diag;
use crate::entry_points::HttpMethod;
use crate::labels::Cap;
use crate::surface::{SourceLocation, SurfaceMap, SurfaceNode};
use serde::{Deserialize, Serialize};

use super::feasibility::Feasibility;

/// Compact reference to a static finding embedded in a [`ChainEdge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRef {
    /// Stable finding ID (matches [`Diag::finding_id`] when present).
    pub finding_id: String,
    /// Stable 64-bit hash from [`Diag::stable_hash`].  Zero when the
    /// finding has not been hashed yet.
    pub stable_hash: u64,
    /// Source location of the sink.
    pub location: SourceLocation,
    /// Rule identifier (`Diag::id`).
    pub rule_id: String,
    /// Resolved sink cap bits ([`Evidence::sink_caps`]).
    pub cap_bits: u32,
}

/// Whether the finding lands inside an externally-reachable surface
/// entry-point.  Phase 24 only resolves *file-local* reach: a finding
/// in `app/views.py` is treated as reachable if any
/// [`EntryPoint`](crate::surface::EntryPoint) declares a handler in
/// that same file.  Phase 25 will fold the call graph in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reach", rename_all = "snake_case")]
pub enum Reach {
    /// Finding is in a file that hosts at least one entry-point.
    /// `route` and `method` describe the first matching entry-point
    /// (surface-canonical order).
    Reachable {
        location: SourceLocation,
        method: HttpMethod,
        route: String,
        auth_required: bool,
    },
    /// Finding is in a file with no surface entry-points.
    Unreachable,
}

/// One edge in the chain graph.
///
/// Phase 24's edges live at the granularity of a single finding.
/// Phase 25 will introduce additional edge kinds (entry → finding,
/// finding → sink-cluster, etc.) once path search is wired up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainEdge {
    pub finding: FindingRef,
    /// Primary cap classification.  Picked deterministically as the
    /// lowest set bit of [`FindingRef::cap_bits`] so two scans of the
    /// same source produce identical edges.
    pub primary_cap: Cap,
    /// Where the finding sits relative to the surface.
    pub reach: Reach,
    /// Phase 25 path-score factor.
    pub feasibility: Feasibility,
}

/// Convert each [`Diag`] to one [`ChainEdge`].
///
/// Findings without cap bits (`Diag::evidence.sink_caps == 0`) are
/// dropped — the chain composer cannot classify them on a typed
/// lattice and Phase 25's scoring expects every edge to expose a
/// primary cap.  This is a deliberate quiet-drop: such findings are
/// usually structural CFG diagnostics (e.g. `cfg-auth-gap`) whose
/// chain participation is modelled by the SurfaceMap's
/// `AuthRequiredOn` edges instead.
///
/// The output order mirrors `findings`; the caller is responsible for
/// any further canonicalisation.
pub fn findings_to_edges(findings: &[Diag], surface: &SurfaceMap) -> Vec<ChainEdge> {
    findings
        .iter()
        .filter_map(|d| build_edge(d, surface))
        .collect()
}

fn build_edge(diag: &Diag, surface: &SurfaceMap) -> Option<ChainEdge> {
    let evidence = diag.evidence.as_ref()?;
    if evidence.sink_caps == 0 {
        return None;
    }
    let cap_bits = evidence.sink_caps;
    let primary_cap = lowest_cap(cap_bits)?;
    let location = SourceLocation::new(diag.path.clone(), diag.line as u32, diag.col as u32);
    let reach = locate_reach(&location, surface);
    let feasibility = Feasibility::for_finding(diag);
    let finding = FindingRef {
        finding_id: diag.finding_id.clone(),
        stable_hash: diag.stable_hash,
        location,
        rule_id: diag.id.clone(),
        cap_bits,
    };
    Some(ChainEdge {
        finding,
        primary_cap,
        reach,
        feasibility,
    })
}

/// Return the lowest single-bit [`Cap`] present in `bits`, or `None`
/// when `bits == 0`.  Deterministic: always picks the lowest bit.
pub fn lowest_cap(bits: u32) -> Option<Cap> {
    if bits == 0 {
        return None;
    }
    let lowest = 1u32 << bits.trailing_zeros();
    Cap::from_bits(lowest)
}

fn locate_reach(loc: &SourceLocation, surface: &SurfaceMap) -> Reach {
    for node in &surface.nodes {
        if let SurfaceNode::EntryPoint(ep) = node {
            if ep.handler_location.file == loc.file {
                return Reach::Reachable {
                    location: ep.location.clone(),
                    method: ep.method,
                    route: ep.route.clone(),
                    auth_required: ep.auth_required,
                };
            }
        }
    }
    Reach::Unreachable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::scan::Diag;
    use crate::evidence::Evidence;
    use crate::patterns::FindingCategory;

    fn diag_with_cap(path: &str, line: usize, caps: Cap) -> Diag {
        let ev = Evidence {
            sink_caps: caps.bits(),
            ..Evidence::default()
        };
        Diag {
            path: path.into(),
            line,
            col: 1,
            id: "test-rule".into(),
            category: FindingCategory::Security,
            evidence: Some(ev),
            ..Diag::default()
        }
    }

    #[test]
    fn lowest_cap_picks_least_significant_bit() {
        let combined = Cap::SQL_QUERY | Cap::FILE_IO;
        assert_eq!(lowest_cap(combined.bits()), Some(Cap::FILE_IO));
    }

    #[test]
    fn drops_findings_without_cap_bits() {
        let mut d = diag_with_cap("a.py", 1, Cap::CODE_EXEC);
        d.evidence.as_mut().unwrap().sink_caps = 0;
        let edges = findings_to_edges(&[d], &SurfaceMap::new());
        assert!(edges.is_empty());
    }

    #[test]
    fn reach_unreachable_without_matching_entry_point() {
        let d = diag_with_cap("orphan.py", 2, Cap::CODE_EXEC);
        let edges = findings_to_edges(&[d], &SurfaceMap::new());
        assert_eq!(edges.len(), 1);
        assert!(matches!(edges[0].reach, Reach::Unreachable));
    }
}

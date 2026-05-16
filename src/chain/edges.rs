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

use crate::callgraph::FileReachMap;
use crate::commands::scan::Diag;
use crate::entry_points::HttpMethod;
use crate::labels::Cap;
use crate::surface::{SourceLocation, SurfaceMap, SurfaceNode};
use serde::{Deserialize, Serialize};

use super::feasibility::Feasibility;
use super::impact::lookup_impact;

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
    /// Primary cap classification.  Picked via [`pick_chain_cap`]: when
    /// several cap bits are set, prefers a bit that has a standalone
    /// rule in [`crate::chain::impact::IMPACT_LATTICE`] over the
    /// lowest bit so a `SQL_QUERY | CODE_EXEC` finding lands on the
    /// chain-relevant cap (`CODE_EXEC`).  Falls back to the lowest set
    /// bit when no bit has a standalone rule, keeping single-cap
    /// findings deterministic.
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
    findings_to_edges_with_reach(findings, surface, None)
}

/// Like [`findings_to_edges`] but optionally consults a [`FileReachMap`]
/// to widen `Reach::Reachable` beyond the file-local match.
///
/// When `reach` is `Some`, a finding's enclosing file is also considered
/// `Reachable` whenever any [`SurfaceNode::EntryPoint`]'s
/// `handler_location.file` transitively reaches the finding's file via
/// the call graph.  The first matching entry-point (surface-canonical
/// order) is used to populate the `route` / `method` / `auth_required`
/// fields.
///
/// `reach = None` is byte-identical to the legacy [`findings_to_edges`]
/// behaviour.  Path strings on both sides must use the same convention
/// (project-relative POSIX) for the widening to fire; mismatched paths
/// silently fall through to the file-local heuristic.
pub fn findings_to_edges_with_reach(
    findings: &[Diag],
    surface: &SurfaceMap,
    reach: Option<&FileReachMap>,
) -> Vec<ChainEdge> {
    findings
        .iter()
        .filter_map(|d| build_edge(d, surface, reach))
        .collect()
}

fn build_edge(
    diag: &Diag,
    surface: &SurfaceMap,
    reach: Option<&FileReachMap>,
) -> Option<ChainEdge> {
    let evidence = diag.evidence.as_ref()?;
    if evidence.sink_caps == 0 {
        return None;
    }
    let cap_bits = evidence.sink_caps;
    let primary_cap = pick_chain_cap(cap_bits)?;
    let location = SourceLocation::new(diag.path.clone(), diag.line as u32, diag.col as u32);
    let reach_kind = locate_reach(&location, surface, reach);
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
        reach: reach_kind,
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

/// Pick the chain-relevant [`Cap`] from a sink-cap bitmask.
///
/// When multiple caps are set, prefer one that has a standalone rule in
/// [`crate::chain::impact::IMPACT_LATTICE`] (e.g. `CODE_EXEC`,
/// `DESERIALIZE`, `SSRF`) over the lowest set bit.  A finding with
/// `sink_caps = SQL_QUERY | CODE_EXEC` previously resolved to
/// `SQL_QUERY` (the lowest bit) and missed the `CODE_EXEC → Rce`
/// lattice rule; this helper resolves it to `CODE_EXEC` instead.
///
/// Iterates bits low to high so ties between caps with standalone
/// rules stay deterministic.  Falls back to [`lowest_cap`] when no
/// bit has a standalone rule, preserving single-cap behaviour.
pub fn pick_chain_cap(bits: u32) -> Option<Cap> {
    if bits == 0 {
        return None;
    }
    let mut remaining = bits;
    while remaining != 0 {
        let bit = 1u32 << remaining.trailing_zeros();
        if let Some(cap) = Cap::from_bits(bit) {
            if lookup_impact(cap, None).is_some() {
                return Some(cap);
            }
        }
        remaining &= !bit;
    }
    lowest_cap(bits)
}

fn locate_reach(
    loc: &SourceLocation,
    surface: &SurfaceMap,
    reach: Option<&FileReachMap>,
) -> Reach {
    // Pass 1: file-local match (legacy behaviour, always applies).
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
    // Pass 2: transitive caller match via the call graph.  Only fires
    // when `reach` is supplied — keeps the legacy file-local behaviour
    // for callers that have not yet wired the call-graph reach map.
    if let Some(reach) = reach {
        for node in &surface.nodes {
            if let SurfaceNode::EntryPoint(ep) = node {
                if reach.reaches(&ep.handler_location.file, &loc.file) {
                    return Reach::Reachable {
                        location: ep.location.clone(),
                        method: ep.method,
                        route: ep.route.clone(),
                        auth_required: ep.auth_required,
                    };
                }
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
    fn pick_chain_cap_prefers_standalone_rule_cap() {
        // SQL_QUERY (bit 7) has no standalone lattice rule; CODE_EXEC
        // (bit 10) does. Lowest-bit alone would pick SQL_QUERY.
        let combined = Cap::SQL_QUERY | Cap::CODE_EXEC;
        assert_eq!(pick_chain_cap(combined.bits()), Some(Cap::CODE_EXEC));
    }

    #[test]
    fn pick_chain_cap_falls_back_to_lowest_when_no_standalone_rule() {
        // SQL_QUERY + FILE_IO: neither has a standalone rule, fall
        // back to lowest_cap behaviour.
        let combined = Cap::SQL_QUERY | Cap::FILE_IO;
        assert_eq!(pick_chain_cap(combined.bits()), Some(Cap::FILE_IO));
    }

    #[test]
    fn pick_chain_cap_single_bit_unchanged() {
        assert_eq!(pick_chain_cap(Cap::CODE_EXEC.bits()), Some(Cap::CODE_EXEC));
        assert_eq!(pick_chain_cap(Cap::SQL_QUERY.bits()), Some(Cap::SQL_QUERY));
        assert_eq!(pick_chain_cap(0), None);
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

    /// Cross-file finding becomes Reachable when the call-graph reach
    /// map records a transitive caller in the entry-point's file.
    #[test]
    fn reach_widens_with_file_reach_map() {
        use crate::callgraph::{FileReachMap, build_call_graph};
        use crate::entry_points::HttpMethod;
        use crate::summary::{FuncSummary, merge_summaries};
        use crate::surface::{EntryPoint, Framework, SourceLocation, SurfaceNode};

        // routes.py::handle -> helper.py::sink
        let handle = FuncSummary {
            name: "handle".into(),
            file_path: "routes.py".into(),
            lang: "python".into(),
            param_count: 0,
            callees: vec![crate::summary::CalleeSite::bare("sink")],
            ..Default::default()
        };
        let sink = FuncSummary {
            name: "sink".into(),
            file_path: "helper.py".into(),
            lang: "python".into(),
            param_count: 0,
            ..Default::default()
        };
        let gs = merge_summaries(vec![handle, sink], None);
        let cg = build_call_graph(&gs, &[]);
        let reach = FileReachMap::build(&cg);

        let mut surface = SurfaceMap::new();
        surface.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new("routes.py", 1, 1),
            framework: Framework::Flask,
            method: HttpMethod::GET,
            route: "/".into(),
            handler_name: "handle".into(),
            handler_location: SourceLocation::new("routes.py", 2, 1),
            auth_required: false,
        }));

        let d = diag_with_cap("helper.py", 10, Cap::CODE_EXEC);

        // Without reach: file-local lookup leaves the finding Unreachable.
        let edges = findings_to_edges(&[d.clone()], &surface);
        assert!(matches!(edges[0].reach, Reach::Unreachable));

        // With reach: transitive caller in `routes.py` lifts to Reachable.
        let edges = findings_to_edges_with_reach(&[d], &surface, Some(&reach));
        match &edges[0].reach {
            Reach::Reachable { route, method, .. } => {
                assert_eq!(route, "/");
                assert_eq!(*method, HttpMethod::GET);
            }
            other => panic!("expected Reachable, got {other:?}"),
        }
    }
}

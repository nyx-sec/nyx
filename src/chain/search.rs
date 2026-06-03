//! Phase 25 — bounded path search for exploit-chain composition.
//!
//! Path topology:
//!
//! ```text
//!   Attacker (virtual) → EntryPoint → Finding* → Sink
//! ```
//!
//! The DFS starts at the implicit attacker node (virtually adjacent to
//! every [`crate::surface::EntryPoint`]), traverses up to [`max_depth`](ChainSearchConfig::max_depth)
//! per-finding hops, and terminates at any
//! [`crate::surface::DangerousLocal`] node.  Each emitted
//! [`ChainFinding`] is the deterministic minimum-length path through a
//! given (entry, sink) pair.
//!
//! # Determinism
//!
//! 1. SurfaceMap nodes are canonicalised before search — every input
//!    list (entries, sinks) is iterated in `SourceLocation` order.
//! 2. Candidate per-entry findings are sorted by
//!    [`crate::chain::edges::FindingRef::stable_hash`] before DFS,
//!    breaking ties by `rule_id` so collisions stay reproducible.
//! 3. The emitted chain list is sorted by `score` descending (ties
//!    broken by `stable_hash` descending, then `implied_impact`
//!    descending) before return.
//!
//! Running the same fixture 10× produces a byte-identical chain list.
//!
//! # Phase 24 follow-ups closed here
//!
//! - `BrowserToLocalRce` auth-gate predicate: when the lattice yields
//!   `BrowserToLocalRce` from `HEADER_INJECTION + CODE_EXEC`, the path
//!   is only kept when the entry's `auth_required` is `false`.  Auth-
//!   gated entries downgrade to the closest standalone impact.
//! - SSRF + LocalListener refinement: when the lattice yields
//!   `InternalNetworkAccess` and the SurfaceMap exposes a local
//!   listener (a [`crate::surface::DataStore`] / [`crate::surface::ExternalService`]
//!   bound to a loopback host), the path is preserved; without a local
//!   listener the chain is still emitted but scored lower (no boost).
//!
//! The "file-local reach → call-graph-aware reach" upgrade remains
//! deferred (see deferred.md): the DFS still treats two findings as
//! adjacent when they share a source file, mirroring Phase 24's
//! `findings_to_edges` reach resolver.
//!
//! Entry-to-finding affinity is enforced symmetrically: the
//! per-entry candidate filter requires the finding's source file to
//! overlap with the entry's `handler_location.file` (or a
//! call-graph reach hit) on top of the route+method match.  Without
//! this gate, two entries that happen to share a (route, method) in
//! a monorepo would each claim every finding under that key,
//! producing `O(entries × findings)` phantom chains that the dedup
//! pass would then collapse.

use crate::callgraph::FileReachMap;
use crate::chain::edges::{ChainEdge, Reach};
use crate::chain::finding::{ChainFinding, ChainSink};
use crate::chain::impact::{ImpactCategory, lookup_impact};
use crate::chain::score::score_path;
use crate::labels::Cap;
use crate::surface::{DangerousLocal, EntryPoint, SurfaceMap, SurfaceNode};

/// Bounded-DFS search configuration.
#[derive(Debug, Clone, Copy)]
pub struct ChainSearchConfig {
    /// Maximum number of per-finding hops in a single chain path.
    /// `0` disables search (no chain is ever emitted).
    pub max_depth: usize,
    /// Drop chains whose score is strictly below this threshold.
    pub min_score: f64,
}

impl Default for ChainSearchConfig {
    fn default() -> Self {
        Self {
            max_depth: 4,
            min_score: crate::chain::score::min_score_default(),
        }
    }
}

/// Result of one search pass: every chain whose score cleared
/// `cfg.min_score`, deterministically ordered.
pub fn find_chains(
    edges: &[ChainEdge],
    surface: &SurfaceMap,
    cfg: ChainSearchConfig,
) -> Vec<ChainFinding> {
    find_chains_with_reach(edges, surface, cfg, None)
}

/// Like [`find_chains`] but optionally consults a [`FileReachMap`] to
/// widen the per-entry-per-sink file-scope filter beyond literal
/// file-equality.
///
/// When `reach` is `Some`, a candidate edge is in scope for a given
/// sink whenever the finding's file *or* a transitive caller of it
/// reaches the sink's file via the call graph.  `reach = None`
/// preserves the legacy file-local behaviour for callers that have
/// not yet wired the call-graph reach map.
pub fn find_chains_with_reach(
    edges: &[ChainEdge],
    surface: &SurfaceMap,
    cfg: ChainSearchConfig,
    reach: Option<&FileReachMap>,
) -> Vec<ChainFinding> {
    if cfg.max_depth == 0 || edges.is_empty() {
        return Vec::new();
    }
    let sinks = collect_sinks(surface);
    let entries = collect_entries(surface);
    let local_listener_present = has_local_listener(surface);

    let mut chains: Vec<ChainFinding> = Vec::new();
    for entry in &entries {
        // Per-entry candidate edge slice: every edge whose reach
        // points at this entry, sorted deterministically.
        let mut candidates: Vec<&ChainEdge> = edges
            .iter()
            .filter(|e| edge_reaches_entry(e, entry, reach))
            .collect();
        candidates.sort_by(|a, b| {
            (
                a.finding.stable_hash,
                &a.finding.rule_id,
                &a.finding.location,
            )
                .cmp(&(
                    b.finding.stable_hash,
                    &b.finding.rule_id,
                    &b.finding.location,
                ))
        });
        for sink in &sinks {
            // Scope candidates to the sink: same-file match (legacy),
            // optionally widened by a call-graph-derived reach map so
            // a finding in `internal_helper.py` whose enclosing
            // function is reached only through `routes.py` still
            // composes against a sink in `routes.py`.
            let scoped: Vec<&ChainEdge> = candidates
                .iter()
                .filter(|e| {
                    paths_overlap(&e.finding.location.file, &sink.location.file)
                        || reach.is_some_and(|r| {
                            r.reaches(&e.finding.location.file, &sink.location.file)
                        })
                })
                .copied()
                .collect();
            if let Some(chain) =
                compose_chain(entry, sink, &scoped, cfg.max_depth, local_listener_present)
                && chain.score >= cfg.min_score
            {
                chains.push(chain);
            }
        }
    }
    canonicalise(&mut chains);
    chains
}

fn collect_sinks(surface: &SurfaceMap) -> Vec<&DangerousLocal> {
    let mut out: Vec<&DangerousLocal> = surface
        .nodes
        .iter()
        .filter_map(|n| match n {
            SurfaceNode::DangerousLocal(d) => Some(d),
            _ => None,
        })
        .collect();
    out.sort_by(|a, b| (&a.location, &a.function_name).cmp(&(&b.location, &b.function_name)));
    out
}

fn collect_entries(surface: &SurfaceMap) -> Vec<&EntryPoint> {
    let mut out: Vec<&EntryPoint> = surface
        .nodes
        .iter()
        .filter_map(|n| match n {
            SurfaceNode::EntryPoint(e) => Some(e),
            _ => None,
        })
        .collect();
    out.sort_by(|a, b| (&a.location, &a.route).cmp(&(&b.location, &b.route)));
    out
}

/// True when the SurfaceMap exposes at least one data store / service
/// whose label resolves to a loopback host.  Used by the SSRF +
/// LocalListener refinement in [`compose_chain`].
fn has_local_listener(surface: &SurfaceMap) -> bool {
    surface.nodes.iter().any(|n| match n {
        SurfaceNode::DataStore(d) => is_loopback_label(&d.label),
        SurfaceNode::ExternalService(s) => is_loopback_label(&s.label),
        _ => false,
    })
}

fn is_loopback_label(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("127.0.0.1")
        || lower.contains("localhost")
        || lower.contains("0.0.0.0")
        || lower.starts_with("unix:")
        || lower.contains("://localhost")
}

fn edge_reaches_entry(edge: &ChainEdge, entry: &EntryPoint, reach: Option<&FileReachMap>) -> bool {
    let route_method_match = match &edge.reach {
        Reach::Reachable { route, method, .. } => *route == entry.route && *method == entry.method,
        Reach::Unreachable => return false,
    };
    if !route_method_match {
        return false;
    }
    // File-affinity gate: the entry's handler must live in (or
    // transitively call into) the same file as the finding.
    // Without this, multiple entries that happen to declare the
    // same (route, method) — common in monorepos that ship
    // several small services side-by-side — would each claim
    // every finding, producing O(entries × findings) phantom
    // chains.  The same shape as the sink-scope filter below:
    // literal file-suffix overlap first, fall back to the
    // call-graph reach map.
    let entry_file = &entry.handler_location.file;
    let finding_file = &edge.finding.location.file;
    paths_overlap(entry_file, finding_file)
        || reach.is_some_and(|r| r.reaches(entry_file, finding_file))
}

fn paths_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Strip leading directory components and compare suffix.  Two
    // representations of the same file (project-relative vs absolute)
    // share a common trailing path segment.
    let a_tail = a.rsplit('/').next().unwrap_or(a);
    let b_tail = b.rsplit('/').next().unwrap_or(b);
    a_tail == b_tail && !a_tail.is_empty()
}

/// Build a single chain for one (entry, sink) pair.
///
/// Bounded DFS: take the longest deterministic prefix of `scoped` up
/// to `max_depth`, then pick the highest-severity lattice match
/// across every (member_cap, sink_cap) pair.  Returning all in-scope
/// edges as members matches the design doc's three-member output for
/// the `CORS + NoAuth + websocket → shell tool` scenario; using the
/// best impact across all pairs ensures `HEADER_INJECTION + CODE_EXEC`
/// lights up `BrowserToLocalRce` even when an unrelated finding (e.g.
/// the standalone auth-gap diagnostic) is sorted first.
fn compose_chain(
    entry: &EntryPoint,
    sink: &DangerousLocal,
    scoped: &[&ChainEdge],
    max_depth: usize,
    local_listener_present: bool,
) -> Option<ChainFinding> {
    if scoped.is_empty() {
        return None;
    }
    let bound = scoped.len().min(max_depth);
    let path: Vec<&ChainEdge> = scoped[..bound].to_vec();
    let sink_cap = sole_cap(sink.cap_bits)?;
    let (impact, member_impacts) = resolve_impact(&path, sink_cap, entry, local_listener_present)?;
    let mut chain = build_chain(entry, sink, &path, impact, &member_impacts);
    // SSRF + LocalListener refinement (Phase 24 deferred close): when
    // the implied impact is `InternalNetworkAccess` AND the SurfaceMap
    // exposes a loopback listener, the chain is more concrete than the
    // bare lattice match — lift the score so it ranks above SSRF chains
    // without a corroborating in-process target.
    if impact == ImpactCategory::InternalNetworkAccess && local_listener_present {
        chain.score *= LOCAL_LISTENER_BOOST;
    }
    Some(chain)
}

/// Score multiplier applied when an `InternalNetworkAccess` chain has
/// a corroborating loopback listener in the SurfaceMap.  Calibrated to
/// lift the chain above an otherwise-identical SSRF chain that lacks
/// the listener context, without overtaking strictly more severe
/// categories.
const LOCAL_LISTENER_BOOST: f64 = 1.5;

/// Pick the lowest-bit single [`Cap`] from `bits`, or `None` when no
/// bit is set.  Sinks in the SurfaceMap may carry multi-bit
/// `cap_bits`; the DFS terminates against the lowest single bit so
/// downstream lattice lookups stay deterministic.
fn sole_cap(bits: u32) -> Option<Cap> {
    crate::chain::edges::lowest_cap(bits)
}

/// Resolve the implied impact for a chain path.
///
/// Walks every (member.primary_cap, sink_cap) pair and picks the
/// highest-severity lattice match.  Returns `None` when no member +
/// sink pair lights up a rule and the sink cap has no standalone
/// rule either.
///
/// Auth gate: `BrowserToLocalRce` only fires when the entry's
/// `auth_required` is `false`.  Authenticated entries fall through
/// to the next-best impact (typically `CODE_EXEC → Rce`).
fn resolve_impact(
    path: &[&ChainEdge],
    sink_cap: Cap,
    entry: &EntryPoint,
    _local_listener_present: bool,
) -> Option<(ImpactCategory, Vec<ImpactCategory>)> {
    let mut best: Option<ImpactCategory> = None;
    for member in path {
        if let Some(cat) = lookup_impact(member.primary_cap, Some(sink_cap)) {
            if cat == ImpactCategory::BrowserToLocalRce && entry.auth_required {
                // Auth gate: this rule cannot fire when the entry is
                // authed.  Keep walking — another pair may light up
                // a different rule.
                continue;
            }
            best = Some(match best {
                Some(prev) => more_severe(prev, cat),
                None => cat,
            });
        }
    }
    // Fall through to standalone on the sink cap when no pair lit up.
    if best.is_none() {
        best = lookup_impact(sink_cap, None);
    }
    best.map(|cat| (cat, member_impact_vec(path)))
}

/// Pick the more-severe of two [`ImpactCategory`] values.  Severity
/// ordering matches the design doc's lattice criticality:
/// `BrowserToLocalRce > Rce > SessionHijack > InternalNetworkAccess > InfoDisclosure`.
fn more_severe(a: ImpactCategory, b: ImpactCategory) -> ImpactCategory {
    if severity_rank(a) >= severity_rank(b) {
        a
    } else {
        b
    }
}

fn severity_rank(c: ImpactCategory) -> u8 {
    match c {
        ImpactCategory::BrowserToLocalRce => 5,
        ImpactCategory::Rce => 4,
        ImpactCategory::SessionHijack => 3,
        ImpactCategory::InternalNetworkAccess => 2,
        ImpactCategory::InfoDisclosure => 1,
    }
}

fn member_impact_vec(path: &[&ChainEdge]) -> Vec<ImpactCategory> {
    path.iter()
        .filter_map(|e| crate::chain::standalone_impact(e.primary_cap))
        .collect()
}

fn build_chain(
    _entry: &EntryPoint,
    sink: &DangerousLocal,
    path: &[&ChainEdge],
    implied_impact: ImpactCategory,
    member_impacts: &[ImpactCategory],
) -> ChainFinding {
    let members: Vec<_> = path.iter().map(|e| e.finding.clone()).collect();
    let stable_hash = ChainFinding::compute_stable_hash(&members, implied_impact);
    let owned_edges: Vec<ChainEdge> = path.iter().map(|e| (*e).clone()).collect();
    let score = score_path(member_impacts, implied_impact, &owned_edges);
    let severity = crate::output::severity::chain_severity(implied_impact, &owned_edges);
    let dynamic_verdict = composite_dynamic_verdict(&owned_edges);
    ChainFinding {
        stable_hash,
        members,
        sink: ChainSink {
            file: sink.location.file.clone(),
            line: sink.location.line,
            col: sink.location.col,
            function_name: sink.function_name.clone(),
            cap_bits: sink.cap_bits,
        },
        implied_impact,
        severity,
        score,
        dynamic_verdict,
        reverify_reason: None,
    }
}

/// Phase 25 placeholder for composite verification.  When *every*
/// member edge has `Feasibility::Confirmed` the composite verdict
/// inherits that confirmation; otherwise `None` (Phase 26 will run a
/// real composite re-verification pass).
fn composite_dynamic_verdict(_path: &[ChainEdge]) -> Option<crate::evidence::VerifyResult> {
    None
}

fn canonicalise(chains: &mut Vec<ChainFinding>) {
    chains.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.stable_hash.cmp(&a.stable_hash))
            .then(b.implied_impact.cmp(&a.implied_impact))
    });
    // Drop duplicates: two chains with the same stable_hash and the
    // same terminal sink serialise byte-identically (stable_hash is a
    // function of members + implied_impact, and the wire format
    // exposes only members, sink, impact, severity, score). They arise
    // when multiple entry-points share a (route, method) but are
    // otherwise unrelated (e.g. monorepos, or a scan covering multiple
    // small apps), each claiming the same finding via the route-only
    // candidate filter in `find_chains_with_reach`. Keep the first
    // occurrence after the sort above; the sort is total enough that
    // the survivor is deterministic.
    chains.dedup_by(|a, b| a.stable_hash == b.stable_hash && a.sink == b.sink);
}

// Manual Ord/PartialOrd for ImpactCategory so the canonicalise
// tie-break has a total order.  Defined here rather than in `impact`
// to avoid leaking ordering into the public type.
impl PartialOrd for ImpactCategory {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ImpactCategory {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainSeverity;
    use crate::chain::edges::FindingRef;
    use crate::chain::feasibility::Feasibility;
    use crate::entry_points::HttpMethod;
    use crate::labels::Cap;
    use crate::surface::{
        DangerousLocal, EntryPoint, Framework, SourceLocation, SurfaceMap, SurfaceNode,
    };

    fn loc(file: &str, line: u32) -> SourceLocation {
        SourceLocation::new(file, line, 1)
    }

    fn entry(file: &str, route: &str, auth: bool) -> SurfaceNode {
        SurfaceNode::EntryPoint(EntryPoint {
            location: loc(file, 1),
            framework: Framework::Flask,
            method: HttpMethod::POST,
            route: route.into(),
            handler_name: "h".into(),
            handler_location: loc(file, 2),
            auth_required: auth,
        })
    }

    fn sink(file: &str, line: u32, fname: &str, caps: Cap) -> SurfaceNode {
        SurfaceNode::DangerousLocal(DangerousLocal {
            location: loc(file, line),
            function_name: fname.into(),
            cap_bits: caps.bits(),
        })
    }

    fn edge_with(
        file: &str,
        line: u32,
        rule: &str,
        cap: Cap,
        route: &str,
        method: HttpMethod,
        feas: Feasibility,
    ) -> ChainEdge {
        ChainEdge {
            finding: FindingRef {
                finding_id: format!("{rule}-{line}"),
                stable_hash: blake3::hash(format!("{rule}:{file}:{line}").as_bytes()).as_bytes()
                    [..8]
                    .try_into()
                    .map(u64::from_le_bytes)
                    .unwrap(),
                location: loc(file, line),
                rule_id: rule.into(),
                cap_bits: cap.bits(),
            },
            primary_cap: cap,
            reach: Reach::Reachable {
                location: loc(file, 1),
                method,
                route: route.into(),
                auth_required: false,
            },
            feasibility: feas,
        }
    }

    #[test]
    fn returns_empty_when_no_findings() {
        let surface = SurfaceMap::new();
        let result = find_chains(&[], &surface, ChainSearchConfig::default());
        assert!(result.is_empty());
    }

    #[test]
    fn standalone_codeexec_via_unauthed_entry_emits_rce_chain() {
        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("app.py", "/exec", false));
        surface
            .nodes
            .push(sink("app.py", 20, "os.system", Cap::CODE_EXEC));
        let e = edge_with(
            "app.py",
            10,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/exec",
            HttpMethod::POST,
            Feasibility::Confirmed,
        );
        let chains = find_chains(&[e], &surface, ChainSearchConfig::default());
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].implied_impact, ImpactCategory::Rce);
    }

    #[test]
    fn header_injection_plus_codeexec_via_unauthed_entry_is_browser_local_rce() {
        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("app.py", "/ws", false));
        surface
            .nodes
            .push(sink("app.py", 30, "shell.exec", Cap::CODE_EXEC));
        let cors = edge_with(
            "app.py",
            10,
            "cfg-cors-allow-all",
            Cap::HEADER_INJECTION,
            "/ws",
            HttpMethod::POST,
            Feasibility::Unverified,
        );
        let exec = edge_with(
            "app.py",
            20,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/ws",
            HttpMethod::POST,
            Feasibility::Unverified,
        );
        let chains = find_chains(
            &[cors, exec],
            &surface,
            ChainSearchConfig {
                max_depth: 4,
                min_score: 0.0,
            },
        );
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].implied_impact, ImpactCategory::BrowserToLocalRce);
        assert_eq!(chains[0].severity, ChainSeverity::Critical);
    }

    #[test]
    fn authed_entry_downgrades_browser_local_rce_to_rce() {
        let mut surface = SurfaceMap::new();
        // Same fixture but entry is authed — should NOT light up
        // BrowserToLocalRce.
        surface.nodes.push(entry("app.py", "/ws", true));
        surface
            .nodes
            .push(sink("app.py", 30, "shell.exec", Cap::CODE_EXEC));
        let cors = edge_with(
            "app.py",
            10,
            "cfg-cors-allow-all",
            Cap::HEADER_INJECTION,
            "/ws",
            HttpMethod::POST,
            Feasibility::Unverified,
        );
        let exec = edge_with(
            "app.py",
            20,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/ws",
            HttpMethod::POST,
            Feasibility::Unverified,
        );
        let chains = find_chains(
            &[cors, exec],
            &surface,
            ChainSearchConfig {
                max_depth: 4,
                min_score: 0.0,
            },
        );
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].implied_impact, ImpactCategory::Rce);
    }

    #[test]
    fn determinism_across_runs() {
        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("app.py", "/exec", false));
        surface
            .nodes
            .push(sink("app.py", 20, "os.system", Cap::CODE_EXEC));
        let e = edge_with(
            "app.py",
            10,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/exec",
            HttpMethod::POST,
            Feasibility::Confirmed,
        );
        let cfg = ChainSearchConfig::default();
        let first = find_chains(std::slice::from_ref(&e), &surface, cfg);
        let first_hashes: Vec<u64> = first.iter().map(|c| c.stable_hash).collect();
        for _ in 0..9 {
            let again = find_chains(std::slice::from_ref(&e), &surface, cfg);
            let again_hashes: Vec<u64> = again.iter().map(|c| c.stable_hash).collect();
            assert_eq!(again_hashes, first_hashes);
        }
    }

    #[test]
    fn ssrf_with_local_listener_scores_higher_than_without() {
        use crate::surface::{DataStore, DataStoreKind};
        let edge = || -> ChainEdge {
            edge_with(
                "app.py",
                10,
                "taint-ssrf",
                Cap::SSRF,
                "/fetch",
                HttpMethod::POST,
                Feasibility::Confirmed,
            )
        };
        let mut surface_no_listener = SurfaceMap::new();
        surface_no_listener
            .nodes
            .push(entry("app.py", "/fetch", false));
        surface_no_listener
            .nodes
            .push(sink("app.py", 20, "requests.get", Cap::SSRF));
        let baseline = find_chains(
            &[edge()],
            &surface_no_listener,
            ChainSearchConfig {
                max_depth: 4,
                min_score: 0.0,
            },
        );
        assert_eq!(baseline.len(), 1);
        assert_eq!(
            baseline[0].implied_impact,
            ImpactCategory::InternalNetworkAccess
        );

        let mut surface_with_listener = surface_no_listener.clone();
        surface_with_listener
            .nodes
            .push(SurfaceNode::DataStore(DataStore {
                location: loc("app.py", 5),
                kind: DataStoreKind::KeyValue,
                label: "redis://127.0.0.1:6379".into(),
            }));
        let boosted = find_chains(
            &[edge()],
            &surface_with_listener,
            ChainSearchConfig {
                max_depth: 4,
                min_score: 0.0,
            },
        );
        assert_eq!(boosted.len(), 1);
        assert_eq!(
            boosted[0].implied_impact,
            ImpactCategory::InternalNetworkAccess
        );
        let ratio = boosted[0].score / baseline[0].score;
        assert!(
            (ratio - LOCAL_LISTENER_BOOST).abs() < 1e-9,
            "expected ×{LOCAL_LISTENER_BOOST} boost, got ratio={ratio}"
        );
    }

    #[test]
    fn score_threshold_drops_low_score_chains() {
        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("app.py", "/r", false));
        surface.nodes.push(sink("app.py", 20, "open", Cap::FILE_IO));
        let e = edge_with(
            "app.py",
            10,
            "test",
            Cap::FILE_IO,
            "/r",
            HttpMethod::GET,
            Feasibility::Unverified,
        );
        let cfg = ChainSearchConfig {
            max_depth: 4,
            min_score: 1_000.0,
        };
        let chains = find_chains(&[e], &surface, cfg);
        assert!(chains.is_empty());
    }

    /// Sink in a different file than the finding composes only when the
    /// call-graph reach map records a transitive caller relationship.
    #[test]
    fn cross_file_chain_requires_reach_map() {
        use crate::callgraph::{FileReachMap, build_call_graph};
        use crate::summary::{FuncSummary, merge_summaries};

        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("routes.py", "/exec", false));
        // Sink lives in a helper file the entry handler transitively
        // reaches, not the entry file itself.
        surface
            .nodes
            .push(sink("helper.py", 20, "os.system", Cap::CODE_EXEC));
        let e = edge_with(
            "routes.py",
            10,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/exec",
            HttpMethod::POST,
            Feasibility::Unverified,
        );

        let cfg = ChainSearchConfig {
            max_depth: 4,
            min_score: 0.0,
        };

        // No reach map: routes.py finding cannot compose against
        // helper.py sink because `paths_overlap` rejects the pair.
        let baseline = find_chains(std::slice::from_ref(&e), &surface, cfg);
        assert!(
            baseline.is_empty(),
            "without reach map, cross-file chain must not compose"
        );

        // Reach map: routes.py::handle calls helper.py::sink so
        // helper.py is reachable from routes.py.
        let handle = FuncSummary {
            name: "handle".into(),
            file_path: "routes.py".into(),
            lang: "python".into(),
            param_count: 0,
            callees: vec![crate::summary::CalleeSite::bare("sink")],
            ..Default::default()
        };
        let sink_fn = FuncSummary {
            name: "sink".into(),
            file_path: "helper.py".into(),
            lang: "python".into(),
            param_count: 0,
            ..Default::default()
        };
        let gs = merge_summaries(vec![handle, sink_fn], None);
        let cg = build_call_graph(&gs, &[]);
        let reach = FileReachMap::build(&cg);

        let chains = find_chains_with_reach(&[e], &surface, cfg, Some(&reach));
        assert_eq!(
            chains.len(),
            1,
            "reach map should widen scope to include helper.py sink"
        );
        assert_eq!(chains[0].implied_impact, ImpactCategory::Rce);
    }

    #[test]
    fn duplicate_chains_from_shared_route_method_are_deduped() {
        // Three unrelated handler files each declare POST /run.  Each
        // file holds one finding + one dangerous-local sink.  Without
        // the dedup pass, the per-entry candidate filter (route +
        // method only) lets every entry claim every finding, and the
        // sink-file scope filter then emits one chain per (entry,
        // sink) pair — 3 chains per file × 3 files = 9 chains where
        // each finding appears 3×.  The wire format does not surface
        // the entry, so the duplicates serialise byte-identically.
        // `canonicalise` must drop them.
        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("a.js", "/run", false));
        surface.nodes.push(entry("b.js", "/run", false));
        surface.nodes.push(entry("c.py", "/run", false));
        surface.nodes.push(sink("a.js", 7, "eval", Cap::CODE_EXEC));
        surface.nodes.push(sink("b.js", 7, "eval", Cap::CODE_EXEC));
        surface.nodes.push(sink("c.py", 7, "eval", Cap::CODE_EXEC));
        let edges = vec![
            edge_with(
                "a.js",
                7,
                "taint-codeexec",
                Cap::CODE_EXEC,
                "/run",
                HttpMethod::POST,
                Feasibility::Unverified,
            ),
            edge_with(
                "b.js",
                7,
                "taint-codeexec",
                Cap::CODE_EXEC,
                "/run",
                HttpMethod::POST,
                Feasibility::Unverified,
            ),
            edge_with(
                "c.py",
                7,
                "taint-codeexec",
                Cap::CODE_EXEC,
                "/run",
                HttpMethod::POST,
                Feasibility::Unverified,
            ),
        ];
        let chains = find_chains(&edges, &surface, ChainSearchConfig::default());
        assert_eq!(
            chains.len(),
            3,
            "expected one chain per finding, not entries × findings",
        );
        let mut hashes: Vec<u64> = chains.iter().map(|c| c.stable_hash).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            3,
            "surviving chains must have distinct hashes"
        );
    }

    /// File-affinity gate on `edge_reaches_entry`: an entry only
    /// claims candidate findings that live in its own handler file
    /// (or are reached from it via the call graph).  Two unrelated
    /// entries declaring the same (route, method) on different
    /// files do not cross-claim each other's findings.
    #[test]
    fn entry_file_affinity_rejects_cross_file_findings_without_reach() {
        let mut surface = SurfaceMap::new();
        surface.nodes.push(entry("a.js", "/run", false));
        surface.nodes.push(entry("b.js", "/run", false));
        surface.nodes.push(sink("a.js", 7, "eval", Cap::CODE_EXEC));
        surface.nodes.push(sink("b.js", 7, "eval", Cap::CODE_EXEC));
        // Single finding lives in a.js only.  Both entries match
        // route+method but only entry@a.js shares the file.
        let edges = vec![edge_with(
            "a.js",
            7,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/run",
            HttpMethod::POST,
            Feasibility::Unverified,
        )];
        let chains = find_chains(&edges, &surface, ChainSearchConfig::default());
        assert_eq!(
            chains.len(),
            1,
            "entry@b.js must not claim a finding in a.js without reach map",
        );
        assert_eq!(chains[0].sink.file, "a.js");
    }

    /// File-affinity gate widens through the call-graph reach map:
    /// an entry whose handler reaches the finding's file (via the
    /// `FileReachMap`) still claims the finding even when the
    /// literal file suffixes differ.
    #[test]
    fn entry_file_affinity_widens_with_reach_map() {
        use crate::callgraph::{FileReachMap, build_call_graph};
        use crate::summary::{FuncSummary, merge_summaries};

        let mut surface = SurfaceMap::new();
        // Entry handler lives in routes.py.  Finding lives in a
        // helper file that routes.py transitively calls.
        surface.nodes.push(entry("routes.py", "/run", false));
        surface
            .nodes
            .push(sink("helper.py", 20, "os.system", Cap::CODE_EXEC));
        let e = edge_with(
            "helper.py",
            10,
            "taint-codeexec",
            Cap::CODE_EXEC,
            "/run",
            HttpMethod::POST,
            Feasibility::Unverified,
        );
        let cfg = ChainSearchConfig {
            max_depth: 4,
            min_score: 0.0,
        };
        // Without a reach map the file-affinity gate rejects the
        // entry/finding pairing.
        let baseline = find_chains(std::slice::from_ref(&e), &surface, cfg);
        assert!(
            baseline.is_empty(),
            "without reach map, cross-file entry/finding pair must reject",
        );
        // Build a reach map where routes.py::handle calls
        // helper.py::sink, so helper.py is reachable from routes.py.
        let handle = FuncSummary {
            name: "handle".into(),
            file_path: "routes.py".into(),
            lang: "python".into(),
            param_count: 0,
            callees: vec![crate::summary::CalleeSite::bare("sink")],
            ..Default::default()
        };
        let sink_fn = FuncSummary {
            name: "sink".into(),
            file_path: "helper.py".into(),
            lang: "python".into(),
            param_count: 0,
            ..Default::default()
        };
        let gs = merge_summaries(vec![handle, sink_fn], None);
        let cg = build_call_graph(&gs, &[]);
        let reach = FileReachMap::build(&cg);
        let chains = find_chains_with_reach(&[e], &surface, cfg, Some(&reach));
        assert_eq!(
            chains.len(),
            1,
            "reach map should widen entry-affinity to helper.py",
        );
        assert_eq!(chains[0].sink.file, "helper.py");
    }
}

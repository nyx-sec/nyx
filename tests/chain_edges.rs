//! Phase 24 acceptance: each impact-lattice rule fires on a synthetic
//! finding + SurfaceMap pair.
//!
//! Mirrors the test plan in `.pitboss/play/plan.md` (Phase 24):
//! "Tests: `tests/chain_edges.rs` covers each impact rule on a
//! synthetic SurfaceMap."  Each `#[test]` builds the minimal Diag(s)
//! that should trigger one rule, runs `findings_to_edges`, then
//! confirms that the resulting edge's primary cap (plus, where the
//! rule needs adjacency, a second edge's cap) classifies through
//! `lookup_impact` to the expected `ImpactCategory`.
//!
//! Lattice (from the design doc, paraphrased — Cap approximations
//! documented in `src/chain/impact.rs`):
//!
//! | Static caps                          | Impact                  |
//! |--------------------------------------|-------------------------|
//! | `CODE_EXEC`                          | `Rce`                   |
//! | `DESERIALIZE`                        | `Rce`                   |
//! | `SSRF`                               | `InternalNetworkAccess` |
//! | `OPEN_REDIRECT + UNAUTHORIZED_ID`    | `SessionHijack`         |
//! | `HEADER_INJECTION + CODE_EXEC`       | `BrowserToLocalRce`     |
//! | `FILE_IO + DATA_EXFIL`               | `InfoDisclosure`        |

use nyx_scanner::chain::edges::{ChainEdge, Reach, findings_to_edges};
use nyx_scanner::chain::feasibility::Feasibility;
use nyx_scanner::chain::impact::{ImpactCategory, lookup_impact};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::entry_points::HttpMethod;
use nyx_scanner::evidence::{Confidence, Evidence};
use nyx_scanner::labels::Cap;
use nyx_scanner::patterns::{FindingCategory, Severity};
use nyx_scanner::surface::{EntryPoint, Framework, SourceLocation, SurfaceMap, SurfaceNode};

fn diag_with_caps(path: &str, line: usize, caps: Cap) -> Diag {
    Diag {
        path: path.into(),
        line,
        col: 1,
        severity: Severity::High,
        id: "taint-test".into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::Medium),
        evidence: Some(Evidence {
            sink_caps: caps.bits(),
            ..Evidence::default()
        }),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash: 0,
    }
}

fn synthetic_surface(handler_file: &str, route: &str) -> SurfaceMap {
    let mut m = SurfaceMap::new();
    m.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
        location: SourceLocation::new(handler_file, 1, 1),
        framework: Framework::Flask,
        method: HttpMethod::GET,
        route: route.into(),
        handler_name: "handler".into(),
        handler_location: SourceLocation::new(handler_file, 2, 1),
        auth_required: false,
    }));
    m
}

fn single_edge(diag: Diag, surface: &SurfaceMap) -> ChainEdge {
    let mut edges = findings_to_edges(&[diag], surface);
    assert_eq!(edges.len(), 1, "expected exactly one edge");
    edges.pop().unwrap()
}

#[test]
fn rule_cmdi_alone_maps_to_rce() {
    let surface = synthetic_surface("app.py", "/run");
    let edge = single_edge(diag_with_caps("app.py", 12, Cap::CODE_EXEC), &surface);
    assert_eq!(edge.primary_cap, Cap::CODE_EXEC);
    assert!(matches!(edge.reach, Reach::Reachable { .. }));
    assert_eq!(
        lookup_impact(edge.primary_cap, None),
        Some(ImpactCategory::Rce)
    );
}

#[test]
fn rule_deserialize_alone_maps_to_rce() {
    let surface = synthetic_surface("app.py", "/load");
    let edge = single_edge(diag_with_caps("app.py", 7, Cap::DESERIALIZE), &surface);
    assert_eq!(edge.primary_cap, Cap::DESERIALIZE);
    assert_eq!(
        lookup_impact(edge.primary_cap, None),
        Some(ImpactCategory::Rce)
    );
}

#[test]
fn rule_ssrf_alone_maps_to_internal_network_access() {
    let surface = synthetic_surface("fetch.py", "/proxy");
    let edge = single_edge(diag_with_caps("fetch.py", 4, Cap::SSRF), &surface);
    assert_eq!(edge.primary_cap, Cap::SSRF);
    assert_eq!(
        lookup_impact(edge.primary_cap, None),
        Some(ImpactCategory::InternalNetworkAccess)
    );
}

#[test]
fn rule_open_redirect_plus_user_session_maps_to_session_hijack() {
    let surface = synthetic_surface("auth.py", "/login");
    let redirect = diag_with_caps("auth.py", 11, Cap::OPEN_REDIRECT);
    let user_id = diag_with_caps("auth.py", 18, Cap::UNAUTHORIZED_ID);
    let edges = findings_to_edges(&[redirect, user_id], &surface);
    assert_eq!(edges.len(), 2);
    let caps: Vec<Cap> = edges.iter().map(|e| e.primary_cap).collect();
    assert!(caps.contains(&Cap::OPEN_REDIRECT));
    assert!(caps.contains(&Cap::UNAUTHORIZED_ID));
    assert_eq!(
        lookup_impact(Cap::OPEN_REDIRECT, Some(Cap::UNAUTHORIZED_ID)),
        Some(ImpactCategory::SessionHijack)
    );
}

#[test]
fn rule_cors_plus_codeexec_maps_to_browser_local_rce() {
    let surface = synthetic_surface("api.py", "/exec");
    let cors = diag_with_caps("api.py", 3, Cap::HEADER_INJECTION);
    let code = diag_with_caps("api.py", 14, Cap::CODE_EXEC);
    let edges = findings_to_edges(&[cors, code], &surface);
    assert_eq!(edges.len(), 2);
    assert_eq!(
        lookup_impact(Cap::HEADER_INJECTION, Some(Cap::CODE_EXEC)),
        Some(ImpactCategory::BrowserToLocalRce)
    );
}

#[test]
fn rule_path_traversal_plus_sensitive_io_maps_to_info_disclosure() {
    let surface = synthetic_surface("files.py", "/download");
    let trav = diag_with_caps("files.py", 5, Cap::FILE_IO);
    let exfil = diag_with_caps("files.py", 9, Cap::DATA_EXFIL);
    let edges = findings_to_edges(&[trav, exfil], &surface);
    assert_eq!(edges.len(), 2);
    assert_eq!(
        lookup_impact(Cap::FILE_IO, Some(Cap::DATA_EXFIL)),
        Some(ImpactCategory::InfoDisclosure)
    );
}

#[test]
fn findings_without_sink_caps_are_dropped() {
    let surface = synthetic_surface("a.py", "/");
    let mut d = diag_with_caps("a.py", 1, Cap::CODE_EXEC);
    d.evidence.as_mut().unwrap().sink_caps = 0;
    let edges = findings_to_edges(&[d], &surface);
    assert!(edges.is_empty());
}

#[test]
fn finding_in_file_with_no_entry_point_is_unreachable() {
    let surface = synthetic_surface("app.py", "/");
    let edge = single_edge(
        diag_with_caps("internal_helper.py", 1, Cap::CODE_EXEC),
        &surface,
    );
    assert!(matches!(edge.reach, Reach::Unreachable));
}

#[test]
fn feasibility_defaults_to_unverified() {
    let surface = synthetic_surface("app.py", "/");
    let edge = single_edge(diag_with_caps("app.py", 1, Cap::CODE_EXEC), &surface);
    assert_eq!(edge.feasibility, Feasibility::Unverified);
}

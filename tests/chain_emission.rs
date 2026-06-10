//! Phase 25 — exploit-chain emission integration tests.
//!
//! Covers the design-doc example: a permissive-CORS finding plus an
//! unauthenticated entry-point plus a code-exec sink → one Critical
//! `BrowserToLocalRce` chain with three members.  Also exercises
//! determinism (10 reruns produce byte-identical chain lists) and
//! SARIF-shape validation of the emitted `runs[0].properties.chains`
//! array.

use nyx_scanner::chain::finding::ChainSeverity;
use nyx_scanner::chain::impact::ImpactCategory;
use nyx_scanner::chain::{ChainEdge, ChainSearchConfig, find_chains};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::entry_points::HttpMethod;
use nyx_scanner::evidence::Evidence;
use nyx_scanner::labels::Cap;
use nyx_scanner::output::{build_findings_json, build_sarif_with_chains};
use nyx_scanner::patterns::{FindingCategory, Severity};
use nyx_scanner::surface::{
    DangerousLocal, EntryPoint, Framework, SourceLocation, SurfaceMap, SurfaceNode,
};

fn loc(file: &str, line: u32) -> SourceLocation {
    SourceLocation::new(file, line, 1)
}

/// Build the SurfaceMap for the design-doc scenario:
///
/// - One Flask entry-point at `app.py:1`, route `/ws`, method `POST`,
///   `auth_required: false`  (the NoAuth half of CORS+NoAuth+websocket).
/// - One DangerousLocal sink at `app.py:30`, function `shell.exec`,
///   Cap::CODE_EXEC (the shell tool sink).
fn fixture_surface_map() -> SurfaceMap {
    let mut m = SurfaceMap::new();
    m.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
        location: loc("app.py", 1),
        framework: Framework::Flask,
        method: HttpMethod::POST,
        route: "/ws".into(),
        handler_name: "ws_handler".into(),
        handler_location: loc("app.py", 2),
        auth_required: false,
    }));
    m.nodes.push(SurfaceNode::DangerousLocal(DangerousLocal {
        location: loc("app.py", 30),
        function_name: "shell.exec".into(),
        cap_bits: Cap::CODE_EXEC.bits(),
        label: String::new(),
    }));
    m
}

/// Build the three constituent findings for the scenario:
///
/// - `d1` — permissive-CORS header injection at `app.py:10`.
/// - `d2` — auth-gap diagnostic at `app.py:15` (cfg-auth-gap; carries
///   `Cap::UNAUTHORIZED_ID` so the lattice has a third member, but the
///   primary chain match is HEADER_INJECTION + CODE_EXEC).
/// - `d3` — shell-exec taint finding at `app.py:25`.
fn fixture_findings() -> Vec<Diag> {
    let mk = |line: usize, rule: &str, cap: Cap, sev: Severity| {
        let ev = Evidence {
            sink_caps: cap.bits(),
            ..Evidence::default()
        };
        let mut d = Diag {
            path: "app.py".into(),
            line,
            col: 1,
            severity: sev,
            id: rule.into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: Some(ev),
            rank_score: None,
            rank_reason: None,
            exposure: None,
            suppressed: false,
            suppression: None,
            triage_state: "open".to_string(),
            triage_note: String::new(),
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        d.stable_hash = nyx_scanner::commands::scan::compute_stable_hash(&d);
        d
    };
    vec![
        mk(
            10,
            "cfg-cors-allow-all",
            Cap::HEADER_INJECTION,
            Severity::Medium,
        ),
        mk(15, "cfg-auth-gap", Cap::UNAUTHORIZED_ID, Severity::Medium),
        mk(25, "taint-shell-exec", Cap::CODE_EXEC, Severity::High),
    ]
}

fn build_chain_edges_for_route(findings: &[Diag], route: &str) -> Vec<ChainEdge> {
    // findings_to_edges sets reach from the SurfaceMap; the design-doc
    // scenario has every finding live in the same file as the entry,
    // so the file-local reach resolver maps every edge to the entry.
    let surface = fixture_surface_map();
    let edges = nyx_scanner::chain::findings_to_edges(findings, &surface);
    edges
        .into_iter()
        .map(|mut e| {
            // Tighten the reach to the exact route so the DFS pairs
            // each edge with the right entry deterministically.
            e.reach = nyx_scanner::chain::edges::Reach::Reachable {
                location: loc("app.py", 1),
                method: HttpMethod::POST,
                route: route.into(),
                auth_required: false,
            };
            e
        })
        .collect()
}

#[test]
fn cors_plus_noauth_plus_websocket_emits_one_critical_chain() {
    let surface = fixture_surface_map();
    let findings = fixture_findings();
    let edges = build_chain_edges_for_route(&findings, "/ws");
    let chains = find_chains(
        &edges,
        &surface,
        ChainSearchConfig {
            max_depth: 4,
            min_score: 0.0,
        },
    );
    assert_eq!(
        chains.len(),
        1,
        "expected exactly one chain, got {chains:?}"
    );
    let chain = &chains[0];
    assert_eq!(chain.implied_impact, ImpactCategory::BrowserToLocalRce);
    assert_eq!(chain.severity, ChainSeverity::Critical);
    assert_eq!(chain.members.len(), 3, "expected three constituent members");
    assert_eq!(chain.sink.function_name, "shell.exec");
    assert_eq!(chain.sink.cap_bits, Cap::CODE_EXEC.bits());
}

#[test]
fn chain_set_is_byte_deterministic_across_10_reruns() {
    let surface = fixture_surface_map();
    let findings = fixture_findings();
    let edges = build_chain_edges_for_route(&findings, "/ws");
    let cfg = ChainSearchConfig {
        max_depth: 4,
        min_score: 0.0,
    };

    let first = find_chains(&edges, &surface, cfg);
    let first_json = serde_json::to_string(&first).unwrap();
    for i in 0..9 {
        let again = find_chains(&edges, &surface, cfg);
        let again_json = serde_json::to_string(&again).unwrap();
        assert_eq!(
            again_json, first_json,
            "chain emission diverged on rerun {i}"
        );
        // stable_hash is a 64-bit fingerprint — verify it does not
        // drift across reruns even when the JSON happens to match
        // (defence in depth against accidental hash randomisation).
        let again_hashes: Vec<u64> = again.iter().map(|c| c.stable_hash).collect();
        let first_hashes: Vec<u64> = first.iter().map(|c| c.stable_hash).collect();
        assert_eq!(again_hashes, first_hashes, "stable_hash drift on rerun {i}");
    }
}

#[test]
fn json_output_carries_chain_member_of_back_references() {
    let surface = fixture_surface_map();
    let findings = fixture_findings();
    let edges = build_chain_edges_for_route(&findings, "/ws");
    let chains = find_chains(
        &edges,
        &surface,
        ChainSearchConfig {
            max_depth: 4,
            min_score: 0.0,
        },
    );

    let value = build_findings_json(&findings, &chains, None);
    let chains_json = value["chains"].as_array().unwrap();
    assert_eq!(chains_json.len(), 1);
    let chain_hash = chains_json[0]["stable_hash"].as_u64().unwrap();

    let findings_json = value["findings"].as_array().unwrap();
    let with_back_refs: Vec<_> = findings_json
        .iter()
        .filter(|f| f.get("chain_member_of").is_some())
        .collect();
    assert_eq!(
        with_back_refs.len(),
        3,
        "every constituent finding should carry chain_member_of"
    );
    for f in with_back_refs {
        assert_eq!(f["chain_member_of"].as_u64(), Some(chain_hash));
    }
}

#[test]
fn sarif_output_validates_against_v210_shape() {
    let surface = fixture_surface_map();
    let findings = fixture_findings();
    let edges = build_chain_edges_for_route(&findings, "/ws");
    let chains = find_chains(
        &edges,
        &surface,
        ChainSearchConfig {
            max_depth: 4,
            min_score: 0.0,
        },
    );
    let sarif = build_sarif_with_chains(&findings, &chains, std::path::Path::new("."));

    // Surface-level v2.1.0 invariants — the SARIF schema requires
    // these fields and we want a tripwire if any disappear.
    assert_eq!(sarif["version"], "2.1.0", "missing or wrong version field");
    assert!(sarif["$schema"].is_string(), "$schema must be a string");
    assert!(sarif["runs"].is_array(), "runs must be an array");
    assert_eq!(
        sarif["runs"].as_array().unwrap().len(),
        1,
        "exactly one run"
    );

    let run = &sarif["runs"][0];
    assert!(run["tool"]["driver"]["name"].is_string());
    assert_eq!(run["tool"]["driver"]["name"], "nyx");
    assert!(run["tool"]["driver"]["rules"].is_array());
    assert!(run["results"].is_array());

    // Phase 25 extension: chains land on run.properties.chains.
    let chains_array = run["properties"]["chains"].as_array().unwrap();
    assert_eq!(chains_array.len(), 1, "exactly one chain emitted");

    // Every chain object carries the documented shape.
    let chain = &chains_array[0];
    assert!(chain["stable_hash"].is_number());
    assert!(chain["members"].is_array());
    assert_eq!(chain["members"].as_array().unwrap().len(), 3);
    assert!(chain["sink"].is_object());
    assert!(chain["implied_impact"].is_string());
    assert_eq!(chain["severity"], "critical");

    // Per-result `chain_member_of` cross-reference.
    let results = run["results"].as_array().unwrap();
    let with_back_refs = results
        .iter()
        .filter(|r| r["properties"].get("chain_member_of").is_some())
        .count();
    assert_eq!(
        with_back_refs, 3,
        "every constituent SARIF result should carry chain_member_of"
    );
}

#[test]
fn determinism_across_input_permutations() {
    // Same set of findings in two different orders must yield the
    // same chain set (the composer canonicalises by stable_hash).
    let surface = fixture_surface_map();
    let findings = fixture_findings();
    let cfg = ChainSearchConfig {
        max_depth: 4,
        min_score: 0.0,
    };

    let order_a = build_chain_edges_for_route(&findings, "/ws");
    let mut findings_rev = findings.clone();
    findings_rev.reverse();
    let order_b = build_chain_edges_for_route(&findings_rev, "/ws");

    let chains_a = find_chains(&order_a, &surface, cfg);
    let chains_b = find_chains(&order_b, &surface, cfg);
    let hashes_a: Vec<u64> = chains_a.iter().map(|c| c.stable_hash).collect();
    let hashes_b: Vec<u64> = chains_b.iter().map(|c| c.stable_hash).collect();
    assert_eq!(hashes_a, hashes_b);
}

#[test]
fn authed_entry_downgrades_to_rce_without_browser_local() {
    let mut surface = fixture_surface_map();
    // Flip auth_required on the entry — should downgrade the chain.
    if let SurfaceNode::EntryPoint(ref mut e) = surface.nodes[0] {
        e.auth_required = true;
    }
    let findings = fixture_findings();
    let edges = build_chain_edges_for_route(&findings, "/ws");
    let chains = find_chains(
        &edges,
        &surface,
        ChainSearchConfig {
            max_depth: 4,
            min_score: 0.0,
        },
    );
    assert_eq!(chains.len(), 1);
    assert_eq!(
        chains[0].implied_impact,
        ImpactCategory::Rce,
        "auth-gated entry must not produce BrowserToLocalRce"
    );
    assert_eq!(chains[0].severity, ChainSeverity::Critical);
}

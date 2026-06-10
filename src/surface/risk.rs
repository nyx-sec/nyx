//! Per-entry-point risk assessment over the [`SurfaceMap`].
//!
//! Computed on demand from the canonicalised node + edge lists, never
//! persisted: the same map always yields the same risks, and keeping
//! the scoring out of the schema means a tuning change does not need a
//! SQLite migration.  Consumed by the `nyx surface` CLI (risk-sorted
//! tree + "top risks" banner) and available to the HTTP API.
//!
//! The model is deliberately simple and explainable: each entry point
//! accumulates points from the sink classes it can reach (worst class
//! dominates, additional classes contribute a small spread bonus), the
//! stores it can write, and the services it talks to; missing auth
//! multiplies the whole thing.  Every contribution is recorded as a
//! human-readable factor so the CLI can print *why* a route is rated
//! `critical` instead of an opaque number.

use super::{DataStoreKind, EdgeKind, EntryPoint, SurfaceMap, SurfaceNode, cap_labels};
use crate::labels::Cap;
use serde::{Deserialize, Serialize};

/// Coarse risk tier derived from the numeric score.  Thresholds are
/// documented on [`RiskTier::from_score`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskTier {
    /// Tier thresholds.  Calibrated so that:
    /// * an unauthenticated route reaching a code-exec sink is
    ///   `Critical` (40 × 1.5 + 5 ≥ 60);
    /// * the same route behind auth is `High` (40 ≥ 35);
    /// * an unauthenticated route writing a SQL store is `High`
    ///   ((15 + 5) × 1.5 + 5 = 35 ≥ 35);
    /// * an unauthenticated route that only reads a SQL store
    ///   (15 × 1.5 + 5 = 27) or talks to one external service
    ///   (8 × 1.5 + 5 = 17) is `Medium`;
    /// * the same single read / single egress *behind auth* (no ×1.5
    ///   scaling) usually stays `Low` — an auth-gated KV/document read
    ///   (10) or one external call (8) is below the 12 threshold;
    /// * a route with no reachable destination at all is `Low`.
    pub fn from_score(score: f64) -> Self {
        if score >= 60.0 {
            RiskTier::Critical
        } else if score >= 35.0 {
            RiskTier::High
        } else if score >= 12.0 {
            RiskTier::Medium
        } else {
            RiskTier::Low
        }
    }

    /// Lowercase display tag (`critical` / `high` / `medium` / `low`).
    pub fn tag(self) -> &'static str {
        match self {
            RiskTier::Critical => "critical",
            RiskTier::High => "high",
            RiskTier::Medium => "medium",
            RiskTier::Low => "low",
        }
    }
}

/// Risk assessment for one entry point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryRisk {
    /// Index of the [`SurfaceNode::EntryPoint`] in the canonicalised
    /// `SurfaceMap::nodes` vector.
    pub entry_idx: usize,
    pub score: f64,
    pub tier: RiskTier,
    /// Human-readable contributions, worst first (e.g.
    /// `["unauthenticated", "reaches code-exec sink", "writes sql store"]`).
    pub factors: Vec<String>,
}

/// Points for the worst dangerous-local sink class reachable from an
/// entry.  Cap order mirrors exploit impact: full code execution
/// dominates, then deserialisation (usually RCE-equivalent), SSTI,
/// the injection family, format strings.
fn dangerous_points(bits: u32) -> f64 {
    let caps = Cap::from_bits_truncate(bits);
    if caps.contains(Cap::CODE_EXEC) {
        40.0
    } else if caps.contains(Cap::DESERIALIZE) {
        35.0
    } else if caps.contains(Cap::SSTI) {
        30.0
    } else if caps.intersects(Cap::XXE | Cap::LDAP_INJECTION | Cap::XPATH_INJECTION) {
        22.0
    } else if caps.intersects(Cap::PROTOTYPE_POLLUTION | Cap::HEADER_INJECTION) {
        18.0
    } else if caps.contains(Cap::FMT_STRING) {
        15.0
    } else if caps.contains(Cap::OPEN_REDIRECT) {
        10.0
    } else {
        8.0
    }
}

/// Assess every entry point in `map`.  Returns one [`EntryRisk`] per
/// entry-point node, sorted by score descending (ties broken by node
/// index so the output is deterministic).
pub fn assess_entry_risks(map: &SurfaceMap) -> Vec<EntryRisk> {
    let mut out: Vec<EntryRisk> = Vec::new();
    for (idx, node) in map.nodes.iter().enumerate() {
        let SurfaceNode::EntryPoint(ep) = node else {
            continue;
        };
        out.push(assess_one(map, idx, ep));
    }
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.entry_idx.cmp(&b.entry_idx))
    });
    out
}

fn assess_one(map: &SurfaceMap, entry_idx: usize, ep: &EntryPoint) -> EntryRisk {
    let mut factors: Vec<String> = Vec::new();
    let mut score = 0.0_f64;

    // Worst reachable dangerous-local class dominates; each *additional*
    // dangerous destination adds a small spread bonus so a route that
    // reaches eval *and* pickle.loads outranks one that only reaches eval.
    let mut worst_dangerous: Option<(f64, u32)> = None;
    let mut extra_dangerous = 0usize;
    let mut writes_store: Option<DataStoreKind> = None;
    let mut reads_store: Option<DataStoreKind> = None;
    let mut talks_external = 0usize;

    for edge in &map.edges {
        if edge.from != entry_idx as u32 || !edge.kind.is_reach_like() {
            continue;
        }
        match map.nodes.get(edge.to as usize) {
            Some(SurfaceNode::DangerousLocal(dl)) => {
                let pts = dangerous_points(dl.cap_bits);
                match &mut worst_dangerous {
                    Some((best, best_bits)) => {
                        extra_dangerous += 1;
                        if pts > *best {
                            *best = pts;
                            *best_bits = dl.cap_bits;
                        }
                    }
                    None => worst_dangerous = Some((pts, dl.cap_bits)),
                }
            }
            Some(SurfaceNode::DataStore(ds)) => {
                if matches!(edge.kind, EdgeKind::WritesTo) {
                    // Keep the most severe store kind: SQL > filesystem > rest.
                    writes_store = Some(worse_store(writes_store, ds.kind));
                } else {
                    reads_store = Some(worse_store(reads_store, ds.kind));
                }
            }
            Some(SurfaceNode::ExternalService(_)) => talks_external += 1,
            _ => {}
        }
    }

    if let Some((pts, bits)) = worst_dangerous {
        score += pts;
        factors.push(format!(
            "reaches {} sink",
            cap_labels(bits).first().copied().unwrap_or("dangerous")
        ));
        if extra_dangerous > 0 {
            let spread = (extra_dangerous as f64 * 2.0).min(10.0);
            score += spread;
            factors.push(format!("{extra_dangerous} more dangerous sink(s)"));
        }
    }
    if let Some(kind) = writes_store {
        let pts = store_points(kind) + 5.0;
        score += pts;
        factors.push(format!("writes {} store", store_tag(kind)));
    } else if let Some(kind) = reads_store {
        let pts = store_points(kind);
        score += pts;
        factors.push(format!("reads {} store", store_tag(kind)));
    }
    if talks_external > 0 {
        score += 8.0;
        factors.push(format!("talks to {talks_external} external service(s)"));
    }
    if mutating_method(ep) {
        score += 3.0;
        factors.push(format!("mutating method ({:?})", ep.method));
    }

    // Auth multiplier last: missing auth scales the whole exposure, it
    // does not merely add a constant.  An unauthenticated route with
    // nothing reachable lands at 5 and stays Low.
    if ep.auth_required {
        factors.push("auth-gated".into());
    } else {
        score = score * 1.5 + 5.0;
        factors.insert(0, "unauthenticated".into());
    }

    EntryRisk {
        entry_idx,
        score,
        tier: RiskTier::from_score(score),
        factors,
    }
}

fn store_points(kind: DataStoreKind) -> f64 {
    match kind {
        DataStoreKind::Sql => 15.0,
        DataStoreKind::Filesystem => 12.0,
        DataStoreKind::Document | DataStoreKind::KeyValue | DataStoreKind::BlobStore => 10.0,
        DataStoreKind::Unknown => 8.0,
    }
}

fn store_tag(kind: DataStoreKind) -> &'static str {
    match kind {
        DataStoreKind::Sql => "sql",
        DataStoreKind::Filesystem => "filesystem",
        DataStoreKind::Document => "document",
        DataStoreKind::KeyValue => "key-value",
        DataStoreKind::BlobStore => "blob",
        DataStoreKind::Unknown => "unknown",
    }
}

/// Keep the more severe of two store kinds (SQL > filesystem > rest).
fn worse_store(current: Option<DataStoreKind>, new: DataStoreKind) -> DataStoreKind {
    match current {
        None => new,
        Some(cur) => {
            if store_points(new) > store_points(cur) {
                new
            } else {
                cur
            }
        }
    }
}

fn mutating_method(ep: &EntryPoint) -> bool {
    use crate::entry_points::HttpMethod;
    matches!(
        ep.method,
        HttpMethod::POST | HttpMethod::PUT | HttpMethod::PATCH | HttpMethod::DELETE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_points::HttpMethod;
    use crate::surface::{
        DangerousLocal, DataStore, EntryPoint, Framework, SourceLocation, SurfaceEdge,
    };

    fn ep(auth: bool, method: HttpMethod) -> SurfaceNode {
        SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new("app.py", 1, 1),
            framework: Framework::Flask,
            method,
            route: "/x".into(),
            handler_name: "h".into(),
            handler_location: SourceLocation::new("app.py", 2, 1),
            auth_required: auth,
        })
    }

    fn dangerous(cap: Cap) -> SurfaceNode {
        SurfaceNode::DangerousLocal(DangerousLocal {
            location: SourceLocation::new("app.py", 9, 1),
            function_name: "danger".into(),
            cap_bits: cap.bits(),
            label: String::new(),
        })
    }

    #[test]
    fn unauth_code_exec_is_critical() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep(false, HttpMethod::GET));
        map.nodes.push(dangerous(Cap::CODE_EXEC));
        map.edges.push(SurfaceEdge {
            from: 0,
            to: 1,
            kind: EdgeKind::Reaches,
        });
        let risks = assess_entry_risks(&map);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].tier, RiskTier::Critical);
        assert!(risks[0].factors.iter().any(|f| f == "unauthenticated"));
        assert!(
            risks[0].factors.iter().any(|f| f.contains("code-exec")),
            "factors: {:?}",
            risks[0].factors
        );
    }

    #[test]
    fn auth_gating_downgrades_tier() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep(true, HttpMethod::GET));
        map.nodes.push(dangerous(Cap::CODE_EXEC));
        map.edges.push(SurfaceEdge {
            from: 0,
            to: 1,
            kind: EdgeKind::Reaches,
        });
        let risks = assess_entry_risks(&map);
        assert_eq!(risks[0].tier, RiskTier::High);
        assert!(risks[0].factors.iter().any(|f| f == "auth-gated"));
    }

    #[test]
    fn unreached_entry_is_low() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep(false, HttpMethod::GET));
        let risks = assess_entry_risks(&map);
        assert_eq!(risks[0].tier, RiskTier::Low);
    }

    #[test]
    fn sql_write_outranks_sql_read() {
        let store = |access| {
            SurfaceNode::DataStore(DataStore {
                location: SourceLocation::new("app.py", 5, 1),
                kind: DataStoreKind::Sql,
                label: "pg".into(),
                owner: "h".into(),
                access,
            })
        };
        let build = |kind: EdgeKind, access| {
            let mut map = SurfaceMap::new();
            map.nodes.push(ep(false, HttpMethod::GET));
            map.nodes.push(store(access));
            map.edges.push(SurfaceEdge {
                from: 0,
                to: 1,
                kind,
            });
            assess_entry_risks(&map)[0].score
        };
        let write = build(EdgeKind::WritesTo, crate::surface::AccessMode::Write);
        let read = build(EdgeKind::ReadsFrom, crate::surface::AccessMode::Read);
        assert!(write > read, "write {write} should outrank read {read}");
    }

    #[test]
    fn risks_sorted_descending() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep(true, HttpMethod::GET)); // 0: low
        map.nodes.push(ep(false, HttpMethod::POST)); // 1: reaches sink
        map.nodes.push(dangerous(Cap::CODE_EXEC)); // 2
        map.edges.push(SurfaceEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Reaches,
        });
        let risks = assess_entry_risks(&map);
        assert_eq!(risks[0].entry_idx, 1);
        assert!(risks[0].score > risks[1].score);
    }
}

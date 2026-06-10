//! Finding-level exposure: which surface entry-point can drive a given
//! source location, and is it auth-gated?
//!
//! This is the bridge that makes the attack surface participate in the
//! core finding pipeline instead of living off to the side in `nyx
//! surface`: every [`Diag`] gets an
//! optional [`Exposure`] annotation describing the *worst-case* route
//! that reaches it (unauthenticated preferred over auth-gated, direct
//! file match preferred over transitive call-graph reach), and the
//! ranking layer turns that into a score component so externally
//! reachable findings sort above internal ones.
//!
//! Matching granularity is file-level, same as the chain composer's
//! [`Reach`](crate::chain::edges::Reach): a finding in `views.py` is exposed
//! when an entry-point's handler lives in `views.py`, or — when a
//! [`FileReachMap`] is supplied — when some handler's file transitively
//! reaches `views.py` through the call graph.

use super::{EntryPoint, Framework, SurfaceMap, SurfaceNode};
use crate::callgraph::FileReachMap;
use crate::commands::scan::Diag;
use crate::entry_points::HttpMethod;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Worst-case route exposure for one finding.  Serialised into the
/// finding JSON / SARIF properties so downstream consumers (CI gates,
/// the web UI) can filter on "externally reachable" without re-running
/// the surface build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    pub route: String,
    pub method: HttpMethod,
    pub framework: Framework,
    /// True when the matched entry-point is behind an auth guard the
    /// surface layer recognised.  An unauthenticated match is always
    /// preferred when both kinds reach the finding.
    pub auth_required: bool,
    /// Entry-point declaration site.
    pub entry_file: String,
    pub entry_line: u32,
    /// `false` when the finding sits in the handler's own file,
    /// `true` when it is only reached through the call graph.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transitive: bool,
}

impl Exposure {
    /// One-line human-readable form, used as a console evidence label:
    /// `"GET /search (unauthenticated)"`,
    /// `"POST /admin/import (auth-gated, via call graph)"`.
    pub fn display(&self) -> String {
        let auth = if self.auth_required {
            "auth-gated"
        } else {
            "unauthenticated"
        };
        let via = if self.transitive {
            ", via call graph"
        } else {
            ""
        };
        format!("{:?} {} ({auth}{via})", self.method, self.route)
    }
}

/// Snapshot of one entry-point, decoupled from the map's lifetime.
struct EntryRef {
    handler_file: String,
    route: String,
    method: HttpMethod,
    framework: Framework,
    auth_required: bool,
    entry_file: String,
    entry_line: u32,
}

impl EntryRef {
    fn exposure(&self, transitive: bool) -> Exposure {
        Exposure {
            route: self.route.clone(),
            method: self.method,
            framework: self.framework,
            auth_required: self.auth_required,
            entry_file: self.entry_file.clone(),
            entry_line: self.entry_line,
            transitive,
        }
    }
}

/// Pre-indexed surface entry-points plus an optional call-graph file
/// reach map.  Build once per scan, query per finding.
pub struct ExposureIndex<'r> {
    entries: Vec<EntryRef>,
    reach: Option<&'r FileReachMap>,
}

impl<'r> ExposureIndex<'r> {
    pub fn build(map: &SurfaceMap, reach: Option<&'r FileReachMap>) -> Self {
        let entries = map
            .nodes
            .iter()
            .filter_map(|n| match n {
                SurfaceNode::EntryPoint(ep) => Some(entry_ref(ep)),
                _ => None,
            })
            .collect();
        Self { entries, reach }
    }

    /// True when the surface has no entry-points at all — exposure
    /// annotation would mark everything unreachable, which is noise
    /// rather than signal (probes may simply not cover the project's
    /// framework), so callers skip annotation entirely.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Worst-case exposure for a finding in `file`.  Preference order:
    /// 1. unauthenticated over auth-gated,
    /// 2. direct (same file as the handler) over transitive,
    /// 3. first in surface-canonical order (deterministic).
    ///
    /// Returns `None` when no entry-point reaches the file.
    pub fn exposure_for_file(&self, file: &str) -> Option<Exposure> {
        let mut best: Option<(u8, &EntryRef, bool)> = None;
        for e in &self.entries {
            let transitive = if e.handler_file == file {
                false
            } else if self.reach.is_some_and(|r| r.reaches(&e.handler_file, file)) {
                true
            } else {
                continue;
            };
            // Lower rank wins; canonical order breaks ties via `<`.
            let rank = (e.auth_required as u8) << 1 | (transitive as u8);
            if best.as_ref().is_none_or(|(r, _, _)| rank < *r) {
                let done = rank == 0;
                best = Some((rank, e, transitive));
                if done {
                    break;
                }
            }
        }
        best.map(|(_, e, transitive)| e.exposure(transitive))
    }
}

fn entry_ref(ep: &EntryPoint) -> EntryRef {
    EntryRef {
        handler_file: ep.handler_location.file.clone(),
        route: ep.route.clone(),
        method: ep.method,
        framework: ep.framework,
        auth_required: ep.auth_required,
        entry_file: ep.location.file.clone(),
        entry_line: ep.location.line,
    }
}

/// Annotate `diags` in place with their worst-case [`Exposure`].
///
/// Skips entirely when the surface has no entry-points (see
/// [`ExposureIndex::is_empty`]).  For each annotated finding a console
/// evidence label (`Exposure: GET /x (unauthenticated)`) is appended so
/// the text renderer shows the route without any renderer change.
/// Idempotent per scan: callers invoke it once, before ranking.
///
/// `scan_root` relativises `Diag::path` (absolute on most scan paths)
/// to the project-relative POSIX convention the surface map uses;
/// without it the direct same-file match never fires and every
/// exposure degrades to (or misses) the transitive path.
pub fn annotate_exposure(
    diags: &mut [Diag],
    map: &SurfaceMap,
    reach: Option<&FileReachMap>,
    scan_root: Option<&std::path::Path>,
) {
    let index = ExposureIndex::build(map, reach);
    if index.is_empty() {
        return;
    }
    // Findings cluster heavily by file; memoise per-file lookups.
    let mut cache: HashMap<String, Option<Exposure>> = HashMap::new();
    for d in diags.iter_mut() {
        let rel = crate::surface::relative_path_string(std::path::Path::new(&d.path), scan_root);
        let exp = cache
            .entry(rel)
            .or_insert_with_key(|k| index.exposure_for_file(k))
            .clone();
        if let Some(exp) = exp {
            d.labels.push(("Exposure".to_string(), exp.display()));
            d.exposure = Some(exp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::SourceLocation;

    fn ep(file: &str, route: &str, auth: bool) -> SurfaceNode {
        SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new(file, 1, 1),
            framework: Framework::Flask,
            method: HttpMethod::GET,
            route: route.into(),
            handler_name: "h".into(),
            handler_location: SourceLocation::new(file, 2, 1),
            auth_required: auth,
        })
    }

    #[test]
    fn direct_match_yields_exposure() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "/a", false));
        let idx = ExposureIndex::build(&map, None);
        let exp = idx.exposure_for_file("app.py").expect("exposed");
        assert_eq!(exp.route, "/a");
        assert!(!exp.transitive);
        assert!(!exp.auth_required);
        assert_eq!(idx.exposure_for_file("other.py"), None);
    }

    #[test]
    fn unauthenticated_entry_preferred_over_auth_gated() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "/locked", true));
        map.nodes.push(ep("app.py", "/open", false));
        let idx = ExposureIndex::build(&map, None);
        let exp = idx.exposure_for_file("app.py").unwrap();
        assert_eq!(exp.route, "/open");
        assert!(!exp.auth_required);
    }

    #[test]
    fn transitive_reach_via_call_graph() {
        use crate::callgraph::build_call_graph;
        use crate::summary::{FuncSummary, merge_summaries};
        // routes.py::handle -> helper.py::sink
        let handle = FuncSummary {
            name: "handle".into(),
            file_path: "routes.py".into(),
            lang: "python".into(),
            callees: vec![crate::summary::CalleeSite::bare("sink")],
            ..Default::default()
        };
        let sink = FuncSummary {
            name: "sink".into(),
            file_path: "helper.py".into(),
            lang: "python".into(),
            ..Default::default()
        };
        let gs = merge_summaries(vec![handle, sink], None);
        let cg = build_call_graph(&gs, &[]);
        let reach = FileReachMap::build(&cg);

        let mut map = SurfaceMap::new();
        map.nodes.push(ep("routes.py", "/r", false));
        let idx = ExposureIndex::build(&map, Some(&reach));
        let exp = idx.exposure_for_file("helper.py").expect("transitive");
        assert!(exp.transitive);
        assert_eq!(exp.route, "/r");
        // Direct match still preferred for the handler's own file.
        assert!(!idx.exposure_for_file("routes.py").unwrap().transitive);
    }

    #[test]
    fn unauth_transitive_beats_auth_direct() {
        use crate::callgraph::build_call_graph;
        use crate::summary::{FuncSummary, merge_summaries};
        let handle = FuncSummary {
            name: "open_handle".into(),
            file_path: "open.py".into(),
            lang: "python".into(),
            callees: vec![crate::summary::CalleeSite::bare("shared")],
            ..Default::default()
        };
        let shared = FuncSummary {
            name: "shared".into(),
            file_path: "shared.py".into(),
            lang: "python".into(),
            ..Default::default()
        };
        let gs = merge_summaries(vec![handle, shared], None);
        let cg = build_call_graph(&gs, &[]);
        let reach = FileReachMap::build(&cg);

        let mut map = SurfaceMap::new();
        map.nodes.push(ep("shared.py", "/locked", true)); // direct, auth
        map.nodes.push(ep("open.py", "/open", false)); // transitive, unauth
        let idx = ExposureIndex::build(&map, Some(&reach));
        let exp = idx.exposure_for_file("shared.py").unwrap();
        assert_eq!(exp.route, "/open", "unauth transitive should win");
        assert!(exp.transitive);
    }

    #[test]
    fn annotate_sets_field_and_label() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "/a", false));
        let mut diags = vec![crate::commands::scan::Diag {
            path: "app.py".into(),
            line: 9,
            col: 1,
            id: "x".into(),
            ..Default::default()
        }];
        annotate_exposure(&mut diags, &map, None, None);
        let exp = diags[0].exposure.as_ref().expect("annotated");
        assert_eq!(exp.route, "/a");
        assert!(
            diags[0]
                .labels
                .iter()
                .any(|(k, v)| k == "Exposure" && v.contains("/a"))
        );
    }

    #[test]
    fn empty_surface_skips_annotation() {
        let map = SurfaceMap::new();
        let mut diags = vec![crate::commands::scan::Diag {
            path: "app.py".into(),
            ..Default::default()
        }];
        annotate_exposure(&mut diags, &map, None, None);
        assert!(diags[0].exposure.is_none());
        assert!(diags[0].labels.is_empty());
    }
}

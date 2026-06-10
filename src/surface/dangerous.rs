//! Dangerous-local sink detection.
//!
//! Walks the post-pass-2 [`GlobalSummaries`] looking for functions
//! that themselves consume `Cap::CODE_EXEC`, `Cap::DESERIALIZE`,
//! `Cap::SSTI`, or `Cap::FMT_STRING` (the canonical "no externally
//! observable side effect" sinks) and emits one
//! [`SurfaceNode::DangerousLocal`] per such function.
//!
//! The cap bits are taken straight from the existing label-rule
//! registry — every Phase 22 sink class continues to land on the same
//! `sink_caps` field downstream rules already populate.  No new
//! detection pass is added here; the surface layer just lifts the
//! cap-bit information out of the summary.

use super::{DangerousLocal, SourceLocation, SurfaceNode, cap_label_string, namespace_file};
use crate::labels::Cap;
use crate::summary::{FuncSummary, GlobalSummaries};

/// Cap bits that indicate the function is a *local* sink — a sink with no
/// externally observable side effect that attacker data flows *into*.
/// Other sink caps live elsewhere in the surface layer so the node
/// taxonomy matches the chain composer's expectations: `SQL_QUERY` /
/// `FILE_IO` → DataStore (see [`super::datastore`]); `SSRF` / `DATA_EXFIL`
/// → ExternalService (see [`super::external`]).
///
/// The set was widened from the original four (code-exec, deserialize,
/// SSTI, format-string) to cover every injection-style local sink the
/// label registry can classify, so a function that only builds an LDAP
/// filter, parses XXE-vulnerable XML, or merges into a prototype is no
/// longer absent from the surface map.
fn dangerous_caps() -> Cap {
    Cap::CODE_EXEC
        | Cap::DESERIALIZE
        | Cap::SSTI
        | Cap::FMT_STRING
        | Cap::LDAP_INJECTION
        | Cap::XPATH_INJECTION
        | Cap::HEADER_INJECTION
        | Cap::OPEN_REDIRECT
        | Cap::XXE
        | Cap::PROTOTYPE_POLLUTION
}

pub fn detect_dangerous_locals(summaries: &GlobalSummaries) -> Vec<SurfaceNode> {
    let mask = dangerous_caps();
    let mut out: Vec<SurfaceNode> = Vec::new();
    for (key, summary) in summaries.iter() {
        let caps = summary.sink_caps() & mask;
        if caps.is_empty() {
            continue;
        }
        // Project-relative POSIX file, keyed off the FuncKey namespace so
        // a dangerous-local node and the entry-point that reaches it agree
        // on file identity (FuncSummary.file_path is an absolute path and
        // would never match an entry-point's relative handler file).
        let file = namespace_file(&key.namespace).to_string();
        let (line, col) = sink_line_col(summary, &file, caps);
        out.push(SurfaceNode::DangerousLocal(DangerousLocal {
            location: SourceLocation { file, line, col },
            function_name: key.qualified_name(),
            cap_bits: caps.bits(),
            label: cap_label_string(caps.bits()),
        }));
    }
    out
}

/// Resolve the `(line, col)` of the dangerous sink inside `summary` by
/// scanning its `param_to_sink` [`crate::summary::SinkSite`] records for a
/// site whose cap intersects the dangerous mask.  Prefers a same-file,
/// non-chain-promoted site (the function's own sink) over a deeper
/// chain-hop site so the coordinates point at code in `file`.  Falls back
/// to `(0, 0)` when the summary carries no located sink (pass-2 transient
/// summaries, or summaries extracted without tree access).
fn sink_line_col(summary: &FuncSummary, file: &str, mask: Cap) -> (u32, u32) {
    let mut fallback: Option<(u32, u32)> = None;
    for (_param, sites) in &summary.param_to_sink {
        for site in sites {
            if site.line == 0 || (site.cap & mask).is_empty() {
                continue;
            }
            let same_file = site.file_rel.is_empty() || site.file_rel == file;
            if same_file && !site.from_chain {
                return (site.line, site.col);
            }
            fallback.get_or_insert((site.line, site.col));
        }
    }
    fallback.unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::FuncSummary;
    use crate::symbol::{FuncKey, Lang};

    fn summary_with_caps(name: &str, file: &str, caps: Cap) -> (FuncKey, FuncSummary) {
        let key = FuncKey::new_function(Lang::Python, file, name, None);
        let summary = FuncSummary {
            name: name.to_string(),
            file_path: file.to_string(),
            lang: "python".to_string(),
            sink_caps: caps.bits(),
            ..Default::default()
        };
        (key, summary)
    }

    #[test]
    fn carries_real_span_and_label_from_param_to_sink() {
        use crate::summary::SinkSite;
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "app.py", "render", None);
        let site = SinkSite {
            file_rel: "app.py".into(),
            line: 17,
            col: 9,
            snippet: "Template(x).render()".into(),
            cap: Cap::SSTI,
            from_chain: false,
        };
        let summary = FuncSummary {
            name: "render".into(),
            file_path: "/abs/app.py".into(), // absolute on purpose
            lang: "python".into(),
            sink_caps: Cap::SSTI.bits(),
            param_to_sink: vec![(0, vec![site].into())],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_dangerous_locals(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DangerousLocal(d) = &nodes[0] else {
            panic!()
        };
        // Project-relative file (from the namespace), not the absolute path.
        assert_eq!(d.location.file, "app.py");
        assert_eq!(d.location.line, 17);
        assert_eq!(d.location.col, 9);
        assert_eq!(d.label, "ssti");
    }

    #[test]
    fn detects_widened_injection_caps() {
        // The widened mask now covers XXE / LDAP / open-redirect etc., which
        // the original four-cap mask missed entirely.
        for cap in [
            Cap::XXE,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::OPEN_REDIRECT,
            Cap::HEADER_INJECTION,
            Cap::PROTOTYPE_POLLUTION,
        ] {
            let mut gs = GlobalSummaries::new();
            let (k, s) = summary_with_caps("h", "danger.py", cap);
            gs.insert(k, s);
            assert_eq!(
                detect_dangerous_locals(&gs).len(),
                1,
                "cap {cap:?} should surface a dangerous-local node"
            );
        }
    }

    #[test]
    fn detects_eval_sink() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_caps("run", "danger.py", Cap::CODE_EXEC);
        gs.insert(k, s);
        let nodes = detect_dangerous_locals(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::DangerousLocal(d) = &nodes[0] else {
            panic!()
        };
        assert_eq!(d.cap_bits & Cap::CODE_EXEC.bits(), Cap::CODE_EXEC.bits());
    }

    #[test]
    fn ignores_sql_only() {
        let mut gs = GlobalSummaries::new();
        let (k, s) = summary_with_caps("query", "data.py", Cap::SQL_QUERY);
        gs.insert(k, s);
        let nodes = detect_dangerous_locals(&gs);
        assert!(nodes.is_empty());
    }
}

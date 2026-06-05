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

use super::{DangerousLocal, SourceLocation, SurfaceNode};
use crate::labels::Cap;
use crate::summary::GlobalSummaries;

/// Cap bits that indicate the function is a *local* sink — code exec,
/// unsafe deserialisation, server-side template injection, format
/// string injection.  Other sink caps (SQL_QUERY → DataStore;
/// SSRF → ExternalService) live elsewhere in the surface layer so the
/// node taxonomy matches the chain composer's expectations.
fn dangerous_caps() -> Cap {
    Cap::CODE_EXEC | Cap::DESERIALIZE | Cap::SSTI | Cap::FMT_STRING
}

pub fn detect_dangerous_locals(summaries: &GlobalSummaries) -> Vec<SurfaceNode> {
    let mask = dangerous_caps();
    let mut out: Vec<SurfaceNode> = Vec::new();
    for (key, summary) in summaries.iter() {
        let caps = summary.sink_caps() & mask;
        if caps.is_empty() {
            continue;
        }
        out.push(SurfaceNode::DangerousLocal(DangerousLocal {
            location: SourceLocation {
                file: summary.file_path.clone(),
                line: 0,
                col: 0,
            },
            function_name: key.qualified_name(),
            cap_bits: caps.bits(),
        }));
    }
    out
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

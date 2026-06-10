//! Finding serialization for SARIF output, with chain-extension
//! support added in Phase 25.
//!
//! Serializes [`crate::commands::scan::Diag`] values to SARIF 2.1.0.
//! Chains land on `runs[0].properties.chains` (SARIF v2.1.0 has no
//! first-class chain concept); see [`build_sarif_with_chains`].

use crate::chain::finding::ChainFinding;
use crate::commands::scan::Diag;
use crate::patterns::{self, Severity};
use once_cell::sync::Lazy;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;

/// Lazily-built global map: pattern ID → description from all language registries.
static PATTERN_DESCRIPTIONS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    for lang in &[
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "javascript",
        "typescript",
    ] {
        for p in patterns::load(lang) {
            map.entry(p.id).or_insert(p.description);
        }
    }
    map
});

/// CFG rule descriptions for rules not in the pattern registry.
pub(crate) fn cfg_rule_description(id: &str) -> Option<&'static str> {
    match id {
        "cfg-unguarded-sink" => Some("Dangerous sink reachable without prior guard or sanitizer"),
        "cfg-unreachable-sink" => Some("Sink in unreachable code"),
        "cfg-auth-gap" => Some("Entry-point handler reaches sink without authentication check"),
        "cfg-error-fallthrough" => {
            Some("Error check does not terminate; dangerous call follows on error path")
        }
        "cfg-resource-leak" => Some("Resource acquired but not released on all exit paths"),
        "cfg-lock-not-released" => Some("Lock acquired but not released on all exit paths"),
        "state-use-after-close" => Some("Variable used after its resource handle was closed"),
        "state-double-close" => Some("Resource handle closed more than once"),
        "state-resource-leak" => Some("Resource acquired but never closed"),
        "state-resource-leak-possible" => Some("Resource may not be closed on all paths"),
        "state-unauthed-access" => Some("Sensitive operation reached without authentication"),
        _ => None,
    }
}

/// Normalise a finding's id to the base SARIF rule id.
///
/// Findings carry source-location-suffixed ids like
/// `"taint-unsanitised-flow (source 12:3)"` so identical (source, sink)
/// pairs can be deduped, but SARIF wants a single rule per category.
/// Cap-specific taint rule classes (e.g. `taint-data-exfiltration`) are
/// preserved as distinct bases so consumers can filter on them rather than
/// folding everything into `taint-unsanitised-flow`.
pub(crate) fn sarif_base_id(id: &str) -> &str {
    if id.starts_with("taint-data-exfiltration") {
        "taint-data-exfiltration"
    } else if id.starts_with("taint-") {
        "taint-unsanitised-flow"
    } else {
        id
    }
}

/// Look up a human-readable description for any rule ID.
pub(crate) fn rule_description(id: &str) -> &str {
    let base_id = sarif_base_id(id);

    if let Some(desc) = PATTERN_DESCRIPTIONS.get(base_id) {
        return desc;
    }
    if let Some(desc) = cfg_rule_description(base_id) {
        return desc;
    }
    match base_id {
        "taint-unsanitised-flow" => "Unsanitised data flows from source to sink",
        "taint-data-exfiltration" => {
            "Sensitive data flows into the payload of an outbound network request"
        }
        _ => id,
    }
}

pub(crate) fn severity_to_level(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Build a SARIF 2.1.0 JSON value from a list of diagnostics.
///
/// Backwards-compatible wrapper for callers that do not yet have a
/// chain list.  Equivalent to
/// [`build_sarif_with_chains`] with an empty chain slice.
pub fn build_sarif(diags: &[Diag], scan_root: &Path) -> Value {
    build_sarif_with_chains(diags, &[], scan_root)
}

/// Build a SARIF 2.1.0 JSON value from a list of diagnostics, with
/// composed exploit chains attached to `runs[0].properties.chains`.
///
/// `chains` is emitted verbatim into the run's `properties` object so
/// SARIF v2.1.0 consumers that do not understand chains can still
/// process the diagnostics.  When the slice is empty the
/// `properties.chains` array is still emitted (as `[]`) so consumers
/// can rely on the key existing.
pub fn build_sarif_with_chains(diags: &[Diag], chains: &[ChainFinding], scan_root: &Path) -> Value {
    let mut rule_ids: Vec<String> = Vec::new();
    let mut rule_index_map: HashMap<String, usize> = HashMap::new();

    for d in diags {
        let base = sarif_base_id(&d.id).to_string();
        if !rule_index_map.contains_key(&base) {
            let idx = rule_ids.len();
            rule_index_map.insert(base.clone(), idx);
            rule_ids.push(base);
        }
    }

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": rule_description(id) },
            })
        })
        .collect();

    // Map of finding stable_hash → chain stable_hash, used to set the
    // per-result `chain_member_of` property.  Findings carry a u64
    // stable hash; chains carry their own u64.  When a finding is a
    // member of multiple chains, the first chain in
    // `canonicalise`-order wins (deterministic).
    let chain_member_of: HashMap<u64, u64> = build_chain_member_map(chains);

    let results: Vec<Value> = diags
        .iter()
        .map(|d| {
            let base = sarif_base_id(&d.id);
            let rule_index = rule_index_map[base];

            let uri = match Path::new(&d.path).strip_prefix(scan_root) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => {
                    tracing::warn!(
                        path = %d.path,
                        scan_root = %scan_root.display(),
                        "SARIF: finding path is outside scan root; redacting"
                    );
                    "<out-of-root>".to_string()
                }
            };

            let msg_text = d
                .message
                .as_deref()
                .unwrap_or_else(|| rule_description(base));

            let mut result = json!({
                "ruleId": base,
                "ruleIndex": rule_index,
                "level": severity_to_level(d.severity),
                "message": { "text": msg_text },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": {
                            "startLine": d.line,
                            "startColumn": d.col
                        }
                    }
                }]
            });

            if let Some(ev) = d.evidence.as_ref()
                && !ev.flow_steps.is_empty()
            {
                let thread_locations: Vec<Value> = ev
                    .flow_steps
                    .iter()
                    .map(|step| {
                        let step_uri = Path::new(&step.file)
                            .strip_prefix(scan_root)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| step.file.clone());
                        let mut loc = json!({
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": { "uri": step_uri },
                                    "region": {
                                        "startLine": step.line,
                                        "startColumn": step.col
                                    }
                                },
                                "message": { "text": step.kind.to_string() }
                            }
                        });
                        if let Some(ref snippet) = step.snippet {
                            loc["location"]["physicalLocation"]["region"]["snippet"] =
                                json!({ "text": snippet });
                        }
                        loc
                    })
                    .collect();
                result["codeFlows"] = json!([{
                    "threadFlows": [{ "locations": thread_locations }]
                }]);
            }

            let mut props = serde_json::Map::new();
            props.insert("category".into(), json!(d.category.to_string()));
            if let Some(conf) = d.confidence {
                props.insert("confidence".into(), json!(conf.to_string()));
            }
            if !crate::commands::scan::is_default_triage_state(&d.triage_state) {
                props.insert("triage_state".into(), json!(d.triage_state));
                if !d.triage_note.is_empty() {
                    props.insert("triage_note".into(), json!(d.triage_note));
                }
            }

            if let Some(field) = d
                .evidence
                .as_ref()
                .and_then(|ev| ev.data_exfil_field.as_deref())
            {
                props.insert("data_exfil_field".into(), json!(field));
            }

            // Attack-surface exposure: the externally-reachable route
            // that drives this finding.  Lets a SARIF consumer (CI gate,
            // dashboard) filter on "reachable from an unauthenticated
            // route" without re-running the surface build.
            if let Some(exp) = &d.exposure {
                props.insert(
                    "exposure".into(),
                    json!({
                        "route": exp.route,
                        "method": format!("{:?}", exp.method),
                        "framework": format!("{:?}", exp.framework),
                        "auth_required": exp.auth_required,
                        "transitive": exp.transitive,
                    }),
                );
            }

            if !d.finding_id.is_empty() {
                props.insert("finding_id".into(), json!(d.finding_id));
            }
            if !d.alternative_finding_ids.is_empty() {
                props.insert("relatedFindings".into(), json!(d.alternative_finding_ids));
            }

            if let Some(engine_notes) = d.evidence.as_ref().and_then(|ev| {
                if ev.engine_notes.is_empty() {
                    None
                } else {
                    Some(&ev.engine_notes)
                }
            }) {
                props.insert(
                    "engine_notes".into(),
                    serde_json::to_value(engine_notes).unwrap_or(Value::Null),
                );
                props.insert(
                    "confidence_capped".into(),
                    json!(
                        engine_notes
                            .iter()
                            .any(crate::engine_notes::EngineNote::lowers_confidence)
                    ),
                );
                if let Some(dir) = crate::engine_notes::worst_direction(engine_notes) {
                    props.insert("loss_direction".into(), json!(dir.tag()));
                }
            }

            if let Some(dv) = d
                .evidence
                .as_ref()
                .and_then(|ev| ev.dynamic_verdict.as_ref())
            {
                result["partialFingerprints"] = json!({
                    "dynamic_verdict_status": serde_json::to_value(dv.status)
                        .unwrap_or(Value::Null)
                });
                props.insert(
                    "nyx_dynamic_verdict".into(),
                    serde_json::to_value(dv).unwrap_or(Value::Null),
                );
            }

            if let Some(ref rollup) = d.rollup {
                props.insert(
                    "rollup".into(),
                    json!({
                        "count": rollup.count,
                    }),
                );

                let related: Vec<Value> = rollup
                    .occurrences
                    .iter()
                    .enumerate()
                    .map(|(idx, loc)| {
                        json!({
                            "id": idx,
                            "physicalLocation": {
                                "artifactLocation": { "uri": &uri },
                                "region": {
                                    "startLine": loc.line,
                                    "startColumn": loc.col
                                }
                            }
                        })
                    })
                    .collect();
                if !related.is_empty() {
                    result["relatedLocations"] = json!(related);
                }
            }

            // Phase 25: cross-reference back to the composed chain
            // this finding participates in (if any).  Stable across
            // reruns because both the finding's `stable_hash` and the
            // chain's `stable_hash` are byte-deterministic.
            if d.stable_hash != 0
                && let Some(chain_hash) = chain_member_of.get(&d.stable_hash)
            {
                props.insert("chain_member_of".into(), json!(chain_hash));
            }

            result["properties"] = Value::Object(props);

            result
        })
        .collect();

    let run_properties = json!({
        "chains": chains.iter().map(serialize_chain).collect::<Vec<_>>(),
    });

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nyx",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": env!("CARGO_PKG_HOMEPAGE"),
                    "rules": rules
                }
            },
            "results": results,
            "properties": run_properties
        }]
    })
}

fn build_chain_member_map(chains: &[ChainFinding]) -> HashMap<u64, u64> {
    let mut out: HashMap<u64, u64> = HashMap::new();
    for chain in chains {
        for member in &chain.members {
            out.entry(member.stable_hash).or_insert(chain.stable_hash);
        }
    }
    out
}

/// JSON shape for one chain inside SARIF's `properties.chains`.  The
/// JSON-findings emitter in [`crate::output::json`] serialises chains
/// the same way (via `serde_json::to_value`), so consumers see an
/// identical chain shape across both formats.
pub(crate) fn serialize_chain(chain: &ChainFinding) -> Value {
    serde_json::to_value(chain).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::scan::{Diag, Location, RollupData};
    use crate::patterns::{FindingCategory, Severity};

    fn make_diag(id: &str, severity: Severity) -> Diag {
        Diag {
            path: "/scan_root/src/main.rs".into(),
            line: 10,
            col: 5,
            severity,
            id: id.into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
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
        }
    }

    #[test]
    fn severity_to_level_high_is_error() {
        assert_eq!(severity_to_level(Severity::High), "error");
    }

    #[test]
    fn severity_to_level_medium_is_warning() {
        assert_eq!(severity_to_level(Severity::Medium), "warning");
    }

    #[test]
    fn severity_to_level_low_is_note() {
        assert_eq!(severity_to_level(Severity::Low), "note");
    }

    #[test]
    fn cfg_rule_description_known_ids() {
        let cases = [
            ("cfg-unguarded-sink", "without prior guard"),
            ("cfg-unreachable-sink", "unreachable"),
            ("cfg-auth-gap", "authentication"),
            ("cfg-error-fallthrough", "dangerous call follows"),
            ("cfg-resource-leak", "not released"),
            ("cfg-lock-not-released", "Lock acquired"),
            (
                "state-use-after-close",
                "after its resource handle was closed",
            ),
            ("state-double-close", "more than once"),
            ("state-resource-leak", "never closed"),
            ("state-resource-leak-possible", "may not be closed"),
            ("state-unauthed-access", "without authentication"),
        ];
        for (id, fragment) in cases {
            let desc = cfg_rule_description(id).unwrap_or_else(|| panic!("no desc for {id}"));
            assert!(
                desc.contains(fragment),
                "Description for '{id}' should contain '{fragment}', got: {desc}"
            );
        }
    }

    #[test]
    fn cfg_rule_description_unknown_id_returns_none() {
        assert!(cfg_rule_description("unknown-rule-xyz").is_none());
        assert!(cfg_rule_description("").is_none());
    }

    #[test]
    fn rule_description_taint_prefix_returns_fallback() {
        let desc = rule_description("taint-unsanitised-flow");
        assert!(
            desc.contains("Unsanitised"),
            "expected taint fallback, got: {desc}"
        );
    }

    #[test]
    fn rule_description_taint_with_suffix_normalises_to_base() {
        let desc = rule_description("taint-unsanitised-flow:foo.rs:42");
        assert!(
            desc.contains("Unsanitised"),
            "expected taint fallback, got: {desc}"
        );
    }

    #[test]
    fn rule_description_cfg_known_id_returns_description() {
        let desc = rule_description("cfg-auth-gap");
        assert!(desc.contains("authentication"));
    }

    #[test]
    fn rule_description_unknown_returns_id_itself() {
        let id = "totally-unknown-rule-zzzz";
        let desc = rule_description(id);
        assert_eq!(desc, id);
    }

    #[test]
    fn build_sarif_empty_diags_produces_valid_structure() {
        let sarif = build_sarif(&[], Path::new("/scan_root"));
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"].is_array());
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "nyx");
        assert_eq!(run["results"].as_array().unwrap().len(), 0);
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn build_sarif_single_diag_has_correct_fields() {
        let diag = make_diag("rs.security.sql-injection", Severity::High);
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));

        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result["ruleId"], "rs.security.sql-injection");
        assert_eq!(result["level"], "error");

        let loc = &result["locations"][0]["physicalLocation"];
        assert_eq!(loc["region"]["startLine"], 10);
        assert_eq!(loc["region"]["startColumn"], 5);
        let uri = loc["artifactLocation"]["uri"].as_str().unwrap();
        assert!(!uri.starts_with("/scan_root"));
        assert!(uri.contains("main.rs"));
    }

    #[test]
    fn build_sarif_severity_mapping() {
        let diags = vec![
            make_diag("rule-high", Severity::High),
            make_diag("rule-medium", Severity::Medium),
            make_diag("rule-low", Severity::Low),
        ];
        let sarif = build_sarif(&diags, Path::new("/"));
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
    }

    #[test]
    fn build_sarif_taint_ids_normalised_to_base() {
        let mut diag = make_diag("taint-unsanitised-flow", Severity::High);
        diag.path = "/scan_root/src/main.rs".into();
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));

        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["ruleId"], "taint-unsanitised-flow");

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "taint-unsanitised-flow");
    }

    #[test]
    fn build_sarif_duplicate_rule_ids_deduplicated() {
        let d1 = make_diag("rs.security.sqli", Severity::High);
        let d2 = make_diag("rs.security.sqli", Severity::Medium);
        let sarif = build_sarif(&[d1, d2], Path::new("/"));
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 0);
    }

    #[test]
    fn build_sarif_message_override_from_diag() {
        let mut diag = make_diag("state-resource-leak", Severity::Medium);
        diag.message = Some("Custom message from state analysis".into());
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(
            result["message"]["text"],
            "Custom message from state analysis"
        );
    }

    #[test]
    fn build_sarif_uses_rule_description_when_no_message() {
        let diag = make_diag("cfg-auth-gap", Severity::High);
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));
        let result = &sarif["runs"][0]["results"][0];
        let msg = result["message"]["text"].as_str().unwrap();
        assert!(msg.contains("authentication"));
    }

    #[test]
    fn build_sarif_rollup_produces_related_locations() {
        let mut diag = make_diag("rs.quality.unwrap", Severity::Low);
        diag.rollup = Some(RollupData {
            count: 3,
            occurrences: vec![Location { line: 5, col: 1 }, Location { line: 12, col: 3 }],
        });
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));
        let result = &sarif["runs"][0]["results"][0];

        let props = &result["properties"];
        assert_eq!(props["rollup"]["count"], 3);

        let related = result["relatedLocations"].as_array().unwrap();
        assert_eq!(related.len(), 2);
        assert_eq!(related[0]["physicalLocation"]["region"]["startLine"], 5);
        assert_eq!(related[1]["physicalLocation"]["region"]["startLine"], 12);
    }

    #[test]
    fn build_sarif_no_rollup_no_related_locations() {
        let diag = make_diag("rs.security.sql-injection", Severity::High);
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("relatedLocations").is_none());
    }

    #[test]
    fn build_sarif_path_relative_to_scan_root() {
        let mut diag = make_diag("rule-x", Severity::High);
        diag.path = "/workspace/src/lib.rs".into();
        let sarif = build_sarif(&[diag], Path::new("/workspace"));
        let uri =
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .as_str()
                .unwrap();
        assert_eq!(uri, "src/lib.rs");
    }

    #[test]
    fn build_sarif_path_outside_scan_root_is_redacted() {
        let mut diag = make_diag("rule-x", Severity::High);
        diag.path = "/other/place/file.rs".into();
        let sarif = build_sarif(&[diag], Path::new("/workspace"));
        let uri =
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .as_str()
                .unwrap();
        assert_eq!(uri, "<out-of-root>");
    }

    #[test]
    fn build_sarif_confidence_in_properties() {
        let mut diag = make_diag("rule-conf", Severity::High);
        diag.confidence = Some(crate::evidence::Confidence::High);
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));
        let props = &sarif["runs"][0]["results"][0]["properties"];
        let conf = props["confidence"].as_str().unwrap();
        assert_eq!(conf, "High");
    }

    #[test]
    fn build_sarif_category_in_properties() {
        let mut diag = make_diag("rule-cat", Severity::Medium);
        diag.category = FindingCategory::Reliability;
        let sarif = build_sarif(&[diag], Path::new("/scan_root"));
        let props = &sarif["runs"][0]["results"][0]["properties"];
        assert_eq!(props["category"], "Reliability");
    }

    #[test]
    fn build_sarif_schema_and_version_fields_present() {
        let sarif = build_sarif(&[], Path::new("/"));
        assert!(sarif["$schema"].as_str().unwrap().contains("sarif"));
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn build_sarif_multiple_distinct_rules_indexed_in_order() {
        let d1 = make_diag("rule-alpha", Severity::High);
        let d2 = make_diag("rule-beta", Severity::Medium);
        let d3 = make_diag("rule-gamma", Severity::Low);
        let sarif = build_sarif(&[d1, d2, d3], Path::new("/"));
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["id"], "rule-alpha");
        assert_eq!(rules[1]["id"], "rule-beta");
        assert_eq!(rules[2]["id"], "rule-gamma");

        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 1);
        assert_eq!(results[2]["ruleIndex"], 2);
    }

    #[test]
    fn build_sarif_with_chains_emits_properties_chains_array() {
        let sarif = build_sarif_with_chains(&[], &[], Path::new("/scan_root"));
        let run_props = &sarif["runs"][0]["properties"];
        assert!(run_props["chains"].is_array());
        assert_eq!(run_props["chains"].as_array().unwrap().len(), 0);
    }
}

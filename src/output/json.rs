//! Phase 25 — JSON output that pairs findings with composed chains.
//!
//! Two top-level keys on the emitted JSON:
//!
//! - `findings` — every [`crate::commands::scan::Diag`] from the scan,
//!   each with `chain_member_of` set when the finding participates in
//!   one of the emitted chains.
//! - `chains` — array of [`crate::chain::finding::ChainFinding`]
//!   structs, in the canonical chain order produced by
//!   [`crate::chain::search::find_chains`].
//!
//! The output is byte-deterministic for a fixed `(diags, chains)` pair
//! because both inputs are themselves canonicalised by the scan
//! pipeline before reaching this layer.

use crate::chain::finding::ChainFinding;
use crate::commands::scan::{Diag, DynamicVerificationSummary};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Build the chain-aware JSON output payload.
///
/// `verdict_diff` is the optional baseline-diff payload from
/// [`crate::baseline`]; when present it lands on the top-level
/// `verdict_diff` key (matching pre-Phase-25 behaviour).
pub fn build_findings_json(
    diags: &[Diag],
    chains: &[ChainFinding],
    verdict_diff: Option<&Value>,
) -> Value {
    let chain_member_of = build_chain_member_map(chains);
    let findings: Vec<Value> = diags
        .iter()
        .map(|d| diag_to_value(d, &chain_member_of))
        .collect();

    let chains_array: Vec<Value> = chains
        .iter()
        .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
        .collect();

    let mut out = json!({
        "findings": findings,
        "chains": chains_array,
        "dynamic_verification": DynamicVerificationSummary::from_diags(diags),
    });
    if let Some(diff) = verdict_diff {
        out["verdict_diff"] = diff.clone();
    }
    out
}

/// Map finding `stable_hash` → chain `stable_hash`.  Findings absent
/// from any chain are not in the map.
fn build_chain_member_map(chains: &[ChainFinding]) -> HashMap<u64, u64> {
    let mut out: HashMap<u64, u64> = HashMap::new();
    for chain in chains {
        for member in &chain.members {
            out.entry(member.stable_hash).or_insert(chain.stable_hash);
        }
    }
    out
}

fn diag_to_value(d: &Diag, chain_member_of: &HashMap<u64, u64>) -> Value {
    // Round-trip through serde to preserve every `Diag` field, then
    // splice `chain_member_of` into the JSON object when applicable.
    let mut v = serde_json::to_value(d).unwrap_or(Value::Null);
    if d.stable_hash != 0
        && let Some(chain_hash) = chain_member_of.get(&d.stable_hash)
        && let Value::Object(ref mut map) = v
    {
        map.insert("chain_member_of".into(), json!(chain_hash));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::edges::FindingRef;
    use crate::chain::finding::{ChainFinding, ChainSeverity, ChainSink};
    use crate::chain::impact::ImpactCategory;
    use crate::commands::scan::Diag;
    use crate::patterns::{FindingCategory, Severity};
    use crate::surface::SourceLocation;

    fn diag(hash: u64) -> Diag {
        Diag {
            path: "a.py".into(),
            line: 1,
            col: 1,
            severity: Severity::High,
            id: "test".into(),
            category: FindingCategory::Security,
            stable_hash: hash,
            ..Diag::default()
        }
    }

    fn chain_with_member(hash: u64) -> ChainFinding {
        let member = FindingRef {
            finding_id: "f".into(),
            stable_hash: hash,
            location: SourceLocation::new("a.py", 1, 1),
            rule_id: "test".into(),
            cap_bits: 0,
        };
        ChainFinding {
            stable_hash: 0xDEAD_BEEF,
            members: vec![member],
            sink: ChainSink {
                file: "a.py".into(),
                line: 5,
                col: 1,
                function_name: "sink".into(),
                cap_bits: 0,
            },
            implied_impact: ImpactCategory::Rce,
            severity: ChainSeverity::Critical,
            score: 200.0,
            dynamic_verdict: None,
            reverify_reason: None,
        }
    }

    #[test]
    fn chain_member_of_is_set_for_chain_members() {
        let d = diag(42);
        let c = chain_with_member(42);
        let v = build_findings_json(&[d], &[c], None);
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings[0]["chain_member_of"], json!(0xDEAD_BEEFu64));
    }

    #[test]
    fn chain_member_of_omitted_when_finding_not_in_any_chain() {
        let d = diag(99);
        let c = chain_with_member(42);
        let v = build_findings_json(&[d], &[c], None);
        let findings = v["findings"].as_array().unwrap();
        assert!(findings[0].get("chain_member_of").is_none());
    }

    #[test]
    fn chains_array_serialised() {
        let c = chain_with_member(42);
        let v = build_findings_json(&[], &[c], None);
        let chains = v["chains"].as_array().unwrap();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0]["severity"], "critical");
        assert_eq!(chains[0]["implied_impact"], "rce");
    }

    #[test]
    fn verdict_diff_preserved() {
        let v = build_findings_json(&[], &[], Some(&json!({"new": []})));
        assert!(v.get("verdict_diff").is_some());
    }
}

//! Baseline diffing for patch-validation CI mode (§M6.5 / Pillar A §15.1).
//!
//! `nyx scan --baseline <file>` reads a previous scan's JSON output (or a
//! stripped `.nyx/baseline.json`) and joins on `Diag::stable_hash`.  The
//! result is a per-finding `VerdictDiffEntry` with a typed `Transition` that
//! CI gates can act on.
//!
//! `nyx scan --baseline-write <file>` writes a stripped baseline JSON:
//! only `stable_hash`, `dynamic_verdict`, `severity`, `path`, and `rule_id`.
//! No source code is included.

use crate::commands::scan::Diag;
use crate::evidence::VerifyStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
//  Baseline entry (stripped — no source code)
// ─────────────────────────────────────────────────────────────────────────────

/// A stripped baseline entry: only what is needed for cross-commit diffing.
/// Contains no source code snippets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub stable_hash: u64,
    /// Dynamic verdict status from the scan that wrote this baseline.
    /// `None` when `--verify` was not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_verdict: Option<VerifyStatus>,
    pub severity: String,
    pub path: String,
    pub rule_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Transition enum
// ─────────────────────────────────────────────────────────────────────────────

/// How a finding's verdict changed between the baseline scan and the current
/// scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    /// Finding exists in the current scan but was absent from the baseline.
    New,
    /// Finding appears in both scans; verdict is unchanged (or neither scan
    /// ran `--verify`).
    Unchanged,
    /// Finding was present in the baseline but disappeared from the current
    /// scan — the vulnerability is gone.
    Resolved,
    /// Finding in both; was `NotConfirmed` in baseline, now `Confirmed`.
    Regressed,
    /// Finding in both; baseline had no verdict (or `Inconclusive` /
    /// `Unsupported`) and it is now `Confirmed`.
    FlippedConfirmed,
    /// Finding in both; was `Confirmed` in baseline, now `NotConfirmed` —
    /// the fix is proven.
    FlippedNotConfirmed,
}

// ─────────────────────────────────────────────────────────────────────────────
//  VerdictDiffEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Per-finding verdict diff produced by comparing a baseline to a current scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictDiffEntry {
    /// Stable cross-commit identity hash.
    pub stable_hash: u64,
    pub path: String,
    pub line: usize,
    pub rule_id: String,
    /// Verdict in the baseline scan (`None` when verify was not run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_status: Option<VerifyStatus>,
    /// Verdict in the current scan (`None` when verify was not run or finding
    /// is absent from the current scan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_status: Option<VerifyStatus>,
    pub transition: Transition,
}

/// Full verdict diff between a baseline and a current scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictDiff {
    pub entries: Vec<VerdictDiffEntry>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Load / write helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Load baseline entries from a file.
///
/// Accepts two JSON formats:
/// - Stripped baseline (`Vec<BaselineEntry>`) — written by `--baseline-write`.
/// - Full scan output (`Vec<Diag>`) — written by `nyx scan --format json`.
///
/// Detection heuristic: try `Vec<BaselineEntry>` first (requires `rule_id`);
/// fall back to `Vec<Diag>`.
pub fn load_baseline(path: &Path) -> crate::errors::NyxResult<Vec<BaselineEntry>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::errors::NyxError::Msg(format!("cannot read baseline {}: {e}", path.display()))
    })?;

    // Try stripped format first.
    if let Ok(entries) = serde_json::from_str::<Vec<BaselineEntry>>(&content) {
        return Ok(entries);
    }

    // Fall back to full Diag list.
    let diags: Vec<Diag> = serde_json::from_str(&content).map_err(|e| {
        crate::errors::NyxError::Msg(format!(
            "baseline {}: not a valid BaselineEntry list or Diag list: {e}",
            path.display()
        ))
    })?;
    Ok(diags_to_baseline_entries(&diags))
}

/// Convert `Diag` values to `BaselineEntry` values.
///
/// Only findings with a non-zero `stable_hash` are included; findings without
/// a hash cannot be joined across scans.
pub fn diags_to_baseline_entries(diags: &[Diag]) -> Vec<BaselineEntry> {
    diags
        .iter()
        .filter(|d| d.stable_hash != 0)
        .map(|d| BaselineEntry {
            stable_hash: d.stable_hash,
            dynamic_verdict: d
                .evidence
                .as_ref()
                .and_then(|ev| ev.dynamic_verdict.as_ref())
                .map(|vr| vr.status),
            severity: d.severity.as_db_str().to_string(),
            path: d.path.clone(),
            rule_id: d.id.clone(),
        })
        .collect()
}

/// Write a stripped baseline JSON to `path`.
///
/// The file contains only `stable_hash`, `dynamic_verdict`, `severity`,
/// `path`, and `rule_id` — no source code snippets or flow steps.
pub fn write_baseline(path: &Path, diags: &[Diag]) -> crate::errors::NyxResult<()> {
    let entries = diags_to_baseline_entries(diags);
    let json = serde_json::to_string_pretty(&entries).map_err(|e| {
        crate::errors::NyxError::Msg(format!("baseline serialize error: {e}"))
    })?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::errors::NyxError::Msg(format!(
                    "cannot create baseline dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    std::fs::write(path, json).map_err(|e| {
        crate::errors::NyxError::Msg(format!(
            "cannot write baseline {}: {e}",
            path.display()
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Diff computation
// ─────────────────────────────────────────────────────────────────────────────

fn classify_transition(
    baseline: Option<VerifyStatus>,
    current: Option<VerifyStatus>,
) -> Transition {
    match (baseline, current) {
        // No verdict change (including both None)
        (a, b) if a == b => Transition::Unchanged,
        // Confirmed → NotConfirmed: fix proven
        (Some(VerifyStatus::Confirmed), Some(VerifyStatus::NotConfirmed)) => {
            Transition::FlippedNotConfirmed
        }
        // NotConfirmed → Confirmed: regression
        (Some(VerifyStatus::NotConfirmed), Some(VerifyStatus::Confirmed)) => {
            Transition::Regressed
        }
        // None / Inconclusive / Unsupported → Confirmed
        (_, Some(VerifyStatus::Confirmed)) => Transition::FlippedConfirmed,
        // Everything else: treat as unchanged (e.g. Confirmed → Inconclusive
        // without a clean NotConfirmed proof is not a resolution)
        _ => Transition::Unchanged,
    }
}

/// Compute a verdict diff between a loaded baseline and the current findings.
pub fn compute_verdict_diff(baseline: &[BaselineEntry], current: &[Diag]) -> VerdictDiff {
    // Build lookup maps keyed by stable_hash.
    let baseline_map: HashMap<u64, &BaselineEntry> =
        baseline.iter().map(|e| (e.stable_hash, e)).collect();
    let current_map: HashMap<u64, &Diag> = current
        .iter()
        .filter(|d| d.stable_hash != 0)
        .map(|d| (d.stable_hash, d))
        .collect();

    let mut entries = Vec::new();

    // Walk current findings.
    for (&hash, diag) in &current_map {
        let current_status = diag
            .evidence
            .as_ref()
            .and_then(|ev| ev.dynamic_verdict.as_ref())
            .map(|vr| vr.status);

        if let Some(base) = baseline_map.get(&hash) {
            let transition = classify_transition(base.dynamic_verdict, current_status);
            entries.push(VerdictDiffEntry {
                stable_hash: hash,
                path: diag.path.clone(),
                line: diag.line,
                rule_id: diag.id.clone(),
                baseline_status: base.dynamic_verdict,
                current_status,
                transition,
            });
        } else {
            // Not in baseline → New.
            entries.push(VerdictDiffEntry {
                stable_hash: hash,
                path: diag.path.clone(),
                line: diag.line,
                rule_id: diag.id.clone(),
                baseline_status: None,
                current_status,
                transition: Transition::New,
            });
        }
    }

    // Walk baseline findings absent from current → Resolved.
    for (&hash, base) in &baseline_map {
        if !current_map.contains_key(&hash) {
            entries.push(VerdictDiffEntry {
                stable_hash: hash,
                path: base.path.clone(),
                line: 0,
                rule_id: base.rule_id.clone(),
                baseline_status: base.dynamic_verdict,
                current_status: None,
                transition: Transition::Resolved,
            });
        }
    }

    // Sort for deterministic output: Resolved first, then New, then the rest,
    // all sub-sorted by (path, line).
    entries.sort_by(|a, b| {
        fn order(t: Transition) -> u8 {
            match t {
                Transition::Resolved => 0,
                Transition::FlippedNotConfirmed => 1,
                Transition::New => 2,
                Transition::Regressed => 3,
                Transition::FlippedConfirmed => 4,
                Transition::Unchanged => 5,
            }
        }
        order(a.transition)
            .cmp(&order(b.transition))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });

    VerdictDiff { entries }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CI gates
// ─────────────────────────────────────────────────────────────────────────────

/// Gate: exit code 2 if any new `Confirmed` finding appears.
///
/// Triggers on `transition == New && current_status == Confirmed` or
/// `transition == FlippedConfirmed`.
pub const GATE_NO_NEW_CONFIRMED: &str = "no-new-confirmed";

/// Gate: exit code 2 if any baseline-`Confirmed` finding is not fully resolved.
///
/// A baseline-Confirmed finding is resolved only when it is absent from the
/// current scan (`Resolved`) or its current verdict is `NotConfirmed`
/// (`FlippedNotConfirmed`).  All other current statuses (`Confirmed`,
/// `Inconclusive`, `Unsupported`) violate this gate.
pub const GATE_RESOLVE_ALL_CONFIRMED: &str = "resolve-all-confirmed";

/// Check a named CI gate against a verdict diff.
///
/// Returns `true` when the gate passes (condition not violated) and `false`
/// when it fails (caller should exit with code 2).
///
/// Unknown gate names always pass so future gate additions are forward-
/// compatible without requiring a binary upgrade.
pub fn check_gate(diff: &VerdictDiff, gate: &str) -> bool {
    match gate {
        GATE_NO_NEW_CONFIRMED => !diff.entries.iter().any(|e| {
            matches!(e.transition, Transition::New | Transition::FlippedConfirmed)
                && e.current_status == Some(VerifyStatus::Confirmed)
        }),
        GATE_RESOLVE_ALL_CONFIRMED => !diff.entries.iter().any(|e| {
            e.baseline_status == Some(VerifyStatus::Confirmed)
                && matches!(
                    e.current_status,
                    Some(VerifyStatus::Confirmed)
                        | Some(VerifyStatus::Inconclusive)
                        | Some(VerifyStatus::Unsupported)
                )
        }),
        _ => true,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Console / JSON rendering
// ─────────────────────────────────────────────────────────────────────────────

fn status_str(s: Option<VerifyStatus>) -> &'static str {
    match s {
        Some(VerifyStatus::Confirmed) => "Confirmed",
        Some(VerifyStatus::NotConfirmed) => "NotConfirmed",
        Some(VerifyStatus::Inconclusive) => "Inconclusive",
        Some(VerifyStatus::Unsupported) => "Unsupported",
        None => "(no verdict)",
    }
}

/// Render a verdict diff as a human-readable console summary.
pub fn format_diff_console(diff: &VerdictDiff) -> String {
    if diff.entries.is_empty() {
        return String::from("  (no findings in baseline or current scan)\n");
    }

    let mut lines = Vec::new();
    let mut non_unchanged = 0usize;

    for e in &diff.entries {
        let hash_str = format!("{:016x}", e.stable_hash);
        let loc = if e.line > 0 {
            format!("{}:{}", e.path, e.line)
        } else {
            e.path.clone()
        };
        match e.transition {
            Transition::New => {
                non_unchanged += 1;
                lines.push(format!(
                    "  + {hash_str}: new {} at {loc}",
                    status_str(e.current_status)
                ));
            }
            Transition::Resolved => {
                non_unchanged += 1;
                lines.push(format!(
                    "  - {hash_str}: {} \u{2192} removed (resolved) at {loc}",
                    status_str(e.baseline_status)
                ));
            }
            Transition::FlippedNotConfirmed => {
                non_unchanged += 1;
                lines.push(format!(
                    "  - {hash_str}: Confirmed \u{2192} NotConfirmed at {loc} (resolved)"
                ));
            }
            Transition::Regressed => {
                non_unchanged += 1;
                lines.push(format!(
                    "  ! {hash_str}: NotConfirmed \u{2192} Confirmed at {loc} (regressed)"
                ));
            }
            Transition::FlippedConfirmed => {
                non_unchanged += 1;
                lines.push(format!(
                    "  + {hash_str}: new Confirmed at {loc}"
                ));
            }
            Transition::Unchanged => {}
        }
    }

    if non_unchanged == 0 {
        return String::from("  (no changes from baseline)\n");
    }

    lines.join("\n") + "\n"
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::scan::{compute_stable_hash, Diag};
    use crate::evidence::{Evidence, VerifyResult, VerifyStatus};
    use crate::patterns::{FindingCategory, Severity};

    fn make_diag(path: &str, line: usize, rule: &str) -> Diag {
        let mut d = Diag {
            path: path.to_string(),
            line,
            col: 0,
            severity: Severity::High,
            id: rule.to_string(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        };
        d.stable_hash = compute_stable_hash(&d);
        d
    }

    fn with_verdict(mut d: Diag, status: VerifyStatus) -> Diag {
        d.evidence = Some(Evidence {
            dynamic_verdict: Some(VerifyResult {
                finding_id: format!("{:016x}", d.stable_hash),
                status,
                triggered_payload: None,
                reason: None,
                inconclusive_reason: None,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
                differential: None,
                replay_stable: None,
                wrong: None,
                hardening_outcome: None,
            }),
            ..Default::default()
        });
        d
    }

    #[test]
    fn new_finding_no_verdict() {
        let current = vec![make_diag("src/a.py", 1, "py.sqli")];
        let diff = compute_verdict_diff(&[], &current);
        assert_eq!(diff.entries.len(), 1);
        assert_eq!(diff.entries[0].transition, Transition::New);
        assert_eq!(diff.entries[0].current_status, None);
    }

    #[test]
    fn new_confirmed_finding() {
        let current = vec![with_verdict(
            make_diag("src/a.py", 1, "py.sqli"),
            VerifyStatus::Confirmed,
        )];
        let diff = compute_verdict_diff(&[], &current);
        assert_eq!(diff.entries[0].transition, Transition::New);
        assert_eq!(diff.entries[0].current_status, Some(VerifyStatus::Confirmed));
    }

    #[test]
    fn resolved_finding() {
        let baseline_diag = make_diag("src/a.py", 1, "py.sqli");
        let baseline = diags_to_baseline_entries(&[baseline_diag]);
        let diff = compute_verdict_diff(&baseline, &[]);
        assert_eq!(diff.entries.len(), 1);
        assert_eq!(diff.entries[0].transition, Transition::Resolved);
    }

    #[test]
    fn flipped_not_confirmed() {
        let d = make_diag("src/a.py", 1, "py.sqli");
        let baseline = vec![BaselineEntry {
            stable_hash: d.stable_hash,
            dynamic_verdict: Some(VerifyStatus::Confirmed),
            severity: "high".to_string(),
            path: d.path.clone(),
            rule_id: d.id.clone(),
        }];
        let current = vec![with_verdict(d, VerifyStatus::NotConfirmed)];
        let diff = compute_verdict_diff(&baseline, &current);
        assert_eq!(diff.entries[0].transition, Transition::FlippedNotConfirmed);
    }

    #[test]
    fn regressed() {
        let d = make_diag("src/a.py", 1, "py.sqli");
        let baseline = vec![BaselineEntry {
            stable_hash: d.stable_hash,
            dynamic_verdict: Some(VerifyStatus::NotConfirmed),
            severity: "high".to_string(),
            path: d.path.clone(),
            rule_id: d.id.clone(),
        }];
        let current = vec![with_verdict(d, VerifyStatus::Confirmed)];
        let diff = compute_verdict_diff(&baseline, &current);
        assert_eq!(diff.entries[0].transition, Transition::Regressed);
    }

    #[test]
    fn gate_no_new_confirmed_passes_when_no_confirmed() {
        let d = make_diag("src/a.py", 1, "py.sqli");
        let diff = compute_verdict_diff(&[], &[d]);
        assert!(check_gate(&diff, GATE_NO_NEW_CONFIRMED));
    }

    #[test]
    fn gate_no_new_confirmed_fails_on_new_confirmed() {
        let current = vec![with_verdict(
            make_diag("src/a.py", 1, "py.sqli"),
            VerifyStatus::Confirmed,
        )];
        let diff = compute_verdict_diff(&[], &current);
        assert!(!check_gate(&diff, GATE_NO_NEW_CONFIRMED));
    }

    #[test]
    fn gate_resolve_all_confirmed_passes_when_flipped() {
        let d = make_diag("src/a.py", 1, "py.sqli");
        let baseline = vec![BaselineEntry {
            stable_hash: d.stable_hash,
            dynamic_verdict: Some(VerifyStatus::Confirmed),
            severity: "high".to_string(),
            path: d.path.clone(),
            rule_id: d.id.clone(),
        }];
        let current = vec![with_verdict(d, VerifyStatus::NotConfirmed)];
        let diff = compute_verdict_diff(&baseline, &current);
        assert!(check_gate(&diff, GATE_RESOLVE_ALL_CONFIRMED));
    }

    #[test]
    fn gate_resolve_all_confirmed_fails_when_still_confirmed() {
        let d = make_diag("src/a.py", 1, "py.sqli");
        let baseline = vec![BaselineEntry {
            stable_hash: d.stable_hash,
            dynamic_verdict: Some(VerifyStatus::Confirmed),
            severity: "high".to_string(),
            path: d.path.clone(),
            rule_id: d.id.clone(),
        }];
        let current = vec![with_verdict(d, VerifyStatus::Confirmed)];
        let diff = compute_verdict_diff(&baseline, &current);
        assert!(!check_gate(&diff, GATE_RESOLVE_ALL_CONFIRMED));
    }

    #[test]
    fn gate_resolve_all_confirmed_passes_when_resolved() {
        let d = make_diag("src/a.py", 1, "py.sqli");
        let baseline = vec![BaselineEntry {
            stable_hash: d.stable_hash,
            dynamic_verdict: Some(VerifyStatus::Confirmed),
            severity: "high".to_string(),
            path: d.path.clone(),
            rule_id: d.id.clone(),
        }];
        // No current findings (finding disappeared entirely).
        let diff = compute_verdict_diff(&baseline, &[]);
        assert!(check_gate(&diff, GATE_RESOLVE_ALL_CONFIRMED));
    }

    #[test]
    fn write_and_load_roundtrip() {
        let d = with_verdict(make_diag("src/a.py", 1, "py.sqli"), VerifyStatus::Confirmed);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_baseline(tmp.path(), &[d.clone()]).unwrap();
        let loaded = load_baseline(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].stable_hash, d.stable_hash);
        assert_eq!(loaded[0].dynamic_verdict, Some(VerifyStatus::Confirmed));
        assert_eq!(loaded[0].path, "src/a.py");
        assert_eq!(loaded[0].rule_id, "py.sqli");
    }

    #[test]
    fn load_full_diag_json() {
        let d = with_verdict(make_diag("src/a.py", 1, "py.sqli"), VerifyStatus::Confirmed);
        let json = serde_json::to_string(&[&d]).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &json).unwrap();
        let loaded = load_baseline(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].stable_hash, d.stable_hash);
    }

    #[test]
    fn baseline_write_no_source() {
        let mut d = with_verdict(make_diag("src/a.py", 1, "py.sqli"), VerifyStatus::Confirmed);
        // Add a flow_step with a snippet (source code) to the evidence.
        if let Some(ref mut ev) = d.evidence {
            ev.flow_steps = vec![crate::evidence::FlowStep {
                step: 1,
                kind: crate::evidence::FlowStepKind::Source,
                file: "src/a.py".into(),
                line: 1,
                col: 0,
                snippet: Some("SECRET CODE".into()),
                variable: None,
                callee: None,
                function: None,
                is_cross_file: false,
            }];
        }
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_baseline(tmp.path(), &[d]).unwrap();
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(!content.contains("SECRET CODE"), "baseline must not contain source code");
    }

    #[test]
    fn unknown_gate_passes() {
        let diff = VerdictDiff { entries: vec![] };
        assert!(check_gate(&diff, "some-future-gate-name"));
    }
}

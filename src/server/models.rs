use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence, VerifyResult, VerifyStatus};
use crate::patterns::{FindingCategory, Severity};
use crate::utils::path::{DEFAULT_UI_MAX_FILE_BYTES, open_repo_text_file};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// Compact related-finding reference for the detail panel.
#[derive(Debug, Clone, Serialize)]
pub struct RelatedFindingView {
    pub index: usize,
    pub rule_id: String,
    pub path: String,
    pub line: usize,
    pub severity: Severity,
}

/// Valid triage states for findings.
pub const VALID_TRIAGE_STATES: &[&str] = &[
    "open",
    "investigating",
    "false_positive",
    "accepted_risk",
    "suppressed",
    "fixed",
];

/// Valid dynamic verification states for findings.
pub const VALID_DYNAMIC_VERIFICATION_STATES: &[&str] = &[
    "Confirmed",
    "NotConfirmed",
    "Inconclusive",
    "Unsupported",
    "Unverified",
];

/// Check if a string is a valid triage state.
pub fn is_valid_triage_state(s: &str) -> bool {
    VALID_TRIAGE_STATES.contains(&s)
}

/// Serializable API representation of a Diag finding.
#[derive(Debug, Clone, Serialize)]
pub struct FindingView {
    pub index: usize,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub portable_fingerprint: String,
    /// Blake3-derived stable cross-commit identity hash (M6.5). Zero when not
    /// yet computed (server-side scans always compute it post-analysis).
    #[serde(skip_serializing_if = "crate::server::models::is_zero_u64")]
    pub stable_hash: u64,
    pub path: String,
    pub line: usize,
    pub col: usize,
    pub severity: Severity,
    pub rule_id: String,
    pub category: FindingCategory,
    pub confidence: Option<Confidence>,
    pub rank_score: Option<f64>,
    pub message: Option<String>,
    pub labels: Vec<(String, String)>,
    pub path_validated: bool,
    pub suppressed: bool,
    pub language: Option<String>,
    pub status: String,
    pub triage_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub triage_note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_context: Option<CodeContextView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_verdict: Option<VerifyResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank_reason: Option<Vec<(String, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizer_status: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_findings: Vec<RelatedFindingView>,
}

/// Lines of source code around a finding for display.
#[derive(Debug, Clone, Serialize)]
pub struct CodeContextView {
    pub start_line: usize,
    pub lines: Vec<String>,
    pub highlight_line: usize,
}

/// Aggregate statistics for a set of findings.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FindingSummary {
    pub total: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_rule: HashMap<String, usize>,
    pub by_file: HashMap<String, usize>,
}

/// A scan job as seen by the API.
#[derive(Debug, Clone, Serialize)]
pub struct ScanView {
    pub id: String,
    pub status: String,
    pub scan_root: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_secs: Option<f64>,
    pub finding_count: Option<usize>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_scanned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<crate::server::progress::TimingBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::server::progress::ScanMetricsSnapshot>,
}

/// Custom rule view for the config API.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct RuleView {
    pub lang: String,
    pub matchers: Vec<String>,
    pub kind: String,
    pub cap: String,
}

/// Terminator view for the config API.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TerminatorView {
    pub lang: String,
    pub name: String,
}

/// Rule list item for GET /api/rules (built-in + custom, with metadata).
#[derive(Debug, Clone, Serialize)]
pub struct RuleListItem {
    pub id: String,
    pub title: String,
    pub language: String,
    pub kind: String,
    pub cap: String,
    pub matchers: Vec<String>,
    pub enabled: bool,
    pub is_custom: bool,
    pub is_gated: bool,
    pub is_class: bool,
    pub case_sensitive: bool,
    pub finding_count: usize,
    pub suppression_rate: f64,
}

/// Full rule detail for GET /api/rules/:id
#[derive(Debug, Clone, Serialize)]
pub struct RuleDetailView {
    pub id: String,
    pub title: String,
    pub language: String,
    pub kind: String,
    pub cap: String,
    pub matchers: Vec<String>,
    pub case_sensitive: bool,
    pub enabled: bool,
    pub is_custom: bool,
    pub is_gated: bool,
    pub is_class: bool,
    pub finding_count: usize,
    pub suppression_rate: f64,
    pub example_findings: Vec<RelatedFindingView>,
}

/// Label entry for sources/sinks/sanitizers listing.
///
/// `case_sensitive` and `is_builtin` default to `false` on deserialize so POST
/// bodies from the UI (which only supply `lang`, `matchers`, `cap`) succeed.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LabelEntryView {
    pub lang: String,
    pub matchers: Vec<String>,
    pub cap: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub is_builtin: bool,
}

/// Profile view for profile listing.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileView {
    pub name: String,
    pub is_builtin: bool,
    pub settings: serde_json::Value,
}

/// Distinct filter values available in a set of findings.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FilterValues {
    pub severities: Vec<String>,
    pub categories: Vec<String>,
    pub confidences: Vec<String>,
    pub languages: Vec<String>,
    pub rules: Vec<String>,
    pub statuses: Vec<String>,
    pub verification_statuses: Vec<String>,
}

/// Collect distinct filter values from a slice of diagnostics.
pub fn collect_filter_values(findings: &[Diag]) -> FilterValues {
    let mut severities = BTreeSet::new();
    let mut categories = BTreeSet::new();
    let mut confidences = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut rules = BTreeSet::new();
    let mut statuses = BTreeSet::new();
    let mut verification_statuses = BTreeSet::new();

    for d in findings {
        severities.insert(d.severity.as_db_str().to_string());
        categories.insert(d.category.to_string());
        if let Some(c) = d.confidence {
            confidences.insert(format!("{c:?}"));
        }
        if let Some(lang) = lang_for_finding_path(&d.path) {
            languages.insert(lang);
        }
        rules.insert(d.id.clone());
        statuses.insert(status_for_diag(d));
        verification_statuses.insert(
            dynamic_status_for_diag(d)
                .unwrap_or("Unverified")
                .to_string(),
        );
    }

    // Always include all valid triage states so the filter dropdown is complete
    for s in VALID_TRIAGE_STATES {
        statuses.insert(s.to_string());
    }
    for s in VALID_DYNAMIC_VERIFICATION_STATES {
        verification_statuses.insert(s.to_string());
    }

    FilterValues {
        severities: severities.into_iter().collect(),
        categories: categories.into_iter().collect(),
        confidences: confidences.into_iter().collect(),
        languages: languages.into_iter().collect(),
        rules: rules.into_iter().collect(),
        statuses: statuses.into_iter().collect(),
        verification_statuses: verification_statuses.into_iter().collect(),
    }
}

/// Map a finding file path extension to a human-readable language name.
pub fn lang_for_finding_path(path: &str) -> Option<String> {
    let ext = path.rsplit('.').next()?;
    match ext.to_ascii_lowercase().as_str() {
        "rs" => Some("Rust".into()),
        "c" => Some("C".into()),
        "cpp" => Some("C++".into()),
        "java" => Some("Java".into()),
        "go" => Some("Go".into()),
        "php" => Some("PHP".into()),
        "py" => Some("Python".into()),
        "ts" => Some("TypeScript".into()),
        "js" => Some("JavaScript".into()),
        "rb" => Some("Ruby".into()),
        _ => None,
    }
}

/// Compute the status string for a diagnostic.
fn status_for_diag(d: &Diag) -> String {
    if !crate::commands::scan::is_default_triage_state(&d.triage_state) {
        d.triage_state.clone()
    } else if d.suppressed {
        "suppressed".to_string()
    } else if d.path_validated {
        "validated".to_string()
    } else {
        "open".to_string()
    }
}

/// Human-readable dynamic status used by API filters and table rows.
pub fn dynamic_status_label(status: VerifyStatus) -> &'static str {
    match status {
        VerifyStatus::Confirmed => "Confirmed",
        VerifyStatus::PartiallyConfirmed => "PartiallyConfirmed",
        VerifyStatus::NotConfirmed => "NotConfirmed",
        VerifyStatus::Inconclusive => "Inconclusive",
        VerifyStatus::Unsupported => "Unsupported",
    }
}

/// Dynamic verification status for a diagnostic, when a verdict exists.
pub fn dynamic_status_for_diag(d: &Diag) -> Option<&'static str> {
    d.evidence
        .as_ref()
        .and_then(|ev| ev.dynamic_verdict.as_ref())
        .map(|verdict| dynamic_status_label(verdict.status))
}

pub(crate) fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Convert a Diag to a FindingView at a given index.
pub fn finding_from_diag(index: usize, d: &Diag) -> FindingView {
    FindingView {
        index,
        fingerprint: compute_fingerprint(d),
        portable_fingerprint: String::new(), // set by caller with scan_root
        stable_hash: d.stable_hash,
        path: d.path.clone(),
        line: d.line,
        col: d.col,
        severity: d.severity,
        rule_id: d.id.clone(),
        category: d.category,
        confidence: d.confidence,
        rank_score: d.rank_score,
        message: d.message.clone(),
        labels: d.labels.clone(),
        path_validated: d.path_validated,
        suppressed: d.suppressed,
        language: lang_for_finding_path(&d.path),
        status: status_for_diag(d),
        triage_state: d.triage_state.clone(),
        triage_note: d.triage_note.clone(),
        code_context: None,
        evidence: None,
        dynamic_verdict: d
            .evidence
            .as_ref()
            .and_then(|ev| ev.dynamic_verdict.clone()),
        guard_kind: None,
        rank_reason: None,
        sanitizer_status: None,
        related_findings: vec![],
    }
}

/// Convert a Diag to a FindingView with code context loaded from disk.
pub fn finding_from_diag_with_context(index: usize, d: &Diag, scan_root: &Path) -> FindingView {
    let mut view = finding_from_diag(index, d);
    view.code_context = load_code_context(&d.path, d.line, scan_root);
    view
}

/// Convert a Diag to a FindingView with full detail (evidence, related findings).
pub fn finding_from_diag_with_detail(
    index: usize,
    d: &Diag,
    scan_root: &Path,
    all_findings: &[Diag],
) -> FindingView {
    let mut view = finding_from_diag_with_context(index, d, scan_root);

    // Evidence (pass through the core type directly)
    view.evidence = d.evidence.clone();
    view.guard_kind = d.guard_kind.clone();
    view.rank_reason = d.rank_reason.clone();

    // Sanitizer status
    view.sanitizer_status = Some(compute_sanitizer_status(d));

    // Related findings: same rule_id OR same file, excluding self, capped at 10
    let mut related = Vec::new();
    for (i, other) in all_findings.iter().enumerate() {
        if i == index {
            continue;
        }
        if other.id == d.id || other.path == d.path {
            related.push(RelatedFindingView {
                index: i,
                rule_id: other.id.clone(),
                path: other.path.clone(),
                line: other.line,
                severity: other.severity,
            });
            if related.len() >= 10 {
                break;
            }
        }
    }
    view.related_findings = related;

    view
}

/// Compute the sanitizer status for a diagnostic based on its evidence.
fn compute_sanitizer_status(d: &Diag) -> String {
    match &d.evidence {
        Some(ev) if !ev.sanitizers.is_empty() => {
            if d.suppressed {
                "applied".into()
            } else {
                "bypassed".into()
            }
        }
        _ => "none".into(),
    }
}

/// Load surrounding lines of code for a finding.
fn load_code_context(path: &str, line: usize, scan_root: &Path) -> Option<CodeContextView> {
    let opened = open_repo_text_file(scan_root, path, DEFAULT_UI_MAX_FILE_BYTES).ok()?;
    let content = opened.content;
    let all_lines: Vec<&str> = content.lines().collect();

    if line == 0 || line > all_lines.len() {
        return None;
    }

    let context_radius = 5;
    let start = line.saturating_sub(context_radius).max(1);
    let end = (line + context_radius).min(all_lines.len());

    let lines: Vec<String> = all_lines[start - 1..end]
        .iter()
        .map(|l| (*l).to_string())
        .collect();

    Some(CodeContextView {
        start_line: start,
        lines,
        highlight_line: line,
    })
}

// ── Scan Comparison Types ────────────────────────────────────────────────────

/// Full response from the scan comparison endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct CompareResponse {
    pub left_scan: CompareScanInfo,
    pub right_scan: CompareScanInfo,
    pub summary: CompareSummary,
    pub new_findings: Vec<ComparedFinding>,
    pub fixed_findings: Vec<ComparedFinding>,
    pub changed_findings: Vec<ChangedFinding>,
    pub unchanged_findings: Vec<ComparedFinding>,
    /// Verdict-level diff entries (M6.5). Populated when findings in both
    /// scans carry `stable_hash` values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verdict_diff: Vec<crate::baseline::VerdictDiffEntry>,
}

/// Minimal scan metadata for comparison headers.
#[derive(Debug, Clone, Serialize)]
pub struct CompareScanInfo {
    pub id: String,
    pub started_at: Option<String>,
    pub finding_count: usize,
}

/// Aggregate counts and severity deltas for a comparison.
#[derive(Debug, Clone, Serialize)]
pub struct CompareSummary {
    pub new_count: usize,
    pub fixed_count: usize,
    pub changed_count: usize,
    pub unchanged_count: usize,
    pub severity_delta: HashMap<String, i64>,
}

/// A finding annotated with its fingerprint for comparison views.
#[derive(Debug, Clone, Serialize)]
pub struct ComparedFinding {
    pub fingerprint: String,
    #[serde(flatten)]
    pub finding: FindingView,
}

/// A finding that exists in both scans but with changed properties.
#[derive(Debug, Clone, Serialize)]
pub struct ChangedFinding {
    pub fingerprint: String,
    #[serde(flatten)]
    pub finding: FindingView,
    pub changes: Vec<FieldChange>,
}

/// A single field that differs between two scans for the same fingerprint.
#[derive(Debug, Clone, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Compute a stable fingerprint for a finding based on identity fields.
///
/// The fingerprint is a blake3 hash of (rule_id, file_path, sink_snippet,
/// source_snippet, function_context). Line/col are intentionally excluded
/// so that fingerprints survive code movement.
pub fn compute_fingerprint(d: &Diag) -> String {
    let sink_snippet = d
        .evidence
        .as_ref()
        .and_then(|e| e.sink.as_ref())
        .and_then(|s| s.snippet.as_deref())
        .unwrap_or("");
    let source_snippet = d
        .evidence
        .as_ref()
        .and_then(|e| e.source.as_ref())
        .and_then(|s| s.snippet.as_deref())
        .unwrap_or("");
    let func_ctx = d
        .evidence
        .as_ref()
        .and_then(|e| e.flow_steps.iter().find_map(|s| s.function.as_deref()))
        .unwrap_or("");
    let input = format!(
        "{}\0{}\0{}\0{}\0{}",
        d.id, d.path, sink_snippet, source_snippet, func_ctx
    );
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Overlay triage states from the database onto a slice of FindingViews.
///
/// For each finding, first checks for an explicit triage state by fingerprint.
/// If none, checks suppression rules in order: fingerprint → rule → rule_in_file → file.
pub fn overlay_triage_states(
    views: &mut [FindingView],
    triage_map: &std::collections::HashMap<String, (String, String, String)>,
    suppression_rules: &[crate::database::index::SuppressionRule],
) {
    for view in views.iter_mut() {
        if let Some((state, note, _)) = triage_map.get(&view.fingerprint) {
            view.triage_state = state.clone();
            view.triage_note = note.clone();
            view.status = state.clone();
        } else {
            for rule in suppression_rules {
                let matches = match rule.suppress_by.as_str() {
                    "fingerprint" => view.fingerprint == rule.match_value,
                    "rule" => view.rule_id == rule.match_value,
                    "rule_in_file" => {
                        let key = format!("{}:{}", view.rule_id, view.path);
                        key == rule.match_value
                    }
                    "file" => view.path == rule.match_value,
                    _ => false,
                };
                if matches {
                    view.triage_state = rule.state.clone();
                    view.triage_note = rule.note.clone();
                    view.status = rule.state.clone();
                    break;
                }
            }
        }
    }
}

/// Compute a portable fingerprint using a path relative to scan_root.
///
/// This fingerprint is stable across machines because it strips the absolute
/// path prefix. Used for `.nyx/triage.json` sync files that get committed to git.
pub fn compute_portable_fingerprint(d: &Diag, scan_root: &Path) -> String {
    let rel_path = d
        .path
        .strip_prefix(scan_root.to_string_lossy().as_ref())
        .unwrap_or(&d.path)
        .trim_start_matches('/');
    let sink_snippet = d
        .evidence
        .as_ref()
        .and_then(|e| e.sink.as_ref())
        .and_then(|s| s.snippet.as_deref())
        .unwrap_or("");
    let source_snippet = d
        .evidence
        .as_ref()
        .and_then(|e| e.source.as_ref())
        .and_then(|s| s.snippet.as_deref())
        .unwrap_or("");
    let func_ctx = d
        .evidence
        .as_ref()
        .and_then(|e| e.flow_steps.iter().find_map(|s| s.function.as_deref()))
        .unwrap_or("");
    let input = format!(
        "{}\0{}\0{}\0{}\0{}",
        d.id, rel_path, sink_snippet, source_snippet, func_ctx
    );
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Build a summary from a slice of findings.
pub fn summarize_findings(findings: &[Diag]) -> FindingSummary {
    let mut summary = FindingSummary {
        total: findings.len(),
        ..Default::default()
    };

    for d in findings {
        let sev_key = d.severity.as_db_str().to_string();
        *summary.by_severity.entry(sev_key).or_insert(0) += 1;
        *summary
            .by_category
            .entry(d.category.to_string())
            .or_insert(0) += 1;
        *summary.by_rule.entry(d.id.clone()).or_insert(0) += 1;
        *summary.by_file.entry(d.path.clone()).or_insert(0) += 1;
    }

    summary
}

// ── Overview Types ───────────────────────────────────────────────────────────

/// Full response for GET /api/overview.
#[derive(Debug, Clone, Serialize)]
pub struct OverviewResponse {
    pub state: String,
    pub total_findings: usize,
    pub new_since_last: usize,
    pub fixed_since_last: usize,
    pub high_confidence_rate: f64,
    pub triage_coverage: f64,
    pub latest_scan_duration_secs: Option<f64>,
    pub latest_scan_id: Option<String>,
    pub latest_scan_at: Option<String>,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_language: HashMap<String, usize>,
    pub top_files: Vec<OverviewCount>,
    pub top_directories: Vec<OverviewCount>,
    pub top_rules: Vec<OverviewCount>,
    pub noisy_rules: Vec<NoisyRule>,
    pub recent_scans: Vec<ScanSummary>,
    pub insights: Vec<Insight>,

    // ── Tier 1 ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthScore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backlog: Option<BacklogStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weighted_top_files: Vec<WeightedFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_distribution: Option<ConfidenceDistribution>,

    // ── Tier 2 ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_quality: Option<ScannerQuality>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issue_categories: Vec<IssueCategoryBucket>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hot_sinks: Vec<HotSink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_buckets: Vec<OwaspBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_file_ratio: Option<f64>,

    // ── Tier 3 ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub language_health: Vec<LanguageHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_hygiene: Option<SuppressionHygiene>,
}

/// Composite repo-health rollup.
#[derive(Debug, Clone, Serialize)]
pub struct HealthScore {
    /// 0–100 score; higher is better.
    pub score: u8,
    /// Letter grade A–F derived from score.
    pub grade: String,
    /// Sub-component contributions (0–100 each) for transparency.
    pub components: Vec<HealthComponent>,
}

/// Single line item in the health-score breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct HealthComponent {
    /// Human label (e.g. "Severity pressure", "Trend", "Triage").
    pub label: String,
    /// 0–100, already inverted so higher = healthier.
    pub score: u8,
    /// Weight applied when blending into the final score (0.0–1.0).
    pub weight: f64,
    /// Short rationale shown in tooltip.
    pub detail: String,
}

/// One-line trend posture for the page header.
#[derive(Debug, Clone, Serialize)]
pub struct PostureSummary {
    /// "improving" | "regressing" | "stable" | "unknown"
    pub trend: String,
    /// "success" | "warning" | "danger" | "info"
    pub severity: String,
    /// Short message shown verbatim in the banner.
    pub message: String,
    /// Findings that were previously fixed and have re-appeared.
    pub reintroduced_count: usize,
}

/// Backlog age statistics computed from finding_first_seen.
#[derive(Debug, Clone, Serialize)]
pub struct BacklogStats {
    /// Days since the oldest still-open finding was first seen.
    pub oldest_open_days: Option<u32>,
    /// Median age of currently-open findings, in days.
    pub median_age_days: Option<u32>,
    /// Findings older than 30 days that remain open.
    pub stale_count: usize,
    /// Histogram buckets (label, count), fixed 5 buckets.
    pub age_buckets: Vec<OverviewCount>,
}

/// Top-file row including severity stack for the weighted ranking.
#[derive(Debug, Clone, Serialize)]
pub struct WeightedFile {
    pub name: String,
    pub score: u32,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

/// Confidence-level distribution.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ConfidenceDistribution {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub none: usize,
}

/// Engine-quality metrics that describe analysis depth/coverage.
#[derive(Debug, Clone, Serialize)]
pub struct ScannerQuality {
    pub files_scanned: u64,
    pub files_skipped: u64,
    /// 0.0–1.0, files_scanned / (files_scanned + files_skipped).
    pub parse_success_rate: f64,
    pub functions_analyzed: u64,
    pub call_edges: u64,
    pub unresolved_calls: u64,
    /// 0.0–1.0, call_edges / (call_edges + unresolved_calls).
    pub call_resolution_rate: f64,
    /// % of taint findings that received a symbolic verdict (Confirmed|Infeasible|Inconclusive).
    pub symex_verified_rate: f64,
    /// Count broken down by symbolic verdict label.
    pub symex_breakdown: HashMap<String, usize>,
    /// Dynamic verifier verdict counts from the latest scan.
    pub dynamic_verification: crate::commands::scan::DynamicVerificationSummary,
}

/// One issue-category bucket (rule-family derived). Broader than OWASP, with
/// engine-friendly labels like "Tainted Flow" or "Code Quality".
#[derive(Debug, Clone, Serialize)]
pub struct IssueCategoryBucket {
    pub label: String,
    pub count: usize,
}

/// "Hot sink", a single callee that absorbs many findings.
#[derive(Debug, Clone, Serialize)]
pub struct HotSink {
    /// Callee name (best-effort; from flow_steps last Sink).
    pub callee: String,
    pub count: usize,
}

/// One OWASP Top-10 (2021) bucket.
#[derive(Debug, Clone, Serialize)]
pub struct OwaspBucket {
    /// "A01:2021, Broken Access Control" etc.
    pub code: String,
    pub label: String,
    pub count: usize,
}

/// Per-language posture.
#[derive(Debug, Clone, Serialize)]
pub struct LanguageHealth {
    pub language: String,
    pub findings: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Suppression-quality breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct SuppressionHygiene {
    /// Findings explicitly triaged by fingerprint.
    pub fingerprint_level: usize,
    /// Findings suppressed by rule-level suppression.
    pub rule_level: usize,
    /// Findings suppressed by file-level suppression.
    pub file_level: usize,
    /// Findings suppressed by rule-in-file suppression.
    pub rule_in_file_level: usize,
    /// % of suppressed findings using low-specificity (rule/file/rule_in_file) rules.
    pub blanket_rate: f64,
}

/// Pinned baseline scan and current drift relative to it.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineInfo {
    pub scan_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    pub baseline_total: usize,
    pub drift_new: usize,
    pub drift_fixed: usize,
}

/// A name + count pair for overview top-N lists.
#[derive(Debug, Clone, Serialize)]
pub struct OverviewCount {
    pub name: String,
    pub count: usize,
}

/// A rule that has high finding count + high suppression rate.
#[derive(Debug, Clone, Serialize)]
pub struct NoisyRule {
    pub rule_id: String,
    pub finding_count: usize,
    pub suppression_rate: f64,
}

/// Compact scan info for the overview recent-scans list.
#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub duration_secs: Option<f64>,
    pub finding_count: Option<i64>,
}

/// An actionable insight for the overview page.
#[derive(Debug, Clone, Serialize)]
pub struct Insight {
    pub kind: String,
    pub message: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
}

/// A single trend data point for GET /api/overview/trends.
#[derive(Debug, Clone, Serialize)]
pub struct TrendPoint {
    pub scan_id: String,
    pub timestamp: String,
    pub total: usize,
    pub by_severity: HashMap<String, usize>,
}

/// Count findings grouped by language.
pub fn by_language_from_findings(findings: &[Diag]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for d in findings {
        if let Some(lang) = lang_for_finding_path(&d.path) {
            *map.entry(lang).or_insert(0) += 1;
        }
    }
    map
}

/// Extract top N directories by finding count.
pub fn top_directories_from_findings(findings: &[Diag], limit: usize) -> Vec<OverviewCount> {
    let mut dir_counts: HashMap<String, usize> = HashMap::new();
    for d in findings {
        let dir = match d.path.rfind('/') {
            Some(i) => &d.path[..i],
            None => ".",
        };
        *dir_counts.entry(dir.to_string()).or_insert(0) += 1;
    }
    let mut sorted: Vec<_> = dir_counts.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    sorted.truncate(limit);
    sorted
        .into_iter()
        .map(|(name, count)| OverviewCount { name, count })
        .collect()
}

/// Sort a HashMap by value descending, take top N, return as OverviewCount.
pub fn top_n_from_map(map: &HashMap<String, usize>, limit: usize) -> Vec<OverviewCount> {
    let mut sorted: Vec<_> = map.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    sorted
        .into_iter()
        .take(limit)
        .map(|(name, &count)| OverviewCount {
            name: name.clone(),
            count,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag_for_path(path: String) -> Diag {
        Diag {
            path,
            line: 1,
            col: 1,
            severity: Severity::Low,
            id: "test.rule".to_string(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: Vec::new(),
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
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
    fn code_context_does_not_read_outside_repo_for_absolute_paths() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "secret").unwrap();

        let diag = diag_for_path(outside.path().to_string_lossy().to_string());
        let view = finding_from_diag_with_context(0, &diag, root.path());

        assert!(view.code_context.is_none());
    }

    #[test]
    fn code_context_reads_repo_files() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("src.rs");
        std::fs::write(&file, "line1\nline2\n").unwrap();

        let diag = diag_for_path(file.to_string_lossy().to_string());
        let view = finding_from_diag_with_context(0, &diag, root.path());

        assert!(view.code_context.is_some());
        assert_eq!(view.code_context.unwrap().highlight_line, 1);
    }
}

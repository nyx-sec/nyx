#![allow(clippy::collapsible_if)]

use crate::commands::scan::Diag;
use crate::database::index::{Indexer, ScanRecord};
use crate::evidence::{Confidence, Verdict};
use crate::server::app::AppState;
use crate::server::models::{
    BacklogStats, BaselineInfo, ConfidenceDistribution, HotSink, Insight, LanguageHealth,
    NoisyRule, OverviewCount, OverviewResponse, PostureSummary, ScanSummary, ScannerQuality,
    SuppressionHygiene, TrendPoint, WeightedFile, by_language_from_findings, compute_fingerprint,
    lang_for_finding_path, summarize_findings, top_directories_from_findings, top_n_from_map,
};
use crate::server::owasp;
use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

const BASELINE_KEY: &str = "baseline_scan_id";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/overview/trends", get(overview_trends))
        .route("/overview/baseline", post(set_baseline))
        .route("/overview/baseline", delete(clear_baseline))
        .route("/overview/baseline/{scan_id}", post(set_baseline_path))
}

/// GET /api/overview, aggregated dashboard data.
async fn overview(State(state): State<AppState>) -> Json<OverviewResponse> {
    // 1. Load latest findings (in-memory → DB fallback)
    let findings = crate::server::routes::findings::load_latest_findings(&state);

    // 2. Collect recent scans (in-memory + DB, deduped)
    let recent_scans = collect_recent_scans(&state, 20);

    // 3. Basic summary
    let summary = summarize_findings(&findings);
    let by_language = by_language_from_findings(&findings);

    // 4. Find latest completed scan info
    let latest_completed = recent_scans.iter().find(|s| s.status == "completed");
    let latest_scan_id = latest_completed.map(|s| s.id.clone());
    let latest_scan_at = latest_completed.and_then(|s| s.started_at.clone());
    let latest_scan_duration = latest_completed.and_then(|s| s.duration_secs);

    // 5. Walk historical scans once for delta + posture + backlog + drift.
    let history = ScanHistory::load(&state, 20);
    let (new_since_last, fixed_since_last, reintroduced_count) =
        history.compare_to_current(&findings);

    // 6. High confidence rate
    let high_confidence_rate = if findings.is_empty() {
        0.0
    } else {
        let high_count = findings
            .iter()
            .filter(|d| d.confidence == Some(Confidence::High))
            .count();
        high_count as f64 / findings.len() as f64
    };

    // 7. Triage coverage
    let triage_coverage = compute_triage_coverage(&state, &findings);

    // 8. Top files, dirs, rules
    let top_files = top_n_from_map(&summary.by_file, 10);
    let top_directories = top_directories_from_findings(&findings, 10);
    let top_rules = top_n_from_map(&summary.by_rule, 10);

    // 9. Noisy rules
    let noisy_rules = compute_noisy_rules(&state, &findings, &summary.by_rule);

    // 10. Insights
    let insights = generate_insights(
        &summary,
        new_since_last,
        fixed_since_last,
        reintroduced_count,
        triage_coverage,
        &noisy_rules,
    );

    // 11. State
    let state_str = if recent_scans.iter().all(|s| s.status != "completed") {
        "empty".to_string()
    } else if is_fresh_scan(latest_completed) {
        "fresh".to_string()
    } else {
        "normal".to_string()
    };

    // ── New (Tier 1/2/3) ──
    let confidence_distribution = Some(compute_confidence_distribution(&findings));
    let weighted_top_files = compute_weighted_top_files(&findings, 10);
    let cross_file_ratio = Some(compute_cross_file_ratio(&findings));
    let hot_sinks = compute_hot_sinks(&findings, 5);
    let owasp_buckets = owasp::bucket_findings(&summary.by_rule);
    let issue_categories = owasp::issue_categories(&summary.by_rule);
    let scanner_quality =
        compute_scanner_quality(&state, &findings, latest_completed.map(|s| s.id.as_str()));
    let language_health = compute_language_health(&findings);
    let suppression_hygiene = Some(compute_suppression_hygiene(&state, &findings));
    let backlog = Some(compute_backlog(&state, &findings, &history));
    let baseline = compute_baseline_info(&state, &findings);
    let posture = Some(build_posture(
        new_since_last,
        fixed_since_last,
        reintroduced_count,
        &history,
        summary.total,
    ));
    let health = Some(crate::server::health::compute(
        &crate::server::health::HealthInputs {
            summary: &summary,
            findings: &findings,
            triage_coverage,
            new_since_last,
            fixed_since_last,
            reintroduced: reintroduced_count,
            // Files-scanned proxy for repo size, used for size-aware
            // severity dampening in `health::compute`.
            repo_files: scanner_quality
                .as_ref()
                .map(|q| q.files_scanned)
                .filter(|&f| f > 0),
            backlog: backlog.as_ref(),
            // Trend is meaningless without ≥2 completed scans ,
            // matches the first-scan check `compare_to_current` uses.
            has_history: history.scans.len() >= 2,
            // Suppression-hygiene modifier, populated when the
            // suppression panel was computable for this scan.
            blanket_suppression_rate: suppression_hygiene.as_ref().map(|s| s.blanket_rate),
        },
    ));

    Json(OverviewResponse {
        state: state_str,
        total_findings: summary.total,
        new_since_last,
        fixed_since_last,
        high_confidence_rate,
        triage_coverage,
        latest_scan_duration_secs: latest_scan_duration,
        latest_scan_id,
        latest_scan_at,
        by_severity: summary.by_severity.clone(),
        by_category: summary.by_category,
        by_language,
        top_files,
        top_directories,
        top_rules,
        noisy_rules,
        recent_scans: recent_scans.into_iter().take(10).collect(),
        insights,
        health,
        posture,
        backlog,
        weighted_top_files,
        confidence_distribution,
        scanner_quality,
        issue_categories,
        hot_sinks,
        owasp_buckets,
        cross_file_ratio,
        baseline,
        language_health,
        suppression_hygiene,
    })
}

/// GET /api/overview/trends, scan-over-scan finding counts.
async fn overview_trends(State(state): State<AppState>) -> Json<Vec<TrendPoint>> {
    let mut points = Vec::new();

    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(scans) = idx.list_scans(20) {
                let completed: Vec<&ScanRecord> =
                    scans.iter().filter(|s| s.status == "completed").collect();

                // Cap at 10 for performance
                for scan in completed.iter().rev().take(10) {
                    let total = scan.finding_count.unwrap_or(0) as usize;
                    let by_severity = scan
                        .findings_json
                        .as_deref()
                        .and_then(|json| serde_json::from_str::<Vec<Diag>>(json).ok())
                        .map(|diags| {
                            let mut sev: HashMap<String, usize> = HashMap::new();
                            for d in &diags {
                                *sev.entry(d.severity.as_db_str().to_string()).or_insert(0) += 1;
                            }
                            sev
                        })
                        .unwrap_or_default();

                    points.push(TrendPoint {
                        scan_id: scan.id.clone(),
                        timestamp: scan.started_at.clone().unwrap_or_default(),
                        total,
                        by_severity,
                    });
                }
            }
        }
    }

    Json(points)
}

#[derive(Debug, Deserialize)]
struct BaselineBody {
    scan_id: String,
}

/// POST /api/overview/baseline { scan_id }, pin a scan as the baseline for drift comparison.
async fn set_baseline(
    State(state): State<AppState>,
    Json(body): Json<BaselineBody>,
) -> Result<StatusCode, StatusCode> {
    set_baseline_inner(&state, &body.scan_id)
}

/// POST /api/overview/baseline/:scan_id, convenience path-form for clients without a JSON body.
async fn set_baseline_path(
    State(state): State<AppState>,
    AxPath(scan_id): AxPath<String>,
) -> Result<StatusCode, StatusCode> {
    set_baseline_inner(&state, &scan_id)
}

fn set_baseline_inner(state: &AppState, scan_id: &str) -> Result<StatusCode, StatusCode> {
    if scan_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pool = state
        .db_pool
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let idx = Indexer::from_pool("_scans", pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    idx.set_metadata(BASELINE_KEY, scan_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/overview/baseline, clear the pinned baseline.
async fn clear_baseline(State(state): State<AppState>) -> Result<StatusCode, StatusCode> {
    let pool = state
        .db_pool
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let idx = Indexer::from_pool("_scans", pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    idx.delete_metadata(BASELINE_KEY)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Cached view of recent completed scans' fingerprints + timestamps. Built once
/// per overview request and reused by delta / posture / backlog / drift.
struct ScanHistory {
    /// Completed scans, oldest → newest.
    scans: Vec<HistoricScan>,
    /// fingerprint → earliest started_at (RFC-3339) seen across history.
    first_seen: HashMap<String, String>,
}

struct HistoricScan {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    started_at: Option<String>,
    fingerprints: HashSet<String>,
    total: usize,
}

impl ScanHistory {
    fn load(state: &AppState, limit: usize) -> Self {
        let mut scans = Vec::new();
        let mut first_seen: HashMap<String, String> = HashMap::new();

        let Some(ref pool) = state.db_pool else {
            return Self { scans, first_seen };
        };
        let Ok(idx) = Indexer::from_pool("_scans", pool) else {
            return Self { scans, first_seen };
        };

        let mut records = idx.list_scans(limit as i64).unwrap_or_default();
        // Filter to completed and reverse to oldest-first.
        records.retain(|r| r.status == "completed");
        records.reverse();

        let mut bulk_inserts: Vec<(String, String)> = Vec::new();

        for r in records {
            let fps: HashSet<String> = r
                .findings_json
                .as_deref()
                .and_then(|j| serde_json::from_str::<Vec<Diag>>(j).ok())
                .map(|diags| diags.iter().map(compute_fingerprint).collect())
                .unwrap_or_default();
            let total = fps.len();
            let started_at = r.started_at.clone();
            // Seed first_seen for new fingerprints.
            if let Some(ref ts) = started_at {
                for fp in &fps {
                    first_seen.entry(fp.clone()).or_insert_with(|| {
                        bulk_inserts.push((fp.clone(), ts.clone()));
                        ts.clone()
                    });
                }
            }
            scans.push(HistoricScan {
                id: r.id,
                started_at,
                fingerprints: fps,
                total,
            });
        }

        // Persist newly observed first-seen entries (best-effort; ignore errors).
        if !bulk_inserts.is_empty() {
            let _ = idx.record_finding_first_seen_bulk(&bulk_inserts);
        }

        Self { scans, first_seen }
    }

    /// Compare current findings against the most-recent historical scan and
    /// against all earlier scans for regression detection.
    /// Returns (new_count, fixed_count, reintroduced_count).
    fn compare_to_current(&self, current: &[Diag]) -> (usize, usize, usize) {
        if self.scans.is_empty() {
            return (0, 0, 0);
        }
        let current_fps: HashSet<String> = current.iter().map(compute_fingerprint).collect();

        // For new/fixed delta, compare against the *previous* completed scan
        // (i.e. the one before the latest, since the latest is "current" in DB
        // most of the time). If only one scan exists, treat all as new.
        let (new_count, fixed_count) = if self.scans.len() >= 2 {
            let prev = &self.scans[self.scans.len() - 2];
            let new_count = current_fps.difference(&prev.fingerprints).count();
            let fixed_count = prev.fingerprints.difference(&current_fps).count();
            (new_count, fixed_count)
        } else {
            (0, 0)
        };

        // Regression: fingerprints that were present in some past scan, were
        // absent in the immediately-preceding scan, and are present now.
        let reintroduced = if self.scans.len() >= 2 {
            let prev_fps = &self.scans[self.scans.len() - 2].fingerprints;
            let mut count = 0usize;
            for fp in current_fps.iter() {
                if prev_fps.contains(fp) {
                    continue;
                }
                // Was present in any earlier scan?
                let earlier = self
                    .scans
                    .iter()
                    .take(self.scans.len() - 2)
                    .any(|s| s.fingerprints.contains(fp));
                if earlier {
                    count += 1;
                }
            }
            count
        } else {
            0
        };

        (new_count, fixed_count, reintroduced)
    }

    /// Trend slope across the last N totals, 1.0 means strictly improving,
    /// -1.0 strictly regressing, 0.0 unchanged. Returns None with <3 points.
    fn trend_slope(&self) -> Option<f64> {
        if self.scans.len() < 3 {
            return None;
        }
        let tail: Vec<f64> = self
            .scans
            .iter()
            .rev()
            .take(5)
            .map(|s| s.total as f64)
            .collect();
        let first = *tail.last()?;
        let last = *tail.first()?;
        if first <= 0.0 && last <= 0.0 {
            return Some(0.0);
        }
        // Improving = total decreased → positive score. Normalize by max.
        let max = first.max(last).max(1.0);
        Some(((first - last) / max).clamp(-1.0, 1.0))
    }
}

/// Collect recent scans from in-memory jobs + DB, deduped by ID.
fn collect_recent_scans(state: &AppState, limit: usize) -> Vec<ScanSummary> {
    let mut seen = HashSet::new();
    let mut scans = Vec::new();

    // In-memory first
    for job in state.job_manager.list_jobs() {
        if seen.insert(job.id.clone()) {
            scans.push(ScanSummary {
                id: job.id.clone(),
                status: format!("{:?}", job.status).to_ascii_lowercase(),
                started_at: job.started_at.map(|t| t.to_rfc3339()),
                duration_secs: job.duration_secs,
                finding_count: job.findings.as_ref().map(|f| f.len() as i64),
            });
        }
    }

    // DB fallback
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(records) = idx.list_scans(limit as i64) {
                for r in records {
                    if seen.insert(r.id.clone()) {
                        scans.push(ScanSummary {
                            id: r.id,
                            status: r.status,
                            started_at: r.started_at,
                            duration_secs: r.duration_secs,
                            finding_count: r.finding_count,
                        });
                    }
                }
            }
        }
    }

    scans.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    scans.truncate(limit);
    scans
}

/// Compute triage coverage: fraction of findings with non-"open" triage state.
fn compute_triage_coverage(state: &AppState, findings: &[Diag]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let Some(ref pool) = state.db_pool else {
        return 0.0;
    };
    let Ok(idx) = Indexer::from_pool("_scans", pool) else {
        return 0.0;
    };

    let triage_map = idx.get_all_triage_states().unwrap_or_default();
    let suppression_rules = idx.get_suppression_rules().unwrap_or_default();

    let mut non_open = 0usize;
    for d in findings {
        let fp = compute_fingerprint(d);
        if let Some((triage_state, _, _)) = triage_map.get(&fp) {
            if triage_state != "open" {
                non_open += 1;
                continue;
            }
        }
        let path = &d.path;
        let rule_id = &d.id;
        for rule in &suppression_rules {
            let matches = match rule.suppress_by.as_str() {
                "fingerprint" => fp == rule.match_value,
                "rule" => *rule_id == rule.match_value,
                "rule_in_file" => format!("{rule_id}:{path}") == rule.match_value,
                "file" => *path == rule.match_value,
                _ => false,
            };
            if matches {
                non_open += 1;
                break;
            }
        }
    }

    non_open as f64 / findings.len() as f64
}

/// Compute noisy rules: high finding count + high suppression rate.
fn compute_noisy_rules(
    state: &AppState,
    findings: &[Diag],
    by_rule: &HashMap<String, usize>,
) -> Vec<NoisyRule> {
    let Some(ref pool) = state.db_pool else {
        return vec![];
    };
    let Ok(idx) = Indexer::from_pool("_scans", pool) else {
        return vec![];
    };

    let triage_map = idx.get_all_triage_states().unwrap_or_default();
    let suppression_rules = idx.get_suppression_rules().unwrap_or_default();

    let mut suppressed_per_rule: HashMap<String, usize> = HashMap::new();
    for d in findings {
        let fp = compute_fingerprint(d);
        let is_suppressed = triage_map
            .get(&fp)
            .map(|(s, _, _)| s == "suppressed" || s == "false_positive")
            .unwrap_or(false)
            || suppression_rules
                .iter()
                .any(|rule| match rule.suppress_by.as_str() {
                    "fingerprint" => fp == rule.match_value,
                    "rule" => d.id == rule.match_value,
                    "rule_in_file" => format!("{}:{}", d.id, d.path) == rule.match_value,
                    "file" => d.path == rule.match_value,
                    _ => false,
                });
        if is_suppressed {
            *suppressed_per_rule.entry(d.id.clone()).or_insert(0) += 1;
        }
    }

    let mut noisy: Vec<NoisyRule> = by_rule
        .iter()
        .filter_map(|(rule_id, &count)| {
            if count < 3 {
                return None;
            }
            let suppressed = suppressed_per_rule.get(rule_id).copied().unwrap_or(0);
            let rate = suppressed as f64 / count as f64;
            if rate >= 0.5 {
                Some(NoisyRule {
                    rule_id: rule_id.clone(),
                    finding_count: count,
                    suppression_rate: rate,
                })
            } else {
                None
            }
        })
        .collect();

    noisy.sort_by_key(|b| std::cmp::Reverse(b.finding_count));
    noisy
}

/// Generate actionable insights from overview data.
fn generate_insights(
    summary: &crate::server::models::FindingSummary,
    new_since_last: usize,
    fixed_since_last: usize,
    reintroduced: usize,
    triage_coverage: f64,
    noisy_rules: &[NoisyRule],
) -> Vec<Insight> {
    let mut insights = Vec::new();

    let high_count = summary.by_severity.get("HIGH").copied().unwrap_or(0);
    if high_count > 0 {
        insights.push(Insight {
            kind: "untriaged_high".into(),
            message: format!(
                "{high_count} High severity finding{} to review",
                if high_count == 1 { "" } else { "s" }
            ),
            severity: "warning".into(),
            action_url: Some("/findings?severity=HIGH&status=open".into()),
        });
    }

    if reintroduced > 0 {
        insights.push(Insight {
            kind: "regression".into(),
            message: format!(
                "{reintroduced} previously-fixed finding{} reintroduced",
                if reintroduced == 1 { "" } else { "s" }
            ),
            severity: "danger".into(),
            action_url: Some("/findings".into()),
        });
    }

    if new_since_last > 0 {
        insights.push(Insight {
            kind: "new_findings".into(),
            message: format!(
                "{new_since_last} new finding{} since last scan",
                if new_since_last == 1 { "" } else { "s" }
            ),
            severity: "warning".into(),
            action_url: Some("/findings".into()),
        });
    }

    if fixed_since_last > 0 {
        insights.push(Insight {
            kind: "fixed_findings".into(),
            message: format!(
                "{fixed_since_last} finding{} fixed since last scan",
                if fixed_since_last == 1 { "" } else { "s" }
            ),
            severity: "success".into(),
            action_url: None,
        });
    }

    for rule in noisy_rules.iter().take(3) {
        insights.push(Insight {
            kind: "noisy_rule".into(),
            message: format!(
                "Rule {} has {:.0}% suppression rate ({} findings)",
                rule.rule_id,
                rule.suppression_rate * 100.0,
                rule.finding_count
            ),
            severity: "info".into(),
            action_url: Some("/rules".into()),
        });
    }

    if triage_coverage < 0.1 && summary.total > 20 {
        insights.push(Insight {
            kind: "low_triage".into(),
            message: format!(
                "Only {:.0}% of findings have been triaged",
                triage_coverage * 100.0
            ),
            severity: "info".into(),
            action_url: Some("/triage".into()),
        });
    }

    insights
}

/// Check if the latest scan completed within the last 5 minutes.
fn is_fresh_scan(scan: Option<&ScanSummary>) -> bool {
    let Some(scan) = scan else { return false };
    let Some(ref started_at) = scan.started_at else {
        return false;
    };
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(started_at) {
        let elapsed = chrono::Utc::now() - ts.with_timezone(&chrono::Utc);
        return elapsed.num_seconds() < 300;
    }
    false
}

// ── Tier 1/2/3 computations ──────────────────────────────────────────────────

fn compute_confidence_distribution(findings: &[Diag]) -> ConfidenceDistribution {
    let mut d = ConfidenceDistribution::default();
    for f in findings {
        match f.confidence {
            Some(Confidence::High) => d.high += 1,
            Some(Confidence::Medium) => d.medium += 1,
            Some(Confidence::Low) => d.low += 1,
            None => d.none += 1,
        }
    }
    d
}

fn compute_weighted_top_files(findings: &[Diag], limit: usize) -> Vec<WeightedFile> {
    use crate::patterns::Severity;
    let mut per_file: HashMap<String, [usize; 3]> = HashMap::new(); // [high, medium, low]
    for f in findings {
        let entry = per_file.entry(f.path.clone()).or_insert([0, 0, 0]);
        match f.severity {
            Severity::High => entry[0] += 1,
            Severity::Medium => entry[1] += 1,
            Severity::Low => entry[2] += 1,
        }
    }
    let mut rows: Vec<WeightedFile> = per_file
        .into_iter()
        .map(|(name, [h, m, l])| WeightedFile {
            name,
            score: (h * 10 + m * 3 + l) as u32,
            high: h,
            medium: m,
            low: l,
            total: h + m + l,
        })
        .collect();
    rows.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| b.total.cmp(&a.total)));
    rows.truncate(limit);
    rows
}

fn compute_cross_file_ratio(findings: &[Diag]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }
    let mut cross = 0usize;
    for f in findings {
        if let Some(ev) = f.evidence.as_ref() {
            if ev.uses_summary || ev.flow_steps.iter().any(|s| s.is_cross_file) {
                cross += 1;
            }
        }
    }
    cross as f64 / findings.len() as f64
}

/// Hot sinks are *only* meaningful for taint findings, counting AST rule IDs
/// (e.g. `rs.quality.unwrap`) here just duplicates the Top Rules table. So we
/// deliberately require a real Sink-step callee (or a parsable sink snippet)
/// and skip everything else. Empty result → frontend hides the card.
fn compute_hot_sinks(findings: &[Diag], limit: usize) -> Vec<HotSink> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for f in findings {
        let Some(ev) = f.evidence.as_ref() else {
            continue;
        };
        let from_flow = ev
            .flow_steps
            .iter()
            .rev()
            .find(|s| matches!(s.kind, crate::evidence::FlowStepKind::Sink))
            .and_then(|s| s.callee.clone())
            .filter(|c| !c.trim().is_empty());
        let from_sink_snippet = ev
            .sink
            .as_ref()
            .and_then(|s| s.snippet.as_ref())
            .and_then(|s| {
                let c = extract_callee_from_snippet(s);
                if c.is_empty() { None } else { Some(c) }
            });
        let Some(callee) = from_flow.or(from_sink_snippet) else {
            continue;
        };
        *counts.entry(callee).or_insert(0) += 1;
    }
    let mut rows: Vec<HotSink> = counts
        .into_iter()
        .map(|(callee, count)| HotSink { callee, count })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.callee.cmp(&b.callee)));
    rows.truncate(limit);
    rows
}

/// Pull the leading identifier from a sink snippet, a best-effort heuristic
/// for the dashboard's "hot sinks" list.
fn extract_callee_from_snippet(s: &str) -> String {
    let trimmed = s.trim();
    let end = trimmed
        .find('(')
        .or_else(|| trimmed.find(char::is_whitespace))
        .unwrap_or(trimmed.len());
    trimmed[..end].trim().to_string()
}

fn compute_scanner_quality(
    state: &AppState,
    findings: &[Diag],
    latest_scan_id: Option<&str>,
) -> Option<ScannerQuality> {
    let pool = state.db_pool.as_ref()?;
    let idx = Indexer::from_pool("_scans", pool).ok()?;

    let mut files_scanned = 0u64;
    let mut files_skipped = 0u64;
    if let Some(scan_id) = latest_scan_id {
        let scans = idx.list_scans(20).unwrap_or_default();
        if let Some(rec) = scans.into_iter().find(|s| s.id == scan_id) {
            files_scanned = rec.files_scanned.unwrap_or(0).max(0) as u64;
            files_skipped = rec.files_skipped.unwrap_or(0).max(0) as u64;
        }
    }

    let parse_success_rate = if files_scanned + files_skipped > 0 {
        files_scanned as f64 / (files_scanned + files_skipped) as f64
    } else {
        0.0
    };

    // Engine metrics from scan_metrics table (if available via Indexer).
    let (functions_analyzed, call_edges, unresolved_calls) = latest_scan_id
        .and_then(|id| idx.get_scan_metrics(id).ok().flatten())
        .map(|m| (m.functions_analyzed, m.call_edges, m.unresolved_calls))
        .unwrap_or((0, 0, 0));

    let call_resolution_rate = if call_edges + unresolved_calls > 0 {
        call_edges as f64 / (call_edges + unresolved_calls) as f64
    } else {
        0.0
    };

    // Symex coverage from current findings.
    let mut breakdown: HashMap<String, usize> = HashMap::new();
    let mut taint_total = 0usize;
    for f in findings {
        let Some(ev) = f.evidence.as_ref() else {
            continue;
        };
        let Some(sv) = ev.symbolic.as_ref() else {
            continue;
        };
        taint_total += 1;
        let label = match sv.verdict {
            Verdict::Confirmed => "confirmed",
            Verdict::Infeasible => "infeasible",
            Verdict::Inconclusive => "inconclusive",
            Verdict::NotAttempted => "not_attempted",
        };
        *breakdown.entry(label.to_string()).or_insert(0) += 1;
    }
    let symex_verified_rate = if taint_total > 0 {
        let attempted = breakdown
            .iter()
            .filter(|(k, _)| k.as_str() != "not_attempted")
            .map(|(_, v)| *v)
            .sum::<usize>();
        attempted as f64 / taint_total as f64
    } else {
        0.0
    };

    Some(ScannerQuality {
        files_scanned,
        files_skipped,
        parse_success_rate,
        functions_analyzed,
        call_edges,
        unresolved_calls,
        call_resolution_rate,
        symex_verified_rate,
        symex_breakdown: breakdown,
        dynamic_verification: crate::commands::scan::DynamicVerificationSummary::from_diags(
            findings,
        ),
    })
}

fn compute_language_health(findings: &[Diag]) -> Vec<LanguageHealth> {
    use crate::patterns::Severity;
    let mut per_lang: HashMap<String, [usize; 4]> = HashMap::new(); // [total, h, m, l]
    for f in findings {
        let Some(lang) = lang_for_finding_path(&f.path) else {
            continue;
        };
        let entry = per_lang.entry(lang).or_insert([0; 4]);
        entry[0] += 1;
        match f.severity {
            Severity::High => entry[1] += 1,
            Severity::Medium => entry[2] += 1,
            Severity::Low => entry[3] += 1,
        }
    }
    let mut rows: Vec<LanguageHealth> = per_lang
        .into_iter()
        .map(|(language, [t, h, m, l])| LanguageHealth {
            language,
            findings: t,
            high: h,
            medium: m,
            low: l,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.high
            .cmp(&a.high)
            .then_with(|| b.findings.cmp(&a.findings))
    });
    rows
}

fn compute_suppression_hygiene(state: &AppState, findings: &[Diag]) -> SuppressionHygiene {
    let mut hygiene = SuppressionHygiene {
        fingerprint_level: 0,
        rule_level: 0,
        file_level: 0,
        rule_in_file_level: 0,
        blanket_rate: 0.0,
    };
    if findings.is_empty() {
        return hygiene;
    }
    let Some(ref pool) = state.db_pool else {
        return hygiene;
    };
    let Ok(idx) = Indexer::from_pool("_scans", pool) else {
        return hygiene;
    };
    let triage_map = idx.get_all_triage_states().unwrap_or_default();
    let suppression_rules = idx.get_suppression_rules().unwrap_or_default();
    let mut total_suppressed = 0usize;
    for d in findings {
        let fp = compute_fingerprint(d);
        if let Some((s, _, _)) = triage_map.get(&fp) {
            if s == "suppressed" || s == "false_positive" {
                hygiene.fingerprint_level += 1;
                total_suppressed += 1;
                continue;
            }
        }
        for rule in &suppression_rules {
            let matched = match rule.suppress_by.as_str() {
                "fingerprint" => fp == rule.match_value,
                "rule" => d.id == rule.match_value,
                "rule_in_file" => format!("{}:{}", d.id, d.path) == rule.match_value,
                "file" => d.path == rule.match_value,
                _ => false,
            };
            if matched {
                match rule.suppress_by.as_str() {
                    "fingerprint" => hygiene.fingerprint_level += 1,
                    "rule" => hygiene.rule_level += 1,
                    "file" => hygiene.file_level += 1,
                    "rule_in_file" => hygiene.rule_in_file_level += 1,
                    _ => {}
                }
                total_suppressed += 1;
                break;
            }
        }
    }
    if total_suppressed > 0 {
        let blanket = hygiene.rule_level + hygiene.file_level + hygiene.rule_in_file_level;
        hygiene.blanket_rate = blanket as f64 / total_suppressed as f64;
    }
    hygiene
}

fn compute_backlog(state: &AppState, findings: &[Diag], history: &ScanHistory) -> BacklogStats {
    // No useful aging data on the first scan, every fingerprint was first-seen
    // today by definition. Avoid the misleading "0d / 0d / 0" display.
    if history.scans.len() <= 1 {
        return BacklogStats {
            oldest_open_days: None,
            median_age_days: None,
            stale_count: 0,
            age_buckets: Vec::new(),
        };
    }

    let now = chrono::Utc::now();

    // Pull DB-cached first_seen first; fall back to in-memory history map.
    let fingerprints: Vec<String> = findings.iter().map(compute_fingerprint).collect();
    let mut cached: HashMap<String, String> = HashMap::new();
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            cached = idx.get_first_seen_map(&fingerprints).unwrap_or_default();
        }
    }
    // Merge history's view (already persisted as we walked).
    for (fp, ts) in &history.first_seen {
        cached.entry(fp.clone()).or_insert_with(|| ts.clone());
    }

    let mut ages_days: Vec<u32> = Vec::with_capacity(fingerprints.len());
    for fp in &fingerprints {
        let Some(ts) = cached.get(fp) else {
            continue;
        };
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            let elapsed = now - dt.with_timezone(&chrono::Utc);
            let days = elapsed.num_days().max(0) as u32;
            ages_days.push(days);
        }
    }

    let oldest_open_days = ages_days.iter().copied().max();
    let median_age_days = if ages_days.is_empty() {
        None
    } else {
        let mut sorted = ages_days.clone();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    };
    let stale_count = ages_days.iter().filter(|d| **d > 30).count();

    // Buckets: ≤1d, ≤7d, ≤30d, ≤90d, >90d
    let mut b = [0usize; 5];
    for d in &ages_days {
        let i = match *d {
            0..=1 => 0,
            2..=7 => 1,
            8..=30 => 2,
            31..=90 => 3,
            _ => 4,
        };
        b[i] += 1;
    }
    let labels = ["≤1d", "≤7d", "≤30d", "≤90d", ">90d"];
    let age_buckets = labels
        .iter()
        .zip(b.iter())
        .map(|(l, c)| OverviewCount {
            name: (*l).to_string(),
            count: *c,
        })
        .collect();

    BacklogStats {
        oldest_open_days,
        median_age_days,
        stale_count,
        age_buckets,
    }
}

fn compute_baseline_info(state: &AppState, findings: &[Diag]) -> Option<BaselineInfo> {
    let pool = state.db_pool.as_ref()?;
    let idx = Indexer::from_pool("_scans", pool).ok()?;
    let scan_id = idx.get_metadata(BASELINE_KEY).ok().flatten()?;
    if scan_id.is_empty() {
        return None;
    }
    // Look up baseline scan record (separate from history, since history is capped at 20).
    let scans = idx.list_scans(200).ok()?;
    let baseline = scans.into_iter().find(|s| s.id == scan_id)?;
    let baseline_fps: HashSet<String> = baseline
        .findings_json
        .as_deref()
        .and_then(|j| serde_json::from_str::<Vec<Diag>>(j).ok())
        .map(|diags| diags.iter().map(compute_fingerprint).collect())
        .unwrap_or_default();
    let current_fps: HashSet<String> = findings.iter().map(compute_fingerprint).collect();
    let drift_new = current_fps.difference(&baseline_fps).count();
    let drift_fixed = baseline_fps.difference(&current_fps).count();
    Some(BaselineInfo {
        scan_id: baseline.id,
        started_at: baseline.started_at,
        baseline_total: baseline_fps.len(),
        drift_new,
        drift_fixed,
    })
}

fn build_posture(
    new_since_last: usize,
    fixed_since_last: usize,
    reintroduced: usize,
    history: &ScanHistory,
    current_total: usize,
) -> PostureSummary {
    // First-scan case: no prior data to diff against. Saying "stable / no change"
    // is misleading, we genuinely don't know yet.
    if history.scans.len() <= 1 {
        return PostureSummary {
            trend: "unknown".into(),
            severity: "info".into(),
            message: format!(
                "First scan: {current_total} finding{} detected. Re-scan to compare.",
                plural(current_total)
            ),
            reintroduced_count: 0,
        };
    }

    let net = fixed_since_last as i64 - new_since_last as i64;
    let trend_slope = history.trend_slope();

    // Severity selection priorities: regressions are loudest.
    let (trend, severity, message) = if reintroduced > 0 {
        (
            "regressing",
            "danger",
            format!(
                "Regressed: {reintroduced} previously-fixed finding{} returned",
                plural(reintroduced)
            ),
        )
    } else if net > 0 {
        (
            "improving",
            "success",
            format!(
                "Improving: net {net:+} since last scan ({fixed_since_last} fixed, {new_since_last} new)"
            ),
        )
    } else if net < 0 {
        (
            "regressing",
            "warning",
            format!(
                "Regressing: net {net:+} since last scan ({new_since_last} new, {fixed_since_last} fixed)"
            ),
        )
    } else if let Some(slope) = trend_slope {
        if slope > 0.1 {
            (
                "improving",
                "success",
                "Improving: gradual decline in finding count over the last 5 scans".to_string(),
            )
        } else if slope < -0.1 {
            (
                "regressing",
                "warning",
                "Regressing: gradual rise in finding count over the last 5 scans".to_string(),
            )
        } else {
            (
                "stable",
                "info",
                "Stable: no net change since last scan".to_string(),
            )
        }
    } else {
        (
            "stable",
            "info",
            "Stable: no net change since last scan".to_string(),
        )
    };

    PostureSummary {
        trend: trend.to_string(),
        severity: severity.to_string(),
        message,
        reintroduced_count: reintroduced,
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// `compute_health_score` moved to `crate::server::health::compute`.

#![allow(clippy::collapsible_if, clippy::redundant_closure)]

use crate::commands::scan::Diag;
use crate::database::index::{Indexer, ScanRecord};
use crate::server::app::AppState;
use crate::server::models::{
    self, ChangedFinding, CompareResponse, CompareScanInfo, CompareSummary, ComparedFinding,
    FieldChange, FindingView, ScanView,
};
use crate::server::progress::ScanMetricsSnapshot;
use crate::server::scan_log::ScanLogEntry;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/scans", post(start_scan).get(list_scans))
        .route("/scans/active", get(active_scan))
        .route("/scans/compare", get(compare_scans))
        .route("/scans/{id}", get(get_scan).delete(delete_scan))
        .route("/scans/{id}/findings", get(get_scan_findings))
        .route("/scans/{id}/logs", get(get_scan_logs))
        .route("/scans/{id}/metrics", get(get_scan_metrics))
}

#[derive(serde::Deserialize, Default)]
struct StartScanRequest {
    scan_root: Option<String>,
    /// Analysis mode: "full" | "ast" | "cfg" | "taint".
    mode: Option<String>,
    /// Engine-depth profile: "fast" | "balanced" | "deep".
    engine_profile: Option<String>,
    /// Run dynamic verification on findings after the static pass. Default false.
    /// Requires the binary to be built with `--features dynamic`; returns 400
    /// when the feature is absent and `verify: true` is requested.
    verify: Option<bool>,
    #[allow(dead_code)]
    languages: Option<Vec<String>>,
    #[allow(dead_code)]
    include_paths: Option<Vec<String>>,
    #[allow(dead_code)]
    exclude_paths: Option<Vec<String>>,
}

fn apply_mode(
    config: &mut crate::utils::config::Config,
    mode: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    use crate::utils::config::AnalysisMode;
    config.scanner.mode = match mode.to_ascii_lowercase().as_str() {
        "full" => AnalysisMode::Full,
        "ast" => AnalysisMode::Ast,
        "cfg" => AnalysisMode::Cfg,
        "taint" => AnalysisMode::Taint,
        _ => {
            return Err(bad_request("mode must be one of: full, ast, cfg, taint"));
        }
    };
    Ok(())
}

fn apply_engine_profile(
    config: &mut crate::utils::config::Config,
    profile: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    use crate::cli::EngineProfile;
    let prof = match profile.to_ascii_lowercase().as_str() {
        "fast" => EngineProfile::Fast,
        "balanced" => EngineProfile::Balanced,
        "deep" => EngineProfile::Deep,
        _ => {
            return Err(bad_request(
                "engine_profile must be one of: fast, balanced, deep",
            ));
        }
    };
    config.analysis.engine = prof.apply(config.analysis.engine);
    Ok(())
}

async fn start_scan(
    State(state): State<AppState>,
    body: Option<Json<StartScanRequest>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let scan_root = resolve_requested_scan_root(req.scan_root.as_deref(), &state.scan_root)?;

    let mut config = state.config.read().clone();
    if let Some(ref mode) = req.mode {
        apply_mode(&mut config, mode)?;
    }
    if let Some(ref profile) = req.engine_profile {
        apply_engine_profile(&mut config, profile)?;
    }

    if req.verify == Some(true) {
        #[cfg(feature = "dynamic")]
        {
            config.scanner.verify = true;
        }
        #[cfg(not(feature = "dynamic"))]
        {
            return Err(bad_request(
                "binary built without --features dynamic; cannot use verify",
            ));
        }
    }

    let event_tx = state.event_tx.clone();
    let db_pool = state.db_pool.clone();
    let database_dir = state.database_dir.clone();

    match state
        .job_manager
        .start_scan(scan_root, config, event_tx, db_pool, database_dir)
    {
        Ok(job_id) => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "job_id": job_id })),
        )),
        Err(msg) => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": msg })),
        )),
    }
}

fn resolve_requested_scan_root(
    requested_root: Option<&str>,
    configured_root: &Path,
) -> Result<PathBuf, (StatusCode, Json<serde_json::Value>)> {
    if let Some(root) = requested_root {
        let requested = Path::new(root)
            .canonicalize()
            .map_err(|_| bad_request("invalid scan_root"))?;
        if requested != configured_root {
            return Err(bad_request(
                "scan_root must match the repository passed to nyx serve",
            ));
        }
    }

    // The request value is validation-only; scans always run against the
    // canonical root configured when the server started.
    Ok(configured_root.to_path_buf())
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message })),
    )
}

async fn list_scans(State(state): State<AppState>) -> Json<Vec<ScanView>> {
    let mut views: Vec<ScanView> = state
        .job_manager
        .list_jobs()
        .iter()
        .map(|j| job_to_view(j))
        .collect();

    // Merge historical scans from DB (deduplicate by ID)
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(records) = idx.list_scans(100) {
                let in_memory_ids: HashSet<String> = views.iter().map(|v| v.id.clone()).collect();
                for record in records {
                    if !in_memory_ids.contains(&record.id) {
                        views.push(scan_record_to_view(&record));
                    }
                }
            }
        }
    }

    // Sort by started_at descending
    views.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    Json(views)
}

async fn active_scan(State(state): State<AppState>) -> Result<Json<ScanView>, StatusCode> {
    let job = state
        .job_manager
        .active_job()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(job_to_view(&job)))
}

async fn get_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<ScanView>, StatusCode> {
    // Check in-memory first
    if let Some(job) = state.job_manager.get_job(&id) {
        return Ok(Json(job_to_view(&job)));
    }

    // Fall back to DB
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(record)) = idx.get_scan(&id) {
                let mut view = scan_record_to_view(&record);
                // Load metrics from DB
                if let Ok(Some(metrics)) = idx.get_scan_metrics(&id) {
                    view.metrics = Some(metrics);
                }
                return Ok(Json(view));
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn delete_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Remove from in-memory jobs (rejects if running)
    if let Err(msg) = state.job_manager.remove_job(&id) {
        if msg.contains("running") {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": msg })),
            ));
        }
        // "Scan not found" in memory is fine, may be DB-only
    }

    // Delete from DB (CASCADE handles metrics + logs)
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            let _ = idx.delete_scan(&id);
        }
    }

    Ok(Json(serde_json::json!({ "status": "deleted", "id": id })))
}

#[derive(serde::Deserialize, Default)]
struct FindingsQuery {
    page: Option<usize>,
    per_page: Option<usize>,
    severity: Option<String>,
    category: Option<String>,
    search: Option<String>,
}

/// Load findings for a scan by ID (in-memory first, then DB fallback).
fn load_scan_findings(state: &AppState, id: &str) -> Result<Vec<Diag>, StatusCode> {
    if let Some(job) = state.job_manager.get_job(id) {
        return Ok(job.findings.map(|f| (*f).clone()).unwrap_or_default());
    }
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(record)) = idx.get_scan(id) {
                return Ok(record
                    .findings_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str::<Vec<Diag>>(j).ok())
                    .unwrap_or_default());
            }
        }
    }
    Err(StatusCode::NOT_FOUND)
}

/// Load minimal scan info for comparison headers.
fn load_scan_info(state: &AppState, id: &str) -> Result<CompareScanInfo, StatusCode> {
    if let Some(job) = state.job_manager.get_job(id) {
        return Ok(CompareScanInfo {
            id: job.id.clone(),
            started_at: job.started_at.map(|t| t.to_rfc3339()),
            finding_count: job.findings.as_ref().map(|f| f.len()).unwrap_or(0),
        });
    }
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(record)) = idx.get_scan(id) {
                return Ok(CompareScanInfo {
                    id: record.id.clone(),
                    started_at: record.started_at.clone(),
                    finding_count: record.finding_count.map(|c| c as usize).unwrap_or(0),
                });
            }
        }
    }
    Err(StatusCode::NOT_FOUND)
}

async fn get_scan_findings(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(query): Query<FindingsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let findings = load_scan_findings(&state, &id)?;

    // Apply filters
    let mut filtered: Vec<&Diag> = findings.iter().collect();
    if let Some(ref sev) = query.severity {
        filtered.retain(|d| d.severity.as_db_str().eq_ignore_ascii_case(sev));
    }
    if let Some(ref cat) = query.category {
        filtered.retain(|d| d.category.to_string().eq_ignore_ascii_case(cat));
    }
    if let Some(ref search) = query.search {
        let s = search.to_ascii_lowercase();
        filtered.retain(|d| {
            d.path.to_ascii_lowercase().contains(&s)
                || d.id.to_ascii_lowercase().contains(&s)
                || d.message
                    .as_deref()
                    .map(|m| m.to_ascii_lowercase().contains(&s))
                    .unwrap_or(false)
        });
    }

    let total = filtered.len();
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).min(200);
    let start = (page - 1) * per_page;

    let page_findings: Vec<FindingView> = filtered
        .into_iter()
        .enumerate()
        .skip(start)
        .take(per_page)
        .map(|(i, d)| models::finding_from_diag_with_context(i, d, &state.scan_root))
        .collect();

    Ok(Json(serde_json::json!({
        "findings": page_findings,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

// ── Scan Comparison ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct CompareQuery {
    left: String,
    right: String,
}

async fn compare_scans(
    State(state): State<AppState>,
    Query(query): Query<CompareQuery>,
) -> Result<Json<CompareResponse>, StatusCode> {
    let left_info = load_scan_info(&state, &query.left)?;
    let right_info = load_scan_info(&state, &query.right)?;

    let left_findings = load_scan_findings(&state, &query.left)?;
    let right_findings = load_scan_findings(&state, &query.right)?;

    // Build fingerprint → Vec<(index, diag)> multi-maps so duplicate
    // fingerprints are preserved instead of silently dropped.
    let mut left_map: HashMap<String, Vec<(usize, &Diag)>> = HashMap::new();
    for (i, d) in left_findings.iter().enumerate() {
        left_map
            .entry(models::compute_fingerprint(d))
            .or_default()
            .push((i, d));
    }
    let mut right_map: HashMap<String, Vec<(usize, &Diag)>> = HashMap::new();
    for (i, d) in right_findings.iter().enumerate() {
        right_map
            .entry(models::compute_fingerprint(d))
            .or_default()
            .push((i, d));
    }

    let mut new_findings = Vec::new();
    let mut fixed_findings = Vec::new();
    let mut changed_findings = Vec::new();
    let mut unchanged_findings = Vec::new();

    // For each fingerprint that appears on the right side, match 1:1 with
    // left-side findings sharing the same fingerprint.  Excess right entries
    // are "new"; excess left entries are "fixed".
    for (fp, right_group) in &right_map {
        if let Some(left_group) = left_map.get(fp) {
            let matched = right_group.len().min(left_group.len());
            // Matched pairs → unchanged or changed
            for i in 0..matched {
                let (idx, diag) = right_group[i];
                let (_, left_diag) = left_group[i];
                let view = models::finding_from_diag_with_context(idx, diag, &state.scan_root);
                let changes = compute_field_changes(left_diag, diag);
                if changes.is_empty() {
                    unchanged_findings.push(ComparedFinding {
                        fingerprint: fp.clone(),
                        finding: view,
                    });
                } else {
                    changed_findings.push(ChangedFinding {
                        fingerprint: fp.clone(),
                        finding: view,
                        changes,
                    });
                }
            }
            // Excess right entries → new
            for &(idx, diag) in &right_group[matched..] {
                new_findings.push(ComparedFinding {
                    fingerprint: fp.clone(),
                    finding: models::finding_from_diag_with_context(idx, diag, &state.scan_root),
                });
            }
        } else {
            // Entire group is new (fingerprint not in left)
            for &(idx, diag) in right_group {
                new_findings.push(ComparedFinding {
                    fingerprint: fp.clone(),
                    finding: models::finding_from_diag_with_context(idx, diag, &state.scan_root),
                });
            }
        }
    }

    // Fixed findings: left-side entries whose fingerprint is missing from
    // right, or excess left entries beyond the matched count.
    for (fp, left_group) in &left_map {
        let right_count = right_map.get(fp).map(|g| g.len()).unwrap_or(0);
        let start = left_group.len().min(right_count);
        for &(idx, diag) in &left_group[start..] {
            fixed_findings.push(ComparedFinding {
                fingerprint: fp.clone(),
                finding: models::finding_from_diag_with_context(idx, diag, &state.scan_root),
            });
        }
    }

    // Compute severity delta: right counts - left counts
    let mut severity_delta: HashMap<String, i64> = HashMap::new();
    for d in &right_findings {
        *severity_delta
            .entry(d.severity.as_db_str().to_string())
            .or_insert(0) += 1;
    }
    for d in &left_findings {
        *severity_delta
            .entry(d.severity.as_db_str().to_string())
            .or_insert(0) -= 1;
    }

    let summary = CompareSummary {
        new_count: new_findings.len(),
        fixed_count: fixed_findings.len(),
        changed_count: changed_findings.len(),
        unchanged_count: unchanged_findings.len(),
        severity_delta,
    };

    Ok(Json(CompareResponse {
        left_scan: left_info,
        right_scan: right_info,
        summary,
        new_findings,
        fixed_findings,
        changed_findings,
        unchanged_findings,
    }))
}

/// Compare two Diags with the same fingerprint and return field-level changes.
fn compute_field_changes(left: &Diag, right: &Diag) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    if left.line != right.line {
        changes.push(FieldChange {
            field: "line".into(),
            old_value: left.line.to_string(),
            new_value: right.line.to_string(),
        });
    }
    if left.col != right.col {
        changes.push(FieldChange {
            field: "col".into(),
            old_value: left.col.to_string(),
            new_value: right.col.to_string(),
        });
    }
    if left.severity != right.severity {
        changes.push(FieldChange {
            field: "severity".into(),
            old_value: left.severity.as_db_str().to_string(),
            new_value: right.severity.as_db_str().to_string(),
        });
    }
    if left.confidence != right.confidence {
        changes.push(FieldChange {
            field: "confidence".into(),
            old_value: left
                .confidence
                .map(|c| format!("{c:?}"))
                .unwrap_or_else(|| "-".into()),
            new_value: right
                .confidence
                .map(|c| format!("{c:?}"))
                .unwrap_or_else(|| "-".into()),
        });
    }

    changes
}

#[derive(serde::Deserialize, Default)]
struct LogsQuery {
    level: Option<String>,
}

async fn get_scan_logs(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Vec<ScanLogEntry>>, StatusCode> {
    // Check in-memory (running scan)
    if let Some(job) = state.job_manager.get_job(&id) {
        if let Some(ref collector) = job.log_collector {
            let mut logs = collector.snapshot();
            if let Some(ref level) = query.level {
                logs.retain(|l| l.level.to_string().eq_ignore_ascii_case(level));
            }
            return Ok(Json(logs));
        }
    }

    // Fall back to DB
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(logs) = idx.get_scan_logs(&id, query.level.as_deref()) {
                return Ok(Json(logs));
            }
        }
    }

    Ok(Json(vec![]))
}

async fn get_scan_metrics(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<ScanMetricsSnapshot>, StatusCode> {
    // Check in-memory (running scan)
    if let Some(job) = state.job_manager.get_job(&id) {
        if let Some(ref metrics) = job.metrics {
            return Ok(Json(metrics.snapshot()));
        }
    }

    // Fall back to DB
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(metrics)) = idx.get_scan_metrics(&id) {
                return Ok(Json(metrics));
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

fn job_to_view(job: &crate::server::jobs::ScanJob) -> ScanView {
    let (timing, metrics_snap) = if let Some(ref progress) = job.progress {
        let snap = progress.snapshot();
        (
            Some(snap.timing),
            job.metrics.as_ref().map(|m| m.snapshot()),
        )
    } else {
        (job.timing.clone(), None)
    };

    ScanView {
        id: job.id.clone(),
        status: format!("{:?}", job.status).to_ascii_lowercase(),
        scan_root: job.scan_root.display().to_string(),
        started_at: job.started_at.map(|t| t.to_rfc3339()),
        finished_at: job.finished_at.map(|t| t.to_rfc3339()),
        duration_secs: job.duration_secs,
        finding_count: job.findings.as_ref().map(|f| f.len()),
        error: job.error.clone(),
        engine_version: job.engine_version.clone(),
        languages: job.languages.clone(),
        files_scanned: job.files_scanned,
        timing,
        metrics: metrics_snap,
    }
}

fn scan_record_to_view(record: &ScanRecord) -> ScanView {
    let timing: Option<crate::server::progress::TimingBreakdown> = record
        .timing_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());

    let languages: Option<Vec<String>> = record
        .languages
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());

    ScanView {
        id: record.id.clone(),
        status: record.status.clone(),
        scan_root: record.scan_root.clone(),
        started_at: record.started_at.clone(),
        finished_at: record.finished_at.clone(),
        duration_secs: record.duration_secs,
        finding_count: record.finding_count.map(|c| c as usize),
        error: record.error.clone(),
        engine_version: record.engine_version.clone(),
        languages,
        files_scanned: record.files_scanned.map(|c| c as u64),
        timing,
        metrics: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_requested_scan_root_defaults_to_configured_root() {
        let dir = tempfile::tempdir().unwrap();
        let configured = dir.path().canonicalize().unwrap();

        let resolved = resolve_requested_scan_root(None, &configured).unwrap();

        assert_eq!(resolved, configured);
    }

    #[test]
    fn resolve_requested_scan_root_accepts_matching_root_but_uses_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let configured = dir.path().canonicalize().unwrap();
        let requested = dir.path().join(".");

        let resolved =
            resolve_requested_scan_root(Some(requested.to_string_lossy().as_ref()), &configured)
                .unwrap();

        assert_eq!(resolved, configured);
    }

    #[test]
    fn resolve_requested_scan_root_rejects_different_root() {
        let configured_dir = tempfile::tempdir().unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let configured = configured_dir.path().canonicalize().unwrap();

        let err = resolve_requested_scan_root(
            Some(other_dir.path().to_string_lossy().as_ref()),
            &configured,
        )
        .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.1.0["error"],
            "scan_root must match the repository passed to nyx serve"
        );
    }
}

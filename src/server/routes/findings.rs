#![allow(clippy::collapsible_if)]

use crate::commands::scan::Diag;
use crate::database::index::Indexer;
use crate::server::app::{AppState, CachedFindings};
use crate::server::error::{ApiError, ApiResult};
use crate::server::models::{
    FilterValues, FindingSummary, FindingView, collect_filter_values, dynamic_status_label,
    finding_from_diag, finding_from_diag_with_detail, overlay_triage_states, summarize_findings,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use std::sync::Arc;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/findings", get(list_findings))
        .route("/findings/summary", get(findings_summary))
        .route("/findings/filters", get(findings_filters))
        .route("/findings/{index}", get(get_finding))
}

/// Sentinel job id for "we read this from SQLite, not from JobManager."
/// Used as the cache key when no in-memory job exists (e.g. fresh server boot).
const DB_FALLBACK_KEY: &str = "__db_fallback__";

/// Bundle returned by [`load_latest_findings`]: the raw diags plus the cache
/// key under which their derived views should be stored. The cache key is the
/// in-memory job id when available, or [`DB_FALLBACK_KEY`] when we fell back
/// to SQLite.
struct LoadedFindings {
    cache_key: String,
    findings: Arc<Vec<Diag>>,
}

/// Load findings for the latest completed scan, falling back to DB if no
/// in-memory completed scan exists (e.g. after a server restart).
fn load_latest_findings_internal(state: &AppState) -> LoadedFindings {
    if let Some(job) = state.job_manager.get_latest_completed() {
        if let Some(ref findings) = job.findings {
            return LoadedFindings {
                cache_key: job.id.clone(),
                findings: Arc::clone(findings),
            };
        }
    }
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(scans) = idx.list_scans(20) {
                for scan in scans {
                    if scan.status == "completed" {
                        if let Some(json) = scan.findings_json.as_deref() {
                            if let Ok(diags) = serde_json::from_str::<Vec<Diag>>(json) {
                                return LoadedFindings {
                                    cache_key: format!("{DB_FALLBACK_KEY}:{}", scan.id),
                                    findings: Arc::new(diags),
                                };
                            }
                        }
                    }
                }
            }
        }
    }
    LoadedFindings {
        cache_key: DB_FALLBACK_KEY.to_string(),
        findings: Arc::new(Vec::new()),
    }
}

/// Build (or fetch from cache) the per-scan derived views.
///
/// Returns clones of `Arc`s so callers can drop the lock immediately and work
/// without contention. Triage state is *not* baked into the cached views, it
/// changes on a different cadence and is overlaid per request.
fn cached_for_latest(state: &AppState) -> CachedFindings {
    let loaded = load_latest_findings_internal(state);

    // Fast path: cache hit for the same job id.
    if let Some(cached) = state.findings_cache.read().as_ref() {
        if cached.job_id == loaded.cache_key {
            return cached.clone();
        }
    }

    // Slow path: rebuild. Guard against concurrent rebuilds of the same key ,
    // a second writer that finds the cache already populated for our key
    // simply returns it.
    let mut guard = state.findings_cache.write();
    if let Some(existing) = guard.as_ref() {
        if existing.job_id == loaded.cache_key {
            return existing.clone();
        }
    }

    let views: Vec<FindingView> = loaded
        .findings
        .iter()
        .enumerate()
        .map(|(i, d)| finding_from_diag(i, d))
        .collect();
    let summary = summarize_findings(&loaded.findings);
    let filters = collect_filter_values(&loaded.findings);

    let entry = CachedFindings {
        job_id: loaded.cache_key,
        views: Arc::new(views),
        summary: Arc::new(summary),
        filters: Arc::new(filters),
    };
    *guard = Some(entry.clone());
    entry
}

/// Load triage states and suppression rules from DB, apply to views.
///
/// Triage state is overlaid onto a freshly-cloned `Vec` rather than mutating
/// the cached views so concurrent readers see consistent data and the cache
/// stays valid across triage edits.
fn apply_triage_overlay(state: &AppState, views: &mut [FindingView]) {
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_triage", pool) {
            let triage_map = idx.get_all_triage_states().unwrap_or_default();
            let rules = idx.get_suppression_rules().unwrap_or_default();
            overlay_triage_states(views, &triage_map, &rules);
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct FindingsQuery {
    severity: Option<String>,
    category: Option<String>,
    rule_id: Option<String>,
    path: Option<String>,
    search: Option<String>,
    language: Option<String>,
    confidence: Option<String>,
    status: Option<String>,
    verification: Option<String>,
    sort_by: Option<String>,
    sort_dir: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn list_findings(
    State(state): State<AppState>,
    Query(query): Query<FindingsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let cached = cached_for_latest(&state);
    let mut views: Vec<FindingView> = (*cached.views).clone();
    apply_triage_overlay(&state, &mut views);

    if let Some(ref sev) = query.severity {
        let sev_upper = sev.to_ascii_uppercase();
        views.retain(|f| f.severity.as_db_str() == sev_upper);
    }
    if let Some(ref cat) = query.category {
        let cat_lower = cat.to_ascii_lowercase();
        views.retain(|f| f.category.to_string().to_ascii_lowercase() == cat_lower);
    }
    if let Some(ref rule) = query.rule_id {
        views.retain(|f| f.rule_id == *rule);
    }
    if let Some(ref path_prefix) = query.path {
        views.retain(|f| f.path.starts_with(path_prefix.as_str()));
    }
    if let Some(ref lang) = query.language {
        let lang_lower = lang.to_ascii_lowercase();
        views.retain(|f| {
            f.language
                .as_ref()
                .is_some_and(|l| l.to_ascii_lowercase() == lang_lower)
        });
    }
    if let Some(ref conf) = query.confidence {
        let conf_lower = conf.to_ascii_lowercase();
        views.retain(|f| {
            f.confidence
                .as_ref()
                .is_some_and(|c| format!("{c:?}").to_ascii_lowercase() == conf_lower)
        });
    }
    if let Some(ref status) = query.status {
        let status_lower = status.to_ascii_lowercase();
        views.retain(|f| f.status.to_ascii_lowercase() == status_lower);
    }
    if let Some(ref verification) = query.verification {
        let verification_lower = verification.to_ascii_lowercase();
        views.retain(|f| {
            let status = f
                .dynamic_verdict
                .as_ref()
                .map(|verdict| dynamic_status_label(verdict.status))
                .unwrap_or("Unverified");
            status.to_ascii_lowercase() == verification_lower
        });
    }
    if let Some(ref search) = query.search {
        let needle = search.to_ascii_lowercase();
        views.retain(|f| {
            f.path.to_ascii_lowercase().contains(&needle)
                || f.rule_id.to_ascii_lowercase().contains(&needle)
                || f.message
                    .as_ref()
                    .is_some_and(|m| m.to_ascii_lowercase().contains(&needle))
        });
    }

    match query.sort_by.as_deref() {
        Some("severity") => views.sort_by_key(|a| a.severity),
        Some("path") | Some("file") => views.sort_by(|a, b| a.path.cmp(&b.path)),
        Some("rule_id") => views.sort_by(|a, b| a.rule_id.cmp(&b.rule_id)),
        Some("score") => views.sort_by(|a, b| {
            b.rank_score
                .unwrap_or(0.0)
                .partial_cmp(&a.rank_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        Some("confidence") => views.sort_by(|a, b| {
            let ca = a.confidence.map(|c| c as u8).unwrap_or(0);
            let cb = b.confidence.map(|c| c as u8).unwrap_or(0);
            ca.cmp(&cb)
        }),
        Some("line") => views.sort_by_key(|a| a.line),
        Some("language") => views.sort_by(|a, b| {
            a.language
                .as_deref()
                .unwrap_or("")
                .cmp(b.language.as_deref().unwrap_or(""))
        }),
        Some("status") => views.sort_by(|a, b| a.status.cmp(&b.status)),
        Some("category") => views.sort_by_key(|a| a.category.to_string()),
        _ => {}
    }
    if query.sort_dir.as_deref() == Some("desc") {
        views.reverse();
    }

    let total = views.len();
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 10000);
    let start = (page - 1) * per_page;
    let page_views: Vec<_> = views.into_iter().skip(start).take(per_page).collect();

    Ok(Json(serde_json::json!({
        "findings": page_views,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

async fn findings_summary(State(state): State<AppState>) -> Json<FindingSummary> {
    Json((*cached_for_latest(&state).summary).clone())
}

async fn findings_filters(State(state): State<AppState>) -> Json<FilterValues> {
    Json((*cached_for_latest(&state).filters).clone())
}

async fn get_finding(
    State(state): State<AppState>,
    Path(index): Path<usize>,
) -> ApiResult<Json<FindingView>> {
    let findings = load_latest_findings_internal(&state).findings;
    let diag = findings
        .get(index)
        .ok_or_else(|| ApiError::not_found(format!("finding {index} not found")))?;
    let mut view = finding_from_diag_with_detail(index, diag, &state.scan_root, &findings);
    apply_triage_overlay(&state, std::slice::from_mut(&mut view));
    Ok(Json(view))
}

/// Public alias for callers (overview, explorer, triage) that just want
/// the raw diag list. Kept as `load_latest_findings` for source-compat.
pub fn load_latest_findings(state: &AppState) -> Arc<Vec<Diag>> {
    load_latest_findings_internal(state).findings
}

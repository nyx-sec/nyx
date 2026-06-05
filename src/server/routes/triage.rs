use crate::database::index::Indexer;
use crate::server::app::AppState;
use crate::server::models::{compute_fingerprint, finding_from_diag, is_valid_triage_state};
use crate::server::routes::findings::load_latest_findings;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/triage", get(list_triage).post(set_triage))
        .route("/triage/audit", get(get_audit_log))
        .route(
            "/triage/suppress",
            get(list_suppressions)
                .post(add_suppression)
                .delete(remove_suppression),
        )
        .route("/triage/export", post(export_triage_file))
        .route("/triage/import", post(import_triage_file))
        .route("/triage/sync-status", get(get_sync_status))
}

// ── POST /api/triage ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SetTriageRequest {
    fingerprints: Vec<String>,
    state: String,
    #[serde(default)]
    note: String,
}

async fn set_triage(
    State(state): State<AppState>,
    Json(body): Json<SetTriageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_triage_state(&body.state) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid state: {}", body.state) })),
        ));
    }
    if body.fingerprints.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "fingerprints must not be empty" })),
        ));
    }

    let pool = state.active_db_pool().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "database not available" })),
    ))?;

    let idx = Indexer::from_pool("_triage", &pool).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    let action = if body.fingerprints.len() > 1 {
        "bulk_set_state"
    } else {
        "set_state"
    };

    let results = idx
        .set_triage_states_bulk(&body.fingerprints, &body.state, &body.note, action)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

    // Auto-sync to .nyx/triage.json
    auto_sync_to_file(&state);

    Ok(Json(serde_json::json!({
        "updated": results.len(),
        "state": body.state,
    })))
}

// ── GET /api/triage ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct ListTriageQuery {
    state: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn list_triage(
    State(state): State<AppState>,
    Query(query): Query<ListTriageQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state
        .active_db_pool()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let idx =
        Indexer::from_pool("_triage", &pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 500);
    let offset = ((page - 1) * per_page) as i64;

    let (rows, total) = idx
        .list_triage_states(query.state.as_deref(), per_page as i64, offset)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Enrich with finding data if available
    let findings = load_latest_findings(&state);
    let mut enriched_views = Vec::new();
    // Build fingerprint → diag index for lookup
    let fp_map: std::collections::HashMap<String, usize> = findings
        .iter()
        .enumerate()
        .map(|(i, d)| (compute_fingerprint(d), i))
        .collect();

    for (fp, ts_state, note, updated_at) in &rows {
        let finding_info = fp_map.get(fp).map(|&i| {
            let d = &findings[i];
            serde_json::json!({
                "index": i,
                "rule_id": d.id,
                "path": d.path,
                "line": d.line,
                "severity": d.severity.as_db_str(),
                "category": d.category.to_string(),
            })
        });

        enriched_views.push(serde_json::json!({
            "fingerprint": fp,
            "state": ts_state,
            "note": note,
            "updated_at": updated_at,
            "finding": finding_info,
        }));
    }

    Ok(Json(serde_json::json!({
        "entries": enriched_views,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

// ── GET /api/triage/audit ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct AuditQuery {
    fingerprint: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn get_audit_log(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state
        .active_db_pool()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let idx =
        Indexer::from_pool("_triage", &pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 500);
    let offset = ((page - 1) * per_page) as i64;

    let (entries, total) = idx
        .get_audit_log(query.fingerprint.as_deref(), per_page as i64, offset)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "entries": entries,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

// ── POST /api/triage/suppress ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddSuppressionRequest {
    by: String,
    value: String,
    #[serde(default)]
    note: String,
}

async fn add_suppression(
    State(state): State<AppState>,
    Json(body): Json<AddSuppressionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let valid_by = ["fingerprint", "rule", "rule_in_file", "file"];
    if !valid_by.contains(&body.by.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid 'by' value: {}", body.by) })),
        ));
    }

    let pool = state.active_db_pool().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "database not available" })),
    ))?;

    let idx = Indexer::from_pool("_triage", &pool).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    let rule_id = idx
        .add_suppression_rule(&body.by, &body.value, "suppressed", &body.note)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

    // Apply to current findings
    let findings = load_latest_findings(&state);
    let views: Vec<_> = findings
        .iter()
        .enumerate()
        .map(|(i, d)| finding_from_diag(i, d))
        .collect();

    // Find matching fingerprints
    let matching_fps: Vec<String> = views
        .iter()
        .filter(|v| match body.by.as_str() {
            "fingerprint" => v.fingerprint == body.value,
            "rule" => v.rule_id == body.value,
            "rule_in_file" => {
                let key = format!("{}:{}", v.rule_id, v.path);
                key == body.value
            }
            "file" => v.path == body.value,
            _ => false,
        })
        .map(|v| v.fingerprint.clone())
        .collect();

    let affected = matching_fps.len();
    if !matching_fps.is_empty() {
        let _ =
            idx.set_triage_states_bulk(&matching_fps, "suppressed", &body.note, "suppress_pattern");
    }
    drop(views);

    // Auto-sync to .nyx/triage.json
    auto_sync_to_file(&state);

    Ok(Json(serde_json::json!({
        "rule_id": rule_id,
        "findings_affected": affected,
    })))
}

// ── GET /api/triage/suppress ────────────────────────────────────────────────

async fn list_suppressions(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state
        .active_db_pool()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let idx =
        Indexer::from_pool("_triage", &pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let rules = idx
        .get_suppression_rules()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "rules": rules })))
}

// ── DELETE /api/triage/suppress ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DeleteSuppressionQuery {
    id: i64,
}

async fn remove_suppression(
    State(state): State<AppState>,
    Query(query): Query<DeleteSuppressionQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state
        .active_db_pool()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let idx =
        Indexer::from_pool("_triage", &pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let deleted = idx
        .delete_suppression_rule(query.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Auto-sync to .nyx/triage.json
    auto_sync_to_file(&state);

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Auto-sync helper ────────────────────────────────────────────────────────

fn auto_sync_to_file(state: &AppState) {
    let sync_enabled = state.config.read().server.triage_sync;
    if !sync_enabled {
        return;
    }
    if let Some(pool) = state.active_db_pool() {
        let scan_root = state.active_scan_root();
        let findings = load_latest_findings(state);
        let _ = crate::server::triage_sync::sync_to_file(&pool, &findings, &scan_root);
    }
}

// ── POST /api/triage/export ─────────────────────────────────────────────────

async fn export_triage_file(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pool = state.active_db_pool().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "database not available" })),
    ))?;

    let findings = load_latest_findings(&state);
    let scan_root = state.active_scan_root();
    let file =
        crate::server::triage_sync::export_triage(&pool, &findings, &scan_root).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
        })?;

    crate::server::triage_sync::save_triage_file(&scan_root, &file).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
    })?;

    let path = crate::server::triage_sync::triage_file_path(&scan_root).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
    })?;
    Ok(Json(serde_json::json!({
        "exported": file.decisions.len(),
        "suppression_rules": file.suppression_rules.len(),
        "path": path.to_string_lossy(),
    })))
}

// ── POST /api/triage/import ─────────────────────────────────────────────────

async fn import_triage_file(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pool = state.active_db_pool().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "database not available" })),
    ))?;

    let scan_root = state.active_scan_root();
    let file = crate::server::triage_sync::load_triage_file_checked(&scan_root)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": ".nyx/triage.json not found" })),
        ))?;

    let findings = load_latest_findings(&state);
    let applied = crate::server::triage_sync::import_triage(&pool, &findings, &scan_root, &file)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
        })?;

    Ok(Json(serde_json::json!({
        "imported": applied,
        "total_in_file": file.decisions.len(),
        "suppression_rules": file.suppression_rules.len(),
    })))
}

// ── GET /api/triage/sync-status ─────────────────────────────────────────────

async fn get_sync_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scan_root = state.active_scan_root();
    let path = crate::server::triage_sync::triage_file_path(&scan_root).ok();
    let file = crate::server::triage_sync::load_triage_file(&scan_root);
    let sync_enabled = state.config.read().server.triage_sync;

    Json(serde_json::json!({
        "file_path": path.as_ref().map(|p| p.to_string_lossy().to_string()),
        "file_exists": path.as_ref().map(|p| p.exists()).unwrap_or(false),
        "sync_enabled": sync_enabled,
        "decisions": file.as_ref().map(|f| f.decisions.len()).unwrap_or(0),
        "suppression_rules": file.as_ref().map(|f| f.suppression_rules.len()).unwrap_or(0),
    }))
}

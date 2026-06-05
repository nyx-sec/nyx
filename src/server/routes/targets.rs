use crate::server::app::AppState;
use crate::server::error::{ApiError, ApiResult};
use crate::utils::targets::{
    TargetRecord, TargetTouch, load_targets, remember_target, remove_target, target_id_for_path,
};
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::path::{Path as FsPath, PathBuf};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/targets", get(list_targets).post(add_target))
        .route("/targets/select", post(select_target))
        .route("/targets/{id}", delete(delete_target))
}

#[derive(Debug, Serialize)]
struct TargetView {
    id: String,
    name: String,
    path: String,
    db_path: String,
    last_seen_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_scan_at: Option<String>,
    active: bool,
    exists: bool,
}

#[derive(Debug, Deserialize)]
struct TargetPathRequest {
    path: String,
}

#[derive(Debug, Deserialize)]
struct SelectTargetRequest {
    id: Option<String>,
    path: Option<String>,
}

async fn list_targets(State(state): State<AppState>) -> ApiResult<Json<Vec<TargetView>>> {
    ensure_active_target_record(&state)?;
    let active = state.active_scan_root();
    let targets = load_targets(&state.database_dir)
        .map_err(|e| ApiError::internal(format!("failed to load targets: {e}")))?;
    Ok(Json(targets_to_views(&targets, &active)))
}

async fn add_target(
    State(state): State<AppState>,
    Json(body): Json<TargetPathRequest>,
) -> ApiResult<Json<TargetView>> {
    let path = canonical_project_path(&body.path)?;
    let record = remember_target(&state.database_dir, &path, TargetTouch::Seen)
        .map_err(|e| ApiError::internal(format!("failed to remember target: {e}")))?;
    let _ = state.db_pool_for(&path);
    Ok(Json(record_to_view(&record, &state.active_scan_root())))
}

async fn select_target(
    State(state): State<AppState>,
    Json(body): Json<SelectTargetRequest>,
) -> ApiResult<Json<TargetView>> {
    let path = if let Some(id) = body.id.as_deref() {
        target_path_by_id(&state, id)?
    } else if let Some(path) = body.path.as_deref() {
        canonical_project_path(path)?
    } else {
        return Err(ApiError::bad_request("target id or path is required"));
    };

    let record = remember_target(&state.database_dir, &path, TargetTouch::Seen)
        .map_err(|e| ApiError::internal(format!("failed to remember target: {e}")))?;
    state.set_active_scan_root(path.clone());
    let _ = state.db_pool_for(&path);
    Ok(Json(record_to_view(&record, &path)))
}

async fn delete_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let removed = remove_target(&state.database_dir, &id)
        .map_err(|e| ApiError::internal(format!("failed to remove target: {e}")))?;
    if removed.is_none() {
        return Err(ApiError::not_found(format!("target {id} not found")));
    }
    Ok(Json(serde_json::json!({ "status": "deleted", "id": id })))
}

fn ensure_active_target_record(state: &AppState) -> ApiResult<()> {
    let active = state.active_scan_root();
    let active_id = target_id_for_path(&active);
    let targets = load_targets(&state.database_dir)
        .map_err(|e| ApiError::internal(format!("failed to load targets: {e}")))?;
    if targets.iter().any(|target| target.id == active_id) {
        return Ok(());
    }
    remember_target(&state.database_dir, &active, TargetTouch::Seen)
        .map(|_| ())
        .map_err(|e| ApiError::internal(format!("failed to remember active target: {e}")))
}

fn canonical_project_path(path: &str) -> ApiResult<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("path is required"));
    }
    let path = FsPath::new(trimmed)
        .canonicalize()
        .map_err(|_| ApiError::bad_request("path does not exist"))?;
    if !path.is_dir() {
        return Err(ApiError::bad_request("path must be a directory"));
    }
    Ok(path)
}

fn target_path_by_id(state: &AppState, id: &str) -> ApiResult<PathBuf> {
    let targets = load_targets(&state.database_dir)
        .map_err(|e| ApiError::internal(format!("failed to load targets: {e}")))?;
    let record = targets
        .iter()
        .find(|target| target.id == id)
        .ok_or_else(|| ApiError::not_found(format!("target {id} not found")))?;
    let path = canonical_project_path(&record.path)?;
    if target_id_for_path(&path) != id {
        return Err(ApiError::bad_request("target path no longer matches id"));
    }
    Ok(path)
}

fn targets_to_views(targets: &[TargetRecord], active: &FsPath) -> Vec<TargetView> {
    targets
        .iter()
        .map(|record| record_to_view(record, active))
        .collect()
}

fn record_to_view(record: &TargetRecord, active: &FsPath) -> TargetView {
    let target_path = FsPath::new(&record.path);
    let active = active
        .canonicalize()
        .unwrap_or_else(|_| active.to_path_buf());
    let target_canonical = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    TargetView {
        id: record.id.clone(),
        name: record.name.clone(),
        path: record.path.clone(),
        db_path: record.db_path.clone(),
        last_seen_at: record.last_seen_at.clone(),
        last_scan_at: record.last_scan_at.clone(),
        active: target_canonical == active,
        exists: target_path.is_dir(),
    }
}

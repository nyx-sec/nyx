//! `GET /api/surface` — serve the project's [`SurfaceMap`](crate::surface::SurfaceMap).
//!
//! Loads the map persisted by the most recent indexed scan from
//! SQLite, falling back to building a fresh entry-point-only map from
//! the on-disk source when no scan has populated one yet.  The
//! response shape is the canonical `SurfaceMap` JSON — identical to
//! `nyx surface --format json` — so the frontend can reuse the same
//! deserialisation in both surfaces.

use crate::commands::surface::load_or_build;
use crate::server::app::AppState;
use crate::server::error::{ApiError, ApiResult};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

pub fn routes() -> Router<AppState> {
    Router::new().route("/surface", get(get_surface))
}

async fn get_surface(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let scan_root = state.active_scan_root();
    let database_dir = state.database_dir.clone();
    let cfg = state.config.read().clone();

    // Building the surface map can do filesystem IO + tree-sitter
    // parsing; keep it off the async runtime.
    let join_result =
        tokio::task::spawn_blocking(move || load_or_build(&scan_root, &database_dir, &cfg))
            .await
            .map_err(|e| ApiError::internal(format!("surface map task failed: {e}")))?;

    let mut map =
        join_result.map_err(|e| ApiError::internal(format!("failed to build surface map: {e}")))?;
    let bytes = map
        .to_json()
        .map_err(|e| ApiError::internal(format!("encode surface map: {e}")))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::internal(format!("re-parse surface map JSON: {e}")))?;
    Ok(Json(value))
}

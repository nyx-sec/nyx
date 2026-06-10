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

    let (mut map, _coverage) =
        join_result.map_err(|e| ApiError::internal(format!("failed to build surface map: {e}")))?;
    // Risk is derived from the canonicalised map, so canonicalise (via
    // `to_json`) first to lock node indices, then assess.
    let bytes = map
        .to_json()
        .map_err(|e| ApiError::internal(format!("encode surface map: {e}")))?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::internal(format!("re-parse surface map JSON: {e}")))?;
    // Attach per-entry-point risk assessment alongside the raw map so the
    // frontend can render a risk-sorted view without re-deriving scores.
    let risks = crate::surface::risk::assess_entry_risks(&map);
    if let Value::Object(obj) = &mut value {
        obj.insert(
            "entry_risks".into(),
            serde_json::to_value(&risks)
                .map_err(|e| ApiError::internal(format!("encode entry risks: {e}")))?,
        );
    }
    Ok(Json(value))
}

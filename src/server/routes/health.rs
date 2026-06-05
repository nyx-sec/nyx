use crate::server::app::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/session", get(session_info))
}

async fn health_check(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "scan_root": state.active_scan_root().display().to_string(),
    }))
}

async fn session_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "csrf_token": state.security.csrf_token(),
    }))
}

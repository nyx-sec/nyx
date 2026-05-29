pub mod config;
pub mod debug;
pub mod events;
pub mod explorer;
pub mod files;
pub mod findings;
pub mod health;
pub mod overview;
pub mod rules;
pub mod scans;
pub mod surface;
pub mod targets;
pub mod triage;

use crate::server::app::AppState;
use axum::Router;

/// Build all API routes under /api.
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .merge(health::routes())
        .merge(findings::routes())
        .merge(files::routes())
        .merge(scans::routes())
        .merge(config::routes())
        .merge(rules::routes())
        .merge(events::routes())
        .merge(triage::routes())
        .merge(overview::routes())
        .merge(explorer::routes())
        .merge(surface::routes())
        .merge(targets::routes())
        .merge(debug::routes())
}

use crate::server::jobs::JobManager;
use crate::server::models::{FilterValues, FindingSummary, FindingView};
use crate::server::observability;
use crate::server::progress::TimingBreakdown;
use crate::server::routes;
use crate::server::security::LocalServerSecurity;
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use axum::Router;
use parking_lot::RwLock;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Events broadcast over SSE to connected clients.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerEvent {
    ScanStarted {
        job_id: String,
    },
    ScanCompleted {
        job_id: String,
    },
    ScanFailed {
        job_id: String,
        error: String,
    },
    ScanProgress {
        job_id: String,
        stage: String,
        files_discovered: u64,
        files_parsed: u64,
        files_analyzed: u64,
        files_skipped: u64,
        batches_total: u64,
        batches_completed: u64,
        dynamic_enabled: bool,
        dynamic_total: u64,
        dynamic_completed: u64,
        current_file: String,
        elapsed_ms: u64,
        timing: TimingBreakdown,
    },
    ConfigChanged,
}

/// Pre-computed views over the latest scan's findings.
///
/// Built once per completed scan and reused across `/findings`,
/// `/findings/summary`, `/findings/filters`, and `/overview` requests so we
/// don't re-walk the diag list (or re-deserialize from SQLite) on every hit.
/// The `job_id` lets readers detect a stale entry without holding a write
/// lock on hot paths.
#[derive(Debug, Clone)]
pub struct CachedFindings {
    pub job_id: String,
    pub views: Arc<Vec<FindingView>>,
    pub summary: Arc<FindingSummary>,
    pub filters: Arc<FilterValues>,
}

/// Shared application state accessible to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub scan_root: Arc<RwLock<PathBuf>>,
    pub config_dir: PathBuf,
    pub database_dir: PathBuf,
    pub security: Arc<LocalServerSecurity>,
    pub config: Arc<RwLock<Config>>,
    pub job_manager: Arc<JobManager>,
    pub event_tx: broadcast::Sender<ServerEvent>,
    pub db_pools: Arc<RwLock<HashMap<PathBuf, Arc<Pool<SqliteConnectionManager>>>>>,
    pub findings_cache: Arc<RwLock<Option<CachedFindings>>>,
}

impl AppState {
    pub fn active_scan_root(&self) -> PathBuf {
        self.scan_root.read().clone()
    }

    pub fn set_active_scan_root(&self, scan_root: PathBuf) {
        *self.scan_root.write() = scan_root;
        *self.findings_cache.write() = None;
    }

    pub fn db_pool_for(
        &self,
        scan_root: &std::path::Path,
    ) -> Option<Arc<Pool<SqliteConnectionManager>>> {
        let canonical = scan_root
            .canonicalize()
            .unwrap_or_else(|_| scan_root.to_path_buf());
        if let Some(pool) = self.db_pools.read().get(&canonical).cloned() {
            return Some(pool);
        }

        let (_, db_path) = match get_project_info(&canonical, &self.database_dir) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("Failed to resolve target DB path: {e}");
                return None;
            }
        };
        let pool = match crate::database::index::Indexer::init(&db_path) {
            Ok(pool) => pool,
            Err(e) => {
                tracing::warn!("Failed to initialize target DB {}: {e}", db_path.display());
                return None;
            }
        };

        self.db_pools.write().insert(canonical, Arc::clone(&pool));
        Some(pool)
    }

    pub fn active_db_pool(&self) -> Option<Arc<Pool<SqliteConnectionManager>>> {
        self.db_pool_for(&self.active_scan_root())
    }
}

/// 50 MiB cap on request bodies, generous for config uploads, tight
/// enough to prevent OOM from a rogue client.
const MAX_BODY_BYTES: usize = 50 * 1024 * 1024;

/// CSP allowing self-hosted scripts only; `'unsafe-inline'` on styles is
/// required by the Vite-built React bundle's inlined CSS.
const CSP: &str = "default-src 'self'; \
    script-src 'self'; \
    style-src 'self' 'unsafe-inline'; \
    img-src 'self' data:; \
    connect-src 'self'";

/// Build the main axum router with all API routes and static asset fallback.
pub fn build_router(state: AppState) -> Router {
    use axum::extract::DefaultBodyLimit;
    use axum::http::{HeaderName, HeaderValue, header};
    use axum::middleware;
    use tower_http::compression::CompressionLayer;
    use tower_http::set_header::SetResponseHeaderLayer;

    let security = Arc::clone(&state.security);

    Router::new()
        .nest("/api", routes::api_routes())
        .fallback(crate::server::assets::static_handler)
        .layer(middleware::from_fn_with_state(
            security,
            crate::server::security::guard_requests,
        ))
        .layer(middleware::from_fn(observability::observe))
        .layer(CompressionLayer::new())
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tower::util::ServiceExt;

    fn test_state(scan_root: PathBuf, port: u16) -> AppState {
        let (event_tx, _) = broadcast::channel(8);
        AppState {
            scan_root: Arc::new(RwLock::new(scan_root.clone())),
            config_dir: scan_root.clone(),
            database_dir: scan_root,
            security: LocalServerSecurity::new(port),
            config: Arc::new(RwLock::new(Config::default())),
            job_manager: Arc::new(JobManager::new(4, 8 * 1024 * 1024)),
            event_tx,
            db_pools: Arc::new(RwLock::new(HashMap::new())),
            findings_cache: Arc::new(RwLock::new(None)),
        }
    }

    async fn session_token(state: &AppState) -> String {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        payload["csrf_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn rejects_bad_host_headers() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header("host", "evil.example:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blocks_mutations_without_csrf_token() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn blocks_cross_origin_mutations_even_with_csrf_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf(), 9700);
        let token = session_token(&state).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("host", "localhost:9700")
                    .header("origin", "http://evil.example:9700")
                    .header("x-nyx-csrf", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_traversal_in_file_route() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/files?path=..%2Fsecret.txt")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn security_headers_present_on_response() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let headers = response.headers();
        assert_eq!(
            headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY"),
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
        );
        assert_eq!(
            headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
            Some("no-referrer"),
        );
        let csp = headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(csp.contains("default-src 'self'"), "CSP was: {csp}");
        assert!(csp.contains("script-src 'self'"), "CSP was: {csp}");
    }

    /// Panic inside a thread that holds a write guard on the shared config lock.
    /// With `parking_lot::RwLock`, the lock must remain usable afterwards ,
    /// this is the poison-recovery contract we rely on in every route handler.
    #[tokio::test]
    async fn config_lock_survives_panic_in_write_guard() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf(), 9700);

        let lock = Arc::clone(&state.config);
        let join = std::thread::spawn(move || {
            let _guard = lock.write();
            panic!("simulated handler panic while holding write lock");
        });
        assert!(join.join().is_err(), "worker thread was expected to panic");

        // A follow-up request that reads the config must still succeed.
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/config")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explorer_tree_skips_symlink_escapes() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.rs");
        std::fs::write(&outside_file, "fn leaked() {}").unwrap();
        symlink(&outside_file, dir.path().join("escape.rs")).unwrap();

        let response = build_router(test_state(dir.path().to_path_buf(), 9700))
            .oneshot(
                Request::builder()
                    .uri("/api/explorer/tree")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = payload.as_array().unwrap();
        assert!(entries.iter().all(|entry| entry["name"] != "escape.rs"));
    }
}

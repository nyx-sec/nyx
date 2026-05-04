//! Cross-file FastAPI `include_router(child)` parent-dep propagation.
//!
//! Distilled from airflow
//! `airflow-core/src/airflow/api_fastapi/execution_api/routes/`:
//! `__init__.py` declares
//! `authenticated_router = VersionedAPIRouter(dependencies=[Security(require_auth)])`
//! and lifts every per-file child router via
//! `authenticated_router.include_router(<child>.router, ...)`.  FastAPI's
//! runtime propagates the parent's `dependencies=[...]` onto every route
//! attached to the child router, including bare child routers declared
//! without inline deps.
//!
//! Pre-fix: per-file router-dep extractor only saw inline declarations,
//! so bare child routers (`router = VersionedAPIRouter()`) fired
//! `missing_ownership_check` / `token_override_without_validation`
//! despite being authorized via the cross-file `include_router` chain.
//!
//! Post-fix: pass 1 persists per-file `PerFileRouterFacts` (router-level
//! deps + include_router edges) into
//! `GlobalSummaries.router_facts_by_module`; pass 2 resolves the
//! cross-file lift via `resolve_cross_file_router_deps_for_file` and
//! pre-populates `AuthorizationModel.cross_file_router_deps` before the
//! FlaskExtractor runs.  Cross-file `Security(...)` markers are flagged
//! scoped-equivalent (architectural intent of include_router auth
//! scoping), so `inject_middleware_auth` promotes the kind to `Other`
//! and ownership checks see the route as authorized.
//!
//! Recall guard: `public_health.py` is attached to `execution_api_router`
//! which has NO `dependencies=[...]` kwarg.  Routes there are genuinely
//! unauthorized — `missing_ownership_check` must still fire.  Without
//! this guard, an over-broad cross-file lift (e.g. blanket "every
//! include_router target inherits any parent's auth") would silently
//! suppress real findings.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn fastapi_cross_file_include_router_lifts_parent_security_onto_child_router() {
    let dir = fixture_path("auth_analysis_fastapi_cross_file_include_router");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

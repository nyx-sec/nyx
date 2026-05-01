//! Debug API route handlers.
//!
//! Provides endpoints for inspecting engine internals: CFG, SSA IR, taint
//! propagation, summaries, call graphs, abstract interpretation, and symbolic
//! execution.

use crate::server::app::AppState;
use crate::server::debug::{self, *};
use crate::utils::path::{DEFAULT_UI_MAX_FILE_BYTES, RepoPathError, resolve_repo_path};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::Deserialize;
use std::path::Path;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/debug/functions", get(list_functions))
        .route("/debug/cfg", get(get_cfg))
        .route("/debug/ssa", get(get_ssa))
        .route("/debug/taint", get(get_taint))
        .route("/debug/summaries", get(get_summaries))
        .route("/debug/call-graph", get(get_call_graph))
        .route("/debug/abstract-interp", get(get_abstract_interp))
        .route("/debug/symex", get(get_symex))
        .route("/debug/pointer", get(get_pointer))
        .route("/debug/type-facts", get(get_type_facts))
        .route("/debug/auth", get(get_auth))
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FileQuery {
    file: String,
}

#[derive(Debug, Deserialize)]
struct FileFunctionQuery {
    file: String,
    function: String,
}

#[derive(Debug, Deserialize)]
struct CallGraphQuery {
    scope: Option<String>,
    file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SummaryQuery {
    function: Option<String>,
    file: Option<String>,
}

// ── Path validation ──────────────────────────────────────────────────────────

fn validate_and_resolve(scan_root: &Path, file: &str) -> Result<std::path::PathBuf, StatusCode> {
    let resolved = resolve_repo_path(scan_root, file).map_err(map_path_error)?;
    let metadata = std::fs::metadata(&resolved.canonical).map_err(|_| StatusCode::NOT_FOUND)?;
    if !metadata.file_type().is_file() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if metadata.len() > DEFAULT_UI_MAX_FILE_BYTES {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(resolved.canonical)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// GET /api/debug/functions?file=<path>
/// List functions available for debug inspection in a file.
async fn list_functions(
    State(state): State<AppState>,
    Query(q): Query<FileQuery>,
) -> Result<Json<Vec<FunctionInfo>>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    Ok(Json(debug::function_list(&analysis)))
}

fn map_path_error(err: RepoPathError) -> StatusCode {
    match err {
        RepoPathError::InvalidPath | RepoPathError::OutsideRoot => StatusCode::FORBIDDEN,
        RepoPathError::NotFound => StatusCode::NOT_FOUND,
        RepoPathError::NotFile
        | RepoPathError::NotDirectory
        | RepoPathError::TooLarge
        | RepoPathError::InvalidText => StatusCode::BAD_REQUEST,
        RepoPathError::Io => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// GET /api/debug/cfg?file=<path>&function=<name>
/// Return the CFG for a specific function as a graph JSON.
async fn get_cfg(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<CfgGraphView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;

    let view = CfgGraphView::from_cfg_function(&analysis.file_cfg, &q.function, &analysis.bytes)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(view))
}

/// GET /api/debug/ssa?file=<path>&function=<name>
/// Return the SSA IR for a specific function.
async fn get_ssa(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<SsaBodyView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, _opt, _cfg) = debug::analyse_function_ssa(&analysis, &q.function)?;
    Ok(Json(SsaBodyView::from_ssa(&ssa, &analysis.bytes)))
}

/// GET /api/debug/taint?file=<path>&function=<name>
/// Return taint analysis results for a specific function.
async fn get_taint(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<TaintAnalysisView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt, body_cfg) = debug::analyse_function_ssa(&analysis, &q.function)?;

    // Try to load global summaries from DB for cross-file context
    let global = load_global_summaries(&state);
    let cross_file_context = global.as_ref().is_some_and(|g| !g.is_empty());
    let ssa_summaries_available = global
        .as_ref()
        .is_some_and(|g| !g.snapshot_ssa().is_empty());

    let (events, _entry_states, exit_states) = debug::analyse_function_taint(
        &ssa,
        body_cfg,
        analysis.lang,
        analysis.summaries(),
        global.as_ref(),
        &opt,
    );

    // Show post-block state so single-block source→sink flows are visible in
    // the debug UI instead of appearing empty at block entry.
    Ok(Json(TaintAnalysisView::from_results(
        &events,
        &exit_states,
        &ssa,
        cross_file_context,
        ssa_summaries_available,
    )))
}

/// GET /api/debug/abstract-interp?file=<path>&function=<name>
/// Return abstract interpretation state for a specific function.
async fn get_abstract_interp(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<AbstractInterpView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt, body_cfg) = debug::analyse_function_ssa(&analysis, &q.function)?;

    let global = load_global_summaries(&state);

    let (_events, block_states, _exit_states) = debug::analyse_function_taint(
        &ssa,
        body_cfg,
        analysis.lang,
        analysis.summaries(),
        global.as_ref(),
        &opt,
    );

    Ok(Json(AbstractInterpView::from_taint_states(
        &block_states,
        &ssa,
        &opt,
    )))
}

/// GET /api/debug/summaries?file=<path>&function=<name>
/// Return interprocedural summaries.
async fn get_summaries(
    State(state): State<AppState>,
    Query(q): Query<SummaryQuery>,
) -> Result<Json<Vec<FuncSummaryView>>, StatusCode> {
    // Try DB first; fall back to on-demand single-file analysis
    let global = match load_global_summaries(&state) {
        Some(g) if !g.is_empty() => g,
        _ => {
            if let Some(ref file) = q.file {
                let path = validate_and_resolve(&state.scan_root, file)?;
                let config = state.config.read();
                debug::analyse_file_summaries(&path, &config)?
            } else {
                return Ok(Json(vec![]));
            }
        }
    };

    let views: Vec<FuncSummaryView> = global
        .iter()
        .filter(|(key, summary)| {
            let name_matches = q.function.as_ref().map(|f| key.name == *f).unwrap_or(true);
            let file_matches = q
                .file
                .as_ref()
                .map(|f| summary.file_path.contains(f.as_str()))
                .unwrap_or(true);
            name_matches && file_matches
        })
        .map(|(key, summary)| {
            let ssa_summary = global.get_ssa(key);
            FuncSummaryView::from_global(key, summary, ssa_summary)
        })
        .collect();

    Ok(Json(views))
}

/// GET /api/debug/call-graph?scope=file|project&file=<path>
/// Return the call graph.
async fn get_call_graph(
    State(state): State<AppState>,
    Query(q): Query<CallGraphQuery>,
) -> Result<Json<CallGraphView>, StatusCode> {
    let scope = q.scope.as_deref().unwrap_or("project");

    let global = if scope == "file" {
        // On-demand: parse the specified file and extract summaries
        let file = q.file.as_deref().ok_or(StatusCode::BAD_REQUEST)?;
        let path = validate_and_resolve(&state.scan_root, file)?;
        let config = state.config.read();
        debug::analyse_file_summaries(&path, &config)?
    } else {
        // Project scope: try DB, fall back to empty graph
        load_global_summaries(&state).unwrap_or_default()
    };

    let cg = crate::callgraph::build_call_graph(&global, &[]);
    let analysis = crate::callgraph::analyse(&cg);

    Ok(Json(CallGraphView::from_call_graph(&cg, &analysis)))
}

/// GET /api/debug/symex?file=<path>&function=<name>
/// Return symbolic execution state for a function.
async fn get_symex(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<SymexView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt, body_cfg) = debug::analyse_function_ssa(&analysis, &q.function)?;

    let global = load_global_summaries(&state);

    let sym_state =
        debug::analyse_function_symex(&ssa, body_cfg, analysis.lang, &opt, global.as_ref());

    Ok(Json(SymexView::from_symbolic_state(&sym_state, &ssa)))
}

/// GET /api/debug/pointer?file=<path>&function=<name>
/// Return the field-sensitive Steensgaard points-to facts for a function.
async fn get_pointer(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<PointerView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, facts) = debug::analyse_function_pointer(&analysis, &q.function)?;
    Ok(Json(PointerView::from_facts(&facts, &ssa)))
}

/// GET /api/debug/type-facts?file=<path>&function=<name>
/// Return per-function type-fact details derived from the SSA optimiser.
async fn get_type_facts(
    State(state): State<AppState>,
    Query(q): Query<FileFunctionQuery>,
) -> Result<Json<TypeFactsView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let analysis = debug::analyse_file(&path, &config)?;
    let (ssa, opt, _cfg) = debug::analyse_function_ssa(&analysis, &q.function)?;
    Ok(Json(TypeFactsView::from_optimize(
        &opt,
        &ssa,
        &analysis.bytes,
    )))
}

/// GET /api/debug/auth?file=<path>
/// Return the file-scoped authorization model, routes, units,
/// sensitive operations, and auth checks, for the debug UI.
async fn get_auth(
    State(state): State<AppState>,
    Query(q): Query<FileQuery>,
) -> Result<Json<AuthAnalysisView>, StatusCode> {
    let path = validate_and_resolve(&state.scan_root, &q.file)?;
    let config = state.config.read();
    let (model, bytes, enabled) = debug::analyse_file_auth(&path, &config)?;
    Ok(Json(AuthAnalysisView::from_model(&model, &bytes, enabled)))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Load global summaries from DB if available.
fn load_global_summaries(state: &AppState) -> Option<crate::summary::GlobalSummaries> {
    let pool = state.db_pool.as_ref()?;
    load_global_summaries_from_pool(&state.scan_root, pool)
}

fn load_global_summaries_from_pool(
    scan_root: &Path,
    pool: &Pool<SqliteConnectionManager>,
) -> Option<crate::summary::GlobalSummaries> {
    let project = scan_root.file_name()?.to_str()?;
    let root_str = scan_root.to_string_lossy();
    let indexer = crate::database::index::Indexer::from_pool(project, pool).ok()?;
    let func_summaries = indexer.load_all_summaries().ok()?;
    let ssa_rows = indexer.load_all_ssa_summaries().ok()?;

    let mut global = crate::summary::merge_summaries(func_summaries, Some(&root_str));
    for (_file_path, name, lang_str, arity, namespace, container, disambig, kind, summary) in
        ssa_rows
    {
        let lang = crate::symbol::Lang::from_slug(&lang_str).unwrap_or(crate::symbol::Lang::Rust);
        let key = crate::symbol::FuncKey {
            lang,
            namespace: if namespace.is_empty() {
                crate::symbol::normalize_namespace(&_file_path, Some(&root_str))
            } else {
                namespace
            },
            container,
            name,
            arity: if arity >= 0 {
                Some(arity as usize)
            } else {
                None
            },
            disambig,
            kind,
        };
        global.insert_ssa(key, summary);
    }

    Some(global)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::index::Indexer;
    use crate::labels::Cap;
    use crate::summary::FuncSummary;
    use crate::summary::ssa_summary::SsaFuncSummary;
    use crate::symbol::{FuncKey, Lang};

    /// Helper: create a DB pool with persisted summaries for a JS helper function.
    fn setup_db_with_summaries(
        dir: &std::path::Path,
        scan_root: &std::path::Path,
    ) -> std::sync::Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>> {
        std::fs::create_dir_all(scan_root.join("src")).unwrap();
        let file_path = scan_root.join("src/helper.js");
        std::fs::write(
            &file_path,
            "function getInput() { return process.env.USER_INPUT; }\nmodule.exports = { getInput };",
        )
        .unwrap();

        let db_path = dir.join("test.sqlite");
        let pool = Indexer::init(&db_path).unwrap();
        let mut indexer =
            Indexer::from_pool(scan_root.file_name().unwrap().to_str().unwrap(), &pool).unwrap();

        indexer
            .replace_summaries_for_file(
                &file_path,
                b"hash",
                &[FuncSummary {
                    name: "getInput".into(),
                    file_path: file_path.to_string_lossy().into_owned(),
                    lang: "javascript".into(),
                    param_count: 0,
                    param_names: vec![],
                    source_caps: Cap::all().bits(),
                    sanitizer_caps: 0,
                    sink_caps: 0,
                    propagating_params: vec![],
                    propagates_taint: false,
                    tainted_sink_params: vec![],
                    callees: vec![],
                    ..Default::default()
                }],
            )
            .unwrap();
        indexer
            .replace_ssa_summaries_for_file(
                &file_path,
                b"hash",
                &[(
                    "getInput".into(),
                    0,
                    "javascript".into(),
                    "src/helper.js".into(),
                    String::new(),
                    None,
                    crate::symbol::FuncKind::Function,
                    SsaFuncSummary {
                        param_to_return: vec![],
                        param_to_sink: vec![],
                        source_caps: Cap::all(),
                        param_to_sink_param: vec![],
                        param_container_to_return: vec![],
                        param_to_container_store: vec![],
                        return_type: None,
                        return_abstract: None,
                        source_to_callback: vec![],

                        receiver_to_return: None,

                        receiver_to_sink: Cap::empty(),

                        abstract_transfer: vec![],
                        param_return_paths: vec![],
                        points_to: Default::default(),
                        field_points_to: Default::default(),
                        return_path_facts: smallvec::SmallVec::new(),
                        typed_call_receivers: vec![],
                        param_to_gate_filters: vec![],
                    },
                )],
            )
            .unwrap();

        pool
    }

    #[test]
    fn taint_route_reports_cross_file_context_when_summaries_present() {
        let dir = tempfile::tempdir().unwrap();
        let scan_root = dir.path().join("myproject");
        let pool = setup_db_with_summaries(dir.path(), &scan_root);

        let global =
            load_global_summaries_from_pool(&scan_root, &pool).expect("should load summaries");

        let cross_file_context = !global.is_empty();
        let ssa_summaries_available = !global.snapshot_ssa().is_empty();

        assert!(
            cross_file_context,
            "cross_file_context should be true when DB has persisted summaries"
        );
        assert!(
            ssa_summaries_available,
            "ssa_summaries_available should be true when DB has SSA summaries"
        );
    }

    #[test]
    fn taint_route_reports_no_cross_file_context_when_db_empty() {
        let dir = tempfile::tempdir().unwrap();
        let scan_root = dir.path().join("emptyproject");
        std::fs::create_dir_all(&scan_root).unwrap();

        let db_path = dir.path().join("empty.sqlite");
        let pool = Indexer::init(&db_path).unwrap();
        let _indexer = Indexer::from_pool("emptyproject", &pool).unwrap();

        let global = load_global_summaries_from_pool(&scan_root, &pool);

        let cross_file_context = global.as_ref().is_some_and(|g| !g.is_empty());
        let ssa_summaries_available = global
            .as_ref()
            .is_some_and(|g| !g.snapshot_ssa().is_empty());

        assert!(
            !cross_file_context,
            "cross_file_context should be false when DB has no summaries"
        );
        assert!(
            !ssa_summaries_available,
            "ssa_summaries_available should be false when DB has no SSA summaries"
        );
    }

    #[test]
    fn taint_view_includes_context_flags_with_no_summaries() {
        // Simulate the debug view construction with no cross-file context
        let view = TaintAnalysisView::from_results(
            &[],
            &[],
            &crate::ssa::ir::SsaBody {
                blocks: vec![],
                entry: crate::ssa::ir::BlockId(0),
                value_defs: vec![],
                cfg_node_map: std::collections::HashMap::new(),
                exception_edges: vec![],
                field_interner: crate::ssa::ir::FieldInterner::default(),
                field_writes: std::collections::HashMap::new(),

                synthetic_externals: std::collections::HashSet::new(),
            },
            false,
            false,
        );

        assert!(!view.cross_file_context);
        assert!(!view.ssa_summaries_available);
    }

    #[test]
    fn taint_view_includes_context_flags_with_summaries() {
        let view = TaintAnalysisView::from_results(
            &[],
            &[],
            &crate::ssa::ir::SsaBody {
                blocks: vec![],
                entry: crate::ssa::ir::BlockId(0),
                value_defs: vec![],
                cfg_node_map: std::collections::HashMap::new(),
                exception_edges: vec![],
                field_interner: crate::ssa::ir::FieldInterner::default(),
                field_writes: std::collections::HashMap::new(),

                synthetic_externals: std::collections::HashSet::new(),
            },
            true,
            true,
        );

        assert!(view.cross_file_context);
        assert!(view.ssa_summaries_available);
    }

    #[test]
    fn taint_view_serializes_context_fields() {
        let view = TaintAnalysisView::from_results(
            &[],
            &[],
            &crate::ssa::ir::SsaBody {
                blocks: vec![],
                entry: crate::ssa::ir::BlockId(0),
                value_defs: vec![],
                cfg_node_map: std::collections::HashMap::new(),
                exception_edges: vec![],
                field_interner: crate::ssa::ir::FieldInterner::default(),
                field_writes: std::collections::HashMap::new(),

                synthetic_externals: std::collections::HashSet::new(),
            },
            true,
            false,
        );

        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["cross_file_context"], true);
        assert_eq!(json["ssa_summaries_available"], false);
    }

    #[test]
    fn load_global_summaries_graceful_on_malformed_db() {
        // A DB with no tables at all should not crash, just return None
        let dir = tempfile::tempdir().unwrap();
        let scan_root = dir.path().join("badproject");
        std::fs::create_dir_all(&scan_root).unwrap();

        let db_path = dir.path().join("bad.sqlite");
        // Create a raw SQLite file without our schema
        let manager = r2d2_sqlite::SqliteConnectionManager::file(&db_path);
        let pool = r2d2::Pool::builder().max_size(1).build(manager).unwrap();

        let result = load_global_summaries_from_pool(&scan_root, &pool);
        // Should return None gracefully, not panic
        assert!(
            result.is_none(),
            "malformed DB should return None, not crash"
        );
    }

    #[test]
    fn load_global_summaries_uses_scan_root_project_and_normalized_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let scan_root = dir.path().join("Example Project");
        std::fs::create_dir_all(scan_root.join("src")).unwrap();
        let file_path = scan_root.join("src/lib.rs");
        std::fs::write(&file_path, "fn helper() {}").unwrap();

        let db_path = dir.path().join("example_project.sqlite");
        let pool = Indexer::init(&db_path).unwrap();
        let mut indexer = Indexer::from_pool("Example Project", &pool).unwrap();

        indexer
            .replace_summaries_for_file(
                &file_path,
                b"hash",
                &[FuncSummary {
                    name: "helper".into(),
                    file_path: file_path.to_string_lossy().into_owned(),
                    lang: "rust".into(),
                    param_count: 0,
                    param_names: vec![],
                    source_caps: 0,
                    sanitizer_caps: 0,
                    sink_caps: 0,
                    propagating_params: vec![],
                    propagates_taint: false,
                    tainted_sink_params: vec![],
                    callees: vec![],
                    ..Default::default()
                }],
            )
            .unwrap();
        indexer
            .replace_ssa_summaries_for_file(
                &file_path,
                b"hash",
                &[(
                    "helper".into(),
                    0,
                    "rust".into(),
                    "src/lib.rs".into(),
                    String::new(),
                    None,
                    crate::symbol::FuncKind::Function,
                    SsaFuncSummary {
                        param_to_return: vec![],
                        param_to_sink: vec![],
                        source_caps: Cap::ENV_VAR,
                        param_to_sink_param: vec![],
                        param_container_to_return: vec![],
                        param_to_container_store: vec![],
                        return_type: None,
                        return_abstract: None,
                        source_to_callback: vec![],

                        receiver_to_return: None,

                        receiver_to_sink: Cap::empty(),

                        abstract_transfer: vec![],
                        param_return_paths: vec![],
                        points_to: Default::default(),
                        field_points_to: Default::default(),
                        return_path_facts: smallvec::SmallVec::new(),
                        typed_call_receivers: vec![],
                        param_to_gate_filters: vec![],
                    },
                )],
            )
            .unwrap();

        let global = load_global_summaries_from_pool(&scan_root, &pool)
            .expect("debug loader should recover project summaries");

        let key = FuncKey {
            lang: Lang::Rust,
            namespace: "src/lib.rs".into(),
            name: "helper".into(),
            arity: Some(0),
            ..Default::default()
        };

        assert!(global.get(&key).is_some());
        assert!(
            global.get_ssa(&key).is_some(),
            "SSA summaries should line up with the normalized function keys"
        );
    }
}

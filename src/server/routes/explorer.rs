#![allow(clippy::collapsible_if)]

use crate::database::index::Indexer;
use crate::server::app::AppState;
use crate::server::models::lang_for_finding_path;
use crate::server::routes::findings::load_latest_findings;
use crate::utils::path::{RepoPathError, resolve_repo_dir, resolve_repo_path};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use crate::patterns::Severity;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/explorer/tree", get(get_tree))
        .route("/explorer/symbols", get(get_symbols))
        .route("/explorer/findings", get(get_findings))
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TreeQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SymbolsQuery {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ExplorerFindingsQuery {
    path: String,
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TreeEntry {
    name: String,
    entry_type: String,
    path: String,
    language: Option<String>,
    finding_count: usize,
    severity_max: Option<String>,
}

#[derive(Debug, Serialize)]
struct SymbolEntry {
    name: String,
    /// Legacy display kind (`"function"` / `"method"`) used by existing CSS
    /// classes in the frontend.  Kept for backward-compat, new consumers
    /// should prefer `func_kind`.
    kind: String,
    /// Structural [`crate::symbol::FuncKind`] slug (`"fn"`, `"method"`,
    /// `"closure"`, `"ctor"`, `"getter"`, `"setter"`, `"toplevel"`).  Lets
    /// the UI distinguish anonymous closures (`<anon#N>`) from named
    /// functions and offer a default-hide toggle.
    func_kind: String,
    /// Enclosing container path (class / impl / module / outer function).
    /// Empty for free top-level functions.  Surfaced so the UI can render
    /// closures as `<anon#N> [in outer_fn]`.
    container: String,
    line: Option<usize>,
    finding_count: usize,
    namespace: Option<String>,
    arity: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ExplorerFinding {
    index: usize,
    line: usize,
    col: usize,
    severity: String,
    rule_id: String,
    category: String,
    message: Option<String>,
    confidence: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

fn max_severity(a: Option<Severity>, b: Severity) -> Severity {
    match a {
        Some(existing) => {
            if severity_rank(b) > severity_rank(existing) {
                b
            } else {
                existing
            }
        }
        None => b,
    }
}

/// Normalize a Diag path to be relative to scan_root.
///
/// Diag.path is typically absolute (from the file walker). The explorer UI
/// works with relative paths, so we strip the scan_root prefix. If the path
/// is already relative (e.g. in tests), return it as-is.
fn relativize_path<'a>(diag_path: &'a str, scan_root_str: &str) -> &'a str {
    diag_path
        .strip_prefix(scan_root_str)
        .unwrap_or(diag_path)
        .trim_start_matches('/')
}

// ── GET /api/explorer/tree ───────────────────────────────────────────────────

async fn get_tree(
    State(state): State<AppState>,
    Query(query): Query<TreeQuery>,
) -> Result<Json<Vec<TreeEntry>>, StatusCode> {
    let scan_root = state.active_scan_root();
    let resolved = resolve_repo_dir(&scan_root, query.path.as_deref()).map_err(map_path_error)?;
    let canonical = resolved.canonical;

    // Load findings and pre-compute per-file and per-directory aggregates
    let findings = load_latest_findings(&state);
    let canonical_root = resolved.root;
    let root_str = canonical_root.to_string_lossy();

    let mut file_counts: HashMap<String, (usize, Severity)> = HashMap::new();
    let mut dir_counts: HashMap<String, (usize, Severity)> = HashMap::new();

    for d in findings.iter() {
        // Normalize Diag absolute path to relative
        let rel = relativize_path(&d.path, &root_str);
        if rel.is_empty() {
            continue;
        }

        let entry = file_counts
            .entry(rel.to_string())
            .or_insert((0, Severity::Low));
        entry.0 += 1;
        entry.1 = max_severity(Some(entry.1), d.severity);

        // Aggregate into all ancestor directories
        let mut path = rel;
        while let Some(i) = path.rfind('/') {
            path = &path[..i];
            let entry = dir_counts
                .entry(path.to_string())
                .or_insert((0, Severity::Low));
            entry.0 += 1;
            entry.1 = max_severity(Some(entry.1), d.severity);
        }
    }

    let mut entries = Vec::new();
    let read_dir = fs::read_dir(&canonical).map_err(|_| StatusCode::NOT_FOUND)?;

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files/directories
        if name.starts_with('.') {
            continue;
        }

        let entry_path = entry.path();
        let is_dir = entry_path.is_dir();

        // Compute relative path from scan_root
        let canonical_entry = match fs::canonicalize(&entry_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !canonical_entry.starts_with(&canonical_root) {
            continue;
        }
        let rel_path = canonical_entry
            .strip_prefix(&canonical_root)
            .unwrap_or(&canonical_entry)
            .to_string_lossy()
            .to_string();

        let (finding_count, severity_max) = if is_dir {
            match dir_counts.get(&rel_path) {
                Some(&(count, sev)) => (count, Some(sev.as_db_str().to_string())),
                None => (0, None),
            }
        } else {
            match file_counts.get(&rel_path) {
                Some(&(count, sev)) => (count, Some(sev.as_db_str().to_string())),
                None => (0, None),
            }
        };

        let language = if is_dir {
            None
        } else {
            lang_for_finding_path(&rel_path)
        };

        entries.push(TreeEntry {
            name,
            entry_type: if is_dir {
                "dir".to_string()
            } else {
                "file".to_string()
            },
            path: rel_path,
            language,
            finding_count,
            severity_max,
        });
    }

    // Sort: dirs first (alpha), then files (alpha)
    entries.sort_by(|a, b| {
        let a_is_dir = a.entry_type == "dir";
        let b_is_dir = b.entry_type == "dir";
        b_is_dir
            .cmp(&a_is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(Json(entries))
}

// ── GET /api/explorer/symbols ────────────────────────────────────────────────

async fn get_symbols(
    State(state): State<AppState>,
    Query(query): Query<SymbolsQuery>,
) -> Result<Json<Vec<SymbolEntry>>, StatusCode> {
    let scan_root = state.active_scan_root();
    let resolved = resolve_repo_path(&scan_root, &query.path).map_err(map_path_error)?;

    let pool = match state.active_db_pool() {
        Some(p) => p,
        None => return Ok(Json(vec![])),
    };

    let idx = Indexer::from_pool("_scans", &pool).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build absolute path for DB lookup (DB stores absolute paths)
    let canonical_root = resolved.root;
    let abs_path = resolved.canonical;
    let abs_path_str = abs_path.to_string_lossy();
    let root_str = canonical_root.to_string_lossy();

    // Load findings for function-level finding count
    let findings = load_latest_findings(&state);
    let mut func_finding_counts: HashMap<String, usize> = HashMap::new();
    for d in findings.iter() {
        let rel = relativize_path(&d.path, &root_str);
        if rel != resolved.relative {
            continue;
        }
        // Try to get function name from evidence flow steps
        if let Some(ref ev) = d.evidence {
            for step in &ev.flow_steps {
                if let Some(ref func) = step.function {
                    *func_finding_counts.entry(func.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    // Try absolute path first (production), then relative (tests)
    let mut symbols = idx
        .load_ssa_summaries_for_file(&abs_path_str)
        .unwrap_or_default();
    if symbols.is_empty() {
        symbols = idx
            .load_ssa_summaries_for_file(&query.path)
            .unwrap_or_default();
    }

    let entries: Vec<SymbolEntry> = symbols
        .into_iter()
        .map(|(name, arity, _lang, namespace, container, func_kind)| {
            // Legacy `kind` field, still used by existing CSS classes
            // (`symbol-kind-method`, `symbol-kind-function`).  Map any
            // method-like FuncKind onto `"method"` and everything else
            // onto `"function"` so the rendered icon stays sensible.
            let kind = match func_kind.as_str() {
                "method" | "ctor" | "getter" | "setter" => "method".to_string(),
                _ => "function".to_string(),
            };
            let finding_count = func_finding_counts.get(&name).copied().unwrap_or(0);
            SymbolEntry {
                name,
                kind,
                func_kind,
                container,
                line: None,
                finding_count,
                namespace: if namespace.is_empty() {
                    None
                } else {
                    Some(namespace)
                },
                arity: if arity < 0 {
                    None
                } else {
                    Some(arity as usize)
                },
            }
        })
        .collect();

    Ok(Json(entries))
}

// ── GET /api/explorer/findings ───────────────────────────────────────────────

async fn get_findings(
    State(state): State<AppState>,
    Query(query): Query<ExplorerFindingsQuery>,
) -> Result<Json<Vec<ExplorerFinding>>, StatusCode> {
    let scan_root = state.active_scan_root();
    let resolved = resolve_repo_path(&scan_root, &query.path).map_err(map_path_error)?;

    let findings = load_latest_findings(&state);
    let root_str = resolved.root.to_string_lossy();

    let mut results: Vec<ExplorerFinding> = findings
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            let rel = relativize_path(&d.path, &root_str);
            rel == resolved.relative
        })
        .map(|(i, d)| ExplorerFinding {
            index: i,
            line: d.line,
            col: d.col,
            severity: d.severity.as_db_str().to_string(),
            rule_id: d.id.clone(),
            category: d.category.to_string(),
            message: d.message.clone(),
            confidence: d.confidence.map(|c| c.to_string()),
        })
        .collect();

    results.sort_by_key(|f| f.line);

    Ok(Json(results))
}

fn map_path_error(err: RepoPathError) -> StatusCode {
    match err {
        RepoPathError::InvalidPath | RepoPathError::OutsideRoot => StatusCode::FORBIDDEN,
        RepoPathError::NotFound => StatusCode::NOT_FOUND,
        RepoPathError::NotDirectory => StatusCode::BAD_REQUEST,
        RepoPathError::NotFile | RepoPathError::TooLarge | RepoPathError::InvalidText => {
            StatusCode::BAD_REQUEST
        }
        RepoPathError::Io => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

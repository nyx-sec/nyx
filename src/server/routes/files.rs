use crate::server::app::AppState;
use crate::server::error::{ApiError, ApiResult};
use crate::utils::path::{DEFAULT_UI_MAX_FILE_BYTES, RepoPathError, open_repo_text_file};
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new().route("/files", get(get_file))
}

#[derive(Debug, Deserialize)]
struct FileQuery {
    path: String,
    start_line: Option<usize>,
    end_line: Option<usize>,
}

#[derive(Debug, Serialize)]
struct FileLine {
    number: usize,
    content: String,
}

#[derive(Debug, Serialize)]
struct FileResponse {
    path: String,
    lines: Vec<FileLine>,
    total_lines: usize,
}

async fn get_file(
    State(state): State<AppState>,
    Query(query): Query<FileQuery>,
) -> ApiResult<Json<FileResponse>> {
    let scan_root = state.active_scan_root();
    let opened = open_repo_text_file(&scan_root, &query.path, DEFAULT_UI_MAX_FILE_BYTES)
        .map_err(|e| map_path_error(e, &query.path))?;
    let content = opened.content;
    let all_lines: Vec<&str> = content.lines().collect();
    let total_lines = all_lines.len();

    // Apply line range (1-indexed)
    let start = query.start_line.unwrap_or(1).max(1);
    let end = query.end_line.unwrap_or(total_lines).min(total_lines);

    let lines: Vec<FileLine> = if start <= end && start <= total_lines {
        all_lines[start - 1..end]
            .iter()
            .enumerate()
            .map(|(i, l)| FileLine {
                number: start + i,
                content: (*l).to_string(),
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(FileResponse {
        path: opened.resolved.relative,
        lines,
        total_lines,
    }))
}

fn map_path_error(err: RepoPathError, path: &str) -> ApiError {
    match err {
        RepoPathError::InvalidPath => ApiError::forbidden(format!("invalid path: {path}")),
        RepoPathError::OutsideRoot => {
            ApiError::forbidden(format!("path outside scan root: {path}"))
        }
        RepoPathError::NotFound => ApiError::not_found(format!("file not found: {path}")),
        RepoPathError::TooLarge => {
            ApiError::bad_request(format!("file too large to display: {path}"))
        }
        RepoPathError::InvalidText => {
            ApiError::bad_request(format!("file is not valid UTF-8 text: {path}"))
        }
        RepoPathError::NotFile => {
            ApiError::bad_request(format!("path is not a regular file: {path}"))
        }
        RepoPathError::NotDirectory => {
            ApiError::bad_request(format!("path is not a directory: {path}"))
        }
        RepoPathError::Io => ApiError::internal(format!("I/O error reading: {path}")),
    }
}

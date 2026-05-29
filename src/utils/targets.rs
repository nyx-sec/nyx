use crate::errors::{NyxError, NyxResult};
use crate::utils::project::{get_project_info, sanitize_project_name};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const TARGETS_FILE: &str = "targets.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetTouch {
    Seen,
    Scanned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetRecord {
    pub id: String,
    pub name: String,
    pub path: String,
    pub db_path: String,
    pub last_seen_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TargetFile {
    #[serde(default)]
    targets: Vec<TargetRecord>,
}

pub fn targets_path(database_dir: &Path) -> PathBuf {
    database_dir.join(TARGETS_FILE)
}

pub fn load_targets(database_dir: &Path) -> NyxResult<Vec<TargetRecord>> {
    let path = targets_path(database_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let file: TargetFile =
        serde_json::from_slice(&bytes).map_err(|e| NyxError::Other(Box::new(e)))?;
    Ok(file.targets)
}

pub fn save_targets(database_dir: &Path, targets: &[TargetRecord]) -> NyxResult<()> {
    fs::create_dir_all(database_dir)?;
    let path = targets_path(database_dir);
    let file = TargetFile {
        targets: targets.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&file).map_err(|e| NyxError::Other(Box::new(e)))?;
    fs::write(path, bytes)?;
    Ok(())
}

pub fn remember_target(
    database_dir: &Path,
    project_path: &Path,
    touch: TargetTouch,
) -> NyxResult<TargetRecord> {
    let canonical = project_path.canonicalize()?;
    let path_str = canonical.to_string_lossy().to_string();
    let now = Utc::now().to_rfc3339();
    let (_, db_path) = get_project_info(&canonical, database_dir)?;
    let mut targets = load_targets(database_dir)?;
    let id = target_id_for_path(&canonical);

    let mut record = TargetRecord {
        id: id.clone(),
        name: display_name_for_path(&canonical),
        path: path_str.clone(),
        db_path: db_path.to_string_lossy().to_string(),
        last_seen_at: now.clone(),
        last_scan_at: (touch == TargetTouch::Scanned).then_some(now.clone()),
    };

    if let Some(existing) = targets.iter_mut().find(|target| target.id == id) {
        existing.name = record.name.clone();
        existing.path = record.path.clone();
        existing.db_path = record.db_path.clone();
        existing.last_seen_at = now;
        if touch == TargetTouch::Scanned {
            existing.last_scan_at = record.last_scan_at.clone();
        } else {
            record.last_scan_at = existing.last_scan_at.clone();
        }
        record = existing.clone();
    } else {
        targets.push(record.clone());
    }

    targets.sort_by(|a, b| {
        b.last_scan_at
            .as_deref()
            .unwrap_or(&b.last_seen_at)
            .cmp(a.last_scan_at.as_deref().unwrap_or(&a.last_seen_at))
            .then_with(|| a.name.cmp(&b.name))
    });
    save_targets(database_dir, &targets)?;
    Ok(record)
}

pub fn remove_target(database_dir: &Path, id: &str) -> NyxResult<Option<TargetRecord>> {
    let mut targets = load_targets(database_dir)?;
    let Some(pos) = targets.iter().position(|target| target.id == id) else {
        return Ok(None);
    };
    let removed = targets.remove(pos);
    save_targets(database_dir, &targets)?;
    Ok(Some(removed))
}

pub fn target_id_for_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    let hash = blake3::hash(path_str.as_bytes()).to_hex().to_string();
    let slug = display_name_for_path(path);
    format!("{}-{}", sanitize_project_name(&slug), &hash[..12])
}

fn display_name_for_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_and_updates_target() {
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();

        let first = remember_target(data.path(), project.path(), TargetTouch::Seen).unwrap();
        assert!(first.last_scan_at.is_none());

        let second = remember_target(data.path(), project.path(), TargetTouch::Scanned).unwrap();
        assert_eq!(first.id, second.id);
        assert!(second.last_scan_at.is_some());

        let targets = load_targets(data.path()).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, first.id);
    }

    #[test]
    fn target_id_is_stable_for_path() {
        let project = tempfile::tempdir().unwrap();
        let a = target_id_for_path(project.path());
        let b = target_id_for_path(project.path());
        assert_eq!(a, b);
    }
}

use crate::cli::IndexAction;
use crate::database::index::{IndexWriteQueue, Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::server::progress::{ScanMetrics, ScanProgress, ScanStage};
use crate::server::scan_log::ScanLogCollector;
use crate::utils::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

pub fn handle(
    action: IndexAction,
    database_dir: &std::path::Path,
    config: &Config,
) -> NyxResult<()> {
    match action {
        IndexAction::Build { path, force } => {
            let build_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&build_path, database_dir)?;
            let _ = crate::utils::targets::remember_target(
                database_dir,
                &build_path,
                crate::utils::targets::TargetTouch::Seen,
            );

            if force || !db_path.exists() {
                build_index(
                    &project_name,
                    &build_path,
                    &db_path,
                    config,
                    !config.output.quiet,
                )?;
                println!(
                    "✔ {} {}",
                    style("Index built:").green(),
                    style(db_path.display()).white().bold()
                );
                exit(0);
            } else {
                println!(
                    "{} {}",
                    style("↩ Index already exists").yellow(),
                    style("(use --force to rebuild)").dim()
                );
                exit(0);
            }
        }
        IndexAction::Status { path } => {
            let status_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&status_path, database_dir)?;

            println!("{}", style("Index status").bold());
            println!(
                "  {:10} {}",
                style("Project").dim(),
                style(&project_name).white().bold()
            );
            println!(
                "  {:10} {}",
                style("Path").dim(),
                style(db_path.display()).underlined()
            );

            if db_path.exists() {
                let meta = fs::metadata(&db_path)?;
                let size = ByteSize::b(meta.len());
                let mtime: DateTime<Local> = meta.modified()?.into();
                println!(
                    "  {:10} {} {}",
                    style("Indexed").dim(),
                    style("✔").green().bold(),
                    style(mtime.format("%Y-%m-%d %H:%M:%S")).dim()
                );
                println!("  {:10} {}", style("Size").dim(), size);
            } else {
                println!(
                    "  {:10} {} {}",
                    style("Indexed").dim(),
                    style("✖").red().bold(),
                    style("(run `nyx index build` to create)").dim()
                );
            }

            exit(0);
        }
    }
}

pub fn build_index(
    project_name: &str,
    project_path: &std::path::Path,
    db_path: &std::path::Path,
    config: &Config,
    show_progress: bool,
) -> NyxResult<()> {
    build_index_with_observer(
        project_name,
        project_path,
        db_path,
        config,
        show_progress,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_index_with_observer(
    project_name: &str,
    project_path: &std::path::Path,
    db_path: &std::path::Path,
    config: &Config,
    show_progress: bool,
    progress: Option<&Arc<ScanProgress>>,
    metrics: Option<&Arc<ScanMetrics>>,
    logs: Option<&Arc<ScanLogCollector>>,
) -> NyxResult<()> {
    // Pass 1 of the indexed scan reads persisted summaries produced here, so
    // framework context must be populated at index-build time, otherwise
    // framework-conditional label rules never contribute to the summaries
    // and indexed scans diverge from non-indexed ones.  Matches the
    // auto-fill in scan_filesystem_with_observer /
    // scan_with_index_parallel_observer.
    let owned_cfg = crate::commands::scan::ensure_framework_ctx(project_path, config);
    let config = owned_cfg.as_ref().unwrap_or(config);

    tracing::debug!("Building index for: {}", project_name);
    let pool = Indexer::init(db_path)?;
    {
        let idx = Indexer::from_pool(project_name, &pool)?;
        idx.clear()?;
    }

    tracing::debug!("Cleaned index for: {}", project_name);

    if let Some(p) = progress {
        p.set_stage(ScanStage::Discovering);
    }
    if let Some(l) = logs {
        l.info(
            format!("Rebuilding index for {}", project_path.display()),
            None,
        );
    }

    let walk_start = std::time::Instant::now();
    let (rx, handle) = spawn_file_walker(project_path, config);
    // Drain the channel BEFORE joining, the bounded channel will deadlock
    // if we join first and the walker blocks on send.
    let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
        if let Some(l) = logs {
            l.error(
                "Walker thread panicked during index rebuild",
                None,
                Some(format!("{err:#?}")),
            );
        }
    }
    if let Some(p) = progress {
        p.record_walk_ms(walk_start.elapsed().as_millis() as u64);
        p.set_files_discovered(paths.len() as u64);
        p.set_stage(ScanStage::Indexing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Index rebuild discovered {} files in {}ms",
                paths.len(),
                walk_start.elapsed().as_millis()
            ),
            None,
        );
    }

    let pb = if show_progress {
        let pb = ProgressBar::new(paths.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{bar:30.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        pb.set_message("Indexing files");
        pb
    } else {
        ProgressBar::hidden()
    };

    let progress = progress.cloned();
    let metrics = metrics.cloned();
    let logs = logs.cloned();
    let pass1_start = std::time::Instant::now();
    let writer = IndexWriteQueue::start(project_name.to_owned(), Arc::clone(&pool));
    let write_tx = writer.sender();
    let index_result = paths.into_par_iter().try_for_each(|path| -> NyxResult<()> {
        // Read once, hash once, pass bytes to both rule execution and
        // summary extraction.  Use pre-computed hash for upsert to avoid
        // a redundant file read inside upsert_file.
        let bytes = std::fs::read(&path)?;
        let hash = Indexer::digest_bytes(&bytes);

        // Parse once and persist every artifact we can reuse later:
        // findings, coarse summaries, and precise SSA summaries.
        let fused = crate::commands::scan::analyse_file_fused(
            &bytes,
            &path,
            config,
            None,
            Some(project_path),
        )?;
        if let Some(ref p) = progress {
            p.inc_parsed(1);
            p.set_current_file(&path.to_string_lossy());
            if let Some(lang) = fused.summaries.first().map(|s| s.lang.as_str()) {
                p.record_language(lang);
            }
        }
        if let Some(ref m) = metrics {
            m.cfg_nodes.fetch_add(fused.cfg_nodes as u64, Relaxed);
        }

        let issue_rows: Vec<(String, String, i64, i64)> = fused
            .diags
            .iter()
            .map(|d| {
                (
                    d.id.clone(),
                    d.severity.as_db_str().to_string(),
                    d.line as i64,
                    d.col as i64,
                )
            })
            .collect();

        let summaries = fused.summaries;
        let ssa_rows: Vec<_> = fused
            .ssa_summaries
            .into_iter()
            .map(|(key, sum)| {
                (
                    key.name,
                    key.arity.unwrap_or(0),
                    key.lang.as_str().to_string(),
                    key.namespace,
                    key.container,
                    key.disambig,
                    key.kind,
                    sum,
                )
            })
            .collect();

        // Persist SSA callee bodies at index-build time so CLI-initiated
        // rebuilds (`--index rebuild`) populate the same
        // `ssa_function_bodies` rows that `scan_with_index_parallel`
        // would have written via its pass-1 branch.  Without this,
        // indexed scans load zero cross-file bodies and cross-file
        // inline silently falls back to summary resolution.
        let body_rows: Vec<_> = fused
            .ssa_bodies
            .into_iter()
            .map(|(key, body)| {
                (
                    key.name,
                    key.arity.unwrap_or(0),
                    key.lang.as_str().to_string(),
                    key.namespace,
                    key.container,
                    key.disambig,
                    key.kind,
                    body,
                )
            })
            .collect();

        let path_for_write = path.clone();
        write_tx.enqueue(move |idx| {
            let file_id = idx.upsert_file_with_hash(&path_for_write, &hash)?;
            idx.replace_issues(
                file_id,
                issue_rows
                    .iter()
                    .map(|(rule_id, severity, line, col)| IssueRow {
                        rule_id: rule_id.as_str(),
                        severity: severity.as_str(),
                        line: *line,
                        col: *col,
                    }),
            )?;

            if !summaries.is_empty() {
                idx.replace_summaries_for_file(&path_for_write, &hash, &summaries)?;
            }
            if !ssa_rows.is_empty() {
                idx.replace_ssa_summaries_for_file(&path_for_write, &hash, &ssa_rows)?;
            }
            if !body_rows.is_empty() {
                idx.replace_ssa_bodies_for_file(&path_for_write, &hash, &body_rows)?;
            }
            Ok(())
        })?;

        pb.inc(1);
        Ok(())
    });
    drop(write_tx);
    let writer_result = writer.finish("Index rebuild");
    index_result?;
    writer_result?;
    pb.finish_and_clear();
    if let Some(p) = &progress {
        p.record_pass1_ms(pass1_start.elapsed().as_millis() as u64);
    }
    if let Some(l) = &logs {
        l.info(
            format!(
                "Index rebuild complete in {}ms",
                pass1_start.elapsed().as_millis()
            ),
            None,
        );
    }

    {
        let idx = Indexer::from_pool(project_name, &pool)?;
        idx.vacuum()?;
    }

    Ok(())
}

#[test]
fn build_index_creates_db_and_registers_files() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    fs::create_dir(&project_dir).unwrap();
    let f_txt = project_dir.join("readme.txt");
    fs::write(&f_txt, "hello").unwrap();

    let db_path = td.path().join("proj.sqlite");

    build_index("proj", &project_dir, &db_path, &cfg, false).expect("index build should succeed");

    // ── Assert ────────────────────────────────────────────────────────────────
    assert!(db_path.is_file(), "SQLite file must exist");

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool("proj", &pool).unwrap();
    let files = idx.get_files("proj").unwrap();
    assert_eq!(files.len(), 1, "exactly one file indexed");
    assert_eq!(files[0], f_txt);
}

#[test]
fn build_index_persists_ssa_summaries() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    fs::create_dir(&project_dir).unwrap();
    fs::write(
        project_dir.join("app.js"),
        r#"var express = require('express');
var app = express();

function cleanHtml(input) {
    return DOMPurify.sanitize(input);
}

app.get('/safe', function(req, res) {
    var name = req.query.name;
    var safe = cleanHtml(name);
    res.send(safe);
});
"#,
    )
    .unwrap();

    let db_path = td.path().join("proj.sqlite");
    build_index("proj", &project_dir, &db_path, &cfg, false).expect("index build should succeed");

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool("proj", &pool).unwrap();
    let ssa = idx.load_all_ssa_summaries().unwrap();
    assert!(
        !ssa.is_empty(),
        "index build should persist SSA summaries for functions with non-trivial SSA effects"
    );
}

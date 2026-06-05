use crate::commands::scan::{self, Diag};
use crate::database::index::{Indexer, ScanRecord};
use crate::server::app::ServerEvent;
use crate::server::progress::{ScanMetrics, ScanProgress, TimingBreakdown};
use crate::server::scan_log::ScanLogCollector;
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Build a dedicated rayon thread pool for server-initiated scans.
/// Reserves at least 2 cores for the tokio HTTP server so the UI stays
/// responsive while a scan is running.
fn build_scan_pool(stack_size: usize) -> rayon::ThreadPool {
    let total = num_cpus::get();
    let scan_threads = total.saturating_sub(2).max(1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(scan_threads)
        .stack_size(stack_size)
        .thread_name(|i| format!("nyx-scan-{i}"))
        .build()
        .expect("failed to build scan thread pool")
}

/// Status of a scan job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

/// A single scan job with its state and results.
#[derive(Debug, Clone)]
pub struct ScanJob {
    pub id: String,
    pub status: JobStatus,
    pub scan_root: PathBuf,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_secs: Option<f64>,
    pub findings: Option<Arc<Vec<Diag>>>,
    pub error: Option<String>,
    pub progress: Option<Arc<ScanProgress>>,
    pub metrics: Option<Arc<ScanMetrics>>,
    pub log_collector: Option<Arc<ScanLogCollector>>,
    pub engine_version: Option<String>,
    pub languages: Option<Vec<String>>,
    pub files_scanned: Option<u64>,
    pub timing: Option<TimingBreakdown>,
}

/// Manages scan jobs with single-scan policy.
pub struct JobManager {
    jobs: Mutex<HashMap<String, ScanJob>>,
    /// Insertion-order tracking for listing.
    job_order: Mutex<Vec<String>>,
    active_job_id: Mutex<Option<String>>,
    max_jobs: usize,
    /// Dedicated rayon pool for scans, keeps the global pool (and tokio
    /// worker threads) free so the web UI stays responsive during a scan.
    scan_pool: rayon::ThreadPool,
}

impl std::fmt::Debug for JobManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobManager")
            .field("max_jobs", &self.max_jobs)
            .finish()
    }
}

impl JobManager {
    pub fn new(max_jobs: usize, rayon_stack_size: usize) -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            job_order: Mutex::new(Vec::new()),
            active_job_id: Mutex::new(None),
            max_jobs,
            scan_pool: build_scan_pool(rayon_stack_size),
        }
    }

    /// Start a new scan. Returns Err if a scan is already running.
    pub fn start_scan(
        self: &Arc<Self>,
        scan_root: PathBuf,
        mut config: Config,
        event_tx: broadcast::Sender<ServerEvent>,
        db_pool: Option<Arc<Pool<SqliteConnectionManager>>>,
        database_dir: PathBuf,
    ) -> Result<String, &'static str> {
        let mut active = self.active_job_id.lock().unwrap_or_else(|p| p.into_inner());
        if active.is_some() {
            return Err("A scan is already running");
        }

        let job_id = Uuid::new_v4().to_string();
        let progress = Arc::new(ScanProgress::new());
        let metrics = Arc::new(ScanMetrics::new());
        let log_collector = Arc::new(ScanLogCollector::default());
        #[cfg(feature = "dynamic")]
        if config.scanner.verify {
            progress.expect_dynamic_verification();
        }

        let engine_version = env!("CARGO_PKG_VERSION").to_string();

        let job = ScanJob {
            id: job_id.clone(),
            status: JobStatus::Running,
            scan_root: scan_root.clone(),
            started_at: Some(chrono::Utc::now()),
            finished_at: None,
            duration_secs: None,
            findings: None,
            error: None,
            progress: Some(Arc::clone(&progress)),
            metrics: Some(Arc::clone(&metrics)),
            log_collector: Some(Arc::clone(&log_collector)),
            engine_version: Some(engine_version.clone()),
            languages: None,
            files_scanned: None,
            timing: None,
        };

        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
            let mut order = self.job_order.lock().unwrap_or_else(|p| p.into_inner());

            // Evict oldest if at capacity.
            while order.len() >= self.max_jobs {
                if let Some(oldest_id) = order.first().cloned() {
                    // Don't evict the active job.
                    if Some(&oldest_id) == active.as_ref() {
                        break;
                    }
                    jobs.remove(&oldest_id);
                    order.remove(0);
                }
            }

            jobs.insert(job_id.clone(), job);
            order.push(job_id.clone());
        }

        *active = Some(job_id.clone());

        if config.framework_ctx.is_none() {
            config.framework_ctx = Some(crate::utils::detect_frameworks(&scan_root));
        }

        let _ = event_tx.send(ServerEvent::ScanStarted {
            job_id: job_id.clone(),
        });

        // Persist initial scan record to DB
        if let Some(ref pool) = db_pool
            && let Ok(idx) = Indexer::from_pool("_scans", pool)
        {
            let _ = idx.insert_scan(&ScanRecord {
                id: job_id.clone(),
                status: "running".to_string(),
                scan_root: scan_root.display().to_string(),
                started_at: Some(chrono::Utc::now().to_rfc3339()),
                finished_at: None,
                duration_secs: None,
                engine_version: Some(engine_version),
                languages: None,
                files_scanned: None,
                files_skipped: None,
                finding_count: None,
                findings_json: None,
                timing_json: None,
                error: None,
            });
        }

        // Spawn SSE progress emitter thread (polls every 500ms)
        let progress_for_sse = Arc::clone(&progress);
        let event_tx_sse = event_tx.clone();
        let jid_sse = job_id.clone();
        let progress_done = Arc::new(AtomicBool::new(false));
        let progress_done_sse = Arc::clone(&progress_done);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let snap = progress_for_sse.snapshot();
                let _ = event_tx_sse.send(ServerEvent::ScanProgress {
                    job_id: jid_sse.clone(),
                    stage: snap.stage,
                    files_discovered: snap.files_discovered,
                    files_parsed: snap.files_parsed,
                    files_analyzed: snap.files_analyzed,
                    files_skipped: snap.files_skipped,
                    batches_total: snap.batches_total,
                    batches_completed: snap.batches_completed,
                    dynamic_enabled: snap.dynamic_enabled,
                    dynamic_total: snap.dynamic_total,
                    dynamic_completed: snap.dynamic_completed,
                    current_file: snap.current_file,
                    elapsed_ms: snap.elapsed_ms,
                    timing: snap.timing,
                });
                if progress_done_sse.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        // Spawn the main scan thread. All rayon parallelism inside the
        // scan is routed through `scan_pool.install()` so it uses our
        // dedicated (CPU-limited) pool, keeping tokio worker threads free.
        let manager = Arc::clone(self);
        let jid = job_id.clone();
        std::thread::spawn(move || {
            // Apply per-scan engine options (e.g. `engine_profile` from the
            // start-scan request) to the process-wide runtime so every
            // rayon worker that calls `analysis_options::current()` sees
            // the resolved values.  The JobManager's `active_job_id` mutex
            // guarantees no other scan is concurrently reading these, so
            // `reinstall` is race-free here.
            crate::utils::analysis_options::reinstall(config.analysis.engine);
            let start = Instant::now();
            log_collector.info("Indexed scan started (rebuild enabled)", None);

            let result = manager
                .scan_pool
                .install(|| -> crate::errors::NyxResult<Vec<Diag>> {
                    let (project_name, db_path) = get_project_info(&scan_root, &database_dir)?;
                    crate::commands::index::build_index_with_observer(
                        &project_name,
                        &scan_root,
                        &db_path,
                        &config,
                        false,
                        Some(&progress),
                        Some(&metrics),
                        Some(&log_collector),
                    )?;
                    let pool = Indexer::init(&db_path)?;
                    let mut diags = scan::scan_with_index_parallel_observer(
                        &project_name,
                        pool,
                        &config,
                        false,
                        &scan_root,
                        Some(&progress),
                        Some(&metrics),
                        Some(&log_collector),
                        None,
                        None,
                    )?;
                    for diag in &mut diags {
                        diag.stable_hash = scan::compute_stable_hash(diag);
                    }
                    #[cfg(feature = "dynamic")]
                    {
                        let _verify_opts = scan::verify_findings_for_scan(
                            &mut diags,
                            &project_name,
                            &db_path,
                            &scan_root,
                            &config,
                            false,
                            true,
                            Some(&progress),
                        );
                    }
                    Ok(diags)
                });
            #[cfg(feature = "dynamic")]
            crate::dynamic::sandbox::cleanup_docker_containers();
            let elapsed = start.elapsed().as_secs_f64();
            if result.is_ok() {
                progress.finish_dynamic_verification();
            }
            progress_done.store(true, Ordering::Relaxed);

            // Collect snapshots and do expensive work (post-processing,
            // JSON serialization) BEFORE acquiring the jobs mutex.
            let progress_snap = progress.snapshot();
            let metrics_snap = metrics.snapshot();
            let logs = log_collector.drain();
            let languages: Vec<String> = progress_snap.languages.keys().cloned().collect();
            let files_scanned = progress_snap.files_discovered;
            let files_skipped = progress_snap.files_skipped;
            let timing = progress_snap.timing;
            let finished_at = chrono::Utc::now();

            // Prepare the final state outside the lock.
            let (status, diags, error_str) = match result {
                Ok(mut diags) => {
                    // Compute stable_hash for every finding (§M6.5 cross-commit identity).
                    // The CLI handler does this in commands/scan.rs::handle, but the
                    // server scan path bypasses handle, so do it here.
                    for d in &mut diags {
                        d.stable_hash = scan::compute_stable_hash(d);
                    }
                    if config.server.triage_sync
                        && let Some(ref pool) = db_pool
                    {
                        match crate::server::triage_sync::sync_from_file(pool, &diags, &scan_root) {
                            Some(applied) if applied > 0 => log_collector.info(
                                format!(
                                    "Imported {applied} triage decisions from .nyx/triage.json"
                                ),
                                None,
                            ),
                            _ => {}
                        }
                    }
                    let dynamic_summary = scan::DynamicVerificationSummary::from_diags(&diags);
                    if !dynamic_summary.is_empty() {
                        log_collector.info(
                            format!(
                                "Dynamic verification: {}",
                                scan::format_dynamic_verification_summary(&dynamic_summary)
                            ),
                            None,
                        );
                    }
                    log_collector.info(format!("Scan completed: {} findings", diags.len()), None);
                    (JobStatus::Completed, Some(Arc::new(diags)), None)
                }
                Err(e) => {
                    let err_str = e.to_string();
                    log_collector.error(&err_str, None, None);
                    (JobStatus::Failed, None, Some(err_str))
                }
            };

            let finding_count = diags.as_ref().map(|d| d.len());

            // Pre-serialize findings JSON outside the lock (can be large).
            let findings_json = diags
                .as_ref()
                .and_then(|f| serde_json::to_string(f.as_slice()).ok());
            let timing_json = serde_json::to_string(&timing).ok();
            let langs_json = serde_json::to_string(&languages).ok();

            // Brief lock: just update in-memory job state.
            {
                let mut jobs = manager.jobs.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(job) = jobs.get_mut(&jid) {
                    job.finished_at = Some(finished_at);
                    job.duration_secs = Some(elapsed);
                    job.languages = Some(languages);
                    job.files_scanned = Some(files_scanned);
                    job.timing = Some(timing);
                    job.status = status.clone();
                    job.findings = diags;
                    job.error = error_str.clone();
                }
            }

            // Clear active flag.
            {
                let mut active = manager
                    .active_job_id
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if active.as_deref() == Some(&jid) {
                    *active = None;
                }
            }

            // Broadcast event (no lock held).
            match status {
                JobStatus::Completed => {
                    let _ = event_tx.send(ServerEvent::ScanCompleted {
                        job_id: jid.clone(),
                    });
                }
                JobStatus::Failed => {
                    let _ = event_tx.send(ServerEvent::ScanFailed {
                        job_id: jid.clone(),
                        error: error_str.clone().unwrap_or_default(),
                    });
                }
                _ => {}
            }

            // Persist to DB (no lock held, can take time).
            if let Some(ref pool) = db_pool
                && let Ok(idx) = Indexer::from_pool("_scans", pool)
            {
                let finished_str = finished_at.to_rfc3339();
                let _ = idx.update_scan(
                    &jid,
                    if finding_count.is_some() {
                        "completed"
                    } else {
                        "failed"
                    },
                    Some(&finished_str),
                    Some(elapsed),
                    finding_count.map(|c| c as i64),
                    findings_json.as_deref(),
                    timing_json.as_deref(),
                    error_str.as_deref(),
                    Some(files_scanned as i64),
                    Some(files_skipped as i64),
                    langs_json.as_deref(),
                );
                let _ = idx.insert_scan_metrics(&jid, &metrics_snap);
                let final_logs = log_collector.drain();
                let all_logs: Vec<_> = logs.into_iter().chain(final_logs).collect();
                if !all_logs.is_empty() {
                    let _ = idx.insert_scan_logs(&jid, &all_logs);
                }
            }
        });

        Ok(job_id)
    }

    /// Get a specific job.
    pub fn get_job(&self, id: &str) -> Option<ScanJob> {
        self.jobs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned()
    }

    /// List all jobs, most recent first.
    pub fn list_jobs(&self) -> Vec<ScanJob> {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let order = self.job_order.lock().unwrap_or_else(|p| p.into_inner());
        order
            .iter()
            .rev()
            .filter_map(|id| jobs.get(id).cloned())
            .collect()
    }

    /// Get the currently active (running) job.
    pub fn active_job(&self) -> Option<ScanJob> {
        let active = self.active_job_id.lock().unwrap_or_else(|p| p.into_inner());
        active.as_ref().and_then(|id| {
            self.jobs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(id)
                .cloned()
        })
    }

    /// Get the latest completed job.
    pub fn get_latest_completed(&self) -> Option<ScanJob> {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let order = self.job_order.lock().unwrap_or_else(|p| p.into_inner());
        order
            .iter()
            .rev()
            .filter_map(|id| jobs.get(id))
            .find(|j| j.status == JobStatus::Completed)
            .cloned()
    }

    /// Remove a job from in-memory state. Rejects if the scan is currently running.
    pub fn remove_job(&self, id: &str) -> Result<(), &'static str> {
        let active = self.active_job_id.lock().unwrap_or_else(|p| p.into_inner());
        if active.as_deref() == Some(id) {
            return Err("Cannot delete a running scan");
        }
        drop(active);

        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if jobs.remove(id).is_none() {
            return Err("Scan not found");
        }
        let mut order = self.job_order.lock().unwrap_or_else(|p| p.into_inner());
        order.retain(|x| x != id);
        Ok(())
    }

    /// Return findings from the latest completed scan, or empty if none.
    pub fn latest_findings(&self) -> Vec<Diag> {
        self.get_latest_completed()
            .and_then(|j| j.findings)
            .map(|arc| arc.as_ref().clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_config() -> Config {
        Config::default()
    }

    fn wait_for_job(manager: &Arc<JobManager>, job_id: &str) -> ScanJob {
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Some(job) = manager.get_job(job_id)
                && job.status != JobStatus::Running
            {
                return job;
            }
        }
        panic!("job {job_id} did not finish in time");
    }

    fn wait_for_scan_metrics(
        idx: &Indexer,
        job_id: &str,
    ) -> crate::server::progress::ScanMetricsSnapshot {
        for _ in 0..100 {
            if let Some(metrics) = idx.get_scan_metrics(job_id).unwrap() {
                return metrics;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("scan metrics for {job_id} were not persisted in time");
    }

    fn wait_for_scan_record(idx: &Indexer, job_id: &str) -> ScanRecord {
        for _ in 0..100 {
            if let Some(record) = idx.get_scan(job_id).unwrap() {
                return record;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("scan record for {job_id} was not persisted in time");
    }

    #[test]
    fn single_scan_policy() {
        let manager = Arc::new(JobManager::new(10, 8 * 1024 * 1024));
        let (tx, _rx) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();

        let id = manager
            .start_scan(
                dir.path().to_path_buf(),
                test_config(),
                tx.clone(),
                None,
                dir.path().to_path_buf(),
            )
            .unwrap();
        assert!(!id.is_empty());

        // Second scan should fail while first is running.
        let result = manager.start_scan(
            dir.path().to_path_buf(),
            test_config(),
            tx,
            None,
            dir.path().to_path_buf(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn bounded_history() {
        let manager = Arc::new(JobManager::new(2, 8 * 1024 * 1024));
        let (tx, _rx) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();

        // Start scan and wait for it to finish.
        let id1 = manager
            .start_scan(
                dir.path().to_path_buf(),
                test_config(),
                tx.clone(),
                None,
                dir.path().to_path_buf(),
            )
            .unwrap();

        // Wait for scan to complete (it's scanning an empty dir so should be fast).
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Some(j) = manager.get_job(&id1)
                && j.status != JobStatus::Running
            {
                break;
            }
        }

        let id2 = manager
            .start_scan(
                dir.path().to_path_buf(),
                test_config(),
                tx.clone(),
                None,
                dir.path().to_path_buf(),
            )
            .unwrap();

        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Some(j) = manager.get_job(&id2)
                && j.status != JobStatus::Running
            {
                break;
            }
        }

        // Third scan should evict the oldest.
        let _id3 = manager
            .start_scan(
                dir.path().to_path_buf(),
                test_config(),
                tx,
                None,
                dir.path().to_path_buf(),
            )
            .unwrap();

        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if manager.active_job().is_none() {
                break;
            }
        }

        // First job should be evicted.
        assert!(manager.get_job(&id1).is_none());
    }

    #[test]
    fn start_scan_uses_indexed_rebuild_and_persists_scan_artifacts() {
        let manager = Arc::new(JobManager::new(4, 8 * 1024 * 1024));
        let (tx, _rx) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();
        let project_dir = dir.path().join("proj");
        fs::create_dir(&project_dir).unwrap();
        fs::write(
            project_dir.join("app.js"),
            r#"function cleanHtml(input) {
    return DOMPurify.sanitize(input);
}

function handleRequest(req, res) {
    const safe = cleanHtml(req.query.name);
    res.send(safe);
}

handleRequest({ query: { name: '<b>x</b>' } }, { send() {} });
"#,
        )
        .unwrap();

        let (_, db_path) =
            crate::utils::project::get_project_info(&project_dir, dir.path()).unwrap();
        let pool = Indexer::init(&db_path).unwrap();

        let id = manager
            .start_scan(
                project_dir,
                test_config(),
                tx,
                Some(Arc::clone(&pool)),
                dir.path().to_path_buf(),
            )
            .unwrap();

        let job = wait_for_job(&manager, &id);
        assert_eq!(job.status, JobStatus::Completed);

        let idx = Indexer::from_pool("proj", &pool).unwrap();
        assert!(
            !idx.load_all_summaries().unwrap().is_empty(),
            "server scan should persist coarse summaries"
        );
        assert!(
            !idx.load_all_ssa_summaries().unwrap().is_empty(),
            "server scan should persist SSA summaries"
        );

        let scans_idx = Indexer::from_pool("_scans", &pool).unwrap();
        let metrics = wait_for_scan_metrics(&scans_idx, &id);
        assert!(
            metrics.summaries_reused >= 1,
            "rebuild-index server scan should reuse persisted summaries in indexed pass 1"
        );

        let mut logs = Vec::new();
        for _ in 0..100 {
            logs = scans_idx.get_scan_logs(&id, None).unwrap();
            if !logs.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(
            logs.iter()
                .any(|entry| entry.message.contains("Indexed scan started")),
            "server scan should persist indexed-path logs"
        );

        let record = wait_for_scan_record(&scans_idx, &id);
        assert_eq!(record.files_scanned, Some(1));
        assert!(
            record.files_skipped.unwrap_or_default() >= 1,
            "scan record should capture indexed summary reuse"
        );
    }
}

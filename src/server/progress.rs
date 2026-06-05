use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScanStage {
    Queued = 0,
    Discovering = 1,
    Indexing = 2,
    LoadingSummaries = 3,
    BuildingCallGraph = 4,
    Analyzing = 5,
    PostProcessing = 6,
    DynamicVerification = 7,
    Complete = 8,
}

impl ScanStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Discovering => "discovering",
            Self::Indexing => "indexing",
            Self::LoadingSummaries => "loading_summaries",
            Self::BuildingCallGraph => "building_call_graph",
            Self::Analyzing => "analyzing",
            Self::PostProcessing => "post_processing",
            Self::DynamicVerification => "dynamic_verification",
            Self::Complete => "complete",
        }
    }
}

/// Lock-free progress reporting from rayon workers during a scan.
#[derive(Debug)]
pub struct ScanProgress {
    /// See [`ScanStage`].
    stage: AtomicU8,
    files_discovered: AtomicU64,
    files_parsed: AtomicU64,
    files_analyzed: AtomicU64,
    files_skipped: AtomicU64,
    batches_total: AtomicU64,
    batches_completed: AtomicU64,
    dynamic_expected: AtomicBool,
    dynamic_finished: AtomicBool,
    dynamic_total: AtomicU64,
    dynamic_completed: AtomicU64,
    current_file: Mutex<String>,
    started_at: Instant,
    walk_ms: AtomicU64,
    pass1_ms: AtomicU64,
    call_graph_ms: AtomicU64,
    pass2_ms: AtomicU64,
    post_process_ms: AtomicU64,
    dynamic_verify_ms: AtomicU64,
    languages: Mutex<HashMap<String, u64>>,
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            stage: AtomicU8::new(ScanStage::Queued as u8),
            files_discovered: AtomicU64::new(0),
            files_parsed: AtomicU64::new(0),
            files_analyzed: AtomicU64::new(0),
            files_skipped: AtomicU64::new(0),
            batches_total: AtomicU64::new(0),
            batches_completed: AtomicU64::new(0),
            dynamic_expected: AtomicBool::new(false),
            dynamic_finished: AtomicBool::new(false),
            dynamic_total: AtomicU64::new(0),
            dynamic_completed: AtomicU64::new(0),
            current_file: Mutex::new(String::new()),
            started_at: Instant::now(),
            walk_ms: AtomicU64::new(0),
            pass1_ms: AtomicU64::new(0),
            call_graph_ms: AtomicU64::new(0),
            pass2_ms: AtomicU64::new(0),
            post_process_ms: AtomicU64::new(0),
            dynamic_verify_ms: AtomicU64::new(0),
            languages: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_stage(&self, stage: ScanStage) {
        let stage = if stage == ScanStage::Complete
            && self.dynamic_expected.load(Relaxed)
            && !self.dynamic_finished.load(Relaxed)
        {
            ScanStage::PostProcessing
        } else {
            stage
        };
        self.stage.store(stage as u8, Relaxed);
    }

    pub fn expect_dynamic_verification(&self) {
        self.dynamic_expected.store(true, Relaxed);
        self.dynamic_finished.store(false, Relaxed);
        self.dynamic_total.store(0, Relaxed);
        self.dynamic_completed.store(0, Relaxed);
    }

    pub fn start_dynamic_verification(&self, total: u64) {
        self.dynamic_expected.store(true, Relaxed);
        self.dynamic_finished.store(false, Relaxed);
        self.dynamic_total.store(total, Relaxed);
        self.dynamic_completed.store(0, Relaxed);
        self.stage
            .store(ScanStage::DynamicVerification as u8, Relaxed);
    }

    pub fn inc_dynamic_completed(&self, n: u64) {
        self.dynamic_completed.fetch_add(n, Relaxed);
    }

    pub fn finish_dynamic_verification(&self) {
        self.dynamic_finished.store(true, Relaxed);
        let total = self.dynamic_total.load(Relaxed);
        if total > 0 {
            self.dynamic_completed.store(total, Relaxed);
        }
        self.stage.store(ScanStage::Complete as u8, Relaxed);
    }

    pub fn set_files_discovered(&self, count: u64) {
        self.files_discovered.store(count, Relaxed);
    }

    pub fn inc_parsed(&self, n: u64) {
        self.files_parsed.fetch_add(n, Relaxed);
    }

    pub fn inc_analyzed(&self, n: u64) {
        self.files_analyzed.fetch_add(n, Relaxed);
    }

    pub fn set_files_skipped(&self, count: u64) {
        self.files_skipped.store(count, Relaxed);
    }

    pub fn inc_skipped(&self, n: u64) {
        self.files_skipped.fetch_add(n, Relaxed);
    }

    pub fn set_batches_total(&self, count: u64) {
        self.batches_total.store(count, Relaxed);
    }

    pub fn inc_batches_completed(&self, n: u64) {
        self.batches_completed.fetch_add(n, Relaxed);
    }

    pub fn set_current_file(&self, path: &str) {
        if let Ok(mut f) = self.current_file.try_lock() {
            f.clear();
            f.push_str(path);
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    pub fn record_walk_ms(&self, ms: u64) {
        self.walk_ms.fetch_add(ms, Relaxed);
    }

    pub fn record_pass1_ms(&self, ms: u64) {
        self.pass1_ms.fetch_add(ms, Relaxed);
    }

    pub fn record_call_graph_ms(&self, ms: u64) {
        self.call_graph_ms.fetch_add(ms, Relaxed);
    }

    pub fn record_pass2_ms(&self, ms: u64) {
        self.pass2_ms.fetch_add(ms, Relaxed);
    }

    pub fn record_post_process_ms(&self, ms: u64) {
        self.post_process_ms.fetch_add(ms, Relaxed);
    }

    pub fn record_dynamic_verify_ms(&self, ms: u64) {
        self.dynamic_verify_ms.fetch_add(ms, Relaxed);
    }

    pub fn record_language(&self, lang: &str) {
        if let Ok(mut langs) = self.languages.try_lock() {
            *langs.entry(lang.to_string()).or_insert(0) += 1;
        }
    }

    pub fn snapshot(&self) -> ScanProgressSnapshot {
        let stage = match self.stage.load(Relaxed) {
            x if x == ScanStage::Queued as u8 => ScanStage::Queued.as_str(),
            x if x == ScanStage::Discovering as u8 => ScanStage::Discovering.as_str(),
            x if x == ScanStage::Indexing as u8 => ScanStage::Indexing.as_str(),
            x if x == ScanStage::LoadingSummaries as u8 => ScanStage::LoadingSummaries.as_str(),
            x if x == ScanStage::BuildingCallGraph as u8 => ScanStage::BuildingCallGraph.as_str(),
            x if x == ScanStage::Analyzing as u8 => ScanStage::Analyzing.as_str(),
            x if x == ScanStage::PostProcessing as u8 => ScanStage::PostProcessing.as_str(),
            x if x == ScanStage::DynamicVerification as u8 => {
                ScanStage::DynamicVerification.as_str()
            }
            x if x == ScanStage::Complete as u8 => ScanStage::Complete.as_str(),
            _ => "unknown",
        }
        .to_string();

        let current_file = self
            .current_file
            .try_lock()
            .map(|f| f.clone())
            .unwrap_or_default();

        let languages = self
            .languages
            .try_lock()
            .map(|l| l.clone())
            .unwrap_or_default();

        ScanProgressSnapshot {
            stage,
            files_discovered: self.files_discovered.load(Relaxed),
            files_parsed: self.files_parsed.load(Relaxed),
            files_analyzed: self.files_analyzed.load(Relaxed),
            files_skipped: self.files_skipped.load(Relaxed),
            batches_total: self.batches_total.load(Relaxed),
            batches_completed: self.batches_completed.load(Relaxed),
            dynamic_enabled: self.dynamic_expected.load(Relaxed),
            dynamic_total: self.dynamic_total.load(Relaxed),
            dynamic_completed: self.dynamic_completed.load(Relaxed),
            current_file,
            elapsed_ms: self.elapsed_ms(),
            timing: TimingBreakdown {
                walk_ms: self.walk_ms.load(Relaxed),
                pass1_ms: self.pass1_ms.load(Relaxed),
                call_graph_ms: self.call_graph_ms.load(Relaxed),
                pass2_ms: self.pass2_ms.load(Relaxed),
                post_process_ms: self.post_process_ms.load(Relaxed),
                dynamic_verify_ms: self.dynamic_verify_ms.load(Relaxed),
            },
            languages,
        }
    }
}

/// Serializable snapshot of scan progress.
#[derive(Debug, Clone, Serialize)]
pub struct ScanProgressSnapshot {
    pub stage: String,
    pub files_discovered: u64,
    pub files_parsed: u64,
    pub files_analyzed: u64,
    pub files_skipped: u64,
    pub batches_total: u64,
    pub batches_completed: u64,
    pub dynamic_enabled: bool,
    pub dynamic_total: u64,
    pub dynamic_completed: u64,
    pub current_file: String,
    pub elapsed_ms: u64,
    pub timing: TimingBreakdown,
    pub languages: HashMap<String, u64>,
}

/// Timing breakdown for each scan phase.
#[derive(Debug, Clone, Serialize, serde::Deserialize, Default)]
pub struct TimingBreakdown {
    pub walk_ms: u64,
    pub pass1_ms: u64,
    pub call_graph_ms: u64,
    pub pass2_ms: u64,
    pub post_process_ms: u64,
    #[serde(default)]
    pub dynamic_verify_ms: u64,
}

/// Engine-level metrics collected during a scan.
#[derive(Debug)]
pub struct ScanMetrics {
    pub cfg_nodes: AtomicU64,
    pub call_edges: AtomicU64,
    pub functions_analyzed: AtomicU64,
    pub summaries_reused: AtomicU64,
    pub unresolved_calls: AtomicU64,
}

impl Default for ScanMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanMetrics {
    pub fn new() -> Self {
        Self {
            cfg_nodes: AtomicU64::new(0),
            call_edges: AtomicU64::new(0),
            functions_analyzed: AtomicU64::new(0),
            summaries_reused: AtomicU64::new(0),
            unresolved_calls: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> ScanMetricsSnapshot {
        ScanMetricsSnapshot {
            cfg_nodes: self.cfg_nodes.load(Relaxed),
            call_edges: self.call_edges.load(Relaxed),
            functions_analyzed: self.functions_analyzed.load(Relaxed),
            summaries_reused: self.summaries_reused.load(Relaxed),
            unresolved_calls: self.unresolved_calls.load(Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_verification_defers_static_complete_stage() {
        let progress = ScanProgress::new();

        progress.expect_dynamic_verification();
        progress.set_stage(ScanStage::Complete);

        let static_done = progress.snapshot();
        assert_eq!(static_done.stage, "post_processing");
        assert!(static_done.dynamic_enabled);
        assert_eq!(static_done.dynamic_total, 0);
        assert_eq!(static_done.dynamic_completed, 0);

        progress.start_dynamic_verification(3);
        progress.inc_dynamic_completed(2);

        let verifying = progress.snapshot();
        assert_eq!(verifying.stage, "dynamic_verification");
        assert_eq!(verifying.dynamic_total, 3);
        assert_eq!(verifying.dynamic_completed, 2);

        progress.finish_dynamic_verification();

        let complete = progress.snapshot();
        assert_eq!(complete.stage, "complete");
        assert_eq!(complete.dynamic_completed, 3);
    }
}

/// Serializable snapshot of engine metrics.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanMetricsSnapshot {
    pub cfg_nodes: u64,
    pub call_edges: u64,
    pub functions_analyzed: u64,
    pub summaries_reused: u64,
    pub unresolved_calls: u64,
}

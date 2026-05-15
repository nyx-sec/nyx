#![allow(clippy::collapsible_if, clippy::type_complexity)]

pub(crate) use crate::ast::{
    analyse_file_fused, extract_all_summaries_from_bytes, run_rules_on_bytes, run_rules_on_file,
};
use crate::callgraph::{CallGraph, FileBatch};
use crate::cli::{IndexMode, OutputFormat};
use crate::database::index::{Indexer, IssueRow};
use crate::errors::NyxResult;
use crate::patterns::{FindingCategory, Severity, SeverityFilter};
use crate::server::progress::{ScanMetrics, ScanProgress, ScanStage};
use crate::server::scan_log::ScanLogCollector;
use crate::summary::{self, GlobalSummaries};
use crate::utils::config::Config;
use crate::utils::project::get_project_info;
use crate::walk::spawn_file_walker;
use console::style;
use dashmap::DashMap;
use indicatif::{ProgressBar, ProgressStyle};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn make_progress_bar(len: u64, msg: &str, show: bool) -> ProgressBar {
    if !show {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {msg} [{bar:30.cyan/blue}] {pos}/{len} ({eta})",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb.set_message(msg.to_string());
    pb
}

fn record_persist_error(errors: &Arc<Mutex<Vec<String>>>, message: String) {
    // Recover from a poisoned mutex rather than panicking: a panic in another
    // rayon worker must not brick the whole scan's error-reporting channel.
    let mut guard = errors.lock().unwrap_or_else(|p| p.into_inner());
    guard.push(message);
}

/// Run per-file analysis, optionally catching panics so the scan can
/// continue past a poisoned input.
///
/// When `enabled` is true, a panic inside `f` is caught, logged, and
/// converted into a `NyxError::Msg`; callers that already match on
/// `Err(_)` will gracefully skip the file.  When `enabled` is false,
/// the panic propagates unchanged, preserving the default behaviour
/// for users who want to catch engine bugs loudly.
///
/// `AssertUnwindSafe` is load-bearing: closures over `&Config` /
/// `&GlobalSummaries` are not automatically unwind-safe, and the
/// protection only needs to hold per-file (any unwind-poisoned local
/// state is discarded when the closure returns).
fn recover_or_propagate<T>(
    enabled: bool,
    path: &Path,
    logs: Option<&Arc<ScanLogCollector>>,
    f: impl FnOnce() -> NyxResult<T>,
) -> NyxResult<T> {
    if !enabled {
        return f();
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .copied()
                .map(str::to_owned)
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic>".to_string());
            tracing::warn!(
                path = %path.display(),
                panic = %msg,
                "analysis panicked; continuing"
            );
            if let Some(l) = logs {
                l.warn(
                    format!("Analysis panicked: {msg}"),
                    Some(path.display().to_string()),
                    Some(msg.clone()),
                );
            }
            Err(crate::errors::NyxError::Msg(format!(
                "analysis panicked: {msg}"
            )))
        }
    }
}

fn fail_if_persist_errors(stage: &str, errors: Arc<Mutex<Vec<String>>>) -> NyxResult<()> {
    let errors = errors.lock().unwrap_or_else(|p| p.into_inner());
    if errors.is_empty() {
        return Ok(());
    }

    let mut details = errors.iter().take(3).cloned().collect::<Vec<_>>();
    if errors.len() > 3 {
        details.push(format!("... and {} more", errors.len() - 3));
    }

    Err(crate::errors::NyxError::Msg(format!(
        "{stage} failed to persist scan state: {}",
        details.join("; ")
    )))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Diag {
    /// Project-relative path of the file containing the finding.
    pub path: String,
    /// 1-based line number of the sink location.
    pub line: usize,
    /// 0-based column offset of the sink location.
    pub col: usize,
    /// Finding severity (Critical / High / Medium / Low / Info).
    pub severity: Severity,
    /// Rule identifier, e.g. `taint-unsanitised-flow`, `cfg-auth-gap`,
    /// `rs.auth.missing_ownership_check`. Taint findings append a
    /// source-location suffix (`"taint-unsanitised-flow (source 12:3)"`)
    /// so sibling paths with the same sink have distinct IDs for
    /// deduplication; [`crate::evidence::Evidence::sink_caps`] disambiguates
    /// findings at the same `(path, line, col)` that reach different sinks.
    pub id: String,
    /// High-level finding category (Security, Reliability, Quality).
    pub category: FindingCategory,
    /// Whether the finding is guarded by a path validation predicate.
    /// Only set for taint findings; `false` for AST/CFG structural findings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_kind: Option<String>,
    /// Optional human-readable message with additional context (e.g. state analysis details).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Structured evidence labels (e.g. Source, Sink) for console display.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,
    /// Confidence level (Low / Medium / High).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<crate::evidence::Confidence>,
    /// Structured evidence (source/sink spans, state transitions, notes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<crate::evidence::Evidence>,
    /// Attack-surface ranking score (higher = more exploitable / important).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank_score: Option<f64>,
    /// Breakdown of how the ranking score was computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank_reason: Option<Vec<(String, String)>>,
    /// Whether this finding was suppressed by an inline `nyx:ignore` directive.
    #[serde(default, skip_serializing_if = "is_false")]
    pub suppressed: bool,
    /// Metadata about the suppression directive, if suppressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression: Option<crate::suppress::SuppressionMeta>,
    /// Rollup data when multiple occurrences are grouped into one finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollup: Option<RollupData>,
    /// Stable identifier for this finding.  Populated for taint findings
    /// so that sibling alternative paths can reference this finding by
    /// ID (see [`Self::alternative_finding_ids`]).  Empty string for
    /// non-taint findings (CFG structural, state-machine, etc.).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub finding_id: String,
    /// Stable IDs of sibling findings that share `(body, sink, source)`
    /// but represent distinct flows (different validation status or
    /// different intermediate variables).  Empty when the finding has
    /// no alternative paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternative_finding_ids: Vec<String>,
    /// Blake3 hash of `(rule_id, path, line, col, sink_caps)` truncated to
    /// 64 bits.  Stable across scans for the same sink location and rule.
    /// Always present (no feature gate); enables M6.5 baseline diffing.
    /// Zero until the post-pass in `scan::handle` computes it.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub stable_hash: u64,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[cfg(test)]
impl Default for Diag {
    fn default() -> Self {
        Self {
            path: String::new(),
            line: 0,
            col: 0,
            severity: crate::patterns::Severity::Low,
            id: String::new(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        }
    }
}

/// Blake3 of `(rule_id, path, line, col, sink_caps)`, truncated to 64 bits.
pub fn compute_stable_hash(diag: &Diag) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(diag.id.as_bytes());
    h.update(b"\0");
    h.update(diag.path.as_bytes());
    h.update(b"\0");
    h.update(&(diag.line as u64).to_le_bytes());
    h.update(&(diag.col as u64).to_le_bytes());
    let sink_caps = diag.evidence.as_ref().map_or(0u32, |e| e.sink_caps);
    h.update(&sink_caps.to_le_bytes());
    let out = h.finalize();
    let bytes = out.as_bytes();
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

/// Rollup data for grouped findings (e.g. 38 occurrences of `rs.quality.unwrap`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollupData {
    /// Total number of occurrences.
    pub count: usize,
    /// First N example locations (controlled by `rollup_examples`).
    pub occurrences: Vec<Location>,
}

/// A source location within a file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub line: usize,
    pub col: usize,
}

/// Statistics about findings suppressed by the prioritization pipeline.
pub struct SuppressionStats {
    pub quality_dropped: usize,
    pub low_budget_dropped: usize,
    pub max_results_dropped: usize,
    pub include_quality: bool,
    #[allow(dead_code)]
    pub show_all: bool,
    pub max_low: u32,
    pub max_low_per_file: u32,
    pub max_low_per_rule: u32,
}

impl SuppressionStats {
    pub fn total_suppressed(&self) -> usize {
        self.quality_dropped + self.low_budget_dropped + self.max_results_dropped
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Detect frameworks at `root` if `cfg.framework_ctx` is `None`, returning a
/// clone of `cfg` with the detection populated.
///
/// Returns `None` when the caller already populated `framework_ctx` (no work
/// needed).  Callers store the `Option<Config>` on the stack and rebind `cfg`
/// through `as_ref().unwrap_or(cfg)`, matching the pattern in
/// `scan_filesystem_with_observer`.
///
/// Framework detection drives framework-conditional label rules (e.g. actix /
/// axum / rocket handler-arg sources, Rails route helpers) and auth-analysis
/// extractors.  If any scan entry point forgets to populate it, the indexed
/// and non-indexed paths silently diverge, missing framework-specific
/// findings in whichever path skipped detection.  This helper exists so the
/// auto-fill stays consistent across `scan_filesystem_with_observer`,
/// `scan_with_index_parallel_observer`, and `build_index_with_observer`.
pub(crate) fn ensure_framework_ctx(root: &Path, cfg: &Config) -> Option<Config> {
    if cfg.framework_ctx.is_some() {
        return None;
    }
    let mut c = cfg.clone();
    c.framework_ctx = Some(crate::utils::detect_frameworks(root));
    Some(c)
}

/// Build a [`crate::resolve::ModuleGraph`] for `root` and stash it on a
/// clone of `cfg`. Returns `None` when the cfg already carries one or
/// when the build produced an empty graph.
///
/// Mirrors `ensure_framework_ctx`'s lifecycle: scan-path entry points
/// call this once between the file walk and pass 1, the graph is shared
/// across all per-file analysis via `Config::module_graph`. Building is
/// best-effort, errors during fs walk land as missing entries rather
/// than aborts.
pub(crate) fn ensure_module_graph(root: &Path, cfg: &Config) -> Option<Config> {
    if cfg.module_graph.is_some() {
        return None;
    }
    let graph = crate::resolve::build_module_graph(&[root.to_path_buf()]);
    let mut c = cfg.clone();
    c.module_graph = Some(std::sync::Arc::new(graph));
    Some(c)
}

/// Does `path` belong to a Preview-tier language (C or C++)?
///
/// Drives the one-time `preview-tier scan` banner in `handle()`.  Tracks
/// the extensions `lang_for_path` in `ast.rs` maps to the `"c"` and `"cpp"`
/// slugs, keep this aligned with that mapping.
pub(crate) fn is_preview_tier_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("c" | "cpp")
    )
}

/// Load every persisted `FuncSummary` for `project` from `db_path` and fold
/// them into a [`GlobalSummaries`]. Best-effort: any failure (pool init,
/// summary load) logs and returns `None`, leaving dynamic verification on
/// the no-summaries code path.
///
/// Called once at the top of the verify loop so per-finding spec derivation
/// hits an in-memory index, not SQLite. The index is wrapped in `Arc` so
/// `VerifyOptions` can be cloned cheaply if a caller threads it onto
/// multiple findings concurrently in the future.
#[cfg(feature = "dynamic")]
fn load_verify_summaries(
    project: &str,
    db_path: &Path,
    scan_root: &Path,
) -> Option<Arc<crate::summary::GlobalSummaries>> {
    let pool = match Indexer::init(db_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("verify: indexer init failed; summary-driven spec derivation off: {e}");
            return None;
        }
    };
    let idx = match Indexer::from_pool(project, &pool) {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!("verify: indexer open failed; summary-driven spec derivation off: {e}");
            return None;
        }
    };
    let all = match idx.load_all_summaries() {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("verify: load_all_summaries failed; spec derivation off: {e}");
            return None;
        }
    };
    let root_str = scan_root.to_string_lossy().into_owned();
    Some(Arc::new(crate::summary::merge_summaries(all, Some(&root_str))))
}

/// Build the whole-program [`crate::callgraph::CallGraph`] from a
/// preloaded [`crate::summary::GlobalSummaries`] so the verifier can
/// thread it into the callgraph-aware spec-derivation path
/// (`SpecDerivationStrategy::FromCallgraphEntry`).
///
/// Best-effort: callgraph construction itself never fails, but this
/// helper exists to keep the verify pipeline parallel with
/// [`load_verify_summaries`] and to absorb future failure modes (e.g.
/// interop-edge loading) behind a single optional return.
#[cfg(feature = "dynamic")]
fn load_verify_callgraph(
    summaries: &crate::summary::GlobalSummaries,
) -> Arc<crate::callgraph::CallGraph> {
    Arc::new(crate::callgraph::build_call_graph(summaries, &[]))
}

/// Entry point called by the CLI.
#[allow(clippy::too_many_arguments)]
pub fn handle(
    path: &str,
    index_mode: IndexMode,
    format: OutputFormat,
    severity_filter: Option<SeverityFilter>,
    fail_on: Option<Severity>,
    show_suppressed: bool,
    show_instances: Option<&str>,
    database_dir: &Path,
    config: &Config,
    baseline: Option<&Path>,
    baseline_write: Option<&Path>,
    gate: Option<&str>,
) -> NyxResult<()> {
    let scan_path = Path::new(path).canonicalize()?;
    let (project_name, db_path) = get_project_info(&scan_path, database_dir)?;

    // Detect frameworks from project manifests and enrich the config.
    let config = &{
        let mut cfg = config.clone();
        if cfg.framework_ctx.is_none() {
            let fw = crate::utils::detect_frameworks(&scan_path);
            if !fw.frameworks.is_empty() {
                tracing::info!(frameworks = ?fw.frameworks, "detected frameworks");
            }
            cfg.framework_ctx = Some(fw);
        }
        cfg
    };

    let is_machine = format == OutputFormat::Json || format == OutputFormat::Sarif;
    let suppress_status = config.output.quiet || is_machine;
    if !suppress_status {
        // Status messages go to stderr so stdout stays clean
        eprintln!(
            "{} {}...\n",
            style("Checking").green().bold(),
            &project_name
        );
    }

    let show_progress = !is_machine && !config.output.quiet;

    // Preview-tier banner: driven by the walker output inside the scan
    // functions below.  Set to true if any C / C++ file is enumerated.
    let preview_tier_seen = Arc::new(AtomicBool::new(false));

    let (mut diags, surface_map): (Vec<Diag>, crate::surface::SurfaceMap) = if index_mode
        == IndexMode::Off
    {
        scan_filesystem_with_observer(
            &scan_path,
            config,
            show_progress,
            None,
            None,
            None,
            Some(&preview_tier_seen),
        )?
    } else {
        if index_mode == IndexMode::Rebuild || !db_path.exists() {
            tracing::debug!("Scanning filesystem index filesystem");
            crate::commands::index::build_index(
                &project_name,
                &scan_path,
                &db_path,
                config,
                show_progress,
            )?;
        }

        let pool = Indexer::init(&db_path)?;
        if config.database.vacuum_on_startup {
            let idx = Indexer::from_pool(&project_name, &pool)?;
            idx.vacuum()?;
        }
        // Indexed scan path: persist + return the SurfaceMap so the
        // Phase 25 chain composer can walk it.  `scan_with_index_parallel_observer`
        // already builds and persists the map into the `surface_map`
        // SQLite table; reload it through the same pool so the indexed
        // chain emission matches the non-indexed branch.
        let scan_pool = Arc::clone(&pool);
        let diags = scan_with_index_parallel_observer(
            &project_name,
            scan_pool,
            config,
            show_progress,
            &scan_path,
            None,
            None,
            None,
            Some(&preview_tier_seen),
        )?;
        let surface_map = {
            let idx = Indexer::from_pool(&project_name, &pool)?;
            idx.load_surface_map()?.unwrap_or_default()
        };
        (diags, surface_map)
    };

    // Print the Preview-tier banner to stderr once, after file enumeration
    // completes and before the console output.  Suppressed under --quiet and
    // for machine-readable output formats (JSON / SARIF) that must keep both
    // stdout and stderr clean of conversational text.
    if !suppress_status && preview_tier_seen.load(Ordering::Relaxed) {
        eprintln!(
            "{}: Nyx is in Preview for C/C++. Pointer aliasing, function pointers,",
            style("warning").yellow().bold()
        );
        eprintln!("array-element taint, and STL container flows are not modeled. Findings are");
        eprintln!("a starting point for review; pair with clang-tidy or Clang Static Analyzer");
        eprintln!("for production gates.\n");
    }

    tracing::debug!("Found {:?} issues (pre-filter).", diags.len());

    // ── Apply severity filter AFTER all downgrades/dedup ────────────────
    if let Some(ref filter) = severity_filter {
        diags.retain(|d| filter.matches(d.severity));
    }

    // ── Apply minimum-score filter AFTER ranking ─────────────────────
    if let Some(min) = config.output.min_score {
        let threshold = f64::from(min);
        diags.retain(|d| d.rank_score.unwrap_or(0.0) >= threshold);
    }

    // ── Apply minimum-confidence filter AFTER confidence assignment ──
    if let Some(min_conf) = config.output.min_confidence {
        diags.retain(|d| d.confidence.is_none_or(|c| c >= min_conf));
    }

    // ── Apply --require-converged filter ────────────────────────────
    if config.output.require_converged {
        retain_converged_findings(&mut diags);
    }

    // ── Apply inline suppressions ───────────────────────────────────
    apply_suppressions(&mut diags);
    if !show_suppressed {
        diags.retain(|d| !d.suppressed);
    }

    // ── Prioritization: category filter, rollup, LOW budgets ─────────
    let stats = prioritize(&mut diags, &config.output, show_instances);

    tracing::debug!("Emitting {:?} issues (post-filter).", diags.len());

    // ── Compute stable_hash for every surviving finding ──────────────────
    for diag in &mut diags {
        diag.stable_hash = compute_stable_hash(diag);
    }

    // ── Dynamic verification (feature-gated) ─────────────────────────────
    #[cfg(feature = "dynamic")]
    if config.scanner.verify {
        let mut opts = crate::dynamic::verify::VerifyOptions::from_config(config);
        // Enable the verdict cache (§12 Q5) when an index DB is in use.
        // When index_mode is Off, the DB is never created, so no cache.
        if index_mode != IndexMode::Off && db_path.exists() {
            opts.db_path = Some(db_path.clone());
            // Preload cross-file summaries once so the spec-derivation
            // pipeline can resolve the enclosing function's `FuncSummary`
            // (strategy 3) and its static `entry_kind` (strategy 4)
            // without re-hitting SQLite per finding. Best-effort: a load
            // failure logs and falls through to the substring heuristics.
            opts.summaries = load_verify_summaries(&project_name, &db_path, &scan_path);
            // Build the whole-program callgraph from the preloaded summaries
            // so strategy 4 can walk reverse edges to a route handler / CLI
            // entry when the sink lives in a leaf helper.
            if let Some(ref s) = opts.summaries {
                opts.callgraph = Some(load_verify_callgraph(s));
            }
        }
        for diag in &mut diags {
            let result = crate::dynamic::verify::verify_finding(diag, &opts);
            if let Some(ref mut ev) = diag.evidence {
                ev.dynamic_verdict = Some(result);
            }
        }
    }

    // ── Baseline write (§M6.5): persist current findings as stripped baseline
    if let Some(bw_path) = baseline_write {
        if let Err(e) = crate::baseline::write_baseline(bw_path, &diags) {
            tracing::warn!(path = %bw_path.display(), error = %e, "baseline-write failed");
            if !suppress_status {
                eprintln!("warning: --baseline-write failed: {e}");
            }
        } else if !suppress_status {
            eprintln!("Baseline written to {}", bw_path.display());
        }
    }

    // ── Baseline diff (§M6.5): load previous baseline and compute transitions
    let verdict_diff = if let Some(bl_path) = baseline {
        match crate::baseline::load_baseline(bl_path) {
            Ok(baseline_entries) => {
                let diff = crate::baseline::compute_verdict_diff(&baseline_entries, &diags);
                Some(diff)
            }
            Err(e) => {
                return Err(crate::errors::NyxError::Msg(format!(
                    "--baseline {}: {e}",
                    bl_path.display()
                )));
            }
        }
    } else {
        None
    };

    // ── Phase 25: compose exploit chains from findings + SurfaceMap ────
    let chain_edges = crate::chain::findings_to_edges(&diags, &surface_map);
    let chain_search_cfg = crate::chain::ChainSearchConfig {
        max_depth: config.chain.max_depth,
        min_score: config.chain.min_score,
    };
    let chains = crate::chain::find_chains(&chain_edges, &surface_map, chain_search_cfg);
    let diags_for_output = crate::output::filter_constituents(
        diags.clone(),
        &chains,
        config.output.show_chain_constituents,
    );

    // ── Output ──────────────────────────────────────────────────────────
    match format {
        OutputFormat::Json => {
            let diff_value = verdict_diff
                .as_ref()
                .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null));
            let out = crate::output::build_findings_json(
                &diags_for_output,
                &chains,
                diff_value.as_ref(),
            );
            let json = serde_json::to_string(&out)
                .map_err(|e| crate::errors::NyxError::Msg(e.to_string()))?;
            println!("{json}");
        }
        OutputFormat::Sarif => {
            let sarif = crate::output::build_sarif_with_chains(
                &diags_for_output,
                &chains,
                &scan_path,
            );
            let json = serde_json::to_string_pretty(&sarif)
                .map_err(|e| crate::errors::NyxError::Msg(e.to_string()))?;
            println!("{json}");
            // Emit diff on stderr for SARIF (stdout is owned by the SARIF schema).
            if let Some(ref diff) = verdict_diff {
                eprintln!("\nBaseline comparison:");
                eprint!("{}", crate::baseline::format_diff_console(diff));
            }
        }
        OutputFormat::Console => {
            tracing::debug!("Printing to console");
            print!(
                "{}",
                crate::fmt::render_console(
                    &diags_for_output,
                    &project_name,
                    Some(&stats),
                    &chains,
                )
            );
            if let Some(ref diff) = verdict_diff {
                println!("\nBaseline comparison:");
                print!("{}", crate::baseline::format_diff_console(diff));
            }
        }
    }

    // ── Convergence telemetry flush ─────────────────────────────────────
    // When `NYX_CONVERGENCE_TELEMETRY=1` is set the SCC and JS/TS pass-2
    // loops have been pushing per-iteration records into the
    // `convergence_telemetry` collector.  Flush them to a JSONL sidecar
    // so downstream analysis can compute P50/P95/P99 iteration counts.
    if crate::convergence_telemetry::is_enabled() {
        let path = crate::convergence_telemetry::default_path(&scan_path);
        match crate::convergence_telemetry::write_jsonl(&path) {
            Ok(n) if n > 0 => {
                tracing::info!(
                    records = n,
                    path = %path.display(),
                    "wrote convergence telemetry sidecar"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to write convergence telemetry sidecar"
                );
            }
        }
    }

    // ── --gate: CI gate check (exit 2 on violation) ─────────────────────
    if let (Some(diff), Some(gate_name)) = (&verdict_diff, gate) {
        if !crate::baseline::check_gate(diff, gate_name) {
            if !suppress_status {
                eprintln!(
                    "Gate '{}' violated. Exit code 2.",
                    gate_name
                );
            }
            std::process::exit(2);
        }
    }

    // ── --fail-on: exit non-zero if threshold breached ──────────────────
    // Suppressed findings do not count toward the threshold.
    if let Some(threshold) = fail_on {
        let breached = diags
            .iter()
            .any(|d| !d.suppressed && d.severity <= threshold);
        if breached {
            std::process::exit(1);
        }
    }

    Ok(())
}

// --------------------------------------------------------------------------------------------
// Shared post-processing helpers
// --------------------------------------------------------------------------------------------

/// Assign confidence, rank, and truncate diagnostics.
pub(crate) fn post_process_diags(diags: &mut Vec<Diag>, cfg: &Config) {
    // 0. Collapse duplicate taint-unsanitised-flow findings at the same
    //    primary location. Runs first so subsequent confidence / ranking
    //    sees a single representative per (sink, rule_base, severity).
    deduplicate_taint_flows(diags);

    // 1. Compute confidence first (needed by ranking).
    for d in diags.iter_mut() {
        if d.confidence.is_none() {
            d.confidence = Some(crate::evidence::compute_confidence(d));
        }
    }
    // 2. Rank (now has access to confidence).
    if cfg.output.attack_surface_ranking {
        crate::rank::rank_diags(diags);
    }
    if let Some(max) = cfg.output.max_results {
        diags.truncate(max as usize);
    }
}

/// Drop diagnostics whose engine provenance notes indicate the analysis
/// that emitted them was not fully converged in a way that affects this
/// specific finding's credibility.
///
/// A diagnostic is **removed** when its evidence carries any engine
/// note whose [`crate::engine_notes::LossDirection`] is `OverReport`
/// (widening lost validation predicates, so the finding is more likely
/// a false positive) or `Bail` (SSA lowering or parse aborted before
/// producing a trustworthy result).
///
/// A diagnostic is **kept** in all other cases:
///   * no evidence struct, or
///   * evidence with no engine notes, or
///   * only informational notes (e.g. `InlineCacheReused`), or
///   * `UnderReport` notes only (the emitted flow is still real; the
///     result set is just a lower bound).
///
/// Surfaced to users via `--require-converged` / the
/// `config.output.require_converged` setting.  Intended as a strict
/// CI gate where a finding from non-converged analysis is worse than
/// no finding at all.
pub fn retain_converged_findings(diags: &mut Vec<Diag>) {
    use crate::engine_notes::{LossDirection, worst_direction};
    diags.retain(|d| {
        d.evidence
            .as_ref()
            .and_then(|ev| worst_direction(&ev.engine_notes))
            .is_none_or(|dir| {
                matches!(
                    dir,
                    LossDirection::UnderReport | LossDirection::Informational
                )
            })
    });
}

/// Collapse `taint-unsanitised-flow` findings that share the same primary
/// sink line, rule base, severity, **and sink capability bits** into a
/// single finding by keeping the tightest source (closest to the sink in
/// the same function; tiebreak by source line asc, source col asc).
///
/// Rule IDs of the form `taint-unsanitised-flow (source L:C)` share a single
/// base `taint-unsanitised-flow`. The grouping key is column-agnostic ,
/// multiple flows to the same sink line differing only in column or source
/// are collapsed to one. The rule_id preserves the source location, so the
/// kept representative still identifies which flow was reported.
///
/// The grouping key **includes the resolved sink capability bits** so that
/// two different sinks on the same line (e.g. `sink_sql(x); sink_shell(x);`)
/// are not collapsed into one finding, they represent materially different
/// vulnerabilities and must surface independently. Findings with different
/// base rule IDs (e.g. `js.code_exec.eval`) or different severities are
/// left untouched per guardrails.
pub(crate) fn deduplicate_taint_flows(diags: &mut Vec<Diag>) {
    use std::collections::HashMap;

    const TAINT_BASE: &str = "taint-unsanitised-flow";

    fn is_taint_flow(id: &str) -> bool {
        id.starts_with(TAINT_BASE)
    }

    fn sink_cap_bits(d: &Diag) -> u32 {
        d.evidence.as_ref().map(|e| e.sink_caps).unwrap_or(0)
    }

    // Group candidates by (path, line, severity, sink_cap_bits). Only
    // `taint-unsanitised-flow` rule IDs participate; findings with other
    // bases (e.g. `js.code_exec.eval`) are left untouched per guardrails.
    let mut groups: HashMap<(String, usize, Severity, u32), Vec<usize>> = HashMap::new();
    for (i, d) in diags.iter().enumerate() {
        if is_taint_flow(&d.id) {
            groups
                .entry((d.path.clone(), d.line, d.severity, sink_cap_bits(d)))
                .or_default()
                .push(i);
        }
    }

    // Score each candidate finding. Lower score = tighter / preferred.
    // (same_function_flag, hop_count, source_distance, source_line, source_col)
    fn score(d: &Diag) -> (u32, u32, usize, u32, u32) {
        let ev = d.evidence.as_ref();
        let src = ev.and_then(|e| e.source.as_ref());
        let src_line = src.map(|s| s.line).unwrap_or(u32::MAX);
        let src_col = src.map(|s| s.col).unwrap_or(u32::MAX);
        // Same-function check: first flow_step (Source) and the step at the
        // sink share an `enclosing_func`. If flow_steps are absent or the
        // function markers are missing, treat as "unknown", worse than a
        // confirmed same-function match but better than a confirmed mismatch.
        let same_function_flag: u32 = ev
            .and_then(|e| {
                let steps = &e.flow_steps;
                if steps.is_empty() {
                    return None;
                }
                let first = &steps[0];
                let last = &steps[steps.len() - 1];
                match (first.function.as_ref(), last.function.as_ref()) {
                    (Some(a), Some(b)) => Some(if a == b { 0u32 } else { 2u32 }),
                    _ => Some(1u32),
                }
            })
            .unwrap_or(1u32);
        let sink_line = d.line as u32;
        let source_distance = if src_line == u32::MAX {
            usize::MAX
        } else {
            (sink_line as i64 - src_line as i64).unsigned_abs() as usize
        };
        let hop_count = ev
            .and_then(|e| e.hop_count)
            .map(|h| h as u32)
            .unwrap_or(u32::MAX);
        (
            same_function_flag,
            hop_count,
            source_distance,
            src_line,
            src_col,
        )
    }

    let mut drop: Vec<usize> = Vec::new();
    for indices in groups.values() {
        if indices.len() <= 1 {
            continue;
        }
        let mut scored: Vec<(usize, _)> = indices.iter().map(|&i| (i, score(&diags[i]))).collect();
        scored.sort_by_key(|a| a.1);
        // Keep scored[0], drop the rest.
        for &(i, _) in scored.iter().skip(1) {
            drop.push(i);
        }
    }

    if drop.is_empty() {
        return;
    }
    drop.sort_unstable();
    drop.dedup();
    // Remove in reverse order to preserve earlier indices.
    for &i in drop.iter().rev() {
        diags.remove(i);
    }
}

/// Build the call graph from global summaries and run SCC/topo analysis.
fn build_and_analyse_call_graph(
    global_summaries: &GlobalSummaries,
) -> (
    crate::callgraph::CallGraph,
    crate::callgraph::CallGraphAnalysis,
) {
    let _span = tracing::info_span!("build_call_graph").entered();
    let call_graph = crate::callgraph::build_call_graph(global_summaries, &[]);
    let cg_analysis = crate::callgraph::analyse(&call_graph);
    tracing::info!(
        nodes = call_graph.graph.node_count(),
        edges = call_graph.graph.edge_count(),
        unresolved_not_found = call_graph.unresolved_not_found.len(),
        unresolved_ambiguous = call_graph.unresolved_ambiguous.len(),
        sccs = cg_analysis.sccs.len(),
        "call graph built"
    );
    (call_graph, cg_analysis)
}

/// Log individual unresolved/ambiguous callees at debug level, deduplicated by callee name.
fn log_unresolved_callees(call_graph: &CallGraph) {
    use std::collections::HashSet;
    let mut seen_not_found: HashSet<&str> = HashSet::new();
    for u in &call_graph.unresolved_not_found {
        if seen_not_found.insert(&u.callee_name) {
            tracing::debug!(caller=%u.caller.name, callee=%u.callee_name, "unresolved callee: not found");
        }
    }
    let mut seen_ambiguous: HashSet<&str> = HashSet::new();
    for a in &call_graph.unresolved_ambiguous {
        if seen_ambiguous.insert(&a.callee_name) {
            tracing::debug!(caller=%a.caller.name, callee=%a.callee_name, candidates=a.candidates.len(), "unresolved callee: ambiguous");
        }
    }
}

/// Stable note prefix for SCC-cap-derived diagnostics. Consumers (UI,
/// downstream filters, tests) can match on this prefix to recognise
/// findings whose analysis was truncated at the safety cap.
pub const SCC_UNCONVERGED_NOTE_PREFIX: &str = "scc_unconverged:";

/// Finer-grained note prefix used when the unconverged SCC
/// spans more than one file.  This signals to reviewers that the
/// precision cost is specifically the cross-file summary/inline
/// convergence cliff and not a pathological intra-file recursion.
///
/// `SCC_UNCONVERGED_NOTE_PREFIX` is a strict prefix of this constant so
/// existing consumers that match the base prefix continue to see these
/// findings.  Tests and UIs that want to distinguish cross-file cases
/// can match on this tighter string.
pub const SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX: &str = "scc_unconverged:cross-file ";

/// Return the set of FuncKeys whose cap snapshot changed between two
/// [`GlobalSummaries::snapshot_caps`] results.
///
/// Used by the Phase-B worklist to derive the next iteration's dirty
/// file set.  Semantics match [`diff_cap_snapshots`], a key that
/// appears or disappears counts as changed.
fn changed_cap_keys_of(
    before: &HashMap<crate::symbol::FuncKey, (u32, u32, u32, Vec<usize>)>,
    after: &HashMap<crate::symbol::FuncKey, (u32, u32, u32, Vec<usize>)>,
) -> HashSet<crate::symbol::FuncKey> {
    let mut changed = HashSet::new();
    for (k, v_after) in after {
        match before.get(k) {
            Some(v_before) if v_before == v_after => {}
            _ => {
                changed.insert(k.clone());
            }
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            changed.insert(k.clone());
        }
    }
    changed
}

/// Return the set of FuncKeys whose SSA summary changed between two
/// snapshots.  Semantics match [`diff_ssa_snapshots`].
fn changed_ssa_keys_of(
    before: &HashMap<crate::symbol::FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    after: &HashMap<crate::symbol::FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
) -> HashSet<crate::symbol::FuncKey> {
    let mut changed = HashSet::new();
    for (k, v_after) in after {
        match before.get(k) {
            Some(v_before) if v_before == v_after => {}
            _ => {
                changed.insert(k.clone());
            }
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            changed.insert(k.clone());
        }
    }
    changed
}

/// Attach a low-confidence tag and a diagnostic note to every finding
/// produced by an SCC batch that did not converge within the safety cap.
///
/// Called once per unconverged batch (after the pass-2 rayon parallelism
/// has collected `iteration_diags`) so the cost is O(n) over the batch's
/// findings, much cheaper than a per-finding `warn!`.
///
/// Confidence is **capped** at `Low` rather than unconditionally set:
/// upstream analysis may have proven something particularly strong about
/// an individual finding (e.g. high-confidence AST match). Capping
/// preserves that attribution while still surfacing the degradation at
/// the batch level.
///
/// `cross_file = true` switches the note to the cross-file
/// variant so downstream consumers can distinguish the two reasons an
/// SCC might hit the cap.
///
/// `reason` carries the trajectory-based classification ([`CapHitReason`])
/// so operators can tell monotone-but-slow from plateau from suspected
/// oscillation.  See the [`crate::engine_notes::CapHitReason`]
/// documentation for the classification rules.
fn tag_unconverged_findings(
    diags: &mut [Diag],
    iterations: usize,
    cap: usize,
    cross_file: bool,
    reason: crate::engine_notes::CapHitReason,
) {
    use crate::engine_notes::{EngineNote, push_unique};
    use crate::evidence::{Confidence, Evidence};

    let engine_note = EngineNote::CrossFileFixpointCapped {
        iterations: iterations as u32,
        reason: reason.clone(),
    };
    let reason_tag = reason.tag();
    for d in diags.iter_mut() {
        d.confidence = match d.confidence {
            Some(c) if c < Confidence::Low => Some(c), // already-lower preserved
            _ => Some(Confidence::Low),
        };
        let note = if cross_file {
            format!(
                "{SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX}SCC did not converge within \
                 {iterations} iterations (cap {cap}, reason={reason_tag}); \
                 cross-file taint may be imprecise"
            )
        } else {
            format!(
                "{SCC_UNCONVERGED_NOTE_PREFIX}SCC did not converge within {iterations} \
                 iterations (cap {cap}, reason={reason_tag}); results may be imprecise"
            )
        };
        match d.evidence.as_mut() {
            Some(ev) => {
                if !ev.notes.iter().any(|n| n == &note) {
                    ev.notes.push(note);
                }
                push_unique(&mut ev.engine_notes, engine_note.clone());
            }
            None => {
                let mut ev = Evidence::default();
                ev.notes.push(note);
                push_unique(&mut ev.engine_notes, engine_note.clone());
                d.evidence = Some(ev);
            }
        }
    }
}

/// Safety cap on SCC fixed-point iterations.
///
/// The convergence predicate is *snapshot equality*, we break as soon as
/// an iteration leaves both `snapshot_caps()` and `snapshot_ssa()`
/// unchanged.  The cap only triggers if something prevents monotone
/// progress (e.g. a non-monotone SSA summary refinement or an SCC larger
/// than the cap length in the worst Jacobi propagation order).
///
/// Why 64 and not 3?
/// -----------------
/// Pass 2 runs Jacobi iteration: every file in the batch is analysed in
/// parallel against the *pre-iteration* `global_summaries`, and updates
/// are only visible to callers on the next iteration.  In a cross-file
/// SCC with `k` functions arranged in a chain, fresh taint introduced at
/// one end of the chain needs up to `k` iterations to reach the other
/// end.  A hard cap of 3 was silently truncating propagation for any
/// SCC of 4+ cross-file functions, findings vanished with no warning.
///
/// `FuncSummary` is a finite-height lattice (≤ 48 bits of caps + a
/// bounded vector of parameter indices) and `insert()` is strictly
/// monotone (OR on caps, union on param vectors).  `SsaFuncSummary` is
/// inserted with last-writer-wins semantics but its extraction is
/// input-monotone in practice (richer `global_summaries` produce
/// at-least-as-precise summaries).  Therefore the real fixed-point is
/// always reached in `O(|SCC| × 16)` iterations.  64 covers every
/// realistic cross-file SCC we have seen while still bounding worst-case
/// cost for pathological cases.
///
/// If the cap *is* hit we emit a `warn!` so the operator knows the
/// result is potentially imprecise rather than silently truncated.
const SCC_FIXPOINT_SAFETY_CAP: usize = 64;

/// Observability hook: records the maximum number of SCC fixed-point
/// iterations used by the most recent [`run_topo_batches`] invocation.
///
/// Reset to 0 at the start of each invocation.  Used by convergence
/// regression tests to prove that adversarial SCCs exercise more
/// iterations than the old bound of 3.  Cheap to read in production
/// (a single relaxed atomic load) so it is always on.
static LAST_SCC_MAX_ITERATIONS: AtomicUsize = AtomicUsize::new(0);

/// Returns the max SCC fixed-point iteration count observed during the
/// most recent two-pass scan.  Intended for tests and diagnostics.
pub fn last_scc_max_iterations() -> usize {
    LAST_SCC_MAX_ITERATIONS.load(Ordering::Relaxed)
}

/// Test-only override for [`SCC_FIXPOINT_SAFETY_CAP`].  When non-zero,
/// the SCC fix-point loop uses this value instead of the const cap.
///
/// Used by convergence tests to force a cap-hit on small fixtures
/// without constructing pathological SCCs that would actually need 64+
/// iterations.  Default 0 = no override; production behaviour unchanged.
static SCC_FIXPOINT_CAP_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Set (or clear) the test-only SCC fix-point cap override.  `cap = 0`
/// restores the default.  Intended exclusively for integration tests
/// that need to force cap-hit behaviour.
pub fn set_scc_fixpoint_cap_override(cap: usize) {
    SCC_FIXPOINT_CAP_OVERRIDE.store(cap, Ordering::Relaxed);
}

fn effective_scc_cap() -> usize {
    let o = SCC_FIXPOINT_CAP_OVERRIDE.load(Ordering::Relaxed);
    if o == 0 { SCC_FIXPOINT_SAFETY_CAP } else { o }
}

/// Observability hook: records the cumulative number of cross-batch
/// summary refinements (FuncSummary, SsaFuncSummary, body, auth)
/// persisted by non-recursive topo batches in the most recent
/// [`run_topo_batches`] invocation.  Intended for the regression tests
/// that prove the topo-refinement pipeline is wired and producing
/// observable cross-batch state, see
/// `tests/topo_pass2_refinement_tests.rs`.  Cheap relaxed load.
static LAST_TOPO_NONRECURSIVE_REFINEMENTS: AtomicUsize = AtomicUsize::new(0);

/// Returns the cumulative count of non-recursive batch refinements
/// (summary + ssa-summary + body + auth inserts) persisted to
/// `global_summaries` during the most recent `run_topo_batches` call.
/// Reset to zero at the start of each invocation.
pub fn last_topo_nonrecursive_refinements() -> usize {
    LAST_TOPO_NONRECURSIVE_REFINEMENTS.load(Ordering::Relaxed)
}

/// Returns `true` when topo-pass-2 cross-batch summary refinement is
/// enabled.  Default: enabled.  Set `NYX_TOPO_REFINE=0` (or `false`)
/// to fall back to the legacy non-recursive branch that runs
/// [`run_rules_on_file`] without persisting refined SSA / body / auth
/// artifacts to `global_summaries`.
fn topo_refine_enabled() -> bool {
    match std::env::var("NYX_TOPO_REFINE") {
        Ok(v) => !matches!(v.as_str(), "0" | "false" | "FALSE" | "False"),
        Err(_) => true,
    }
}

/// Run pass 2 analysis on a sequence of topo-ordered file batches.
///
/// For batches with mutual recursion, iterates until summaries converge
/// (bounded by [`SCC_FIXPOINT_SAFETY_CAP`]).  Updates `global_summaries`
/// between batches so later callers see refined callee context.
///
/// `call_graph` is required by the Phase-B worklist: after each
/// iteration we compute the set of FuncKeys whose summary changed,
/// fan out to their callers via the call graph, and only re-analyse
/// files that contain a caller of a changed key in the next iteration.
/// This reduces per-iteration cost from O(|batch.files|) to
/// O(|dirty_files|), which is typically a small fraction of the
/// batch for SCCs larger than 4–8 functions.
///
/// When `call_graph` is missing an edge (e.g. a summary was inserted
/// after graph construction), we conservatively fall back to
/// re-analysing the full batch, correctness is preserved at the cost
/// of the worklist optimisation for that iteration.
#[allow(clippy::too_many_arguments)]
fn run_topo_batches(
    batches: &[FileBatch<'_>],
    orphans: &[&PathBuf],
    global_summaries: &mut GlobalSummaries,
    call_graph: &CallGraph,
    cfg: &Config,
    scan_root: Option<&Path>,
    pb: &ProgressBar,
    progress: Option<&Arc<ScanProgress>>,
    logs: Option<&Arc<ScanLogCollector>>,
) -> Vec<Diag> {
    let root_str = scan_root.map(|r| r.to_string_lossy());
    let root_str_ref = root_str.as_deref();
    let mut result: Vec<Diag> = Vec::new();

    // Reset the observability counter for this invocation so tests and
    // diagnostics always see fresh data.
    LAST_SCC_MAX_ITERATIONS.store(0, Ordering::Relaxed);
    LAST_TOPO_NONRECURSIVE_REFINEMENTS.store(0, Ordering::Relaxed);

    let refine_nonrecursive = topo_refine_enabled();

    for (batch_idx, batch) in batches.iter().enumerate() {
        if batch.has_mutual_recursion {
            // SCC fixed-point: iterate until summaries converge (snapshot
            // equality) or we hit the safety cap.
            //
            // `batch.cross_file` distinguishes SCCs whose recursion
            // spans multiple files.  These require joint
            // summary + inline-cache convergence.  Today the per-file
            // inline cache is reconstructed fresh in `analyse_file` so
            // summary convergence implicitly implies inline convergence
            // (monotone summaries ⇒ deterministic inline results).  The
            // `cross_file` flag is threaded through so that cap-hit
            // diagnostics can report the more specific cause.
            let scc_cap = effective_scc_cap();
            let cross_file_scc = batch.cross_file;
            if cross_file_scc {
                tracing::debug!(
                    batch = batch_idx,
                    files = batch.files.len(),
                    "cross-file SCC fixed-point: iterating with joint \
                     summary + inline convergence"
                );
            }
            let mut converged = false;
            let mut iters_used: usize = 0;
            // Ring buffer of per-iteration change-set sizes, used to
            // classify the reason when the cap actually fires.  Bounded
            // at 4 entries so the memory overhead is negligible even
            // with a 64-iter budget; the classifier only needs the tail.
            let mut delta_trajectory: smallvec::SmallVec<[u32; 4]> = smallvec::SmallVec::new();

            // SCC fixpoint worklist: files to re-analyse in this iteration.
            // Initialised to the full batch so iteration 0 behaves like
            // the unconditional re-analysis; subsequent iterations prune
            // to files containing a caller of a changed summary.
            //
            // Storing `PathBuf` clones (matching how the rest of the
            // SCC loop identifies files) so membership tests are cheap
            // HashSet lookups.
            let mut dirty_files: HashSet<std::path::PathBuf> =
                batch.files.iter().map(|p| (*p).clone()).collect();

            // Per-file diag cache: retains the most-recent iteration's
            // diagnostics for each file.  When Phase-B skips a clean
            // file in iteration N, its diags from iteration N-1 are
            // still in this map, preserving final-iteration
            // completeness.
            let mut diags_by_file: HashMap<std::path::PathBuf, Vec<Diag>> = HashMap::new();

            for iter in 0..scc_cap {
                iters_used = iter + 1;
                let snap_before = global_summaries.snapshot_caps();

                let ssa_snap_before = global_summaries.snapshot_ssa().clone();

                // Phase-B: restrict this iteration's analysis to dirty
                // files only.  `batch.files` is the authoritative list
                // for ordering / membership; `dirty_files` filters.
                let iter_files: Vec<&PathBuf> = batch
                    .files
                    .iter()
                    .filter(|p| dirty_files.contains(**p))
                    .copied()
                    .collect();

                let batch_results: Vec<(
                    std::path::PathBuf,
                    Vec<Diag>,
                    Vec<crate::summary::FuncSummary>,
                    Vec<(
                        crate::symbol::FuncKey,
                        crate::summary::ssa_summary::SsaFuncSummary,
                    )>,
                    Vec<(
                        crate::symbol::FuncKey,
                        crate::taint::ssa_transfer::CalleeSsaBody,
                    )>,
                )> = iter_files
                    .par_iter()
                    .map(|path| {
                        if let Some(p) = progress {
                            p.set_current_file(&path.to_string_lossy());
                        }
                        let bytes = match std::fs::read(path) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(
                                    "pass 2 (SCC iter {}): cannot read {}: {e}",
                                    iter,
                                    path.display()
                                );
                                if let Some(l) = logs {
                                    l.warn(
                                        format!("Cannot read file for pass 2: {e}"),
                                        Some(path.display().to_string()),
                                        None,
                                    );
                                }
                                return (path.to_path_buf(), vec![], vec![], vec![], vec![]);
                            }
                        };
                        match recover_or_propagate(
                            cfg.scanner.enable_panic_recovery,
                            path,
                            logs,
                            || {
                                analyse_file_fused(
                                    &bytes,
                                    path,
                                    cfg,
                                    Some(global_summaries),
                                    scan_root,
                                )
                            },
                        ) {
                            Ok(r) => {
                                pb.inc(0); // don't double-count iterations in progress bar
                                (
                                    path.to_path_buf(),
                                    r.diags,
                                    r.summaries,
                                    r.ssa_summaries,
                                    r.ssa_bodies,
                                )
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "pass 2 (SCC iter {}): {}: {e}",
                                    iter,
                                    path.display()
                                );
                                if let Some(l) = logs {
                                    l.warn(
                                        format!("Pass 2 (SCC iter {iter}) analysis failed: {e}"),
                                        Some(path.display().to_string()),
                                        None,
                                    );
                                }
                                (path.to_path_buf(), vec![], vec![], vec![], vec![])
                            }
                        }
                    })
                    .collect();

                let mut ssa_count: usize = 0;
                let mg = cfg.module_graph.as_deref();
                for (path, diags, summaries, ssa_summaries, _ssa_bodies) in batch_results {
                    // Phase-B: replace (not append) this file's diags
                    // so the cache always reflects the latest
                    // iteration's output.  Clean files skipped this
                    // iteration retain their previous diags.
                    diags_by_file.insert(path, diags);

                    for s in summaries {
                        let key = s.func_key_with_resolver(root_str_ref, mg);
                        global_summaries.insert(key, s);
                    }

                    for (key, ssa_sum) in ssa_summaries {
                        global_summaries.insert_ssa(key, ssa_sum);
                        ssa_count += 1;
                    }
                }

                let snap_after = global_summaries.snapshot_caps();
                let ssa_converged = ssa_snap_before == *global_summaries.snapshot_ssa();
                let iter_converged = snap_before == snap_after && ssa_converged;

                // Phase-B: collect the exact set of FuncKeys whose
                // summary changed this iteration, and derive the next
                // iteration's dirty-file set from it.
                //
                // A file becomes dirty for iteration N+1 iff it
                // contains at least one caller of a FuncKey that
                // changed in iteration N.  If no key changed, the
                // dirty set is empty, which implies convergence (and
                // matches `iter_converged` above).
                let changed_cap_keys = changed_cap_keys_of(&snap_before, &snap_after);
                let changed_ssa_keys =
                    changed_ssa_keys_of(&ssa_snap_before, global_summaries.snapshot_ssa());
                let all_changed_keys: HashSet<crate::symbol::FuncKey> =
                    changed_cap_keys.union(&changed_ssa_keys).cloned().collect();
                let changed_caps_count = changed_cap_keys.len();
                let changed_ssa_count = changed_ssa_keys.len();
                let iter_delta = changed_caps_count + changed_ssa_count;
                if delta_trajectory.len() == 4 {
                    delta_trajectory.remove(0);
                }
                delta_trajectory.push(iter_delta as u32);

                // Recompute dirty_files for the next iteration: every
                // file in the batch that owns at least one caller of a
                // changed key.  Fall back to the full batch when the
                // call graph does not resolve any caller (e.g. all
                // changes happened in leaf functions that no one in
                // this batch calls, rare but must not regress to
                // missed analysis).
                let namespaces_needing_reanalysis =
                    crate::callgraph::namespaces_for_callers(call_graph, &all_changed_keys);
                let next_dirty: HashSet<std::path::PathBuf> = batch
                    .files
                    .iter()
                    .filter(|p| {
                        let abs = p.to_string_lossy();
                        let rel = crate::symbol::namespace_with_package(&abs, root_str_ref, mg);
                        namespaces_needing_reanalysis.contains(&rel)
                    })
                    .map(|p| (*p).clone())
                    .collect();
                dirty_files = next_dirty;

                tracing::debug!(
                    batch = batch_idx,
                    files = batch.files.len(),
                    recursive = true,
                    iteration = iter,
                    ssa_summaries_updated = ssa_count,
                    ssa_converged,
                    converged = iter_converged,
                    delta = iter_delta,
                    dirty_next = dirty_files.len(),
                    "SCC batch iteration"
                );
                // Phase-B strengthened fixpoint: converged iff no
                // summary changed (snapshot equality) *and* no
                // downstream caller remains to reprocess.  The latter
                // catches the rare case where snapshot equality holds
                // by coincidence but the call graph would still have
                // requested re-analysis.  In practice one implies the
                // other; asserting both is a defensive invariant.
                if iter_converged && dirty_files.is_empty() {
                    converged = true;
                    break;
                }
                if iter_converged {
                    // Snapshots equal but dirty_files non-empty is
                    // anomalous, log and treat as converged
                    // (snapshot equality is the correctness-preserving
                    // signal).
                    tracing::debug!(
                        batch = batch_idx,
                        dirty = dirty_files.len(),
                        "SCC converged by snapshot but dirty_files non-empty; \
                         call graph disagrees with summary diff, accepting \
                         snapshot as authoritative"
                    );
                    converged = true;
                    break;
                }
            }
            // After the loop, flatten per-file diags into the
            // iteration_diags vector in batch order for deterministic
            // output.  Files that were in the batch but never made
            // dirty (shouldn't happen, iter 0 runs all of them) are
            // skipped silently.
            let mut iteration_diags: Vec<Diag> = Vec::new();
            for p in &batch.files {
                if let Some(v) = diags_by_file.remove(*p) {
                    iteration_diags.extend(v);
                }
            }
            LAST_SCC_MAX_ITERATIONS.fetch_max(iters_used, Ordering::Relaxed);

            // Emit per-batch telemetry record (no-op unless
            // NYX_CONVERGENCE_TELEMETRY=1).  Recorded regardless of
            // converged / cap-hit so the downstream distribution
            // analysis sees early-convergence runs too.
            crate::convergence_telemetry::record(
                crate::convergence_telemetry::ConvergenceEvent::SccBatch(
                    crate::convergence_telemetry::SccBatchRecord {
                        schema: crate::convergence_telemetry::SCHEMA_VERSION,
                        batch_index: batch_idx,
                        file_count: batch.files.len(),
                        cross_file: cross_file_scc,
                        iterations: iters_used,
                        cap: scc_cap,
                        converged,
                        trajectory: delta_trajectory.clone(),
                    },
                ),
            );

            if !converged {
                let reason = crate::engine_notes::CapHitReason::classify(&delta_trajectory);
                tracing::warn!(
                    batch = batch_idx,
                    files = batch.files.len(),
                    iterations = iters_used,
                    cap = scc_cap,
                    cross_file = cross_file_scc,
                    reason = reason.tag(),
                    "SCC batch did not converge within safety cap, results \
                     may be imprecise. This usually indicates a very large \
                     mutually-recursive region or a non-monotone summary \
                     refinement; please file a bug with a reproducer."
                );
                if let Some(l) = logs {
                    l.warn(
                        format!(
                            "SCC batch {batch_idx} ({} files, cross_file={cross_file_scc}) \
                             did not converge within {scc_cap} iterations (reason={})",
                            batch.files.len(),
                            reason.tag()
                        ),
                        None,
                        None,
                    );
                }

                // Tag findings from an unconverged batch so operators know
                // the results are potentially imprecise. Cap confidence at
                // Low (overriding any higher pre-set) and append a note to
                // the evidence so downstream UIs / reviewers can surface
                // the degradation.  Cross-file SCCs get a
                // tighter note prefix so the precision cause is explicit.
                tag_unconverged_findings(
                    &mut iteration_diags,
                    iters_used,
                    scc_cap,
                    cross_file_scc,
                    reason,
                );
            }
            // Count progress for these files once.
            pb.inc(batch.files.len() as u64);
            if let Some(p) = progress {
                p.inc_analyzed(batch.files.len() as u64);
                p.inc_batches_completed(1);
            }
            result.extend(iteration_diags);
        } else if refine_nonrecursive {
            // Non-recursive batch with cross-batch refinement.
            //
            // Run `analyse_file_fused` so the batch produces refined
            // FuncSummary / SsaFuncSummary / CalleeSsaBody / AuthCheckSummary
            // artifacts on top of pass-1's output.  After the batch's
            // parallel section completes, persist those refinements into
            // `global_summaries` sequentially.  Subsequent batches in
            // topo order (caller-most batches) then resolve their call
            // sites against the refined cross-file context, the final
            // step in the callee-first topo pipeline that pass-2
            // sequencing was always meant to deliver.
            //
            // Opt out via `NYX_TOPO_REFINE=0` if a precision regression
            // surfaces; the legacy `run_rules_on_file` branch stays
            // available for triage.
            #[allow(clippy::type_complexity)]
            let batch_results: Vec<(
                std::path::PathBuf,
                Vec<Diag>,
                Vec<crate::summary::FuncSummary>,
                Vec<(
                    crate::symbol::FuncKey,
                    crate::summary::ssa_summary::SsaFuncSummary,
                )>,
                Vec<(
                    crate::symbol::FuncKey,
                    crate::taint::ssa_transfer::CalleeSsaBody,
                )>,
                Vec<(
                    crate::symbol::FuncKey,
                    crate::auth_analysis::model::AuthCheckSummary,
                )>,
            )> = batch
                .files
                .par_iter()
                .map(|path| {
                    if let Some(p) = progress {
                        p.set_current_file(&path.to_string_lossy());
                    }
                    let bytes = match std::fs::read(path) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                "pass 2 (non-recursive): cannot read {}: {e}",
                                path.display()
                            );
                            if let Some(l) = logs {
                                l.warn(
                                    format!("Cannot read file for pass 2: {e}"),
                                    Some(path.display().to_string()),
                                    None,
                                );
                            }
                            pb.inc(1);
                            if let Some(p) = progress {
                                p.inc_analyzed(1);
                            }
                            return (path.to_path_buf(), vec![], vec![], vec![], vec![], vec![]);
                        }
                    };
                    match recover_or_propagate(
                        cfg.scanner.enable_panic_recovery,
                        path,
                        logs,
                        || analyse_file_fused(&bytes, path, cfg, Some(global_summaries), scan_root),
                    ) {
                        Ok(r) => {
                            pb.inc(1);
                            if let Some(p) = progress {
                                p.inc_analyzed(1);
                            }
                            (
                                path.to_path_buf(),
                                r.diags,
                                r.summaries,
                                r.ssa_summaries,
                                r.ssa_bodies,
                                r.auth_summaries,
                            )
                        }
                        Err(e) => {
                            tracing::warn!("pass 2 (non-recursive): {}: {e}", path.display());
                            if let Some(l) = logs {
                                l.warn(
                                    format!("Pass 2 analysis failed: {e}"),
                                    Some(path.display().to_string()),
                                    None,
                                );
                            }
                            pb.inc(1);
                            if let Some(p) = progress {
                                p.inc_analyzed(1);
                            }
                            (path.to_path_buf(), vec![], vec![], vec![], vec![], vec![])
                        }
                    }
                })
                .collect();

            // Sequential persistence: union refined artifacts back into
            // `global_summaries` so caller-most batches see them.
            let mut batch_diags: Vec<Diag> = Vec::new();
            let mut refined_summaries: usize = 0;
            let mut refined_ssa: usize = 0;
            let mut refined_bodies: usize = 0;
            let mut refined_auth: usize = 0;
            let mg = cfg.module_graph.as_deref();
            for (_path, diags, summaries, ssa_summaries, ssa_bodies, auth_summaries) in
                batch_results
            {
                batch_diags.extend(diags);
                for s in summaries {
                    let key = s.func_key_with_resolver(root_str_ref, mg);
                    global_summaries.insert(key, s);
                    refined_summaries += 1;
                }
                for (key, ssa_sum) in ssa_summaries {
                    global_summaries.insert_ssa(key, ssa_sum);
                    refined_ssa += 1;
                }
                for (key, body) in ssa_bodies {
                    global_summaries.insert_body(key, body);
                    refined_bodies += 1;
                }
                for (key, auth_sum) in auth_summaries {
                    global_summaries.insert_auth(key, auth_sum);
                    refined_auth += 1;
                }
            }
            let total_refinements = refined_summaries + refined_ssa + refined_bodies + refined_auth;
            LAST_TOPO_NONRECURSIVE_REFINEMENTS.fetch_add(total_refinements, Ordering::Relaxed);

            tracing::debug!(
                batch = batch_idx,
                files = batch.files.len(),
                recursive = false,
                refined_summaries,
                refined_ssa,
                refined_bodies,
                refined_auth,
                "non-recursive batch complete (refinements persisted)"
            );
            if let Some(p) = progress {
                p.inc_batches_completed(1);
            }
            result.extend(batch_diags);
        } else {
            // Legacy non-recursive batch (NYX_TOPO_REFINE=0): single
            // pass that discards refined SSA / body / auth artifacts.
            let batch_diags: Vec<Diag> = batch
                .files
                .par_iter()
                .flat_map_iter(|path| {
                    if let Some(p) = progress {
                        p.set_current_file(&path.to_string_lossy());
                    }
                    let d = match recover_or_propagate(
                        cfg.scanner.enable_panic_recovery,
                        path,
                        logs,
                        || run_rules_on_file(path, cfg, Some(global_summaries), scan_root),
                    ) {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!("pass 2: {}: {e}", path.display());
                            if let Some(l) = logs {
                                l.warn(
                                    format!("Pass 2 analysis failed: {e}"),
                                    Some(path.display().to_string()),
                                    None,
                                );
                            }
                            vec![]
                        }
                    };
                    pb.inc(1);
                    if let Some(p) = progress {
                        p.inc_analyzed(1);
                    }
                    d
                })
                .collect();

            tracing::debug!(
                batch = batch_idx,
                files = batch.files.len(),
                recursive = false,
                "non-recursive batch complete (legacy, refinement disabled)"
            );
            if let Some(p) = progress {
                p.inc_batches_completed(1);
            }
            result.extend(batch_diags);
        }
    }

    // Orphan files (no functions in call graph), process last, single pass.
    if !orphans.is_empty() {
        let orphan_diags: Vec<Diag> = orphans
            .par_iter()
            .flat_map_iter(|path| {
                if let Some(p) = progress {
                    p.set_current_file(&path.to_string_lossy());
                }
                let d = match recover_or_propagate(
                    cfg.scanner.enable_panic_recovery,
                    path,
                    logs,
                    || run_rules_on_file(path, cfg, Some(global_summaries), scan_root),
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("pass 2: {}: {e}", path.display());
                        if let Some(l) = logs {
                            l.warn(
                                format!("Pass 2 analysis failed: {e}"),
                                Some(path.display().to_string()),
                                None,
                            );
                        }
                        vec![]
                    }
                };
                pb.inc(1);
                if let Some(p) = progress {
                    p.inc_analyzed(1);
                }
                d
            })
            .collect();
        if let Some(p) = progress {
            p.inc_batches_completed(1);
        }
        result.extend(orphan_diags);
    }

    result
}

// --------------------------------------------------------------------------------------------
// Two‑pass scanning (no index)
// --------------------------------------------------------------------------------------------

/// Walk the filesystem and perform a two‑pass scan:
///
///  **Pass 1** – Parse every file and extract function summaries.
///  **Pass 2** – Re‑parse every file and run taint analysis with the
///               merged cross‑file summaries.
///
/// AST pattern queries are run during pass 2 (they don't depend on summaries).
pub(crate) fn scan_filesystem(
    root: &Path,
    cfg: &Config,
    show_progress: bool,
) -> NyxResult<Vec<Diag>> {
    scan_filesystem_with_observer(root, cfg, show_progress, None, None, None, None)
        .map(|(diags, _surface_map)| diags)
}

/// Same as [`scan_filesystem`] but additionally returns the `SurfaceMap`
/// built from the post-pass-2 view.  The non-indexed path used to drop
/// the surface map on the floor; this entry-point lets `nyx surface` (and
/// other consumers that need the attack-surface model alongside the
/// findings) avoid running the analysis twice.
pub(crate) fn scan_filesystem_with_surface_map(
    root: &Path,
    cfg: &Config,
    show_progress: bool,
) -> NyxResult<(Vec<Diag>, crate::surface::SurfaceMap)> {
    scan_filesystem_with_observer(root, cfg, show_progress, None, None, None, None)
}

/// Walk the filesystem and perform a two-pass scan, optionally reporting
/// progress and metrics through the supplied atomic structs.
///
/// When `preview_tier_seen` is supplied, the observer sets it to `true` once
/// it encounters the first Preview-tier file (C / C++) in the walked set.
/// Used by the CLI to drive the one-time Preview-tier banner.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_filesystem_with_observer(
    root: &Path,
    cfg: &Config,
    show_progress: bool,
    progress: Option<&Arc<ScanProgress>>,
    metrics: Option<&Arc<ScanMetrics>>,
    logs: Option<&Arc<ScanLogCollector>>,
    preview_tier_seen: Option<&Arc<AtomicBool>>,
) -> NyxResult<(Vec<Diag>, crate::surface::SurfaceMap)> {
    // Ensure framework context is available (handle sets it, but direct
    // callers like scan_no_index may not).
    let owned_cfg = ensure_framework_ctx(root, cfg);
    let cfg = owned_cfg.as_ref().unwrap_or(cfg);

    if let Some(p) = progress {
        p.set_stage(ScanStage::Discovering);
    }

    // ── Collect file list ────────────────────────────────────────────────
    let walk_start = std::time::Instant::now();
    let all_paths: Vec<PathBuf> = {
        let _span = tracing::info_span!("walk_files").entered();
        let (rx, handle) = spawn_file_walker(root, cfg);
        let paths: Vec<PathBuf> = rx.into_iter().flatten().collect();
        if let Err(err) = handle.join() {
            tracing::error!("walker thread panicked: {:#?}", err);
            if let Some(l) = logs {
                l.error("Walker thread panicked", None, Some(format!("{err:#?}")));
            }
        }
        paths
    };
    tracing::info!(file_count = all_paths.len(), "file walk complete");

    // ── Build TS/JS module graph once for the scan root ──────────────────
    // Phase 04: resolver foundation. The graph is built between walk and
    // pass 1 so every per-file analysis (CFG-time import classification,
    // pass-2 cross-file lookup) sees the same view. Build cost is bounded
    // (no AST parsing, manifests only) and the result lives behind an
    // `Arc` on `Config::module_graph`.
    let owned_cfg_with_graph = ensure_module_graph(root, cfg);
    let cfg = owned_cfg_with_graph.as_ref().unwrap_or(cfg);

    if let Some(flag) = preview_tier_seen {
        if all_paths.iter().any(|p| is_preview_tier_path(p)) {
            flag.store(true, Ordering::Relaxed);
        }
    }

    if let Some(p) = progress {
        p.record_walk_ms(walk_start.elapsed().as_millis() as u64);
        p.set_files_discovered(all_paths.len() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "File walk complete: {} files discovered in {}ms",
                all_paths.len(),
                walk_start.elapsed().as_millis()
            ),
            None,
        );
    }

    let needs_taint = matches!(
        cfg.scanner.mode,
        crate::utils::config::AnalysisMode::Full
            | crate::utils::config::AnalysisMode::Cfg
            | crate::utils::config::AnalysisMode::Taint
    );

    if !needs_taint {
        // ── AST-only: single fused pass (no cross-file context needed) ──
        if let Some(p) = progress {
            p.set_stage(ScanStage::Indexing);
        }
        if let Some(l) = logs {
            l.info("Starting AST-only analysis (no taint)", None);
        }
        let _span = tracing::info_span!("ast_only_analysis", files = all_paths.len()).entered();
        let pb = make_progress_bar(all_paths.len() as u64, "Running analysis", show_progress);

        let mut diags: Vec<Diag> = all_paths
            .par_iter()
            .flat_map_iter(|path| {
                let bytes = match std::fs::read(path) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("analysis: cannot read {}: {e}", path.display());
                        if let Some(l) = logs {
                            l.warn(
                                format!("Cannot read file: {e}"),
                                Some(path.display().to_string()),
                                None,
                            );
                        }
                        pb.inc(1);
                        if let Some(p) = progress {
                            p.inc_parsed(1);
                            p.inc_analyzed(1);
                            p.set_current_file(&path.to_string_lossy());
                        }
                        return Vec::<Diag>::new();
                    }
                };
                let result = match recover_or_propagate(
                    cfg.scanner.enable_panic_recovery,
                    path,
                    logs,
                    || analyse_file_fused(&bytes, path, cfg, None, Some(root)),
                ) {
                    Ok(r) => r.diags,
                    Err(e) => {
                        tracing::warn!("analysis: {}: {e}", path.display());
                        if let Some(l) = logs {
                            l.warn(
                                format!("Analysis failed: {e}"),
                                Some(path.display().to_string()),
                                None,
                            );
                        }
                        vec![]
                    }
                };
                pb.inc(1);
                if let Some(p) = progress {
                    p.inc_parsed(1);
                    p.inc_analyzed(1);
                    p.set_current_file(&path.to_string_lossy());
                }
                result
            })
            .collect();
        pb.finish_and_clear();

        if let Some(p) = progress {
            p.set_stage(ScanStage::Complete);
        }
        post_process_diags(&mut diags, cfg);
        // AST-only mode does not produce a SurfaceMap (no CFG / summaries).
        return Ok((diags, crate::surface::SurfaceMap::new()));
    }

    // ── Taint mode: two-pass with fused pass 1 ──────────────────────────
    //
    // Pass 1 (fused): parse + CFG (once!) → extract summaries + run
    //   AST queries + local taint + CFG structural analyses.
    //   Summaries are collected for the cross-file merge.
    //
    // Pass 2: re-run full analysis with global summaries injected.
    //   This requires a second parse+CFG, but ONLY for taint-mode files
    //   that need cross-file context.  For repos where most functions
    //   don't have unresolved callees, pass 1 results are already correct.

    // ── Pass 1: fused summary extraction + parallel merge ──────────────
    //
    // Each rayon thread builds a local `GlobalSummaries` from its chunk,
    // then the per-thread maps are merged in a binary reduce tree.
    // This eliminates the serial merge_summaries bottleneck.
    if let Some(p) = progress {
        p.set_stage(ScanStage::Indexing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Starting pass 1: extracting summaries from {} files",
                all_paths.len()
            ),
            None,
        );
    }
    let pass1_start = std::time::Instant::now();
    let mut global_summaries: GlobalSummaries = {
        let _span = tracing::info_span!("pass1_fused", files = all_paths.len()).entered();
        let pb = make_progress_bar(
            all_paths.len() as u64,
            "Pass 1: Extracting summaries",
            show_progress,
        );
        let root_str = root.to_string_lossy();
        let mg = cfg.module_graph.as_deref();

        let gs = all_paths
            .par_iter()
            .fold(GlobalSummaries::new, |mut local_gs, path| {
                if let Ok(bytes) = std::fs::read(path) {
                    match recover_or_propagate(
                        cfg.scanner.enable_panic_recovery,
                        path,
                        logs,
                        || analyse_file_fused(&bytes, path, cfg, None, Some(root)),
                    ) {
                        Ok(r) => {
                            // Extract lang slug before consuming summaries
                            let first_lang = r.summaries.first().map(|s| s.lang.clone());

                            for s in r.summaries {
                                let key = s.func_key_with_resolver(Some(&root_str), mg);
                                local_gs.insert(key, s);
                            }

                            // Insert SSA summaries keyed by FuncKey
                            if !r.ssa_summaries.is_empty() {
                                for (key, ssa_sum) in r.ssa_summaries {
                                    local_gs.insert_ssa(key, ssa_sum);
                                }
                            }

                            // Insert eligible callee bodies
                            for (key, body) in r.ssa_bodies {
                                local_gs.insert_body(key, body);
                            }

                            // Insert per-function auth-check summaries so
                            // pass 2's `run_auth_analysis` can lift helpers
                            // defined in other files.
                            for (key, auth_sum) in r.auth_summaries {
                                local_gs.insert_auth(key, auth_sum);
                            }

                            // Insert per-Python-file router-dep facts so
                            // pass 2's auth analysis can lift FastAPI
                            // router-level `dependencies=[Security(...)]`
                            // declarations across the
                            // `<parent>.include_router(<this_file>.<router>,
                            // ...)` boundary — the canonical airflow
                            // execution-API auth shape.
                            if let Some((module_id, facts)) = r.router_facts {
                                local_gs.insert_router_facts(module_id, facts);
                            }

                            // Phase-09 indexed-mode parity: cache the
                            // file's cross-package import map by namespace
                            // so an inlined callee body loaded from SQLite
                            // (where the body's own Arc is stripped by
                            // `#[serde(skip)]`) can recover its package
                            // boundary at step 0.7.
                            if let Some((ns, map)) = r.cross_package_imports {
                                local_gs.insert_cross_package_imports(ns, map);
                            }

                            // Record language for progress
                            if let Some(p) = progress {
                                if let Some(ref lang) = first_lang {
                                    p.record_language(lang);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("pass 1: {}: {e}", path.display());
                            if let Some(l) = logs {
                                l.warn(
                                    format!("Pass 1 analysis failed: {e}"),
                                    Some(path.display().to_string()),
                                    None,
                                );
                            }
                        }
                    }
                } else {
                    tracing::warn!("pass 1: cannot read {}", path.display());
                    if let Some(l) = logs {
                        l.warn("Cannot read file", Some(path.display().to_string()), None);
                    }
                }
                pb.inc(1);
                if let Some(p) = progress {
                    p.inc_parsed(1);
                    p.set_current_file(&path.to_string_lossy());
                }
                local_gs
            })
            .reduce(GlobalSummaries::new, |mut a, b| {
                a.merge(b);
                a
            });

        pb.finish_and_clear();
        tracing::info!("pass 1 complete");
        gs
    };
    if let Some(p) = progress {
        p.record_pass1_ms(pass1_start.elapsed().as_millis() as u64);
    }
    // Observability: record how many cross-file SSA bodies wound up in
    // GlobalSummaries so we can distinguish "no bodies available" from
    // "bodies available but inline didn't fire."
    tracing::debug!(
        cross_file_bodies = global_summaries.bodies_len(),
        "pass 1: cross-file SSA bodies available for taint"
    );
    if let Some(l) = logs {
        l.info(
            format!(
                "Pass 1 complete in {}ms ({} cross-file SSA bodies, {} auth summaries)",
                pass1_start.elapsed().as_millis(),
                global_summaries.bodies_len(),
                global_summaries.auth_len(),
            ),
            None,
        );
    }

    // ── Build call graph ────────────────────────────────────────────────
    if let Some(l) = logs {
        l.info("Building call graph", None);
    }
    let cg_start = std::time::Instant::now();
    // Install the type-hierarchy index on `global_summaries` BEFORE
    // building the call graph so the runtime taint engine consults
    // exactly the same view of virtual dispatch that the call-graph
    // builder uses to fan out edges.  See
    // `GlobalSummaries::install_hierarchy` and
    // `GlobalSummaries::resolve_callee_widened`.
    global_summaries.install_hierarchy();
    let (call_graph, cg_analysis) = build_and_analyse_call_graph(&global_summaries);
    log_unresolved_callees(&call_graph);
    if let Some(p) = progress {
        p.record_call_graph_ms(cg_start.elapsed().as_millis() as u64);
    }
    if let Some(m) = metrics {
        m.call_edges.store(
            call_graph.graph.edge_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.functions_analyzed.store(
            call_graph.graph.node_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.unresolved_calls.store(
            (call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len()) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Call graph built in {}ms: {} nodes, {} edges, {} unresolved",
                cg_start.elapsed().as_millis(),
                call_graph.graph.node_count(),
                call_graph.graph.edge_count(),
                call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len(),
            ),
            None,
        );
    }

    // ── Pass 2: re-run with cross-file global summaries ──────────────────
    if let Some(p) = progress {
        p.set_stage(ScanStage::Analyzing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Starting pass 2: taint analysis on {} files",
                all_paths.len()
            ),
            None,
        );
    }
    let pass2_start = std::time::Instant::now();
    let mut gs = global_summaries;
    let mut diags: Vec<Diag> = {
        let _span = tracing::info_span!("pass2_analysis", files = all_paths.len()).entered();
        let pb = make_progress_bar(
            all_paths.len() as u64,
            "Pass 2: Running analysis",
            show_progress,
        );

        let (batches, orphans) = crate::callgraph::scc_file_batches_with_metadata(
            &call_graph,
            &cg_analysis,
            &all_paths,
            root,
        );
        tracing::info!(
            batches = batches.len(),
            orphan_files = orphans.len(),
            "topo-ordered file batches computed"
        );
        if let Some(l) = logs {
            l.info(
                format!(
                    "Topo-ordered file batches: {} batches, {} orphan files",
                    batches.len(),
                    orphans.len()
                ),
                None,
            );
        }

        let total_batches = batches.len() as u64 + u64::from(!orphans.is_empty());
        if let Some(p) = progress {
            p.set_batches_total(total_batches);
        }
        let result = run_topo_batches(
            &batches,
            &orphans,
            &mut gs,
            &call_graph,
            cfg,
            Some(root),
            &pb,
            progress,
            logs,
        );

        pb.finish_and_clear();
        result
    };
    tracing::info!(diags = diags.len(), "pass 2 complete");

    // Phase 21: build the SurfaceMap from the post-pass-2 view.
    // No persistence here; the index-backed path persists into the
    // `surface_map` SQLite table.  The map is returned alongside the
    // diagnostics so consumers (e.g. `nyx surface`) can avoid scanning
    // twice.
    let surface_map = crate::surface::build::build_surface_map(
        &crate::surface::build::SurfaceBuildInputs {
            files: &all_paths,
            scan_root: Some(root),
            global_summaries: &gs,
            call_graph: &call_graph,
            config: cfg,
        },
    );
    if let Some(p) = progress {
        p.record_pass2_ms(pass2_start.elapsed().as_millis() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Pass 2 complete in {}ms: {} raw findings",
                pass2_start.elapsed().as_millis(),
                diags.len()
            ),
            None,
        );
    }

    let pp_start = std::time::Instant::now();
    if let Some(p) = progress {
        p.set_stage(ScanStage::PostProcessing);
    }
    post_process_diags(&mut diags, cfg);
    if let Some(p) = progress {
        p.record_post_process_ms(pp_start.elapsed().as_millis() as u64);
        p.set_stage(ScanStage::Complete);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Post-processing complete in {}ms: {} final findings",
                pp_start.elapsed().as_millis(),
                diags.len()
            ),
            None,
        );
    }

    Ok((diags, surface_map))
}

// --------------------------------------------------------------------------------------------
// Two‑pass scanning (with index)
// --------------------------------------------------------------------------------------------

/// Indexed two‑pass scan:
///
///  **Pass 1** – For every file that needs scanning, extract summaries and
///               persist them to the database.  Unchanged files keep their
///               existing summaries.
///  **Pass 2** – Load *all* summaries from the DB, merge them, and re‑run
///               taint analysis on every file with the full cross‑file view.
///               Files whose *own* code has not changed AND whose
///               dependencies have not changed can serve cached issues
///               instead.  (Today we conservatively re‑analyse every file in
///               pass 2; caching will be refined in approach 2 / 3.)
pub fn scan_with_index_parallel(
    project: &str,
    pool: Arc<Pool<SqliteConnectionManager>>,
    cfg: &Config,
    show_progress: bool,
    scan_root: &Path,
) -> NyxResult<Vec<Diag>> {
    scan_with_index_parallel_observer(
        project,
        pool,
        cfg,
        show_progress,
        scan_root,
        None,
        None,
        None,
        None,
    )
}

/// See `scan_filesystem_with_observer` for `preview_tier_seen`.
#[allow(clippy::too_many_arguments)]
pub fn scan_with_index_parallel_observer(
    project: &str,
    pool: Arc<Pool<SqliteConnectionManager>>,
    cfg: &Config,
    show_progress: bool,
    scan_root: &Path,
    progress: Option<&Arc<ScanProgress>>,
    metrics: Option<&Arc<ScanMetrics>>,
    logs: Option<&Arc<ScanLogCollector>>,
    preview_tier_seen: Option<&Arc<AtomicBool>>,
) -> NyxResult<Vec<Diag>> {
    // Match scan_filesystem_with_observer: auto-fill framework detection when
    // the caller didn't supply one.  Without this, directly-invoked indexed
    // scans drop framework-specific findings and break indexed/non-indexed
    // parity.
    let owned_cfg = ensure_framework_ctx(scan_root, cfg);
    let cfg = owned_cfg.as_ref().unwrap_or(cfg);

    if let Some(p) = progress {
        p.set_stage(ScanStage::Discovering);
    }
    let walk_start = std::time::Instant::now();
    let indexed_files = {
        let idx = Indexer::from_pool(project, &pool)?;
        idx.get_files(project)?
    };
    let (rx, handle) = spawn_file_walker(scan_root, cfg);
    let files: Vec<PathBuf> = rx.into_iter().flatten().collect();
    if let Err(err) = handle.join() {
        tracing::error!("walker thread panicked: {:#?}", err);
        if let Some(l) = logs {
            l.error(
                "Walker thread panicked during indexed scan",
                None,
                Some(format!("{err:#?}")),
            );
        }
    }
    if let Some(flag) = preview_tier_seen {
        if files.iter().any(|p| is_preview_tier_path(p)) {
            flag.store(true, Ordering::Relaxed);
        }
    }
    if let Some(p) = progress {
        p.record_walk_ms(walk_start.elapsed().as_millis() as u64);
        p.set_files_discovered(files.len() as u64);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Indexed scan discovered {} files in {}ms",
                files.len(),
                walk_start.elapsed().as_millis()
            ),
            None,
        );
    }

    // Phase 04: build the TS/JS module graph between fs walk and pass 1
    // so the indexed scan path sees the same resolver state as the
    // non-indexed path (`scan_filesystem_with_observer`).
    let owned_cfg_with_graph = ensure_module_graph(scan_root, cfg);
    let cfg = owned_cfg_with_graph.as_ref().unwrap_or(cfg);

    let current_files: HashSet<PathBuf> = files.iter().cloned().collect();
    let removed_files: Vec<PathBuf> = indexed_files
        .into_iter()
        .filter(|path| !current_files.contains(path))
        .collect();
    if !removed_files.is_empty() {
        let mut idx = Indexer::from_pool(project, &pool)?;
        for path in &removed_files {
            idx.remove_file_and_related(path)?;
        }
        tracing::info!(
            removed = removed_files.len(),
            "pruned deleted files from indexed scan state"
        );
        if let Some(l) = logs {
            l.info(
                format!(
                    "Pruned {} deleted files from indexed state",
                    removed_files.len()
                ),
                None,
            );
        }
    }

    let needs_taint = matches!(
        cfg.scanner.mode,
        crate::utils::config::AnalysisMode::Full
            | crate::utils::config::AnalysisMode::Cfg
            | crate::utils::config::AnalysisMode::Taint
    );

    // ── Pass 1: ensure summaries are up‑to‑date ──────────────────────────
    if needs_taint {
        if let Some(p) = progress {
            p.set_stage(ScanStage::Indexing);
        }
        if let Some(l) = logs {
            l.info(
                format!("Refreshing persisted summaries for {} files", files.len()),
                None,
            );
        }
        let _span = tracing::info_span!("pass1_indexed", files = files.len()).entered();
        let pb = make_progress_bar(
            files.len() as u64,
            "Pass 1: Extracting summaries",
            show_progress,
        );
        let pass1_start = std::time::Instant::now();
        let persist_errors = Arc::new(Mutex::new(Vec::new()));
        let skipped_files = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let scan_root_ref = scan_root.to_path_buf();
        let persist_errors_ref = Arc::clone(&persist_errors);
        let skipped_files_ref = Arc::clone(&skipped_files);
        let progress_ref = progress.cloned();
        files.par_iter().for_each_init(
            || Indexer::from_pool(project, &pool).expect("db pool"),
            |idx, path| {
                if let Some(p) = &progress_ref {
                    p.set_current_file(&path.to_string_lossy());
                }
                // Read once, hash once, use the hash for the change check
                // to avoid a second file read inside should_scan.
                if let Ok(bytes) = std::fs::read(path) {
                    let hash = Indexer::digest_bytes(&bytes);
                    let needs_scan = idx.should_scan_with_hash(path, &hash).unwrap_or(true);
                    if needs_scan {
                        match recover_or_propagate(
                            cfg.scanner.enable_panic_recovery,
                            path,
                            logs,
                            || {
                                extract_all_summaries_from_bytes(
                                    &bytes,
                                    path,
                                    cfg,
                                    Some(&scan_root_ref),
                                )
                            },
                        ) {
                            Ok((func_sums, ssa_sums, ssa_bodies, auth_sums, cross_pkg_imports)) => {
                                if let Some(p) = &progress_ref {
                                    p.inc_parsed(1);
                                    if let Some(lang) = func_sums.first().map(|s| s.lang.as_str()) {
                                        p.record_language(lang);
                                    }
                                }
                                let ssa_rows: Vec<_> = ssa_sums
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
                                let body_rows: Vec<_> = ssa_bodies
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
                                let auth_rows: Vec<_> = auth_sums
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
                                // Single transaction for all four caches:
                                // one fsync per file instead of four.
                                let cpi_arg = cross_pkg_imports
                                    .as_ref()
                                    .map(|(ns, map)| (ns.as_str(), map.as_ref()));
                                if let Err(e) = idx.replace_all_for_file(
                                    path, &hash, &func_sums, &ssa_rows, &body_rows, &auth_rows,
                                    cpi_arg,
                                ) {
                                    record_persist_error(
                                        &persist_errors_ref,
                                        format!("summaries {}: {e}", path.display()),
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("pass 1: {}: {e}", path.display());
                            }
                        }
                    } else {
                        skipped_files_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(p) = &progress_ref {
                            p.inc_skipped(1);
                        }
                    }
                } else {
                    tracing::warn!("pass 1: cannot read {}", path.display());
                }
                pb.inc(1);
            },
        );
        pb.finish_and_clear();
        let skipped = skipped_files.load(std::sync::atomic::Ordering::Relaxed);
        if let Some(p) = progress {
            p.set_files_skipped(skipped);
            p.record_pass1_ms(pass1_start.elapsed().as_millis() as u64);
        }
        if let Some(m) = metrics {
            m.summaries_reused
                .store(skipped, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(l) = logs {
            l.info(
                format!(
                    "Indexed pass 1 complete: {} refreshed, {} reused",
                    files.len().saturating_sub(skipped as usize),
                    skipped
                ),
                None,
            );
        }
        fail_if_persist_errors("Pass 1", persist_errors)?;
    }

    // ── Load global summaries ────────────────────────────────────────────
    let root_str = scan_root.to_string_lossy();
    let global_summaries: Option<GlobalSummaries> = if needs_taint {
        if let Some(p) = progress {
            p.set_stage(ScanStage::LoadingSummaries);
        }
        let _span = tracing::info_span!("load_summaries_db").entered();
        let idx = Indexer::from_pool(project, &pool)?;
        let all = idx.load_all_summaries()?;
        tracing::info!(summaries = all.len(), "loaded cross-file summaries from DB");
        let mut gs = summary::merge_summaries(all, Some(&root_str));

        // Load and insert SSA summaries
        let ssa_rows = idx.load_all_ssa_summaries()?;
        let ssa_count = ssa_rows.len();
        if !ssa_rows.is_empty() {
            tracing::info!(
                ssa_summaries = ssa_rows.len(),
                "loaded SSA summaries from DB"
            );
            for (file_path, name, lang_str, arity, namespace, container, disambig, kind, ssa_sum) in
                ssa_rows
            {
                let lang =
                    crate::symbol::Lang::from_slug(&lang_str).unwrap_or(crate::symbol::Lang::Rust);
                // Use persisted namespace; fall back to normalized file_path
                let ns = if namespace.is_empty() {
                    crate::symbol::namespace_with_package(
                        &file_path,
                        Some(&root_str),
                        cfg.module_graph.as_deref(),
                    )
                } else {
                    namespace
                };
                let key = crate::symbol::FuncKey {
                    lang,
                    namespace: ns,
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
                gs.insert_ssa(key, ssa_sum);
            }
        }

        // Load Phase-09 cross-package import maps so an inlined callee
        // body loaded from SQLite (where the body's own Arc is stripped
        // by `#[serde(skip)]`) can recover its package boundary at
        // step 0.7.  Indexed-mode parity with `scan_filesystem`.
        match idx.load_all_cross_package_imports() {
            Ok(rows) => {
                for (_file_path, namespace, map) in rows {
                    if !map.is_empty() {
                        gs.insert_cross_package_imports(namespace, std::sync::Arc::new(map));
                    }
                }
            }
            Err(e) => {
                tracing::warn!("failed to load cross_package_imports from DB: {e}");
            }
        }

        // Load cross-file callee bodies from DB
        let body_count = if crate::symex::cross_file_symex_enabled() {
            match idx.load_all_ssa_bodies() {
                Ok(body_rows) => {
                    let count = body_rows.len();
                    for (
                        file_path,
                        name,
                        lang_str,
                        arity,
                        namespace,
                        container,
                        disambig,
                        kind,
                        body,
                    ) in body_rows
                    {
                        let lang = crate::symbol::Lang::from_slug(&lang_str)
                            .unwrap_or(crate::symbol::Lang::Rust);
                        let ns = if namespace.is_empty() {
                            crate::symbol::namespace_with_package(
                                &file_path,
                                Some(&root_str),
                                cfg.module_graph.as_deref(),
                            )
                        } else {
                            namespace
                        };
                        let key = crate::symbol::FuncKey {
                            lang,
                            namespace: ns,
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
                        gs.insert_body(key, body);
                    }
                    count
                }
                Err(e) => {
                    tracing::warn!("failed to load SSA bodies from DB: {e}");
                    0
                }
            }
        } else {
            0
        };

        // Load per-function auth-check summaries so pass 2's
        // `run_auth_analysis` can lift helpers defined in other files.
        let auth_rows = idx.load_all_auth_summaries()?;
        let auth_count = auth_rows.len();
        if !auth_rows.is_empty() {
            tracing::info!(
                auth_summaries = auth_rows.len(),
                "loaded auth summaries from DB"
            );
            for (
                file_path,
                name,
                lang_str,
                arity,
                namespace,
                container,
                disambig,
                kind,
                auth_sum,
            ) in auth_rows
            {
                let lang =
                    crate::symbol::Lang::from_slug(&lang_str).unwrap_or(crate::symbol::Lang::Rust);
                let ns = if namespace.is_empty() {
                    crate::symbol::namespace_with_package(
                        &file_path,
                        Some(&root_str),
                        cfg.module_graph.as_deref(),
                    )
                } else {
                    namespace
                };
                let key = crate::symbol::FuncKey {
                    lang,
                    namespace: ns,
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
                gs.insert_auth(key, auth_sum);
            }
        }

        // Same observability as the non-indexed scan path so callers
        // see a uniform "cross-file bodies available" signal regardless
        // of which scan path populated GlobalSummaries.
        tracing::debug!(
            cross_file_bodies = body_count,
            "indexed scan: cross-file SSA bodies available for taint"
        );
        if let Some(l) = logs {
            l.info(
                format!(
                    "Loaded {} coarse summaries, {} SSA summaries, {} SSA bodies, {} auth summaries from DB",
                    gs.snapshot_caps().len(),
                    ssa_count,
                    body_count,
                    auth_count,
                ),
                None,
            );
        }

        Some(gs)
    } else {
        None
    };

    if !needs_taint {
        // ── AST-only: existing parallel scan with caching ────────────────
        if let Some(p) = progress {
            p.set_stage(ScanStage::Analyzing);
        }
        if let Some(l) = logs {
            l.info("Starting AST-only indexed analysis", None);
        }
        let pass2_start = std::time::Instant::now();
        let _span = tracing::info_span!("pass2_indexed_ast_only").entered();
        let pb2 = make_progress_bar(
            files.len() as u64,
            "Pass 2: Running analysis",
            show_progress,
        );
        let diag_map: DashMap<String, Vec<Diag>> = DashMap::new();
        let persist_errors = Arc::new(Mutex::new(Vec::new()));
        let skipped_files = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let persist_errors_ref = Arc::clone(&persist_errors);
        let skipped_files_ref = Arc::clone(&skipped_files);
        let progress_ref = progress.cloned();
        files.into_par_iter().for_each_init(
            || Indexer::from_pool(project, &pool).expect("db pool"),
            |idx, path| {
                if let Some(p) = &progress_ref {
                    p.set_current_file(&path.to_string_lossy());
                }
                let bytes_opt = std::fs::read(&path).ok();
                let hash = bytes_opt.as_ref().map(|b| Indexer::digest_bytes(b));

                let needs_scan = match (&hash, &bytes_opt) {
                    (Some(h), _) => idx.should_scan_with_hash(&path, h).unwrap_or(true),
                    _ => true,
                };

                let mut diags = if needs_scan {
                    if let Some(p) = &progress_ref {
                        p.inc_parsed(1);
                        p.inc_analyzed(1);
                    }
                    let d = recover_or_propagate(
                        cfg.scanner.enable_panic_recovery,
                        &path,
                        logs,
                        || match &bytes_opt {
                            Some(bytes) => {
                                run_rules_on_bytes(bytes, &path, cfg, None, Some(scan_root))
                            }
                            None => run_rules_on_file(&path, cfg, None, Some(scan_root)),
                        },
                    )
                    .unwrap_or_default();

                    let file_id = match &hash {
                        Some(h) => idx.upsert_file_with_hash(&path, h),
                        None => idx.upsert_file(&path),
                    };
                    match file_id {
                        Ok(file_id) => {
                            if let Err(e) = idx.replace_issues(
                                file_id,
                                d.iter().map(|d| IssueRow {
                                    rule_id: &d.id,
                                    severity: d.severity.as_db_str(),
                                    line: d.line as i64,
                                    col: d.col as i64,
                                }),
                            ) {
                                record_persist_error(
                                    &persist_errors_ref,
                                    format!("issues {}: {e}", path.display()),
                                );
                            }
                        }
                        Err(e) => {
                            record_persist_error(
                                &persist_errors_ref,
                                format!("file row {}: {e}", path.display()),
                            );
                        }
                    }
                    d
                } else {
                    skipped_files_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Some(p) = &progress_ref {
                        p.inc_skipped(1);
                    }
                    idx.get_issues_from_file(&path).unwrap_or_default()
                };

                // AST-only: drop taint/cfg findings
                diags.retain(|d| !d.id.starts_with("taint") && !d.id.starts_with("cfg-"));

                if !diags.is_empty() {
                    diag_map
                        .entry(path.to_string_lossy().to_string())
                        .or_default()
                        .append(&mut diags);
                }
                pb2.inc(1);
            },
        );
        pb2.finish_and_clear();
        let skipped = skipped_files.load(std::sync::atomic::Ordering::Relaxed);
        if let Some(p) = progress {
            p.set_files_skipped(skipped);
            p.record_pass2_ms(pass2_start.elapsed().as_millis() as u64);
            p.set_stage(ScanStage::PostProcessing);
        }
        if let Some(m) = metrics {
            m.summaries_reused
                .store(skipped, std::sync::atomic::Ordering::Relaxed);
        }
        fail_if_persist_errors("AST-only pass 2", persist_errors)?;

        let mut diags: Vec<Diag> = diag_map.into_iter().flat_map(|(_, v)| v).collect();
        let post_process_start = std::time::Instant::now();
        post_process_diags(&mut diags, cfg);
        if let Some(p) = progress {
            p.record_post_process_ms(post_process_start.elapsed().as_millis() as u64);
            p.set_stage(ScanStage::Complete);
        }
        if let Some(l) = logs {
            l.info(
                format!(
                    "AST-only indexed scan complete in {}ms: {} findings, {} reused files",
                    pass2_start.elapsed().as_millis(),
                    diags.len(),
                    skipped
                ),
                None,
            );
        }
        return Ok(diags);
    }

    // ── Taint mode: build call graph + topo-ordered pass 2 ────────────
    let mut global_summaries = global_summaries.ok_or_else(|| {
        crate::errors::NyxError::Msg(
            "internal: global_summaries missing in taint-mode pass 2".to_string(),
        )
    })?;
    if let Some(p) = progress {
        p.set_stage(ScanStage::BuildingCallGraph);
    }
    let cg_start = std::time::Instant::now();
    // Install the type-hierarchy index on `global_summaries` BEFORE
    // building the call graph so the runtime taint engine consults
    // exactly the same view of virtual dispatch that the call-graph
    // builder uses to fan out edges.  See
    // `GlobalSummaries::install_hierarchy` and
    // `GlobalSummaries::resolve_callee_widened`.
    global_summaries.install_hierarchy();
    let (call_graph, cg_analysis) = build_and_analyse_call_graph(&global_summaries);
    log_unresolved_callees(&call_graph);
    if let Some(p) = progress {
        p.record_call_graph_ms(cg_start.elapsed().as_millis() as u64);
    }
    if let Some(m) = metrics {
        m.call_edges.store(
            call_graph.graph.edge_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.functions_analyzed.store(
            call_graph.graph.node_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        m.unresolved_calls.store(
            (call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len()) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Call graph built in {}ms: {} nodes, {} edges, {} unresolved",
                cg_start.elapsed().as_millis(),
                call_graph.graph.node_count(),
                call_graph.graph.edge_count(),
                call_graph.unresolved_not_found.len() + call_graph.unresolved_ambiguous.len(),
            ),
            None,
        );
    }

    let (batches, orphans) = crate::callgraph::scc_file_batches_with_metadata(
        &call_graph,
        &cg_analysis,
        &files,
        scan_root,
    );
    tracing::info!(
        batches = batches.len(),
        orphan_files = orphans.len(),
        "topo-ordered file batches computed (indexed)"
    );
    if let Some(l) = logs {
        l.info(
            format!(
                "Topo-ordered indexed analysis plan: {} batches, {} orphan files",
                batches.len(),
                orphans.len()
            ),
            None,
        );
    }

    let _span = tracing::info_span!("pass2_indexed").entered();
    if let Some(p) = progress {
        p.set_stage(ScanStage::Analyzing);
        p.set_batches_total(batches.len() as u64 + u64::from(!orphans.is_empty()));
    }
    let pass2_start = std::time::Instant::now();
    let pb2 = make_progress_bar(
        files.len() as u64,
        "Pass 2: Running analysis",
        show_progress,
    );

    let topo_diags = run_topo_batches(
        &batches,
        &orphans,
        &mut global_summaries,
        &call_graph,
        cfg,
        Some(scan_root),
        &pb2,
        progress,
        logs,
    );
    pb2.finish_and_clear();
    if let Some(p) = progress {
        p.record_pass2_ms(pass2_start.elapsed().as_millis() as u64);
        p.set_stage(ScanStage::PostProcessing);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Indexed pass 2 complete in {}ms: {} raw findings",
                pass2_start.elapsed().as_millis(),
                topo_diags.len()
            ),
            None,
        );
    }

    // Persist issues to DB after topo analysis, grouped by file.
    {
        let mut by_file: HashMap<&str, Vec<&Diag>> = HashMap::new();
        for d in &topo_diags {
            by_file.entry(&d.path).or_default().push(d);
        }
        let mut idx = Indexer::from_pool(project, &pool)?;
        for path in &files {
            if !path.exists() {
                idx.remove_file_and_related(path)?;
                continue;
            }

            let file_id = idx.upsert_file(path)?;
            let empty: [&Diag; 0] = [];
            let file_diags = by_file
                .get(path.to_string_lossy().as_ref())
                .map(Vec::as_slice)
                .unwrap_or(&empty);

            idx.replace_issues(
                file_id,
                file_diags.iter().map(|d| IssueRow {
                    rule_id: &d.id,
                    severity: d.severity.as_db_str(),
                    line: d.line as i64,
                    col: d.col as i64,
                }),
            )?;
        }
    }
    if let Some(l) = logs {
        l.info(
            format!("Persisted findings for {} files", files.len()),
            None,
        );
    }

    let mut diags = topo_diags;

    // Phase 21: build + persist the SurfaceMap from the post-pass-2
    // view.  Errors here are logged but not propagated — the surface
    // map is an additive Phase F deliverable, not a scan gate.
    {
        let surface_map = crate::surface::build::build_surface_map(
            &crate::surface::build::SurfaceBuildInputs {
                files: &files,
                scan_root: Some(scan_root),
                global_summaries: &global_summaries,
                call_graph: &call_graph,
                config: cfg,
            },
        );
        let mut idx = Indexer::from_pool(project, &pool)?;
        if let Err(e) = idx.replace_surface_map(&surface_map) {
            tracing::warn!("failed to persist surface_map: {e}");
        } else if let Some(l) = logs {
            l.info(
                format!(
                    "Surface map: {} nodes, {} edges",
                    surface_map.node_count(),
                    surface_map.edge_count()
                ),
                None,
            );
        }
    }

    // NOTE: Taint-mode output is *not* filtered here.  `run_rules_on_bytes`
    // already gates AST queries and auth analyses behind `mode == Full`, so
    // Taint-mode raw output is exactly the set of diagnostics the analysis
    // pipeline intends to produce (taint + cfg-* + state-* from state
    // analysis + auth.* when configured).  A previous revision clipped this
    // to `taint*`/`cfg-*` only, silently dropping state-model findings and
    // breaking parity with `scan_filesystem`, fixed.  Mode-scoped
    // filtering, if ever needed, belongs in the analysis layer, not here.

    let post_process_start = std::time::Instant::now();
    post_process_diags(&mut diags, cfg);
    if let Some(p) = progress {
        p.record_post_process_ms(post_process_start.elapsed().as_millis() as u64);
        p.set_stage(ScanStage::Complete);
    }
    if let Some(l) = logs {
        l.info(
            format!(
                "Indexed scan complete in {}ms: {} final findings",
                pass2_start.elapsed().as_millis(),
                diags.len()
            ),
            None,
        );
    }

    Ok(diags)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Low-noise prioritization pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Rules eligible for rollup grouping (high-frequency, low-signal patterns).
const ROLLUP_RULES: &[&str] = &[
    "rs.quality.unwrap",
    "rs.quality.expect",
    "rs.quality.panic_macro",
];

/// Apply category filtering, rollup grouping, and LOW budgets to reduce noise.
///
/// Modifies `diags` in place and returns suppression statistics for the footer.
pub(crate) fn prioritize(
    diags: &mut Vec<Diag>,
    config: &crate::utils::config::OutputConfig,
    show_instances: Option<&str>,
) -> SuppressionStats {
    let mut stats = SuppressionStats {
        quality_dropped: 0,
        low_budget_dropped: 0,
        max_results_dropped: 0,
        include_quality: config.include_quality,
        show_all: config.show_all,
        max_low: config.max_low,
        max_low_per_file: config.max_low_per_file,
        max_low_per_rule: config.max_low_per_rule,
    };

    if config.show_all {
        return stats;
    }

    // ── 1. Category filter: drop Quality unless include_quality ────────
    if !config.include_quality {
        let before = diags.len();
        diags.retain(|d| d.category != FindingCategory::Quality);
        stats.quality_dropped = before - diags.len();
    }

    // ── 2. Rollup: group high-frequency LOW Quality findings ──────────
    rollup_findings(diags, config, show_instances);

    // ── 3. LOW budgets ────────────────────────────────────────────────
    apply_low_budgets(diags, config, &mut stats);

    // ── 4. Global max_results with severity stability ─────────────────
    if let Some(max) = config.max_results {
        let max = max as usize;
        if diags.len() > max {
            // Partition by severity priority: High first, then Medium, then Low
            let high_count = diags
                .iter()
                .filter(|d| d.severity == Severity::High)
                .count();
            let med_count = diags
                .iter()
                .filter(|d| d.severity == Severity::Medium)
                .count();

            let take = if high_count >= max {
                // Only High fits
                diags.retain(|d| d.severity == Severity::High);
                diags.truncate(max);
                max
            } else if high_count + med_count >= max {
                // High + some Medium
                let med_slots = max - high_count;
                let mut med_seen = 0usize;
                diags.retain(|d| {
                    if d.severity == Severity::High {
                        true
                    } else if d.severity == Severity::Medium && med_seen < med_slots {
                        med_seen += 1;
                        true
                    } else {
                        false
                    }
                });
                max
            } else {
                // High + Medium + some Low
                let low_slots = max - high_count - med_count;
                let mut low_seen = 0usize;
                diags.retain(|d| {
                    if d.severity == Severity::High || d.severity == Severity::Medium {
                        true
                    } else if low_seen < low_slots {
                        low_seen += 1;
                        true
                    } else {
                        false
                    }
                });
                max
            };
            let original_total = high_count + med_count + diags.len(); // approximate
            stats.max_results_dropped = original_total.saturating_sub(take);
        }
    }

    stats
}

/// Group eligible LOW Quality findings into rollup Diags.
fn rollup_findings(
    diags: &mut Vec<Diag>,
    config: &crate::utils::config::OutputConfig,
    show_instances: Option<&str>,
) {
    use std::collections::HashMap;

    // Identify which diags are eligible for rollup
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (i, d) in diags.iter().enumerate() {
        if d.severity != Severity::Low {
            continue;
        }
        if d.category != FindingCategory::Quality {
            continue;
        }
        if !ROLLUP_RULES.contains(&d.id.as_str()) {
            continue;
        }
        if show_instances == Some(d.id.as_str()) {
            continue;
        }
        groups
            .entry((d.path.clone(), d.id.clone()))
            .or_default()
            .push(i);
    }

    // Only rollup groups with more than 1 occurrence
    let mut to_remove: Vec<usize> = Vec::new();
    let mut rollups: Vec<Diag> = Vec::new();

    for ((_path, _rule_id), mut indices) in groups {
        if indices.len() <= 1 {
            continue;
        }

        // Sort by (line, col) for deterministic canonical location
        indices.sort_by_key(|&i| (diags[i].line, diags[i].col));

        let canonical_idx = indices[0];
        let total = indices.len();

        // Collect example locations (first N)
        let examples: Vec<Location> = indices
            .iter()
            .take(config.rollup_examples as usize)
            .map(|&i| Location {
                line: diags[i].line,
                col: diags[i].col,
            })
            .collect();

        // Build rollup Diag from canonical
        let canonical = &diags[canonical_idx];
        let rollup_diag = Diag {
            path: canonical.path.clone(),
            line: canonical.line,
            col: canonical.col,
            severity: canonical.severity,
            id: canonical.id.clone(),
            category: canonical.category,
            path_validated: false,
            guard_kind: None,
            message: canonical.message.clone(),
            labels: vec![],
            confidence: canonical.confidence,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: Some(RollupData {
                count: total,
                occurrences: examples,
            }),
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };

        rollups.push(rollup_diag);
        to_remove.extend(indices);
    }

    if to_remove.is_empty() {
        return;
    }

    // Remove originals (in reverse order to preserve indices)
    to_remove.sort_unstable();
    to_remove.dedup();
    for &i in to_remove.iter().rev() {
        diags.remove(i);
    }

    // Sort rollups for deterministic output: by (path, id, line)
    rollups.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.id.cmp(&b.id))
            .then(a.line.cmp(&b.line))
    });

    // Add rollup diags
    diags.extend(rollups);
}

/// Enforce per-file, per-rule, and total LOW budgets.
fn apply_low_budgets(
    diags: &mut Vec<Diag>,
    config: &crate::utils::config::OutputConfig,
    stats: &mut SuppressionStats,
) {
    use std::collections::HashMap;

    let mut per_file: HashMap<String, u32> = HashMap::new();
    let mut per_rule: HashMap<String, u32> = HashMap::new();
    let mut total_low: u32 = 0;

    let before = diags.len();
    diags.retain(|d| {
        // High/Medium always kept
        if d.severity != Severity::Low {
            return true;
        }

        // Check per-file budget
        let file_count = per_file.entry(d.path.clone()).or_insert(0);
        if *file_count >= config.max_low_per_file {
            return false;
        }

        // Check per-rule budget
        let rule_count = per_rule.entry(d.id.clone()).or_insert(0);
        if *rule_count >= config.max_low_per_rule {
            return false;
        }

        // Check total budget
        if total_low >= config.max_low {
            return false;
        }

        *file_count += 1;
        *rule_count += 1;
        total_low += 1;
        true
    });
    stats.low_budget_dropped = before - diags.len();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Inline suppression application
// ─────────────────────────────────────────────────────────────────────────────

/// Apply inline `nyx:ignore` / `nyx:ignore-next-line` suppressions to `diags`.
///
/// For each unique file path in the diagnostics, the source file is read once,
/// suppression directives are parsed, and matching findings are marked as
/// suppressed.
fn apply_suppressions(diags: &mut [Diag]) {
    use std::collections::HashMap;

    // Group diag indices by path (clone path strings to avoid borrowing diags).
    let mut by_path: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, d) in diags.iter().enumerate() {
        by_path.entry(d.path.clone()).or_default().push(i);
    }

    for (path, indices) in &by_path {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        let file_path = Path::new(path.as_str());
        let index = crate::suppress::parse_inline_suppressions(file_path, &source);
        if index.is_empty() {
            continue;
        }
        for &i in indices {
            if let Some(meta) = index.check(diags[i].line, &diags[i].id) {
                diags[i].suppressed = true;
                diags[i].suppression = Some(meta);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  deduplicate_taint_flows tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod dedup_taint_flow_tests {
    use super::*;
    use crate::evidence::{Evidence, FlowStep, FlowStepKind, SpanEvidence};

    fn make_taint(path: &str, line: usize, col: usize, source_line: u32, source_col: u32) -> Diag {
        Diag {
            path: path.into(),
            line,
            col,
            severity: Severity::High,
            id: format!("taint-unsanitised-flow (source {source_line}:{source_col})"),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: Some(Evidence {
                source: Some(SpanEvidence {
                    path: path.into(),
                    line: source_line,
                    col: source_col,
                    kind: "source".into(),
                    snippet: None,
                }),
                sink: Some(SpanEvidence {
                    path: path.into(),
                    line: line as u32,
                    col: col as u32,
                    kind: "sink".into(),
                    snippet: None,
                }),
                hop_count: Some(1),
                flow_steps: vec![
                    FlowStep {
                        step: 1,
                        kind: FlowStepKind::Source,
                        file: path.into(),
                        line: source_line,
                        col: source_col,
                        snippet: None,
                        variable: None,
                        callee: None,
                        function: Some("f".into()),
                        is_cross_file: false,
                    },
                    FlowStep {
                        step: 2,
                        kind: FlowStepKind::Sink,
                        file: path.into(),
                        line: line as u32,
                        col: col as u32,
                        snippet: None,
                        variable: None,
                        callee: None,
                        function: Some("f".into()),
                        is_cross_file: false,
                    },
                ],
                ..Default::default()
            }),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }
    }

    #[test]
    fn dedup_collapses_two_sources_to_same_sink_keeps_tighter_source() {
        // Two findings at line 10: one with source at line 3 (distance 7),
        // one with source at line 8 (distance 2). The closer source wins.
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("a.rs", 10, 5, 8, 1),
        ];
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0].id.contains("(source 8:1)"),
            "should keep tighter source, got id={}",
            diags[0].id
        );
    }

    #[test]
    fn dedup_does_not_drop_different_sink_locations() {
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("a.rs", 12, 5, 3, 1),
        ];
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn dedup_does_not_drop_across_severities() {
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("a.rs", 10, 5, 8, 1),
        ];
        diags[1].severity = Severity::Medium;
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn dedup_does_not_drop_across_paths() {
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("b.rs", 10, 5, 3, 1),
        ];
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn dedup_leaves_non_taint_rule_ids_alone() {
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("a.rs", 10, 5, 8, 1),
        ];
        diags[1].id = "js.code_exec.eval".into();
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn dedup_collapses_same_line_different_columns() {
        // Two findings at line 10 but different columns, the widened key
        // (path, line, severity) collapses them; the tighter source wins.
        let mut diags = vec![
            make_taint("a.rs", 10, 3, 4, 1),
            make_taint("a.rs", 10, 17, 8, 1),
        ];
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0].id.contains("(source 8:1)"),
            "should keep tighter source (distance 2), got id={}",
            diags[0].id
        );
    }

    #[test]
    fn dedup_does_not_drop_different_sink_caps_on_same_line() {
        // Two findings at line 10, same column, same severity, but with
        // different resolved sink capability bits (SQL vs SHELL). They must
        // NOT collapse: different sink kinds are materially different
        // vulnerabilities. Regression guard.
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("a.rs", 10, 5, 3, 1),
        ];
        if let Some(ev) = diags[0].evidence.as_mut() {
            ev.sink_caps = crate::labels::Cap::SQL_QUERY.bits();
        }
        if let Some(ev) = diags[1].evidence.as_mut() {
            ev.sink_caps = crate::labels::Cap::SHELL_ESCAPE.bits();
        }
        deduplicate_taint_flows(&mut diags);
        assert_eq!(
            diags.len(),
            2,
            "findings with different sink caps must not dedup"
        );
    }

    #[test]
    fn dedup_collapses_same_sink_caps_on_same_line() {
        // Same line, same severity, same sink caps, this is the canonical
        // dedup case (two flows to the same sink, differing only in source).
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 3, 1),
            make_taint("a.rs", 10, 5, 8, 1),
        ];
        if let Some(ev) = diags[0].evidence.as_mut() {
            ev.sink_caps = crate::labels::Cap::SHELL_ESCAPE.bits();
        }
        if let Some(ev) = diags[1].evidence.as_mut() {
            ev.sink_caps = crate::labels::Cap::SHELL_ESCAPE.bits();
        }
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn dedup_prefers_same_function_over_cross_function() {
        // Two findings at line 10: one from same function, one from cross-function.
        let mut diags = vec![
            make_taint("a.rs", 10, 5, 8, 1),
            make_taint("a.rs", 10, 5, 2, 1),
        ];
        // Second one is cross-function (different enclosing_func on the Source step).
        if let Some(ev) = diags[1].evidence.as_mut() {
            if let Some(first) = ev.flow_steps.first_mut() {
                first.function = Some("other".into());
            }
        }
        deduplicate_taint_flows(&mut diags);
        assert_eq!(diags.len(), 1);
        // Kept should be the same-function one (source 8:1).
        assert!(diags[0].id.contains("(source 8:1)"));
    }
}

#[cfg(test)]
mod scc_tagging_tests {
    use super::*;
    use crate::evidence::{Confidence, Evidence};

    fn make_diag(confidence: Option<Confidence>) -> Diag {
        Diag {
            path: "a.py".into(),
            line: 1,
            col: 1,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence,
            evidence: Some(Evidence::default()),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }
    }

    #[test]
    fn tag_unconverged_caps_confidence_and_appends_note() {
        let mut diags = vec![make_diag(Some(Confidence::High)), make_diag(None)];
        tag_unconverged_findings(
            &mut diags,
            64,
            64,
            false,
            crate::engine_notes::CapHitReason::Unknown,
        );

        assert_eq!(diags[0].confidence, Some(Confidence::Low));
        assert_eq!(diags[1].confidence, Some(Confidence::Low));
        for d in &diags {
            let ev = d.evidence.as_ref().expect("evidence populated");
            assert!(
                ev.notes
                    .iter()
                    .any(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX)),
                "expected scc_unconverged note, got {:?}",
                ev.notes
            );
        }
    }

    #[test]
    fn tag_unconverged_preserves_lower_than_low_confidence() {
        // Nothing is strictly below Low today, but the cap-at-Low logic
        // should still produce Low as the floor when confidence is Low.
        let mut diags = vec![make_diag(Some(Confidence::Low))];
        tag_unconverged_findings(
            &mut diags,
            10,
            64,
            false,
            crate::engine_notes::CapHitReason::Unknown,
        );
        assert_eq!(diags[0].confidence, Some(Confidence::Low));
    }

    #[test]
    fn tag_unconverged_creates_evidence_when_missing() {
        let mut d = make_diag(None);
        d.evidence = None;
        let mut diags = vec![d];
        tag_unconverged_findings(
            &mut diags,
            7,
            64,
            false,
            crate::engine_notes::CapHitReason::Unknown,
        );

        let ev = diags[0].evidence.as_ref().expect("evidence created");
        assert!(
            ev.notes
                .iter()
                .any(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
        );
    }

    #[test]
    fn tag_unconverged_does_not_duplicate_notes_on_rerun() {
        let mut diags = vec![make_diag(None)];
        tag_unconverged_findings(
            &mut diags,
            64,
            64,
            false,
            crate::engine_notes::CapHitReason::Unknown,
        );
        tag_unconverged_findings(
            &mut diags,
            64,
            64,
            false,
            crate::engine_notes::CapHitReason::Unknown,
        );
        let notes = &diags[0].evidence.as_ref().unwrap().notes;
        let count = notes
            .iter()
            .filter(|n| n.starts_with(SCC_UNCONVERGED_NOTE_PREFIX))
            .count();
        assert_eq!(count, 1, "should not duplicate scc_unconverged note");
    }

    #[test]
    fn tag_unconverged_cross_file_variant_uses_tighter_prefix() {
        // Cross-file SCC cap-hit should emit a cross-file note
        // variant while remaining a strict superset of the base
        // prefix so existing consumers still match.
        let mut diags = vec![make_diag(None)];
        tag_unconverged_findings(
            &mut diags,
            64,
            64,
            true,
            crate::engine_notes::CapHitReason::Unknown,
        );

        let ev = diags[0].evidence.as_ref().expect("evidence populated");
        // The cross-file note must also start with the base prefix so
        // callers filtering on `SCC_UNCONVERGED_NOTE_PREFIX` still see it.
        assert!(SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX.starts_with(SCC_UNCONVERGED_NOTE_PREFIX));
        assert!(
            ev.notes
                .iter()
                .any(|n| n.starts_with(SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX)),
            "expected cross-file scc_unconverged note, got {:?}",
            ev.notes
        );
    }

    #[test]
    fn tag_unconverged_non_cross_file_does_not_use_cross_file_prefix() {
        // Sanity check: the non-cross-file variant must not emit the
        // cross-file note. Prevents accidental tag unification.
        let mut diags = vec![make_diag(None)];
        tag_unconverged_findings(
            &mut diags,
            64,
            64,
            false,
            crate::engine_notes::CapHitReason::Unknown,
        );

        let ev = diags[0].evidence.as_ref().expect("evidence populated");
        assert!(
            !ev.notes
                .iter()
                .any(|n| n.starts_with(SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX)),
            "intra-file SCC should not carry cross-file note, got {:?}",
            ev.notes
        );
    }
}

#[test]
fn scan_with_index_parallel_uses_existing_index_without_rescanning() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    std::fs::create_dir(&project_dir).unwrap();
    std::fs::write(project_dir.join("foo.txt"), "abc").unwrap();

    let (project_name, db_path) = get_project_info(&project_dir, td.path()).unwrap();
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg, false)
        .unwrap();

    let pool = Indexer::init(&db_path).unwrap();

    assert_eq!(
        Indexer::from_pool(&project_name, &pool)
            .unwrap()
            .get_files(&project_name)
            .unwrap()
            .len(),
        1
    );

    let diags =
        scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false, &project_dir)
            .expect("scan should succeed");

    assert!(diags.is_empty());
}

#[test]
fn scan_with_index_parallel_discovers_new_files_after_index_build() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    std::fs::create_dir(&project_dir).unwrap();
    std::fs::write(project_dir.join("foo.txt"), "abc").unwrap();

    let (project_name, db_path) = get_project_info(&project_dir, td.path()).unwrap();
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg, false)
        .unwrap();

    std::fs::write(project_dir.join("bar.txt"), "xyz").unwrap();

    let pool = Indexer::init(&db_path).unwrap();
    scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false, &project_dir)
        .expect("scan should succeed");

    let files = Indexer::from_pool(&project_name, &pool)
        .unwrap()
        .get_files(&project_name)
        .unwrap();
    assert_eq!(
        files.len(),
        2,
        "new files should be discovered without rebuild"
    );
}

#[test]
fn scan_with_index_parallel_clears_stale_issues_when_file_becomes_clean() {
    let mut cfg = Config::default();
    cfg.performance.worker_threads = Some(1);
    cfg.performance.channel_multiplier = 1;
    cfg.performance.batch_size = 2;

    let td = tempfile::tempdir().unwrap();
    let project_dir = td.path().join("proj");
    std::fs::create_dir(&project_dir).unwrap();
    let app = project_dir.join("app.js");
    std::fs::write(
        &app,
        r#"
function run() {
  const cmd = process.env.CMD;
  eval(cmd);
}
"#,
    )
    .unwrap();

    let (project_name, db_path) = get_project_info(&project_dir, td.path()).unwrap();
    crate::commands::index::build_index(&project_name, &project_dir, &db_path, &cfg, false)
        .unwrap();

    let pool = Indexer::init(&db_path).unwrap();
    let idx = Indexer::from_pool(&project_name, &pool).unwrap();
    assert!(
        !idx.get_issues_from_file(&app).unwrap().is_empty(),
        "the initial indexed build should persist at least one issue"
    );

    std::fs::write(
        &app,
        r#"
function run() {
  const cmd = "safe";
  console.log(cmd);
}
"#,
    )
    .unwrap();

    let diags =
        scan_with_index_parallel(&project_name, Arc::clone(&pool), &cfg, false, &project_dir)
            .expect("scan should succeed");
    assert!(
        diags.is_empty(),
        "the cleaned file should no longer report findings"
    );

    let idx = Indexer::from_pool(&project_name, &pool).unwrap();
    assert!(
        idx.get_issues_from_file(&app).unwrap().is_empty(),
        "DB issues should be cleared when a file becomes clean"
    );
}

#[test]
fn severity_filter_applied_at_output_stage() {
    // Simulate: findings start as High, get downgraded to Medium by nonprod logic,
    // then --severity HIGH should filter them out.
    let diags = vec![
        Diag {
            path: "tests/test.py".into(),
            line: 1,
            col: 1,
            severity: Severity::Medium, // was High, downgraded
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        },
        Diag {
            path: "src/main.rs".into(),
            line: 10,
            col: 5,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        },
    ];

    let filter = SeverityFilter::parse("HIGH").unwrap();
    let filtered: Vec<_> = diags
        .into_iter()
        .filter(|d| filter.matches(d.severity))
        .collect();

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].severity, Severity::High);
    assert_eq!(filtered[0].path, "src/main.rs");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Prioritization pipeline tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod prioritize_tests {
    use super::*;
    use crate::utils::config::OutputConfig;

    fn make_diag(
        path: &str,
        line: usize,
        severity: Severity,
        id: &str,
        cat: FindingCategory,
    ) -> Diag {
        Diag {
            path: path.into(),
            line,
            col: 1,
            severity,
            id: id.into(),
            category: cat,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }
    }

    fn default_config() -> OutputConfig {
        OutputConfig::default()
    }

    #[test]
    fn quality_dropped_by_default() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::High,
                "taint-flow",
                FindingCategory::Security,
            ),
        ];
        let stats = prioritize(&mut diags, &default_config(), None);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].id, "taint-flow");
        assert_eq!(stats.quality_dropped, 1);
    }

    #[test]
    fn quality_kept_with_include_quality() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::High,
                "taint-flow",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 2);
        assert_eq!(stats.quality_dropped, 0);
    }

    #[test]
    fn show_all_disables_everything() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                3,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.show_all = true;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 3); // no filtering, no rollup
        assert_eq!(stats.quality_dropped, 0);
        assert_eq!(stats.low_budget_dropped, 0);
        assert!(diags.iter().all(|d| d.rollup.is_none()));
    }

    #[test]
    fn rollup_groups_by_file_and_rule() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                10,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                20,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                30,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "b.rs",
                5,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "b.rs",
                15,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        let _stats = prioritize(&mut diags, &cfg, None);

        // Should have 2 rollup diags (one per file)
        let rollups: Vec<_> = diags.iter().filter(|d| d.rollup.is_some()).collect();
        assert_eq!(rollups.len(), 2);

        let a_rollup = rollups.iter().find(|d| d.path == "a.rs").unwrap();
        assert_eq!(a_rollup.rollup.as_ref().unwrap().count, 3);

        let b_rollup = rollups.iter().find(|d| d.path == "b.rs").unwrap();
        assert_eq!(b_rollup.rollup.as_ref().unwrap().count, 2);
    }

    #[test]
    fn rollup_examples_limited() {
        let mut diags: Vec<Diag> = (1..=20)
            .map(|i| {
                make_diag(
                    "a.rs",
                    i,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                )
            })
            .collect();
        let mut cfg = default_config();
        cfg.include_quality = true;
        cfg.rollup_examples = 3;
        let _stats = prioritize(&mut diags, &cfg, None);

        let rollup = diags.iter().find(|d| d.rollup.is_some()).unwrap();
        assert_eq!(rollup.rollup.as_ref().unwrap().count, 20);
        assert_eq!(rollup.rollup.as_ref().unwrap().occurrences.len(), 3);
    }

    #[test]
    fn rollup_canonical_is_first_sorted() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                50,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                10,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                30,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        let _stats = prioritize(&mut diags, &cfg, None);

        let rollup = diags.iter().find(|d| d.rollup.is_some()).unwrap();
        assert_eq!(rollup.line, 10); // canonical = first sorted
    }

    #[test]
    fn low_budget_per_file() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "some-rule",
                FindingCategory::Security,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Low,
                "some-rule-2",
                FindingCategory::Security,
            ),
            make_diag(
                "b.rs",
                1,
                Severity::Low,
                "some-rule",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.max_low_per_file = 1;
        cfg.max_low = 100;
        cfg.max_low_per_rule = 100;
        let stats = prioritize(&mut diags, &cfg, None);
        // a.rs: only 1 LOW kept, b.rs: 1 LOW kept
        assert_eq!(diags.len(), 2);
        assert_eq!(stats.low_budget_dropped, 1);
    }

    #[test]
    fn low_budget_per_rule() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rule-x",
                FindingCategory::Security,
            ),
            make_diag(
                "b.rs",
                1,
                Severity::Low,
                "rule-x",
                FindingCategory::Security,
            ),
            make_diag(
                "c.rs",
                1,
                Severity::Low,
                "rule-x",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.max_low_per_file = 100;
        cfg.max_low = 100;
        cfg.max_low_per_rule = 2;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 2);
        assert_eq!(stats.low_budget_dropped, 1);
    }

    #[test]
    fn low_budget_total() {
        let mut diags: Vec<Diag> = (1..=5)
            .map(|i| {
                make_diag(
                    &format!("f{i}.rs"),
                    1,
                    Severity::Low,
                    &format!("rule-{i}"),
                    FindingCategory::Security,
                )
            })
            .collect();
        let mut cfg = default_config();
        cfg.max_low_per_file = 100;
        cfg.max_low_per_rule = 100;
        cfg.max_low = 3;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 3);
        assert_eq!(stats.low_budget_dropped, 2);
    }

    #[test]
    fn high_medium_never_dropped_by_low_budget() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::High,
                "vuln-1",
                FindingCategory::Security,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Medium,
                "vuln-2",
                FindingCategory::Security,
            ),
            make_diag(
                "a.rs",
                3,
                Severity::Low,
                "vuln-3",
                FindingCategory::Security,
            ),
        ];
        let mut cfg = default_config();
        cfg.max_low = 0;
        cfg.max_low_per_file = 0;
        cfg.max_low_per_rule = 0;
        let stats = prioritize(&mut diags, &cfg, None);
        assert_eq!(diags.len(), 2); // High + Medium kept
        assert!(diags.iter().all(|d| d.severity != Severity::Low));
        assert_eq!(stats.low_budget_dropped, 1);
    }

    #[test]
    fn rollup_counts_as_one_for_budget() {
        // 10 unwrap findings in same file → 1 rollup → counts as 1 LOW
        let mut diags: Vec<Diag> = (1..=10)
            .map(|i| {
                make_diag(
                    "a.rs",
                    i,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                )
            })
            .collect();
        // Add another LOW finding from a different rule
        diags.push(make_diag(
            "a.rs",
            100,
            Severity::Low,
            "other-rule",
            FindingCategory::Security,
        ));

        let mut cfg = default_config();
        cfg.include_quality = true;
        cfg.max_low_per_file = 2; // allow 2 per file
        cfg.max_low = 100;
        cfg.max_low_per_rule = 100;
        let _stats = prioritize(&mut diags, &cfg, None);

        // Should have rollup (1) + other-rule (1) = 2
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn show_instances_bypasses_rollup_for_rule() {
        let mut diags = vec![
            make_diag(
                "a.rs",
                1,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                2,
                Severity::Low,
                "rs.quality.unwrap",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                3,
                Severity::Low,
                "rs.quality.expect",
                FindingCategory::Quality,
            ),
            make_diag(
                "a.rs",
                4,
                Severity::Low,
                "rs.quality.expect",
                FindingCategory::Quality,
            ),
        ];
        let mut cfg = default_config();
        cfg.include_quality = true;
        cfg.max_low = 100;
        cfg.max_low_per_file = 100;
        cfg.max_low_per_rule = 100;
        let _stats = prioritize(&mut diags, &cfg, Some("rs.quality.unwrap"));

        // unwrap not rolled up (2 individual), expect rolled up (1 rollup)
        let unwrap_count = diags.iter().filter(|d| d.id == "rs.quality.unwrap").count();
        let expect_rollup = diags
            .iter()
            .find(|d| d.id == "rs.quality.expect" && d.rollup.is_some());
        assert_eq!(unwrap_count, 2);
        assert!(expect_rollup.is_some());
    }

    #[test]
    fn json_includes_rollup_data() {
        let d = Diag {
            path: "a.rs".into(),
            line: 10,
            col: 1,
            severity: Severity::Low,
            id: "rs.quality.unwrap".into(),
            category: FindingCategory::Quality,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: Some(RollupData {
                count: 38,
                occurrences: vec![Location { line: 10, col: 1 }, Location { line: 20, col: 5 }],
            }),
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"rollup\""));
        assert!(json.contains("\"count\":38"));
        assert!(json.contains("\"occurrences\""));
    }

    #[test]
    fn deterministic_output() {
        let make_diags = || {
            vec![
                make_diag(
                    "b.rs",
                    5,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
                make_diag(
                    "a.rs",
                    10,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
                make_diag(
                    "a.rs",
                    3,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
                make_diag(
                    "b.rs",
                    1,
                    Severity::Low,
                    "rs.quality.unwrap",
                    FindingCategory::Quality,
                ),
            ]
        };
        let mut cfg = default_config();
        cfg.include_quality = true;

        let mut d1 = make_diags();
        let mut d2 = make_diags();
        let _s1 = prioritize(&mut d1, &cfg, None);
        let _s2 = prioritize(&mut d2, &cfg, None);

        let j1 = serde_json::to_string(&d1).unwrap();
        let j2 = serde_json::to_string(&d2).unwrap();
        assert_eq!(j1, j2, "same input should produce same output");
    }
}

#[cfg(test)]
mod stable_hash_tests {
    use super::*;
    use crate::evidence::Evidence;
    use crate::labels::Cap;
    use crate::patterns::{FindingCategory, Severity};

    fn base_diag() -> Diag {
        Diag {
            path: "src/handler.rs".into(),
            line: 42,
            col: 5,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: Some(Evidence {
                sink_caps: Cap::SQL_QUERY.bits(),
                ..Default::default()
            }),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        }
    }

    #[test]
    fn compute_stable_hash_is_deterministic() {
        let d = base_diag();
        let h1 = compute_stable_hash(&d);
        let h2 = compute_stable_hash(&d);
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }

    #[test]
    fn compute_stable_hash_sensitive_to_rule_id() {
        let d1 = base_diag();
        let mut d2 = base_diag();
        d2.id = "taint-unsanitised-flow (source 5:1)".into();
        assert_ne!(compute_stable_hash(&d1), compute_stable_hash(&d2));
    }

    #[test]
    fn compute_stable_hash_sensitive_to_path() {
        let d1 = base_diag();
        let mut d2 = base_diag();
        d2.path = "src/other.rs".into();
        assert_ne!(compute_stable_hash(&d1), compute_stable_hash(&d2));
    }

    #[test]
    fn compute_stable_hash_sensitive_to_line() {
        let d1 = base_diag();
        let mut d2 = base_diag();
        d2.line = 43;
        assert_ne!(compute_stable_hash(&d1), compute_stable_hash(&d2));
    }

    #[test]
    fn compute_stable_hash_sensitive_to_col() {
        let d1 = base_diag();
        let mut d2 = base_diag();
        d2.col = 6;
        assert_ne!(compute_stable_hash(&d1), compute_stable_hash(&d2));
    }

    #[test]
    fn compute_stable_hash_sensitive_to_sink_caps() {
        let d1 = base_diag();
        let mut d2 = base_diag();
        d2.evidence = Some(Evidence {
            sink_caps: Cap::CODE_EXEC.bits(),
            ..Default::default()
        });
        assert_ne!(compute_stable_hash(&d1), compute_stable_hash(&d2));
    }

    #[test]
    fn compute_stable_hash_collision_resistance() {
        let d1 = Diag {
            path: "src/a.rs".into(),
            line: 1,
            col: 0,
            id: "rule-x".into(),
            ..base_diag()
        };
        let d2 = Diag {
            path: "src/b.rs".into(),
            line: 1,
            col: 0,
            id: "rule-x".into(),
            ..base_diag()
        };
        let d3 = Diag {
            path: "src/a.rs".into(),
            line: 2,
            col: 0,
            id: "rule-x".into(),
            ..base_diag()
        };
        let h1 = compute_stable_hash(&d1);
        let h2 = compute_stable_hash(&d2);
        let h3 = compute_stable_hash(&d3);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }
}

//! Top-level entry point for the dynamic layer.
//!
//! The CLI subcommand and any library consumer call [`verify_finding`].
//! It is the only function the rest of the crate needs to know about.

use crate::callgraph::CallGraph;
use crate::commands::scan::Diag;
use crate::dynamic::corpus::{payloads_for, CORPUS_VERSION};
use crate::dynamic::oob::OobListener;
use crate::dynamic::report::{AttemptSummary, VerifyResult, VerifyStatus};
use crate::dynamic::runner::{run_spec, RunError};
use crate::dynamic::sandbox::{toolchain_id_with_digest, SandboxOptions};
use crate::dynamic::spec::{HarnessSpec, SPEC_FORMAT_VERSION};
use crate::dynamic::telemetry::{self, TelemetryEvent};
use crate::dynamic::toolchain;
use crate::evidence::{InconclusiveReason, SpecDerivationStrategy, UnsupportedReason};
use crate::summary::GlobalSummaries;
use crate::utils::config::Config;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub sandbox: SandboxOptions,
    /// Project root for repro artifact symlinks (optional).
    pub project_root: Option<std::path::PathBuf>,
    /// Path to the Nyx index database for the dynamic verdict cache (§12 Q5).
    /// When `None` (e.g. `--no-index` mode), the cache is bypassed entirely.
    pub db_path: Option<std::path::PathBuf>,
    /// When `true`, skip the `Confidence >= Medium` gate and attempt
    /// verification on all findings. Corresponds to `--verify-all-confidence`.
    pub verify_all_confidence: bool,
    /// Cross-file function summaries shared by every finding in a scan.
    ///
    /// Threaded into [`HarnessSpec::from_finding_with_summaries`] so the
    /// summary-walk strategy and the entry-kind-aware callgraph strategy
    /// can resolve the diag's enclosing function against the same
    /// [`GlobalSummaries`] index the taint engine used. Held by `Arc` so the
    /// caller (e.g. the scan command) can build the index once and reuse it
    /// across the per-finding loop without cloning.
    ///
    /// `None` disables the summary-driven derivation paths; strategy 3 is a
    /// no-op and strategy 4 falls back to the rule-id substring heuristic.
    pub summaries: Option<Arc<GlobalSummaries>>,
    /// Whole-program [`CallGraph`] threaded into the callgraph-aware
    /// branch of strategy 4 ([`SpecDerivationStrategy::FromCallgraphEntry`]).
    ///
    /// When present alongside [`Self::summaries`], the verifier walks
    /// reverse edges from the sink's enclosing function to the nearest
    /// entry-point ancestor (route handler, CLI subcommand, `main`).
    /// `None` keeps strategy 4 on the legacy rule-id substring path.
    pub callgraph: Option<Arc<CallGraph>>,
}

impl VerifyOptions {
    /// Build `VerifyOptions` from scanner config.
    ///
    /// Binds a per-scan [`OobListener`] on a free loopback port and attaches
    /// it to `sandbox.oob_listener`. The listener is held by `Arc` so every
    /// per-finding clone of `VerifyOptions` shares the same accept thread;
    /// it is torn down via the `OobListener::Drop` impl once the last
    /// `Arc` is released at end of scan.
    ///
    /// If `OobListener::bind` fails (e.g. all loopback ports are in use),
    /// the field stays `None`; the runner skips OOB-callback payloads
    /// (`src/dynamic/runner.rs` `oob_nonce_slot` branch) while non-OOB
    /// payloads continue to run against their existing oracle.
    pub fn from_config(config: &Config) -> Self {
        use crate::dynamic::sandbox::SandboxBackend;
        let backend = match config.scanner.verify_backend.as_str() {
            "docker" => SandboxBackend::Docker,
            "process" => SandboxBackend::Process,
            _ => SandboxBackend::Auto,
        };
        let oob_listener = OobListener::bind().ok().map(Arc::new);
        Self {
            sandbox: SandboxOptions {
                backend,
                oob_listener,
                ..SandboxOptions::default()
            },
            project_root: None,
            db_path: None,
            verify_all_confidence: config.scanner.verify_all_confidence,
            summaries: None,
            callgraph: None,
        }
    }
}

// ── Dynamic verdict cache helpers (§12 Q5) ───────────────────────────────────

/// Hash the content of `entry_file` with BLAKE3 and return a 16-char hex string.
///
/// Returns `"unavailable"` when the file cannot be read (e.g. the finding
/// points to a file that no longer exists). The cache simply misses in that case.
fn compute_entry_content_hash(entry_file: &str) -> String {
    std::fs::read(entry_file)
        .map(|bytes| {
            let h = blake3::hash(&bytes);
            format!(
                "{:016x}",
                u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap())
            )
        })
        .unwrap_or_else(|_| "unavailable".to_owned())
}

/// Placeholder transitive import digest.
///
/// Full transitive import analysis is deferred. The empty string is a valid
/// conservative placeholder: a stale cache hit can only occur when a transitive
/// import changes without the entry file changing, which is rare and unlikely to
/// cause incorrect verdicts given the harness is also re-confirmed by the oracle.
fn transitive_import_digest_placeholder() -> &'static str {
    ""
}

/// Look up a cached verdict in the `dynamic_verdict_cache` table.
///
/// Opens the DB in read-write mode (no-create) so it never creates a DB that
/// does not yet exist. Returns `None` on any error or cache miss.
fn lookup_verdict_cache(
    db_path: &std::path::Path,
    spec_hash: &str,
    entry_content_hash: &str,
    transitive_import_digest: &str,
    toolchain_id: &str,
) -> Option<VerifyResult> {
    use rusqlite::{Connection, OpenFlags};
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(db_path, flags).ok()?;
    conn.query_row(
        "SELECT verdict_json FROM dynamic_verdict_cache \
         WHERE spec_hash = ?1 AND entry_content_hash = ?2 \
         AND transitive_import_digest = ?3 AND toolchain_id = ?4 \
         AND corpus_version = ?5 AND spec_format_version = ?6 \
         LIMIT 1",
        rusqlite::params![
            spec_hash,
            entry_content_hash,
            transitive_import_digest,
            toolchain_id,
            CORPUS_VERSION as i64,
            SPEC_FORMAT_VERSION as i64,
        ],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|json| serde_json::from_str(&json).ok())
}

/// Insert or replace a verdict in the `dynamic_verdict_cache` table.
///
/// Best-effort: silently ignores all errors (DB unavailable, serialisation
/// failure, UNIQUE constraint violation, etc.). The cache is an optimisation;
/// a miss is never fatal.
fn insert_verdict_cache(
    db_path: &std::path::Path,
    spec_hash: &str,
    entry_content_hash: &str,
    transitive_import_digest: &str,
    toolchain_id: &str,
    result: &VerifyResult,
) {
    use rusqlite::{Connection, OpenFlags};
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(db_path, flags) else {
        return;
    };
    let Ok(json) = serde_json::to_string(result) else {
        return;
    };
    let now = chrono::Utc::now().to_rfc3339();
    let _ = conn.execute(
        "INSERT OR REPLACE INTO dynamic_verdict_cache \
         (spec_hash, entry_content_hash, transitive_import_digest, toolchain_id, \
          corpus_version, spec_format_version, verdict_json, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            spec_hash,
            entry_content_hash,
            transitive_import_digest,
            toolchain_id,
            CORPUS_VERSION as i64,
            SPEC_FORMAT_VERSION as i64,
            json,
            now,
        ],
    );
}

/// Build an `Inconclusive(EntryKindUnsupported)` verdict for a finding whose
/// derived spec named an entry kind the lang emitter does not yet handle.
///
/// `attempted` is the spec's entry kind; `lang` is the spec's language; the
/// supported list and human-readable hint come from the lang emitter via
/// [`crate::dynamic::lang::entry_kinds_supported`] /
/// [`crate::dynamic::lang::entry_kind_hint`], so adding new shapes in later
/// Track B phases automatically narrows what gets routed here without
/// touching this function.
///
/// The caller passes the originating [`Diag`] when one is in scope (for the
/// pre-flight gate) or `None` otherwise (for the residual harness-emit path,
/// where only the spec is available); telemetry derives `lang`/`path` from
/// the diag when present and falls back to the spec otherwise.
fn entry_kind_unsupported_verdict(
    finding_id: String,
    diag: Option<&Diag>,
    spec_entry_path: &str,
    lang: crate::symbol::Lang,
    attempted: crate::dynamic::spec::EntryKind,
) -> VerifyResult {
    let supported = crate::dynamic::lang::entry_kinds_supported(lang).to_vec();
    let hint = crate::dynamic::lang::entry_kind_hint(lang, attempted);
    let inconclusive_reason = InconclusiveReason::EntryKindUnsupported {
        lang,
        attempted,
        supported,
        hint,
    };
    let event = match diag {
        Some(d) => TelemetryEvent::no_spec(
            d,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        ),
        None => TelemetryEvent::no_spec_for_path(
            spec_entry_path,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        ),
    };
    telemetry::emit(&event);
    VerifyResult {
        finding_id,
        status: VerifyStatus::Inconclusive,
        triggered_payload: None,
        reason: None,
        inconclusive_reason: Some(inconclusive_reason),
        detail: None,
        attempts: vec![],
        toolchain_match: None,
    }
}

/// Decide whether a [`HarnessSpec::from_finding_opts`] failure should surface
/// as `Unsupported` (the finding is genuinely unmodellable) or
/// `Inconclusive(SpecDerivationFailed)` (the rule namespace or sink evidence
/// carried enough signal that derivation *should* have worked).
///
/// The rule-of-thumb: if any spec-derivation strategy could plausibly have
/// fired (i.e. the finding had a usable rule namespace, non-empty path, or
/// non-zero sink caps) yet none produced a spec, the failure is
/// **Inconclusive** — we tried and missed. Otherwise it's **Unsupported**.
fn spec_derivation_failed_verdict(
    finding_id: String,
    diag: &Diag,
    reason: UnsupportedReason,
) -> VerifyResult {
    if matches!(reason, UnsupportedReason::SpecDerivationFailed) && should_be_inconclusive(diag) {
        let strategies: Vec<SpecDerivationStrategy> =
            HarnessSpec::derivation_strategies().to_vec();
        let hint = derivation_failure_hint(diag);
        let inconclusive_reason = InconclusiveReason::SpecDerivationFailed {
            tried: strategies,
            hint,
        };
        let event = TelemetryEvent::no_spec(
            diag,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        );
        telemetry::emit(&event);
        return VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(inconclusive_reason),
            detail: None,
            attempts: vec![],
            toolchain_match: None,
        };
    }

    let event = TelemetryEvent::no_spec(diag, VerifyStatus::Unsupported, None);
    telemetry::emit(&event);

    VerifyResult {
        finding_id,
        status: VerifyStatus::Unsupported,
        triggered_payload: None,
        reason: Some(reason),
        inconclusive_reason: None,
        detail: None,
        attempts: vec![],
        toolchain_match: None,
    }
}

/// True when the finding has *some* derivable signal (rule namespace, sink
/// caps, or evidence) so a spec-derivation failure should be surfaced as
/// `Inconclusive` rather than `Unsupported`.
fn should_be_inconclusive(diag: &Diag) -> bool {
    let has_rule_ns = diag.id.split('.').count() >= 2
        && !diag.id.starts_with("taint-")
        && !diag.id.starts_with("cfg-")
        && !diag.id.starts_with("state-");
    let has_evidence = diag
        .evidence
        .as_ref()
        .map(|e| e.sink_caps != 0 || !e.flow_steps.is_empty() || e.sink.is_some())
        .unwrap_or(false);
    has_rule_ns || has_evidence
}

fn derivation_failure_hint(diag: &Diag) -> String {
    let ev = match diag.evidence.as_ref() {
        Some(e) => e,
        None => return "no evidence on finding".to_owned(),
    };
    let mut parts: Vec<String> = Vec::new();
    if !diag.id.is_empty() {
        parts.push(format!("rule_id={}", diag.id));
    }
    if ev.sink_caps == 0 {
        parts.push("sink_caps=0".to_owned());
    }
    if ev.flow_steps.is_empty() {
        parts.push("no_flow_steps".to_owned());
    }
    if diag.path.is_empty() {
        parts.push("empty_path".to_owned());
    } else {
        parts.push(format!("path={}", diag.path));
    }
    parts.join("; ")
}

/// Try to dynamically confirm a static finding.
///
/// Never fails: every error path collapses into a [`VerifyStatus`] so the
/// caller can treat dynamic verification as best-effort enrichment.
pub fn verify_finding(diag: &Diag, opts: &VerifyOptions) -> VerifyResult {
    let finding_id = format!("{:016x}", diag.stable_hash);

    let spec = match HarnessSpec::from_finding_full(
        diag,
        opts.verify_all_confidence,
        opts.summaries.as_deref(),
        opts.callgraph.as_deref(),
    ) {
        Ok(s) => s,
        Err(reason) => {
            return spec_derivation_failed_verdict(finding_id, diag, reason);
        }
    };

    // Pre-flight gate: surface a structured `Inconclusive(EntryKindUnsupported)`
    // up-front when the spec's [`EntryKind`] is not in the lang emitter's
    // supported list.  Without this, the same condition would degrade silently
    // through `lang::emit -> HarnessError::Unsupported` and lose the
    // supported-list / hint context the operator needs to triage.
    if !spec.entry_kind_is_supported() {
        return entry_kind_unsupported_verdict(
            finding_id,
            Some(diag),
            &spec.entry_file,
            spec.lang,
            spec.entry_kind,
        );
    }

    // Scan the entry file's directory for sensitive files (§17.3 mount filter).
    // If the entry file itself matches a sensitive pattern, refuse to run it:
    // the harness would copy it into the workdir and expose secrets.
    {
        let entry_path = Path::new(&spec.entry_file);
        let scan_dir = entry_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let notes = crate::dynamic::mount_filter::scan_sensitive_files(scan_dir);
        for note in &notes {
            let note_abs = scan_dir.join(&note.path);
            if entry_path == note_abs {
                return VerifyResult {
                    finding_id,
                    status: VerifyStatus::Unsupported,
                    triggered_payload: None,
                    reason: Some(UnsupportedReason::RequiredFileRedactedForSecrets(
                        note.path.clone(),
                    )),
                    inconclusive_reason: None,
                    detail: None,
                    attempts: vec![],
                    toolchain_match: None,
                };
            }
        }
    }

    // Resolve toolchain information (lang-aware: §22.2).
    use crate::symbol::Lang;
    let toolchain_res = match spec.lang {
        Lang::Rust => toolchain::resolve_rust(Path::new(".")),
        Lang::JavaScript | Lang::TypeScript => toolchain::resolve_node(Path::new(".")),
        Lang::Go => toolchain::resolve_go(Path::new(".")),
        Lang::Java => toolchain::resolve_java(Path::new(".")),
        Lang::Php => toolchain::resolve_php(Path::new(".")),
        _ => toolchain::resolve_python(Path::new(".")),
    };
    let toolchain_match = if toolchain_res.toolchain_drift { "drift" } else { "exact" };
    // Enrich the resolved toolchain_id with the Docker image digest (§22.1).
    // The enriched ID is used as the toolchain_id component of the verdict cache
    // key so that image updates always invalidate stale cache entries.
    let effective_toolchain_id = toolchain_id_with_digest(&toolchain_res.toolchain_id);

    // Verdict cache lookup (§12 Q5): skip execution when a valid cached result exists.
    let entry_hash = compute_entry_content_hash(&spec.entry_file);
    let import_digest = transitive_import_digest_placeholder();
    if let Some(ref db_path) = opts.db_path {
        if let Some(cached) = lookup_verdict_cache(
            db_path,
            &spec.spec_hash,
            &entry_hash,
            import_digest,
            &effective_toolchain_id,
        ) {
            return cached;
        }
    }

    let start = Instant::now();
    let result = run_spec(&spec, &opts.sandbox);
    let elapsed = start.elapsed();

    // Extract build_attempts before result is consumed by build_verdict.
    let build_attempts = match &result {
        Ok(run) => run.build_attempts,
        Err(RunError::BuildFailed { attempts, .. }) => *attempts,
        _ => 1,
    };

    let verdict = build_verdict(
        &finding_id,
        &spec,
        result,
        toolchain_match,
        opts,
        elapsed,
    );

    // Store result in verdict cache (best-effort; errors are silently ignored).
    if let Some(ref db_path) = opts.db_path {
        insert_verdict_cache(
            db_path,
            &spec.spec_hash,
            &entry_hash,
            import_digest,
            &effective_toolchain_id,
            &verdict,
        );
    }

    // Emit telemetry (best-effort; never affects verdict).
    let event = TelemetryEvent::new(
        &spec,
        verdict.status,
        verdict.inconclusive_reason.clone(),
        toolchain_match,
        elapsed,
        build_attempts,
    );
    telemetry::emit(&event);

    verdict
}

fn build_verdict(
    finding_id: &str,
    spec: &HarnessSpec,
    result: Result<crate::dynamic::runner::RunOutcome, RunError>,
    toolchain_match: &str,
    opts: &VerifyOptions,
    _elapsed: std::time::Duration,
) -> VerifyResult {
    match result {
        Ok(run) => {
            let attempts: Vec<AttemptSummary> = run
                .attempts
                .iter()
                .map(|a| AttemptSummary {
                    payload_label: a.payload_label.to_string(),
                    exit_code: a.outcome.exit_code,
                    timed_out: a.outcome.timed_out,
                    triggered: a.triggered,
                    sink_hit: a.outcome.sink_hit,
                })
                .collect();

            if let Some(i) = run.triggered_by {
                let triggered_payload = run.attempts[i].payload_label.to_string();
                let payloads = payloads_for(spec.expected_cap);
                let vuln_payloads: Vec<_> = payloads.iter().filter(|p| !p.is_benign).collect();
                let payload_bytes = vuln_payloads
                    .get(i)
                    .map(|p| p.bytes)
                    .unwrap_or(b"");

                // Emit repro artifact.
                let repro_result = crate::dynamic::repro::write(
                    spec,
                    &opts.sandbox,
                    &run.attempts[i].outcome,
                    &VerifyResult {
                        finding_id: finding_id.to_owned(),
                        status: VerifyStatus::Confirmed,
                        triggered_payload: Some(triggered_payload.clone()),
                        reason: None,
                        inconclusive_reason: None,
                        detail: None,
                        attempts: attempts.clone(),
                        toolchain_match: Some(toolchain_match.to_owned()),
                    },
                    &run.harness_source,
                    &run.entry_source,
                    payload_bytes,
                    run.attempts[i].payload_label,
                    opts.project_root.as_deref(),
                );

                // If repro write fails, downgrade to NonReproducible.
                if repro_result.is_err() {
                    return VerifyResult {
                        finding_id: finding_id.to_owned(),
                        status: VerifyStatus::Inconclusive,
                        triggered_payload: None,
                        reason: None,
                        inconclusive_reason: Some(InconclusiveReason::NonReproducible),
                        detail: Some(format!("repro write failed: {}", repro_result.unwrap_err())),
                        attempts,
                        toolchain_match: Some(toolchain_match.to_owned()),
                    };
                }

                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Confirmed,
                    triggered_payload: Some(triggered_payload),
                    reason: None,
                    inconclusive_reason: None,
                    detail: None,
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                }
            } else if run.oracle_collision {
                // Oracle fired but probe didn't — likely collision.
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Inconclusive,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: Some(InconclusiveReason::OracleCollisionSuspected),
                    detail: Some("oracle fired but sink-reachability probe did not".to_owned()),
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                }
            } else {
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::NotConfirmed,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: None,
                    detail: None,
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                }
            }
        }
        Err(RunError::NoPayloadsForCap) => VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::NoPayloadsForCap),
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
        },
        Err(RunError::Harness(e)) => {
            // Defence-in-depth residual for `EntryKindUnsupported` from the
            // lang dispatcher. Promote to `Inconclusive(EntryKindUnsupported)`
            // so the operator sees the supported list + hint, but only when
            // the spec's entry kind is genuinely outside the supported list —
            // otherwise the pre-flight gate already handled it (or a stray
            // emitter mis-tagged a payload-slot rejection, which now uses
            // `PayloadSlotUnsupported` and falls through to the generic
            // `Unsupported(reason)` arm below).
            if let crate::dynamic::harness::HarnessError::Unsupported(
                UnsupportedReason::EntryKindUnsupported,
            ) = &e
            {
                let supported = crate::dynamic::lang::entry_kinds_supported(spec.lang);
                if !supported.contains(&spec.entry_kind) {
                    return entry_kind_unsupported_verdict(
                        finding_id.to_owned(),
                        None,
                        &spec.entry_file,
                        spec.lang,
                        spec.entry_kind,
                    );
                }
            }
            // Typed `Unsupported(reason)` carries its semantics in `reason`; the
            // free-form `detail` is reserved for `Inconclusive`/unexpected paths
            // (cf. §10 decision 14 and the verify_result_json_shape contract).
            let (reason, detail) = match &e {
                crate::dynamic::harness::HarnessError::Unsupported(r) => (Some(r.clone()), None),
                _ => (Some(UnsupportedReason::BackendUnavailable), Some(format!("{e}"))),
            };
            VerifyResult {
                finding_id: finding_id.to_owned(),
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason,
                inconclusive_reason: None,
                detail,
                attempts: vec![],
                toolchain_match: None,
            }
        }
        Err(RunError::BuildFailed { stderr, attempts: build_att }) => VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::BuildFailed),
            detail: Some(format!("build failed after {build_att} attempts: {stderr}")),
            attempts: vec![],
            toolchain_match: None,
        },
        Err(RunError::Sandbox(e)) => VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::SandboxError),
            detail: Some(format!("sandbox failed: {e:?}")),
            attempts: vec![],
            toolchain_match: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_entry_content_hash_stable_for_same_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("entry.py");
        std::fs::write(&path, b"def run(x): pass\n").unwrap();
        let h1 = compute_entry_content_hash(path.to_str().unwrap());
        let h2 = compute_entry_content_hash(path.to_str().unwrap());
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_ne!(h1, "unavailable");
    }

    #[test]
    fn compute_entry_content_hash_different_for_different_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let p1 = dir.path().join("a.py");
        let p2 = dir.path().join("b.py");
        std::fs::write(&p1, b"def run(x): return x\n").unwrap();
        std::fs::write(&p2, b"def run(x): return x + 1\n").unwrap();
        let h1 = compute_entry_content_hash(p1.to_str().unwrap());
        let h2 = compute_entry_content_hash(p2.to_str().unwrap());
        assert_ne!(h1, h2, "different content must produce different hashes");
    }

    #[test]
    fn compute_entry_content_hash_missing_file_returns_unavailable() {
        let h = compute_entry_content_hash("/tmp/nyx_test_nonexistent_entry_file_99999.py");
        assert_eq!(h, "unavailable");
    }

    #[test]
    fn transitive_import_digest_placeholder_is_stable() {
        assert_eq!(transitive_import_digest_placeholder(), "");
    }

    #[test]
    fn verdict_cache_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        // Create and initialize the DB with the required schema.
        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    spec_hash TEXT NOT NULL,
                    entry_content_hash TEXT NOT NULL,
                    transitive_import_digest TEXT NOT NULL,
                    toolchain_id TEXT NOT NULL,
                    corpus_version INTEGER NOT NULL,
                    spec_format_version INTEGER NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                           toolchain_id, corpus_version, spec_format_version)
                );",
            )
            .unwrap();
        }

        let result = VerifyResult {
            finding_id: "test_finding_0001".to_owned(),
            status: crate::evidence::VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".to_owned()),
        };

        // Insert.
        insert_verdict_cache(&db_path, "spec_abc", "hash_xyz", "", "python-3.11", &result);

        // Lookup — should return the same result.
        let cached = lookup_verdict_cache(&db_path, "spec_abc", "hash_xyz", "", "python-3.11");
        assert!(cached.is_some(), "cache hit expected after insert");
        let cached = cached.unwrap();
        assert_eq!(cached.finding_id, "test_finding_0001");
        assert_eq!(cached.status, crate::evidence::VerifyStatus::NotConfirmed);
    }

    #[test]
    fn verdict_cache_miss_on_different_spec_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    spec_hash TEXT NOT NULL,
                    entry_content_hash TEXT NOT NULL,
                    transitive_import_digest TEXT NOT NULL,
                    toolchain_id TEXT NOT NULL,
                    corpus_version INTEGER NOT NULL,
                    spec_format_version INTEGER NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                           toolchain_id, corpus_version, spec_format_version)
                );",
            )
            .unwrap();
        }

        let result = VerifyResult {
            finding_id: "test_finding_0002".to_owned(),
            status: crate::evidence::VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".to_owned()),
        };

        insert_verdict_cache(&db_path, "spec_aaa", "hash_xyz", "", "python-3.11", &result);

        // Different spec_hash → miss.
        let miss = lookup_verdict_cache(&db_path, "spec_bbb", "hash_xyz", "", "python-3.11");
        assert!(miss.is_none(), "different spec_hash must be a cache miss");
    }

    #[test]
    fn verdict_cache_returns_none_for_nonexistent_db() {
        let result = lookup_verdict_cache(
            std::path::Path::new("/tmp/nyx_nonexistent_verdict_cache_99999.db"),
            "spec_abc",
            "hash_xyz",
            "",
            "python-3.11",
        );
        assert!(result.is_none(), "non-existent DB must return None");
    }

    #[test]
    fn insert_verdict_cache_is_noop_for_nonexistent_db() {
        // Should not panic or create the DB.
        let db_path = std::path::Path::new("/tmp/nyx_nonexistent_verdict_cache_insert_99999.db");
        let result = VerifyResult {
            finding_id: "test".to_owned(),
            status: crate::evidence::VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
        };
        insert_verdict_cache(db_path, "spec", "hash", "", "python-3", &result);
        assert!(!db_path.exists(), "insert must not create a new DB");
    }

    /// Verify that a cache entry keyed on an older corpus_version is a miss
    /// once CORPUS_VERSION is bumped.  This proves the cache invalidation
    /// mechanic in §15.4 / Pillar D: changing a payload's cap evicts stale entries.
    ///
    /// The test simulates a bump by inserting with an old version literal and
    /// then looking up with the current CORPUS_VERSION (which is the default).
    #[test]
    fn dynamic_verdict_cache_corpus_version_invalidation() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test_corp_ver.db");

        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    spec_hash TEXT NOT NULL,
                    entry_content_hash TEXT NOT NULL,
                    transitive_import_digest TEXT NOT NULL,
                    toolchain_id TEXT NOT NULL,
                    corpus_version INTEGER NOT NULL,
                    spec_format_version INTEGER NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                           toolchain_id, corpus_version, spec_format_version)
                );",
            )
            .unwrap();
        }

        // The current CORPUS_VERSION is 3.  Simulate an entry from version 2.
        let stale_corpus_version = CORPUS_VERSION.saturating_sub(1);
        assert!(
            stale_corpus_version < CORPUS_VERSION,
            "test requires CORPUS_VERSION > 1"
        );

        let result = VerifyResult {
            finding_id: "stale_entry".to_owned(),
            status: crate::evidence::VerifyStatus::Confirmed,
            triggered_payload: Some("sqli-tautology".to_owned()),
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".to_owned()),
        };

        // Insert directly with the old corpus_version bypassing the helper.
        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            let json = serde_json::to_string(&result).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT OR REPLACE INTO dynamic_verdict_cache \
                 (spec_hash, entry_content_hash, transitive_import_digest, toolchain_id, \
                  corpus_version, spec_format_version, verdict_json, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    "spec_stale",
                    "hash_stale",
                    "",
                    "python-3.11",
                    stale_corpus_version as i64,
                    SPEC_FORMAT_VERSION as i64,
                    json,
                    now,
                ],
            )
            .unwrap();
        }

        // Lookup using current CORPUS_VERSION → must be a MISS.
        let miss = lookup_verdict_cache(&db_path, "spec_stale", "hash_stale", "", "python-3.11");
        assert!(
            miss.is_none(),
            "stale corpus_version ({stale_corpus_version}) must not match current CORPUS_VERSION ({CORPUS_VERSION})"
        );

        // Insert with current CORPUS_VERSION → must be a HIT.
        insert_verdict_cache(&db_path, "spec_stale", "hash_stale", "", "python-3.11", &result);
        let hit = lookup_verdict_cache(&db_path, "spec_stale", "hash_stale", "", "python-3.11");
        assert!(
            hit.is_some(),
            "current corpus_version entry must be a cache hit"
        );
    }
}

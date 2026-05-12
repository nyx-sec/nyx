//! Top-level entry point for the dynamic layer.
//!
//! The CLI subcommand and any library consumer call [`verify_finding`].
//! It is the only function the rest of the crate needs to know about.

use crate::commands::scan::Diag;
use crate::dynamic::corpus::payloads_for;
use crate::dynamic::report::{AttemptSummary, VerifyResult, VerifyStatus};
use crate::dynamic::runner::{run_spec, RunError};
use crate::dynamic::sandbox::SandboxOptions;
use crate::dynamic::spec::HarnessSpec;
use crate::dynamic::telemetry::{self, TelemetryEvent};
use crate::dynamic::toolchain;
use crate::evidence::{InconclusiveReason, UnsupportedReason};
use crate::utils::config::Config;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub sandbox: SandboxOptions,
    /// Project root for repro artifact symlinks (optional).
    pub project_root: Option<std::path::PathBuf>,
}

impl VerifyOptions {
    /// Build `VerifyOptions` from scanner config.
    pub fn from_config(config: &Config) -> Self {
        use crate::dynamic::sandbox::SandboxBackend;
        let backend = match config.scanner.verify_backend.as_str() {
            "docker" => SandboxBackend::Docker,
            "process" => SandboxBackend::Process,
            _ => SandboxBackend::Auto,
        };
        Self {
            sandbox: SandboxOptions {
                backend,
                ..SandboxOptions::default()
            },
            project_root: None,
        }
    }
}

/// Try to dynamically confirm a static finding.
///
/// Never fails: every error path collapses into a [`VerifyStatus`] so the
/// caller can treat dynamic verification as best-effort enrichment.
pub fn verify_finding(diag: &Diag, opts: &VerifyOptions) -> VerifyResult {
    let finding_id = format!("{:016x}", diag.stable_hash);

    let spec = match HarnessSpec::from_finding(diag) {
        Ok(s) => s,
        Err(reason) => {
            return VerifyResult {
                finding_id,
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason: Some(reason),
                inconclusive_reason: None,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
            };
        }
    };

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

    // Emit telemetry (best-effort; never affects verdict).
    let event = TelemetryEvent::new(
        &spec,
        verdict.status,
        verdict.inconclusive_reason,
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

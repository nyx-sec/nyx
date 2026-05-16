//! Structured evidence and confidence types for scan diagnostics.
//!
//! These types capture the provenance of findings (source locations,
//! sanitizer/guard info, state-machine transitions) in a structured form
//! that can be serialized to JSON and consumed by ranking, filtering,
//! and downstream tooling.
#![allow(clippy::collapsible_if)]

use crate::commands::scan::Diag;
use crate::patterns::Severity;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// ─────────────────────────────────────────────────────────────────────────────
//  Confidence
// ─────────────────────────────────────────────────────────────────────────────

/// Confidence level for a diagnostic finding.
///
/// Ordered Low < Medium < High so that `>=` comparisons work naturally
/// for filtering (e.g. `--min-confidence medium` keeps Medium and High).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

impl FromStr for Confidence {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(format!(
                "unknown confidence level: {s:?} (expected low, medium, high)"
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Flow Steps
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of operation at a flow step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStepKind {
    /// A source read: user input, environment variable, network data, etc.
    Source,
    /// A local assignment propagating taint from one variable to another.
    Assignment,
    /// A function call through which taint flows (via argument or return value).
    Call,
    /// An SSA phi node merging tainted values from multiple predecessors.
    Phi,
    /// The dangerous sink where tainted data is consumed.
    Sink,
}

impl fmt::Display for FlowStepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => write!(f, "source"),
            Self::Assignment => write!(f, "assignment"),
            Self::Call => write!(f, "call"),
            Self::Phi => write!(f, "phi"),
            Self::Sink => write!(f, "sink"),
        }
    }
}

/// A single step in a taint flow path (display-ready).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    /// 1-based position of this step in the flow (source = 1, sink = N).
    pub step: u32,
    pub kind: FlowStepKind,
    /// Project-relative file path where this step occurs.
    pub file: String,
    /// 1-based line number of the operation.
    pub line: u32,
    /// 0-based column offset of the operation.
    pub col: u32,
    /// Source code snippet at this location, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// SSA variable name carrying taint at this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    /// For [`FlowStepKind::Call`] steps, the name of the function called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee: Option<String>,
    /// Name of the enclosing function at this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// True when this step crosses a file boundary, resolved via a cross-file
    /// summary rather than direct SSA flow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_cross_file: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Symbolic verdict
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolic verification verdict for a taint path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Constraint solver confirmed the path is feasible.
    Confirmed,
    /// Constraint solver proved the path is infeasible.
    Infeasible,
    /// Constraint solver could not determine feasibility.
    Inconclusive,
    /// No symbolic analysis was attempted for this finding.
    NotAttempted,
}

/// Summary of symbolic constraint analysis for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicVerdict {
    /// The outcome of symbolic path feasibility analysis.
    pub verdict: Verdict,
    /// Number of path constraints checked during analysis.
    #[serde(default)]
    pub constraints_checked: u32,
    /// Number of distinct paths explored from source to sink.
    #[serde(default)]
    pub paths_explored: u32,
    /// Human-readable witness or proof sketch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
    /// Interprocedural call chains leading to callee-internal sinks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interproc_call_chains: Vec<Vec<String>>,
    /// Cutoff/fallback reasons that limited analysis precision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoff_notes: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Dynamic verification verdict types (always present; not feature-gated)
// ─────────────────────────────────────────────────────────────────────────────

/// Why dynamic verification cannot be attempted for a finding.
///
/// Typed so that callers can pattern-match on the reason rather than parsing
/// strings. Serializes as PascalCase (e.g. `"BackendUnavailable"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum UnsupportedReason {
    /// The binary was not built with `--features dynamic`, or no backend
    /// implementation exists yet for this platform.
    BackendUnavailable,
    /// The entry kind (e.g. `HttpRoute`, `CliSubcommand`) is not yet supported;
    /// only `EntryKind::Function` is driven in current milestones.
    EntryKindUnsupported,
    /// The lang emitter does not yet support the spec's [`crate::dynamic::spec::PayloadSlot`]
    /// shape (e.g. `PayloadSlot::Param(n>0)` on Rust, `PayloadSlot::HttpBody`
    /// on JavaScript). Distinct from [`UnsupportedReason::EntryKindUnsupported`]:
    /// the entry kind is driveable, only the payload-injection slot is not.
    PayloadSlotUnsupported,
    /// Finding confidence is below `Medium`; dynamic verification is not
    /// attempted for low-confidence findings to avoid noise.
    ConfidenceTooLow,
    /// The finding has no `flow_steps` from which to derive an entry point.
    NoFlowSteps,
    /// No payload corpus exists for the sink capability.
    NoPayloadsForCap,
    /// A `HarnessSpec` could not be derived from the finding (missing entry
    /// function, unresolvable language, or zero sink capability bits).
    SpecDerivationFailed,
    /// The harness required a file that was redacted by the mount filter for
    /// secret containment. Path of the redacted file is carried inline.
    RequiredFileRedactedForSecrets(String),
    /// The language is not yet supported by the dynamic harness emitter.
    LangUnsupported,
}

/// What kind of entry point a harness should call.
///
/// Lives in `evidence.rs` (not `dynamic::spec`) so that
/// [`InconclusiveReason::EntryKindUnsupported`] can name the attempted /
/// supported variants without depending on the `dynamic` feature. The
/// canonical accessor is `crate::dynamic::spec::EntryKind` (re-export).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryKind {
    /// Free function. Build a `main` that calls it directly.
    Function,
    /// HTTP route. Stand up the framework, send a request.
    HttpRoute,
    /// CLI subcommand. Spawn the binary with crafted argv.
    CliSubcommand,
    /// Library API surface. Build an in-process consumer.
    LibraryApi,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Function => "Function",
            Self::HttpRoute => "HttpRoute",
            Self::CliSubcommand => "CliSubcommand",
            Self::LibraryApi => "LibraryApi",
        };
        f.write_str(s)
    }
}

/// Spec-derivation strategy attempted by [`crate::dynamic::spec::HarnessSpec::from_finding_opts`].
///
/// Lives in `evidence.rs` (not `dynamic::spec`) so that
/// [`InconclusiveReason::SpecDerivationFailed`] can carry a `Vec` of attempted
/// strategies without requiring the `dynamic` feature.  The canonical
/// accessor is `crate::dynamic::spec::SpecDerivationStrategy` (re-export).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SpecDerivationStrategy {
    /// Walk the finding's `evidence.flow_steps`. Original derivation path:
    /// the outermost `Source` step with a `function` annotation becomes the
    /// entry point. Requires non-empty `flow_steps`.
    FromFlowSteps,
    /// Inspect the diag's `id` (rule namespace, e.g. `py.cmdi.os_system`,
    /// `java.deser.readobject`, `rs.auth.missing_ownership_check.taint`) plus
    /// `evidence.sink_caps` to synthesize a single-step flow. Used when the
    /// rule namespace alone identifies a sink class.
    FromRuleNamespace,
    /// Walk a matching [`crate::summary::FuncSummary`] for the sink's
    /// enclosing function and construct a synthetic param-to-sink flow per
    /// parameter when no real `flow_steps` exist.
    FromFuncSummaryWalk,
    /// Resolve an entry point through the call graph by treating an entry-kind
    /// function (HTTP route, CLI handler) as the spec entry.
    FromCallgraphEntry,
}

impl fmt::Display for SpecDerivationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FromFlowSteps => "from_flow_steps",
            Self::FromRuleNamespace => "from_rule_namespace",
            Self::FromFuncSummaryWalk => "from_func_summary_walk",
            Self::FromCallgraphEntry => "from_callgraph_entry",
        };
        f.write_str(s)
    }
}

/// Typed reason for `VerifyStatus::Inconclusive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum InconclusiveReason {
    /// The oracle fired but the sink-reachability probe did not — likely an
    /// oracle collision where a coincidental output matched the marker pattern.
    OracleCollisionSuspected,
    /// The repro artifact could not be written to disk; verdict cannot be
    /// independently reproduced.
    NonReproducible,
    /// Harness build failed after retries.
    BuildFailed,
    /// Sandbox error (spawn failure, I/O error, etc.).
    SandboxError,
    /// Every [`SpecDerivationStrategy`] candidate was attempted but none
    /// produced a runnable [`crate::dynamic::spec::HarnessSpec`]. Distinct
    /// from [`UnsupportedReason::SpecDerivationFailed`]: the latter covers
    /// genuinely unmodellable findings (e.g. unknown language, zero sink
    /// bits), while this variant signals that the rule namespace, sink
    /// evidence, or call graph carried enough signal that derivation
    /// *should* have worked but did not.
    SpecDerivationFailed {
        tried: Vec<SpecDerivationStrategy>,
        hint: String,
    },
    /// The lang-specific harness emitter does not yet support the spec's
    /// [`EntryKind`].  Carries the language, the attempted entry kind, the
    /// list of entry kinds the emitter currently understands, and a
    /// human-actionable hint pointing at the phase that will add support.
    EntryKindUnsupported {
        lang: Lang,
        attempted: EntryKind,
        supported: Vec<EntryKind>,
        hint: String,
    },
    /// The capability's corpus lacks a paired benign control payload, so
    /// the differential-confirmation rule (§4.1) cannot be evaluated.
    /// Downgrades the verdict from a would-be `Confirmed` because the
    /// vulnerable-only firing might still be caused by a coincidental
    /// oracle match (a benign control would rule that out).
    NoBenignControl,
    /// The differential rule observed `!vuln_probe_fires && benign_probe_fires`:
    /// the benign control triggered the oracle but the vulnerable payload
    /// did not.  Surfaces a misconfigured corpus, a swapped pair, or an
    /// oracle that fires unconditionally; never a valid `Confirmed`.
    ReversedDifferential,
    /// Phase 08 §C.4: the harness process died with a crash signal
    /// (SIGSEGV / SIGABRT / etc.) but no sink-site
    /// [`crate::dynamic::probe::ProbeKind::Crash`] record was written —
    /// i.e. the crash happened outside the instrumented sink (setup
    /// code, harness build, library init).  Downgrades the verdict
    /// rather than letting an unrelated abort masquerade as a
    /// confirmed sink fire.
    UnrelatedCrash,
    /// Phase 18 §E.2: the sandbox backend in use cannot enforce the
    /// isolation a given oracle relies on (e.g. macOS process backend
    /// without `sandbox-exec`, so filesystem-escape oracles would run
    /// against an unconfined host).  Downgrades the verdict rather
    /// than letting an unhardened backend produce a false `Confirmed`.
    BackendInsufficient {
        backend: String,
        oracle_kind: String,
    },
    /// Phase 30 §C — the dynamic policy module refused to execute a
    /// finding whose static metadata mentions credentials, private
    /// keys, or a production endpoint regex.  The second security
    /// layer above the existing
    /// [`crate::dynamic::policy::Scrubber`] forensic redaction: even a
    /// successful confirmation is unsafe to obtain when the payload
    /// would have to mention or transmit live secrets.  Carries the
    /// rule name that fired (`credentials`, `private-key`,
    /// `production-endpoint`) and an evidence excerpt for triage.
    PolicyDeniedDynamic {
        rule: String,
        /// Logical name of the diag field that matched the deny rule
        /// (e.g. `path`, `evidence.notes[2]`, `flow_steps[1].snippet`).
        /// Empty string for verdicts loaded from older telemetry that
        /// did not capture this field.
        #[serde(default)]
        field: String,
        excerpt: String,
    },
}

impl fmt::Display for InconclusiveReason {
    /// Human-readable phrasing per variant.  Used by callers that splice
    /// the typed reason into a user-facing string (e.g. the
    /// `reverify_reason` field on a chain finding).  Consumers that need
    /// structured access should read the enum variant directly via
    /// `VerifyResult::inconclusive_reason`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OracleCollisionSuspected => {
                f.write_str("oracle collision suspected (marker matched without sink reach)")
            }
            Self::NonReproducible => f.write_str("repro artifact could not be written"),
            Self::BuildFailed => f.write_str("harness build failed after retries"),
            Self::SandboxError => f.write_str("sandbox error"),
            Self::SpecDerivationFailed { tried, hint } => {
                f.write_str("spec derivation failed (tried: ")?;
                for (i, s) in tried.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{s}")?;
                }
                write!(f, "; hint: {hint})")
            }
            Self::EntryKindUnsupported {
                lang,
                attempted,
                supported,
                hint,
            } => {
                write!(
                    f,
                    "entry kind {attempted:?} unsupported for {lang:?} (supported: "
                )?;
                for (i, k) in supported.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k:?}")?;
                }
                write!(f, "; hint: {hint})")
            }
            Self::NoBenignControl => {
                f.write_str("no benign control payload available for differential confirmation")
            }
            Self::ReversedDifferential => f.write_str(
                "reversed differential (benign payload fired, vulnerable payload did not)",
            ),
            Self::UnrelatedCrash => {
                f.write_str("harness crashed outside the instrumented sink")
            }
            Self::BackendInsufficient {
                backend,
                oracle_kind,
            } => write!(
                f,
                "{backend} backend cannot enforce isolation for {oracle_kind} oracle"
            ),
            Self::PolicyDeniedDynamic {
                rule,
                field,
                excerpt,
            } => {
                if field.is_empty() {
                    write!(
                        f,
                        "dynamic execution refused by policy rule {rule} (matched: {excerpt})"
                    )
                } else {
                    write!(
                        f,
                        "dynamic execution refused by policy rule {rule} (matched {field}: {excerpt})"
                    )
                }
            }
        }
    }
}

/// High-level outcome of a dynamic verification attempt.
///
/// Serializes as PascalCase (`"Confirmed"`, `"NotConfirmed"`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum VerifyStatus {
    /// Sink fired with at least one payload. The static finding is exploitable
    /// against the live target.
    Confirmed,
    /// All payloads ran cleanly. Either the path is infeasible at runtime
    /// or the corpus is too narrow. Treat as "static-only", not "false positive".
    NotConfirmed,
    /// Could not build, run, or observe (toolchain missing, sandbox refused,
    /// timeout on every attempt, etc.).
    Inconclusive,
    /// Dynamic verification was not attempted. See `reason` for the typed cause.
    Unsupported,
}

/// Summary of a single payload attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptSummary {
    pub payload_label: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub triggered: bool,
    /// Whether the in-harness sink-reachability probe fired for this attempt.
    #[serde(default)]
    pub sink_hit: bool,
}

/// Outcome of the Phase 07 differential confirmation rule.
///
/// Reflects which side of the (vulnerable, benign-control) probe pair
/// fired the oracle.  Stored on [`VerifyResult::differential`] so
/// operators can see the actual rule input that produced the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DifferentialVerdict {
    /// Vulnerable payload fired the oracle and the benign control did not.
    Confirmed,
    /// Both vulnerable and benign payloads fired the oracle — the oracle
    /// cannot discriminate; downgrade to
    /// [`InconclusiveReason::OracleCollisionSuspected`].
    OracleCollisionSuspected,
    /// Neither payload fired.
    NotConfirmed,
    /// Only the benign payload fired (vulnerable did not).  Surfaces a
    /// misconfigured corpus or a swapped pair; downgrade to
    /// [`InconclusiveReason::ReversedDifferential`].
    ReversedDifferential,
}

/// Probe-arg snapshot stored on [`DifferentialOutcome`].
///
/// Mirrors `crate::dynamic::probe::ProbeArg` without depending on the
/// `dynamic` feature.  The conversion is centralised in
/// `crate::dynamic::differential::build_outcome`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value")]
pub enum DifferentialProbeArg {
    String(String),
    Bytes(Vec<u8>),
    Int(i64),
}

/// One probe observation captured during a differential payload run.
///
/// Mirrors `crate::dynamic::probe::SinkProbe` without depending on the
/// `dynamic` feature.  Embedded inside
/// [`DifferentialOutcome::vuln_probes`] /
/// [`DifferentialOutcome::benign_probes`] for forensic review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialProbeRecord {
    pub sink_callee: String,
    pub args: Vec<DifferentialProbeArg>,
    pub captured_at_ns: u64,
    pub payload_id: String,
}

/// Full record of a Phase 07 differential confirmation run.
///
/// Captures the rule's verdict plus the raw probe traces from both the
/// vulnerable payload run and the benign-control run.  Stored on
/// [`VerifyResult::differential`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialOutcome {
    pub verdict: DifferentialVerdict,
    /// Label of the vulnerable payload (matches
    /// [`AttemptSummary::payload_label`] for the same run).
    pub vuln_label: String,
    /// Label of the benign-control payload.
    pub benign_label: String,
    /// Probe records drained from the vulnerable run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vuln_probes: Vec<DifferentialProbeRecord>,
    /// Probe records drained from the benign run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub benign_probes: Vec<DifferentialProbeRecord>,
}

/// Result of a dynamic verification attempt for one finding.
///
/// Always present when `config.scanner.verify` is true and the `dynamic`
/// feature is enabled. The `status` field is the high-level verdict;
/// `reason` carries the typed `UnsupportedReason` when status is
/// `Unsupported`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Stable ID of the finding this result is for.
    pub finding_id: String,
    /// High-level outcome.
    pub status: VerifyStatus,
    /// Label of the payload that triggered, when `status == Confirmed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_payload: Option<String>,
    /// Typed reason for `Unsupported` status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<UnsupportedReason>,
    /// Typed reason for `Inconclusive` status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inconclusive_reason: Option<InconclusiveReason>,
    /// Free-form error detail (used for `Inconclusive` status).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Per-attempt log.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<AttemptSummary>,
    /// How well the resolved toolchain matches the project's pinned toolchain.
    /// `"exact"` = precise match; `"drift"` = closest approximation used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain_match: Option<String>,
    /// Phase 07 differential-confirmation trace.  Present whenever the
    /// verifier ran both a vulnerable payload and its paired benign
    /// control (status `Confirmed` and the `OracleCollisionSuspected` /
    /// `ReversedDifferential` Inconclusive paths).  `None` for verdicts
    /// that never reached the differential step (e.g. `NoPayloadsForCap`,
    /// `BuildFailed`, `NoBenignControl`, `NotConfirmed` with vuln-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub differential: Option<DifferentialOutcome>,
    /// Eval-corpus repro stability flag.  `Some(true)` when `reproduce.sh`
    /// inside the verifier's bundle replayed green (`ReplayResult::Pass`),
    /// `Some(false)` when it diverged or aborted, `None` when no replay
    /// has been attempted (host infrastructure missing, backend not
    /// supported, etc.).  Drives the `stable_replays` column in
    /// `tests/eval_corpus/tabulate.py` — the eval-corpus
    /// `repro_stability` budget cannot fire until this field carries a
    /// `Some(true)` for at least one Confirmed row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_stable: Option<bool>,
    /// Eval-corpus manual-triage flag.  `Some(true)` when the user
    /// recorded a `wrong:<reason>` verdict via `nyx verify-feedback` or
    /// when an automated ground-truth pass marked this finding as a
    /// false confirmed.  `Some(false)` when explicitly marked right;
    /// `None` when no triage has happened.  Drives the
    /// `wrong_confirmed` column in `tests/eval_corpus/tabulate.py`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrong: Option<bool>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Structured evidence for a diagnostic finding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// Where tainted data originated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SpanEvidence>,

    /// Where the dangerous operation happens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink: Option<SpanEvidence>,

    /// Validation guards protecting this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guards: Vec<SpanEvidence>,

    /// Sanitizers applied to this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sanitizers: Vec<SpanEvidence>,

    /// State-machine evidence (resource lifecycle / auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateEvidence>,

    /// Free-form notes for ranking and display.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,

    /// Kind of taint source (structured; replaces "source_kind:..." in notes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<crate::labels::SourceKind>,

    /// Number of SSA blocks between source and sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_count: Option<u16>,

    /// Whether this finding was resolved via a cross-function summary.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub uses_summary: bool,

    /// Number of matching capability bits between source and sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_specificity: Option<u8>,

    /// Step-by-step taint flow from source to sink.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_steps: Vec<FlowStep>,

    /// Human-readable explanation of the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// Reasons why confidence is not higher.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_limiters: Vec<String>,

    /// Symbolic constraint analysis verdict for this finding's taint path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbolic: Option<SymbolicVerdict>,

    /// Resolved sink capability bits (u32 from `Cap::bits()`).
    ///
    /// Used by deduplication to distinguish findings that share a
    /// `(path, line, severity)` key but target different sinks (e.g.
    /// `sink_sql(x); sink_shell(x);` on the same line). 0 when the sink
    /// caps could not be resolved at the CFG node (e.g. pure summary
    /// resolution where the caller's sink node carries no label).
    #[serde(default, skip_serializing_if = "is_zero_cap_bits")]
    pub sink_caps: u32,

    /// Engine provenance notes attached to this finding (e.g. "worklist
    /// iteration budget was hit before convergence"), propagated from
    /// [`crate::taint::Finding::engine_notes`].  Empty for typical
    /// under-budget findings and skipped during serialization in that case.
    #[serde(default, skip_serializing_if = "smallvec::SmallVec::is_empty")]
    pub engine_notes: smallvec::SmallVec<[crate::engine_notes::EngineNote; 2]>,

    /// For `Cap::DATA_EXFIL` findings, the destination object-literal field
    /// the tainted value reached (e.g. `"body"`, `"headers"`, `"json"`).
    /// `None` for non-exfil findings, for exfil findings whose payload arg
    /// was not an object literal, or when the sink was resolved through a
    /// summary path that did not preserve destination metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_exfil_field: Option<String>,

    /// Result of dynamic verification for this finding, when
    /// `config.scanner.verify` is true and the `dynamic` feature is enabled.
    /// Always `None` in static-only scans and in non-dynamic builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_verdict: Option<VerifyResult>,
}

fn is_zero_cap_bits(v: &u32) -> bool {
    *v == 0
}

impl Evidence {
    /// Returns `true` if the evidence contains no useful data.
    pub fn is_empty(&self) -> bool {
        self.source.is_none()
            && self.sink.is_none()
            && self.guards.is_empty()
            && self.sanitizers.is_empty()
            && self.state.is_none()
            && self.notes.is_empty()
            && self.source_kind.is_none()
            && self.hop_count.is_none()
            && !self.uses_summary
            && self.cap_specificity.is_none()
            && self.flow_steps.is_empty()
            && self.explanation.is_none()
            && self.confidence_limiters.is_empty()
            && self.symbolic.is_none()
            && self.sink_caps == 0
            && self.engine_notes.is_empty()
            && self.dynamic_verdict.is_none()
    }
}

/// A source-location evidence span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvidence {
    pub path: String,
    pub line: u32,
    pub col: u32,
    /// One of: `"source"`, `"sink"`, `"guard"`, `"sanitizer"`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Evidence from a state-machine analysis (resource lifecycle / auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvidence {
    /// The state machine: `"resource"` or `"auth"`.
    pub machine: String,
    /// Variable name if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// State before the event.
    pub from_state: String,
    /// State after the event.
    pub to_state: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  compute_confidence
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a confidence level for `diag` based on its rule ID, severity,
/// evidence, and analysis kind.
///
/// This is called as a post-pass after all findings are collected; findings
/// that already have a confidence set (e.g. from CFG analysis) are preserved.
///
/// When the finding carries engine provenance notes whose
/// [`crate::engine_notes::LossDirection`] is `OverReport` or `Bail`,
/// the computed confidence is capped at `Medium` regardless of the
/// points-based taint score.  `OverReport` means precision was widened
/// (validation guards may have been lost, so the finding is more
/// likely to be a false positive); `Bail` means analysis of the body
/// aborted before producing a trustworthy result.  `UnderReport` notes
/// (e.g. `WorklistCapped`) do *not* cap confidence, the reported flow
/// is still real, just surrounded by an incomplete result set.
pub fn compute_confidence(diag: &Diag) -> Confidence {
    // Degraded analysis caps confidence
    if let Some(ev) = &diag.evidence
        && ev.notes.iter().any(|n| n.starts_with("degraded:"))
    {
        return Confidence::Low;
    }

    let id = &diag.id;

    let base = if id.starts_with("taint-data-exfiltration") {
        // DATA_EXFIL is calibrated independently from the generic taint path:
        // the value at risk is the leak of an *already-sensitive* source, not
        // the construction of an attacker payload, so the points-based scoring
        // tuned for code-exec / SSRF / SQLi over-credits these findings.  Route
        // to a narrower decision tree that asks "did we corroborate a real
        // string body leaving the process?" instead.
        compute_data_exfil_confidence(diag)
    } else if id.starts_with("taint-") {
        compute_taint_confidence(diag)
    } else if id.starts_with("state-") {
        match id.as_str() {
            "state-use-after-close" => Confidence::High,
            "state-double-close" => Confidence::High,
            "state-unauthed-access" => Confidence::High,
            "state-resource-leak" => Confidence::Medium,
            "state-resource-leak-possible" => Confidence::Low,
            _ => Confidence::Medium,
        }
    } else if id.starts_with("cfg-") {
        // If CFG conversion already set confidence, preserve it
        diag.confidence.unwrap_or(Confidence::Medium)
    } else if diag.severity == Severity::High {
        // AST patterns: High severity → Medium confidence, else Low
        Confidence::Medium
    } else {
        Confidence::Low
    };

    apply_engine_notes_cap(diag, base)
}

/// Cap `base` at `Medium` when the finding carries any engine note
/// whose direction is [`crate::engine_notes::LossDirection::OverReport`]
/// or [`crate::engine_notes::LossDirection::Bail`].
///
/// Returns `base` unchanged when no evidence is present, no notes are
/// attached, or only `Informational` / `UnderReport` notes are present.
fn apply_engine_notes_cap(diag: &Diag, base: Confidence) -> Confidence {
    let Some(ev) = &diag.evidence else {
        return base;
    };
    let Some(worst) = crate::engine_notes::worst_direction(&ev.engine_notes) else {
        return base;
    };
    match worst {
        crate::engine_notes::LossDirection::OverReport
        | crate::engine_notes::LossDirection::Bail => base.min(Confidence::Medium),
        // UnderReport: result set is a lower bound, but the emitted
        // finding itself remains as credible as the analysis decided.
        // Do not cap, the rank completeness penalty is the right lever
        // for that case (see rank.rs::completeness_penalty).
        crate::engine_notes::LossDirection::UnderReport => base,
        // Informational is filtered out upstream by `worst_direction`,
        // but keep the arm to force a decision if the enum grows.
        crate::engine_notes::LossDirection::Informational => base,
    }
}

/// Points-based confidence scoring for taint findings.
///
/// Uses evidence metadata (source kind, path length, validation, cap
/// specificity, summary resolution) to produce a nuanced confidence level
/// instead of the previous flat High assignment.
fn compute_taint_confidence(diag: &Diag) -> Confidence {
    let ev = match &diag.evidence {
        Some(e) => e,
        None => return Confidence::High, // no evidence struct → conservative High
    };

    let mut score: i32 = 0;

    // Source kind (prefer structured field, fall back to notes)
    score += match ev.source_kind {
        Some(kind) => structured_source_kind_score(kind),
        None => source_kind_score(&ev.notes),
    };

    // Evidence completeness
    let has_source = ev.source.is_some();
    let has_sink = ev.sink.is_some();
    let has_snippet = ev.source.as_ref().is_some_and(|s| s.snippet.is_some())
        || ev.sink.as_ref().is_some_and(|s| s.snippet.is_some());
    score += if has_source && has_sink && has_snippet {
        3
    } else if has_source && has_sink {
        2
    } else {
        1
    };

    // Hop count penalty (prefer structured field)
    score += match ev.hop_count {
        Some(count) => match count {
            0..=3 => 0,
            4..=8 => -1,
            _ => -2,
        },
        None => hop_count_score(&ev.notes),
    };

    // Path validation penalty (use Diag field directly)
    if diag.path_validated {
        score -= 3;
    }

    // Cap specificity bonus (prefer structured field)
    score += match ev.cap_specificity {
        Some(count) => {
            if count == 1 {
                1
            } else {
                0
            }
        }
        None => cap_specificity_score(&ev.notes),
    };

    // Summary resolution penalty (prefer structured field)
    if ev.uses_summary || ev.notes.iter().any(|n| n == "uses_summary") {
        score -= 1;
    }

    // Symbolic verdict adjustments
    if let Some(ref sv) = ev.symbolic {
        match sv.verdict {
            Verdict::Infeasible => score -= 5,
            Verdict::Confirmed => {
                // Stronger bonus when extract_witness produced a concrete payload
                // (contains "flows to" or "reaches"); raw Display-only fallback
                // from get_sink_witness does not contain these phrases.
                if sv
                    .witness
                    .as_ref()
                    .is_some_and(|w| w.contains("flows to") || w.contains("reaches"))
                {
                    score += 3;
                } else {
                    score += 2;
                }
            }
            Verdict::Inconclusive | Verdict::NotAttempted => {}
        }

        // Backwards-driven corroboration / infeasibility.  We
        // deliberately use a smaller magnitude than the symex verdict so
        // symex (which reasons about concrete payloads) stays the stronger
        // signal; backwards is a structural agreement check.
        use crate::taint::backwards::{NOTE_BUDGET, NOTE_CONFIRMED, NOTE_INFEASIBLE};
        if sv.cutoff_notes.iter().any(|n| n == NOTE_CONFIRMED) {
            score += 1;
        }
        if sv.cutoff_notes.iter().any(|n| n == NOTE_INFEASIBLE) {
            score -= 3;
        }
        let _ = NOTE_BUDGET;
    }

    match score {
        5.. => Confidence::High,
        2..=4 => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// Confidence routing for `taint-data-exfiltration` findings.
///
/// The generic taint scorer ranks DATA_EXFIL too aggressively: a Sensitive
/// source plus a sink call is enough to push it into the Medium/High band,
/// but the leak class needs corroboration that a real string body actually
/// leaves the process (otherwise we surface every `fetch(..., {body: x})`
/// where `x` happens to be Sensitive-tagged).  This routing is deliberately
/// capped at Medium and only fires Medium when the symbolic execution
/// verdict confirms the path (abstract interpretation participates only as
/// a sink-suppression filter inside SSA taint and does not surface a
/// separate verdict here).
///
/// Routing:
///   * Source < Sensitive → Low (caller already strips DATA_EXFIL for
///     Plain sources, but defensively floor here).
///   * Symbolic verdict `Confirmed` → Medium (symex produced a witness
///     that a tainted string reaches the body argument).
///   * Symbolic verdict `Inconclusive` / `NotAttempted` / no symbolic
///     analysis → Low (instruction's "Inconclusive" tier; the `Confidence`
///     enum has no separate Inconclusive variant so it floors to Low).
///   * Symbolic verdict `Infeasible` → Low (path proven dead).
///
/// After routing, a `path_validated` guard on the diag drops the result
/// one tier (Medium → Low; Low stays Low) and `apply_engine_notes_cap`
/// applies the standard engine-notes cap.
fn compute_data_exfil_confidence(diag: &Diag) -> Confidence {
    let ev = match &diag.evidence {
        Some(e) => e,
        None => return Confidence::Low,
    };

    let is_sensitive = ev
        .source_kind
        .map(|k| k.sensitivity() >= crate::labels::Sensitivity::Sensitive)
        .unwrap_or(false);
    if !is_sensitive {
        return Confidence::Low;
    }

    let mut base = match ev.symbolic.as_ref().map(|s| s.verdict) {
        Some(Verdict::Confirmed) => Confidence::Medium,
        Some(Verdict::Infeasible) => Confidence::Low,
        Some(Verdict::Inconclusive) | Some(Verdict::NotAttempted) | None => Confidence::Low,
    };

    // Guarded flow: drop a tier.  A validation predicate on the path means
    // the leak may be unreachable in practice, so the corroborated witness
    // is downgraded one step (Medium → Low; Low stays Low).
    if diag.path_validated && base > Confidence::Low {
        base = Confidence::Low;
    }

    apply_engine_notes_cap(diag, base)
}

/// Score a structured `SourceKind` value.
///
/// UserInput=+3, EnvironmentConfig=+2, Unknown/FileSystem=+1, Database/CaughtException=0.
fn structured_source_kind_score(kind: crate::labels::SourceKind) -> i32 {
    use crate::labels::SourceKind;
    match kind {
        // Cookie / Header carry auth material, score them at the same
        // ranking weight as direct user input rather than the lower
        // FileSystem/Database tiers.
        SourceKind::UserInput | SourceKind::Cookie | SourceKind::Header => 3,
        SourceKind::EnvironmentConfig => 2,
        SourceKind::Unknown | SourceKind::FileSystem => 1,
        SourceKind::Database | SourceKind::CaughtException => 0,
    }
}

/// Extract source_kind from evidence notes and return points (legacy fallback).
///
/// UserInput=+3, EnvironmentConfig=+2, Unknown/FileSystem=+1, Database/CaughtException=0.
fn source_kind_score(notes: &[String]) -> i32 {
    for note in notes {
        if let Some(kind) = note.strip_prefix("source_kind:") {
            return match kind {
                "UserInput" => 3,
                "EnvironmentConfig" => 2,
                "Unknown" | "FileSystem" => 1,
                _ => 0, // Database, CaughtException, etc.
            };
        }
    }
    1 // conservative default if missing
}

/// Extract hop_count from evidence notes and return penalty.
///
/// 0–3 blocks = 0, 4–8 = −1, 9+ = −2.
fn hop_count_score(notes: &[String]) -> i32 {
    for note in notes {
        if let Some(count_str) = note.strip_prefix("hop_count:") {
            if let Ok(count) = count_str.parse::<u16>() {
                return match count {
                    0..=3 => 0,
                    4..=8 => -1,
                    _ => -2,
                };
            }
        }
    }
    0 // no hop info → no penalty
}

/// Extract cap_specificity from evidence notes and return bonus.
///
/// 1 bit (exact match) = +1, otherwise 0.
fn cap_specificity_score(notes: &[String]) -> i32 {
    for note in notes {
        if let Some(count_str) = note.strip_prefix("cap_specificity:") {
            if let Ok(count) = count_str.parse::<u8>() {
                return if count == 1 { 1 } else { 0 };
            }
        }
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
//  Explanation & Confidence Limiters
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a human-readable explanation of a taint finding from its evidence.
pub fn generate_explanation(diag: &Diag) -> Option<String> {
    let ev = diag.evidence.as_ref()?;
    let source = ev.source.as_ref()?;
    let sink = ev.sink.as_ref()?;

    let source_callee = source.snippet.as_deref().unwrap_or("(unknown source)");
    let sink_callee = sink.snippet.as_deref().unwrap_or("(unknown sink)");

    // Extract source kind label (prefer structured field)
    let source_kind_label = if let Some(kind) = ev.source_kind {
        use crate::labels::SourceKind;
        match kind {
            SourceKind::UserInput => "user input",
            SourceKind::Cookie => "cookie",
            SourceKind::Header => "request header",
            SourceKind::EnvironmentConfig => "environment/config",
            SourceKind::Database => "database",
            SourceKind::FileSystem => "file system",
            SourceKind::CaughtException => "caught exception",
            SourceKind::Unknown => "unclassified",
        }
    } else {
        // Legacy fallback: parse from notes
        let kind_str = ev
            .notes
            .iter()
            .find_map(|n| n.strip_prefix("source_kind:"))
            .unwrap_or("unknown");
        match kind_str {
            "UserInput" => "user input",
            "EnvironmentConfig" => "environment/config",
            "Database" => "database",
            "FileSystem" => "file system",
            "CaughtException" => "caught exception",
            _ => "unclassified",
        }
    };

    // Extract category from rule ID
    let category = diag
        .id
        .strip_prefix("taint-unsanitised-flow")
        .map(|_| extract_category_from_id(&diag.id))
        .unwrap_or_else(|| "injection".to_string());

    let step_count = ev.flow_steps.len();
    let mut explanation = if step_count > 2 {
        format!(
            "Unsanitised {source_kind_label} data flows from {source_callee} (line {}) through {} steps to {sink_callee} (line {}), creating a potential {category} vulnerability.",
            source.line,
            step_count - 2, // exclude source and sink themselves
            sink.line,
        )
    } else {
        format!(
            "Unsanitised {source_kind_label} data flows from {source_callee} (line {}) to {sink_callee} (line {}), creating a potential {category} vulnerability.",
            source.line, sink.line,
        )
    };

    // Conditional addenda
    if diag.path_validated {
        if let Some(ref guard) = diag.guard_kind {
            explanation.push_str(&format!(
                " A {guard} guard was detected but may not be sufficient."
            ));
        }
    }
    if ev.uses_summary || ev.notes.iter().any(|n| n == "uses_summary") {
        explanation.push_str(" The flow crosses function boundaries via summary resolution.");
    }

    Some(explanation)
}

/// Extract a vulnerability category label from the Diag (used in explanation text).
fn extract_category_from_id(id: &str) -> String {
    // Rule IDs like "taint-unsanitised-flow (source 3:1)", category comes
    // from the finding category field, but we approximate from the ID here.
    if id.contains("sql") || id.contains("SQL") {
        "SQL injection".to_string()
    } else if id.contains("xss") || id.contains("XSS") {
        "XSS".to_string()
    } else {
        "injection".to_string()
    }
}

/// Compute reasons why confidence is not higher.
pub fn compute_confidence_limiters(diag: &Diag) -> Vec<String> {
    let mut limiters = Vec::new();
    let ev = match &diag.evidence {
        Some(e) => e,
        None => return limiters,
    };

    // Hop count (prefer structured field)
    let hop = ev.hop_count.or_else(|| {
        ev.notes
            .iter()
            .find_map(|n| n.strip_prefix("hop_count:")?.parse::<u16>().ok())
    });
    if let Some(count) = hop {
        if count >= 4 {
            limiters.push(format!(
                "Taint path spans {count} blocks, increasing chance of intermediate sanitization"
            ));
        }
    }

    // Summary resolution (prefer structured field)
    if ev.uses_summary || ev.notes.iter().any(|n| n == "uses_summary") {
        limiters.push("Flow resolved via cross-function summary (may be imprecise)".into());
    }

    // Path validated (use Diag field directly)
    if diag.path_validated {
        limiters.push("Validation guard detected on path (may provide protection)".into());
    }

    // Cap specificity (prefer structured field)
    let cap_spec = ev.cap_specificity.or_else(|| {
        ev.notes
            .iter()
            .find_map(|n| n.strip_prefix("cap_specificity:")?.parse::<u8>().ok())
    });
    if cap_spec == Some(0) {
        limiters.push("Source and sink capability types do not match specifically".into());
    }

    // Source kind unknown (prefer structured field)
    let is_unknown = ev.source_kind == Some(crate::labels::SourceKind::Unknown)
        || ev.notes.iter().any(|n| n == "source_kind:Unknown");
    if is_unknown {
        limiters.push("Source type is unclassified (lower exploitation confidence)".into());
    }

    // Symbolic verdict
    if let Some(ref sv) = ev.symbolic {
        if sv.verdict == Verdict::Infeasible {
            limiters.push("Symbolic analysis proved this path is infeasible".into());
        }
    }

    // Demand-driven backwards analysis notes (stored on
    // `symbolic.cutoff_notes` so the evidence pipeline already plumbs
    // them).  When the backwards walk proved the flow infeasible or ran
    // out of budget, surface a user-readable limiter.
    if let Some(ref sv) = ev.symbolic {
        use crate::taint::backwards::{NOTE_BUDGET, NOTE_CONFIRMED, NOTE_INFEASIBLE};
        if sv.cutoff_notes.iter().any(|n| n == NOTE_INFEASIBLE) {
            limiters.push("Backwards demand-driven analysis proved this flow infeasible".into());
        } else if sv.cutoff_notes.iter().any(|n| n == NOTE_BUDGET) {
            limiters.push(
                "Backwards demand-driven analysis exceeded its budget (verdict not reached)".into(),
            );
        }
        // Confirmation is *not* a limiter, it is a positive signal.  The
        // taint-confidence scorer picks it up separately.
        let _ = NOTE_CONFIRMED;
    }

    limiters
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::SourceKind;

    fn make_diag(id: &str, severity: Severity) -> Diag {
        Diag {
            path: "test.rs".into(),
            line: 1,
            col: 1,
            severity,
            id: id.into(),
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
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }
    }

    #[test]
    fn compute_confidence_taint_strong_path() {
        // UserInput(+3) + source+sink+snippet(+3) + short path(0) + cap_specificity:1(+1) = 7 → High
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("env::var(\"X\")".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "source_kind:UserInput".into(),
                "hop_count:1".into(),
                "cap_specificity:1".into(),
            ],
            source_kind: Some(crate::labels::SourceKind::UserInput),
            hop_count: Some(1),
            cap_specificity: Some(1),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_taint_medium_path() {
        // EnvironmentConfig(+2) + source+sink no snippet(+2) + hop_count:5(−1) = 3 → Medium
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec!["source_kind:EnvironmentConfig".into(), "hop_count:5".into()],
            source_kind: Some(crate::labels::SourceKind::EnvironmentConfig),
            hop_count: Some(5),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn compute_confidence_taint_weak_path() {
        // Database(0) + source+sink no snippet(+2) + hop_count:12(−2) + uses_summary(−1) = −1 → Low
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 20,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec![
                "source_kind:Database".into(),
                "hop_count:12".into(),
                "uses_summary".into(),
            ],
            source_kind: Some(crate::labels::SourceKind::Database),
            hop_count: Some(12),
            uses_summary: true,
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_taint_validated_with_source() {
        // UserInput(+3) + source+sink+snippet(+3) + path_validated(−3) = 3 → Medium
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.path_validated = true;
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec!["path_validated".into(), "source_kind:UserInput".into()],
            source_kind: Some(crate::labels::SourceKind::UserInput),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn compute_confidence_taint_no_evidence() {
        // No Evidence struct → conservative High
        let d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_degraded_caps_to_low() {
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: None,
            sink: None,
            guards: vec![],
            sanitizers: vec![],
            state: None,
            notes: vec!["degraded:budget_exceeded".into()],
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_state_rules() {
        assert_eq!(
            compute_confidence(&make_diag("state-use-after-close", Severity::High)),
            Confidence::High,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-double-close", Severity::Medium)),
            Confidence::High,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-unauthed-access", Severity::High)),
            Confidence::High,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-resource-leak", Severity::Medium)),
            Confidence::Medium,
        );
        assert_eq!(
            compute_confidence(&make_diag("state-resource-leak-possible", Severity::Low)),
            Confidence::Low,
        );
    }

    #[test]
    fn compute_confidence_cfg_preserves_existing() {
        let mut d = make_diag("cfg-unguarded-sink", Severity::High);
        d.confidence = Some(Confidence::Low);
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_ast_low() {
        let d = make_diag("rs.code_exec.eval", Severity::Medium);
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_ast_high_severity_medium() {
        let d = make_diag("rs.code_exec.eval", Severity::High);
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    // ── engine_notes direction-aware capping ────────────────────────

    fn taint_high_confidence_diag() -> Diag {
        // A known-High taint configuration: UserInput + source+sink+snippet +
        // short path + cap_specificity=1 → score 7 → High.  Re-used as the
        // "clean" baseline for every engine-notes cap test.
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query.id".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 5,
                col: 1,
                kind: "sink".into(),
                snippet: Some("exec(id)".into()),
            }),
            source_kind: Some(SourceKind::UserInput),
            cap_specificity: Some(1),
            hop_count: Some(1),
            ..Default::default()
        });
        d
    }

    fn with_notes(mut d: Diag, notes: Vec<crate::engine_notes::EngineNote>) -> Diag {
        let mut ev = d.evidence.clone().unwrap_or_default();
        ev.engine_notes = smallvec::SmallVec::from_vec(notes);
        d.evidence = Some(ev);
        d
    }

    #[test]
    fn confidence_uncapped_without_engine_notes() {
        assert_eq!(
            compute_confidence(&taint_high_confidence_diag()),
            Confidence::High,
            "baseline must be High so cap tests have something to cap"
        );
    }

    #[test]
    fn confidence_not_capped_by_under_report() {
        // UnderReport indicates we may have missed OTHER findings.  The
        // finding we *did* emit is still sound; its confidence stays High.
        let d = with_notes(
            taint_high_confidence_diag(),
            vec![crate::engine_notes::EngineNote::WorklistCapped { iterations: 100 }],
        );
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn confidence_capped_at_medium_by_over_report() {
        // OverReport (PredicateStateWidened) means validation predicates
        // were lost, the emitted finding is more likely to be spurious.
        let d = with_notes(
            taint_high_confidence_diag(),
            vec![crate::engine_notes::EngineNote::PredicateStateWidened],
        );
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn confidence_capped_at_medium_by_bail() {
        let d = with_notes(
            taint_high_confidence_diag(),
            vec![crate::engine_notes::EngineNote::ParseTimeout { timeout_ms: 1000 }],
        );
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn confidence_cap_does_not_upgrade_low() {
        // `base.min(Medium)` is what caps, it must not *raise* a Low
        // baseline to Medium.  Use a taint finding with weak evidence so
        // the points scorer gives us Low, then attach a Bail note.
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::Low);
        d.evidence = Some(Evidence {
            source: None,
            sink: None,
            source_kind: Some(SourceKind::Database),
            hop_count: Some(10),
            ..Default::default()
        });
        d = with_notes(
            d,
            vec![crate::engine_notes::EngineNote::ParseTimeout { timeout_ms: 100 }],
        );
        assert_eq!(
            compute_confidence(&d),
            Confidence::Low,
            "Bail cap must never raise Low → Medium"
        );
    }

    #[test]
    fn confidence_not_capped_by_informational() {
        let d = with_notes(
            taint_high_confidence_diag(),
            vec![crate::engine_notes::EngineNote::InlineCacheReused],
        );
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn confidence_cap_applies_to_state_findings_too() {
        // state-use-after-close is High by default; an OverReport note
        // on it must cap it to Medium, same as the taint path.
        let d = with_notes(
            make_diag("state-use-after-close", Severity::High),
            vec![crate::engine_notes::EngineNote::PredicateStateWidened],
        );
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn confidence_cap_chooses_worst_when_mixed() {
        // UnderReport alone does not cap; OverReport does.  Mixing them
        // must apply the cap (worst-direction wins).
        let d = with_notes(
            taint_high_confidence_diag(),
            vec![
                crate::engine_notes::EngineNote::WorklistCapped { iterations: 10 },
                crate::engine_notes::EngineNote::PredicateStateWidened,
            ],
        );
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn evidence_is_empty() {
        let ev = Evidence::default();
        assert!(ev.is_empty());

        let ev2 = Evidence {
            source: Some(SpanEvidence {
                path: "x.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            ..Default::default()
        };
        assert!(!ev2.is_empty());
    }

    #[test]
    fn confidence_ord() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
        assert!(Confidence::Low < Confidence::High);
    }

    #[test]
    fn confidence_display_and_parse() {
        assert_eq!(Confidence::Low.to_string(), "Low");
        assert_eq!(Confidence::Medium.to_string(), "Medium");
        assert_eq!(Confidence::High.to_string(), "High");

        assert_eq!("low".parse::<Confidence>().unwrap(), Confidence::Low);
        assert_eq!("MEDIUM".parse::<Confidence>().unwrap(), Confidence::Medium);
        assert_eq!("High".parse::<Confidence>().unwrap(), Confidence::High);
        assert!("invalid".parse::<Confidence>().is_err());
    }

    #[test]
    fn compute_confidence_does_not_override_preset() {
        // AST patterns set confidence directly; compute_confidence must not overwrite.
        let mut d = make_diag("rs.quality.expect", Severity::Low);
        d.confidence = Some(Confidence::High);
        // The post-pass only runs when confidence is None, but verify compute_confidence
        // itself would return something different (Low for AST + Low severity), proving
        // the guard in scan.rs is necessary.
        assert_eq!(compute_confidence(&d), Confidence::Low);
        // The actual guard: confidence is already Some, so scan.rs skips compute_confidence.
        assert_eq!(d.confidence, Some(Confidence::High));
    }

    #[test]
    fn json_omits_none_fields() {
        let ev = Evidence::default();
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn symbolic_verdict_serde_round_trip() {
        for verdict in [
            Verdict::Confirmed,
            Verdict::Infeasible,
            Verdict::Inconclusive,
            Verdict::NotAttempted,
        ] {
            let sv = SymbolicVerdict {
                verdict,
                constraints_checked: 42,
                paths_explored: 7,
                witness: Some("x=null forces false branch".into()),
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            };
            let json = serde_json::to_string(&sv).unwrap();
            let rt: SymbolicVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(rt.verdict, verdict);
            assert_eq!(rt.constraints_checked, 42);
            assert_eq!(rt.paths_explored, 7);
            assert_eq!(rt.witness.as_deref(), Some("x=null forces false branch"));
        }
        // Verify snake_case serialization
        let json = serde_json::to_string(&Verdict::NotAttempted).unwrap();
        assert_eq!(json, "\"not_attempted\"");
    }

    #[test]
    fn evidence_with_symbolic_not_empty() {
        let ev = Evidence {
            symbolic: Some(SymbolicVerdict {
                verdict: Verdict::Confirmed,
                constraints_checked: 1,
                paths_explored: 1,
                witness: None,
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            }),
            ..Default::default()
        };
        assert!(!ev.is_empty());
    }

    #[test]
    fn symbolic_witness_omitted_when_none() {
        let sv = SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 0,
            witness: None,
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        };
        let json = serde_json::to_string(&sv).unwrap();
        assert!(!json.contains("witness"));
    }

    #[test]
    fn compute_confidence_structured_fields_only() {
        // Structured fields without notes → same result as with notes
        // UserInput(+3) + source+sink+snippet(+3) + hop_count:1(0) + cap_specificity:1(+1) = 7 → High
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            source_kind: Some(crate::labels::SourceKind::UserInput),
            hop_count: Some(1),
            cap_specificity: Some(1),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn compute_confidence_notes_only_backward_compat() {
        // Notes only (no structured fields) → backward compatible
        // EnvironmentConfig(+2) + source+sink(+2) + hop_count:5(−1) = 3 → Medium
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            notes: vec!["source_kind:EnvironmentConfig".into(), "hop_count:5".into()],
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Medium);
    }

    #[test]
    fn compute_confidence_symbolic_infeasible_demotes() {
        // UserInput(+3) + source+sink+snippet(+3) + Infeasible(−5) = 1 → Low
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: Some("req.query".into()),
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: Some("exec()".into()),
            }),
            source_kind: Some(crate::labels::SourceKind::UserInput),
            symbolic: Some(SymbolicVerdict {
                verdict: Verdict::Infeasible,
                constraints_checked: 3,
                paths_explored: 1,
                witness: None,
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            }),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::Low);
    }

    #[test]
    fn compute_confidence_symbolic_confirmed_boosts() {
        // EnvironmentConfig(+2) + source+sink(+2) + Confirmed(+2) = 6 → High
        let mut d = make_diag("taint-unsanitised-flow (source 1:1)", Severity::High);
        d.evidence = Some(Evidence {
            source: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 1,
                col: 1,
                kind: "source".into(),
                snippet: None,
            }),
            sink: Some(SpanEvidence {
                path: "test.rs".into(),
                line: 10,
                col: 5,
                kind: "sink".into(),
                snippet: None,
            }),
            source_kind: Some(crate::labels::SourceKind::EnvironmentConfig),
            symbolic: Some(SymbolicVerdict {
                verdict: Verdict::Confirmed,
                constraints_checked: 2,
                paths_explored: 1,
                witness: None,
                interproc_call_chains: Vec::new(),
                cutoff_notes: Vec::new(),
            }),
            ..Default::default()
        });
        assert_eq!(compute_confidence(&d), Confidence::High);
    }

    #[test]
    fn evidence_with_structured_fields_not_empty() {
        let ev = Evidence {
            source_kind: Some(crate::labels::SourceKind::UserInput),
            ..Default::default()
        };
        assert!(!ev.is_empty());

        let ev2 = Evidence {
            uses_summary: true,
            ..Default::default()
        };
        assert!(!ev2.is_empty());
    }

    #[test]
    fn source_kind_serde_round_trip() {
        use crate::labels::SourceKind;
        for kind in [
            SourceKind::UserInput,
            SourceKind::EnvironmentConfig,
            SourceKind::FileSystem,
            SourceKind::Database,
            SourceKind::CaughtException,
            SourceKind::Unknown,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let rt: SourceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, kind);
        }
        // Verify snake_case serialization
        let json = serde_json::to_string(&crate::labels::SourceKind::UserInput).unwrap();
        assert_eq!(json, "\"user_input\"");
    }
}

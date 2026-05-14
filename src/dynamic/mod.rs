//! Dynamic verification layer (feature-gated: `dynamic`).
//!
//! Static analysis confirms a flow exists. Dynamic execution confirms it fires.
//! This module turns a [`crate::commands::scan::Diag`] into a runnable harness,
//! injects a payload from a per-cap corpus, executes inside a sandbox, and
//! reports back whether the sink actually triggered.
//!
//! Pipeline:
//!
//! ```text
//!   Diag --> HarnessSpec --> lang::emit() --> BuiltHarness
//!                                                  |
//!                                                  v
//!                                          sandbox::run(payload)
//!                                                  |
//!                                                  v
//!                                           SandboxOutcome
//!                                                  |
//!                                                  v
//!                                          oracle + sink_hit check
//!                                                  |
//!                                                  v
//!                                            VerifyResult
//! ```
//!
//! All submodules are read-only consumers of the static engine's output.
//! Nothing in this tree mutates SSA, taint, or label state.
//!
//! Off by default. Enable with `--features dynamic`. Heavy deps (container
//! runtime client, fuzzer harness) live behind the same gate.
//!
//! # Spec derivation strategies
//!
//! [`spec::HarnessSpec::from_finding_opts`] tries a fixed-order pipeline of
//! [`spec::SpecDerivationStrategy`] candidates and returns the first one that
//! produces a runnable spec. Ordering is deliberately chosen so the cheapest,
//! most-precise sources fire first:
//!
//! 1. [`SpecDerivationStrategy::FromFlowSteps`] — the original derivation
//!    path. Walks `evidence.flow_steps` for the outermost `Source` and uses
//!    its enclosing function as the entry. Fires for taint findings with a
//!    real cross-function flow.
//! 2. [`SpecDerivationStrategy::FromRuleNamespace`] — consumes the diag's
//!    rule id (`py.cmdi.os_system`, `java.deser.readobject`,
//!    `rs.auth.missing_ownership_check.taint`) plus `evidence.sink_caps` to
//!    synthesize a single-step flow. Fires for AST/CFG findings whose rule
//!    namespace identifies the sink class.
//! 3. [`SpecDerivationStrategy::FromFuncSummaryWalk`] — walks a
//!    [`crate::summary::FuncSummary`] for the sink's enclosing function and
//!    picks a `tainted_sink_params` entry. Currently only fires when a
//!    summary is threaded in by the caller; the default verifier path does
//!    not.
//! 4. [`SpecDerivationStrategy::FromCallgraphEntry`] — last-chance heuristic
//!    that treats `*.http.*` and `*.cli.*` rule ids as entry-point findings.
//!
//! When every strategy returns `None`, [`verify::verify_finding`] decides
//! whether to lift the failure to
//! [`crate::evidence::InconclusiveReason::SpecDerivationFailed`] (the finding
//! had derivable signal but no strategy matched) or to keep it as
//! [`crate::evidence::UnsupportedReason::SpecDerivationFailed`] (genuinely
//! unmodellable).
//!
//! [`SpecDerivationStrategy::FromFlowSteps`]: spec::SpecDerivationStrategy::FromFlowSteps
//! [`SpecDerivationStrategy::FromRuleNamespace`]: spec::SpecDerivationStrategy::FromRuleNamespace
//! [`SpecDerivationStrategy::FromFuncSummaryWalk`]: spec::SpecDerivationStrategy::FromFuncSummaryWalk
//! [`SpecDerivationStrategy::FromCallgraphEntry`]: spec::SpecDerivationStrategy::FromCallgraphEntry

pub mod build_sandbox;
pub mod corpus;
pub mod differential;
pub mod environment;
pub mod harness;
pub mod lang;
pub mod mount_filter;
pub mod oob;
pub mod oracle;
pub mod policy;
pub mod probe;
pub mod repro;
pub mod report;
pub mod runner;
pub mod sandbox;
pub mod spec;
pub mod telemetry;
pub mod toolchain;
pub mod verify;

pub use report::{VerifyResult, VerifyStatus};
pub use spec::HarnessSpec;
pub use verify::{verify_finding, VerifyOptions};

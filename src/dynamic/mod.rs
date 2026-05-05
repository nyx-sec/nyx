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
//!   Diag --> HarnessSpec --> Harness (generated source/binary)
//!                                |
//!                                v
//!                          Sandbox::run(payload)
//!                                |
//!                                v
//!                            VerifyResult
//! ```
//!
//! All submodules are read-only consumers of the static engine's output.
//! Nothing in this tree mutates SSA, taint, or label state.
//!
//! Off by default. Enable with `--features dynamic`. Heavy deps (container
//! runtime client, fuzzer harness) live behind the same gate.

pub mod corpus;
pub mod harness;
pub mod report;
pub mod runner;
pub mod sandbox;
pub mod spec;
pub mod verify;

pub use report::{VerifyResult, VerifyStatus};
pub use spec::HarnessSpec;
pub use verify::{verify_finding, VerifyOptions};

//! Harness specification: the bridge between a static finding and a runnable harness.
//!
//! A [`HarnessSpec`] is built from a [`crate::commands::scan::Diag`] without
//! any further analysis. It records what the dynamic side needs to know:
//! which entry point to drive, which parameter carries the payload, what
//! sink (cap) we expect to hit, and which language toolchain to use.
//!
//! Construction is total but may return `None` when the finding lacks the
//! evidence required to drive it dynamically (no source span, no callable
//! entry, sink in dead code, etc.). Those findings stay static-only.

use crate::commands::scan::Diag;
use crate::labels::Cap;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};

/// What kind of entry point the harness should call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Where the payload goes when the harness fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadSlot {
    /// Nth positional parameter of the entry function.
    Param(usize),
    /// Named HTTP query parameter.
    QueryParam(String),
    /// HTTP request body (raw bytes).
    HttpBody,
    /// Environment variable.
    EnvVar(String),
    /// CLI argv slot (0-based, excluding argv[0]).
    Argv(usize),
    /// stdin.
    Stdin,
}

/// Self-contained recipe for building and running a single harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// Stable id of the source finding (`Diag::id` plus location hash).
    pub finding_id: String,
    /// Project-relative path to the file holding the entry point.
    pub entry_file: String,
    /// Function/route/subcommand name to drive.
    pub entry_name: String,
    /// How to invoke it.
    pub entry_kind: EntryKind,
    /// Source language (drives toolchain selection).
    pub lang: Lang,
    /// Where the payload is injected.
    pub payload_slot: PayloadSlot,
    /// Sink capability we expect to fire (drives oracle + corpus pick).
    pub expected_cap: Cap,
    /// Optional symex-derived constraint hints (prefix/suffix locks, etc.).
    /// Populated later from `Evidence::engine_notes` when available.
    #[serde(default)]
    pub constraint_hints: Vec<String>,
}

impl HarnessSpec {
    /// Build a spec from a finding. Returns `None` when the finding cannot
    /// be driven dynamically (missing entry, ambient sink, etc.).
    ///
    /// Stub: real impl will read `Diag::evidence.flow_steps` to pick the
    /// outermost entry function and walk the source span back to a parameter.
    pub fn from_finding(_diag: &Diag) -> Option<Self> {
        // TODO(dynamic): map flow_steps[0] -> entry function, evidence.source_span -> PayloadSlot,
        //                evidence.sink_caps -> expected_cap.
        None
    }
}

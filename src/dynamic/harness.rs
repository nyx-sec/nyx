//! Harness code generation.
//!
//! Given a [`HarnessSpec`], emit a small program that:
//!
//! 1. Imports/loads the target module from the project tree.
//! 2. Reads the payload from a known channel (env var `NYX_PAYLOAD`).
//! 3. Invokes the entry point with the payload routed to the right slot.
//! 4. Lets the sink either fire or not — the oracle observes from outside.
//!
//! One generator per [`Lang`]. Each emits source plus a build command.
//! Build artefacts are staged inside the sandbox working dir, never the
//! user's tree.

use crate::dynamic::spec::HarnessSpec;
use crate::symbol::Lang;
use std::path::PathBuf;

/// A built harness ready to hand off to the sandbox.
#[derive(Debug, Clone)]
pub struct BuiltHarness {
    /// Working directory containing the harness source + any build output.
    pub workdir: PathBuf,
    /// Command to invoke (e.g. `["python3", "harness.py"]` or
    /// `["./target/release/harness"]`).
    pub command: Vec<String>,
    /// Environment variables to set when running. Payload bytes go in via
    /// `NYX_PAYLOAD` regardless of language.
    pub env: Vec<(String, String)>,
}

/// Build a harness from a spec. Returns the artefact + run command.
///
/// Stub: per-language emitters will live in their own files
/// (`harness/python.rs`, `harness/rust.rs`, etc.) and dispatch off
/// `spec.lang`.
pub fn build(_spec: &HarnessSpec) -> Result<BuiltHarness, HarnessError> {
    Err(HarnessError::Unimplemented)
}

#[derive(Debug)]
pub enum HarnessError {
    Unimplemented,
    UnsupportedLang(Lang),
    BuildFailed(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for HarnessError {
    fn from(e: std::io::Error) -> Self {
        HarnessError::Io(e)
    }
}

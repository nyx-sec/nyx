//! Verdict types for dynamic verification results.
//!
//! The canonical definitions live in [`crate::evidence`] so they are always
//! present regardless of the `dynamic` feature flag.  This module re-exports
//! them for use inside the dynamic pipeline without requiring callers to reach
//! into `evidence` directly.

pub use crate::evidence::{AttemptSummary, UnsupportedReason, VerifyResult, VerifyStatus};

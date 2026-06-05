//! IDOR / unauthorized-id-access (`Cap::UNAUTHORIZED_ID`)
//! per-language payload slices.
//!
//! Phase 11 (Track J.9) carves an IDOR oracle across all seven
//! backend-capable languages.  Each harness stands up a mock data
//! store keyed by `owner_id` and a hard-coded `caller_id`
//! (`"alice"`).  The vuln payload supplies an `owner_id` that
//! belongs to another user (`"bob"`); the harness's instrumented
//! lookup returns the record without an authorization check and
//! writes a [`crate::dynamic::probe::ProbeKind::IdorAccess { caller_id,
//! owner_id }`] probe.  The
//! [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
//! predicate fires whenever `caller_id != owner_id`.  The paired
//! benign control asks for the caller's own record (`"alice"`), so
//! the probe records matching ids and the predicate stays clear.

pub mod go;
pub mod java;
pub mod js;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;

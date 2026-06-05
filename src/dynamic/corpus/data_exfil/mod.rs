//! Data-exfiltration (`Cap::DATA_EXFIL`) per-language payload
//! slices.
//!
//! Phase 11 (Track J.9) carves an outbound-network oracle across
//! all seven backend-capable languages.  Each harness stands up a
//! mock HTTP client that records the destination host of every
//! outbound request via a
//! [`crate::dynamic::probe::ProbeKind::OutboundNetwork { host }`]
//! probe.  The
//! [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
//! predicate fires when the captured `host` falls outside the
//! configured loopback allowlist (`&["127.0.0.1", "localhost"]`).
//! The vuln payload supplies `attacker.test`; the paired benign
//! control supplies `127.0.0.1` so the predicate stays clear.

pub mod go;
pub mod java;
pub mod js;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;

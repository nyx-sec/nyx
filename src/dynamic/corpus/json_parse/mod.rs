//! JSON-parse pollution (`Cap::JSON_PARSE`) per-language payload
//! slices.
//!
//! Phase 11 (Track J.9) reuses the prototype-canary oracle from
//! Phase 10 across the three languages whose JSON parsers have a
//! published pollution surface: JavaScript (`JSON.parse` then deep
//! assign), Python (`json.loads` then `dict.update` /
//! `setattr`-driven attribute pollution), Ruby (`JSON.parse` then
//! recursive merge).  Every vuln payload binds a JSON literal whose
//! top-level key is `__proto__`; the per-language harness's
//! instrumented canary trap (`Object.prototype.__nyx_canary` in JS,
//! a `dict`/class-scoped sentinel in Python, an `Object.prepend`
//! flag in Ruby) records a
//! [`crate::dynamic::probe::ProbeKind::PrototypePollution`] probe
//! once the malicious key reaches the shared chain.  The paired
//! benign control sends a JSON literal whose top-level key is the
//! regular property `data`, leaving the chain untouched.

pub mod go;
pub mod java;
pub mod javascript;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;

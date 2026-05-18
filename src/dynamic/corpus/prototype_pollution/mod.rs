//! Prototype-pollution (`Cap::PROTOTYPE_POLLUTION`) per-language
//! payload slices.
//!
//! Phase 10 (Track J.8) carves the JavaScript / TypeScript prototype-
//! pollution gadget against three sink families: `lodash.merge`,
//! `Object.assign` with tainted RHS, and `JSON.parse`-then-deep-assign.
//! Every vuln payload binds a JSON literal whose top-level key is
//! `__proto__`; the harness's instrumented deep-merge walks the key
//! into `Object.prototype` and a `Proxy`-style setter trap on
//! `Object.prototype.__nyx_canary` records a
//! [`crate::dynamic::probe::ProbeKind::PrototypePollution`] probe.  The
//! paired benign control sends a JSON literal whose top-level key is
//! the regular property `data`, leaving the prototype chain
//! untouched.  The
//! [`crate::dynamic::oracle::ProbePredicate::PrototypeCanaryTouched`]
//! predicate fires only on probes whose `property` equals the canary
//! name (`__nyx_canary`).

pub mod javascript;
pub mod typescript;

//! Deserialization (`Cap::DESERIALIZE`) per-language payload slices.
//!
//! Phase 03 (Track J.1) lands the first cap end-to-end: Java
//! (`ObjectInputStream.readObject` / `XMLDecoder`), Python (`pickle.loads`
//! / `yaml.unsafe_load`), PHP (`unserialize`), and Ruby (`Marshal.load`
//! / `YAML.load`).  Every vuln payload is paired with a benign control
//! whose oracle should *not* fire — the per-language harness shims
//! emit a [`crate::dynamic::probe::ProbeKind::Deserialize`] record with
//! `gadget_chain_invoked: true` when a non-allowlisted gadget class is
//! materialised by the instrumented deserialiser; benign well-formed
//! serialized data does not reach the allowlist boundary and so leaves
//! no Deserialize probe.

pub mod java;
pub mod php;
pub mod python;
pub mod ruby;

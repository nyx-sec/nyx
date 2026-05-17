//! SQLi (`Cap::SQL_QUERY`) per-language payload slices.
//!
//! Each submodule exposes a `pub const PAYLOADS: &[CuratedPayload]` slice
//! registered against `(Cap::SQL_QUERY, Lang::<lang>)` in
//! [`super::registry::CORPUS`].

pub mod rust;

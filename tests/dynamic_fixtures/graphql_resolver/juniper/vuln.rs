//! Phase 21 (Track M.3) — Juniper GraphQL resolver vuln fixture.
//!
//! `resolve_user(id)` is a Juniper resolver (substring marker only —
//! the real `juniper` crate is not on the workdir's Cargo.toml).  The
//! resolver builds a SQL query via raw string concat — classic
//! GraphQL → SQLi shape.

// use juniper::graphql_object;

pub fn resolve_user(id: &str) -> String {
    // SINK: tainted id concatenated into SQL.
    let query = format!("SELECT * FROM users WHERE id = '{}'", id);
    let _ = query;
    format!("user-{}", id)
}

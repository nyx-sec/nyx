//! Phase 21 — Juniper resolver benign control.
// use juniper::graphql_object;

pub fn resolve_user(id: &str) -> String {
    let safe: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    format!("user-{}", safe)
}

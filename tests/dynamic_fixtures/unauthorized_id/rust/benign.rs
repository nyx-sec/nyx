// Phase 11 (Track J.9) — Rust UNAUTHORIZED_ID benign control fixture.
use std::collections::HashMap;

const CALLER_ID: &str = "alice";

pub fn run(owner_id: &str) -> Option<String> {
    if owner_id != CALLER_ID {
        return None;
    }
    let mut store = HashMap::new();
    store.insert("alice".to_string(), "alice@x".to_string());
    store.insert("bob".to_string(), "bob@x".to_string());
    store.get(owner_id).cloned()
}

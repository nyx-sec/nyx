// Phase 11 (Track J.9) — Rust CRYPTO benign control fixture.
//
// Uses `rand::rngs::OsRng` (a CSPRNG) for key derivation.
use rand::rngs::OsRng;
use rand::RngCore;

pub fn run(_value: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

// Phase 11 (Track J.9) — Rust CRYPTO vuln fixture.
//
// Uses `rand::thread_rng` truncated to 16 bits (a non-CSPRNG
// configuration) to derive a key bounded inside the weak budget.
use rand::Rng;

pub fn run(_value: &str) -> u16 {
    rand::thread_rng().gen_range(0..=0xFFFF) as u16
}

// Phase 11 (Track J.9) — Rust CRYPTO vuln fixture.
//
// Models a config-driven crypto endpoint that picks the RNG based on
// the request payload — `*_WEAK` routes through `rand::thread_rng`
// truncated to 16 bits (a non-CSPRNG configuration) and `*_STRONG`
// routes through `rand::rngs::OsRng` (a CSPRNG).  Both branches return
// `[u8; 8]` so the harness's `NyxKeyToInt` reducer treats them
// uniformly.  The weak branch zero-pads the 16-bit value into the low
// two bytes, leaving `nyx_bytes_to_key_int` to read it back as a small
// big-endian `u64` that trips the `WeakKeyEntropy` predicate; the
// strong branch fills all eight bytes from the CSPRNG so the reduced
// `u64` overshoots the 16-bit budget.
use rand::Rng;
use rand::RngCore;
use rand::rngs::OsRng;

pub fn run(value: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    if value.contains("STRONG") {
        OsRng.fill_bytes(&mut key);
    } else {
        let weak = rand::thread_rng().gen_range(0..=0xFFFFu16);
        key[6] = (weak >> 8) as u8;
        key[7] = (weak & 0xFF) as u8;
    }
    key
}

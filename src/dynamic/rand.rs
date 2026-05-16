//! Deterministic seeded RNG for the dynamic layer (Phase 30 — Track C
//! determinism audit).
//!
//! Every randomness source in [`crate::dynamic`] must route through
//! [`SpecRng`] so identical inputs (spec hash + corpus version) produce
//! identical sandbox runs.  Non-determinism inside the verifier breaks
//! the Phase 27 `events.jsonl` replay invariant, the Phase 28 repro
//! bundle hermeticity contract, and the Phase 29 per-cell budget gates.
//!
//! The implementation is intentionally minimal:
//!
//! * No external RNG crate — blake3 is the project's hashing primitive
//!   and an extra `rand`/`rand_chacha` dep would expand the supply-chain
//!   surface for no gain.
//! * Output stream is a SHAKE-style hash chain: every 32-byte block is
//!   `blake3(seed || counter_le)`, with the counter incremented after
//!   each block.  Throughput is dwarfed by sandbox / build cost so any
//!   added cycles compared to a CSPRNG do not show up in
//!   `benches/dynamic_bench.rs`.
//! * No `Send`/thread-local state — callers thread the [`SpecRng`]
//!   explicitly so a fork in control flow always produces a fresh,
//!   reproducible substream.  Mutation fuzzers can clone the RNG before
//!   forking to keep both branches reproducible.
//!
//! # Audit gate
//!
//! `scripts/check_no_unseeded_rand.sh` greps `src/dynamic/` for the
//! banned non-deterministic APIs (`rand::thread_rng`, `OsRng`,
//! `from_entropy`, `getrandom::getrandom`, `Uuid::new_v4`, `fastrand`).
//! Any match exits the script non-zero so CI catches regressions before
//! they land.  The seccomp policy file is allowed to mention
//! `"getrandom"` because that string is a syscall name, not a Rust API
//! call; the audit script's regex filters that case out.

use blake3::Hasher;

/// Length of the seed mixed into every block of the RNG stream.  32
/// bytes = full blake3 output width; using anything smaller would lose
/// entropy if a caller passes a longer spec hash.
const SEED_BYTES: usize = 32;

/// Width of a single hash-chain block.  Matches blake3's natural output
/// length so we never have to truncate or extend.
const BLOCK_BYTES: usize = 32;

/// Deterministic pseudo-random number generator keyed by a spec hash.
///
/// Construct via [`SpecRng::seeded`] (the standard entry point used by
/// every verifier call site) or [`SpecRng::from_seed_bytes`] (for tests
/// that need to pin the seed independently of a spec).
///
/// The same seed always produces the same byte stream, so any consumer
/// inside [`crate::dynamic`] that needs randomness (mutation fuzzer
/// payload choice, environment variable jitter, stub port jitter, …)
/// gets a reproducible roll without leaking host entropy into the
/// verdict.
#[derive(Debug, Clone)]
pub struct SpecRng {
    seed: [u8; SEED_BYTES],
    counter: u64,
    buf: [u8; BLOCK_BYTES],
    buf_pos: usize,
}

impl SpecRng {
    /// Seed an RNG from a spec hash hex string.
    ///
    /// The hex prefix is hashed with blake3 to normalise it to 32 bytes
    /// — callers may pass the short 16-hex-char spec hash (the form
    /// stamped onto [`crate::dynamic::spec::HarnessSpec::spec_hash`])
    /// or a longer derivation; both produce a full-width seed.
    pub fn seeded(spec_hash: &str) -> Self {
        let mut h = Hasher::new();
        h.update(b"nyx.dynamic.rand.v1\0");
        h.update(spec_hash.as_bytes());
        let mut seed = [0u8; SEED_BYTES];
        seed.copy_from_slice(h.finalize().as_bytes());
        Self::from_seed_bytes(seed)
    }

    /// Seed from raw bytes.  Exposed for tests that need a known seed
    /// without round-tripping through a spec hash.
    pub fn from_seed_bytes(seed: [u8; SEED_BYTES]) -> Self {
        Self {
            seed,
            counter: 0,
            buf: [0u8; BLOCK_BYTES],
            buf_pos: BLOCK_BYTES,
        }
    }

    /// Refill the internal buffer with the next block of the hash
    /// chain.  Called lazily as bytes are consumed.
    fn refill(&mut self) {
        let mut h = Hasher::new();
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        let digest = h.finalize();
        self.buf.copy_from_slice(digest.as_bytes());
        self.counter = self.counter.wrapping_add(1);
        self.buf_pos = 0;
    }

    /// Fill `out` with deterministic pseudo-random bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0;
        while written < out.len() {
            if self.buf_pos == BLOCK_BYTES {
                self.refill();
            }
            let take = (out.len() - written).min(BLOCK_BYTES - self.buf_pos);
            out[written..written + take]
                .copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + take]);
            self.buf_pos += take;
            written += take;
        }
    }

    /// Draw the next `u64` from the stream.  Used by the rejection
    /// loop in [`Self::gen_range`].
    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Draw a `u32`.  Convenience for callers picking among small
    /// alternatives (payload variants, env mutation slots).
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() & 0xFFFF_FFFF) as u32
    }

    /// Sample a `usize` uniformly in `[0, upper)`.  Panics when
    /// `upper == 0` because the request is meaningless; callers should
    /// guard zero-length slices.
    ///
    /// Uses rejection sampling against the largest multiple of `upper`
    /// that fits in a `u64` so the distribution is exactly uniform —
    /// modulo-bias would otherwise nudge the corpus picker toward
    /// low-indexed payloads.
    pub fn gen_range(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "SpecRng::gen_range upper bound must be > 0");
        let upper_u64 = upper as u64;
        let zone = u64::MAX - (u64::MAX % upper_u64);
        loop {
            let candidate = self.next_u64();
            if candidate < zone {
                return (candidate % upper_u64) as usize;
            }
        }
    }

    /// Pick one element from `slice`.  Returns `None` only when the
    /// slice is empty so callers can use `?` for empty-corpus paths.
    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            Some(&slice[self.gen_range(slice.len())])
        }
    }

    /// In-place Fisher–Yates shuffle.  Useful for the mutation fuzzer
    /// when iterating a payload list in a reproducible order without
    /// pre-sorting in caller code.
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.gen_range(i + 1);
            slice.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_same_stream() {
        let mut a = SpecRng::seeded("deadbeefcafebabe");
        let mut b = SpecRng::seeded("deadbeefcafebabe");
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = SpecRng::seeded("aaaa");
        let mut b = SpecRng::seeded("bbbb");
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn fill_bytes_crosses_block_boundary() {
        // 80 > BLOCK_BYTES (32) — exercises the refill loop and proves
        // stream continuity across block transitions.
        let mut rng = SpecRng::seeded("boundary");
        let mut a = vec![0u8; 80];
        rng.fill_bytes(&mut a);
        let mut rng2 = SpecRng::seeded("boundary");
        let mut b1 = vec![0u8; 32];
        let mut b2 = vec![0u8; 48];
        rng2.fill_bytes(&mut b1);
        rng2.fill_bytes(&mut b2);
        let mut concat = b1.clone();
        concat.extend_from_slice(&b2);
        assert_eq!(a, concat);
    }

    #[test]
    fn gen_range_stays_in_bounds() {
        let mut rng = SpecRng::seeded("range");
        for _ in 0..1000 {
            let v = rng.gen_range(7);
            assert!(v < 7);
        }
    }

    #[test]
    #[should_panic]
    fn gen_range_zero_panics() {
        let mut rng = SpecRng::seeded("range");
        rng.gen_range(0);
    }

    #[test]
    fn choose_empty_returns_none() {
        let mut rng = SpecRng::seeded("choose");
        let empty: [u32; 0] = [];
        assert!(rng.choose(&empty).is_none());
    }

    #[test]
    fn choose_is_reproducible() {
        let items = [10u32, 20, 30, 40, 50];
        let mut a = SpecRng::seeded("pick");
        let mut b = SpecRng::seeded("pick");
        for _ in 0..16 {
            assert_eq!(a.choose(&items), b.choose(&items));
        }
    }

    #[test]
    fn shuffle_is_reproducible() {
        let mut v1: Vec<u32> = (0..20).collect();
        let mut v2 = v1.clone();
        let mut a = SpecRng::seeded("shuffle");
        let mut b = SpecRng::seeded("shuffle");
        a.shuffle(&mut v1);
        b.shuffle(&mut v2);
        assert_eq!(v1, v2);
    }

    #[test]
    fn clone_forks_substream_reproducibly() {
        // Cloning at any point must produce identical streams from
        // both halves — required so a fuzzer fork (try-this-mutation
        // vs try-that) is hermetic.
        let mut rng = SpecRng::seeded("fork");
        rng.next_u32();
        let mut a = rng.clone();
        let mut b = rng.clone();
        let mut buf_a = [0u8; 48];
        let mut buf_b = [0u8; 48];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn from_seed_bytes_is_deterministic() {
        let seed = [7u8; SEED_BYTES];
        let mut a = SpecRng::from_seed_bytes(seed);
        let mut b = SpecRng::from_seed_bytes(seed);
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

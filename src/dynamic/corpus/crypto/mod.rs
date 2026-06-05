//! Weak-crypto (`Cap::CRYPTO`) per-language payload slices.
//!
//! Phase 11 (Track J.9) carves a weak-key entropy oracle across the
//! five backend languages where homegrown key generation is common
//! enough to matter: Java (`java.util.Random.nextBytes` → key bytes),
//! Python (`random.randint(0, 0xFFFF)`), PHP (`mt_rand(0, 0xFFFF)`),
//! Go (`math/rand.Intn(0x10000)`), Rust (`rand::thread_rng` truncated
//! to 16 bits).  Every vuln payload triggers the harness's
//! instrumented key-generation path with a seed that produces an
//! attacker-derivable key bounded inside the 16-bit search space.
//! The harness shim writes a
//! [`crate::dynamic::probe::ProbeKind::WeakKey { key_int }`] probe
//! with the produced integer view of the key bytes; the
//! [`crate::dynamic::oracle::ProbePredicate::WeakKeyEntropy`]
//! predicate fires when `key_int < 2^max_bits` (`max_bits = 16` by
//! default).  The paired benign control routes the same harness
//! through a CSPRNG (`SecureRandom`, `secrets.token_bytes`,
//! `random_bytes(32)`, `crypto/rand.Read`, `rand::rngs::OsRng`) so
//! the produced `key_int` trivially exceeds the budget and the
//! predicate stays clear.

pub mod go;
pub mod java;
pub mod php;
pub mod python;
pub mod rust;

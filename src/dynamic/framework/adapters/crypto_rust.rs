//! Rust [`super::super::FrameworkAdapter`] matching weak-crypto sink
//! constructions (`md5::compute` / `Md5::digest`, `sha1::Sha1::digest`,
//! `rand::random` / non-CSPRNG `rand::Rng::gen_*`, `crypto::des` DES /
//! `crypto::rc4` RC4 ciphers).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Rust weak-crypto entry points and the surrounding
//! source imports the matching crate.
//!
//! See sibling adapters [`super::crypto_python::CryptoPythonAdapter`],
//! [`super::crypto_java::CryptoJavaAdapter`],
//! [`super::crypto_ruby::CryptoRubyAdapter`], and
//! [`super::crypto_go::CryptoGoAdapter`] for the same shape on other
//! languages.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoRustAdapter;

const ADAPTER_NAME: &str = "crypto-rust";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "compute"
            | "digest"
            | "finalize"
            | "random"
            | "gen"
            | "gen_range"
            | "gen_bool"
            | "thread_rng"
            | "new_unkeyed"
    ) || matches!(
        name,
        "md5::compute"
            | "Md5::digest"
            | "Md5::new"
            | "md_5::Md5::digest"
            | "md_5::Md5::new"
            | "sha1::Sha1::digest"
            | "sha1::Sha1::new"
            | "Sha1::digest"
            | "Sha1::new"
            | "rand::random"
            | "rand::thread_rng"
            | "rand::Rng::gen"
            | "rand::Rng::gen_range"
            | "rand::rngs::ThreadRng::gen"
            | "Des::new"
            | "TdesEde3::new"
            | "Rc4::new"
    )
}

fn source_imports_rust_crypto(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"use md5",
        b"use md_5",
        b"use sha1",
        b"use sha_1",
        b"use rand",
        b"md5::",
        b"md_5::Md5",
        b"sha1::Sha1",
        b"sha_1::Sha1",
        b"rand::random",
        b"rand::thread_rng",
        b"rand::Rng",
        b"des::Des",
        b"rc4::Rc4",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a hardened path (CSPRNG via `getrandom` /
/// `OsRng`, SHA-256+ digests, AES-GCM / ChaCha20-Poly1305 / Argon2
/// authenticated encryption + KDF, `ring` constants).
fn source_routed_through_strong_path(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"getrandom::getrandom",
        b"rand::rngs::OsRng",
        b"OsRng",
        b"sha2::Sha256",
        b"sha2::Sha384",
        b"sha2::Sha512",
        b"sha3::Sha3_256",
        b"sha3::Sha3_512",
        b"ring::digest::SHA256",
        b"ring::digest::SHA384",
        b"ring::digest::SHA512",
        b"aes_gcm",
        b"AesGcm",
        b"chacha20poly1305",
        b"ChaCha20Poly1305",
        b"argon2::Argon2",
        b"argon2::PasswordHash",
        b"bcrypt::hash",
        b"ed25519_dalek",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoRustAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Rust
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if source_routed_through_strong_path(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_weak_crypto);
        let matches_source = source_imports_rust_crypto(file_bytes);
        if matches_call && matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_md5_compute() {
        let src: &[u8] = b"use md5;\npub fn sign(value: &[u8]) -> md5::Digest {\n    md5::compute(value)\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("md5::compute")],
            ..Default::default()
        };
        assert!(
            CryptoRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_sha1_digest() {
        let src: &[u8] = b"use sha1::Sha1;\nuse sha1::Digest;\npub fn sign(value: &[u8]) -> Vec<u8> {\n    let mut h = Sha1::new();\n    h.update(value);\n    h.finalize().to_vec()\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("Sha1::new")],
            ..Default::default()
        };
        assert!(
            CryptoRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_rand_random() {
        let src: &[u8] = b"use rand;\npub fn token() -> u64 {\n    rand::random::<u64>()\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "token".into(),
            callees: vec![crate::summary::CalleeSite::bare("rand::random")],
            ..Default::default()
        };
        assert!(
            CryptoRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_osrng() {
        let src: &[u8] = b"use rand;\nuse rand::rngs::OsRng;\nuse rand::RngCore;\npub fn token() -> [u8; 32] {\n    let mut buf = [0u8; 32];\n    OsRng.fill_bytes(&mut buf);\n    buf\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "token".into(),
            callees: vec![crate::summary::CalleeSite::bare("rand::random")],
            ..Default::default()
        };
        assert!(
            CryptoRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_sha256_in_source() {
        let src: &[u8] = b"use sha2::Sha256;\nuse sha2::Digest;\npub fn sign(value: &[u8]) -> Vec<u8> {\n    let mut h = Sha256::new();\n    h.update(value);\n    h.finalize().to_vec()\n}\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("Sha256::new")],
            ..Default::default()
        };
        assert!(
            CryptoRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"pub fn add(a: i64, b: i64) -> i64 { a + b }\n";
        let tree = parse_rust(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            CryptoRustAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

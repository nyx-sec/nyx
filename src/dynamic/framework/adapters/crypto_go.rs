//! Go [`super::super::FrameworkAdapter`] matching weak-crypto sink
//! constructions (`math/rand.Int*` non-CSPRNG randomness used for
//! key material, `crypto/md5.Sum` / `crypto/sha1.Sum` /
//! `crypto/des.NewCipher` / `crypto/rc4.NewCipher`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Go weak-crypto entry points and the surrounding
//! source imports the matching stdlib module.
//!
//! See sibling adapters [`super::crypto_python::CryptoPythonAdapter`],
//! [`super::crypto_java::CryptoJavaAdapter`], and
//! [`super::crypto_ruby::CryptoRubyAdapter`] for the same shape on
//! other languages.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoGoAdapter;

const ADAPTER_NAME: &str = "crypto-go";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "Int"
            | "Intn"
            | "Int31"
            | "Int31n"
            | "Int63"
            | "Int63n"
            | "Uint32"
            | "Uint64"
            | "Float32"
            | "Float64"
            | "Read"
            | "Sum"
            | "New"
            | "NewCipher"
    ) || matches!(
        name,
        "rand.Int"
            | "rand.Intn"
            | "rand.Int31"
            | "rand.Int31n"
            | "rand.Int63"
            | "rand.Int63n"
            | "rand.Uint32"
            | "rand.Uint64"
            | "rand.Float32"
            | "rand.Float64"
            | "rand.Read"
            | "md5.Sum"
            | "md5.New"
            | "sha1.Sum"
            | "sha1.New"
            | "des.NewCipher"
            | "des.NewTripleDESCipher"
            | "rc4.NewCipher"
    )
}

fn source_imports_go_crypto(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"\"math/rand\"",
        b"math/rand\"",
        b"\"crypto/md5\"",
        b"crypto/md5\"",
        b"\"crypto/sha1\"",
        b"crypto/sha1\"",
        b"\"crypto/des\"",
        b"crypto/des\"",
        b"\"crypto/rc4\"",
        b"crypto/rc4\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a hardened path (`crypto/rand` CSPRNG,
/// `crypto/sha256` or stronger, `crypto/aes` paired with `GCM`,
/// `golang.org/x/crypto/chacha20poly1305`).
fn source_routed_through_strong_path(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"\"crypto/rand\"",
        b"crypto/rand\"",
        b"\"crypto/sha256\"",
        b"crypto/sha256\"",
        b"\"crypto/sha512\"",
        b"crypto/sha512\"",
        b"sha3.New",
        b"chacha20poly1305",
        b"cipher.NewGCM",
        b"argon2.Key",
        b"argon2.IDKey",
        b"bcrypt.GenerateFromPassword",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoGoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Go
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
        let matches_source = source_imports_go_crypto(file_bytes);
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

    fn parse_go(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_math_rand_intn() {
        let src: &[u8] = b"package vuln\nimport \"math/rand\"\nfunc Run() int {\n    return rand.Intn(1000)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("rand.Intn")],
            ..Default::default()
        };
        assert!(
            CryptoGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_md5_sum() {
        let src: &[u8] = b"package vuln\nimport \"crypto/md5\"\nfunc Sign(b []byte) [16]byte {\n    return md5.Sum(b)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("md5.Sum")],
            ..Default::default()
        };
        assert!(
            CryptoGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_des_newcipher() {
        let src: &[u8] = b"package vuln\nimport \"crypto/des\"\nimport \"crypto/cipher\"\nfunc Enc(key []byte) (cipher.Block, error) {\n    return des.NewCipher(key)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Enc".into(),
            callees: vec![crate::summary::CalleeSite::bare("des.NewCipher")],
            ..Default::default()
        };
        assert!(
            CryptoGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_crypto_rand() {
        let src: &[u8] = b"package vuln\nimport \"math/rand\"\nimport \"crypto/rand\"\nfunc Run() ([]byte, error) {\n    key := make([]byte, 32)\n    if _, err := rand.Read(key); err != nil { return nil, err }\n    return key, nil\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Run".into(),
            callees: vec![crate::summary::CalleeSite::bare("rand.Read")],
            ..Default::default()
        };
        assert!(
            CryptoGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_sha256_in_source() {
        let src: &[u8] = b"package vuln\nimport \"crypto/sha256\"\nfunc Sign(b []byte) [32]byte {\n    return sha256.Sum256(b)\n}\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("sha256.Sum256")],
            ..Default::default()
        };
        assert!(
            CryptoGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"package vuln\nfunc Add(a, b int) int { return a + b }\n";
        let tree = parse_go(src);
        let summary = FuncSummary {
            name: "Add".into(),
            ..Default::default()
        };
        assert!(
            CryptoGoAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

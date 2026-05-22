//! PHP [`super::super::FrameworkAdapter`] matching weak-crypto sink
//! constructions (`md5()` / `sha1()` for message digests,
//! `mt_rand()` / `rand()` for key material, `mcrypt_encrypt()` and
//! `mcrypt_create_iv()` legacy primitives, `hash('md5'|'sha1', …)`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical PHP weak-crypto entry points and the surrounding
//! source is plausibly a PHP script (starts with `<?php` or uses the
//! short `<?` tag).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoPhpAdapter;

const ADAPTER_NAME: &str = "crypto-php";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name
        .rsplit_once("::")
        .map(|(_, s)| s)
        .unwrap_or(name)
        .rsplit_once('\\')
        .map(|(_, s)| s)
        .unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "md5"
            | "sha1"
            | "md5_file"
            | "sha1_file"
            | "mt_rand"
            | "rand"
            | "mt_srand"
            | "srand"
            | "crc32"
            | "mcrypt_create_iv"
            | "mcrypt_encrypt"
            | "mcrypt_decrypt"
            | "uniqid"
    )
}

fn source_is_php_script(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[b"<?php", b"<?=", b"<?\n"];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a hardened path (`random_bytes`,
/// `random_int`, `openssl_random_pseudo_bytes`, `sodium_crypto_*`,
/// `hash('sha256', …)` or stronger, `openssl_encrypt` with GCM).
fn source_routed_through_strong_path(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"random_bytes(",
        b"random_int(",
        b"openssl_random_pseudo_bytes(",
        b"sodium_crypto_",
        b"hash('sha256'",
        b"hash(\"sha256\"",
        b"hash('sha384'",
        b"hash(\"sha384\"",
        b"hash('sha512'",
        b"hash(\"sha512\"",
        b"hash('sha3-256'",
        b"hash(\"sha3-256\"",
        b"'aes-256-gcm'",
        b"\"aes-256-gcm\"",
        b"'chacha20-poly1305'",
        b"\"chacha20-poly1305\"",
        b"password_hash(",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoPhpAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
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
        let matches_source = source_is_php_script(file_bytes);
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

    fn parse_php(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_md5() {
        let src: &[u8] =
            b"<?php\nfunction sign($value) {\n    return md5($value);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("md5")],
            ..Default::default()
        };
        assert!(
            CryptoPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_mt_rand() {
        let src: &[u8] = b"<?php\nfunction key_byte() {\n    return mt_rand(0, 255);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "key_byte".into(),
            callees: vec![crate::summary::CalleeSite::bare("mt_rand")],
            ..Default::default()
        };
        assert!(
            CryptoPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_random_bytes() {
        let src: &[u8] = b"<?php\nfunction key() {\n    if (function_exists('random_bytes')) {\n        return random_bytes(32);\n    }\n    return md5(uniqid());\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "key".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("md5"),
                crate::summary::CalleeSite::bare("random_bytes"),
            ],
            ..Default::default()
        };
        assert!(
            CryptoPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_sha256_hashing_present() {
        let src: &[u8] =
            b"<?php\nfunction sign($value) {\n    return hash('sha256', $value);\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("hash")],
            ..Default::default()
        };
        assert!(
            CryptoPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"<?php\nfunction add($a, $b) {\n    return $a + $b;\n}\n";
        let tree = parse_php(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            CryptoPhpAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

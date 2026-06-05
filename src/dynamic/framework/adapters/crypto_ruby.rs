//! Ruby [`super::super::FrameworkAdapter`] matching weak-crypto sink
//! constructions (`Digest::MD5` / `Digest::SHA1` / `OpenSSL::HMAC`
//! over `MD5`/`SHA1`, `rand` / `srand` / `Random.rand` used for key
//! material).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Ruby weak-crypto entry points and the
//! surrounding source requires the matching stdlib module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoRubyAdapter;

const ADAPTER_NAME: &str = "crypto-ruby";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name.rsplit_once("::").map(|(_, s)| s).unwrap_or(name);
    let last = last.rsplit_once('.').map(|(_, s)| s).unwrap_or(last);
    matches!(
        last,
        "hexdigest" | "digest" | "base64digest" | "file" | "rand" | "srand"
    ) || matches!(
        name,
        "Digest::MD5.hexdigest"
            | "Digest::MD5.digest"
            | "Digest::MD5.base64digest"
            | "Digest::MD5.new"
            | "Digest::SHA1.hexdigest"
            | "Digest::SHA1.digest"
            | "Digest::SHA1.base64digest"
            | "Digest::SHA1.new"
            | "OpenSSL::Digest.new"
            | "OpenSSL::Digest::MD5.new"
            | "OpenSSL::Digest::SHA1.new"
            | "OpenSSL::HMAC.digest"
            | "OpenSSL::HMAC.hexdigest"
            | "Random.rand"
            | "Kernel.rand"
            | "Kernel.srand"
    )
}

fn source_imports_ruby_crypto(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require 'digest'",
        b"require \"digest\"",
        b"require 'digest/md5'",
        b"require \"digest/md5\"",
        b"require 'digest/sha1'",
        b"require \"digest/sha1\"",
        b"require 'openssl'",
        b"require \"openssl\"",
        b"Digest::MD5",
        b"Digest::SHA1",
        b"OpenSSL::Digest",
        b"OpenSSL::HMAC",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a hardened path (`SecureRandom`, SHA-256+,
/// `OpenSSL::Cipher.new("AES-256-GCM")`, libsodium).
fn source_routed_through_strong_path(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require 'securerandom'",
        b"require \"securerandom\"",
        b"SecureRandom.",
        b"Digest::SHA256",
        b"Digest::SHA384",
        b"Digest::SHA512",
        b"\"SHA256\"",
        b"'SHA256'",
        b"\"SHA-256\"",
        b"'SHA-256'",
        b"\"SHA384\"",
        b"\"SHA512\"",
        b"\"AES-256-GCM\"",
        b"'AES-256-GCM'",
        b"\"ChaCha20-Poly1305\"",
        b"RbNaCl::",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoRubyAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
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
        let matches_source = source_imports_ruby_crypto(file_bytes);
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

    fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_digest_md5_hexdigest() {
        let src: &[u8] = b"require 'digest'\n\
            def sign(value)\n  Digest::MD5.hexdigest(value)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("Digest::MD5.hexdigest")],
            ..Default::default()
        };
        assert!(
            CryptoRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_openssl_hmac_md5() {
        let src: &[u8] = b"require 'openssl'\n\
            def sign(key, value)\n  OpenSSL::HMAC.hexdigest('MD5', key, value)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("OpenSSL::HMAC.hexdigest")],
            ..Default::default()
        };
        assert!(
            CryptoRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_securerandom() {
        let src: &[u8] = b"require 'digest'\nrequire 'securerandom'\n\
            def run(value)\n  if value.include?('STRONG')\n    SecureRandom.hex(32)\n  else\n    Digest::MD5.hexdigest(value)\n  end\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Digest::MD5.hexdigest")],
            ..Default::default()
        };
        assert!(
            CryptoRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_sha256_in_source() {
        let src: &[u8] = b"require 'digest'\n\
            def sign(value)\n  Digest::SHA256.hexdigest(value)\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("Digest::SHA256.hexdigest")],
            ..Default::default()
        };
        assert!(
            CryptoRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b)\n  a + b\nend\n";
        let tree = parse_ruby(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            CryptoRubyAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

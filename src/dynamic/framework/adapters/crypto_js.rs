//! JavaScript [`super::super::FrameworkAdapter`] matching weak-crypto
//! sink constructions (`Math.random` for key material,
//! `crypto.createHash('md5'|'sha1')`, `crypto.createCipheriv('des'|'rc4')`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Node weak-crypto entry points and the
//! surrounding source imports the matching `crypto` module (or uses
//! `Math.random` for key material).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoJsAdapter;

const ADAPTER_NAME: &str = "crypto-js";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "random" | "createHash" | "createCipheriv" | "createCipher" | "pseudoRandomBytes"
    ) || matches!(
        name,
        "Math.random"
            | "crypto.createHash"
            | "crypto.createCipher"
            | "crypto.createCipheriv"
            | "crypto.pseudoRandomBytes"
    )
}

fn source_imports_js_crypto(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('crypto')",
        b"require(\"crypto\")",
        b"from 'crypto'",
        b"from \"crypto\"",
        b"import crypto",
        b"Math.random(",
        b"createHash('md5'",
        b"createHash(\"md5\"",
        b"createHash('sha1'",
        b"createHash(\"sha1\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a hardened path
/// (`crypto.randomBytes` / `crypto.randomUUID` /
/// `createHash('sha256'+)`, `createCipheriv('aes-256-gcm')`).
fn source_routed_through_strong_path(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"crypto.randomBytes",
        b"crypto.randomUUID",
        b"crypto.randomInt",
        b"crypto.webcrypto.getRandomValues",
        b"createHash('sha256'",
        b"createHash(\"sha256\"",
        b"createHash('sha384'",
        b"createHash(\"sha384\"",
        b"createHash('sha512'",
        b"createHash(\"sha512\"",
        b"createCipheriv('aes-256-gcm'",
        b"createCipheriv(\"aes-256-gcm\"",
        b"createCipheriv('chacha20-poly1305'",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoJsAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::JavaScript
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
        let matches_source = source_imports_js_crypto(file_bytes);
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

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_math_random_key() {
        let src: &[u8] = b"function run(value) { return Math.random(); }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Math.random")],
            ..Default::default()
        };
        assert!(
            CryptoJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_create_hash_md5() {
        let src: &[u8] = b"const crypto = require('crypto');\nfunction sign(value) { return crypto.createHash('md5').update(value).digest('hex'); }\nmodule.exports = { sign };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("crypto.createHash")],
            ..Default::default()
        };
        assert!(
            CryptoJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_random_bytes() {
        let src: &[u8] = b"const crypto = require('crypto');\nfunction run(value) { if (value === 'STRONG') return crypto.randomBytes(32); return Math.random(); }\nmodule.exports = { run };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("Math.random"),
                crate::summary::CalleeSite::bare("crypto.randomBytes"),
            ],
            ..Default::default()
        };
        assert!(
            CryptoJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\nmodule.exports = { add };\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            CryptoJsAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

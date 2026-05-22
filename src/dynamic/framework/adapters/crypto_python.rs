//! Python [`super::super::FrameworkAdapter`] matching weak-crypto
//! sink constructions (`random.randint` / `random.random` for key
//! material, `hashlib.md5` / `hashlib.sha1` used without
//! `usedforsecurity=False`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Python weak-crypto entry points and the
//! surrounding source imports the matching stdlib module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoPythonAdapter;

const ADAPTER_NAME: &str = "crypto-python";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "randint" | "random" | "uniform" | "choice" | "seed" | "md5" | "sha1" | "new"
    ) || matches!(
        name,
        "random.randint"
            | "random.random"
            | "random.uniform"
            | "random.choice"
            | "random.seed"
            | "hashlib.md5"
            | "hashlib.sha1"
            | "Crypto.Hash.MD5.new"
            | "Crypto.Hash.SHA1.new"
    )
}

fn source_imports_python_crypto(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"import random",
        b"from random ",
        b"import hashlib",
        b"from hashlib ",
        b"from Crypto.Hash",
        b"from Cryptodome.Hash",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a CSPRNG / hardened path (`secrets.*`,
/// `os.urandom`, or hashlib called with `usedforsecurity=False`).
fn source_routed_through_csprng(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"secrets.token_bytes",
        b"secrets.token_hex",
        b"secrets.token_urlsafe",
        b"secrets.randbits",
        b"secrets.choice",
        b"secrets.SystemRandom",
        b"os.urandom(",
        b"usedforsecurity=False",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoPythonAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if source_routed_through_csprng(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_weak_crypto);
        let matches_source = source_imports_python_crypto(file_bytes);
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_random_randint() {
        let src: &[u8] = b"import random\n\
            def run(value):\n    return random.randint(0, 0xFFFF)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("random.randint")],
            ..Default::default()
        };
        assert!(
            CryptoPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_hashlib_md5() {
        let src: &[u8] = b"import hashlib\n\
            def sign(value):\n    return hashlib.md5(value).hexdigest()\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("hashlib.md5")],
            ..Default::default()
        };
        assert!(
            CryptoPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_secrets() {
        let src: &[u8] = b"import random\nimport secrets\n\
            def run(value):\n    if 'STRONG' in value:\n        return secrets.token_bytes(32)\n    return random.randint(0, 0xFFFF)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("random.randint"),
                crate::summary::CalleeSite::bare("secrets.token_bytes"),
            ],
            ..Default::default()
        };
        assert!(
            CryptoPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_md5_used_for_non_security() {
        let src: &[u8] = b"import hashlib\n\
            def cache_key(value):\n    return hashlib.md5(value, usedforsecurity=False).hexdigest()\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "cache_key".into(),
            callees: vec![crate::summary::CalleeSite::bare("hashlib.md5")],
            ..Default::default()
        };
        assert!(
            CryptoPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def add(a, b):\n    return a + b\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            CryptoPythonAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

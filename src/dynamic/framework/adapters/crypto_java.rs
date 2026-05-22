//! Java [`super::super::FrameworkAdapter`] matching weak-crypto
//! sink constructions (`java.util.Random.nextBytes`,
//! `MessageDigest.getInstance("MD5"|"SHA-1")`,
//! `Cipher.getInstance("DES"|"RC4"|"AES/ECB")`,
//! `KeyGenerator.getInstance("DES")`).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Java weak-crypto entry points and the
//! surrounding source imports the matching `java.util.Random` /
//! `java.security.*` / `javax.crypto.*` module.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct CryptoJavaAdapter;

const ADAPTER_NAME: &str = "crypto-java";

fn callee_is_weak_crypto(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "nextBytes" | "nextInt" | "nextLong" | "nextFloat" | "nextDouble" | "getInstance"
    ) || matches!(
        name,
        "java.util.Random.nextBytes"
            | "Random.nextBytes"
            | "MessageDigest.getInstance"
            | "Cipher.getInstance"
            | "KeyGenerator.getInstance"
            | "Mac.getInstance"
    )
}

fn source_imports_java_crypto(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"java.util.Random",
        b"java.security.MessageDigest",
        b"javax.crypto.Cipher",
        b"javax.crypto.KeyGenerator",
        b"javax.crypto.Mac",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// crypto call through a hardened path (`SecureRandom`,
/// `MessageDigest.getInstance("SHA-256")` or stronger,
/// `Cipher.getInstance("AES/GCM/...")`).
fn source_routed_through_strong_path(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"java.security.SecureRandom",
        b"SecureRandom.getInstanceStrong",
        b"new SecureRandom",
        b"\"SHA-256\"",
        b"\"SHA-384\"",
        b"\"SHA-512\"",
        b"\"SHA3-256\"",
        b"\"AES/GCM/",
        b"\"AES/CBC/PKCS5Padding\"",
        b"\"ChaCha20-Poly1305\"",
        b"\"HmacSHA256\"",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for CryptoJavaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
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
        let matches_source = source_imports_java_crypto(file_bytes);
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

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_util_random_nextbytes() {
        let src: &[u8] = b"import java.util.Random;\n\
            public class Vuln {\n    public static byte[] run(String v) {\n        Random r = new Random(0L);\n        byte[] key = new byte[2];\n        r.nextBytes(key);\n        return key;\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("nextBytes")],
            ..Default::default()
        };
        assert!(
            CryptoJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_message_digest_md5() {
        let src: &[u8] = b"import java.security.MessageDigest;\n\
            public class Vuln {\n    public static byte[] sign(byte[] v) throws Exception {\n        MessageDigest md = MessageDigest.getInstance(\"MD5\");\n        return md.digest(v);\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "sign".into(),
            callees: vec![crate::summary::CalleeSite::bare("MessageDigest.getInstance")],
            ..Default::default()
        };
        assert!(
            CryptoJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_source_routes_through_secure_random() {
        let src: &[u8] = b"import java.util.Random;\nimport java.security.SecureRandom;\n\
            public class Vuln {\n    public static byte[] run(String v) {\n        if (v.contains(\"STRONG\")) { byte[] k = new byte[32]; new SecureRandom().nextBytes(k); return k; }\n        Random r = new Random(0L);\n        byte[] k = new byte[2];\n        r.nextBytes(k);\n        return k;\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("nextBytes")],
            ..Default::default()
        };
        assert!(
            CryptoJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_method() {
        let src: &[u8] = b"public class Plain { public static int add(int a, int b) { return a + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            CryptoJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}

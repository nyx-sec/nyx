//! Phase 02, Track A.2: integration coverage for the extension + shebang +
//! content-sniff language probes that drive
//! [`nyx_scanner::dynamic::spec::HarnessSpec`] derivation.
//!
//! Exercises the new behaviour through both the standalone helper
//! ([`Lang::from_path_or_content`]) and the spec-derivation path that calls
//! it, so a regression in either layer fails this suite.
//!
//! Gated on `--features dynamic`; the probes themselves live on the
//! always-present [`nyx_scanner::symbol::Lang`] type, but the spec side they
//! feed into is feature-gated.

#[cfg(feature = "dynamic")]
mod lang_detect {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::spec::{HarnessSpec, SpecDerivationStrategy};
    use nyx_scanner::evidence::{Confidence, Evidence};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use nyx_scanner::symbol::Lang;
    use std::path::{Path, PathBuf};

    fn fixture(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/lang_detect")
            .join(rel)
    }

    fn read_head(path: &Path, cap: usize) -> Vec<u8> {
        use std::io::Read;
        let mut buf = Vec::new();
        let f = std::fs::File::open(path).expect("fixture must exist");
        f.take(cap as u64)
            .read_to_end(&mut buf)
            .expect("fixture must be readable");
        buf
    }

    fn make_diag(id: &str, path: &Path, sink_caps: u32) -> Diag {
        Diag {
            path: path.to_string_lossy().into_owned(),
            line: 4,
            col: 0,
            severity: Severity::High,
            id: id.into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(Evidence {
                sink_caps,
                ..Default::default()
            }),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        }
    }

    // ── Direct probe coverage ────────────────────────────────────────────────

    #[test]
    fn extensionless_python_cli_detected_via_shebang() {
        let path = fixture("cli_python");
        let head = read_head(&path, 200);
        assert!(
            path.extension().is_none(),
            "fixture must remain extensionless"
        );
        assert_eq!(Lang::from_path_or_content(&path, &head), Some(Lang::Python));
    }

    #[test]
    fn extensionless_node_cli_detected_via_shebang() {
        let path = fixture("cli_node");
        let head = read_head(&path, 200);
        assert!(path.extension().is_none());
        assert_eq!(
            Lang::from_path_or_content(&path, &head),
            Some(Lang::JavaScript)
        );
    }

    #[test]
    fn pyi_stub_extension_resolves_to_python() {
        let path = fixture("script.pyi");
        // No file head needed; extension wins.
        assert_eq!(Lang::from_path_or_content(&path, b""), Some(Lang::Python));
        assert_eq!(Lang::from_extension("pyi"), Some(Lang::Python));
    }

    #[test]
    fn cjs_extension_resolves_to_javascript() {
        let path = fixture("module.cjs");
        assert_eq!(
            Lang::from_path_or_content(&path, b""),
            Some(Lang::JavaScript)
        );
        assert_eq!(Lang::from_extension("cjs"), Some(Lang::JavaScript));
    }

    #[test]
    fn kts_extension_resolves_to_java_for_jvm_toolchain() {
        // `.kts` is Kotlin source. The 10-language `Lang` enum has no Kotlin
        // variant, so JVM-family scripts fold into `Lang::Java` for the
        // dynamic spec layer. This covers the `kt` / `kts` extensions called
        // out in the phase 02 deliverables.
        let path = fixture("build.gradle.kts");
        assert_eq!(Lang::from_path_or_content(&path, b""), Some(Lang::Java));
        assert_eq!(Lang::from_extension("kts"), Some(Lang::Java));
        assert_eq!(Lang::from_extension("kt"), Some(Lang::Java));
    }

    #[test]
    fn shebang_only_python_script_resolves() {
        // `cli_python` is the canonical "shebang-only" entry point: no
        // extension, identification depends entirely on `#!/usr/bin/env
        // python3`. Re-asserting separately so a regression that breaks
        // env-prefixed shebang parsing fails its own test name.
        let path = fixture("cli_python");
        let head = read_head(&path, 200);
        assert!(head.starts_with(b"#!/usr/bin/env python3"));
        assert_eq!(Lang::from_path_or_content(&path, &head), Some(Lang::Python));
    }

    #[test]
    fn unknown_extension_with_no_signal_returns_none() {
        // Extension unknown, no shebang, no content sniff hits → None.
        let path = Path::new("does/not/exist.weirdext");
        assert_eq!(Lang::from_path_or_content(path, b"random text"), None);
    }

    // ── Spec derivation must accept the new probes ──────────────────────────

    #[test]
    fn spec_derivation_resolves_lang_for_extensionless_python_cli() {
        // A CLI-namespaced rule against the extensionless Python script must
        // derive a spec (FromCallgraphEntry strategy) — pre-Phase 02 this
        // failed because `Lang::from_extension("")` returned None.
        let path = fixture("cli_python");
        let diag = make_diag("py.cli.argv_handler", &path, Cap::SHELL_ESCAPE.bits());
        let spec =
            HarnessSpec::from_finding(&diag).expect("extensionless CLI script must derive a spec");
        assert_eq!(spec.lang, Lang::Python);
        assert_eq!(spec.toolchain_id, "python-3");
    }

    #[test]
    fn spec_derivation_resolves_lang_for_extensionless_node_cli() {
        let path = fixture("cli_node");
        let diag = make_diag("js.cli.argv_handler", &path, Cap::SHELL_ESCAPE.bits());
        let spec =
            HarnessSpec::from_finding(&diag).expect("extensionless node CLI must derive a spec");
        assert_eq!(spec.lang, Lang::JavaScript);
        assert_eq!(spec.toolchain_id, "node-20");
    }

    #[test]
    fn spec_derivation_accepts_pyi_extension() {
        let path = fixture("script.pyi");
        let diag = make_diag("py.cmdi.os_system", &path, Cap::SHELL_ESCAPE.bits());
        let spec = HarnessSpec::from_finding(&diag).expect(".pyi must derive a spec");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Python);
    }

    #[test]
    fn spec_derivation_accepts_cjs_extension() {
        let path = fixture("module.cjs");
        let diag = make_diag("js.cmdi.exec", &path, Cap::SHELL_ESCAPE.bits());
        let spec = HarnessSpec::from_finding(&diag).expect(".cjs must derive a spec");
        assert_eq!(spec.lang, Lang::JavaScript);
    }

    #[test]
    fn spec_derivation_accepts_kts_extension() {
        let path = fixture("build.gradle.kts");
        let diag = make_diag("java.cmdi.exec", &path, Cap::SHELL_ESCAPE.bits());
        let spec = HarnessSpec::from_finding(&diag).expect(".kts must derive a spec");
        assert_eq!(spec.lang, Lang::Java);
    }

    // ── Regression: previously-detected languages must still resolve ────────

    #[test]
    fn previously_detected_extensions_unchanged() {
        // The classic 10 extensions plus the mid-Phase 01 inventory of
        // C++ extensions — one assertion each so a regression fails on a
        // single extension, not the whole batch.
        for (ext, lang) in [
            ("rs", Lang::Rust),
            ("c", Lang::C),
            ("cpp", Lang::Cpp),
            ("cc", Lang::Cpp),
            ("hpp", Lang::Cpp),
            ("java", Lang::Java),
            ("go", Lang::Go),
            ("php", Lang::Php),
            ("py", Lang::Python),
            ("ts", Lang::TypeScript),
            ("tsx", Lang::TypeScript),
            ("js", Lang::JavaScript),
            ("jsx", Lang::JavaScript),
            ("rb", Lang::Ruby),
        ] {
            assert_eq!(
                Lang::from_extension(ext),
                Some(lang),
                "extension `.{ext}` must continue to resolve to {lang:?}"
            );
        }
    }
}

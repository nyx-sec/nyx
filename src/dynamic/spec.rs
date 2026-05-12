//! Harness specification: the bridge between a static finding and a runnable harness.
//!
//! A [`HarnessSpec`] is built from a [`crate::commands::scan::Diag`] without
//! any further analysis. It records what the dynamic side needs to know:
//! which entry point to drive, which parameter carries the payload, what
//! sink (cap) we expect to hit, and which language toolchain to use.
//!
//! Construction is total but may return `Err` when the finding lacks the
//! evidence required to drive it dynamically (confidence too low, no source
//! span, no callable entry, sink in dead code, etc.). Those findings stay
//! static-only.
//!
//! # Versioning
//!
//! [`SPEC_FORMAT_VERSION`] is baked into every [`HarnessSpec::spec_hash`].
//! Bump it — and update `compute_spec_hash` — whenever any field changes
//! meaning, the hash inputs change, or the corpus changes in a way that
//! would invalidate previously-computed hashes.

use crate::commands::scan::Diag;
use crate::dynamic::corpus::CORPUS_VERSION;
use crate::evidence::{Confidence, FlowStepKind, UnsupportedReason};
use crate::labels::Cap;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Bump whenever [`HarnessSpec`] fields change meaning or the spec hash
/// inputs change. Downstream tools should reject specs with an unrecognised
/// version.
pub const SPEC_FORMAT_VERSION: u32 = 1;

/// Identifies the entry point extracted from a taint flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRef {
    /// Project-relative path of the file containing the entry function.
    pub file: String,
    /// Name of the entry function (unqualified).
    pub function: String,
}

/// What kind of entry point the harness should call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Free function. Build a `main` that calls it directly.
    Function,
    /// HTTP route. Stand up the framework, send a request.
    HttpRoute,
    /// CLI subcommand. Spawn the binary with crafted argv.
    CliSubcommand,
    /// Library API surface. Build an in-process consumer.
    LibraryApi,
}

/// Where the payload goes when the harness fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadSlot {
    /// Nth positional parameter of the entry function.
    Param(usize),
    /// Named HTTP query parameter.
    QueryParam(String),
    /// HTTP request body (raw bytes).
    HttpBody,
    /// Environment variable.
    EnvVar(String),
    /// CLI argv slot (0-based, excluding argv[0]).
    Argv(usize),
    /// stdin.
    Stdin,
}

/// Self-contained recipe for building and running a single harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// Stable id of the source finding (`Diag::stable_hash` as hex).
    pub finding_id: String,
    /// Project-relative path to the file holding the entry point.
    pub entry_file: String,
    /// Function/route/subcommand name to drive.
    pub entry_name: String,
    /// How to invoke it.
    pub entry_kind: EntryKind,
    /// Source language (drives toolchain selection).
    pub lang: Lang,
    /// Toolchain identifier string (e.g. `"rust-stable"`, `"node-20"`).
    /// Informational; harness builder may override for local installs.
    pub toolchain_id: String,
    /// Where the payload is injected.
    pub payload_slot: PayloadSlot,
    /// Sink capability we expect to fire (drives oracle + corpus pick).
    pub expected_cap: Cap,
    /// Optional symex-derived constraint hints (prefix/suffix locks, etc.).
    /// Populated later from `Evidence::engine_notes` when available.
    #[serde(default)]
    pub constraint_hints: Vec<String>,
    /// Project-relative path of the file containing the sink call site.
    /// Used by the harness emitter to instrument the exact line.
    pub sink_file: String,
    /// 1-based line number of the sink call site in `sink_file`.
    pub sink_line: u32,
    /// Blake3 hash (16 hex chars) of the spec's key fields, version-pinned.
    /// Stable across identical specs; used for deduplication and caching.
    pub spec_hash: String,
}

impl HarnessSpec {
    /// Build a spec from a finding. Returns `Err` with a typed reason when
    /// the finding cannot be driven dynamically.
    ///
    /// Conditions for `Err` return:
    /// - Confidence below `Medium` (bypass with `from_finding_opts(diag, true)`)
    /// - No `flow_steps` in evidence
    /// - No callable entry (source step missing a `function` annotation)
    /// - Unknown language (file extension unrecognised)
    /// - Zero sink capability bits
    pub fn from_finding(diag: &Diag) -> Result<Self, UnsupportedReason> {
        Self::from_finding_opts(diag, false)
    }

    /// Like `from_finding`, but with `verify_all_confidence=true` the
    /// `Confidence >= Medium` gate is skipped so low-confidence findings
    /// are also attempted.
    pub fn from_finding_opts(
        diag: &Diag,
        verify_all_confidence: bool,
    ) -> Result<Self, UnsupportedReason> {
        // Require at least Medium confidence unless caller opts out.
        if !verify_all_confidence {
            match diag.confidence {
                Some(c) if c >= Confidence::Medium => {}
                _ => return Err(UnsupportedReason::ConfidenceTooLow),
            }
        }

        let evidence = diag.evidence.as_ref().ok_or(UnsupportedReason::NoFlowSteps)?;

        if evidence.flow_steps.is_empty() {
            return Err(UnsupportedReason::NoFlowSteps);
        }

        let entry = outermost_entry(&evidence.flow_steps)
            .ok_or(UnsupportedReason::SpecDerivationFailed)?;

        let ext = Path::new(&entry.file)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let lang = Lang::from_extension(ext).ok_or(UnsupportedReason::SpecDerivationFailed)?;

        let expected_cap = Cap::from_bits_truncate(evidence.sink_caps);
        if expected_cap.is_empty() {
            return Err(UnsupportedReason::SpecDerivationFailed);
        }

        let toolchain_id = toolchain_id_for_lang(lang).to_owned();

        // Sink location: prefer explicit sink step; fall back to diag location.
        let (sink_file, sink_line) = evidence
            .flow_steps
            .iter()
            .rev()
            .find(|s| matches!(s.kind, FlowStepKind::Sink))
            .map(|s| (s.file.clone(), s.line))
            .unwrap_or_else(|| (diag.path.clone(), diag.line as u32));

        let mut spec = HarnessSpec {
            finding_id: format!("{:016x}", diag.stable_hash),
            entry_file: entry.file,
            entry_name: entry.function,
            entry_kind: EntryKind::Function,
            lang,
            toolchain_id,
            payload_slot: PayloadSlot::Param(0),
            expected_cap,
            constraint_hints: vec![],
            sink_file,
            sink_line,
            spec_hash: String::new(),
        };

        spec.spec_hash = compute_spec_hash(&spec);
        Ok(spec)
    }
}

/// Walk `flow_steps` and return the entry point: the enclosing function of
/// the first `Source` step that has a function annotation. This is the
/// outermost callable that receives the tainted input.
pub fn outermost_entry(steps: &[crate::evidence::FlowStep]) -> Option<EntryRef> {
    for step in steps {
        if matches!(step.kind, FlowStepKind::Source) {
            if let Some(ref func) = step.function {
                if !func.is_empty() {
                    return Some(EntryRef {
                        file: step.file.clone(),
                        function: func.clone(),
                    });
                }
            }
        }
    }
    None
}

/// Default toolchain label for a language (informational; harness builder
/// may override for locally-installed compilers/runtimes).
fn toolchain_id_for_lang(lang: Lang) -> &'static str {
    match lang {
        Lang::Rust => "rust-stable",
        Lang::C => "gcc-stable",
        Lang::Cpp => "g++-stable",
        Lang::Java => "java-21",
        Lang::Go => "go-stable",
        Lang::Php => "php-8",
        Lang::Python => "python-3",
        Lang::Ruby => "ruby-3",
        Lang::TypeScript | Lang::JavaScript => "node-20",
    }
}

/// Blake3 hash of the spec's key fields, truncated to 8 bytes and hex-encoded.
///
/// Inputs (in order):
///   `SPEC_FORMAT_VERSION` (u32 LE), entry_file, entry_name, payload_slot tag
///   + value, expected_cap bits (u32 LE), sorted constraint_hints,
///   toolchain_id, `CORPUS_VERSION` (u32 LE).
///
/// Bump [`SPEC_FORMAT_VERSION`] when the inputs or semantics change.
fn compute_spec_hash(spec: &HarnessSpec) -> String {
    let mut h = blake3::Hasher::new();

    h.update(&SPEC_FORMAT_VERSION.to_le_bytes());
    h.update(spec.entry_file.as_bytes());
    h.update(b"\0");
    h.update(spec.entry_name.as_bytes());
    h.update(b"\0");

    // Payload slot: tag byte + optional value
    match &spec.payload_slot {
        PayloadSlot::Param(n) => {
            h.update(&[0u8]);
            h.update(&(*n as u64).to_le_bytes());
        }
        PayloadSlot::QueryParam(s) => {
            h.update(&[1u8]);
            h.update(s.as_bytes());
        }
        PayloadSlot::HttpBody => {
            h.update(&[2u8]);
        }
        PayloadSlot::EnvVar(s) => {
            h.update(&[3u8]);
            h.update(s.as_bytes());
        }
        PayloadSlot::Argv(n) => {
            h.update(&[4u8]);
            h.update(&(*n as u64).to_le_bytes());
        }
        PayloadSlot::Stdin => {
            h.update(&[5u8]);
        }
    }

    h.update(&spec.expected_cap.bits().to_le_bytes());

    let mut hints = spec.constraint_hints.clone();
    hints.sort_unstable();
    for hint in &hints {
        h.update(hint.as_bytes());
        h.update(b"\0");
    }

    h.update(spec.toolchain_id.as_bytes());
    h.update(b"\0");
    h.update(spec.sink_file.as_bytes());
    h.update(b"\0");
    h.update(&spec.sink_line.to_le_bytes());
    h.update(&CORPUS_VERSION.to_le_bytes());

    let out = h.finalize();
    let bytes = out.as_bytes();
    format!("{:016x}", u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, FlowStep, FlowStepKind};

    fn source_step(file: &str, function: &str) -> FlowStep {
        FlowStep {
            step: 1,
            kind: FlowStepKind::Source,
            file: file.into(),
            line: 1,
            col: 0,
            snippet: None,
            variable: Some("x".into()),
            callee: None,
            function: Some(function.into()),
            is_cross_file: false,
        }
    }

    fn sink_step(file: &str) -> FlowStep {
        FlowStep {
            step: 2,
            kind: FlowStepKind::Sink,
            file: file.into(),
            line: 10,
            col: 0,
            snippet: None,
            variable: None,
            callee: None,
            function: None,
            is_cross_file: false,
        }
    }

    #[test]
    fn outermost_entry_picks_source_step() {
        let steps = vec![source_step("src/main.rs", "handle_request"), sink_step("src/main.rs")];
        let entry = outermost_entry(&steps).unwrap();
        assert_eq!(entry.file, "src/main.rs");
        assert_eq!(entry.function, "handle_request");
    }

    #[test]
    fn outermost_entry_none_when_no_source() {
        let steps = vec![sink_step("src/main.rs")];
        assert!(outermost_entry(&steps).is_none());
    }

    #[test]
    fn outermost_entry_none_when_source_has_no_function() {
        let mut step = source_step("src/main.rs", "");
        step.function = None;
        let steps = vec![step, sink_step("src/main.rs")];
        assert!(outermost_entry(&steps).is_none());
    }

    #[test]
    fn from_finding_err_low_confidence() {
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Low),
            ..Default::default()
        };
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::ConfidenceTooLow
        );
    }

    #[test]
    fn from_finding_err_no_flow_steps() {
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Medium),
            evidence: Some(Evidence::default()),
            ..Default::default()
        };
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::NoFlowSteps
        );
    }

    #[test]
    fn from_finding_ok_rust_medium_confidence() {
        use crate::labels::Cap;
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.rs", "process"),
                sink_step("src/handler.rs"),
            ],
            sink_caps: Cap::SQL_QUERY.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Medium),
            evidence: Some(evidence),
            ..Default::default()
        };
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.lang, Lang::Rust);
        assert_eq!(spec.entry_name, "process");
        assert_eq!(spec.toolchain_id, "rust-stable");
        assert!(!spec.spec_hash.is_empty());
    }

    #[test]
    fn spec_hash_is_deterministic() {
        use crate::labels::Cap;
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.rs", "process"),
                sink_step("src/handler.rs"),
            ],
            sink_caps: Cap::SQL_QUERY.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            ..Default::default()
        };
        let s1 = HarnessSpec::from_finding(&diag).unwrap();
        let s2 = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(s1.spec_hash, s2.spec_hash);
    }

    fn base_spec() -> HarnessSpec {
        use crate::labels::Cap;
        let mut spec = HarnessSpec {
            finding_id: "0000000000000000".into(),
            entry_file: "src/handler.rs".into(),
            entry_name: "process".into(),
            entry_kind: EntryKind::Function,
            lang: crate::symbol::Lang::Rust,
            toolchain_id: "rust-stable".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/handler.rs".into(),
            sink_line: 10,
            spec_hash: String::new(),
        };
        spec.spec_hash = compute_spec_hash(&spec);
        spec
    }

    #[test]
    fn spec_hash_flips_on_entry_file() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.entry_file = "src/other.rs".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "entry_file mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_entry_name() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.entry_name = "other_handler".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "entry_name mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_payload_slot() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.payload_slot = PayloadSlot::Param(1);
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "payload_slot mutation must change spec_hash");

        let mut s3 = s1.clone();
        s3.payload_slot = PayloadSlot::HttpBody;
        s3.spec_hash = compute_spec_hash(&s3);
        assert_ne!(s1.spec_hash, s3.spec_hash, "payload_slot tag change must change spec_hash");

        let mut s4 = s1.clone();
        s4.payload_slot = PayloadSlot::EnvVar("NYX_INPUT".into());
        s4.spec_hash = compute_spec_hash(&s4);
        assert_ne!(s1.spec_hash, s4.spec_hash, "EnvVar payload_slot must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_expected_cap() {
        use crate::labels::Cap;
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.expected_cap = Cap::CODE_EXEC;
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "expected_cap mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_constraint_hints() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.constraint_hints = vec!["prefix:admin/".into()];
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "constraint_hints mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_toolchain_id() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.toolchain_id = "rust-nightly".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "toolchain_id mutation must change spec_hash");
    }
}

//! Top-level entry point for the dynamic layer.
//!
//! The CLI subcommand and any library consumer call [`verify_finding`].
//! It is the only function the rest of the crate needs to know about.

use crate::callgraph::CallGraph;
use crate::commands::scan::Diag;
use crate::dynamic::corpus::{CORPUS_VERSION, payloads_for};
use crate::dynamic::oob::OobListener;
use crate::dynamic::report::{AttemptSummary, VerifyResult, VerifyStatus};
use crate::dynamic::runner::{RunError, run_spec};
use crate::dynamic::sandbox::{SandboxOptions, toolchain_id_with_digest};
use crate::dynamic::spec::{HarnessSpec, SPEC_FORMAT_VERSION};
use crate::dynamic::stubs::StubHarness;
use crate::dynamic::telemetry::{self, SamplingPolicy, TelemetryEvent};
use crate::dynamic::toolchain;
#[cfg(target_os = "linux")]
use crate::evidence::HardeningPrimitive;
use crate::evidence::{
    HardeningSummary, InconclusiveReason, SpecDerivationStrategy, UnsupportedReason,
};
use crate::summary::GlobalSummaries;
use crate::utils::config::Config;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub sandbox: SandboxOptions,
    /// Project root for repro artifact symlinks (optional).
    pub project_root: Option<std::path::PathBuf>,
    /// Path to the Nyx index database for the dynamic verdict cache (§12 Q5).
    /// When `None` (e.g. `--no-index` mode), the cache is bypassed entirely.
    pub db_path: Option<std::path::PathBuf>,
    /// When `true`, skip the `Confidence >= Medium` gate and attempt
    /// verification on all findings. Corresponds to `--verify-all-confidence`.
    pub verify_all_confidence: bool,
    /// Cross-file function summaries shared by every finding in a scan.
    ///
    /// Threaded into [`HarnessSpec::from_finding_with_summaries`] so the
    /// summary-walk strategy and the entry-kind-aware callgraph strategy
    /// can resolve the diag's enclosing function against the same
    /// [`GlobalSummaries`] index the taint engine used. Held by `Arc` so the
    /// caller (e.g. the scan command) can build the index once and reuse it
    /// across the per-finding loop without cloning.
    ///
    /// `None` disables the summary-driven derivation paths; strategy 3 is a
    /// no-op and strategy 4 falls back to the rule-id substring heuristic.
    pub summaries: Option<Arc<GlobalSummaries>>,
    /// Whole-program [`CallGraph`] threaded into the callgraph-aware
    /// branch of strategy 4 ([`SpecDerivationStrategy::FromCallgraphEntry`]).
    ///
    /// When present alongside [`Self::summaries`], the verifier walks
    /// reverse edges from the sink's enclosing function to the nearest
    /// entry-point ancestor (route handler, CLI subcommand, `main`).
    /// `None` keeps strategy 4 on the legacy rule-id substring path.
    pub callgraph: Option<Arc<CallGraph>>,
    /// When `true`, refuse to stamp `Confirmed`
    /// on findings whose [`HarnessSpec::expected_cap`] includes
    /// [`crate::labels::Cap::FILE_IO`] because the active sandbox
    /// backend cannot confine filesystem reach.  Set by
    /// [`Self::from_config`] on macOS hosts where
    /// `/usr/bin/sandbox-exec` is missing; the verifier downgrades
    /// such findings to
    /// [`crate::evidence::InconclusiveReason::BackendInsufficient`]
    /// rather than running against an unhardened host.
    pub refuse_filesystem_confirm: bool,
    /// Sampling policy applied to every telemetry event emitted from the
    /// verify pipeline.  Default `keep_all` so unit tests and embedded
    /// callers do not silently lose records.
    pub telemetry_policy: SamplingPolicy,
    /// When `true` the verifier prints every recorded
    /// [`crate::dynamic::trace::TraceEvent`] to stderr at end-of-verify.
    /// Wired to the `--verbose` CLI flag; off by default so
    /// non-interactive scans stay quiet.
    pub trace_verbose: bool,
    /// When `true`, the verifier re-runs
    /// `reproduce.sh` against the freshly written repro bundle whenever a
    /// finding is `Confirmed` and stamps the typed
    /// [`crate::evidence::VerifyResult::replay_stable`] field via
    /// [`crate::dynamic::repro::replay_stability`]. Opt-in because
    /// invoking `reproduce.sh` per Confirmed finding doubles wall-clock
    /// cost. The eval-corpus driver flips it on; interactive `nyx scan`
    /// keeps it off and leaves `replay_stable: None`.
    ///
    /// Default `false`. [`Self::from_config`] honours the
    /// `NYX_VERIFY_REPLAY_STABLE` environment variable (`1` / `true`).
    pub replay_stable_check: bool,
    /// When `true` and `replay_stable_check` is also `true`, the verifier
    /// passes `--docker` to `reproduce.sh` instead of running it through the
    /// host's process backend. This lets eval-corpus runs mark
    /// `replay_stable` from the bare-image replay path when the host has
    /// stripped language toolchains.
    ///
    /// Default `false`.  [`Self::from_config`] honours the
    /// `NYX_VERIFY_REPLAY_DOCKER` environment variable (`1` / `true`).
    /// The flag is inert when `replay_stable_check == false`.
    pub replay_use_docker: bool,
    /// Test/observability hook: when `Some`, [`verify_finding`] records
    /// every [`crate::dynamic::trace::TraceEvent`] into this trace handle
    /// instead of constructing a fresh internal one. Lets integration
    /// tests inspect the verifier's stage timeline (e.g. the
    /// `framework_adapter_*` events) without scraping stderr or writing
    /// a repro bundle. `None` in production paths.
    pub trace_sink: Option<Arc<crate::dynamic::trace::VerifyTrace>>,
}

impl VerifyOptions {
    /// Build `VerifyOptions` from scanner config.
    ///
    /// Binds a per-scan [`OobListener`] on a free loopback port and attaches
    /// it to `sandbox.oob_listener`. The listener is held by `Arc` so every
    /// per-finding clone of `VerifyOptions` shares the same accept thread;
    /// it is torn down via the `OobListener::Drop` impl once the last
    /// `Arc` is released at end of scan.
    ///
    /// If `OobListener::bind` fails (e.g. all loopback ports are in use),
    /// the field stays `None`; the runner skips OOB-callback payloads
    /// (`src/dynamic/runner.rs` `oob_nonce_slot` branch) while non-OOB
    /// payloads continue to run against their existing oracle.
    pub fn from_config(config: &Config) -> Self {
        use crate::dynamic::sandbox::{NetworkPolicy, ProcessHardeningProfile, SandboxBackend};
        let backend = match config.scanner.verify_backend.as_str() {
            "docker" => SandboxBackend::Docker,
            "process" => SandboxBackend::Process,
            "firecracker" => SandboxBackend::Firecracker,
            _ => SandboxBackend::Auto,
        };
        // Surface the per-scan listener as a
        // [`NetworkPolicy::OobOutbound`] so the docker backend turns on
        // bridge networking + the iptables egress filter, and the process
        // backend reaches the listener via the same accessor as before.
        let network_policy = match OobListener::bind().ok().map(Arc::new) {
            Some(listener) => NetworkPolicy::OobOutbound { listener },
            None => NetworkPolicy::None,
        };
        // `--harden=strict` (or `harden_profile = "strict"` in nyx.toml)
        // opts the verifier into the full process-backend lockdown.  Linux
        // engages namespace unshare + chroot + default-deny seccomp on top
        // of the baseline; macOS wraps the harness with `sandbox-exec -f
        // <cap>.sb` keyed off the per-finding expected cap (set later in
        // `verify_finding` because the cap is only known once spec
        // derivation runs).
        let process_hardening = match config.scanner.harden_profile.as_str() {
            "strict" => ProcessHardeningProfile::Strict,
            _ => ProcessHardeningProfile::Standard,
        };
        // The macOS process backend depends on `/usr/bin/sandbox-exec` to
        // confine filesystem reach.  When the
        // binary is absent, surface that up-front so filesystem oracles
        // degrade to `Inconclusive(BackendInsufficient)` instead of
        // running against an unhardened host.
        #[cfg(target_os = "macos")]
        let refuse_filesystem_confirm =
            !crate::dynamic::sandbox::process_macos::sandbox_exec_available();
        #[cfg(not(target_os = "macos"))]
        let refuse_filesystem_confirm = false;

        let replay_stable_check = std::env::var("NYX_VERIFY_REPLAY_STABLE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);
        let replay_use_docker = std::env::var("NYX_VERIFY_REPLAY_DOCKER")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);

        Self {
            sandbox: SandboxOptions {
                backend,
                network_policy,
                process_hardening,
                ..SandboxOptions::default()
            },
            project_root: None,
            db_path: None,
            verify_all_confidence: config.scanner.verify_all_confidence,
            summaries: None,
            callgraph: None,
            refuse_filesystem_confirm,
            telemetry_policy: SamplingPolicy::from_config(&config.telemetry),
            trace_verbose: false,
            replay_stable_check,
            replay_use_docker,
            trace_sink: None,
        }
    }
}

/// Predicate driving the
/// [`SandboxOptions::bind_mount_host_libs`] opt-in for the Linux
/// process backend under [`ProcessHardeningProfile::Strict`].
///
/// Returns `true` for languages whose harness runtime ships as an
/// external interpreter (`python3`, `node`, `java`, `ruby`, `php`).
/// Those interpreters dlopen shared libraries from the host filesystem
/// at cold-start, so the `chroot(2)` step in
/// [`crate::dynamic::sandbox::process_linux`] needs the host's
/// `/lib`, `/lib64`, `/usr/lib`, and `/usr/bin` reachable inside the
/// workdir.
///
/// Returns `false` for natively-compiled languages (`rust`, `c`,
/// `cpp`, `go`).  Their harnesses are linked statically under Strict
/// via [`crate::dynamic::build_sandbox::static_link_for_profile`], so
/// the chroot survives without bind-mounts and we skip the
/// `mount(2)` syscall sequence to avoid the host-mount side-channel
/// the bind-mounts open up.
///
/// Standard-profile runs ignore this entirely; the engine only
/// consults the predicate inside the Strict branch in
/// [`verify_finding`].
fn lang_needs_host_libs(lang: crate::symbol::Lang) -> bool {
    use crate::symbol::Lang::*;
    matches!(lang, Python | JavaScript | TypeScript | Java | Ruby | Php)
}

// ── Dynamic verdict cache helpers (§12 Q5) ───────────────────────────────────

/// Hash the content of `entry_file` with BLAKE3 and return a 16-char hex string.
///
/// Returns `"unavailable"` when the file cannot be read (e.g. the finding
/// points to a file that no longer exists). The cache simply misses in that case.
fn compute_entry_content_hash(entry_file: &str) -> String {
    std::fs::read(entry_file)
        .map(|bytes| {
            let h = blake3::hash(&bytes);
            format!(
                "{:016x}",
                u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap())
            )
        })
        .unwrap_or_else(|_| "unavailable".to_owned())
}

/// Placeholder transitive import digest.
///
/// Full transitive import analysis is deferred. The empty string is a valid
/// conservative placeholder: a stale cache hit can only occur when a transitive
/// import changes without the entry file changing, which is rare and unlikely to
/// cause incorrect verdicts given the harness is also re-confirmed by the oracle.
fn transitive_import_digest_placeholder() -> &'static str {
    ""
}

/// Look up a cached verdict in the `dynamic_verdict_cache` table.
///
/// Opens the DB in read-write mode (no-create) so it never creates a DB that
/// does not yet exist. Returns `None` on any error or cache miss.
fn lookup_verdict_cache(
    db_path: &std::path::Path,
    spec_hash: &str,
    entry_content_hash: &str,
    transitive_import_digest: &str,
    toolchain_id: &str,
) -> Option<VerifyResult> {
    use rusqlite::{Connection, OpenFlags};
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(db_path, flags).ok()?;
    conn.query_row(
        "SELECT verdict_json FROM dynamic_verdict_cache \
         WHERE spec_hash = ?1 AND entry_content_hash = ?2 \
         AND transitive_import_digest = ?3 AND toolchain_id = ?4 \
         AND corpus_version = ?5 AND spec_format_version = ?6 \
         LIMIT 1",
        rusqlite::params![
            spec_hash,
            entry_content_hash,
            transitive_import_digest,
            toolchain_id,
            CORPUS_VERSION as i64,
            SPEC_FORMAT_VERSION as i64,
        ],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|json| serde_json::from_str(&json).ok())
}

/// Insert or replace a verdict in the `dynamic_verdict_cache` table.
///
/// Best-effort: silently ignores all errors (DB unavailable, serialisation
/// failure, UNIQUE constraint violation, etc.). The cache is an optimisation;
/// a miss is never fatal.
fn insert_verdict_cache(
    db_path: &std::path::Path,
    spec_hash: &str,
    entry_content_hash: &str,
    transitive_import_digest: &str,
    toolchain_id: &str,
    result: &VerifyResult,
) {
    use rusqlite::{Connection, OpenFlags};
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(db_path, flags) else {
        return;
    };
    let Ok(json) = serde_json::to_string(result) else {
        return;
    };
    let now = chrono::Utc::now().to_rfc3339();
    let _ = conn.execute(
        "INSERT OR REPLACE INTO dynamic_verdict_cache \
         (spec_hash, entry_content_hash, transitive_import_digest, toolchain_id, \
          corpus_version, spec_format_version, verdict_json, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            spec_hash,
            entry_content_hash,
            transitive_import_digest,
            toolchain_id,
            CORPUS_VERSION as i64,
            SPEC_FORMAT_VERSION as i64,
            json,
            now,
        ],
    );
}

/// Build an `Inconclusive(EntryKindUnsupported)` verdict for a finding whose
/// derived spec named an entry kind the lang emitter does not yet handle.
///
/// `attempted` is the spec's entry kind; `lang` is the spec's language; the
/// supported list and human-readable hint come from the lang emitter via
/// [`crate::dynamic::lang::entry_kinds_supported`] /
/// [`crate::dynamic::lang::entry_kind_hint`], so adding new entry-kind
/// shapes there automatically narrows what gets routed here without
/// touching this function.
///
/// The caller passes the originating [`Diag`] when one is in scope (for the
/// pre-flight gate) or `None` otherwise (for the residual harness-emit path,
/// where only the spec is available); telemetry derives `lang`/`path` from
/// the diag when present and falls back to the spec otherwise.
fn entry_kind_unsupported_verdict(
    finding_id: String,
    diag: Option<&Diag>,
    spec_entry_path: &str,
    lang: crate::symbol::Lang,
    attempted: crate::dynamic::spec::EntryKindTag,
    policy: &SamplingPolicy,
) -> VerifyResult {
    let supported = crate::dynamic::lang::entry_kinds_supported(lang).to_vec();
    let hint = crate::dynamic::lang::entry_kind_hint(lang, attempted);
    let inconclusive_reason = InconclusiveReason::EntryKindUnsupported {
        lang,
        attempted,
        supported,
        hint,
    };
    let event = match diag {
        Some(d) => TelemetryEvent::no_spec(
            d,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        ),
        None => TelemetryEvent::no_spec_for_path(
            spec_entry_path,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        ),
    };
    telemetry::emit_with_policy(&event, policy);
    VerifyResult {
        finding_id,
        status: VerifyStatus::Inconclusive,
        triggered_payload: None,
        reason: None,
        inconclusive_reason: Some(inconclusive_reason),
        detail: None,
        attempts: vec![],
        toolchain_match: None,
        differential: None,
        replay_stable: None,
        wrong: None,
        hardening_outcome: None,
    }
}

/// Decide whether a [`HarnessSpec::from_finding_opts`] failure should surface
/// as `Unsupported` (the finding is genuinely unmodellable) or
/// `Inconclusive(SpecDerivationFailed)` (the rule namespace or sink evidence
/// carried enough signal that derivation *should* have worked).
///
/// The rule-of-thumb: if any spec-derivation strategy could plausibly have
/// fired (i.e. the finding had a usable rule namespace, non-empty path, or
/// non-zero sink caps) yet none produced a spec, the failure is
/// **Inconclusive** — we tried and missed. Otherwise it's **Unsupported**.
fn spec_derivation_failed_verdict(
    finding_id: String,
    diag: &Diag,
    reason: UnsupportedReason,
    policy: &SamplingPolicy,
) -> VerifyResult {
    if matches!(reason, UnsupportedReason::SpecDerivationFailed) && should_be_inconclusive(diag) {
        let strategies: Vec<SpecDerivationStrategy> = HarnessSpec::derivation_strategies().to_vec();
        let hint = derivation_failure_hint(diag);
        let inconclusive_reason = InconclusiveReason::SpecDerivationFailed {
            tried: strategies,
            hint,
        };
        let event = TelemetryEvent::no_spec(
            diag,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        );
        telemetry::emit_with_policy(&event, policy);
        return VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(inconclusive_reason),
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };
    }

    let event = TelemetryEvent::no_spec(diag, VerifyStatus::Unsupported, None);
    telemetry::emit_with_policy(&event, policy);

    VerifyResult {
        finding_id,
        status: VerifyStatus::Unsupported,
        triggered_payload: None,
        reason: Some(reason),
        inconclusive_reason: None,
        detail: None,
        attempts: vec![],
        toolchain_match: None,
        differential: None,
        replay_stable: None,
        wrong: None,
        hardening_outcome: None,
    }
}

/// Phase 25 (Track K.0): render the [`crate::dynamic::trace::TraceStage::SpecScoringResult`]
/// detail string.
///
/// Deterministic and within the trace-detail budget: the winning strategy
/// followed by the loser ranking in descending-score order, each tagged with
/// its covered flow depth so a trace consumer sees *why* the winner won.
fn format_spec_scoring_detail(
    winner: SpecDerivationStrategy,
    runners_up: &[(SpecDerivationStrategy, crate::dynamic::spec::SpecScore)],
) -> String {
    use std::fmt::Write as _;
    let mut detail = format!("winner={winner} runners_up=");
    if runners_up.is_empty() {
        detail.push_str("none");
    } else {
        for (i, (strat, score)) in runners_up.iter().enumerate() {
            if i > 0 {
                detail.push(',');
            }
            let _ = write!(detail, "{strat}:{}", score.flow_depth);
        }
    }
    detail
}

/// True when the finding has *some* derivable signal (rule namespace or a
/// drivable taint flow) so a spec-derivation failure should be surfaced as
/// `Inconclusive` rather than `Unsupported`.
///
/// A finding with neither a non-zero sink capability nor any flow steps has no
/// dynamic model at all: there is no cap to select a payload corpus / oracle
/// and no flow to drive.  This is the shape of the structural CFG / state
/// rules (`cfg-unguarded-sink`, `cfg-resource-leak`, `state-unauthed-access`,
/// `state-resource-leak`, `cfg-error-fallthrough`), which carry a sink span
/// but zero cap bits.  A bare sink span is therefore *not* treated as
/// "derivation should have worked" — such findings route to `Unsupported`
/// (a non-engine outcome), not engine-`Inconclusive(SpecDerivationFailed)`.
fn should_be_inconclusive(diag: &Diag) -> bool {
    let has_rule_ns = diag.id.split('.').count() >= 2
        && !diag.id.starts_with("taint-")
        && !diag.id.starts_with("cfg-")
        && !diag.id.starts_with("state-");
    let has_drivable_evidence = diag
        .evidence
        .as_ref()
        .map(|e| e.sink_caps != 0 || !e.flow_steps.is_empty())
        .unwrap_or(false);
    has_rule_ns || has_drivable_evidence
}

fn derivation_failure_hint(diag: &Diag) -> String {
    let ev = match diag.evidence.as_ref() {
        Some(e) => e,
        None => return "no evidence on finding".to_owned(),
    };
    let mut parts: Vec<String> = Vec::new();
    if !diag.id.is_empty() {
        parts.push(format!("rule_id={}", diag.id));
    }
    if ev.sink_caps == 0 {
        parts.push("sink_caps=0".to_owned());
    }
    if ev.flow_steps.is_empty() {
        parts.push("no_flow_steps".to_owned());
    }
    if diag.path.is_empty() {
        parts.push("empty_path".to_owned());
    } else {
        parts.push(format!("path={}", diag.path));
    }
    parts.join("; ")
}

/// True when a build / runtime-load failure's stderr indicates a genuinely
/// absent host dependency or toolchain rather than a defect in the harness
/// the engine emitted.
///
/// These are host limitations — the dynamic verifier cannot run *this* finding
/// on *this* host because a framework gem / Python module / npm package is not
/// installed and could not be resolved offline, a top-level `require` /
/// `import` / `use` failed at load time (`NYX_IMPORT_ERROR:`), or the language
/// interpreter / compiler itself is missing.  The verdict routes to
/// `Unsupported(LangUnsupported)` so the operator sees "not verifiable on this
/// host", not engine-`Inconclusive(BuildFailed)`.
///
/// The needles are deliberately specific to dependency-resolution / load
/// failures: a malformed emitted harness produces compiler / syntax errors
/// (`error[E…]`, `SyntaxError`, …) that match none of these and stay
/// `Inconclusive(BuildFailed)`, preserving visibility of real engine defects.
fn build_failure_is_host_limitation(stderr: &str) -> bool {
    const NEEDLES: &[&str] = &[
        // Top-level require/import/use failure emitted by the per-language
        // harness preambles (js_shared / ruby / php / python) with exit 77.
        "NYX_IMPORT_ERROR:",
        // Python: missing module / offline pip resolution miss.
        "No module named",
        "ModuleNotFoundError",
        "No matching distribution found",
        "Could not find a version that satisfies",
        // Ruby / Bundler: gem not installed / not resolvable offline.
        "Could not find gem",
        "Bundler::GemNotFound",
        "in any of the sources",
        "Could not find ", // bundler: "Could not find X-1.2.3 in locally installed gems"
        // Node: missing package.
        "Cannot find module",
        "ERR_MODULE_NOT_FOUND",
        // Generic missing-toolchain signatures.
        "command not found",
        "executable file not found",
        "No such file or directory (os error 2)",
    ];
    if NEEDLES.iter().any(|n| stderr.contains(n)) {
        return true;
    }
    // Java / Kotlin: an `import` of a framework package that is not on the
    // host classpath produces `error: package <pkg> does not exist`.  Offline
    // and without the dependency JAR (e.g. Spring on a bare host), that is a
    // host limitation, not an emitter defect.
    if stderr.contains("does not exist") && stderr.contains("package ") {
        return true;
    }
    false
}

/// True when a C / C++ harness build failure proves the emitter could not
/// bind a standalone driver to the *resolved entry symbol*, as opposed to a
/// fixable defect in otherwise-supported emitted code.
///
/// The compiler-native languages embed the fixture via `#include "entry.c"`
/// and provide their own `main`.  When the taint sink's enclosing function is
/// an ordinary (non-`main`) symbol inside a file that *also* defines `main`,
/// the harness `main` collides with the fixture's (`redefinition of 'main'`),
/// or the resolved symbol's arity / signature matches no driveable shape
/// (`too many/few arguments to function call`, `conflicting types for`).
/// These are structural properties of the source — the entry simply is not a
/// driveable top-level shape for the signature-blind C emitter — so the
/// verdict is `Unsupported(EntryKindUnsupported)`, not
/// engine-`Inconclusive(BuildFailed)`.
///
/// Per-language signatures (the compiler / type-checker is present and the
/// emitted source is syntactically well-formed; it simply cannot *bind* a
/// runnable driver to the resolved entry's shape):
/// - **C / C++**: the harness `main` collides with a fixture that defines its
///   own `main` (`redefinition of 'main'`), or the resolved symbol's arity /
///   signature matches no driveable shape (`too many/few arguments`,
///   `conflicting types for`).
/// - **Go**: the cross-package driver references a symbol that does not
///   resolve (`undefined: entry.Run` — the resolved entry is a *method* on a
///   struct or an unexported function, not the package-level func the default
///   driver calls; or `undefined: strings` — the emitter's driver for this
///   framework shape references a package it did not import).  Either way the
///   Go emitter cannot produce a runnable driver for this entry shape.
/// - **Java**: the resolved entry is an *instance* method the static driver
///   invokes without a receiver (`non-static method … cannot be referenced
///   from a static context`).
///
/// These are deterministic shape-incompatibilities, not retriable build
/// failures, so they route to `Unsupported(EntryKindUnsupported)` rather than
/// engine-`Inconclusive(BuildFailed)`.  Genuinely-absent toolchains /
/// dependencies are handled separately by [`build_failure_is_host_limitation`];
/// a transient build error in an otherwise-supported shape carries none of
/// these signatures and still surfaces as `Inconclusive(BuildFailed)`.
fn build_failure_is_undrivable_entry(lang: crate::symbol::Lang, stderr: &str) -> bool {
    use crate::symbol::Lang;
    match lang {
        Lang::C | Lang::Cpp => {
            const NEEDLES: &[&str] = &[
                "redefinition of 'main'",
                "redefinition of \u{2018}main\u{2019}", // gcc curly-quote variant
                "too many arguments to function call",
                "too few arguments to function call",
                "too many arguments to function", // gcc phrasing
                "too few arguments to function",  // gcc phrasing
                "conflicting types for",
            ];
            NEEDLES.iter().any(|n| stderr.contains(n))
        }
        // A Go harness compile error (`undefined: …`) means the generated
        // cross-package driver references a symbol that does not resolve — a
        // method/unexported entry surfaced as `undefined: entry.X`, or a
        // package the per-shape driver failed to import.  The Go emitter
        // cannot bind a runnable driver to this entry shape.
        Lang::Go => stderr.contains("undefined:"),
        // The Java static driver invoked an instance method without a receiver.
        Lang::Java => stderr.contains("cannot be referenced from a static context"),
        _ => false,
    }
}

/// Try to dynamically confirm a static finding.
///
/// Never fails: every error path collapses into a [`VerifyStatus`] so the
/// caller can treat dynamic verification as best-effort enrichment.
pub fn verify_finding(diag: &Diag, opts: &VerifyOptions) -> VerifyResult {
    let finding_id = format!("{:016x}", diag.stable_hash);

    // One trace per finding, threaded into [`SandboxOptions`] so the
    // runner can append `build_*` / `sandbox_started` / `oracle_*` stages
    // from inside `run_spec`.
    //
    // Tests may pre-seed `opts.trace_sink` with their own `Arc<VerifyTrace>`
    // handle; when present we reuse it instead of allocating a fresh one
    // so assertions can inspect the recorded stages after the call returns.
    let trace = opts
        .trace_sink
        .clone()
        .unwrap_or_else(|| Arc::new(crate::dynamic::trace::VerifyTrace::new()));
    trace.record(
        crate::dynamic::trace::TraceStage::SpecStarted,
        Some(format!("rule={} path={}", diag.id, diag.path)),
    );

    // Cross-cutting policy deny rules.  Findings whose static metadata
    // mentions credentials, private keys, or production endpoint regexes
    // are refused up front: the sandbox is never started and no payload
    // is materialised, so a leaked secret cannot round-trip through the
    // harness even if the deny rule is wrong.  The verifier returns
    // `Inconclusive(PolicyDeniedDynamic)` so the operator sees *why*
    // dynamic execution was skipped without losing the static finding
    // from the report.
    if let crate::dynamic::policy::PolicyDecision::Deny {
        rule,
        field,
        excerpt,
    } = crate::dynamic::policy::evaluate(diag)
    {
        trace.record(
            crate::dynamic::trace::TraceStage::Verdict,
            Some(format!("policy_denied rule={rule} field={field}")),
        );
        if opts.trace_verbose {
            trace.print_to_stderr();
        }
        let inconclusive_reason = InconclusiveReason::PolicyDeniedDynamic {
            rule: rule.to_owned(),
            field: field.clone(),
            excerpt: excerpt.clone(),
        };
        // Emit telemetry so the events log records the deny;
        // operators triaging refusals need it on the wire even though
        // the sandbox never ran.
        let tel_event = TelemetryEvent::no_spec(
            diag,
            VerifyStatus::Inconclusive,
            Some(inconclusive_reason.clone()),
        );
        telemetry::emit_with_policy(&tel_event, &opts.telemetry_policy);
        return VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(inconclusive_reason),
            detail: Some(format!("dynamic execution refused by policy rule {rule}")),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };
    }

    // Phase 25 (Track K.0): derive the spec through the multi-strategy
    // scoring path. `derive_best_ranked` runs every strategy, scores each
    // candidate, and returns the winner plus the loser ranking for
    // telemetry.
    let ctx = crate::dynamic::spec::SpecDerivationCtx::new(
        opts.verify_all_confidence,
        opts.summaries.as_deref(),
        opts.callgraph.as_deref(),
    );
    let spec = match HarnessSpec::derive_best_ranked(diag, &ctx) {
        Ok((s, runners_up)) => {
            trace.record(
                crate::dynamic::trace::TraceStage::SpecScoringResult,
                Some(format_spec_scoring_detail(s.derivation, &runners_up)),
            );
            s
        }
        Err(reason) => {
            trace.record(
                crate::dynamic::trace::TraceStage::Verdict,
                Some(format!("spec_derivation_failed reason={reason:?}")),
            );
            if opts.trace_verbose {
                trace.print_to_stderr();
            }
            return spec_derivation_failed_verdict(
                finding_id,
                diag,
                reason,
                &opts.telemetry_policy,
            );
        }
    };
    trace.record(
        crate::dynamic::trace::TraceStage::SpecDone,
        Some(format!(
            "spec_hash={} lang={:?} entry_kind={:?}",
            spec.spec_hash, spec.lang, spec.entry_kind
        )),
    );
    // Surface framework-adapter dispatch outcome to the trace so
    // operators (and the determinism audit) can see whether an adapter
    // claimed the entry function.  Emits `Detected` with the adapter
    // name in `detail` when one matched, otherwise `None`.
    match &spec.framework {
        Some(binding) => trace.record(
            crate::dynamic::trace::TraceStage::FrameworkAdapterDetected,
            Some(format!(
                "adapter={} kind={:?}",
                binding.adapter, binding.kind
            )),
        ),
        None => trace.record(
            crate::dynamic::trace::TraceStage::FrameworkAdapterNone,
            Some(format!("lang={:?} entry={}", spec.lang, spec.entry_name)),
        ),
    }

    // Record whether the synthesized harness will drive the finding's
    // enclosing entry function (so caller-side guards participate in the
    // verdict) or fall back to a synthetic direct-sink invocation because
    // no enclosing entry could be derived.  The per-language emitters
    // consult the same `entry_is_derivable()` predicate, so this trace
    // event is the build-time source of truth for the entry-vs-sink choice.
    trace.record(
        crate::dynamic::trace::TraceStage::EntryInvocation,
        Some(if spec.entry_is_derivable() {
            format!("mode=entry_function entry={}", spec.entry_name)
        } else {
            "mode=direct_sink fallback=no_enclosing_entry".to_owned()
        }),
    );

    // Pre-flight gate: surface a structured `Inconclusive(EntryKindUnsupported)`
    // up-front when the spec's [`EntryKind`] is not in the lang emitter's
    // supported list.  Without this, the same condition would degrade silently
    // through `lang::emit -> HarnessError::Unsupported` and lose the
    // supported-list / hint context the operator needs to triage.
    if !spec.entry_kind_is_supported() {
        return entry_kind_unsupported_verdict(
            finding_id,
            Some(diag),
            &spec.entry_file,
            spec.lang,
            spec.entry_kind.tag(),
            &opts.telemetry_policy,
        );
    }

    // When the active backend cannot confine filesystem reach
    // (macOS process backend without `sandbox-exec`),
    // refuse to run filesystem-escape oracles up-front and emit a
    // structured `Inconclusive(BackendInsufficient)` so operators see
    // the backend gap instead of a quiet `Confirmed` against an
    // unhardened host.
    if opts.refuse_filesystem_confirm && spec.expected_cap.contains(crate::labels::Cap::FILE_IO) {
        let backend = if cfg!(target_os = "macos") {
            "macos-process-without-sandbox-exec"
        } else {
            "process"
        };
        return VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::BackendInsufficient {
                backend: backend.to_owned(),
                oracle_kind: "filesystem-escape".to_owned(),
            }),
            detail: Some(
                "filesystem-escape oracle refused: sandbox backend cannot confine \
                 file reach (sandbox-exec missing). Install Apple's `sandbox-exec` \
                 binary or run via the docker backend."
                    .to_owned(),
            ),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };
    }

    // Scan the entry file's directory for sensitive files (§17.3 mount filter).
    // If the entry file itself matches a sensitive pattern, refuse to run it:
    // the harness would copy it into the workdir and expose secrets.
    {
        let entry_path = Path::new(&spec.entry_file);
        let scan_dir = entry_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let notes = crate::dynamic::mount_filter::scan_sensitive_files(scan_dir);
        for note in &notes {
            let note_abs = scan_dir.join(&note.path);
            if entry_path == note_abs {
                return VerifyResult {
                    finding_id,
                    status: VerifyStatus::Unsupported,
                    triggered_payload: None,
                    reason: Some(UnsupportedReason::RequiredFileRedactedForSecrets(
                        note.path.clone(),
                    )),
                    inconclusive_reason: None,
                    detail: None,
                    attempts: vec![],
                    toolchain_match: None,
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                };
            }
        }
    }

    // Resolve toolchain information (lang-aware: §22.2).
    use crate::symbol::Lang;
    let toolchain_res = match spec.lang {
        Lang::Rust => toolchain::resolve_rust(Path::new(".")),
        Lang::JavaScript | Lang::TypeScript => toolchain::resolve_node(Path::new(".")),
        Lang::Go => toolchain::resolve_go(Path::new(".")),
        Lang::Java => toolchain::resolve_java(Path::new(".")),
        Lang::Php => toolchain::resolve_php(Path::new(".")),
        _ => toolchain::resolve_python(Path::new(".")),
    };
    let toolchain_match = if toolchain_res.toolchain_drift {
        "drift"
    } else {
        "exact"
    };
    // Enrich the resolved toolchain_id with the Docker image digest (§22.1).
    // The enriched ID is used as the toolchain_id component of the verdict cache
    // key so that image updates always invalidate stale cache entries.
    let effective_toolchain_id = toolchain_id_with_digest(&toolchain_res.toolchain_id);

    // Verdict cache lookup (§12 Q5): skip execution when a valid cached result exists.
    let entry_hash = compute_entry_content_hash(&spec.entry_file);
    let import_digest = transitive_import_digest_placeholder();
    if let Some(ref db_path) = opts.db_path
        && let Some(cached) = lookup_verdict_cache(
            db_path,
            &spec.spec_hash,
            &entry_hash,
            import_digest,
            &effective_toolchain_id,
        )
    {
        return cached;
    }

    // Spawn the boundary stubs the spec demands *before* the sandbox
    // runs.  When `stubs_required` is
    // empty `StubHarness::start` is a no-op so the 500 ms boot budget
    // for stub-less harnesses stays intact.  The harness lives for
    // the lifetime of this `verify_finding` call; its `Drop` releases
    // listening sockets / removes tempdirs at function exit.
    let stub_workdir = match opts.project_root.as_deref() {
        Some(p) => p.to_owned(),
        None => std::env::temp_dir(),
    };
    let stub_harness = match StubHarness::start(&spec.stubs_required, &stub_workdir) {
        Ok(h) => Arc::new(h),
        Err(_) => Arc::new(StubHarness::default()),
    };

    // Build a per-finding `SandboxOptions` clone that carries the
    // stub endpoints + the live stub handle.  This is the only place
    // that mutates the caller's options; downstream cloning happens
    // inside `run_spec` so the original `opts.sandbox` is left
    // untouched.
    let mut sandbox_opts = opts.sandbox.clone();
    let mut sandbox_extra_env = sandbox_opts.extra_env.clone();
    for (name, value) in stub_harness.endpoints() {
        sandbox_extra_env.push((name.to_owned(), value));
    }
    sandbox_opts.extra_env = sandbox_extra_env;
    if !stub_harness.is_empty() {
        sandbox_opts.stub_harness = Some(Arc::clone(&stub_harness));
    }
    // When the operator opted into Strict hardening, seed `seccomp_caps`
    // from the spec's expected cap so the Linux process backend installs
    // the cap-minimal syscall allowlist and the macOS backend picks the
    // matching `.sb` profile (`FILE_IO -> path_traversal`, `CODE_EXEC ->
    // cmdi`, etc.).  Standard runs leave the field at 0 (base allowlist /
    // no wrap) for back-compat.
    if matches!(
        sandbox_opts.process_hardening,
        crate::dynamic::sandbox::ProcessHardeningProfile::Strict,
    ) {
        sandbox_opts.seccomp_caps = spec.expected_cap.bits();
        // Interpreted-language harnesses cannot resolve their interpreter
        // + shared libraries from inside the
        // chroot unless the host's `/lib`, `/lib64`, `/usr/lib`, and
        // `/usr/bin` are bind-mounted into the workdir.  Native-compile
        // langs (Rust / C / C++ / Go) are statically linked under
        // Strict by `static_link_for_profile` so we keep the chroot
        // tight by skipping the bind-mounts for them.
        sandbox_opts.bind_mount_host_libs = lang_needs_host_libs(spec.lang);
    }
    // Hand the runner an `Arc` clone so it can append `build_*` /
    // `sandbox_started` / `oracle_*` stages from inside `run_spec`.
    // The verifier still owns the trace for verdict-stage appending
    // after `run_spec` returns.
    sandbox_opts.trace = Some(Arc::clone(&trace));

    let start = Instant::now();
    let result = run_spec(&spec, &sandbox_opts);
    let elapsed = start.elapsed();

    // Extract build_attempts before result is consumed by build_verdict.
    let build_attempts = match &result {
        Ok(run) => run.build_attempts,
        Err(RunError::BuildFailed { attempts, .. }) => *attempts,
        _ => 1,
    };

    let mut verdict = build_verdict(&finding_id, &spec, result, toolchain_match, opts, elapsed);

    // Stamp `replay_stable` from a `reproduce.sh` rerun against the
    // freshly written bundle.  Opt-in (see
    // `VerifyOptions::replay_stable_check`) because invoking the script
    // per Confirmed finding doubles wall-clock cost.  The eval-corpus
    // driver flips it on so the tabulated `stable_replays` column becomes
    // non-vacuous; interactive `nyx scan` keeps `replay_stable: None`.
    if verdict.status == VerifyStatus::Confirmed
        && opts.replay_stable_check
        && let Some(bundle) = crate::dynamic::repro::bundle_root_for(&spec.spec_hash)
        && bundle.join("reproduce.sh").exists()
    {
        let replay_args: &[&str] = if opts.replay_use_docker {
            &["--docker"]
        } else {
            &[]
        };
        let replay = crate::dynamic::repro::replay_bundle(&bundle, replay_args);
        verdict.replay_stable = crate::dynamic::repro::replay_stability(&replay);
    }

    // Store result in verdict cache (best-effort; errors are silently ignored).
    if let Some(ref db_path) = opts.db_path {
        insert_verdict_cache(
            db_path,
            &spec.spec_hash,
            &entry_hash,
            import_digest,
            &effective_toolchain_id,
            &verdict,
        );
    }

    // Emit telemetry (best-effort; never affects verdict).
    let event = TelemetryEvent::new(
        &spec,
        verdict.status,
        verdict.inconclusive_reason.clone(),
        toolchain_match,
        elapsed,
        build_attempts,
    );
    telemetry::emit_with_policy(&event, &opts.telemetry_policy);

    // Verdict is the terminal trace stage.  Recorded after cache insert +
    // telemetry so the trace reflects the full pipeline the operator just
    // saw run.
    trace.record(
        crate::dynamic::trace::TraceStage::Verdict,
        Some(format!("status={:?}", verdict.status)),
    );
    if opts.trace_verbose {
        trace.print_to_stderr();
    }

    verdict
}

/// Project the platform-cfg'd [`crate::dynamic::sandbox::HardeningRecord`]
/// into the portable [`HardeningSummary`] that lands on
/// [`VerifyResult::hardening_outcome`].  Returns `None` when the run did
/// not record a hardening outcome (docker backend, non-Linux/non-macOS
/// host, or `Standard` profile on a host whose backend skipped the wrap).
///
/// Exposed for tests so a `sandbox::run`-driven probe can assert that the
/// projection lands the same record `build_verdict` would stamp on a
/// `Confirmed` `VerifyResult` from the same triggering attempt.
pub fn summarize_hardening(
    outcome: &crate::dynamic::sandbox::SandboxOutcome,
) -> Option<HardeningSummary> {
    use crate::dynamic::sandbox::HardeningRecord;
    let record = outcome.hardening_outcome.as_ref()?;
    match record {
        #[cfg(target_os = "linux")]
        HardeningRecord::Linux(o) => {
            use crate::dynamic::sandbox::process_linux::{
                HardeningLevel, PrimitiveStatus, ProcessHardeningProfileTag,
            };
            fn status_str(s: PrimitiveStatus) -> (String, Option<i32>) {
                match s {
                    PrimitiveStatus::Skipped => ("skipped".to_owned(), None),
                    PrimitiveStatus::Applied => ("applied".to_owned(), None),
                    PrimitiveStatus::Failed(errno) => ("failed".to_owned(), Some(errno)),
                }
            }
            let primitives = [
                ("no_new_privs", o.no_new_privs),
                ("rlimit_cpu", o.rlimit_cpu),
                ("rlimit_nofile", o.rlimit_nofile),
                ("rlimit_as", o.rlimit_as),
                ("unshare", o.unshare),
                ("chroot", o.chroot),
                ("seccomp", o.seccomp),
            ]
            .into_iter()
            .map(|(name, st)| {
                let (status, errno) = status_str(st);
                HardeningPrimitive {
                    name: name.to_owned(),
                    status,
                    errno,
                }
            })
            .collect();
            let level = match o.level() {
                HardeningLevel::Baseline => "baseline",
                HardeningLevel::Full => "full",
                HardeningLevel::Partial => "partial",
                HardeningLevel::None => "none",
            };
            // The Linux backend uses the same `.sb`-style profile name
            // surface (Standard / Strict) as macOS via the profile tag.
            let profile = match o.profile {
                ProcessHardeningProfileTag::Standard => String::new(),
                ProcessHardeningProfileTag::Strict => "strict".to_owned(),
            };
            Some(HardeningSummary {
                backend: "linux-process".to_owned(),
                level: level.to_owned(),
                profile,
                primitives,
            })
        }
        #[cfg(target_os = "macos")]
        HardeningRecord::Macos(o) => {
            use crate::dynamic::sandbox::process_macos::HardeningLevel;
            let level = match o.level {
                HardeningLevel::Trusted => "trusted",
                HardeningLevel::Sandboxed => "sandboxed",
                HardeningLevel::Failed => "failed",
            };
            Some(HardeningSummary {
                backend: "macos-process".to_owned(),
                level: level.to_owned(),
                profile: o.profile.clone(),
                primitives: Vec::new(),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        _ => None,
    }
}

fn build_verdict(
    finding_id: &str,
    spec: &HarnessSpec,
    result: Result<crate::dynamic::runner::RunOutcome, RunError>,
    toolchain_match: &str,
    opts: &VerifyOptions,
    _elapsed: std::time::Duration,
) -> VerifyResult {
    match result {
        Ok(run) => {
            let attempts: Vec<AttemptSummary> = run
                .attempts
                .iter()
                .map(|a| AttemptSummary {
                    payload_label: a.payload_label.to_string(),
                    exit_code: a.outcome.exit_code,
                    timed_out: a.outcome.timed_out,
                    triggered: a.triggered,
                    sink_hit: a.outcome.sink_hit,
                })
                .collect();

            if let Some(i) = run.triggered_by {
                let triggered_payload = run.attempts[i].payload_label.to_string();
                // Resolve repro bytes by label, not by index: OOB payloads
                // skipped for lack of a listener leave `attempts` shorter
                // than `vuln_payloads`, so a positional lookup can pull the
                // wrong payload's bytes.  The label is the stable key.
                let payloads = payloads_for(spec.expected_cap);
                let payload_bytes = payloads
                    .iter()
                    .find(|p| !p.is_benign && p.label == triggered_payload)
                    .map(|p| p.bytes)
                    .unwrap_or(b"");
                let hardening_outcome = summarize_hardening(&run.attempts[i].outcome);

                // Emit repro artifact.
                let repro_result = crate::dynamic::repro::write(
                    spec,
                    &opts.sandbox,
                    &run.attempts[i].outcome,
                    &VerifyResult {
                        finding_id: finding_id.to_owned(),
                        status: VerifyStatus::Confirmed,
                        triggered_payload: Some(triggered_payload.clone()),
                        reason: None,
                        inconclusive_reason: None,
                        detail: None,
                        attempts: attempts.clone(),
                        toolchain_match: Some(toolchain_match.to_owned()),
                        differential: run.differential.clone(),
                        replay_stable: None,
                        wrong: None,
                        hardening_outcome: hardening_outcome.clone(),
                    },
                    &run.harness_source,
                    &run.entry_source,
                    payload_bytes,
                    run.attempts[i].payload_label,
                    opts.project_root.as_deref(),
                );

                // If repro write fails, downgrade to NonReproducible.
                if let Err(err) = repro_result {
                    return VerifyResult {
                        finding_id: finding_id.to_owned(),
                        status: VerifyStatus::Inconclusive,
                        triggered_payload: None,
                        reason: None,
                        inconclusive_reason: Some(InconclusiveReason::NonReproducible),
                        detail: Some(format!("repro write failed: {err}")),
                        attempts,
                        toolchain_match: Some(toolchain_match.to_owned()),
                        differential: run.differential,
                        replay_stable: None,
                        wrong: None,
                        hardening_outcome,
                    };
                }

                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Confirmed,
                    triggered_payload: Some(triggered_payload),
                    reason: None,
                    inconclusive_reason: None,
                    detail: None,
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                    differential: run.differential,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome,
                }
            } else if run.unrelated_crash {
                // The harness crashed but the death happened outside the
                // instrumented sink (no Crash probe was written).
                // Downgrade rather than letting a setup-code abort
                // masquerade as a confirmed fire.
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Inconclusive,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: Some(InconclusiveReason::UnrelatedCrash),
                    detail: Some(
                        "process crashed with no sink-site crash probe, likely setup-code abort, not the sink"
                            .to_owned(),
                    ),
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            } else if run.no_benign_control {
                // Vuln oracle + sink-hit fired but the paired benign
                // control was missing.  Downgrade to
                // `Inconclusive(NoBenignControl)` rather than stamping
                // `Confirmed` from a one-sided observation.
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Inconclusive,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: Some(InconclusiveReason::NoBenignControl),
                    detail: Some(
                        "vulnerable oracle fired but no paired benign control payload for differential confirmation".to_owned(),
                    ),
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            } else if let Some(d) = run.differential.as_ref() {
                // Differential ran but didn't produce `Confirmed`.  Map
                // the rule's verdict onto the corresponding inconclusive
                // reason or fall through to `NotConfirmed`.
                match d.verdict {
                    crate::evidence::DifferentialVerdict::OracleCollisionSuspected => {
                        VerifyResult {
                            finding_id: finding_id.to_owned(),
                            status: VerifyStatus::Inconclusive,
                            triggered_payload: None,
                            reason: None,
                            inconclusive_reason: Some(
                                InconclusiveReason::OracleCollisionSuspected,
                            ),
                            detail: Some(
                                "differential rule: both vulnerable and benign payloads fired the oracle".to_owned(),
                            ),
                            attempts,
                            toolchain_match: Some(toolchain_match.to_owned()),
                            differential: run.differential,
                            replay_stable: None,
                            wrong: None,
                            hardening_outcome: None,
                        }
                    }
                    crate::evidence::DifferentialVerdict::ReversedDifferential => {
                        VerifyResult {
                            finding_id: finding_id.to_owned(),
                            status: VerifyStatus::Inconclusive,
                            triggered_payload: None,
                            reason: None,
                            inconclusive_reason: Some(
                                InconclusiveReason::ReversedDifferential,
                            ),
                            detail: Some(
                                "differential rule: only the benign control fired the oracle".to_owned(),
                            ),
                            attempts,
                            toolchain_match: Some(toolchain_match.to_owned()),
                            differential: run.differential,
                            replay_stable: None,
                            wrong: None,
                            hardening_outcome: None,
                        }
                    }
                    crate::evidence::DifferentialVerdict::Confirmed
                    | crate::evidence::DifferentialVerdict::ConfirmedProvenOob
                    | crate::evidence::DifferentialVerdict::ConfirmedWithKnownGuard
                    | crate::evidence::DifferentialVerdict::NotConfirmed => VerifyResult {
                        finding_id: finding_id.to_owned(),
                        status: VerifyStatus::NotConfirmed,
                        triggered_payload: None,
                        reason: None,
                        inconclusive_reason: None,
                        detail: None,
                        attempts,
                        toolchain_match: Some(toolchain_match.to_owned()),
                        differential: run.differential,
                        replay_stable: None,
                        wrong: None,
                        hardening_outcome: None,
                    },
                }
            } else if run.sink_reached_no_oracle {
                // Phase 26: a vuln payload's in-harness sink-reachability
                // probe fired but its oracle marker never did, and the run
                // produced no Confirmed-class verdict and no colliding
                // differential.  The sink is reachable at runtime yet the
                // exploit chain did not complete (no marker file written,
                // no OOB callback observed, output lacked the proof token).
                // Surface `PartiallyConfirmed` so engine work can ratchet on
                // the real sink-reachability gap without overstating it as a
                // confirmed exploit.  No repro artifact is written: there is
                // no proven exploit to reproduce.
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::PartiallyConfirmed,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: None,
                    detail: Some(
                        "sink-reachability probe fired but the oracle marker was not observed; exploit chain did not complete".to_owned(),
                    ),
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            } else if run.oracle_collision {
                // Oracle fired but the sink-hit sentinel did not —
                // legacy single-payload collision path, predates the
                // differential rule.
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Inconclusive,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: Some(InconclusiveReason::OracleCollisionSuspected),
                    detail: Some("oracle fired but sink-reachability probe did not".to_owned()),
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            } else {
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::NotConfirmed,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: None,
                    detail: None,
                    attempts,
                    toolchain_match: Some(toolchain_match.to_owned()),
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            }
        }
        Err(RunError::NoPayloadsForCap) => VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::NoPayloadsForCap),
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        Err(RunError::SoundOracleUnavailable { cap, lang, hint }) => VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::SoundOracleUnavailable { cap, lang, hint }),
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        Err(RunError::Harness(e)) => {
            // Defence-in-depth residual for `EntryKindUnsupported` from the
            // lang dispatcher. Promote to `Inconclusive(EntryKindUnsupported)`
            // so the operator sees the supported list + hint, but only when
            // the spec's entry kind is genuinely outside the supported list —
            // otherwise the pre-flight gate already handled it (or a stray
            // emitter mis-tagged a payload-slot rejection, which now uses
            // `PayloadSlotUnsupported` and falls through to the generic
            // `Unsupported(reason)` arm below).
            if let crate::dynamic::harness::HarnessError::Unsupported(
                UnsupportedReason::EntryKindUnsupported,
            ) = &e
            {
                let supported = crate::dynamic::lang::entry_kinds_supported(spec.lang);
                if !supported.contains(&spec.entry_kind.tag()) {
                    return entry_kind_unsupported_verdict(
                        finding_id.to_owned(),
                        None,
                        &spec.entry_file,
                        spec.lang,
                        spec.entry_kind.tag(),
                        &opts.telemetry_policy,
                    );
                }
            }
            // Typed `Unsupported(reason)` carries its semantics in `reason`; the
            // free-form `detail` is reserved for `Inconclusive`/unexpected paths
            // (cf. §10 decision 14 and the verify_result_json_shape contract).
            let (reason, detail) = match &e {
                crate::dynamic::harness::HarnessError::Unsupported(r) => (Some(r.clone()), None),
                _ => (
                    Some(UnsupportedReason::BackendUnavailable),
                    Some(format!("{e}")),
                ),
            };
            VerifyResult {
                finding_id: finding_id.to_owned(),
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason,
                inconclusive_reason: None,
                detail,
                attempts: vec![],
                toolchain_match: None,
                differential: None,
                replay_stable: None,
                wrong: None,
                hardening_outcome: None,
            }
        }
        Err(RunError::BuildFailed {
            stderr,
            attempts: build_att,
        }) => {
            // A build / runtime-load failure caused by a genuinely-absent host
            // dependency or toolchain (an offline dependency-resolution miss,
            // a missing module / gem / package, a top-level import failure, a
            // missing interpreter) is a host limitation, not a defect in the
            // harness the engine emitted.  Such failures route to
            // `Unsupported(LangUnsupported)` — a non-engine outcome — rather
            // than `Inconclusive(BuildFailed)`, so the Inconclusive bucket
            // stays reserved for failures the engine could plausibly fix.
            // Real harness build defects (compiler errors, malformed emitted
            // source) carry none of these signatures and stay `Inconclusive`.
            if build_failure_is_host_limitation(&stderr) {
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Unsupported,
                    triggered_payload: None,
                    reason: Some(UnsupportedReason::LangUnsupported),
                    inconclusive_reason: None,
                    detail: None,
                    attempts: vec![],
                    toolchain_match: None,
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            } else if build_failure_is_undrivable_entry(spec.lang, &stderr) {
                // The toolchain is present and the emitted harness is
                // well-formed, but it cannot bind a standalone driver to the
                // resolved entry: the compiler-native langs (C / C++) reject
                // the harness because the fixture defines its own `main` that
                // collides with the harness `main`, or the entry's arity /
                // signature matches no driveable shape.  That is an
                // unsupported *entry shape* for this source, not a fixable
                // engine defect — route to `Unsupported(EntryKindUnsupported)`
                // rather than engine-`Inconclusive(BuildFailed)`.
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Unsupported,
                    triggered_payload: None,
                    reason: Some(UnsupportedReason::EntryKindUnsupported),
                    inconclusive_reason: None,
                    detail: None,
                    attempts: vec![],
                    toolchain_match: None,
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            } else {
                VerifyResult {
                    finding_id: finding_id.to_owned(),
                    status: VerifyStatus::Inconclusive,
                    triggered_payload: None,
                    reason: None,
                    inconclusive_reason: Some(InconclusiveReason::BuildFailed),
                    detail: Some(format!("build failed after {build_att} attempts: {stderr}")),
                    attempts: vec![],
                    toolchain_match: None,
                    differential: None,
                    replay_stable: None,
                    wrong: None,
                    hardening_outcome: None,
                }
            }
        }
        Err(RunError::Sandbox(e)) => VerifyResult {
            finding_id: finding_id.to_owned(),
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::SandboxError),
            detail: Some(format!("sandbox failed: {e:?}")),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-global env vars (`NYX_VERIFY_REPLAY_STABLE`,
    /// `NYX_VERIFY_REPLAY_DOCKER`) are mutated by several tests in this
    /// module; without serialisation a parallel `cargo test` invocation
    /// races on the global state and produces flakes that vanish under
    /// `--test-threads=1`.  Every env-mutating test acquires this guard
    /// for the duration of its body.  `unwrap_or_else(into_inner)`
    /// recovers from poisoning so a failing test does not cascade-fail
    /// every later test in the suite.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn compute_entry_content_hash_stable_for_same_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("entry.py");
        std::fs::write(&path, b"def run(x): pass\n").unwrap();
        let h1 = compute_entry_content_hash(path.to_str().unwrap());
        let h2 = compute_entry_content_hash(path.to_str().unwrap());
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_ne!(h1, "unavailable");
    }

    #[test]
    fn compute_entry_content_hash_different_for_different_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let p1 = dir.path().join("a.py");
        let p2 = dir.path().join("b.py");
        std::fs::write(&p1, b"def run(x): return x\n").unwrap();
        std::fs::write(&p2, b"def run(x): return x + 1\n").unwrap();
        let h1 = compute_entry_content_hash(p1.to_str().unwrap());
        let h2 = compute_entry_content_hash(p2.to_str().unwrap());
        assert_ne!(h1, h2, "different content must produce different hashes");
    }

    #[test]
    fn compute_entry_content_hash_missing_file_returns_unavailable() {
        let h = compute_entry_content_hash("/tmp/nyx_test_nonexistent_entry_file_99999.py");
        assert_eq!(h, "unavailable");
    }

    #[test]
    fn transitive_import_digest_placeholder_is_stable() {
        assert_eq!(transitive_import_digest_placeholder(), "");
    }

    #[test]
    fn from_config_defaults_replay_stable_check_off() {
        let _env_guard = env_lock();
        // Make sure the test is hermetic — `from_config` reads the env
        // var, so a stale process-wide setting could mask the default.
        unsafe { std::env::remove_var("NYX_VERIFY_REPLAY_STABLE") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(
            !opts.replay_stable_check,
            "NYX_VERIFY_REPLAY_STABLE absent must leave the opt-in off so \
             interactive `nyx scan` does not pay the per-finding reproduce.sh cost"
        );
    }

    #[test]
    fn from_config_picks_up_replay_stable_env_flag() {
        let _env_guard = env_lock();
        unsafe { std::env::set_var("NYX_VERIFY_REPLAY_STABLE", "1") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(opts.replay_stable_check);
        unsafe { std::env::set_var("NYX_VERIFY_REPLAY_STABLE", "true") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(opts.replay_stable_check);
        unsafe { std::env::set_var("NYX_VERIFY_REPLAY_STABLE", "0") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(!opts.replay_stable_check);
        unsafe { std::env::remove_var("NYX_VERIFY_REPLAY_STABLE") };
    }

    #[test]
    fn from_config_defaults_replay_use_docker_off() {
        let _env_guard = env_lock();
        // Same hermeticity concern as `replay_stable_check`: clear any
        // stale process-wide setting so the default is observable.
        unsafe { std::env::remove_var("NYX_VERIFY_REPLAY_DOCKER") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(
            !opts.replay_use_docker,
            "NYX_VERIFY_REPLAY_DOCKER absent must leave the opt-in off so \
             interactive `nyx scan` does not require docker for the replay step"
        );
    }

    #[test]
    fn from_config_picks_up_replay_docker_env_flag() {
        let _env_guard = env_lock();
        unsafe { std::env::set_var("NYX_VERIFY_REPLAY_DOCKER", "1") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(opts.replay_use_docker);
        unsafe { std::env::set_var("NYX_VERIFY_REPLAY_DOCKER", "true") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(opts.replay_use_docker);
        unsafe { std::env::set_var("NYX_VERIFY_REPLAY_DOCKER", "0") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(!opts.replay_use_docker);
        unsafe { std::env::remove_var("NYX_VERIFY_REPLAY_DOCKER") };
    }

    #[test]
    fn from_config_defaults_process_hardening_to_standard() {
        use crate::dynamic::sandbox::ProcessHardeningProfile;
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(
            matches!(
                opts.sandbox.process_hardening,
                ProcessHardeningProfile::Standard
            ),
            "back-compat: missing harden_profile must keep the Standard baseline so \
             existing call sites (process backend without `--harden=strict`) keep \
             their pre-Phase-17 hardening matrix"
        );
    }

    #[test]
    fn from_config_picks_up_strict_harden_profile() {
        use crate::dynamic::sandbox::ProcessHardeningProfile;
        let mut config = Config::default();
        config.scanner.harden_profile = "strict".to_owned();
        let opts = VerifyOptions::from_config(&config);
        assert!(
            matches!(
                opts.sandbox.process_hardening,
                ProcessHardeningProfile::Strict
            ),
            "harden_profile=strict must engage the full Phase-17/18 lockdown so \
             `--harden=strict` actually wraps the harness with sandbox-exec on macOS \
             and layers chroot + seccomp on Linux"
        );
    }

    #[test]
    fn lang_needs_host_libs_returns_true_for_interpreted_langs() {
        use crate::symbol::Lang;
        // Every lang that ships its harness as an external interpreter
        // (python3 / node / java / ruby / php) must opt in so the
        // Strict chroot still finds the runtime's shared libraries.
        for lang in [
            Lang::Python,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Java,
            Lang::Ruby,
            Lang::Php,
        ] {
            assert!(
                lang_needs_host_libs(lang),
                "{lang:?} runs through an external interpreter that dlopens \
                 host libs at cold-start, so the verifier must request \
                 bind-mounts when Strict hardening engages"
            );
        }
    }

    #[test]
    fn lang_needs_host_libs_returns_false_for_native_langs() {
        use crate::symbol::Lang;
        // Native-compile langs are statically linked under Strict via
        // `static_link_for_profile`, so the chroot survives without
        // exposing the host filesystem through bind-mounts.
        for lang in [Lang::Rust, Lang::C, Lang::Cpp, Lang::Go] {
            assert!(
                !lang_needs_host_libs(lang),
                "{lang:?} is statically linked under Strict; bind-mounting \
                 host libs would widen the chroot surface for zero gain"
            );
        }
    }

    #[test]
    fn from_config_unknown_harden_profile_falls_back_to_standard() {
        use crate::dynamic::sandbox::ProcessHardeningProfile;
        let mut config = Config::default();
        config.scanner.harden_profile = "lockdown".to_owned();
        let opts = VerifyOptions::from_config(&config);
        assert!(
            matches!(
                opts.sandbox.process_hardening,
                ProcessHardeningProfile::Standard
            ),
            "unknown harden_profile values must degrade to Standard so a typo in \
             nyx.toml does not silently leave the operator without the baseline \
             hardening they were already paying for"
        );
    }

    #[test]
    fn verdict_cache_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        // Create and initialize the DB with the required schema.
        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    spec_hash TEXT NOT NULL,
                    entry_content_hash TEXT NOT NULL,
                    transitive_import_digest TEXT NOT NULL,
                    toolchain_id TEXT NOT NULL,
                    corpus_version INTEGER NOT NULL,
                    spec_format_version INTEGER NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                           toolchain_id, corpus_version, spec_format_version)
                );",
            )
            .unwrap();
        }

        let result = VerifyResult {
            finding_id: "test_finding_0001".to_owned(),
            status: crate::evidence::VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".to_owned()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };

        // Insert.
        insert_verdict_cache(&db_path, "spec_abc", "hash_xyz", "", "python-3.11", &result);

        // Lookup — should return the same result.
        let cached = lookup_verdict_cache(&db_path, "spec_abc", "hash_xyz", "", "python-3.11");
        assert!(cached.is_some(), "cache hit expected after insert");
        let cached = cached.unwrap();
        assert_eq!(cached.finding_id, "test_finding_0001");
        assert_eq!(cached.status, crate::evidence::VerifyStatus::NotConfirmed);
    }

    #[test]
    fn verdict_cache_miss_on_different_spec_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    spec_hash TEXT NOT NULL,
                    entry_content_hash TEXT NOT NULL,
                    transitive_import_digest TEXT NOT NULL,
                    toolchain_id TEXT NOT NULL,
                    corpus_version INTEGER NOT NULL,
                    spec_format_version INTEGER NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                           toolchain_id, corpus_version, spec_format_version)
                );",
            )
            .unwrap();
        }

        let result = VerifyResult {
            finding_id: "test_finding_0002".to_owned(),
            status: crate::evidence::VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".to_owned()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };

        insert_verdict_cache(&db_path, "spec_aaa", "hash_xyz", "", "python-3.11", &result);

        // Different spec_hash → miss.
        let miss = lookup_verdict_cache(&db_path, "spec_bbb", "hash_xyz", "", "python-3.11");
        assert!(miss.is_none(), "different spec_hash must be a cache miss");
    }

    #[test]
    fn verdict_cache_returns_none_for_nonexistent_db() {
        let result = lookup_verdict_cache(
            std::path::Path::new("/tmp/nyx_nonexistent_verdict_cache_99999.db"),
            "spec_abc",
            "hash_xyz",
            "",
            "python-3.11",
        );
        assert!(result.is_none(), "non-existent DB must return None");
    }

    #[test]
    fn insert_verdict_cache_is_noop_for_nonexistent_db() {
        // Should not panic or create the DB.
        let db_path = std::path::Path::new("/tmp/nyx_nonexistent_verdict_cache_insert_99999.db");
        let result = VerifyResult {
            finding_id: "test".to_owned(),
            status: crate::evidence::VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };
        insert_verdict_cache(db_path, "spec", "hash", "", "python-3", &result);
        assert!(!db_path.exists(), "insert must not create a new DB");
    }

    /// Verify that a cache entry keyed on an older corpus_version is a miss
    /// once CORPUS_VERSION is bumped.  This proves the cache invalidation
    /// mechanic in §15.4 / Pillar D: changing a payload's cap evicts stale entries.
    ///
    /// The test simulates a bump by inserting with an old version literal and
    /// then looking up with the current CORPUS_VERSION (which is the default).
    #[test]
    fn dynamic_verdict_cache_corpus_version_invalidation() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test_corp_ver.db");

        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dynamic_verdict_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    spec_hash TEXT NOT NULL,
                    entry_content_hash TEXT NOT NULL,
                    transitive_import_digest TEXT NOT NULL,
                    toolchain_id TEXT NOT NULL,
                    corpus_version INTEGER NOT NULL,
                    spec_format_version INTEGER NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(spec_hash, entry_content_hash, transitive_import_digest,
                           toolchain_id, corpus_version, spec_format_version)
                );",
            )
            .unwrap();
        }

        // The current CORPUS_VERSION is 3.  Simulate an entry from version 2.
        let stale_corpus_version = CORPUS_VERSION.saturating_sub(1);
        assert!(
            stale_corpus_version < CORPUS_VERSION,
            "test requires CORPUS_VERSION > 1"
        );

        let result = VerifyResult {
            finding_id: "stale_entry".to_owned(),
            status: crate::evidence::VerifyStatus::Confirmed,
            triggered_payload: Some("sqli-tautology".to_owned()),
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".to_owned()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };

        // Insert directly with the old corpus_version bypassing the helper.
        {
            use rusqlite::Connection;
            let conn = Connection::open(&db_path).unwrap();
            let json = serde_json::to_string(&result).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT OR REPLACE INTO dynamic_verdict_cache \
                 (spec_hash, entry_content_hash, transitive_import_digest, toolchain_id, \
                  corpus_version, spec_format_version, verdict_json, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    "spec_stale",
                    "hash_stale",
                    "",
                    "python-3.11",
                    stale_corpus_version as i64,
                    SPEC_FORMAT_VERSION as i64,
                    json,
                    now,
                ],
            )
            .unwrap();
        }

        // Lookup using current CORPUS_VERSION → must be a MISS.
        let miss = lookup_verdict_cache(&db_path, "spec_stale", "hash_stale", "", "python-3.11");
        assert!(
            miss.is_none(),
            "stale corpus_version ({stale_corpus_version}) must not match current CORPUS_VERSION ({CORPUS_VERSION})"
        );

        // Insert with current CORPUS_VERSION → must be a HIT.
        insert_verdict_cache(
            &db_path,
            "spec_stale",
            "hash_stale",
            "",
            "python-3.11",
            &result,
        );
        let hit = lookup_verdict_cache(&db_path, "spec_stale", "hash_stale", "", "python-3.11");
        assert!(
            hit.is_some(),
            "current corpus_version entry must be a cache hit"
        );
    }

    fn partial_spec() -> HarnessSpec {
        HarnessSpec {
            finding_id: "deadbeefcafef00d".into(),
            entry_file: "app.py".into(),
            entry_name: "login".into(),
            entry_kind: crate::dynamic::spec::EntryKind::Function,
            lang: crate::symbol::Lang::Python,
            toolchain_id: "python-3.11".into(),
            payload_slot: crate::dynamic::spec::PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "app.py".into(),
            sink_line: 10,
            spec_hash: "cafecafecafe0001".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    /// Phase 26: a vuln payload whose sink-reachability probe fired but whose
    /// oracle marker never did — and no Confirmed-class verdict, no
    /// differential outcome, no benign-control gap — must surface as
    /// `PartiallyConfirmed`, carry no `triggered_payload`, and write no repro.
    #[test]
    fn build_verdict_sink_reached_no_oracle_maps_to_partially_confirmed() {
        use crate::dynamic::runner::{Attempt, RunOutcome};
        use crate::dynamic::sandbox::SandboxOutcome;

        let opts = VerifyOptions::from_config(&Config::default());
        let run = RunOutcome {
            spec: partial_spec(),
            attempts: vec![Attempt {
                payload_label: "sqli-tautology",
                outcome: SandboxOutcome {
                    exit_code: Some(0),
                    stdout: b"__NYX_SINK_HIT__".to_vec(),
                    stderr: Vec::new(),
                    timed_out: false,
                    oob_callback_seen: false,
                    sink_hit: true,
                    duration: std::time::Duration::ZERO,
                    hardening_outcome: None,
                },
                oracle_fired: false,
                triggered: false,
            }],
            triggered_by: None,
            oracle_collision: false,
            sink_reached_no_oracle: true,
            build_attempts: 1,
            harness_source: String::new(),
            entry_source: String::new(),
            differential: None,
            no_benign_control: false,
            unrelated_crash: false,
        };

        let verdict = build_verdict(
            "deadbeefcafef00d",
            &partial_spec(),
            Ok(run),
            "exact",
            &opts,
            std::time::Duration::ZERO,
        );

        assert_eq!(verdict.status, VerifyStatus::PartiallyConfirmed);
        assert!(
            verdict.triggered_payload.is_none(),
            "PartiallyConfirmed must not claim a triggering payload"
        );
        assert!(
            verdict
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("sink-reachability probe fired"),
            "detail must explain the sink reached but the chain did not complete: {:?}",
            verdict.detail
        );
        // The sink-hit attempt must survive into the surfaced attempt list.
        assert_eq!(verdict.attempts.len(), 1);
        assert!(verdict.attempts[0].sink_hit);
        assert!(!verdict.attempts[0].triggered);
    }

    /// Regression guard: a clean run (no sink hit, no oracle) must stay
    /// `NotConfirmed` — the `PartiallyConfirmed` branch must not swallow the
    /// ordinary negative case.
    #[test]
    fn build_verdict_clean_run_stays_not_confirmed() {
        use crate::dynamic::runner::{Attempt, RunOutcome};
        use crate::dynamic::sandbox::SandboxOutcome;

        let opts = VerifyOptions::from_config(&Config::default());
        let run = RunOutcome {
            spec: partial_spec(),
            attempts: vec![Attempt {
                payload_label: "sqli-tautology",
                outcome: SandboxOutcome {
                    exit_code: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    timed_out: false,
                    oob_callback_seen: false,
                    sink_hit: false,
                    duration: std::time::Duration::ZERO,
                    hardening_outcome: None,
                },
                oracle_fired: false,
                triggered: false,
            }],
            triggered_by: None,
            oracle_collision: false,
            sink_reached_no_oracle: false,
            build_attempts: 1,
            harness_source: String::new(),
            entry_source: String::new(),
            differential: None,
            no_benign_control: false,
            unrelated_crash: false,
        };

        let verdict = build_verdict(
            "deadbeefcafef00d",
            &partial_spec(),
            Ok(run),
            "exact",
            &opts,
            std::time::Duration::ZERO,
        );

        assert_eq!(verdict.status, VerifyStatus::NotConfirmed);
    }
}

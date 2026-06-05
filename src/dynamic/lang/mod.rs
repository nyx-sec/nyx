//! Per-language harness emitters.
//!
//! Each submodule implements [`LangEmitter`] for one language. The top-level
//! [`emit`] function dispatches on `spec.lang` and validates `spec.entry_kind`
//! against the chosen emitter's [`LangEmitter::entry_kinds_supported`] list
//! before delegating, so unsupported entry kinds short-circuit with a typed
//! `UnsupportedReason::EntryKindUnsupported` rather than producing a
//! never-runnable harness.
//!
//! Two free helpers — [`entry_kinds_supported`] and [`entry_kind_hint`] — wrap
//! the trait dispatch so callers outside the harness build path (notably the
//! verifier, which surfaces an `Inconclusive` verdict with the supported list
//! and hint baked in) can advertise capability without instantiating a spec.

pub mod c;
pub mod cpp;
pub mod go;
pub mod java;
pub mod java_owasp_stubs;
pub mod java_servlet_stubs;
pub mod javascript;
pub mod js_shared;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod typescript;

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec};
use crate::evidence::UnsupportedReason;
use crate::symbol::Lang;

/// Generated harness source ready to write to disk.
#[derive(Debug, Clone)]
pub struct HarnessSource {
    /// Harness source code as a UTF-8 string.
    pub source: String,
    /// Filename for the harness (e.g. `"harness.py"`, `"src/main.rs"`).
    pub filename: String,
    /// Shell command to invoke the harness (relative to the workdir).
    pub command: Vec<String>,
    /// Additional files to write to the workdir alongside the main source.
    /// Each entry is `(relative_path, content)`. Subdirectories are created
    /// automatically (e.g. `"Cargo.toml"` or `"src/entry.rs"`).
    pub extra_files: Vec<(String, String)>,
    /// Where to copy the entry source file (relative to workdir).
    /// `None` = workdir root (Python default).
    /// `Some("src/entry.rs")` = Rust module path.
    pub entry_subpath: Option<String>,
}

/// Phase 26 — one step in a chain-composite harness.
///
/// The composite re-verifier walks every member of a chain and assembles
/// a sequence of per-step harnesses.  Each step is invoked with the
/// previous step's stdout threaded into the
/// [`ChainStepHarness::PREV_OUTPUT_ENV`] env var so the harness can fold
/// the chained input into its payload (e.g. browser-fetch → websocket
/// message → shell tool).
///
/// `extra_env` is additive on top of the sandbox's own
/// [`crate::dynamic::sandbox::SandboxOptions::extra_env`]; the runner is
/// responsible for splicing both in.
#[derive(Debug, Clone)]
pub struct ChainStepHarness {
    pub source: String,
    pub filename: String,
    pub command: Vec<String>,
    pub extra_env: Vec<(String, String)>,
    /// Companion files staged alongside [`Self::source`] in the chain
    /// step's workdir.  Each entry is `(relative_path, content)`;
    /// subdirectories in `relative_path` are created automatically.
    /// Mirrors [`HarnessSource::extra_files`] so an emitter whose chain
    /// step needs a build manifest (Rust's `Cargo.toml`, future
    /// `pom.xml`, etc.) can ship it without smuggling everything into
    /// `source`.
    pub extra_files: Vec<(String, String)>,
}

impl ChainStepHarness {
    /// Env-var name the previous step's stdout is bound to in the next
    /// step's environment.  Stable surface — kept distinct from
    /// `NYX_PAYLOAD` so a chain step can read both at once.
    pub const PREV_OUTPUT_ENV: &'static str = "NYX_PREV_OUTPUT";

    /// Sentinel printed to stdout by the terminal chain step so the
    /// runner's [`crate::dynamic::sandbox::SandboxOutcome::sink_hit`]
    /// fold can flip to `true` on a successful end-to-end compose.
    /// Mirrors the per-language tracer sentinel used by the regular
    /// harness emitters; the runner detects the byte sequence in
    /// stdout/stderr.
    pub const SINK_HIT_SENTINEL: &'static str = "__NYX_SINK_HIT__";
}

/// Phase 26 — terminal-step descriptor for [`LangEmitter::compose_chain_step`].
///
/// Carries the chain's terminal sink callee so the emitter can rewrite
/// the final step's source to invoke the probe shim with the threaded
/// payload and emit the [`ChainStepHarness::SINK_HIT_SENTINEL`]; the
/// composite reverifier then promotes its verdict from `Inconclusive`
/// to `Confirmed` when the runner observes the sentinel on the chain's
/// last step.
///
/// Non-terminal steps pass `None` so they retain the prev-output echo
/// behaviour.
#[derive(Debug, Clone)]
pub struct ChainStepTerminal {
    /// Callee name for the chain's terminal sink (e.g. `"eval"`,
    /// `"os.system"`, `"setattr"`).  Used as the first argument to
    /// `__nyx_probe(callee, prev)` so the per-language probe shim
    /// records the witness.  Kept as `String` rather than `&str` so the
    /// reverifier can hand-roll a `ChainStepTerminal` from a
    /// [`crate::chain::finding::ChainSink`] without lifetime gymnastics.
    pub sink_callee: String,
    /// Capability bits associated with the sink.  Today the emitters do
    /// not read this — recorded so a future per-cap sink-fire shape
    /// dispatcher can pick the right invocation idiom without re-walking
    /// the chain.
    pub sink_cap_bits: u32,
}

/// Per-language harness emitter contract.
///
/// Implementations are zero-sized unit structs (one per `src/dynamic/lang/*.rs`
/// module).  The [`emit`](LangEmitter::emit) method is the legacy
/// per-language entry point retained for the build pipeline; the two
/// capability methods are consulted both at dispatch time (`lang::emit`
/// pre-flight check) and by the verifier when constructing
/// `Inconclusive(EntryKindUnsupported { … })`.
pub trait LangEmitter {
    /// Build a harness source bundle for `spec`.
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason>;

    /// The set of [`EntryKind`](crate::dynamic::spec::EntryKind) variants this emitter understands,
    /// projected to the [`EntryKindTag`] discriminant so the slice can
    /// live in `'static` storage even after Phase 18 extended
    /// `EntryKind` with data-bearing variants.
    ///
    /// Must be non-empty: every emitter advertises at least one shape it can
    /// (or will) drive — even stub modules whose `emit` returns
    /// `LangUnsupported`.  Empty would be indistinguishable from "language
    /// not in the dispatch table" and would defeat the structured
    /// advertisement that callers consume.
    fn entry_kinds_supported(&self) -> &'static [EntryKindTag];

    /// Human-actionable hint produced when `attempted` is not in
    /// [`entry_kinds_supported`](LangEmitter::entry_kinds_supported).
    ///
    /// The string is consumed by
    /// [`crate::evidence::InconclusiveReason::EntryKindUnsupported::hint`] and
    /// surfaces directly to operators triaging dynamic verification gaps;
    /// keep it specific (name the supported kinds, name the phase that will
    /// extend support).
    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String;

    /// Synthesise the language-specific manifest / lockfile contents that
    /// pin the [`Environment`]'s direct deps + toolchain into a file the
    /// build sandbox can consume.
    ///
    /// Default impl returns an empty bundle — every emitter that ships a
    /// real build step overrides this (Python emits `requirements.txt`,
    /// Rust emits a pinned `Cargo.toml`, etc.).  The harness builder
    /// writes every returned `(rel_path, content)` pair into the workdir
    /// alongside the generated source.
    ///
    /// Phase 09 - Track D.2 deliverable.  The default keeps the surface
    /// area additive: emitters that have not yet been wired through the
    /// capture path simply produce no manifest and the build cache key
    /// degrades to the existing lockfile-hash path.
    fn materialize_runtime(&self, _env: &Environment) -> RuntimeArtifacts {
        RuntimeArtifacts::default()
    }

    /// Phase 26 — Track G.3: build one step of a chain-composite harness.
    ///
    /// `prev_output` carries the previous step's stdout (or `None` for
    /// the chain's entry step).  `terminal` is `Some` only on the
    /// chain's last step and carries the sink callee so the emitter
    /// can splice in a `__nyx_probe(callee, prev)` call plus the
    /// [`ChainStepHarness::SINK_HIT_SENTINEL`] stdout banner that the
    /// runner detects via [`crate::dynamic::sandbox::SandboxOutcome::sink_hit`].
    ///
    /// Default impl produces a portable POSIX-shell stub that echoes
    /// the previous step's output verbatim, and (when `terminal` is
    /// set) appends a `printf '__NYX_SINK_HIT__\n'` line.  Concrete
    /// emitters override to splice in the language-native probe shim.
    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        default_chain_step(prev_output, terminal)
    }
}

/// Default chain-step harness.  Emitted by [`LangEmitter::compose_chain_step`]
/// when an emitter does not override the trait method.
pub fn default_chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let mut script = String::from("#!/bin/sh\nprintf '%s' \"${NYX_PREV_OUTPUT:-}\"\n");
    if terminal.is_some() {
        script.push_str("printf '\\n");
        script.push_str(ChainStepHarness::SINK_HIT_SENTINEL);
        script.push_str("\\n'\n");
    }
    ChainStepHarness {
        source: script,
        filename: "step.sh".to_owned(),
        command: vec!["sh".to_owned(), "step.sh".to_owned()],
        extra_env: prev_output
            .map(|bytes| {
                vec![(
                    ChainStepHarness::PREV_OUTPUT_ENV.to_owned(),
                    String::from_utf8_lossy(bytes).into_owned(),
                )]
            })
            .unwrap_or_default(),
        extra_files: Vec::new(),
    }
}

/// Public free-fn dispatcher for [`LangEmitter::compose_chain_step`].
///
/// Returns the lang-agnostic shell stub when `lang` has no registered
/// emitter so callers do not need to special-case that path.
pub fn compose_chain_step(
    lang: Lang,
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    dispatch(lang, |e| e.compose_chain_step(prev_output, terminal))
        .unwrap_or_else(|| default_chain_step(prev_output, terminal))
}

/// Public free-fn dispatcher for [`LangEmitter::materialize_runtime`].
///
/// Returns an empty [`RuntimeArtifacts`] when `env.lang` has no
/// registered emitter so callers do not need to special-case that path.
/// Used by the harness builder to fold runtime manifest artifacts into
/// the staged workdir (Phase 09 — Track D.2).
pub fn materialize_runtime(env: &Environment) -> RuntimeArtifacts {
    dispatch(env.lang, |e| e.materialize_runtime(env)).unwrap_or_default()
}

/// Dispatch to the appropriate language emitter.
///
/// Validates `spec.entry_kind` against the chosen emitter's supported list
/// before delegating; an unsupported entry kind short-circuits with
/// [`UnsupportedReason::EntryKindUnsupported`] so the verifier can surface a
/// structured `Inconclusive` verdict with the supported list and hint baked
/// in (instead of producing a never-runnable harness).
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    let supported = entry_kinds_supported(spec.lang);
    if !supported.is_empty() && !supported.contains(&spec.entry_kind.tag()) {
        return Err(UnsupportedReason::EntryKindUnsupported);
    }
    dispatch(spec.lang, |e| e.emit(spec)).unwrap_or(Err(UnsupportedReason::LangUnsupported))
}

/// Public free-fn dispatcher for the supported entry kinds of `lang`.
///
/// Returns an empty slice when `lang` has no registered emitter — callers
/// distinguish that from "emitter exists but advertises none" by treating
/// empty as "language unsupported".
pub fn entry_kinds_supported(lang: Lang) -> &'static [EntryKindTag] {
    dispatch(lang, |e| e.entry_kinds_supported()).unwrap_or(&[])
}

/// Public free-fn dispatcher for an emitter's hint about `attempted`.
///
/// Falls back to a generic message when `lang` has no registered emitter so
/// callers do not need to special-case that path.
pub fn entry_kind_hint(lang: Lang, attempted: EntryKindTag) -> String {
    dispatch(lang, |e| e.entry_kind_hint(attempted)).unwrap_or_else(|| {
        format!("no harness emitter is registered for {lang:?}; attempted {attempted}")
    })
}

/// Internal helper: invoke `f` against the emitter registered for `lang`,
/// returning `None` when no emitter is registered for that language.
fn dispatch<R>(lang: Lang, f: impl FnOnce(&dyn LangEmitter) -> R) -> Option<R> {
    let emitter: Option<&dyn LangEmitter> = match lang {
        Lang::Python => Some(&python::PythonEmitter),
        Lang::Rust => Some(&rust::RustEmitter),
        Lang::JavaScript => Some(&javascript::JavaScriptEmitter),
        Lang::TypeScript => Some(&typescript::TypeScriptEmitter),
        Lang::Go => Some(&go::GoEmitter),
        Lang::Java => Some(&java::JavaEmitter),
        Lang::Php => Some(&php::PhpEmitter),
        Lang::Ruby => Some(&ruby::RubyEmitter),
        Lang::C => Some(&c::CEmitter),
        Lang::Cpp => Some(&cpp::CppEmitter),
    };
    emitter.map(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::EntryKind;

    /// Every registered emitter must advertise at least one entry kind so the
    /// verifier never produces an empty `supported` list in
    /// `Inconclusive(EntryKindUnsupported { supported, .. })`.
    #[test]
    fn every_lang_advertises_at_least_one_entry_kind() {
        for lang in [
            Lang::Python,
            Lang::Rust,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Go,
            Lang::Java,
            Lang::Php,
            Lang::Ruby,
            Lang::C,
            Lang::Cpp,
        ] {
            let kinds = entry_kinds_supported(lang);
            assert!(
                !kinds.is_empty(),
                "{lang:?} emitter must advertise at least one EntryKind"
            );
        }
    }

    #[test]
    fn entry_kind_hint_mentions_attempted() {
        let hint = entry_kind_hint(Lang::Python, EntryKindTag::HttpRoute);
        assert!(
            hint.contains("HttpRoute"),
            "hint must mention the attempted entry kind, got: {hint:?}"
        );
    }

    /// Phase 18 (Track M.0) — every Phase 18 variant resolves to a
    /// distinct [`EntryKindTag`] via [`EntryKind::tag`], and the
    /// per-language emitters short-circuit those tags with a typed
    /// `Inconclusive(EntryKindUnsupported)` hint that mentions the
    /// follow-up phase that will close the gap.
    #[test]
    fn entry_kind_tag_round_trips_for_phase_18_variants() {
        use crate::evidence::EntryKindTag as T;
        assert_eq!(EntryKind::Function.tag(), T::Function);
        assert_eq!(EntryKind::HttpRoute.tag(), T::HttpRoute);
        assert_eq!(EntryKind::CliSubcommand.tag(), T::CliSubcommand);
        assert_eq!(EntryKind::LibraryApi.tag(), T::LibraryApi);
        assert_eq!(
            EntryKind::ClassMethod {
                class: "Cls".into(),
                method: "do".into(),
            }
            .tag(),
            T::ClassMethod
        );
        assert_eq!(
            EntryKind::MessageHandler {
                queue: "q".into(),
                message_schema: None,
            }
            .tag(),
            T::MessageHandler
        );
        assert_eq!(
            EntryKind::ScheduledJob { schedule: None }.tag(),
            T::ScheduledJob
        );
        assert_eq!(
            EntryKind::GraphQLResolver {
                type_name: "User".into(),
                field: "name".into(),
            }
            .tag(),
            T::GraphQLResolver
        );
        assert_eq!(
            EntryKind::WebSocket { path: "/ws".into() }.tag(),
            T::WebSocket
        );
        assert_eq!(
            EntryKind::Middleware {
                name: "auth".into()
            }
            .tag(),
            T::Middleware
        );
        assert_eq!(EntryKind::Migration { version: None }.tag(), T::Migration);
        assert_eq!(EntryKind::Unknown.tag(), T::Unknown);
    }

    /// Phase 21 (Track M.3) — the five remaining `EntryKind` variants
    /// (`ScheduledJob` / `GraphQLResolver` / `WebSocket` / `Middleware`
    /// / `Migration`) are now wired on the per-lang emitters the brief
    /// targets.  This regression guard pins the per-lang advertisement
    /// matrix.  Languages outside each variant's lang-set still route
    /// through the supported-set gate so the verifier emits
    /// `Inconclusive(EntryKindUnsupported)` rather than degrading
    /// silently.
    #[test]
    fn entry_kind_phase_21_variants_advertised_per_brief() {
        use crate::evidence::EntryKindTag as T;
        let want = |lang: Lang, tag: T| -> bool {
            match (lang, tag) {
                // ScheduledJob: cron (JS), quartz (Java), celery (Python),
                // sidekiq (Ruby).  TypeScript shares the JS emitter so it
                // inherits the variant through the shared SUPPORTED slice.
                (
                    Lang::Python | Lang::JavaScript | Lang::TypeScript | Lang::Java | Lang::Ruby,
                    T::ScheduledJob,
                ) => true,
                // GraphQLResolver: apollo + relay (JS), graphene (Python),
                // juniper (Rust), gqlgen (Go).  TypeScript shares the JS
                // emitter so it inherits resolver dispatch.
                (
                    Lang::Python | Lang::JavaScript | Lang::TypeScript | Lang::Rust | Lang::Go,
                    T::GraphQLResolver,
                ) => true,
                // WebSocket: socketio + channels (Python), ws (JS),
                // actioncable (Ruby).
                (Lang::Python | Lang::JavaScript | Lang::TypeScript | Lang::Ruby, T::WebSocket) => {
                    true
                }
                // Middleware: express (JS), django (Python), rails (Ruby),
                // spring (Java), laravel (PHP).
                (
                    Lang::Python
                    | Lang::JavaScript
                    | Lang::TypeScript
                    | Lang::Java
                    | Lang::Ruby
                    | Lang::Php,
                    T::Middleware,
                ) => true,
                // Migration: rails (Ruby), django + flask (Python),
                // laravel (PHP), sequelize + prisma (JS).
                (
                    Lang::Python | Lang::JavaScript | Lang::TypeScript | Lang::Ruby | Lang::Php,
                    T::Migration,
                ) => true,
                _ => false,
            }
        };
        let phase_21_tags = [
            T::ScheduledJob,
            T::GraphQLResolver,
            T::WebSocket,
            T::Middleware,
            T::Migration,
        ];
        for lang in [
            Lang::Python,
            Lang::Rust,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Go,
            Lang::Java,
            Lang::Php,
            Lang::Ruby,
            Lang::C,
            Lang::Cpp,
        ] {
            let supported = entry_kinds_supported(lang);
            for tag in phase_21_tags {
                let expected = want(lang, tag);
                let actual = supported.contains(&tag);
                assert_eq!(
                    actual, expected,
                    "{lang:?} expected supported={expected:?} for {tag:?}; got supported={actual:?}",
                );
                if !actual {
                    let hint = entry_kind_hint(lang, tag);
                    assert!(
                        hint.contains(tag.as_str()),
                        "{lang:?} hint for unsupported {tag:?} must mention the attempted tag, got: {hint:?}"
                    );
                }
            }
        }
    }

    /// Phase 20 (Track M.2) — `MessageHandler` is supported on the five
    /// langs the brief lists (Python, Java, JavaScript, TypeScript, Go)
    /// and remains unsupported on the rest (Ruby, PHP, Rust, C, Cpp).
    /// The verifier should produce a structured
    /// `Inconclusive(EntryKindUnsupported)` for the unsupported set.
    #[test]
    fn entry_kind_message_handler_supported_in_phase_20_langs() {
        use crate::evidence::EntryKindTag as T;
        let supported_langs = [
            Lang::Python,
            Lang::Java,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Go,
        ];
        let unsupported_langs = [Lang::Php, Lang::Ruby, Lang::Rust, Lang::C, Lang::Cpp];
        for lang in supported_langs {
            let supported = entry_kinds_supported(lang);
            assert!(
                supported.contains(&T::MessageHandler),
                "{lang:?} must advertise MessageHandler after Phase 20; got {supported:?}",
            );
        }
        for lang in unsupported_langs {
            let supported = entry_kinds_supported(lang);
            assert!(
                !supported.contains(&T::MessageHandler),
                "{lang:?} must not yet advertise MessageHandler — Phase 20 only covers 5 langs",
            );
        }
    }

    /// Phase 19 (Track M.1) — every lang emitter now advertises
    /// `ClassMethod` so the verifier dispatches structurally instead
    /// of degrading to `Inconclusive(EntryKindUnsupported)`.
    #[test]
    fn entry_kind_class_method_supported_everywhere_after_phase_19() {
        use crate::evidence::EntryKindTag as T;
        for lang in [
            Lang::Python,
            Lang::Rust,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Go,
            Lang::Java,
            Lang::Php,
            Lang::Ruby,
            Lang::C,
            Lang::Cpp,
        ] {
            let supported = entry_kinds_supported(lang);
            assert!(
                supported.contains(&T::ClassMethod),
                "{lang:?} must advertise ClassMethod after Phase 19; got {supported:?}"
            );
        }
    }
}

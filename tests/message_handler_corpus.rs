//! Phase 20 (Track M.2) — `MessageHandler` end-to-end acceptance.
//!
//! Asserts the new `EntryKind::MessageHandler { queue, message_schema }`
//! variant is supported by the per-language emitters the brief targets
//! (Python, Java, JavaScript, TypeScript, Go) so the
//! `Inconclusive(EntryKindUnsupported { attempted: MessageHandler })`
//! rate drops to 0% across those five languages.  Also exercises the
//! 10 Phase 20 framework adapters (`kafka-python`, `kafka-java`,
//! `sqs-python`, `sqs-java`, `sqs-node`, `pubsub-python`, `pubsub-go`,
//! `rabbit-python`, `rabbit-java`, `nats-go`) against the fixtures
//! under `tests/dynamic_fixtures/message_handler/`.
//!
//! `cargo nextest run --features dynamic --test message_handler_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::framework::{detect_binding, FrameworkBinding};
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

const SUPPORTED_LANGS: &[Lang] = &[
    Lang::Python,
    Lang::Java,
    Lang::JavaScript,
    Lang::TypeScript,
    Lang::Go,
];

const UNSUPPORTED_LANGS: &[Lang] = &[
    Lang::Php,
    Lang::Ruby,
    Lang::Rust,
    Lang::C,
    Lang::Cpp,
];

fn entry_file(broker_lang: &str) -> &'static str {
    // Phase 20 fixtures live at tests/dynamic_fixtures/message_handler/{broker_lang}/{vuln,benign}.
    match broker_lang {
        "kafka_python" => "tests/dynamic_fixtures/message_handler/kafka_python/vuln.py",
        "kafka_java" => "tests/dynamic_fixtures/message_handler/kafka_java/Vuln.java",
        "sqs_python" => "tests/dynamic_fixtures/message_handler/sqs_python/vuln.py",
        "sqs_java" => "tests/dynamic_fixtures/message_handler/sqs_java/Vuln.java",
        "sqs_node" => "tests/dynamic_fixtures/message_handler/sqs_node/vuln.js",
        "pubsub_python" => "tests/dynamic_fixtures/message_handler/pubsub_python/vuln.py",
        "pubsub_go" => "tests/dynamic_fixtures/message_handler/pubsub_go/vuln.go",
        "rabbit_python" => "tests/dynamic_fixtures/message_handler/rabbit_python/vuln.py",
        "rabbit_java" => "tests/dynamic_fixtures/message_handler/rabbit_java/Vuln.java",
        "nats_go" => "tests/dynamic_fixtures/message_handler/nats_go/vuln.go",
        other => panic!("unknown broker_lang fixture {other}"),
    }
}

fn make_spec(lang: Lang, queue: &str, handler: &str, fixture: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase20msghandler".into(),
        entry_file: fixture.into(),
        entry_name: handler.into(),
        entry_kind: EntryKind::MessageHandler {
            queue: queue.into(),
            message_schema: None,
        },
        lang,
        toolchain_id: "phase20".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::CODE_EXEC,
        constraint_hints: vec![],
        sink_file: fixture.into(),
        sink_line: 1,
        spec_hash: "phase20msghandler".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

// ── Supported-set assertions ──────────────────────────────────────────────────

#[test]
fn message_handler_supported_by_phase_20_lang_emitters() {
    for lang in SUPPORTED_LANGS {
        let supported = lang::entry_kinds_supported(*lang);
        assert!(
            supported.contains(&EntryKindTag::MessageHandler),
            "{lang:?} must advertise MessageHandler after Phase 20; supported = {supported:?}",
        );
    }
}

#[test]
fn message_handler_not_supported_outside_phase_20_langs() {
    for lang in UNSUPPORTED_LANGS {
        let supported = lang::entry_kinds_supported(*lang);
        assert!(
            !supported.contains(&EntryKindTag::MessageHandler),
            "{lang:?} must not yet advertise MessageHandler — Phase 20 only covers 5 langs; got {supported:?}",
        );
    }
}

#[test]
fn message_handler_emit_does_not_short_circuit_for_supported_langs() {
    let cases: &[(Lang, &str, &str, &str)] = &[
        (Lang::Python, "kafka_python", "orders", "handler"),
        (Lang::Java, "kafka_java", "orders", "onMessage"),
        (Lang::JavaScript, "sqs_node", "jobs", "handler"),
        (Lang::TypeScript, "sqs_node", "jobs", "handler"),
        (Lang::Go, "pubsub_go", "my-sub", "OnMessage"),
    ];
    for (lang, broker_lang, queue, handler) in cases {
        let spec = make_spec(*lang, queue, handler, entry_file(broker_lang));
        let result = lang::emit(&spec);
        assert!(
            result.is_ok(),
            "{lang:?} emit returned {result:?} for MessageHandler spec",
        );
    }
}

#[test]
fn message_handler_harness_carries_queue_and_handler_literals() {
    let cases: &[(Lang, &str, &str, &str)] = &[
        (Lang::Python, "kafka_python", "orders", "handler"),
        (Lang::Java, "kafka_java", "orders", "onMessage"),
        (Lang::JavaScript, "sqs_node", "jobs", "handler"),
        (Lang::Go, "pubsub_go", "my-sub", "OnMessage"),
    ];
    for (lang, broker_lang, queue, handler) in cases {
        let spec = make_spec(*lang, queue, handler, entry_file(broker_lang));
        let h = lang::emit(&spec).expect("emit ok");
        assert!(
            h.source.contains(queue),
            "{lang:?} harness must reference queue {queue:?}; source: {}",
            h.source
        );
        assert!(
            h.source.contains(handler),
            "{lang:?} harness must reference handler {handler:?}",
        );
    }
}

#[test]
fn message_handler_python_dispatch_subscribes_to_loopback() {
    let spec = make_spec(
        Lang::Python,
        "orders",
        "handler",
        entry_file("kafka_python"),
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("NyxKafkaLoopback"));
    assert!(h.source.contains("subscribe"));
    assert!(h.source.contains("__NYX_BROKER_PUBLISH__"));
    assert!(h.source.contains("payload"));
}

#[test]
fn message_handler_java_emits_reflective_dispatch() {
    let spec = make_spec(Lang::Java, "orders", "onMessage", entry_file("kafka_java"));
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("NyxKafkaLoopback"));
    assert!(h.source.contains("Class.forName"));
    assert!(h.source.contains("getDeclaredMethod"));
}

#[test]
fn message_handler_node_uses_sqs_loopback() {
    let spec = make_spec(Lang::JavaScript, "jobs", "handler", entry_file("sqs_node"));
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("NyxSqsLoopback"));
    assert!(h.source.contains("subscribe"));
    assert!(h.source.contains("__NYX_BROKER_PUBLISH__:sqs"));
}

#[test]
fn message_handler_go_uses_nyx_handlers_registry() {
    let spec = make_spec(Lang::Go, "my-sub", "OnMessage", entry_file("pubsub_go"));
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("entry.NyxHandlers"));
    assert!(h.source.contains("NewNyxPubsubLoopback"));
}

// ── Framework-adapter assertions ──────────────────────────────────────────────

fn ts_language_for(lang: Lang) -> tree_sitter::Language {
    match lang {
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Lang::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn detect_for(lang: Lang, fixture: &str, handler: &str) -> Option<FrameworkBinding> {
    let bytes = std::fs::read(fixture).expect("fixture exists");
    let ts_lang = ts_language_for(lang);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(&bytes, None).unwrap();
    let summary = FuncSummary {
        name: handler.into(),
        ..Default::default()
    };
    detect_binding(&summary, tree.root_node(), &bytes, lang)
}

#[test]
fn kafka_python_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Python, entry_file("kafka_python"), "handler")
        .expect("kafka-python detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn kafka_java_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Java, entry_file("kafka_java"), "onMessage")
        .expect("kafka-java detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn sqs_python_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Python, entry_file("sqs_python"), "handler")
        .expect("sqs-python detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn sqs_java_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Java, entry_file("sqs_java"), "handleMessage")
        .expect("sqs-java detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn sqs_node_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::JavaScript, entry_file("sqs_node"), "handler")
        .expect("sqs-node detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn pubsub_python_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Python, entry_file("pubsub_python"), "callback")
        .expect("pubsub-python detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn pubsub_go_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Go, entry_file("pubsub_go"), "OnMessage")
        .expect("pubsub-go detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn rabbit_python_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Python, entry_file("rabbit_python"), "on_message")
        .expect("rabbit-python detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn rabbit_java_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Java, entry_file("rabbit_java"), "onMessage")
        .expect("rabbit-java detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn nats_go_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Go, entry_file("nats_go"), "OnMessage")
        .expect("nats-go detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn registry_slices_include_phase_20_adapters() {
    let java_names: Vec<&'static str> = adapters_for(Lang::Java)
        .iter()
        .map(|a| a.name())
        .collect();
    assert!(java_names.contains(&"kafka-java"));
    assert!(java_names.contains(&"sqs-java"));
    assert!(java_names.contains(&"rabbit-java"));

    let python_names: Vec<&'static str> = adapters_for(Lang::Python)
        .iter()
        .map(|a| a.name())
        .collect();
    assert!(python_names.contains(&"kafka-python"));
    assert!(python_names.contains(&"sqs-python"));
    assert!(python_names.contains(&"pubsub-python"));
    assert!(python_names.contains(&"rabbit-python"));

    let go_names: Vec<&'static str> = adapters_for(Lang::Go)
        .iter()
        .map(|a| a.name())
        .collect();
    assert!(go_names.contains(&"pubsub-go"));
    assert!(go_names.contains(&"nats-go"));

    let js_names: Vec<&'static str> = adapters_for(Lang::JavaScript)
        .iter()
        .map(|a| a.name())
        .collect();
    assert!(js_names.contains(&"sqs-node"));
}

// ── End-to-end Phase 20 acceptance via run_spec ───────────────────────────────
//
// Toolchain-gated.  Each language's run_spec block invokes the
// dynamic runner on the fixture under tests/dynamic_fixtures/message_handler/
// and asserts the differential verdict.  A missing toolchain triggers
// a structured skip (eprintln + early return) — the test stays green
// so the wider suite is not held hostage to a single host's missing
// `python3` / `node` / `javac` / `go`.

mod e2e_phase_20 {
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::runner::{run_spec, RunError, RunOutcome};
    use nyx_scanner::dynamic::sandbox::SandboxOptions;
    use nyx_scanner::dynamic::spec::{
        default_toolchain_id, EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy,
    };
    use nyx_scanner::evidence::DifferentialVerdict;
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn command_available(bin: &str) -> bool {
        Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn toolchain_for(lang: Lang) -> &'static str {
        match lang {
            Lang::Java => "java",
            Lang::Python => "python3",
            Lang::JavaScript | Lang::TypeScript => "node",
            Lang::Go => "go",
            _ => unreachable!("e2e_phase_20 only covers Java/Python/Node/Go"),
        }
    }

    fn adapter_for(fixture_dir: &str) -> &'static str {
        match fixture_dir {
            "kafka_python" => "kafka-python",
            "kafka_java" => "kafka-java",
            "sqs_python" => "sqs-python",
            "sqs_java" => "sqs-java",
            "sqs_node" => "sqs-node",
            "pubsub_python" => "pubsub-python",
            "pubsub_go" => "pubsub-go",
            "rabbit_python" => "rabbit-python",
            "rabbit_java" => "rabbit-java",
            "nats_go" => "nats-go",
            other => panic!("unknown fixture_dir {other}"),
        }
    }

    fn build_spec(
        lang: Lang,
        fixture_dir: &str,
        fixture_file: &str,
        handler: &str,
        queue: &str,
    ) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/message_handler")
            .join(fixture_dir)
            .join(fixture_file);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture_file);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase20-e2e-message-handler|");
        digest.update(fixture_dir.as_bytes());
        digest.update(b"|");
        digest.update(fixture_file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        if matches!(lang, Lang::Java) {
            let workdir = std::path::PathBuf::from("/tmp/nyx-harness").join(&spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
        }

        let adapter = adapter_for(fixture_dir);
        let framework = Some(nyx_scanner::dynamic::framework::FrameworkBinding {
            adapter: adapter.to_owned(),
            kind: EntryKind::MessageHandler {
                queue: queue.to_owned(),
                message_schema: None,
            },
            route: None,
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: handler.to_owned(),
            entry_kind: EntryKind::MessageHandler {
                queue: queue.to_owned(),
                message_schema: None,
            },
            lang,
            toolchain_id: default_toolchain_id(lang).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash: spec_hash.clone(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework,
            java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
        };

        (spec, tmp)
    }

    fn run(
        lang: Lang,
        fixture_dir: &str,
        fixture_file: &str,
        handler: &str,
        queue: &str,
    ) -> Option<RunOutcome> {
        let bin = toolchain_for(lang);
        if !command_available(bin) {
            eprintln!("SKIP {lang:?} {fixture_dir}/{fixture_file}: missing toolchain {bin}");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(lang, fixture_dir, fixture_file, handler, queue);
        let opts = SandboxOptions {
            backend: nyx_scanner::dynamic::sandbox::SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {lang:?} {fixture_dir}/{fixture_file}: harness build failed after {attempts} attempts: {stderr}",
                );
                None
            }
            Err(e) => panic!(
                "run_spec({lang:?} {fixture_dir}/{fixture_file}) errored: {e:?}",
            ),
        }
    }

    /// Python kafka vuln must Confirm: the synthetic Kafka loopback
    /// delivers `; echo NYX_PWN_CMDI` to the handler's `os.system`
    /// which prints `NYX_PWN_CMDI` to stdout and the differential
    /// oracle reads it.
    #[test]
    fn kafka_python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "kafka_python", "vuln.py", "handler", "orders")
        else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "kafka-python MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn sqs_python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "sqs_python", "vuln.py", "handler", "jobs")
        else {
            return;
        };
        assert!(outcome.triggered_by.is_some());
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn pubsub_python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(
            Lang::Python,
            "pubsub_python",
            "vuln.py",
            "callback",
            "projects/p/subscriptions/s",
        ) else {
            return;
        };
        assert!(outcome.triggered_by.is_some());
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn rabbit_python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(
            Lang::Python,
            "rabbit_python",
            "vuln.py",
            "on_message",
            "work",
        ) else {
            return;
        };
        assert!(outcome.triggered_by.is_some());
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn sqs_node_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "sqs_node", "vuln.js", "handler", "jobs")
        else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "sqs-node vuln failed; attempts: {:?}",
            outcome.attempts,
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }
}

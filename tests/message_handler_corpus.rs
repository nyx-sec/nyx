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
use nyx_scanner::dynamic::framework::{
    FrameworkBinding, detect_binding, detect_binding_with_context,
};
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::CalleeSite;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::summary::ssa_summary::SsaFuncSummary;
use nyx_scanner::symbol::Lang;

const SUPPORTED_LANGS: &[Lang] = &[
    Lang::Python,
    Lang::Java,
    Lang::JavaScript,
    Lang::TypeScript,
    Lang::Go,
];

const UNSUPPORTED_LANGS: &[Lang] = &[Lang::Php, Lang::Ruby, Lang::Rust, Lang::C, Lang::Cpp];

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

fn make_spec_with_adapter(
    lang: Lang,
    queue: &str,
    handler: &str,
    fixture: &str,
    adapter: &str,
) -> HarnessSpec {
    let mut spec = make_spec(lang, queue, handler, fixture);
    spec.framework = Some(FrameworkBinding {
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
    spec
}

fn assert_extra_file_contains(files: &[(String, String)], path: &str, needle: &str, context: &str) {
    assert!(
        files.iter().any(|(p, c)| p == path && c.contains(needle)),
        "{context} must stage {path} containing {needle:?}; got {files:?}"
    );
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
    assert!(h.source.contains("_nyx_try_real_kafka"));
    assert!(h.source.contains("KafkaConsumer"));
    assert!(h.source.contains("KafkaProducer"));
    assert!(h.source.contains("_nyx_try_kafka_http"));
    assert!(h.source.contains("NYX_KAFKA_ENDPOINT"));
    assert!(h.source.contains("NyxKafkaLoopback"));
    assert!(h.source.contains("subscribe"));
    assert!(h.source.contains("poll"));
    assert!(h.source.contains("commit"));
    assert!(h.source.contains("\"deliver\""));
    assert!(h.source.contains("\"ack\""));
    assert!(h.source.contains("__NYX_BROKER_PUBLISH__"));
    assert!(h.source.contains("NYX_KAFKA_LOG"));
    assert!(h.source.contains("_nyx_record_broker_publish"));
    assert!(h.source.contains("payload"));
    assert!(
        h.source.find("_nyx_try_real_kafka").unwrap()
            < h.source.find("_nyx_try_kafka_http").unwrap(),
        "kafka-python should try the real kafka-python client before HTTP fallback"
    );
}

#[test]
fn message_handler_java_emits_reflective_dispatch() {
    let spec = make_spec(Lang::Java, "orders", "onMessage", entry_file("kafka_java"));
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("nyxTryLiveKafkaClient"));
    assert!(h.source.contains("KafkaProducer"));
    assert!(h.source.contains("KafkaConsumer"));
    assert!(h.source.contains("ProducerRecord"));
    assert!(h.source.contains("nyxTryRealKafkaClient"));
    assert!(h.source.contains("MockConsumer"));
    assert!(h.source.contains("commitSync"));
    assert!(h.source.contains("nyxTryKafkaHttp"));
    assert!(h.source.contains("NYX_KAFKA_ENDPOINT"));
    assert!(h.source.contains("NyxKafkaLoopback"));
    assert!(h.source.contains("Class.forName"));
    assert!(h.source.contains("getDeclaredMethod"));
    assert!(h.source.contains("brokerRef.poll"));
    assert!(h.source.contains("brokerRef.commit"));
    assert!(h.source.contains("\"deliver\""));
    assert!(h.source.contains("\"ack\""));
    assert!(h.source.contains("NYX_KAFKA_LOG"));
    assert!(h.source.contains("nyxRecordBrokerPublish"));
    assert!(
        h.source.find("nyxTryLiveKafkaClient").unwrap()
            < h.source.find("nyxTryRealKafkaClient").unwrap(),
        "kafka-java should try a live Kafka client before MockConsumer"
    );
}

#[test]
fn message_handler_node_uses_sqs_loopback() {
    let spec = make_spec(Lang::JavaScript, "jobs", "handler", entry_file("sqs_node"));
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("NyxSqsLoopback"));
    assert!(h.source.contains("_nyxTryRealSqs"));
    assert!(h.source.contains("@aws-sdk/client-sqs"));
    assert!(h.source.contains("SendMessageCommand"));
    assert!(h.source.contains("ReceiveMessageCommand"));
    assert!(h.source.contains("DeleteMessageCommand"));
    assert!(h.source.contains("receiveMessage"));
    assert!(h.source.contains("deleteMessage"));
    assert!(h.source.contains("'deliver'"));
    assert!(h.source.contains("'ack'"));
    assert!(h.source.contains("__NYX_BROKER_PUBLISH__:sqs"));
    assert!(h.source.contains("NYX_SQS_LOG"));
    assert!(h.source.contains("_nyxRecordBrokerPublish"));
}

#[test]
fn message_handler_python_sqs_tries_real_boto3_client_first() {
    let spec = make_spec_with_adapter(
        Lang::Python,
        "jobs",
        "handler",
        entry_file("sqs_python"),
        "sqs-python",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("_nyx_try_real_sqs"));
    assert!(h.source.contains("boto3.client(\"sqs\""));
    assert!(h.source.contains("send_message"));
    assert!(h.source.contains("receive_message"));
    assert!(h.source.contains("delete_message"));
    assert!(h.source.contains("NyxSqsLoopback"));
}

#[test]
fn message_handler_java_sqs_tries_real_aws_sdk_client_first() {
    let spec = make_spec_with_adapter(
        Lang::Java,
        "jobs",
        "onMessage",
        entry_file("sqs_java"),
        "sqs-java",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("nyxTryRealSqs"));
    assert!(
        h.source
            .contains("software.amazon.awssdk.services.sqs.SqsClient")
    );
    assert!(h.source.contains("SendMessageRequest"));
    assert!(h.source.contains("ReceiveMessageRequest"));
    assert!(h.source.contains("DeleteMessageRequest"));
    assert!(h.command.iter().any(|arg| arg == ".:lib/*"));
    assert!(h.source.contains("NyxSqsLoopback"));
}

#[test]
fn message_handler_python_pubsub_tries_real_client_before_fallbacks() {
    let spec = make_spec_with_adapter(
        Lang::Python,
        "projects/p/subscriptions/s",
        "callback",
        entry_file("pubsub_python"),
        "pubsub-python",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("_nyx_try_real_pubsub"));
    assert!(h.source.contains("google.cloud"));
    assert!(h.source.contains("PublisherClient"));
    assert!(h.source.contains("SubscriberClient"));
    assert!(h.source.contains("_nyx_try_pubsub_http"));
    assert!(
        h.source.find("_nyx_try_real_pubsub").unwrap()
            < h.source.find("_nyx_try_pubsub_http").unwrap(),
        "pubsub-python should try google-cloud-pubsub before HTTP fallback"
    );
}

#[test]
fn message_handler_python_rabbit_tries_real_client_before_fallbacks() {
    let spec = make_spec_with_adapter(
        Lang::Python,
        "work",
        "on_message",
        entry_file("rabbit_python"),
        "rabbit-python",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("_nyx_try_real_rabbit"));
    assert!(h.source.contains("import pika"));
    assert!(h.source.contains("BlockingConnection"));
    assert!(h.source.contains("basic_get"));
    assert!(h.source.contains("_nyx_try_rabbit_http"));
    assert!(
        h.source.find("_nyx_try_real_rabbit").unwrap()
            < h.source.find("_nyx_try_rabbit_http").unwrap(),
        "rabbit-python should try pika before HTTP fallback"
    );
}

#[test]
fn message_handler_java_rabbit_tries_real_client_before_fallbacks() {
    let spec = make_spec_with_adapter(
        Lang::Java,
        "work",
        "onMessage",
        entry_file("rabbit_java"),
        "rabbit-java",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("nyxTryRealRabbitClient"));
    assert!(h.source.contains("com.rabbitmq.client.ConnectionFactory"));
    assert!(h.source.contains("basicPublish"));
    assert!(h.source.contains("basicGet"));
    assert!(h.source.contains("basicAck"));
    assert!(h.source.contains("nyxTryRabbitHttp"));
    assert!(h.command.iter().any(|arg| arg == ".:lib/*"));
    assert!(
        h.source.find("nyxTryRealRabbitClient").unwrap()
            < h.source.find("nyxTryRabbitHttp").unwrap(),
        "rabbit-java should try the RabbitMQ Java client before HTTP fallback"
    );
}

#[test]
fn message_handler_real_client_runtime_deps_are_staged_from_adapter() {
    let py_kafka = lang::emit(&make_spec_with_adapter(
        Lang::Python,
        "orders",
        "handler",
        entry_file("kafka_python"),
        "kafka-python",
    ))
    .expect("emit kafka-python");
    assert_extra_file_contains(
        &py_kafka.extra_files,
        "requirements.txt",
        "kafka-python",
        "kafka-python",
    );

    let py_pubsub = lang::emit(&make_spec_with_adapter(
        Lang::Python,
        "projects/p/subscriptions/s",
        "callback",
        entry_file("pubsub_python"),
        "pubsub-python",
    ))
    .expect("emit pubsub-python");
    assert_extra_file_contains(
        &py_pubsub.extra_files,
        "requirements.txt",
        "google-cloud-pubsub",
        "pubsub-python",
    );

    let py_rabbit = lang::emit(&make_spec_with_adapter(
        Lang::Python,
        "work",
        "on_message",
        entry_file("rabbit_python"),
        "rabbit-python",
    ))
    .expect("emit rabbit-python");
    assert_extra_file_contains(
        &py_rabbit.extra_files,
        "requirements.txt",
        "pika",
        "rabbit-python",
    );

    let node_sqs = lang::emit(&make_spec_with_adapter(
        Lang::JavaScript,
        "jobs",
        "handler",
        entry_file("sqs_node"),
        "sqs-node",
    ))
    .expect("emit sqs-node");
    assert_extra_file_contains(
        &node_sqs.extra_files,
        "package.json",
        "@aws-sdk/client-sqs",
        "sqs-node",
    );

    let java_kafka = lang::emit(&make_spec_with_adapter(
        Lang::Java,
        "orders",
        "onMessage",
        entry_file("kafka_java"),
        "kafka-java",
    ))
    .expect("emit kafka-java");
    assert_extra_file_contains(
        &java_kafka.extra_files,
        "pom.xml",
        "kafka-clients",
        "kafka-java",
    );

    let java_rabbit = lang::emit(&make_spec_with_adapter(
        Lang::Java,
        "work",
        "onMessage",
        entry_file("rabbit_java"),
        "rabbit-java",
    ))
    .expect("emit rabbit-java");
    assert_extra_file_contains(
        &java_rabbit.extra_files,
        "pom.xml",
        "amqp-client",
        "rabbit-java",
    );

    let go_pubsub = lang::emit(&make_spec_with_adapter(
        Lang::Go,
        "my-sub",
        "OnMessage",
        entry_file("pubsub_go"),
        "pubsub-go",
    ))
    .expect("emit pubsub-go");
    assert_extra_file_contains(
        &go_pubsub.extra_files,
        "go.mod",
        "cloud.google.com/go/pubsub",
        "pubsub-go",
    );

    let go_nats = lang::emit(&make_spec_with_adapter(
        Lang::Go,
        "events",
        "OnMessage",
        entry_file("nats_go"),
        "nats-go",
    ))
    .expect("emit nats-go");
    assert_extra_file_contains(
        &go_nats.extra_files,
        "go.mod",
        "github.com/nats-io/nats.go",
        "nats-go",
    );
}

#[test]
fn message_handler_go_pubsub_tries_real_client_before_fallbacks() {
    let spec = make_spec_with_adapter(
        Lang::Go,
        "my-sub",
        "OnMessage",
        entry_file("pubsub_go"),
        "pubsub-go",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("nyxTryRealPubsub"));
    assert!(h.source.contains("cloud.google.com/go/pubsub"));
    assert!(h.source.contains("pubsubapi.NewClient"));
    assert!(h.source.contains("CreateSubscription"));
    assert!(h.source.contains("nyxFetchHttpBroker"));
    assert!(
        h.source.find("nyxTryRealPubsub").unwrap() < h.source.find("nyxFetchHttpBroker").unwrap(),
        "pubsub-go should try the real Pub/Sub client before HTTP fallback"
    );
}

#[test]
fn message_handler_go_uses_nyx_handlers_registry() {
    let spec = make_spec(Lang::Go, "my-sub", "OnMessage", entry_file("pubsub_go"));
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("entry.NyxHandlers"));
    assert!(h.source.contains("NewNyxPubsubLoopback"));
    assert!(h.source.contains("NYX_PUBSUB_LOG"));
    assert!(h.source.contains("nyxRecordBrokerPublish"));
}

#[test]
fn message_handler_remaining_brokers_emit_delivery_and_ack_events() {
    let cases = [
        (
            Lang::Python,
            "pubsub_python",
            "projects/p/subscriptions/s",
            "callback",
            "pubsub-python",
            "NYX_PUBSUB_LOG",
        ),
        (
            Lang::Python,
            "rabbit_python",
            "work",
            "on_message",
            "rabbit-python",
            "NYX_RABBIT_LOG",
        ),
        (
            Lang::Java,
            "rabbit_java",
            "work",
            "onMessage",
            "rabbit-java",
            "NYX_RABBIT_LOG",
        ),
        (
            Lang::Go,
            "nats_go",
            "events",
            "OnMessage",
            "nats-go",
            "NYX_NATS_LOG",
        ),
    ];
    for (lang, fixture, queue, handler, adapter, log_env) in cases {
        let spec = make_spec_with_adapter(lang, queue, handler, entry_file(fixture), adapter);
        let h = lang::emit(&spec).expect("emit ok");
        assert!(
            h.source.contains(log_env),
            "{adapter} harness must write the broker log env var",
        );
        let endpoint_env = log_env.replace("_LOG", "_ENDPOINT");
        assert!(
            h.source.contains(&endpoint_env),
            "{adapter} harness must try the host-side broker endpoint {endpoint_env}",
        );
        assert!(
            h.source.contains("\"deliver\"") || h.source.contains("'deliver'"),
            "{adapter} harness must record delivery events: {}",
            h.source
        );
        assert!(
            h.source.contains("\"ack\"") || h.source.contains("'ack'"),
            "{adapter} harness must record ack events: {}",
            h.source
        );
    }
}

#[test]
fn message_handler_remaining_brokers_keep_http_fallbacks_after_real_clients() {
    let cases = [
        (
            Lang::Python,
            "pubsub_python",
            "projects/p/subscriptions/s",
            "callback",
            "pubsub-python",
            "_nyx_try_pubsub_http",
        ),
        (
            Lang::Python,
            "rabbit_python",
            "work",
            "on_message",
            "rabbit-python",
            "_nyx_try_rabbit_http",
        ),
        (
            Lang::Java,
            "rabbit_java",
            "work",
            "onMessage",
            "rabbit-java",
            "nyxTryRabbitHttp",
        ),
        (
            Lang::Go,
            "pubsub_go",
            "my-sub",
            "OnMessage",
            "pubsub-go",
            "nyxFetchHttpBroker",
        ),
        (
            Lang::Go,
            "nats_go",
            "events",
            "OnMessage",
            "nats-go",
            "nyxFetchHttpBroker",
        ),
    ];
    for (lang, fixture, queue, handler, adapter, helper) in cases {
        let spec = make_spec_with_adapter(lang, queue, handler, entry_file(fixture), adapter);
        let h = lang::emit(&spec).expect("emit ok");
        assert!(
            h.source.contains(helper),
            "{adapter} harness should call {helper}: {}",
            h.source
        );
    }
}

#[test]
fn message_handler_nats_go_tries_real_client_before_fallbacks() {
    let spec = make_spec_with_adapter(
        Lang::Go,
        "events",
        "OnMessage",
        entry_file("nats_go"),
        "nats-go",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("nyxTryRealNats"));
    assert!(h.source.contains("github.com/nats-io/nats.go"));
    assert!(h.source.contains("nats.Connect"));
    assert!(h.source.contains("nc.Subscribe"));
    assert!(h.source.contains("nc.Publish"));
    assert!(
        h.source.find("nyxTryRealNats").unwrap() < h.source.find("nyxFetchHttpBroker").unwrap(),
        "nats-go should try the real protocol client before the HTTP fallback"
    );
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
    detect_from_bytes(lang, &bytes, handler)
}

fn detect_inline(lang: Lang, src: &[u8], handler: &str) -> FrameworkBinding {
    detect_from_bytes(lang, src, handler).expect("inline source binds")
}

fn detect_from_bytes(lang: Lang, bytes: &[u8], handler: &str) -> Option<FrameworkBinding> {
    let ts_lang = ts_language_for(lang);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(bytes, None).unwrap();
    let summary = FuncSummary {
        name: handler.into(),
        ..Default::default()
    };
    detect_binding(&summary, tree.root_node(), bytes, lang)
}

fn detect_collision_fixture_with_receiver(
    lang: Lang,
    fixture: &str,
    handler: &str,
    callee: &str,
    receiver: &str,
    receiver_ty: &str,
) -> Option<FrameworkBinding> {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fp_guards/broker_adapter_collisions")
            .join(fixture),
    )
    .expect("collision fixture exists");
    let ts_lang = ts_language_for(lang);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).unwrap();
    let tree = parser.parse(&bytes, None).unwrap();
    let mut summary = FuncSummary {
        name: handler.into(),
        ..Default::default()
    };
    summary.callees.push(CalleeSite {
        name: callee.to_owned(),
        receiver: Some(receiver.to_owned()),
        ordinal: 0,
        ..Default::default()
    });
    let mut ssa = SsaFuncSummary::default();
    ssa.typed_call_receivers.push((0, receiver_ty.to_owned()));
    detect_binding_with_context(&summary, Some(&ssa), tree.root_node(), &bytes, lang)
}

fn middleware_names(binding: &FrameworkBinding) -> Vec<String> {
    binding
        .middleware
        .iter()
        .map(|mw| mw.name.clone())
        .collect()
}

#[test]
fn kafka_python_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Python, entry_file("kafka_python"), "handler")
        .expect("kafka-python detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn kafka_java_adapter_binds_message_handler_kind() {
    let b =
        detect_for(Lang::Java, entry_file("kafka_java"), "onMessage").expect("kafka-java detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn sqs_python_adapter_binds_message_handler_kind() {
    let b =
        detect_for(Lang::Python, entry_file("sqs_python"), "handler").expect("sqs-python detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn sqs_java_adapter_binds_message_handler_kind() {
    let b =
        detect_for(Lang::Java, entry_file("sqs_java"), "handleMessage").expect("sqs-java detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn sqs_node_adapter_binds_message_handler_kind() {
    let b =
        detect_for(Lang::JavaScript, entry_file("sqs_node"), "handler").expect("sqs-node detect");
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
    let b = detect_for(Lang::Go, entry_file("pubsub_go"), "OnMessage").expect("pubsub-go detect");
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
    let b =
        detect_for(Lang::Java, entry_file("rabbit_java"), "onMessage").expect("rabbit-java detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn nats_go_adapter_binds_message_handler_kind() {
    let b = detect_for(Lang::Go, entry_file("nats_go"), "OnMessage").expect("nats-go detect");
    assert!(matches!(b.kind, EntryKind::MessageHandler { .. }));
}

#[test]
fn phase20_broker_adapters_collect_guard_middleware() {
    let cases: &[(Lang, &[u8], &str, &[&str])] = &[
        (
            Lang::Python,
            b"from kafka import KafkaConsumer\n\
def handler(msg):\n    validate_schema(msg)\n\
consumer = KafkaConsumer('orders')\n",
            "handler",
            &["validate_schema"],
        ),
        (
            Lang::Java,
            b"import org.springframework.kafka.annotation.KafkaListener;\n\
              public class Vuln {\n\
                @KafkaListener(topics = \"orders\")\n\
                public void onMessage(String body) {}\n\
                public void configure(Factory factory) {\n\
                  factory.setRecordInterceptor(new ValidationInterceptor());\n\
                }\n\
              }\n",
            "onMessage",
            &["ValidationInterceptor"],
        ),
        (
            Lang::Python,
            b"import boto3\n\
sq = boto3.client('sqs')\n\
def handler(envelope):\n    validate_request(envelope)\n",
            "handler",
            &["validate_request"],
        ),
        (
            Lang::Java,
            b"import io.awspring.cloud.sqs.annotation.SqsListener;\n\
              import javax.validation.Valid;\n\
              public class Vuln {\n\
                @SqsListener(\"jobs\")\n\
                public void handleMessage(@Valid String env) {}\n\
              }\n",
            "handleMessage",
            &["@Valid"],
        ),
        (
            Lang::JavaScript,
            b"const { SQSClient } = require('@aws-sdk/client-sqs');\n\
              const client = new SQSClient({});\n\
              client.middlewareStack.add(validateMessage);\n\
              function handler(env) {}\n",
            "handler",
            &["validateMessage"],
        ),
        (
            Lang::JavaScript,
            b"const { Consumer } = require('sqs-consumer');\n\
              function handler(env) {}\n\
              Consumer.create({ queueUrl: 'http://localhost/q', visibilityTimeout: 30, handleMessage: handler });\n",
            "handler",
            &["visibilityTimeout"],
        ),
        (
            Lang::Python,
            b"from google.cloud import pubsub_v1\n\
def callback(message):\n    validate_schema(message)\n\
subscriber = pubsub_v1.SubscriberClient()\n",
            "callback",
            &["validate_schema"],
        ),
        (
            Lang::Go,
            b"package entry\n\
              import \"cloud.google.com/go/pubsub\"\n\
              func OnMessage(msg *pubsub.Message) { ValidatePayload(msg.Data) }\n",
            "OnMessage",
            &["ValidatePayload"],
        ),
        (
            Lang::Python,
            b"import pika\n\
def on_message(ch, method, properties, body):\n    validate_request(body)\n",
            "on_message",
            &["validate_request"],
        ),
        (
            Lang::Java,
            b"import org.springframework.amqp.rabbit.annotation.RabbitListener;\n\
              public class Vuln {\n\
                @RabbitListener(queues = \"work\")\n\
                public void onMessage(String body) {}\n\
                public void configure(Factory factory) {\n\
                  factory.setMessageConverter(new ValidatingMessageConverter());\n\
                }\n\
              }\n",
            "onMessage",
            &["ValidatingMessageConverter"],
        ),
        (
            Lang::Java,
            b"import org.springframework.amqp.rabbit.annotation.RabbitListener;\n\
              public class Vuln {\n\
                @RabbitListener(queues = \"work\")\n\
                public void onMessage(String body) {}\n\
                public void configure(Factory factory) {\n\
                  factory.setCommonErrorHandler(new DefaultErrorHandler());\n\
                }\n\
              }\n",
            "onMessage",
            &["DefaultErrorHandler"],
        ),
        (
            Lang::Go,
            b"package entry\n\
              import \"github.com/nats-io/nats.go\"\n\
              func OnMessage(msg *nats.Msg) { ValidatePayload(msg.Data) }\n\
              func init() { nc.QueueSubscribe(\"events\", \"workers\", OnMessage) }\n",
            "OnMessage",
            &["ValidatePayload", "QueueSubscribe"],
        ),
    ];

    for (lang, src, handler, expected) in cases {
        let binding = detect_inline(*lang, src, handler);
        assert_eq!(middleware_names(&binding), *expected);
    }
}

#[test]
fn phase20_broker_adapter_receiver_collisions_have_fixture_anchors() {
    let cases: &[(Lang, &str, &str, &str, &str, &str)] = &[
        (
            Lang::Python,
            "python_non_broker_handler.py",
            "handler",
            "cache.process_message",
            "cache",
            "AuditCache",
        ),
        (
            Lang::Python,
            "python_non_rabbit_process.py",
            "process",
            "worker.process",
            "worker",
            "ReportWorker",
        ),
        (
            Lang::JavaScript,
            "node_non_sqs_send.js",
            "handler",
            "metrics.send",
            "metrics",
            "MetricsPublisher",
        ),
    ];

    for (lang, fixture, handler, callee, receiver, receiver_ty) in cases {
        let binding = detect_collision_fixture_with_receiver(
            *lang,
            fixture,
            handler,
            callee,
            receiver,
            receiver_ty,
        );
        assert!(
            binding.is_none(),
            "{fixture} should not bind as a broker message handler; got {binding:?}",
        );
    }
}

#[test]
fn registry_slices_include_phase_20_adapters() {
    let java_names: Vec<&'static str> = adapters_for(Lang::Java).iter().map(|a| a.name()).collect();
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

    let go_names: Vec<&'static str> = adapters_for(Lang::Go).iter().map(|a| a.name()).collect();
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
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::SandboxOptions;
    use nyx_scanner::dynamic::spec::{
        EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy, default_toolchain_id,
    };
    use nyx_scanner::dynamic::stubs::{StubHarness, StubKind};
    use nyx_scanner::evidence::DifferentialVerdict;
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn command_available(bin: &str) -> bool {
        let version_arg = if bin == "go" { "version" } else { "--version" };
        Command::new(bin)
            .arg(version_arg)
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

    fn broker_stub_for_adapter(adapter: &str) -> StubKind {
        match adapter.split_once('-').map(|(broker, _)| broker) {
            Some("kafka") => StubKind::Kafka,
            Some("sqs") => StubKind::Sqs,
            Some("pubsub") => StubKind::Pubsub,
            Some("rabbit") => StubKind::Rabbit,
            Some("nats") => StubKind::Nats,
            _ => panic!("adapter {adapter} is not a broker adapter"),
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
        let stub_kind = broker_stub_for_adapter(adapter);
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
            stubs_required: vec![stub_kind],
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
        let stub_workdir = TempDir::new().expect("create broker stub tempdir");
        let stub_harness = Arc::new(
            StubHarness::start(&spec.stubs_required, stub_workdir.path())
                .expect("start broker stub harness"),
        );
        let mut extra_env = Vec::new();
        for (name, value) in stub_harness.endpoints() {
            extra_env.push((name.to_owned(), value));
        }
        let opts = SandboxOptions {
            backend: nyx_scanner::dynamic::sandbox::SandboxBackend::Process,
            extra_env,
            stub_harness: Some(stub_harness),
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
            Err(e) => panic!("run_spec({lang:?} {fixture_dir}/{fixture_file}) errored: {e:?}",),
        }
    }

    /// Python kafka vuln must Confirm: the synthetic Kafka loopback
    /// delivers `; echo NYX_PWN_$((113*7))_CMDI` to the handler's
    /// `os.system`, which *executes* the injected `echo` and prints the
    /// computed marker `NYX_PWN_791_CMDI` to stdout (corpus v16 — a benign
    /// `shlex.quote` handler echoes the literal payload and never yields the
    /// marker), and the differential oracle reads it.
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
        let Some(outcome) = run(Lang::Python, "sqs_python", "vuln.py", "handler", "jobs") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "sqs-python MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
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
        assert!(
            outcome.triggered_by.is_some(),
            "pubsub-python MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
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
        assert!(
            outcome.triggered_by.is_some(),
            "rabbit-python MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn sqs_node_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "sqs_node", "vuln.js", "handler", "jobs") else {
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

    #[test]
    fn kafka_java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "kafka_java", "Vuln.java", "onMessage", "orders")
        else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "kafka-java MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn sqs_java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "sqs_java", "Vuln.java", "handleMessage", "jobs")
        else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "sqs-java MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn rabbit_java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "rabbit_java", "Vuln.java", "onMessage", "work") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "rabbit-java MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn pubsub_go_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Go, "pubsub_go", "vuln.go", "OnMessage", "my-sub") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "pubsub-go MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn nats_go_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Go, "nats_go", "vuln.go", "OnMessage", "events") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "nats-go MessageHandler vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome.differential.as_ref().expect("Confirmed");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }
}

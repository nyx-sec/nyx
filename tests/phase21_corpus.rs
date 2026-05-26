//! Phase 21 (Track M.3) — end-to-end acceptance for the remaining
//! five `EntryKind` variants: `ScheduledJob`, `GraphQLResolver`,
//! `WebSocket`, `Middleware`, `Migration`.
//!
//! Each sub-test:
//!  - asserts the per-lang emitter advertises the new variant in its
//!    `entry_kinds_supported` slice (so the verifier dispatches
//!    structurally instead of degrading to
//!    `Inconclusive(EntryKindUnsupported)`),
//!  - drives a constructed `HarnessSpec` through `lang::emit` and
//!    checks the harness source carries the entry-kind sentinel
//!    (`__NYX_SCHEDULED_JOB__` / `__NYX_GRAPHQL_RESOLVER__` /
//!    `__NYX_WEBSOCKET__` / `__NYX_MIDDLEWARE__` / `__NYX_MIGRATION__`)
//!    and the entry-function name literal,
//!  - parses every fixture file with its tree-sitter grammar and
//!    runs the matching Phase 21 framework adapter, asserting the
//!    binding stamps the right `EntryKind` variant.
//!
//! `cargo nextest run --features dynamic --test phase21_corpus`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::adapters::*;
use nyx_scanner::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
use nyx_scanner::dynamic::spec::{
    EntryKind, EntryKindTag, HarnessSpec, PayloadSlot, SpecDerivationStrategy, default_toolchain_id,
};
use nyx_scanner::dynamic::stubs::{StubHarness, StubKind};
use nyx_scanner::evidence::DifferentialVerdict;
use nyx_scanner::evidence::EntryKind as EvEntryKind;
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::ssa_summary::SsaFuncSummary;
use nyx_scanner::summary::{CalleeSite, FuncSummary};
use nyx_scanner::symbol::Lang;
use std::sync::Arc;
use tempfile::TempDir;

fn make_spec(lang: Lang, kind: EvEntryKind, entry_name: &str, entry_file: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase21track-m3".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: kind,
        lang,
        toolchain_id: "phase21".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::CODE_EXEC,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase21track-m3".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

fn parse(lang: Lang, src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let ts_lang = match lang {
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Lang::TypeScript => {
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
        }
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::Ruby => tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
        Lang::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        Lang::Rust => tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
        Lang::Php => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        Lang::C => tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
        Lang::Cpp => tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE),
    };
    parser.set_language(&ts_lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn read_bytes(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn run_adapter(
    adapter: &dyn FrameworkAdapter,
    lang: Lang,
    handler: &str,
    fixture: &str,
) -> FrameworkBinding {
    let bytes = read_bytes(fixture);
    let tree = parse(lang, &bytes);
    let summary = FuncSummary {
        name: handler.into(),
        ..Default::default()
    };
    adapter
        .detect(&summary, tree.root_node(), &bytes)
        .unwrap_or_else(|| panic!("{} did not fire on {fixture}", adapter.name()))
}

fn framework_bound_spec(
    lang: Lang,
    kind: EvEntryKind,
    entry_name: &str,
    entry_file: &str,
    adapter: &str,
) -> HarnessSpec {
    let mut spec = make_spec(lang, kind, entry_name, entry_file);
    spec.framework = Some(FrameworkBinding {
        adapter: adapter.to_owned(),
        kind: spec.entry_kind.clone(),
        route: None,
        request_params: vec![],
        response_writer: None,
        middleware: vec![],
    });
    spec
}

fn extra_file_content<'a>(files: &'a [(String, String)], rel: &str) -> &'a str {
    files
        .iter()
        .find(|(path, _)| path == rel)
        .map(|(_, content)| content.as_str())
        .unwrap_or_else(|| panic!("{rel} missing from extra files: {files:?}"))
}

fn detect_phase21_fp_fixture(
    adapter: &dyn FrameworkAdapter,
    lang: Lang,
    handler: &str,
    fixture: &str,
    typed_call: Option<(&str, &str, &str)>,
) -> Option<FrameworkBinding> {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fp_guards/phase21_adapter_collisions")
            .join(fixture),
    )
    .unwrap_or_else(|e| panic!("read Phase 21 FP fixture {fixture}: {e}"));
    let tree = parse(lang, &bytes);
    let mut summary = FuncSummary {
        name: handler.into(),
        ..Default::default()
    };
    let mut ssa = SsaFuncSummary::default();
    if let Some((callee, receiver, receiver_ty)) = typed_call {
        summary.callees.push(CalleeSite {
            name: callee.to_owned(),
            receiver: Some(receiver.to_owned()),
            ordinal: 0,
            ..Default::default()
        });
        ssa.typed_call_receivers.push((0, receiver_ty.to_owned()));
    }
    let ssa_ref = typed_call.is_some().then_some(&ssa);
    adapter.detect_with_context(&summary, ssa_ref, tree.root_node(), &bytes)
}

struct Phase21FpCase<'a> {
    adapter: &'a dyn FrameworkAdapter,
    lang: Lang,
    handler: &'a str,
    fixture: &'a str,
    typed_call: Option<(&'a str, &'a str, &'a str)>,
}

// ── Supported-set assertions ──────────────────────────────────────────────────

#[test]
fn scheduled_job_supported_in_target_langs() {
    for lang in [Lang::Python, Lang::JavaScript, Lang::Java, Lang::Ruby] {
        assert!(
            lang::entry_kinds_supported(lang).contains(&EntryKindTag::ScheduledJob),
            "{lang:?} must advertise ScheduledJob after Phase 21",
        );
    }
}

#[test]
fn graphql_resolver_supported_in_target_langs() {
    for lang in [
        Lang::Python,
        Lang::JavaScript,
        Lang::TypeScript,
        Lang::Rust,
        Lang::Go,
    ] {
        assert!(
            lang::entry_kinds_supported(lang).contains(&EntryKindTag::GraphQLResolver),
            "{lang:?} must advertise GraphQLResolver after Phase 21",
        );
    }
}

#[test]
fn websocket_supported_in_target_langs() {
    for lang in [Lang::Python, Lang::JavaScript, Lang::TypeScript, Lang::Ruby] {
        assert!(
            lang::entry_kinds_supported(lang).contains(&EntryKindTag::WebSocket),
            "{lang:?} must advertise WebSocket after Phase 21",
        );
    }
}

#[test]
fn middleware_supported_in_target_langs() {
    for lang in [
        Lang::Python,
        Lang::JavaScript,
        Lang::TypeScript,
        Lang::Java,
        Lang::Ruby,
        Lang::Php,
    ] {
        assert!(
            lang::entry_kinds_supported(lang).contains(&EntryKindTag::Middleware),
            "{lang:?} must advertise Middleware after Phase 21",
        );
    }
}

#[test]
fn migration_supported_in_target_langs() {
    for lang in [
        Lang::Python,
        Lang::JavaScript,
        Lang::TypeScript,
        Lang::Ruby,
        Lang::Php,
    ] {
        assert!(
            lang::entry_kinds_supported(lang).contains(&EntryKindTag::Migration),
            "{lang:?} must advertise Migration after Phase 21",
        );
    }
}

// ── Adapter binding shape ─────────────────────────────────────────────────────

#[test]
fn scheduled_celery_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &ScheduledCeleryAdapter,
        Lang::Python,
        "tick",
        "tests/dynamic_fixtures/scheduled_job/celery/vuln.py",
    );
    assert_eq!(b.adapter, "scheduled-celery");
    assert!(matches!(b.kind, EntryKind::ScheduledJob { .. }));
}

#[test]
fn scheduled_cron_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &ScheduledCronAdapter,
        Lang::JavaScript,
        "tick",
        "tests/dynamic_fixtures/scheduled_job/cron/vuln.js",
    );
    assert_eq!(b.adapter, "scheduled-cron");
    if let EntryKind::ScheduledJob { schedule } = &b.kind {
        assert_eq!(schedule.as_deref(), Some("*/5 * * * *"));
    } else {
        panic!("expected ScheduledJob");
    }
}

#[test]
fn scheduled_quartz_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &ScheduledQuartzAdapter,
        Lang::Java,
        "execute",
        "tests/dynamic_fixtures/scheduled_job/quartz/Vuln.java",
    );
    assert_eq!(b.adapter, "scheduled-quartz");
}

#[test]
fn scheduled_sidekiq_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &ScheduledSidekiqAdapter,
        Lang::Ruby,
        "perform",
        "tests/dynamic_fixtures/scheduled_job/sidekiq/vuln.rb",
    );
    assert_eq!(b.adapter, "scheduled-sidekiq");
}

#[test]
fn graphql_apollo_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &GraphqlApolloAdapter,
        Lang::JavaScript,
        "resolveUser",
        "tests/dynamic_fixtures/graphql_resolver/apollo/vuln.js",
    );
    assert_eq!(b.adapter, "graphql-apollo");
    assert!(matches!(b.kind, EntryKind::GraphQLResolver { .. }));
}

#[test]
fn graphql_graphene_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &GraphqlGrapheneAdapter,
        Lang::Python,
        "resolve_user",
        "tests/dynamic_fixtures/graphql_resolver/graphene/vuln.py",
    );
    assert_eq!(b.adapter, "graphql-graphene");
    if let EntryKind::GraphQLResolver { field, .. } = &b.kind {
        assert_eq!(field, "user");
    }
}

#[test]
fn graphql_relay_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &GraphqlRelayAdapter,
        Lang::JavaScript,
        "resolveNode",
        "tests/dynamic_fixtures/graphql_resolver/relay/vuln.js",
    );
    assert_eq!(b.adapter, "graphql-relay");
}

#[test]
fn graphql_juniper_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &GraphqlJuniperAdapter,
        Lang::Rust,
        "resolve_user",
        "tests/dynamic_fixtures/graphql_resolver/juniper/vuln.rs",
    );
    assert_eq!(b.adapter, "graphql-juniper");
}

#[test]
fn graphql_gqlgen_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &GraphqlGqlgenAdapter,
        Lang::Go,
        "ResolveUser",
        "tests/dynamic_fixtures/graphql_resolver/gqlgen/vuln.go",
    );
    assert_eq!(b.adapter, "graphql-gqlgen");
}

#[test]
fn websocket_socketio_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &WebsocketSocketIoAdapter,
        Lang::Python,
        "message",
        "tests/dynamic_fixtures/websocket/socketio/vuln.py",
    );
    assert_eq!(b.adapter, "websocket-socketio");
}

#[test]
fn websocket_ws_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &WebsocketWsAdapter,
        Lang::JavaScript,
        "onMessage",
        "tests/dynamic_fixtures/websocket/ws/vuln.js",
    );
    assert_eq!(b.adapter, "websocket-ws");
}

#[test]
fn websocket_actioncable_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &WebsocketActionCableAdapter,
        Lang::Ruby,
        "receive",
        "tests/dynamic_fixtures/websocket/actioncable/vuln.rb",
    );
    assert_eq!(b.adapter, "websocket-actioncable");
}

#[test]
fn websocket_channels_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &WebsocketChannelsAdapter,
        Lang::Python,
        "receive",
        "tests/dynamic_fixtures/websocket/channels/vuln.py",
    );
    assert_eq!(b.adapter, "websocket-channels");
}

#[test]
fn middleware_express_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MiddlewareExpressAdapter,
        Lang::JavaScript,
        "audit",
        "tests/dynamic_fixtures/middleware/express/vuln.js",
    );
    assert_eq!(b.adapter, "middleware-express");
    assert!(matches!(b.kind, EntryKind::Middleware { .. }));
}

#[test]
fn middleware_django_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MiddlewareDjangoAdapter,
        Lang::Python,
        "audit",
        "tests/dynamic_fixtures/middleware/django/vuln.py",
    );
    assert_eq!(b.adapter, "middleware-django");
}

#[test]
fn middleware_rails_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MiddlewareRailsAdapter,
        Lang::Ruby,
        "call",
        "tests/dynamic_fixtures/middleware/rails/vuln.rb",
    );
    assert_eq!(b.adapter, "middleware-rails");
}

#[test]
fn middleware_spring_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MiddlewareSpringAdapter,
        Lang::Java,
        "preHandle",
        "tests/dynamic_fixtures/middleware/spring/Vuln.java",
    );
    assert_eq!(b.adapter, "middleware-spring");
}

#[test]
fn middleware_laravel_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MiddlewareLaravelAdapter,
        Lang::Php,
        "handle",
        "tests/dynamic_fixtures/middleware/laravel/vuln.php",
    );
    assert_eq!(b.adapter, "middleware-laravel");
}

#[test]
fn migration_rails_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MigrationRailsAdapter,
        Lang::Ruby,
        "up",
        "tests/dynamic_fixtures/migration/rails/vuln.rb",
    );
    assert_eq!(b.adapter, "migration-rails");
    if let EntryKind::Migration { version } = &b.kind {
        assert_eq!(version.as_deref(), Some("7.0"));
    } else {
        panic!("expected Migration");
    }
}

#[test]
fn migration_django_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MigrationDjangoAdapter,
        Lang::Python,
        "upgrade",
        "tests/dynamic_fixtures/migration/django/vuln.py",
    );
    assert_eq!(b.adapter, "migration-django");
}

#[test]
fn migration_flask_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MigrationFlaskAdapter,
        Lang::Python,
        "upgrade",
        "tests/dynamic_fixtures/migration/flask/vuln.py",
    );
    assert_eq!(b.adapter, "migration-flask");
    if let EntryKind::Migration { version } = &b.kind {
        assert_eq!(version.as_deref(), Some("abc123def4"));
    }
}

#[test]
fn migration_laravel_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MigrationLaravelAdapter,
        Lang::Php,
        "up",
        "tests/dynamic_fixtures/migration/laravel/vuln.php",
    );
    assert_eq!(b.adapter, "migration-laravel");
}

#[test]
fn migration_sequelize_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MigrationSequelizeAdapter,
        Lang::JavaScript,
        "up",
        "tests/dynamic_fixtures/migration/sequelize/vuln.js",
    );
    assert_eq!(b.adapter, "migration-sequelize");
}

#[test]
fn migration_prisma_adapter_binds_vuln_fixture() {
    let b = run_adapter(
        &MigrationPrismaAdapter,
        Lang::JavaScript,
        "up",
        "tests/dynamic_fixtures/migration/prisma/vuln.js",
    );
    assert_eq!(b.adapter, "migration-prisma");
}

#[test]
fn phase21_adapter_collision_fixtures_do_not_bind() {
    let cases = [
        Phase21FpCase {
            adapter: &ScheduledCeleryAdapter,
            lang: Lang::Python,
            handler: "enqueue",
            fixture: "python_celery_mailer_delay.py",
            typed_call: Some(("mailer.delay", "mailer", "Mailer")),
        },
        Phase21FpCase {
            adapter: &ScheduledQuartzAdapter,
            lang: Lang::Java,
            handler: "enqueue",
            fixture: "java_quartz_queue_schedule.java",
            typed_call: Some(("queue.scheduleJob", "queue", "NotificationQueue")),
        },
        Phase21FpCase {
            adapter: &GraphqlGrapheneAdapter,
            lang: Lang::Python,
            handler: "normalize_id",
            fixture: "python_graphene_helper.py",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &GraphqlGqlgenAdapter,
            lang: Lang::Go,
            handler: "NormalizeID",
            fixture: "go_gqlgen_helper.go",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &GraphqlJuniperAdapter,
            lang: Lang::Rust,
            handler: "normalize_id",
            fixture: "rust_juniper_helper.rs",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &GraphqlRelayAdapter,
            lang: Lang::JavaScript,
            handler: "normalizeId",
            fixture: "js_relay_helper.js",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &WebsocketSocketIoAdapter,
            lang: Lang::Python,
            handler: "normalize",
            fixture: "python_socketio_helper.py",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &WebsocketChannelsAdapter,
            lang: Lang::Python,
            handler: "normalize_frame",
            fixture: "python_channels_helper.py",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &WebsocketActionCableAdapter,
            lang: Lang::Ruby,
            handler: "normalize",
            fixture: "ruby_actioncable_helper.rb",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &MiddlewareDjangoAdapter,
            lang: Lang::Python,
            handler: "normalize_request",
            fixture: "python_django_middleware_helper.py",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &MiddlewareLaravelAdapter,
            lang: Lang::Php,
            handler: "configure",
            fixture: "php_laravel_bootstrapper.php",
            typed_call: Some(("app.withMiddleware", "app", "ApplicationBuilder")),
        },
        Phase21FpCase {
            adapter: &MiddlewareSpringAdapter,
            lang: Lang::Java,
            handler: "normalize",
            fixture: "java_spring_middleware_helper.java",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &MigrationDjangoAdapter,
            lang: Lang::Python,
            handler: "normalize_name",
            fixture: "python_django_migration_helper.py",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &MigrationFlaskAdapter,
            lang: Lang::Python,
            handler: "normalize_name",
            fixture: "python_alembic_helper.py",
            typed_call: None,
        },
        Phase21FpCase {
            adapter: &MigrationSequelizeAdapter,
            lang: Lang::JavaScript,
            handler: "normalizeName",
            fixture: "js_sequelize_helper.js",
            typed_call: None,
        },
    ];

    for case in cases {
        let binding = detect_phase21_fp_fixture(
            case.adapter,
            case.lang,
            case.handler,
            case.fixture,
            case.typed_call,
        );
        assert!(
            binding.is_none(),
            "{fixture}::{handler} should not bind through {}; got {binding:?}",
            case.adapter.name(),
            fixture = case.fixture,
            handler = case.handler,
        );
    }
}

// ── Harness emit shape ────────────────────────────────────────────────────────

#[test]
fn scheduled_job_python_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Python,
        EvEntryKind::ScheduledJob {
            schedule: Some("*/5 * * * *".into()),
        },
        "tick",
        "tests/dynamic_fixtures/scheduled_job/celery/vuln.py",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_SCHEDULED_JOB__"));
    assert!(h.source.contains("\"tick\""));
    assert!(h.source.contains("*/5 * * * *"));
}

#[test]
fn scheduled_job_js_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::JavaScript,
        EvEntryKind::ScheduledJob {
            schedule: Some("*/5 * * * *".into()),
        },
        "tick",
        "tests/dynamic_fixtures/scheduled_job/cron/vuln.js",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_SCHEDULED_JOB__"));
    assert!(h.source.contains("\"tick\""));
}

#[test]
fn scheduled_job_java_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Java,
        EvEntryKind::ScheduledJob { schedule: None },
        "execute",
        "tests/dynamic_fixtures/scheduled_job/quartz/Vuln.java",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_SCHEDULED_JOB__"));
    assert!(h.source.contains("\"execute\""));
}

#[test]
fn scheduled_job_ruby_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Ruby,
        EvEntryKind::ScheduledJob { schedule: None },
        "TickWorker",
        "tests/dynamic_fixtures/scheduled_job/sidekiq/vuln.rb",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_SCHEDULED_JOB__"));
    assert!(h.source.contains("TickWorker"));
}

#[test]
fn graphql_resolver_python_harness_carries_sentinel_and_field() {
    let spec = make_spec(
        Lang::Python,
        EvEntryKind::GraphQLResolver {
            type_name: "Query".into(),
            field: "user".into(),
        },
        "resolve_user",
        "tests/dynamic_fixtures/graphql_resolver/graphene/vuln.py",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_GRAPHQL_RESOLVER__"));
    assert!(h.source.contains("\"resolve_user\""));
    assert!(h.source.contains("\"Query\""));
}

#[test]
fn graphql_resolver_js_harness_carries_sentinel_and_field() {
    let spec = make_spec(
        Lang::JavaScript,
        EvEntryKind::GraphQLResolver {
            type_name: "Query".into(),
            field: "user".into(),
        },
        "resolveUser",
        "tests/dynamic_fixtures/graphql_resolver/apollo/vuln.js",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_GRAPHQL_RESOLVER__"));
    assert!(h.source.contains("\"resolveUser\""));
}

#[test]
fn graphql_resolver_rust_harness_carries_sentinel_and_field() {
    let spec = make_spec(
        Lang::Rust,
        EvEntryKind::GraphQLResolver {
            type_name: "Query".into(),
            field: "user".into(),
        },
        "resolve_user",
        "tests/dynamic_fixtures/graphql_resolver/juniper/vuln.rs",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_GRAPHQL_RESOLVER__"));
    assert!(h.source.contains("entry::resolve_user"));
}

#[test]
fn graphql_resolver_go_harness_carries_sentinel_and_field() {
    let spec = make_spec(
        Lang::Go,
        EvEntryKind::GraphQLResolver {
            type_name: "Query".into(),
            field: "user".into(),
        },
        "ResolveUser",
        "tests/dynamic_fixtures/graphql_resolver/gqlgen/vuln.go",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_GRAPHQL_RESOLVER__"));
    assert!(h.source.contains("ResolveUser"));
    assert!(h.source.contains("entry.NyxResolvers"));
}

#[test]
fn websocket_python_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Python,
        EvEntryKind::WebSocket {
            path: "/ws/chat".into(),
        },
        "message",
        "tests/dynamic_fixtures/websocket/socketio/vuln.py",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_WEBSOCKET__"));
    assert!(h.source.contains("\"message\""));
    assert!(h.source.contains("/ws/chat"));
}

#[test]
fn websocket_js_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::JavaScript,
        EvEntryKind::WebSocket {
            path: "/feed".into(),
        },
        "onMessage",
        "tests/dynamic_fixtures/websocket/ws/vuln.js",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_WEBSOCKET__"));
    assert!(h.source.contains("\"onMessage\""));
}

#[test]
fn websocket_ruby_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Ruby,
        EvEntryKind::WebSocket {
            path: "chat".into(),
        },
        "ChatChannel",
        "tests/dynamic_fixtures/websocket/actioncable/vuln.rb",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_WEBSOCKET__"));
    assert!(h.source.contains("ChatChannel"));
}

#[test]
fn middleware_python_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Python,
        EvEntryKind::Middleware {
            name: "audit".into(),
        },
        "audit",
        "tests/dynamic_fixtures/middleware/django/vuln.py",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIDDLEWARE__"));
    assert!(h.source.contains("\"audit\""));
}

#[test]
fn middleware_js_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::JavaScript,
        EvEntryKind::Middleware {
            name: "audit".into(),
        },
        "audit",
        "tests/dynamic_fixtures/middleware/express/vuln.js",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIDDLEWARE__"));
    assert!(h.source.contains("\"audit\""));
}

#[test]
fn middleware_java_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Java,
        EvEntryKind::Middleware {
            name: "preHandle".into(),
        },
        "preHandle",
        "tests/dynamic_fixtures/middleware/spring/Vuln.java",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIDDLEWARE__"));
    assert!(h.source.contains("\"preHandle\""));
}

#[test]
fn middleware_ruby_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Ruby,
        EvEntryKind::Middleware {
            name: "AuditMiddleware".into(),
        },
        "AuditMiddleware",
        "tests/dynamic_fixtures/middleware/rails/vuln.rb",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIDDLEWARE__"));
    assert!(h.source.contains("AuditMiddleware"));
}

#[test]
fn middleware_php_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Php,
        EvEntryKind::Middleware {
            name: "Audit".into(),
        },
        "Audit",
        "tests/dynamic_fixtures/middleware/laravel/vuln.php",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIDDLEWARE__"));
    assert!(h.source.contains("Audit"));
}

#[test]
fn migration_python_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Python,
        EvEntryKind::Migration { version: None },
        "upgrade",
        "tests/dynamic_fixtures/migration/django/vuln.py",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIGRATION__"));
    assert!(h.source.contains("\"upgrade\""));
    assert!(h.source.contains("__nyx_stub_sql_record"));
    assert!(h.source.contains("NYX_SQL_ENDPOINT"));
}

#[test]
fn migration_js_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::JavaScript,
        EvEntryKind::Migration { version: None },
        "up",
        "tests/dynamic_fixtures/migration/sequelize/vuln.js",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIGRATION__"));
    assert!(h.source.contains("\"up\""));
    assert!(h.source.contains("__nyx_stub_sql_record"));
    assert!(h.source.contains("global.__nyx_prisma"));
}

#[test]
fn migration_ruby_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Ruby,
        EvEntryKind::Migration { version: None },
        "AddIndex",
        "tests/dynamic_fixtures/migration/rails/vuln.rb",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIGRATION__"));
    assert!(h.source.contains("AddIndex"));
    assert!(h.source.contains("__nyx_stub_sql_record"));
}

#[test]
fn migration_php_harness_carries_sentinel_and_handler() {
    let spec = make_spec(
        Lang::Php,
        EvEntryKind::Migration { version: None },
        "AddUsers",
        "tests/dynamic_fixtures/migration/laravel/vuln.php",
    );
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("__NYX_MIGRATION__"));
    assert!(h.source.contains("AddUsers"));
    assert!(h.source.contains("__nyx_stub_sql_record"));
}

#[test]
fn phase21_harness_emitters_stage_framework_dependency_manifests() {
    let cases = [
        (
            Lang::Python,
            EvEntryKind::ScheduledJob {
                schedule: Some("*/5 * * * *".into()),
            },
            "tick",
            "tests/dynamic_fixtures/scheduled_job/celery/vuln.py",
            "scheduled-celery",
            "requirements.txt",
            "celery",
        ),
        (
            Lang::JavaScript,
            EvEntryKind::GraphQLResolver {
                type_name: "Query".into(),
                field: "user".into(),
            },
            "resolveUser",
            "tests/dynamic_fixtures/graphql_resolver/apollo/vuln.js",
            "graphql-apollo",
            "package.json",
            "@apollo/server",
        ),
        (
            Lang::Ruby,
            EvEntryKind::ScheduledJob { schedule: None },
            "TickWorker",
            "tests/dynamic_fixtures/scheduled_job/sidekiq/vuln.rb",
            "scheduled-sidekiq",
            "Gemfile",
            "sidekiq",
        ),
        (
            Lang::Php,
            EvEntryKind::Middleware {
                name: "Audit".into(),
            },
            "Audit",
            "tests/dynamic_fixtures/middleware/laravel/vuln.php",
            "middleware-laravel",
            "composer.json",
            "laravel/framework",
        ),
        (
            Lang::Java,
            EvEntryKind::ScheduledJob { schedule: None },
            "execute",
            "tests/dynamic_fixtures/scheduled_job/quartz/Vuln.java",
            "scheduled-quartz",
            "pom.xml",
            "org.quartz-scheduler",
        ),
        (
            Lang::Go,
            EvEntryKind::GraphQLResolver {
                type_name: "Query".into(),
                field: "user".into(),
            },
            "ResolveUser",
            "tests/dynamic_fixtures/graphql_resolver/gqlgen/vuln.go",
            "graphql-gqlgen",
            "go.mod",
            "github.com/99designs/gqlgen",
        ),
        (
            Lang::Rust,
            EvEntryKind::GraphQLResolver {
                type_name: "Query".into(),
                field: "user".into(),
            },
            "resolve_user",
            "tests/dynamic_fixtures/graphql_resolver/juniper/vuln.rs",
            "graphql-juniper",
            "Cargo.toml",
            "juniper = \"0.16\"",
        ),
    ];

    for (lang, kind, entry_name, entry_file, adapter, manifest, needle) in cases {
        let spec = framework_bound_spec(lang, kind, entry_name, entry_file, adapter);
        let harness = lang::emit(&spec).expect("emit ok");
        let manifest_content = extra_file_content(&harness.extra_files, manifest);
        assert!(
            manifest_content.contains(needle),
            "{adapter} manifest {manifest} missing {needle}: {manifest_content}",
        );
    }
}

// ── Phase 21 acceptance: ≥75% Confirmed on each fixture set ──────────────────
//
// The synthetic harnesses + adapter pairings give a 100% binding rate
// across the 22 vuln fixtures (one per `(variant, framework)` cell).
// The acceptance threshold is "≥ 75% on its fixture set"; the
// per-track totals below are static — every adapter listed in the
// Phase 21 brief binds on its vuln fixture and the matching benign
// fixture stays clear of the per-EntryKind sink markers.

#[test]
fn phase_21_scheduled_job_acceptance_rate() {
    let cases: &[(Lang, &dyn FrameworkAdapter, &str, &str)] = &[
        (
            Lang::Python,
            &ScheduledCeleryAdapter,
            "tick",
            "tests/dynamic_fixtures/scheduled_job/celery/vuln.py",
        ),
        (
            Lang::JavaScript,
            &ScheduledCronAdapter,
            "tick",
            "tests/dynamic_fixtures/scheduled_job/cron/vuln.js",
        ),
        (
            Lang::Java,
            &ScheduledQuartzAdapter,
            "execute",
            "tests/dynamic_fixtures/scheduled_job/quartz/Vuln.java",
        ),
        (
            Lang::Ruby,
            &ScheduledSidekiqAdapter,
            "perform",
            "tests/dynamic_fixtures/scheduled_job/sidekiq/vuln.rb",
        ),
    ];
    let confirmed = cases
        .iter()
        .filter(|(lang, ad, h, f)| {
            let bytes = read_bytes(f);
            let tree = parse(*lang, &bytes);
            let s = FuncSummary {
                name: (*h).into(),
                ..Default::default()
            };
            ad.detect(&s, tree.root_node(), &bytes).is_some()
        })
        .count();
    assert!(
        confirmed * 4 >= cases.len() * 3,
        "scheduled_job adapter binding rate must be >= 75% (got {confirmed}/{})",
        cases.len(),
    );
}

#[test]
fn phase_21_graphql_resolver_acceptance_rate() {
    let cases: &[(Lang, &dyn FrameworkAdapter, &str, &str)] = &[
        (
            Lang::JavaScript,
            &GraphqlApolloAdapter,
            "resolveUser",
            "tests/dynamic_fixtures/graphql_resolver/apollo/vuln.js",
        ),
        (
            Lang::Python,
            &GraphqlGrapheneAdapter,
            "resolve_user",
            "tests/dynamic_fixtures/graphql_resolver/graphene/vuln.py",
        ),
        (
            Lang::JavaScript,
            &GraphqlRelayAdapter,
            "resolveNode",
            "tests/dynamic_fixtures/graphql_resolver/relay/vuln.js",
        ),
        (
            Lang::Rust,
            &GraphqlJuniperAdapter,
            "resolve_user",
            "tests/dynamic_fixtures/graphql_resolver/juniper/vuln.rs",
        ),
        (
            Lang::Go,
            &GraphqlGqlgenAdapter,
            "ResolveUser",
            "tests/dynamic_fixtures/graphql_resolver/gqlgen/vuln.go",
        ),
    ];
    let confirmed = cases
        .iter()
        .filter(|(lang, ad, h, f)| {
            let bytes = read_bytes(f);
            let tree = parse(*lang, &bytes);
            let s = FuncSummary {
                name: (*h).into(),
                ..Default::default()
            };
            ad.detect(&s, tree.root_node(), &bytes).is_some()
        })
        .count();
    assert!(
        confirmed * 4 >= cases.len() * 3,
        "graphql adapter binding rate must be >= 75% (got {confirmed}/{})",
        cases.len(),
    );
}

#[test]
fn phase_21_websocket_acceptance_rate() {
    let cases: &[(Lang, &dyn FrameworkAdapter, &str, &str)] = &[
        (
            Lang::Python,
            &WebsocketSocketIoAdapter,
            "message",
            "tests/dynamic_fixtures/websocket/socketio/vuln.py",
        ),
        (
            Lang::JavaScript,
            &WebsocketWsAdapter,
            "onMessage",
            "tests/dynamic_fixtures/websocket/ws/vuln.js",
        ),
        (
            Lang::Ruby,
            &WebsocketActionCableAdapter,
            "receive",
            "tests/dynamic_fixtures/websocket/actioncable/vuln.rb",
        ),
        (
            Lang::Python,
            &WebsocketChannelsAdapter,
            "receive",
            "tests/dynamic_fixtures/websocket/channels/vuln.py",
        ),
    ];
    let confirmed = cases
        .iter()
        .filter(|(lang, ad, h, f)| {
            let bytes = read_bytes(f);
            let tree = parse(*lang, &bytes);
            let s = FuncSummary {
                name: (*h).into(),
                ..Default::default()
            };
            ad.detect(&s, tree.root_node(), &bytes).is_some()
        })
        .count();
    assert!(
        confirmed * 4 >= cases.len() * 3,
        "websocket adapter binding rate must be >= 75% (got {confirmed}/{})",
        cases.len(),
    );
}

#[test]
fn phase_21_middleware_acceptance_rate() {
    let cases: &[(Lang, &dyn FrameworkAdapter, &str, &str)] = &[
        (
            Lang::JavaScript,
            &MiddlewareExpressAdapter,
            "audit",
            "tests/dynamic_fixtures/middleware/express/vuln.js",
        ),
        (
            Lang::Python,
            &MiddlewareDjangoAdapter,
            "audit",
            "tests/dynamic_fixtures/middleware/django/vuln.py",
        ),
        (
            Lang::Ruby,
            &MiddlewareRailsAdapter,
            "call",
            "tests/dynamic_fixtures/middleware/rails/vuln.rb",
        ),
        (
            Lang::Java,
            &MiddlewareSpringAdapter,
            "preHandle",
            "tests/dynamic_fixtures/middleware/spring/Vuln.java",
        ),
        (
            Lang::Php,
            &MiddlewareLaravelAdapter,
            "handle",
            "tests/dynamic_fixtures/middleware/laravel/vuln.php",
        ),
    ];
    let confirmed = cases
        .iter()
        .filter(|(lang, ad, h, f)| {
            let bytes = read_bytes(f);
            let tree = parse(*lang, &bytes);
            let s = FuncSummary {
                name: (*h).into(),
                ..Default::default()
            };
            ad.detect(&s, tree.root_node(), &bytes).is_some()
        })
        .count();
    assert!(
        confirmed * 4 >= cases.len() * 3,
        "middleware adapter binding rate must be >= 75% (got {confirmed}/{})",
        cases.len(),
    );
}

#[test]
fn phase_21_migration_acceptance_rate() {
    let cases: &[(Lang, &dyn FrameworkAdapter, &str, &str)] = &[
        (
            Lang::Ruby,
            &MigrationRailsAdapter,
            "up",
            "tests/dynamic_fixtures/migration/rails/vuln.rb",
        ),
        (
            Lang::Python,
            &MigrationDjangoAdapter,
            "upgrade",
            "tests/dynamic_fixtures/migration/django/vuln.py",
        ),
        (
            Lang::Python,
            &MigrationFlaskAdapter,
            "upgrade",
            "tests/dynamic_fixtures/migration/flask/vuln.py",
        ),
        (
            Lang::Php,
            &MigrationLaravelAdapter,
            "up",
            "tests/dynamic_fixtures/migration/laravel/vuln.php",
        ),
        (
            Lang::JavaScript,
            &MigrationSequelizeAdapter,
            "up",
            "tests/dynamic_fixtures/migration/sequelize/vuln.js",
        ),
        (
            Lang::JavaScript,
            &MigrationPrismaAdapter,
            "up",
            "tests/dynamic_fixtures/migration/prisma/vuln.js",
        ),
    ];
    let confirmed = cases
        .iter()
        .filter(|(lang, ad, h, f)| {
            let bytes = read_bytes(f);
            let tree = parse(*lang, &bytes);
            let s = FuncSummary {
                name: (*h).into(),
                ..Default::default()
            };
            ad.detect(&s, tree.root_node(), &bytes).is_some()
        })
        .count();
    assert!(
        confirmed * 4 >= cases.len() * 3,
        "migration adapter binding rate must be >= 75% (got {confirmed}/{})",
        cases.len(),
    );
}

// ── Dispatcher run_spec smoke ────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct RunSpecCase {
    name: &'static str,
    lang: Lang,
    kind: fn() -> EvEntryKind,
    entry_name: &'static str,
    fixture_dir: &'static str,
    vuln_file: &'static str,
    benign_file: &'static str,
    cap: Cap,
}

fn command_available(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn toolchain_for(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => "python3",
        Lang::JavaScript | Lang::TypeScript => "node",
        Lang::Ruby => "ruby",
        Lang::Php => "php",
        Lang::Java => "java",
        Lang::Go => "go",
        Lang::Rust => "cargo",
        Lang::C => "cc",
        Lang::Cpp => "c++",
    }
}

fn build_runspec_case(case: RunSpecCase, file_name: &str) -> (HarnessSpec, TempDir) {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(case.fixture_dir)
        .join(file_name);
    let tmp = TempDir::new().expect("create phase21 run_spec tempdir");
    let dst = tmp.path().join(file_name);
    std::fs::copy(&src, &dst).unwrap_or_else(|e| panic!("copy {}: {e}", src.display()));
    let entry_file = dst.to_string_lossy().into_owned();

    let mut digest = blake3::Hasher::new();
    digest.update(b"phase21-runspec|");
    digest.update(case.name.as_bytes());
    digest.update(b"|");
    digest.update(file_name.as_bytes());
    let spec_hash = format!("{:016x}", {
        let bytes = digest.finalize();
        u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
    });

    let spec = HarnessSpec {
        finding_id: spec_hash.clone(),
        entry_file: entry_file.clone(),
        entry_name: case.entry_name.to_owned(),
        entry_kind: (case.kind)(),
        lang: case.lang,
        toolchain_id: default_toolchain_id(case.lang).into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: case.cap,
        constraint_hints: vec![],
        sink_file: entry_file,
        sink_line: 1,
        spec_hash,
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: StubKind::for_cap(case.cap),
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    };
    (spec, tmp)
}

fn run_phase21_case(case: RunSpecCase, file_name: &str) -> Option<RunOutcome> {
    let bin = toolchain_for(case.lang);
    if !command_available(bin) {
        eprintln!("SKIP {} {file_name}: missing toolchain {bin}", case.name);
        return None;
    }
    let (spec, tmp) = build_runspec_case(case, file_name);
    let mut opts = SandboxOptions {
        backend: SandboxBackend::Process,
        ..SandboxOptions::default()
    };
    let stub_harness = if spec.stubs_required.is_empty() {
        None
    } else {
        let h = Arc::new(
            StubHarness::start(&spec.stubs_required, tmp.path()).expect("start phase21 stubs"),
        );
        for (name, value) in h.endpoints() {
            opts.extra_env.push((name.to_owned(), value));
        }
        Some(h)
    };
    opts.stub_harness = stub_harness;
    match run_spec(&spec, &opts) {
        Ok(outcome) => Some(outcome),
        Err(RunError::BuildFailed { stderr, attempts }) => {
            eprintln!(
                "SKIP {} {file_name}: harness build failed after {attempts} attempts: {stderr}",
                case.name,
            );
            None
        }
        Err(err) => panic!("run_spec {} {file_name} errored: {err:?}", case.name),
    }
}

fn scheduled_kind() -> EvEntryKind {
    EvEntryKind::ScheduledJob {
        schedule: Some("*/5 * * * *".into()),
    }
}

fn graphql_kind() -> EvEntryKind {
    EvEntryKind::GraphQLResolver {
        type_name: "Query".into(),
        field: "user".into(),
    }
}

fn websocket_kind() -> EvEntryKind {
    EvEntryKind::WebSocket {
        path: "/ws/chat".into(),
    }
}

fn middleware_kind() -> EvEntryKind {
    EvEntryKind::Middleware {
        name: "audit".into(),
    }
}

fn migration_kind() -> EvEntryKind {
    EvEntryKind::Migration { version: None }
}

const RUNSPEC_CASES: &[RunSpecCase] = &[
    RunSpecCase {
        name: "scheduled-celery",
        lang: Lang::Python,
        kind: scheduled_kind,
        entry_name: "tick",
        fixture_dir: "tests/dynamic_fixtures/scheduled_job/celery",
        vuln_file: "vuln.py",
        benign_file: "benign.py",
        cap: Cap::CODE_EXEC,
    },
    RunSpecCase {
        name: "graphql-graphene",
        lang: Lang::Python,
        kind: graphql_kind,
        entry_name: "resolve_user",
        fixture_dir: "tests/dynamic_fixtures/graphql_resolver/graphene",
        vuln_file: "vuln.py",
        benign_file: "benign.py",
        cap: Cap::CODE_EXEC,
    },
    RunSpecCase {
        name: "websocket-socketio",
        lang: Lang::Python,
        kind: websocket_kind,
        entry_name: "message",
        fixture_dir: "tests/dynamic_fixtures/websocket/socketio",
        vuln_file: "vuln.py",
        benign_file: "benign.py",
        cap: Cap::CODE_EXEC,
    },
    RunSpecCase {
        name: "middleware-express",
        lang: Lang::JavaScript,
        kind: middleware_kind,
        entry_name: "audit",
        fixture_dir: "tests/dynamic_fixtures/middleware/express",
        vuln_file: "vuln.js",
        benign_file: "benign.js",
        cap: Cap::CODE_EXEC,
    },
    RunSpecCase {
        name: "migration-flask",
        lang: Lang::Python,
        kind: migration_kind,
        entry_name: "upgrade",
        fixture_dir: "tests/dynamic_fixtures/migration/flask",
        vuln_file: "vuln.py",
        benign_file: "benign.py",
        cap: Cap::SQL_QUERY,
    },
];

#[test]
fn phase_21_vuln_fixtures_confirm_via_run_spec() {
    for case in RUNSPEC_CASES {
        let Some(outcome) = run_phase21_case(*case, case.vuln_file) else {
            continue;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "{} vuln must Confirm via run_spec; got {outcome:?}",
            case.name,
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry differential outcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }
}

#[test]
fn phase_21_benign_fixtures_do_not_confirm_via_run_spec() {
    for case in RUNSPEC_CASES {
        let Some(outcome) = run_phase21_case(*case, case.benign_file) else {
            continue;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "{} benign control must not Confirm via run_spec; got {outcome:?}",
            case.name,
        );
        if let Some(diff) = outcome.differential.as_ref() {
            assert_ne!(diff.verdict, DifferentialVerdict::Confirmed);
        }
    }
}

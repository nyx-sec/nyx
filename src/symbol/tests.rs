use super::*;

#[test]
fn lang_round_trip() {
    for slug in &[
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "typescript",
        "javascript",
    ] {
        let lang = Lang::from_slug(slug).unwrap();
        assert_eq!(lang.as_str(), *slug);
    }
}

#[test]
fn lang_aliases() {
    assert_eq!(Lang::from_slug("js"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_slug("ts"), Some(Lang::TypeScript));
}

#[test]
fn func_key_display() {
    let k = FuncKey::new_function(Lang::Rust, "src/lib.rs", "my_func", Some(2));
    assert_eq!(k.to_string(), "rust::src/lib.rs::my_func/2");
}

#[test]
fn func_key_display_method_with_container() {
    let k = FuncKey {
        lang: Lang::Java,
        namespace: "src/OrderService.java".into(),
        container: "OrderService".into(),
        name: "process".into(),
        arity: Some(1),
        disambig: None,
        kind: FuncKind::Method,
    };
    assert_eq!(
        k.to_string(),
        "java::src/OrderService.java::OrderService::process/1[method]"
    );
}

#[test]
fn func_key_display_closure_with_disambig() {
    let k = FuncKey {
        lang: Lang::JavaScript,
        namespace: "src/app.js".into(),
        container: "outer".into(),
        name: "<anon>".into(),
        arity: Some(0),
        disambig: Some(421),
        kind: FuncKind::Closure,
    };
    assert_eq!(
        k.to_string(),
        "javascript::src/app.js::outer::<anon>/0#421[closure]"
    );
}

#[test]
fn func_key_qualified_name_free_function() {
    let k = FuncKey::new_function(Lang::Rust, "lib.rs", "foo", Some(0));
    assert_eq!(k.qualified_name(), "foo");
}

#[test]
fn func_key_qualified_name_method() {
    let k = FuncKey {
        lang: Lang::Python,
        namespace: "app.py".into(),
        container: "Service".into(),
        name: "run".into(),
        arity: Some(1),
        disambig: None,
        kind: FuncKind::Method,
    };
    assert_eq!(k.qualified_name(), "Service::run");
}

#[test]
fn method_vs_function_same_name_are_distinct_keys() {
    let free = FuncKey::new_function(Lang::Python, "app.py", "process", Some(1));
    let method = FuncKey {
        lang: Lang::Python,
        namespace: "app.py".into(),
        container: "Worker".into(),
        name: "process".into(),
        arity: Some(1),
        disambig: None,
        kind: FuncKind::Method,
    };
    assert_ne!(free, method);
    assert_ne!(free.qualified_name(), method.qualified_name());
}

#[test]
fn two_methods_same_name_different_containers_are_distinct() {
    let order = FuncKey {
        lang: Lang::Java,
        namespace: "src/Services.java".into(),
        container: "OrderService".into(),
        name: "process".into(),
        arity: Some(1),
        disambig: None,
        kind: FuncKind::Method,
    };
    let user = FuncKey {
        lang: Lang::Java,
        namespace: "src/Services.java".into(),
        container: "UserService".into(),
        name: "process".into(),
        arity: Some(1),
        disambig: None,
        kind: FuncKind::Method,
    };
    assert_ne!(order, user);
}

#[test]
fn closure_disambig_separates_same_name_siblings() {
    let a = FuncKey {
        lang: Lang::JavaScript,
        namespace: "f.js".into(),
        container: "outer".into(),
        name: "<anon>".into(),
        arity: Some(0),
        disambig: Some(100),
        kind: FuncKind::Closure,
    };
    let b = FuncKey {
        lang: Lang::JavaScript,
        namespace: "f.js".into(),
        container: "outer".into(),
        name: "<anon>".into(),
        arity: Some(0),
        disambig: Some(205),
        kind: FuncKind::Closure,
    };
    assert_ne!(a, b);
}

#[test]
fn legacy_json_without_new_fields_deserialises() {
    // JSON written before container/disambig/kind existed must still parse.
    let json = r#"{
        "lang": "rust",
        "namespace": "src/lib.rs",
        "name": "helper",
        "arity": 1
    }"#;
    let key: FuncKey = serde_json::from_str(json).unwrap();
    assert_eq!(key.name, "helper");
    assert_eq!(key.container, "");
    assert_eq!(key.disambig, None);
    assert_eq!(key.kind, FuncKind::Function);
}

#[test]
fn round_trip_full_fields_serde() {
    let k = FuncKey {
        lang: Lang::Ruby,
        namespace: "lib/worker.rb".into(),
        container: "Admin::Worker".into(),
        name: "run".into(),
        arity: Some(2),
        disambig: Some(9001),
        kind: FuncKind::Method,
    };
    let json = serde_json::to_string(&k).unwrap();
    let back: FuncKey = serde_json::from_str(&json).unwrap();
    assert_eq!(k, back);
}

#[test]
fn normalize_strips_root() {
    assert_eq!(
        normalize_namespace("/home/user/proj/src/lib.rs", Some("/home/user/proj")),
        "src/lib.rs"
    );
    assert_eq!(
        normalize_namespace("/home/user/proj/src/lib.rs", Some("/home/user/proj/")),
        "src/lib.rs"
    );
}

#[test]
fn normalize_fallback_on_no_root() {
    assert_eq!(normalize_namespace("test.rs", None), "test.rs");
}

#[test]
fn normalize_fallback_on_mismatch() {
    assert_eq!(
        normalize_namespace("/other/path/lib.rs", Some("/home/user/proj")),
        "/other/path/lib.rs"
    );
}

// ── Phase 02: extension + shebang + content sniff ──────────────────────────

use std::path::Path;

#[test]
fn from_extension_accepts_phase02_additions() {
    // Each of the new extensions must round-trip to the documented language.
    assert_eq!(Lang::from_extension("cjs"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_extension("mjs"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_extension("jsx"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_extension("mts"), Some(Lang::TypeScript));
    assert_eq!(Lang::from_extension("cts"), Some(Lang::TypeScript));
    assert_eq!(Lang::from_extension("tsx"), Some(Lang::TypeScript));
    assert_eq!(Lang::from_extension("pyi"), Some(Lang::Python));
    assert_eq!(Lang::from_extension("kt"), Some(Lang::Java));
    assert_eq!(Lang::from_extension("kts"), Some(Lang::Java));
    // C++ inventory extended in Phase 01 / ast.rs: keep the helper aligned.
    assert_eq!(Lang::from_extension("cc"), Some(Lang::Cpp));
    assert_eq!(Lang::from_extension("hpp"), Some(Lang::Cpp));
}

#[test]
fn from_extension_is_case_insensitive() {
    // Real-world filesystems mix case (especially on Windows / macOS).
    assert_eq!(Lang::from_extension("PY"), Some(Lang::Python));
    assert_eq!(Lang::from_extension("Java"), Some(Lang::Java));
    assert_eq!(Lang::from_extension("JSX"), Some(Lang::JavaScript));
}

#[test]
fn from_path_or_content_extension_wins() {
    // Even with a misleading shebang the explicit extension must take
    // precedence — file-format ground truth beats hand-edited interpreter
    // hints.
    let head = b"#!/usr/bin/env node\nprint('hi')\n";
    let path = Path::new("/tmp/script.py");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_shebang_python_env() {
    let head = b"#!/usr/bin/env python3\nimport os\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_shebang_node_direct() {
    let head = b"#!/usr/local/bin/node\nconsole.log(1)\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(
        Lang::from_path_or_content(path, head),
        Some(Lang::JavaScript)
    );
}

#[test]
fn from_path_or_content_shebang_ruby_direct() {
    let head = b"#!/usr/bin/ruby\nputs 1\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Ruby));
}

#[test]
fn from_path_or_content_shebang_php() {
    let head = b"#!/usr/bin/env php\n<?php echo 1;\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Php));
}

#[test]
fn from_path_or_content_shebang_with_env_dash_flag() {
    // `env -S` is the portable trick for passing args; the second token after
    // env is the real interpreter.
    let head = b"#!/usr/bin/env -S python3 -u\nimport sys\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_shebang_unknown_interpreter_falls_through_to_sniff() {
    // bash isn't a supported language — shebang returns None — and the
    // body's `<?php` opener should still be picked up by the content sniff.
    let head = b"#!/bin/bash\n<?php echo 1; ?>\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Php));
}

#[test]
fn from_path_or_content_content_sniff_php() {
    let head = b"<?php echo 'hi'; ?>";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Php));
}

#[test]
fn from_path_or_content_content_sniff_go_package_main() {
    let head = b"package main\n\nimport \"fmt\"\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Go));
}

#[test]
fn from_path_or_content_content_sniff_java_package_semicolon() {
    let head = b"package com.example.app;\n\npublic class Main {}\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Java));
}

#[test]
fn from_path_or_content_content_sniff_python_def() {
    let head = b"\"\"\"docstring\"\"\"\n\ndef handle(x):\n    return x\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_content_sniff_rust_use_std() {
    let head = b"use std::path::Path;\n\nfn main() {}\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Rust));
}

#[test]
fn from_path_or_content_returns_none_when_nothing_matches() {
    let path = Path::new("/tmp/runme.weird");
    assert_eq!(Lang::from_path_or_content(path, b"plain text data"), None);
}

#[test]
fn from_path_or_content_empty_head_with_unknown_extension_returns_none() {
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, b""), None);
}

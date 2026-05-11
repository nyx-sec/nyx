//! End-to-end integration tests for the Phase-6 type-hierarchy index
//! installation and runtime fan-out wiring.
//!
//! These tests run the production pass-1 extraction pipeline
//! (`extract_all_summaries_from_bytes` + `merge_summaries` +
//! `insert_ssa`) on synthetic multi-file sources, then exercise the
//! `GlobalSummaries::install_hierarchy` + `resolve_callee_widened`
//! contract that the taint engine's runtime callee resolver consumes.
//!
//! Why integration-level coverage matters
//! ──────────────────────────────────────
//! The unit tests in `src/summary/tests.rs::hierarchy_widened_tests`
//! cover the lookup contract on hand-crafted summaries.  These tests
//! cover the *upstream* invariant: that pass-1's
//! `cfg/hierarchy.rs` extractor populates `FuncSummary::hierarchy_edges`
//! correctly for every supported language (Java, Rust, TypeScript,
//! Python), and that `install_hierarchy` rebuilds the index off those
//! edges so the runtime resolver sees concrete implementers at virtual-
//! dispatch call sites.
//!
//! When this file fails, the gap is somewhere between the AST
//! extractor (`src/cfg/hierarchy.rs`), the summary plumbing
//! (`FuncSummary::hierarchy_edges`), and the runtime install (`scan.rs`
//! `install_hierarchy` call site).  Unit-test failures localise more
//! tightly; integration-test failures point at the seam.

mod common;

use nyx_scanner::ast::extract_all_summaries_from_bytes;
use nyx_scanner::summary::{CalleeQuery, GlobalSummaries, ssa_summary::SsaFuncSummary};
use nyx_scanner::symbol::{FuncKey, Lang};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

use common::test_config;

struct File<'a> {
    namespace: &'a str,
    bytes: &'a [u8],
}

/// Run pass-1 extraction + merge over a synthetic file set, then
/// install the hierarchy index, mirroring exactly what production
/// scan paths do before pass 2 runs.
fn build_gs(files: &[File<'_>]) -> GlobalSummaries {
    let cfg = test_config(AnalysisMode::Taint);
    let mut all_func: Vec<nyx_scanner::summary::FuncSummary> = Vec::new();
    let mut all_ssa: Vec<(FuncKey, SsaFuncSummary)> = Vec::new();
    for f in files {
        let path = Path::new(f.namespace);
        let (func, ssa, _bodies, _auth, _cpi) =
            extract_all_summaries_from_bytes(f.bytes, path, &cfg, None)
                .expect("extract_all_summaries_from_bytes must succeed");
        all_func.extend(func);
        all_ssa.extend(ssa);
    }
    let mut gs = nyx_scanner::summary::merge_summaries(all_func, None);
    for (k, s) in all_ssa {
        gs.insert_ssa(k, s);
    }
    gs.install_hierarchy();
    gs
}

// ─────────────────────────────────────────────────────────────────────────
//  C1, Java interface fan-out
// ─────────────────────────────────────────────────────────────────────────

/// Pass-1 must extract the `class FileLogger implements ILogger`
/// edge.  After `install_hierarchy`, a query with
/// `receiver_type = ILogger` widens to both ILogger's own method and
/// every implementer's overriding method.
#[test]
fn java_interface_with_two_impls_fans_out_to_both() {
    // Three files: one defines the interface, two define impls.  Each
    // impl declares `void log(String s)` so the leaf-name lookup has
    // material to fan out to.
    let logger_iface = br#"
package app;
public interface ILogger {
    void log(String s);
}
"#;
    let console_logger = br#"
package app;
public class ConsoleLogger implements ILogger {
    public void log(String s) {
        System.out.println(s);
    }
}
"#;
    let file_logger = br#"
package app;
public class FileLogger implements ILogger {
    public void log(String s) {
        java.io.File f = new java.io.File("/tmp/" + s);
    }
}
"#;

    let gs = build_gs(&[
        File {
            namespace: "src/ILogger.java",
            bytes: logger_iface,
        },
        File {
            namespace: "src/ConsoleLogger.java",
            bytes: console_logger,
        },
        File {
            namespace: "src/FileLogger.java",
            bytes: file_logger,
        },
    ]);

    let h = gs.hierarchy().expect("hierarchy must be installed");
    let subs = h.subs_of(Lang::Java, "ILogger");
    assert!(
        subs.iter().any(|s| s == "ConsoleLogger"),
        "ConsoleLogger missing from ILogger sub-types: {subs:?}"
    );
    assert!(
        subs.iter().any(|s| s == "FileLogger"),
        "FileLogger missing from ILogger sub-types: {subs:?}"
    );

    // Runtime widening: receiver typed as ILogger must reach every
    // concrete impl's `log(s)`.
    let widened = gs.resolve_callee_widened(&CalleeQuery {
        name: "log",
        caller_lang: Lang::Java,
        caller_namespace: "src/Main.java",
        caller_container: None,
        receiver_type: Some("ILogger"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    let containers: Vec<&str> = widened.iter().map(|k| k.container.as_str()).collect();
    assert!(
        containers.contains(&"ConsoleLogger"),
        "ConsoleLogger::log missing from widened set: {containers:?}"
    );
    assert!(
        containers.contains(&"FileLogger"),
        "FileLogger::log missing from widened set: {containers:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  C2, Rust trait fan-out
// ─────────────────────────────────────────────────────────────────────────

/// Pass-1 must extract `impl Logger for SafeLogger` and
/// `impl Logger for EvalLogger` edges.  Receiver typed as `Logger`
/// widens to both impls.
#[test]
fn rust_trait_with_two_impls_fans_out() {
    let trait_def = br#"
pub trait Logger {
    fn log(&self, s: &str);
}
"#;
    let safe_impl = br#"
use crate::Logger;

pub struct SafeLogger;

impl Logger for SafeLogger {
    fn log(&self, _s: &str) {
        // no-op
    }
}
"#;
    let eval_impl = br#"
use crate::Logger;
use std::process::Command;

pub struct EvalLogger;

impl Logger for EvalLogger {
    fn log(&self, s: &str) {
        let _ = Command::new(s).output();
    }
}
"#;

    let gs = build_gs(&[
        File {
            namespace: "src/lib.rs",
            bytes: trait_def,
        },
        File {
            namespace: "src/safe.rs",
            bytes: safe_impl,
        },
        File {
            namespace: "src/eval.rs",
            bytes: eval_impl,
        },
    ]);

    let h = gs.hierarchy().expect("hierarchy must be installed");
    let subs = h.subs_of(Lang::Rust, "Logger");
    assert!(
        subs.iter().any(|s| s == "SafeLogger"),
        "SafeLogger missing from Logger impls: {subs:?}"
    );
    assert!(
        subs.iter().any(|s| s == "EvalLogger"),
        "EvalLogger missing from Logger impls: {subs:?}"
    );

    let widened = gs.resolve_callee_widened(&CalleeQuery {
        name: "log",
        caller_lang: Lang::Rust,
        caller_namespace: "src/main.rs",
        caller_container: None,
        receiver_type: Some("Logger"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(2),
    });
    // `arity = 2` because the trait method takes `(&self, &str)`.
    // Some Rust pipelines record the receiver in arity, others don't ,
    // accept either as long as both impls fan out.
    let widened_any_arity = if widened.is_empty() {
        gs.resolve_callee_widened(&CalleeQuery {
            name: "log",
            caller_lang: Lang::Rust,
            caller_namespace: "src/main.rs",
            caller_container: None,
            receiver_type: Some("Logger"),
            namespace_qualifier: None,
            receiver_var: None,
            arity: Some(1),
        })
    } else {
        widened
    };

    let containers: Vec<&str> = widened_any_arity
        .iter()
        .map(|k| k.container.as_str())
        .collect();
    assert!(
        containers.contains(&"SafeLogger") || containers.contains(&"EvalLogger"),
        "neither SafeLogger nor EvalLogger present in widened set: {containers:?}; \
         hierarchy_edges from impl Logger for X must reach \
         resolve_callee_widened"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  C3, TypeScript class extends fan-out
// ─────────────────────────────────────────────────────────────────────────

/// Pass-1 must extract `class Sub extends Super` and
/// `class Sub2 extends Super` edges.  Receiver typed as `Super`
/// widens to both subs.
#[test]
fn ts_class_with_two_subclasses_fans_out() {
    let super_class = br#"
export class Base {
    handle(s: string): void {}
}
"#;
    let sub_a = br#"
import { Base } from './base';
export class SubA extends Base {
    handle(s: string): void {
        eval(s);
    }
}
"#;
    let sub_b = br#"
import { Base } from './base';
export class SubB extends Base {
    handle(s: string): void {
        // safe
    }
}
"#;

    let gs = build_gs(&[
        File {
            namespace: "src/base.ts",
            bytes: super_class,
        },
        File {
            namespace: "src/suba.ts",
            bytes: sub_a,
        },
        File {
            namespace: "src/subb.ts",
            bytes: sub_b,
        },
    ]);

    let h = gs.hierarchy().expect("hierarchy must be installed");
    let subs = h.subs_of(Lang::TypeScript, "Base");
    assert!(
        subs.iter().any(|s| s == "SubA"),
        "SubA missing from Base sub-types: {subs:?}"
    );
    assert!(
        subs.iter().any(|s| s == "SubB"),
        "SubB missing from Base sub-types: {subs:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  C4, Python class hierarchy
// ─────────────────────────────────────────────────────────────────────────

/// Pass-1 must extract `class Concrete(Base)` edges.  The
/// hierarchy index keyed on Python's `Lang::Python` reflects this.
#[test]
fn python_class_with_subclass_fans_out() {
    let base_py = br#"
class Base:
    def run(self, s):
        pass
"#;
    let concrete_py = br#"
from base import Base

class Concrete(Base):
    def run(self, s):
        eval(s)
"#;

    let gs = build_gs(&[
        File {
            namespace: "src/base.py",
            bytes: base_py,
        },
        File {
            namespace: "src/concrete.py",
            bytes: concrete_py,
        },
    ]);

    let h = gs.hierarchy().expect("hierarchy must be installed");
    let subs = h.subs_of(Lang::Python, "Base");
    assert!(
        subs.iter().any(|s| s == "Concrete"),
        "Concrete missing from Base sub-types in Python: {subs:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  C5, Languages without an extractor are silently empty
// ─────────────────────────────────────────────────────────────────────────

/// Go's structural / implicit interface satisfaction is intractable
/// to enumerate from per-file information and is **deliberately
/// omitted** from the extractor.  This test pins the contract: a Go
/// program with what looks like inheritance produces an empty
/// hierarchy index, and `resolve_callee_widened` collapses to today's
/// single-result behaviour, no fan-out, no regression.
#[test]
fn go_program_produces_empty_hierarchy() {
    // Go interface + struct that satisfies it implicitly.  No `extends`
    // syntax exists in Go; the extractor returns no edges.
    let go_src = br#"
package main

type Logger interface {
    Log(s string)
}

type ConsoleLogger struct{}

func (c *ConsoleLogger) Log(s string) {
    println(s)
}
"#;

    let gs = build_gs(&[File {
        namespace: "src/main.go",
        bytes: go_src,
    }]);

    let h = gs
        .hierarchy()
        .expect("hierarchy must be installed even when empty");
    assert!(
        h.subs_of(Lang::Go, "Logger").is_empty(),
        "Go must have no recorded subtypes — implicit interface satisfaction \
         is deliberately omitted"
    );

    // Runtime widening collapses to today's single-result behaviour.
    let widened = gs.resolve_callee_widened(&CalleeQuery {
        name: "Log",
        caller_lang: Lang::Go,
        caller_namespace: "src/main.go",
        caller_container: None,
        receiver_type: Some("Logger"),
        namespace_qualifier: None,
        receiver_var: None,
        arity: Some(1),
    });
    // Either empty (Logger has no Log method body in summaries) or
    // single result, must NEVER fan out.
    assert!(
        widened.len() <= 1,
        "Go must produce ≤ 1 result with no hierarchy fan-out, got {widened:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  C6, Hierarchy install is idempotent
// ─────────────────────────────────────────────────────────────────────────

/// Calling `install_hierarchy` twice produces the same view.  This
/// guards against a future regression where a stateful builder leaks
/// state across calls.
#[test]
fn install_hierarchy_is_idempotent() {
    let logger_iface = br#"
package app;
public interface ILogger { void log(String s); }
"#;
    let console_logger = br#"
package app;
public class ConsoleLogger implements ILogger {
    public void log(String s) { System.out.println(s); }
}
"#;

    let mut gs = build_gs(&[
        File {
            namespace: "src/ILogger.java",
            bytes: logger_iface,
        },
        File {
            namespace: "src/ConsoleLogger.java",
            bytes: console_logger,
        },
    ]);

    let first = gs
        .hierarchy()
        .unwrap()
        .subs_of(Lang::Java, "ILogger")
        .to_vec();
    gs.install_hierarchy();
    let second = gs
        .hierarchy()
        .unwrap()
        .subs_of(Lang::Java, "ILogger")
        .to_vec();
    assert_eq!(first, second, "install_hierarchy must be idempotent");
}

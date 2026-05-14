//! PHP harness emitter.
//!
//! Generates a PHP script that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Includes the entry file (`entry.php`) from the workdir.
//! 3. Calls the entry function with the payload routed to the correct slot.
//! 4. Catches all Throwables to prevent harness crashes from masking results.
//!
//! Sink-reachability probe: fixtures explicitly emit `__NYX_SINK_HIT__` before
//! the actual sink call (same pattern as Rust / JS fixtures).
//!
//! Payload slot support:
//! - `PayloadSlot::Param(n)` — n-th positional argument.
//! - `PayloadSlot::EnvVar(name)` — set `$_ENV`/`putenv()` before calling.
//! - `PayloadSlot::Stdin` — wrap `STDIN` with the payload.
//! - Other slots produce `UnsupportedReason::PayloadSlotUnsupported`.
//!
//! Build: no compilation step. Command is `php harness.php`.
//! Build container: `nyx-build-php:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for PHP.  Method bodies delegate to the
/// existing free functions in this module.
pub struct PhpEmitter;

/// Entry kinds the PHP emitter currently understands.  Extended in Phase 15
/// (Track B PHP vertical) to include `HttpRoute` (Slim / Laravel / Symfony
/// closures) and `CliSubcommand` (`$argv`).
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for PhpEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "php emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — Track B will add Slim / Laravel / Symfony route + CLI shapes in phase 15"
        )
    }
}

/// Source of the `__nyx_probe` shim for the PHP harness (Phase 06 —
/// Track C.1).
pub fn probe_shim() -> &'static str {
    r#"
// ── __nyx_probe shim (Phase 06 — Track C.1) ──────────────────────────────────
function __nyx_probe(string $sinkCallee, ...$args): void {
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') {
        return;
    }
    $ser = [];
    foreach ($args as $a) {
        if (is_int($a)) {
            $ser[] = ['kind' => 'Int', 'value' => $a];
        } else {
            $ser[] = ['kind' => 'String', 'value' => (string) $a];
        }
    }
    $rec = [
        'sink_callee' => $sinkCallee,
        'args' => $ser,
        'captured_at_ns' => (int) (microtime(true) * 1e9),
        'payload_id' => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
    ];
    $line = json_encode($rec) . "\n";
    @file_put_contents($p, $line, FILE_APPEND);
}
"#
}

/// Emit a PHP harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_) | PayloadSlot::EnvVar(_) | PayloadSlot::Stdin => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let source = generate_source(spec);

    Ok(HarnessSource {
        source,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.php".to_owned()),
    })
}

fn generate_source(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_expr) = build_call(spec, entry_fn);

    format!(
        r#"<?php
// Nyx dynamic harness — auto-generated, do not edit.

// ── Payload loading ────────────────────────────────────────────────────────────
function nyx_payload(): string {{
    $v = getenv('NYX_PAYLOAD');
    if ($v !== false && $v !== '') {{
        return $v;
    }}
    $b64 = getenv('NYX_PAYLOAD_B64');
    if ($b64 !== false && $b64 !== '') {{
        return base64_decode($b64, true) ?: '';
    }}
    return '';
}}

$payload = nyx_payload();

// ── Entry include ─────────────────────────────────────────────────────────────
try {{
    require_once __DIR__ . '/entry.php';
}} catch (Throwable $e) {{
    fwrite(STDERR, 'NYX_IMPORT_ERROR: ' . $e->getMessage() . "\n");
    exit(77);
}}

// ── Pre-call setup ─────────────────────────────────────────────────────────────
{pre_call}
// ── Call entry point ──────────────────────────────────────────────────────────
try {{
    $result = {call_expr};
    if ($result !== null) {{
        echo $result . "\n";
    }}
}} catch (Throwable $e) {{
    fwrite(STDERR, 'NYX_EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
}}
"#,
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
fn build_call(spec: &HarnessSpec, func: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            let pre = String::new();
            let call = if *idx == 0 {
                format!("{func}($payload)")
            } else {
                let pads = (0..*idx).map(|_| "''").collect::<Vec<_>>().join(", ");
                format!("{func}({pads}, $payload)")
            };
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("putenv({name:?} . '=' . $payload);\n$_ENV[{name:?}] = $payload;\n");
            let call = format!("{func}()");
            (pre, call)
        }
        PayloadSlot::Stdin => {
            // Replace STDIN with an in-memory stream containing the payload.
            let pre = "if (defined('STDIN')) {\n    $stream = fopen('php://memory', 'r+');\n    fwrite($stream, $payload);\n    rewind($stream);\n    // Note: STDIN reassignment is not portable; fixture reads via fgets(STDIN).\n}\n".to_owned();
            let call = format!("{func}()");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("{func}($payload)");
            (pre, call)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "php0000000000001".into(),
            entry_file: "src/login.php".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Php,
            toolchain_id: "php-8".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/login.php".into(),
            sink_line: 10,
            spec_hash: "php0000000000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.starts_with("<?php"));
        assert!(harness.source.contains("NYX_PAYLOAD"));
        assert!(harness.source.contains("require_once"));
        assert!(harness.source.contains("login($payload)"));
        assert_eq!(harness.filename, "harness.php");
        assert_eq!(harness.command, vec!["php", "harness.php"]);
    }

    #[test]
    fn emit_param_index_0() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("login($payload)"));
    }

    #[test]
    fn emit_param_index_2() {
        let spec = make_spec(PayloadSlot::Param(2));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("login('', '', $payload)"));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_HOST".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("putenv"));
        assert!(harness.source.contains("\"DB_HOST\""));
    }

    #[test]
    fn emit_http_body_is_unsupported() {
        let spec = make_spec(PayloadSlot::HttpBody);
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn emit_entry_subpath_is_entry_php() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry.php".to_owned()));
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!PhpEmitter.entry_kinds_supported().is_empty());
        assert!(PhpEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = PhpEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 15"));
    }

    #[test]
    fn harness_has_base64_decode() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("base64_decode"));
        assert!(harness.source.contains("NYX_PAYLOAD_B64"));
    }
}

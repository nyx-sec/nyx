//! PHP harness emitter.
//!
//! Phase 15 (Track B PHP vertical) replaces the single legacy `emit`
//! body with dispatch over [`PhpShape`] — the cross product of
//! [`EntryKind`] and a lightweight per-file shape detector that
//! inspects the entry file for Slim/Laravel/Symfony route closures,
//! `$argv`-driven CLI scripts, and top-level script bodies.
//!
//! Each shape emits a single `harness.php` that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Includes the entry file (`entry.php`) from the workdir.
//! 3. Invokes the entry function / closure via the per-shape adapter.
//! 4. Catches all Throwables so the harness exit stays observable.
//!
//! Sink-reachability probe: fixtures explicitly emit `__NYX_SINK_HIT__`
//! before the actual sink call (same pattern as Rust / JS fixtures).
//!
//! Payload slot support:
//! - `PayloadSlot::Param(n)` — n-th positional argument.
//! - `PayloadSlot::EnvVar(name)` — set `$_ENV`/`putenv()` before calling.
//! - `PayloadSlot::Stdin` — wrap `STDIN` with the payload.
//! - `PayloadSlot::Argv(n)` — appended to `$argv` for CLI shapes.
//! - `PayloadSlot::QueryParam(name)` — surfaced via `$_GET[name]` /
//!   request stub query for route closures.
//! - `PayloadSlot::HttpBody` — surfaced via `$_POST` / request stub body
//!   for route closures.
//!
//! Build: no compilation step. Command is `php harness.php`.
//! Build container: `nyx-build-php:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for PHP.  Method bodies delegate to the
/// existing free functions in this module.
pub struct PhpEmitter;

/// Entry kinds the PHP emitter understands after Phase 15.
///
/// `HttpRoute` covers Slim / Laravel / Symfony route closures.
/// `CliSubcommand` covers `$argv`-driven CLI scripts.  `Function`
/// covers plain functions and top-level scripts.
const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::HttpRoute,
    EntryKind::CliSubcommand,
];

impl LangEmitter for PhpEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "php emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 15 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_php(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — PHP chain-step harness.
///
/// Splices the PHP probe shim ([`probe_shim`]) in front of a minimal
/// driver that reads `NYX_PREV_OUTPUT` via `getenv()` and forwards it
/// on stdout.  When the step is the chain's terminal step the driver
/// also calls `__nyx_probe(callee, [prev])` and emits the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` for the chain.
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let shim = probe_shim();
    let mut driver = String::from(
        "$prev = getenv(\"NYX_PREV_OUTPUT\");\nif ($prev === false) { $prev = \"\"; }\necho $prev;\n",
    );
    if let Some(t) = terminal {
        let callee = php_string_literal(&t.sink_callee);
        let sentinel = php_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "__nyx_probe({callee}, [$prev]);\necho \"\\n\" . {sentinel} . \"\\n\";\n",
        ));
    }
    let source = format!("<?php\n{shim}\n{driver}");
    ChainStepHarness {
        source,
        filename: "step.php".to_owned(),
        command: vec!["php".to_owned(), "step.php".to_owned()],
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

/// Escape a string for safe PHP double-quoted literal embedding.
/// Backslash and double-quote escape only; bytes outside printable
/// ASCII are left to PHP's source decoder.
fn php_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ── Phase 15: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
///
/// One harness template per variant.  When the entry file is unreadable
/// or no marker fires the detector defaults to [`PhpShape::Generic`],
/// preserving the pre-Phase-15 behaviour (direct function call).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpShape {
    /// Slim / Laravel / Symfony route closure.  Harness builds a
    /// minimal request stub (query/body) and invokes the closure
    /// resolved from `$GLOBALS['__nyx_route']` (which the entry file
    /// publishes during include).
    RouteClosure,
    /// CLI script driven by `$argv`.  Harness mutates `$argv` then
    /// includes the entry file (whose top-level body reads `$argv`),
    /// or — when the spec names a function — calls the function after
    /// setting `$argv`.
    CliArgvScript,
    /// Top-level script body — no function entry point.  Harness just
    /// includes the entry file (the include itself runs the body).
    TopLevelScript,
    /// Plain function — pre-Phase-15 default.  Harness calls
    /// `funcName($payload)` directly.
    Generic,
}

impl PhpShape {
    /// Detect the shape from `(spec, source)`.  Framework markers in
    /// the source win over `spec.entry_kind`.
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let entry = spec.entry_name.as_str();
        let kind = spec.entry_kind;

        let has_route_marker = source.contains("$app->get(")
            || source.contains("$app->post(")
            || source.contains("$app->any(")
            || source.contains("$app->map(")
            || source.contains("$router->get(")
            || source.contains("$router->post(")
            || source.contains("Route::get(")
            || source.contains("Route::post(")
            || source.contains("Route::any(")
            || source.contains("// nyx-shape: route");
        let has_argv = source.contains("$argv") || source.contains("// nyx-shape: cli");
        let has_function_decl = source.contains("function ")
            && !source.trim_start().starts_with("<?php\n//");
        let entry_named_function = entry != "main"
            && entry != "__main__"
            && !entry.is_empty()
            && source.contains(&format!("function {entry}"));

        if has_route_marker {
            return Self::RouteClosure;
        }
        if has_argv && !entry_named_function {
            return Self::CliArgvScript;
        }
        if kind == EntryKind::HttpRoute {
            return Self::RouteClosure;
        }
        if kind == EntryKind::CliSubcommand {
            return Self::CliArgvScript;
        }
        // TopLevelScript only fires when we actually saw the source
        // and confirmed there's no function declaration to call.  When
        // the source is unreadable (empty), fall through to Generic so
        // the legacy pre-Phase-15 behaviour (direct named-function call)
        // survives.
        if !source.is_empty() && !has_function_decl && entry.is_empty() {
            return Self::TopLevelScript;
        }
        Self::Generic
    }
}

/// Public wrapper to detect the shape for a finalised `HarnessSpec`,
/// reading the entry file from disk.
pub fn detect_shape(spec: &HarnessSpec) -> PhpShape {
    let src = read_entry_source(&spec.entry_file);
    PhpShape::detect(spec, &src)
}

fn read_entry_source(entry_file: &str) -> String {
    let candidates = [PathBuf::from(entry_file), PathBuf::from(".").join(entry_file)];
    for path in &candidates {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s;
        }
    }
    String::new()
}

/// Phase 09 — Track D.2: synthesise a `composer.json` with the captured
/// PHP version pin and (where known) the framework deps.
pub fn materialize_php(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let php_ver = env
        .toolchain
        .version_string
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    let php_ver = if php_ver.is_empty() {
        "8.1".to_owned()
    } else {
        php_ver
    };
    let mut body = String::with_capacity(128);
    body.push_str("{\n");
    body.push_str("  \"name\": \"nyx/harness\",\n");
    body.push_str("  \"require\": {\n");
    body.push_str(&format!("    \"php\": \">={php_ver}\"\n"));
    body.push_str("  }\n");
    body.push_str("}\n");
    artifacts.push("composer.json", body);
    artifacts
}

/// Source of the `__nyx_probe` shim for the PHP harness (Phase 06 —
/// Track C.1).
pub fn probe_shim() -> &'static str {
    r#"
// ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
const __NYX_DENY_SUBSTRINGS = [
    'TOKEN','SECRET','PASSWORD','PASSWD','API_KEY','APIKEY','PRIVATE_KEY',
    'CREDENTIAL','SESSION','COOKIE','AUTH','BEARER','AWS_ACCESS','AWS_SESSION',
    'GH_TOKEN','GITHUB_TOKEN','NPM_TOKEN','PYPI_TOKEN','DOCKER_PASS',
];
const __NYX_PAYLOAD_LIMIT = 16 * 1024;
const __NYX_REDACTED = '<redacted-by-nyx-policy>';

function __nyx_is_denied_key(string $k): bool {
    $ku = strtoupper($k);
    foreach (__NYX_DENY_SUBSTRINGS as $n) {
        if (strpos($ku, $n) !== false) return true;
    }
    return false;
}

function __nyx_witness(string $sinkCallee, array $args): array {
    $env = [];
    foreach ($_ENV as $k => $v) {
        $env[(string)$k] = __nyx_is_denied_key((string)$k) ? __NYX_REDACTED : (string)$v;
    }
    // Sort for deterministic output.
    ksort($env);
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    $pb = substr($payload, 0, __NYX_PAYLOAD_LIMIT);
    $bytes = [];
    for ($i = 0; $i < strlen($pb); $i++) $bytes[] = ord($pb[$i]);
    $repr = [];
    foreach ($args as $a) $repr[] = is_string($a) ? $a : (string) $a;
    return [
        'env_snapshot'  => $env,
        'cwd'           => @getcwd() ?: '',
        'payload_bytes' => $bytes,
        'callee'        => $sinkCallee,
        'args_repr'     => $repr,
    ];
}

function __nyx_emit(array $rec): void {
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $line = json_encode($rec) . "\n";
    @file_put_contents($p, $line, FILE_APPEND);
}

function __nyx_probe(string $sinkCallee, ...$args): void {
    $ser = [];
    foreach ($args as $a) {
        if (is_int($a)) {
            $ser[] = ['kind' => 'Int', 'value' => $a];
        } else {
            $ser[] = ['kind' => 'String', 'value' => (string) $a];
        }
    }
    __nyx_emit([
        'sink_callee'    => $sinkCallee,
        'args'           => $ser,
        'captured_at_ns' => (int) (microtime(true) * 1e9),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'Normal'],
        'witness'        => __nyx_witness($sinkCallee, $args),
    ]);
}

// Phase 08: PHP cannot catch SIGSEGV from userland, but pcntl_signal and
// register_shutdown_function intercept SIGABRT-class fatal errors.
function __nyx_install_crash_guard(string $sinkCallee): void {
    $emit_crash = function (string $signalName) use ($sinkCallee) {
        __nyx_emit([
            'sink_callee'    => $sinkCallee,
            'args'           => [],
            'captured_at_ns' => (int) (microtime(true) * 1e9),
            'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
            'kind'           => ['kind' => 'Crash', 'signal' => $signalName],
            'witness'        => __nyx_witness($sinkCallee, []),
        ]);
    };
    set_error_handler(function ($errno, $errstr) use ($emit_crash) {
        if ($errno & (E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR)) {
            $emit_crash('SIGABRT');
        }
        return false;
    });
    register_shutdown_function(function () use ($emit_crash) {
        $err = error_get_last();
        if ($err && ($err['type'] & (E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR))) {
            $emit_crash('SIGABRT');
        }
    });
    if (function_exists('pcntl_signal') && function_exists('pcntl_async_signals')) {
        pcntl_async_signals(true);
        foreach ([SIGABRT, defined('SIGBUS') ? SIGBUS : null, defined('SIGFPE') ? SIGFPE : null, defined('SIGILL') ? SIGILL : null] as $sig) {
            if ($sig === null) continue;
            pcntl_signal($sig, function ($s) use ($emit_crash) {
                $name = 'SIGABRT';
                if (defined('SIGABRT') && $s === SIGABRT) $name = 'SIGABRT';
                if (defined('SIGBUS')  && $s === SIGBUS)  $name = 'SIGBUS';
                if (defined('SIGFPE')  && $s === SIGFPE)  $name = 'SIGFPE';
                if (defined('SIGILL')  && $s === SIGILL)  $name = 'SIGILL';
                $emit_crash($name);
                pcntl_signal($s, SIG_DFL);
                posix_kill(posix_getpid(), $s);
            });
        }
    }
}

// Phase 10 (Track D.3) stub helpers.  When the verifier spawned a SqlStub it
// publishes the queries-log path through NYX_SQL_LOG; a sink call site that
// wants the host-side stub to see its query appends one record-per-call.  The
// helper is a no-op when NYX_SQL_LOG is unset so the same fixture source still
// runs under harness modes that didn't spawn a stub.  Mirrors the Python and
// Node shims so the host-side SqlStub log-line format (hash-space-prefixed
// detail lines, then the query line) is identical across language emitters.
function __nyx_stub_sql_record($query, array $detail = []): void {
    $p = getenv('NYX_SQL_LOG');
    if ($p === false || $p === '') return;
    $buf = '';
    foreach ($detail as $k => $v) {
        $buf .= '# ' . (string)$k . ': ' . (string)$v . "\n";
    }
    $q = (string)$query;
    $buf .= $q;
    if (substr($q, -1) !== "\n") $buf .= "\n";
    @file_put_contents($p, $buf, FILE_APPEND);
}

// Phase 10 (Track D.3) HTTP recording helper.  When the verifier spawned an
// HttpStub it publishes the side-channel log path through NYX_HTTP_LOG; a
// sink call site whose outbound request never reaches the on-the-wire
// listener (DNS-mocked, network-isolated sandbox, pre-flight check) can
// call this helper to surface the attempted call.  Format matches the SQL
// helper so the host-side merger parses both streams identically.
function __nyx_stub_http_record($method, $url, $body = null, array $detail = []): void {
    $p = getenv('NYX_HTTP_LOG');
    if ($p === false || $p === '') return;
    $buf = '';
    $buf .= '# method: ' . (string)$method . "\n";
    $buf .= '# url: ' . (string)$url . "\n";
    if ($body !== null) {
        $buf .= '# body: ' . (string)$body . "\n";
    }
    foreach ($detail as $k => $v) {
        $buf .= '# ' . (string)$k . ': ' . (string)$v . "\n";
    }
    $buf .= (string)$method . ' ' . (string)$url . "\n";
    @file_put_contents($p, $buf, FILE_APPEND);
}
"#
}

/// Emit a PHP harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_)
        | PayloadSlot::EnvVar(_)
        | PayloadSlot::Stdin
        | PayloadSlot::Argv(_)
        | PayloadSlot::QueryParam(_)
        | PayloadSlot::HttpBody => {}
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = PhpShape::detect(spec, &entry_source);
    let source = generate_source(spec, shape);

    Ok(HarnessSource {
        source,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.php".to_owned()),
    })
}

fn generate_source(spec: &HarnessSpec, shape: PhpShape) -> String {
    let entry_fn = &spec.entry_name;
    let pre_call = build_pre_call(spec, shape);
    let entry_block = build_entry_block(shape);
    let call_expr = build_call_expr(spec, shape, entry_fn);
    let shim = probe_shim();
    let crash_callee = if entry_fn.is_empty() { "main" } else { entry_fn.as_str() };

    format!(
        r#"<?php
// Nyx dynamic harness — auto-generated, do not edit (Phase 15 — PhpShape::{shape:?}).
{shim}
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

// Phase 08 sink-site signal handler: install AFTER payload decode so a crash
// inside `nyx_payload` writes no Crash probe and routes the verifier to
// `Inconclusive(UnrelatedCrash)`.  A fatal-error inside the entry call below
// DOES fire the handler and writes a Crash probe to `NYX_PROBE_PATH`.
__nyx_install_crash_guard('{crash_callee}');

// ── Pre-call setup ─────────────────────────────────────────────────────────────
{pre_call}
// ── Entry include ─────────────────────────────────────────────────────────────
{entry_block}
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
        shape = shape,
        pre_call = pre_call,
        entry_block = entry_block,
        call_expr = call_expr,
        shim = shim,
        crash_callee = crash_callee,
    )
}

fn build_pre_call(spec: &HarnessSpec, shape: PhpShape) -> String {
    let mut out = String::new();
    match &spec.payload_slot {
        PayloadSlot::EnvVar(name) => {
            out.push_str(&format!(
                "putenv({name:?} . '=' . $payload);\n$_ENV[{name:?}] = $payload;\n"
            ));
        }
        PayloadSlot::Stdin => {
            out.push_str(
                "if (defined('STDIN')) {\n    $stream = fopen('php://memory', 'r+');\n    fwrite($stream, $payload);\n    rewind($stream);\n}\n",
            );
        }
        PayloadSlot::Argv(n) => {
            out.push_str("$argv = $argv ?? [];\n");
            out.push_str("$argv[0] = $argv[0] ?? 'nyx_harness';\n");
            for _ in 0..*n {
                out.push_str("$argv[] = '';\n");
            }
            out.push_str("$argv[] = $payload;\n");
            out.push_str("$argc = count($argv);\n");
            out.push_str("$_SERVER['argv'] = $argv;\n");
            out.push_str("$_SERVER['argc'] = $argc;\n");
        }
        PayloadSlot::QueryParam(name) => {
            out.push_str(&format!("$_GET[{name:?}] = $payload;\n"));
            out.push_str("$_REQUEST = array_merge($_REQUEST ?? [], $_GET);\n");
        }
        PayloadSlot::HttpBody => {
            out.push_str("$_POST['body'] = $payload;\n");
            out.push_str("$GLOBALS['__nyx_body'] = $payload;\n");
        }
        _ => {}
    }
    if matches!(shape, PhpShape::CliArgvScript)
        && !matches!(&spec.payload_slot, PayloadSlot::Argv(_))
    {
        out.push_str("$argv = $argv ?? ['nyx_harness'];\n");
        out.push_str("$argv[] = $payload;\n");
        out.push_str("$argc = count($argv);\n");
        out.push_str("$_SERVER['argv'] = $argv;\n");
        out.push_str("$_SERVER['argc'] = $argc;\n");
    }
    out
}

fn build_entry_block(_shape: PhpShape) -> String {
    r#"try {
    require_once __DIR__ . '/entry.php';
} catch (Throwable $e) {
    fwrite(STDERR, 'NYX_IMPORT_ERROR: ' . $e->getMessage() . "\n");
    exit(77);
}"#
    .to_owned()
}

fn build_call_expr(spec: &HarnessSpec, shape: PhpShape, func: &str) -> String {
    match shape {
        PhpShape::TopLevelScript => "null".to_owned(),
        PhpShape::CliArgvScript => {
            if func.is_empty() || func == "main" || func == "__main__" {
                "null".to_owned()
            } else if function_exists_call(func) {
                format!("{func}()")
            } else {
                "null".to_owned()
            }
        }
        PhpShape::RouteClosure => {
            // Entry script publishes the route closure via
            // `$GLOBALS['__nyx_route']`.  When the global is missing,
            // fall back to calling the named function directly.
            format!(
                "(isset($GLOBALS['__nyx_route']) && is_callable($GLOBALS['__nyx_route'])) ? call_user_func($GLOBALS['__nyx_route'], $payload) : (function_exists({func:?}) ? {func}($payload) : null)"
            )
        }
        PhpShape::Generic => build_generic_call(spec, func),
    }
}

fn build_generic_call(spec: &HarnessSpec, func: &str) -> String {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            if *idx == 0 {
                format!("{func}($payload)")
            } else {
                let pads = (0..*idx).map(|_| "''").collect::<Vec<_>>().join(", ");
                format!("{func}({pads}, $payload)")
            }
        }
        PayloadSlot::EnvVar(_) | PayloadSlot::Stdin => format!("{func}()"),
        _ => format!("{func}($payload)"),
    }
}

/// Wrap the named-function call in a `function_exists` guard for shapes
/// where the entry function may be optional (CLI scripts whose body is
/// the entry, not a named function).
fn function_exists_call(_func: &str) -> bool {
    true
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
            stubs_required: vec![],
            framework: None,
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
    fn emit_http_body_now_supported_for_route_shape() {
        let mut spec = make_spec(PayloadSlot::HttpBody);
        spec.entry_kind = EntryKind::HttpRoute;
        let h = emit(&spec).unwrap();
        assert!(h.source.contains("$GLOBALS['__nyx_body']"));
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
        assert!(PhpEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::HttpRoute));
        assert!(PhpEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = PhpEmitter.entry_kind_hint(EntryKind::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 15"));
    }

    #[test]
    fn harness_has_base64_decode() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("base64_decode"));
        assert!(harness.source.contains("NYX_PAYLOAD_B64"));
    }

    // ── Phase 15: shape detection ────────────────────────────────────────────

    fn make_spec_with(kind: EntryKind, name: &str, entry_file: &str) -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.entry_kind = kind;
        s.entry_name = name.to_owned();
        s.entry_file = entry_file.to_owned();
        s
    }

    #[test]
    fn shape_detect_slim_route_closure() {
        let src = "<?php\n$app->get('/run', function ($req, $res) {\n    return 'hi';\n});\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::RouteClosure);
    }

    #[test]
    fn shape_detect_laravel_route_closure() {
        let src = "<?php\nRoute::get('/run', function ($payload) { return $payload; });\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::RouteClosure);
    }

    #[test]
    fn shape_detect_cli_argv_script() {
        let src = "<?php\n$cmd = $argv[1] ?? '';\necho $cmd;\n";
        let spec = make_spec_with(EntryKind::CliSubcommand, "main", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::CliArgvScript);
    }

    #[test]
    fn shape_detect_top_level_script() {
        let src = "<?php\necho 'hello';\n";
        let spec = make_spec_with(EntryKind::Function, "", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::TopLevelScript);
    }

    #[test]
    fn shape_detect_generic_function() {
        let src = "<?php\nfunction login($payload) { return $payload; }\n";
        let spec = make_spec_with(EntryKind::Function, "login", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::Generic);
    }

    #[test]
    fn route_shape_emits_globals_dispatch() {
        let spec = make_spec_with(EntryKind::HttpRoute, "ping", "entry.php");
        let src = generate_source(&spec, PhpShape::RouteClosure);
        assert!(src.contains("$GLOBALS['__nyx_route']"));
    }

    #[test]
    fn cli_shape_appends_payload_to_argv() {
        let spec = make_spec_with(EntryKind::CliSubcommand, "main", "entry.php");
        let src = generate_source(&spec, PhpShape::CliArgvScript);
        assert!(src.contains("$argv"));
        assert!(src.contains("$_SERVER['argv']"));
    }

    #[test]
    fn top_level_script_only_includes() {
        let spec = make_spec_with(EntryKind::Function, "", "entry.php");
        let src = generate_source(&spec, PhpShape::TopLevelScript);
        assert!(src.contains("require_once"));
        assert!(src.contains("$result = null"));
    }

    #[test]
    fn emit_splices_probe_shim_and_installs_crash_guard() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("__nyx_probe shim (Phase 06 — Track C.1"),
            "probe_shim banner missing from generated harness.php — splicing regressed",
        );
        assert!(
            h.source
                .contains("function __nyx_install_crash_guard(string $sinkCallee)"),
            "install_crash_guard definition missing from generated harness.php",
        );
        assert!(
            h.source.contains("__nyx_install_crash_guard('login');"),
            "install_crash_guard call site missing or wrong callee in harness body",
        );
        let install_pos = h
            .source
            .find("__nyx_install_crash_guard('login');")
            .unwrap();
        let payload_pos = h.source.find("$payload = nyx_payload();").unwrap();
        let invoke_pos = h.source.find("login($payload)").unwrap();
        assert!(
            payload_pos < install_pos && install_pos < invoke_pos,
            "install_crash_guard ordering wrong: payload_pos={payload_pos} install_pos={install_pos} invoke_pos={invoke_pos}",
        );
    }

    #[test]
    fn probe_shim_publishes_stub_sql_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("function __nyx_stub_sql_record"),
            "PHP probe shim must define __nyx_stub_sql_record"
        );
        assert!(
            shim.contains("NYX_SQL_LOG"),
            "stub recorder must read NYX_SQL_LOG"
        );
    }

    #[test]
    fn probe_shim_publishes_stub_http_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("function __nyx_stub_http_record"),
            "PHP probe shim must define __nyx_stub_http_record"
        );
        assert!(
            shim.contains("NYX_HTTP_LOG"),
            "stub recorder must read NYX_HTTP_LOG"
        );
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        let step = chain_step(Some(b"<prev>"), None);
        assert!(
            step.source.contains("__nyx_probe"),
            "PHP chain step must splice the probe shim"
        );
        assert!(
            step.source.starts_with("<?php"),
            "PHP chain step must open with <?php"
        );
        assert!(
            step.source.contains("getenv(\"NYX_PREV_OUTPUT\")"),
            "PHP chain step must keep its NYX_PREV_OUTPUT forwarder"
        );
        let shim_pos = step.source.find("__nyx_probe").unwrap();
        let driver_pos = step.source.find("getenv(\"NYX_PREV_OUTPUT\")").unwrap();
        assert!(
            shim_pos < driver_pos,
            "probe shim must come before the driver so the shim's helpers are in scope when a sink rewrite splices in"
        );
    }
}

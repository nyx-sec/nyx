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
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
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
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::ClassMethod,
    EntryKindTag::Middleware,
    EntryKindTag::Migration,
];

impl LangEmitter for PhpEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "php emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 15 / 19 / 20 / 21 shape dispatch"
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
    /// Slim / generic route closure published via
    /// `$GLOBALS['__nyx_route']`.  Harness builds a minimal request
    /// stub (query/body) and invokes the closure resolved from the
    /// global (which the entry file publishes during include).
    RouteClosure,
    /// Laravel route — `Route::get('/x', 'Controller@method')` or
    /// closure callable.  Phase 16 v1 dispatches through the same
    /// `$GLOBALS['__nyx_route']` channel as `RouteClosure` but
    /// publishes a `NYX_LARAVEL_TEST=1` stdout marker so the
    /// verifier can confirm the framework toolchain knob propagated.
    LaravelRoute,
    /// Symfony route — `#[Route('/x')]` PHP attribute on a
    /// controller method or top-level function.  Phase 16 v1
    /// dispatches via reflective invocation (the entry file's
    /// `entry.php` instantiates the controller class and the harness
    /// calls the method) plus an `NYX_SYMFONY_TEST=1` stdout marker.
    SymfonyRoute,
    /// CodeIgniter route — `$routes->get('users/(:num)', ...)`
    /// published from `app/Config/Routes.php`.  Phase 16 v1
    /// dispatches via the `$GLOBALS['__nyx_route']` channel plus a
    /// `NYX_CODEIGNITER_TEST=1` stdout marker.
    CodeIgniterRoute,
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
        let kind = spec.entry_kind.tag();

        let has_symfony_marker = source.contains("#[Route(")
            || source.contains("Symfony\\Component\\Routing")
            || source.contains("Symfony\\Component\\HttpKernel")
            || source.contains("// nyx-shape: symfony");
        let has_laravel_marker = source.contains("Illuminate\\Support\\Facades\\Route")
            || source.contains("Illuminate\\Routing")
            || source.contains("Route::get(")
            || source.contains("Route::post(")
            || source.contains("Route::put(")
            || source.contains("Route::patch(")
            || source.contains("Route::delete(")
            || source.contains("Route::any(")
            || source.contains("Route::match(")
            || source.contains("App\\Http\\Controllers")
            || source.contains("// nyx-shape: laravel");
        let has_codeigniter_marker = source.contains("CodeIgniter\\Router")
            || source.contains("CodeIgniter\\HTTP")
            || source.contains("$routes->get(")
            || source.contains("$routes->post(")
            || source.contains("$routes->put(")
            || source.contains("$routes->patch(")
            || source.contains("$routes->delete(")
            || source.contains("$routes->add(")
            || source.contains("extends BaseController")
            || source.contains("// nyx-shape: codeigniter");
        let has_route_marker = source.contains("$app->get(")
            || source.contains("$app->post(")
            || source.contains("$app->any(")
            || source.contains("$app->map(")
            || source.contains("$router->get(")
            || source.contains("$router->post(")
            || source.contains("// nyx-shape: route");
        let has_argv = source.contains("$argv") || source.contains("// nyx-shape: cli");
        let has_function_decl =
            source.contains("function ") && !source.trim_start().starts_with("<?php\n//");
        let entry_named_function = entry != "main"
            && entry != "__main__"
            && !entry.is_empty()
            && source.contains(&format!("function {entry}"));

        if has_symfony_marker {
            return Self::SymfonyRoute;
        }
        if has_laravel_marker {
            return Self::LaravelRoute;
        }
        if has_codeigniter_marker {
            return Self::CodeIgniterRoute;
        }
        if has_route_marker {
            return Self::RouteClosure;
        }
        if has_argv && !entry_named_function {
            return Self::CliArgvScript;
        }
        if kind == EntryKindTag::HttpRoute {
            return Self::RouteClosure;
        }
        if kind == EntryKindTag::CliSubcommand {
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
    let candidates = [
        PathBuf::from(entry_file),
        PathBuf::from(".").join(entry_file),
    ];
    for path in &candidates {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s;
        }
    }
    String::new()
}

/// Map an entry file path like `tests/.../vuln.php` to the basename
/// (`vuln.php`) the harness will `require_once`.  Falls back to
/// `vuln.php` when the path is unusable so the harness still attempts
/// the require (the fallback inline matcher fires when the require
/// fails).
fn derive_php_entry_basename(entry_file: &str) -> String {
    PathBuf::from(entry_file)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "vuln.php".to_owned())
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

    // Phase 03 (Track J.1): deserialize-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::DESERIALIZE {
        return Ok(emit_deserialize_harness(spec));
    }
    // Phase 04 (Track J.2): SSTI-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::SSTI {
        return Ok(emit_ssti_harness(spec));
    }
    // Phase 05 (Track J.3): XXE-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::XXE {
        return Ok(emit_xxe_harness(spec));
    }
    // Phase 06 (Track J.4): LDAP_INJECTION-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::LDAP_INJECTION {
        return Ok(emit_ldap_harness(spec));
    }
    // Phase 07 (Track J.5): XPATH_INJECTION-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::XPATH_INJECTION {
        return Ok(emit_xpath_harness(spec));
    }
    // Phase 08 (Track J.6): HEADER_INJECTION-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }
    // Phase 09 (Track J.7): OPEN_REDIRECT-sink short-circuit.
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 19 (Track M.1): ClassMethod short-circuit.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(class, method));
    }

    // Phase 21 (Track M.3): Middleware short-circuit (Laravel handle()).
    if let crate::evidence::EntryKind::Middleware { name } = &spec.entry_kind {
        return Ok(emit_middleware_harness(&spec.entry_name, name));
    }

    // Phase 21 (Track M.3): Migration short-circuit (Laravel up()).
    if let crate::evidence::EntryKind::Migration { version } = &spec.entry_kind {
        return Ok(emit_migration_harness(&spec.entry_name, version.as_deref()));
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

/// Phase 03 — Track J.1 deserialize harness for PHP.
///
/// Forges a minimal valid PHP serialized object blob
/// (`O:<len>:"<class>":0:{{}}`) from the marker carried by
/// `NYX_PAYLOAD`, then runs it through `unserialize` with the
/// `allowed_classes` option set to a static allowlist
/// (`__primitive_int`, `__primitive_string`).  When the resulting
/// object is `__PHP_Incomplete_Class` and its preserved class name is
/// outside the allowlist, the shim writes a
/// [`crate::dynamic::probe::ProbeKind::Deserialize`] probe with
/// `gadget_chain_invoked: true` — matching the PHP 7+ hardening
/// pattern (`unserialize($s, ['allowed_classes' => […]])`).  Both
/// vuln and benign payloads reach the real `unserialize` call; the
/// allowlist post-check distinguishes them.
pub fn emit_deserialize_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"<?php
// Nyx dynamic harness — deserialize (Phase 03 / Track J.1).
{shim}

function _nyx_deserialize_probe(bool $invoked): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee' => 'unserialize',
        'args' => [],
        'captured_at_ns' => (int) (hrtime(true)),
        'payload_id' => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind' => ['kind' => 'Deserialize', 'gadget_chain_invoked' => $invoked],
        'witness' => __nyx_witness('unserialize', []),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

function _nyx_incomplete_class_name(object $o): string {{
    // __PHP_Incomplete_Class stores the original class name on a
    // private-named property; casting to array surfaces it under the
    // documented `__PHP_Incomplete_Class_Name` key.
    $arr = (array) $o;
    return (string) ($arr['__PHP_Incomplete_Class_Name'] ?? '');
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$prefix = 'NYX_GADGET_CLASS:';
if (strncmp($payload, $prefix, strlen($prefix)) === 0) {{
    $cls = substr($payload, strlen($prefix));
    $allowed = ['__primitive_int', '__primitive_string'];
    $blob = 'O:' . strlen($cls) . ':"' . $cls . '":0:{{}}';
    $result = @unserialize($blob, ['allowed_classes' => $allowed]);
    if (is_object($result) && $result instanceof __PHP_Incomplete_Class) {{
        $name = _nyx_incomplete_class_name($result);
        if (!in_array($name, $allowed, true)) {{
            _nyx_deserialize_probe(true);
        }}
    }}
}}
// Sink-reachability sentinel — runner's `vuln_fired && sink_hit`
// gate consumes this; without it differential confirmation cannot
// fire even when the probe was written.
echo "__NYX_SINK_HIT__\n";
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 04 — Track J.2 SSTI harness for PHP (Twig).
///
/// Reads `NYX_PAYLOAD`, simulates Twig's `{{expr}}` evaluation, prints
/// `{"render": "<result>"}` plus the sink-hit sentinel.  Synthetic
/// renderer keeps the corpus deterministic without bundling Twig in
/// the sandbox image.
pub fn emit_ssti_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"<?php
// Nyx dynamic harness — SSTI Twig (Phase 04 / Track J.2).
//
// Routes `NYX_PAYLOAD` through the real `twig/twig` composer
// package's `Twig\Environment::createTemplate(...)->render([])`
// call.  The corpus vuln payload `{{{{7*7}}}}` reaches Twig's
// expression evaluator and renders as `49`; the benign control
// `7*7` has no `{{{{` / `}}}}` markers so the engine echoes it
// verbatim.
require_once __DIR__ . '/vendor/autoload.php';

{shim}

function _nyx_twig_render(string $payload): string {{
    try {{
        $twig = new \Twig\Environment(new \Twig\Loader\ArrayLoader([]));
        $template = $twig->createTemplate($payload);
        return $template->render([]);
    }} catch (\Throwable $e) {{
        return '<twig-error:' . get_class($e) . '>';
    }}
}}

function _nyx_ssti_probe(string $rendered): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee' => 'Twig\\Environment::render',
        'args' => [['kind' => 'String', 'value' => $rendered]],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id' => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind' => ['kind' => 'Normal'],
        'witness' => __nyx_witness('Twig\\Environment::render', [$rendered]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$rendered = _nyx_twig_render($payload);
_nyx_ssti_probe($rendered);
echo "__NYX_SINK_HIT__\n";
echo json_encode(["render" => $rendered]) . "\n";
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![(
            "composer.json".to_owned(),
            r#"{
    "name": "nyx/ssti-twig-harness",
    "require": {
        "twig/twig": "^3.0"
    },
    "config": {
        "preferred-install": "dist"
    }
}
"#
            .to_owned(),
        )],
        entry_subpath: None,
    }
}

/// Phase 05 — Track J.3 XXE harness for PHP (`simplexml_load_string`).
///
/// Reads `NYX_PAYLOAD`, registers a real `libxml_set_external_entity_loader`
/// callback (the canonical PHP hook for external entity resolution),
/// parses the payload with `simplexml_load_string` under
/// `LIBXML_NOENT | LIBXML_DTDLOAD` (the configuration real XXE-prone
/// code uses), and writes a `ProbeKind::Xxe` probe whose
/// `entity_expanded` flag tracks whether the loader fired.  The
/// loader returns `null` so the harness never fetches the SYSTEM
/// resource, but the resolution boundary fires at the real parser
/// hook the brief calls out.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"<?php
// Nyx dynamic harness — XXE simplexml_load_string (Phase 05 / Track J.3).
{shim}

// Build the XML document fed into the parser.  Two shapes (Phase 05 OOB
// closure, 2026-05-21):
//   - URL-form NYX_PAYLOAD (`http://...` / `https://...`): treat as the
//     SYSTEM URL of an external entity and wrap into a canonical XXE
//     DTD.  The external-entity loader hook below performs the loopback
//     GET so the OOB listener observes the per-finding nonce.
//   - Anything else: treat as the full XML document (existing shape).
function _nyx_build_xxe_document(string $payload): string {{
    if (str_starts_with($payload, 'http://') || str_starts_with($payload, 'https://')) {{
        $escaped = str_replace(['&', '"', '<'], ['&amp;', '&quot;', '&lt;'], $payload);
        return "<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n  <!ENTITY xxe SYSTEM \"" . $escaped . "\">\n]>\n<data>&xxe;</data>";
    }}
    return $payload;
}}

function _nyx_libxml_parse(string $payload): bool {{
    $expanded = false;
    // Real parser hook: libxml calls this for every <!ENTITY name SYSTEM "uri">
    // reference resolved in the document.  Mark expanded.  When the
    // SYSTEM URL points at loopback HTTP, perform a real fetch so the
    // OOB listener observes the callback (Phase 05 OOB closure); other
    // schemes return null so the parser substitutes empty.
    libxml_set_external_entity_loader(function ($public, $system, $context) use (&$expanded) {{
        $expanded = true;
        if (is_string($system) && (
            str_starts_with($system, 'http://127.0.0.1')
            || str_starts_with($system, 'http://host-gateway')
            || str_starts_with($system, 'http://localhost')
        )) {{
            $ctx = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true]]);
            @file_get_contents($system, false, $ctx);
        }}
        return null;
    }});
    $prev_errors = libxml_use_internal_errors(true);
    // LIBXML_NOENT enables entity substitution (turning `&xxe;` into
    // the resolved body) and LIBXML_DTDLOAD allows the parser to load
    // the DTD declarations — the combination real XXE-vulnerable PHP
    // code passes to `simplexml_load_string`.
    $doc = _nyx_build_xxe_document($payload);
    @simplexml_load_string($doc, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
    libxml_clear_errors();
    libxml_use_internal_errors($prev_errors);
    // Reset the loader to default so nothing leaks across runs.
    libxml_set_external_entity_loader(null);
    return $expanded;
}}

function _nyx_xxe_probe(string $payload, bool $expanded): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'simplexml_load_string',
        'args'           => [['kind' => 'String', 'value' => $payload]],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'Xxe', 'entity_expanded' => $expanded],
        'witness'        => __nyx_witness('simplexml_load_string', [$payload]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$expanded = _nyx_libxml_parse($payload);
_nyx_xxe_probe($payload, $expanded);
echo "__NYX_SINK_HIT__\n";
echo json_encode(["entity_expanded" => $expanded]) . "\n";
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 06 — Track J.4 LDAP-injection harness for PHP (`ldap_search`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `(uid=<payload>)` filter,
/// evaluates the filter against the in-sandbox LDAP directory (three
/// users: `alice`, `bob`, `carol`) using the same RFC-4515 subset the
/// [`crate::dynamic::stubs::ldap_server`] stub implements, and writes
/// a `ProbeKind::Ldap { entries_returned }` probe whose `n` is the
/// count the directory returned.  Mirrors the synthetic-harness
/// pattern used by Phase 03 / 04 / 05.
pub fn emit_ldap_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"<?php
// Nyx dynamic harness — LDAP_INJECTION ldap_search (Phase 06 / Track J.4).
{shim}

$NYX_LDAP_USERS = ['alice', 'bob', 'carol'];

function _nyx_attr_match(string $pattern, string $uid): bool {{
    if ($pattern === '*') return true;
    $star = strpos($pattern, '*');
    if ($star === false) return $pattern === $uid;
    $prefix = substr($pattern, 0, $star);
    $suffix = substr($pattern, $star + 1);
    return str_starts_with($uid, $prefix) && str_ends_with($uid, $suffix);
}}

function _nyx_split_clauses(string $src): array {{
    $out = [];
    $i = 0;
    $n = strlen($src);
    while ($i < $n) {{
        if ($src[$i] !== '(') {{ $i++; continue; }}
        $depth = 0;
        $start = $i;
        while ($i < $n) {{
            $c = $src[$i];
            if ($c === '(') $depth++;
            elseif ($c === ')') {{
                $depth--;
                if ($depth === 0) {{ $i++; break; }}
            }}
            $i++;
        }}
        $out[] = substr($src, $start, $i - $start);
    }}
    return $out;
}}

function _nyx_inner_has_break(string $inner): bool {{
    $depth = 0;
    $n = strlen($inner);
    for ($i = 0; $i < $n; $i++) {{
        $c = $inner[$i];
        if ($c === '(') $depth++;
        elseif ($c === ')') {{
            $depth--;
            if ($depth < 0) return true;
        }}
    }}
    return false;
}}

function _nyx_match_one(string $filt, string $uid): bool {{
    $f = trim($filt);
    if (!(str_starts_with($f, '(') && str_ends_with($f, ')'))) return true;
    $inner = substr($f, 1, strlen($f) - 2);
    if (_nyx_inner_has_break($inner)) return true;
    if (str_starts_with($inner, '&') || str_starts_with($inner, '|')) {{
        $clauses = _nyx_split_clauses(substr($inner, 1));
        if (empty($clauses)) return false;
        $is_and = str_starts_with($inner, '&');
        $ok = $is_and;
        foreach ($clauses as $c) {{
            $m = _nyx_match_one($c, $uid);
            $ok = $is_and ? ($ok && $m) : ($ok || $m);
        }}
        return $ok;
    }}
    $eq = strpos($inner, '=');
    if ($eq === false) return true;
    $attr = strtolower(substr($inner, 0, $eq));
    $pattern = substr($inner, $eq + 1);
    if ($attr !== 'uid' && $attr !== 'cn') return true;
    return _nyx_attr_match($pattern, $uid);
}}

function _nyx_ldap_count_via_stub(string $filt): ?int {{
    $ep = getenv('NYX_LDAP_ENDPOINT');
    if ($ep === false || $ep === '') return null;
    $sep = strrpos($ep, ':');
    if ($sep === false || $sep === 0 || $sep === strlen($ep) - 1) return null;
    $host = substr($ep, 0, $sep);
    $port = (int) substr($ep, $sep + 1);
    if ($port <= 0) return null;
    $errno = 0;
    $errstr = '';
    $sock = @fsockopen($host, $port, $errno, $errstr, 2.0);
    if ($sock === false) return null;
    stream_set_timeout($sock, 2);
    @fwrite($sock, 'SEARCH ' . $filt . "\n");
    $line = @fgets($sock);
    @fclose($sock);
    if ($line === false) return null;
    $line = rtrim($line, "\r\n");
    if (!str_starts_with($line, 'COUNT ')) return null;
    $tail = trim(substr($line, strlen('COUNT ')));
    if ($tail === '' || !ctype_digit($tail)) return null;
    return (int) $tail;
}}

function _nyx_ldap_count_local(string $filt, array $users): int {{
    $f = trim($filt);
    if ($f === '') return 0;
    if (!(str_starts_with($f, '(') && str_ends_with($f, ')'))) return count($users);
    $inner = substr($f, 1, strlen($f) - 2);
    if (_nyx_inner_has_break($inner)) return count($users);
    $count = 0;
    foreach ($users as $u) {{
        if (_nyx_match_one($f, $u)) $count++;
    }}
    return $count;
}}

function _nyx_ldap_count(string $filt, array $users): int {{
    $via_stub = _nyx_ldap_count_via_stub($filt);
    if ($via_stub !== null) return $via_stub;
    return _nyx_ldap_count_local($filt, $users);
}}

function _nyx_ldap_probe(string $filt, int $entries_returned): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'ldap_search',
        'args'           => [['kind' => 'String', 'value' => $filt]],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'Ldap', 'entries_returned' => $entries_returned],
        'witness'        => __nyx_witness('ldap_search', [$filt]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$filt = '(uid=' . $payload . ')';
$count = _nyx_ldap_count($filt, $NYX_LDAP_USERS);
_nyx_ldap_probe($filt, $count);
echo "__NYX_SINK_HIT__\n";
echo json_encode(['filter' => $filt, 'entries_returned' => $count]) . "\n";
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 07 — Track J.5 XPath-injection harness for PHP
/// (`DOMXPath::query`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `//user[@name='<payload>']`
/// expression, evaluates the resulting expression against the
/// canonical XML staged in the workdir via
/// [`crate::dynamic::stubs::xpath_document`] (three `<user>`
/// records), and writes a `ProbeKind::Xpath { nodes_returned }`
/// probe whose `n` is the count the evaluator returned.  Mirrors the
/// synthetic-harness pattern used by Phase 03 / 04 / 05 / 06; a
/// future structural fix will link real `DOMXPath` via the staged
/// document.
pub fn emit_xpath_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let corpus_filename = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_FILENAME;
    let corpus_xml = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_XML;
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"<?php
// Nyx dynamic harness — XPATH_INJECTION DOMXPath::query (Phase 07 / Track J.5).
{shim}

// Synthetic in-process XPath evaluator over the canonical staged
// document — counts <user> nodes that satisfy the `[@name='…']`
// predicate the host code synthesised from the payload.  Real
// `DOMXPath::query` is not invoked (the harness ignores `_spec` and
// inlines the evaluator); the differential rule still holds because
// the vuln payload's `' or '1'='1` tail rewraps the selector into a
// match-everything shape.
$NYX_XPATH_USERS = ['alice', 'bob', 'carol'];

function _nyx_xpath_select($expr, array $users): int {{
    // Recognise the canonical `//user[@name='<payload>']` shape the
    // synthetic harness emits.  Anything else falls through to "no
    // match" so a malformed expression cannot accidentally confirm.
    $needle = "//user[@name=";
    if (strncmp($expr, $needle, strlen($needle)) !== 0) {{
        return 0;
    }}
    $rest = substr($expr, strlen($needle));
    if (!str_ends_with($rest, ']')) {{
        return 0;
    }}
    $predicate = substr($rest, 0, strlen($rest) - 1);
    if (preg_match("/^'([^']*)'(.*)\$/", $predicate, $m)) {{
        // `name='alice'`  → exact-match against the literal
        // `name='alice' or '1'='1'` → OR-tail breakouts; presence of
        //   ` or ` after the closing quote means the selector is now
        //   tautological → every user matches.
        $literal = $m[1];
        $tail = trim($m[2]);
        if ($tail === '' || $tail === ']') {{
            $count = 0;
            foreach ($users as $u) {{
                if ($u === $literal) $count++;
            }}
            return $count;
        }}
        if (preg_match("/^or\\s+/i", $tail)) {{
            return count($users);
        }}
    }}
    if (preg_match('/^"([^"]*)"\\s*$/', $predicate, $m)) {{
        $literal = $m[1];
        $count = 0;
        foreach ($users as $u) {{
            if ($u === $literal) $count++;
        }}
        return $count;
    }}
    if (preg_match("/^concat\\(/i", $predicate)) {{
        // `concat('a',\"'\",'b')` benign-escape path: extract the
        // joined literal and match exactly once.
        if (preg_match_all("/'([^']*)'/", $predicate, $parts)) {{
            $joined = '';
            foreach ($parts[1] as $p) {{
                if ($p === ',"') continue;
                $joined .= $p;
            }}
            // Normalise embedded single-quote literals back to the
            // raw character so a `concat`-quoted username collapses
            // to the same literal the user typed.
            $joined = str_replace(",\"'\",", "'", $joined);
            $count = 0;
            foreach ($users as $u) {{
                if ($u === $joined) $count++;
            }}
            return $count;
        }}
    }}
    return count($users);
}}

function _nyx_xpath_probe(string $expr, int $nodes_returned): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'DOMXPath::query',
        'args'           => [['kind' => 'String', 'value' => $expr]],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'Xpath', 'nodes_returned' => $nodes_returned],
        'witness'        => __nyx_witness('DOMXPath::query', [$expr]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

function _nyx_xpath_via_fixture(string $payload, string $entry_basename, string $entry_name): ?int {{
    // Phase 07 tier-(a): require the fixture file and call its
    // `$entry_name` function so the real `DOMXPath::query` runs
    // against the staged corpus document.  Returns the result-set
    // length, or `null` when the require / call fails so the caller
    // can fall back to the inline matcher.
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {{
        return null;
    }}
    try {{
        require_once $candidate;
    }} catch (\Throwable $_) {{
        return null;
    }}
    if (!function_exists($entry_name)) {{
        return null;
    }}
    try {{
        $result = $entry_name($payload);
    }} catch (\Throwable $_) {{
        // Malformed XPath / parse error — treat as a 0-node return so
        // a benign fixture that rejects the payload stays NotConfirmed.
        return 0;
    }}
    if ($result instanceof DOMNodeList) {{
        return $result->length;
    }}
    if (is_array($result)) {{
        return count($result);
    }}
    return null;
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$expr = "//user[@name='" . $payload . "']";
$nodes = _nyx_xpath_via_fixture($payload, "{entry_basename}", "{entry_name}");
if ($nodes === null) {{
    $nodes = _nyx_xpath_select($expr, $NYX_XPATH_USERS);
}}
_nyx_xpath_probe($expr, $nodes);
echo "__NYX_SINK_HIT__\n";
echo json_encode(['expr' => $expr, 'nodes_returned' => $nodes]) . "\n";
"#
    );
    let extra_files = vec![(corpus_filename.to_owned(), corpus_xml.to_owned())];
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files,
        entry_subpath: None,
    }
}

/// Phase 08 — Track J.6 header-injection harness for PHP (`header()`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented `header()`
/// shim that records the *unmodified* value bytes (including any
/// embedded `\r\n`) via a `ProbeKind::HeaderEmit` probe.  Mirrors
/// the synthetic-harness pattern used by Phase 03 / 04 / 05 / 06 /
/// 07.
pub fn emit_header_injection_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"<?php
// Nyx dynamic harness — HEADER_INJECTION header() (Phase 08 / Track J.6).
{shim}

function _nyx_header_probe(string $name, string $value): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'header()',
        'args'           => [
            ['kind' => 'String', 'value' => $name],
            ['kind' => 'String', 'value' => $value],
        ],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'HeaderEmit', 'name' => $name, 'value' => $value],
        'witness'        => __nyx_witness('header()', [$name, $value]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$name = 'Set-Cookie';
$value = $payload;
_nyx_header_probe($name, $value);
echo "__NYX_SINK_HIT__\n";
echo json_encode(['name' => $name, 'value' => $value]) . "\n";
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 09 — Track J.7 open-redirect harness for PHP (`header("Location: …")` /
/// `Response::redirect`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented redirect shim
/// that records the bound `Location:` value plus the request's origin
/// host via a `ProbeKind::Redirect` probe.  Mirrors the
/// synthetic-harness pattern used by Phase 03 / 04 / 05 / 06 / 07 / 08.
pub fn emit_open_redirect_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"<?php
// Nyx dynamic harness — OPEN_REDIRECT Response::redirect (Phase 09 / Track J.7).
{shim}

function _nyx_redirect_probe(string $location, string $requestHost): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'Response::redirect',
        'args'           => [
            ['kind' => 'String', 'value' => $location],
        ],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => [
            'kind' => 'Redirect',
            'location' => $location,
            'request_host' => $requestHost,
        ],
        'witness'        => __nyx_witness('Response::redirect', [$location]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$requestHost = 'example.com';
$location = $payload;
_nyx_redirect_probe($location, $requestHost);
echo "__NYX_SINK_HIT__\n";
echo json_encode(['location' => $location, 'request_host' => $requestHost]) . "\n";
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

fn generate_source(spec: &HarnessSpec, shape: PhpShape) -> String {
    let entry_fn = &spec.entry_name;
    let pre_call = build_pre_call(spec, shape);
    let entry_block = build_entry_block(shape);
    let call_expr = build_call_expr(spec, shape, entry_fn);
    let shim = probe_shim();
    let toolchain_marker = build_toolchain_marker(shape);
    let crash_callee = if entry_fn.is_empty() {
        "main"
    } else {
        entry_fn.as_str()
    };

    format!(
        r#"<?php
// Nyx dynamic harness — auto-generated, do not edit (Phase 16 — PhpShape::{shape:?}).
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
// ── Framework toolchain marker (Phase 16 — Track L.14) ────────────────────────
{toolchain_marker}// ── Call entry point ──────────────────────────────────────────────────────────
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
        toolchain_marker = toolchain_marker,
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

/// Phase 19 (Track M.1) — class-method harness for PHP.
///
/// Includes the entry file, instantiates the class via its default
/// constructor (`new $class()`), falls back to a single mock-dependency
/// ctor when the zero-arg path throws, then invokes
/// `$instance->method($payload)`.
fn emit_class_method_harness(class: &str, method: &str) -> HarnessSource {
    let shim = probe_shim();
    let mock_http = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::HttpClient,
        crate::symbol::Lang::Php,
    );
    let mock_db = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::DatabaseConnection,
        crate::symbol::Lang::Php,
    );
    let mock_log = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::Logger,
        crate::symbol::Lang::Php,
    );
    let body = format!(
        r#"<?php
// Nyx dynamic harness — class method (Phase 19 / Track M.1).
{shim}
{mock_http}
{mock_db}
{mock_log}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$_b64 = getenv('NYX_PAYLOAD_B64');
if ((!$payload || $payload === '') && is_string($_b64) && $_b64 !== '') {{
    $decoded = base64_decode($_b64, true);
    if ($decoded !== false) $payload = $decoded;
}}

try {{
    require_once __DIR__ . '/entry.php';
}} catch (Throwable $e) {{
    fwrite(STDERR, 'NYX_IMPORT_ERROR: ' . $e->getMessage() . "\n");
    exit(77);
}}

function _nyx_build_receiver(string $cls) {{
    if (!class_exists($cls)) return null;
    try {{ return new $cls(); }} catch (Throwable $e) {{}}
    $rc = new ReflectionClass($cls);
    $ctor = $rc->getConstructor();
    if ($ctor === null) {{
        try {{ return $rc->newInstanceWithoutConstructor(); }} catch (Throwable $e) {{}}
        return null;
    }}
    $args = [];
    foreach ($ctor->getParameters() as $p) {{
        $n = strtolower($p->getName());
        if (strpos($n, 'http') !== false || strpos($n, 'client') !== false) {{
            $args[] = new MockHttpClient();
        }} elseif (strpos($n, 'db') !== false || strpos($n, 'conn') !== false || strpos($n, 'repo') !== false || strpos($n, 'session') !== false) {{
            $args[] = new MockDatabaseConnection();
        }} elseif (strpos($n, 'log') !== false) {{
            $args[] = new MockLogger();
        }} else {{
            $args[] = null;
        }}
    }}
    try {{ return $rc->newInstanceArgs($args); }} catch (Throwable $e) {{}}
    return null;
}}

$instance = _nyx_build_receiver({class_lit:?});
if ($instance === null) {{
    fwrite(STDERR, "NYX_CLASS_CTOR_FAILED: " . {class_lit:?} . "\n");
    exit(78);
}}
if (!method_exists($instance, {method_lit:?})) {{
    fwrite(STDERR, "NYX_METHOD_NOT_FOUND: " . {method_lit:?} . "\n");
    exit(78);
}}
try {{
    $result = call_user_func([$instance, {method_lit:?}], $payload);
    if ($result !== null) {{
        echo $result . "\n";
    }}
}} catch (Throwable $e) {{
    fwrite(STDERR, 'NYX_EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
}}
"#,
        class_lit = class,
        method_lit = method,
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.php".to_owned()),
    }
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

fn nyx_php_preamble() -> String {
    let shim = probe_shim();
    format!(
        r#"<?php
// Nyx dynamic harness — Phase 21 / Track M.3 (auto-generated).
{shim}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$_b64 = getenv('NYX_PAYLOAD_B64');
if ((!$payload || $payload === '') && is_string($_b64) && $_b64 !== '') {{
    $decoded = base64_decode($_b64, true);
    if ($decoded !== false) $payload = $decoded;
}}

try {{
    require_once __DIR__ . '/entry.php';
}} catch (Throwable $e) {{
    fwrite(STDERR, 'NYX_IMPORT_ERROR: ' . $e->getMessage() . "\n");
    exit(77);
}}

echo "__NYX_SINK_HIT__\n";
"#,
        shim = shim,
    )
}

fn emit_middleware_harness(handler: &str, name: &str) -> HarnessSource {
    let preamble = nyx_php_preamble();
    let body = format!(
        r#"{preamble}
echo "__NYX_MIDDLEWARE__: " . {name:?} . "\n";

$req = new stdClass();
$req->body = $payload;
$req->path = '/nyx';
$req->method = 'POST';
$req->query = [ 'q' => $payload ];
$next = function ($r) {{ return $r; }};

if (class_exists({handler:?})) {{
    $inst = new {handler}();
    if (method_exists($inst, 'handle')) {{
        try {{
            $result = $inst->handle($req, $next);
            if ($result !== null) echo (string)$result . "\n";
        }} catch (Throwable $e) {{
            fwrite(STDERR, 'NYX_EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
        }}
    }} else {{
        fwrite(STDERR, 'NYX_METHOD_NOT_FOUND: handle' . "\n");
        exit(78);
    }}
}} elseif (function_exists({handler:?})) {{
    try {{
        $result = call_user_func({handler:?}, $req, $next);
        if ($result !== null) echo (string)$result . "\n";
    }} catch (Throwable $e) {{
        fwrite(STDERR, 'NYX_EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
    }}
}} else {{
    fwrite(STDERR, 'NYX_HANDLER_NOT_FOUND: ' . {handler:?} . "\n");
    exit(78);
}}
"#,
        preamble = preamble,
        handler = handler,
        name = name,
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.php".to_owned()),
    }
}

fn emit_migration_harness(handler: &str, version: Option<&str>) -> HarnessSource {
    let preamble = nyx_php_preamble();
    let version_repr = version.unwrap_or("<no-version>");
    let body = format!(
        r#"{preamble}
echo "__NYX_MIGRATION__: " . {version:?} . "\n";

if (class_exists({handler:?})) {{
    $inst = new {handler}();
    if (method_exists($inst, 'up')) {{
        try {{
            $result = $inst->up();
            if ($result !== null) echo (string)$result . "\n";
        }} catch (Throwable $e) {{
            fwrite(STDERR, 'NYX_EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
        }}
    }} else {{
        fwrite(STDERR, 'NYX_METHOD_NOT_FOUND: up' . "\n");
        exit(78);
    }}
}} elseif (function_exists({handler:?})) {{
    try {{
        $result = call_user_func({handler:?});
        if ($result !== null) echo (string)$result . "\n";
    }} catch (Throwable $e) {{
        fwrite(STDERR, 'NYX_EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
    }}
}} else {{
    fwrite(STDERR, 'NYX_HANDLER_NOT_FOUND: ' . {handler:?} . "\n");
    exit(78);
}}
"#,
        preamble = preamble,
        handler = handler,
        version = version_repr,
    );
    HarnessSource {
        source: body,
        filename: "harness.php".to_owned(),
        command: vec!["php".to_owned(), "harness.php".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.php".to_owned()),
    }
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
        PhpShape::RouteClosure | PhpShape::LaravelRoute | PhpShape::CodeIgniterRoute => {
            // Entry script publishes the route closure via
            // `$GLOBALS['__nyx_route']`.  When the global is missing,
            // fall back to calling the named function directly.
            format!(
                "(isset($GLOBALS['__nyx_route']) && is_callable($GLOBALS['__nyx_route'])) ? call_user_func($GLOBALS['__nyx_route'], $payload) : (function_exists({func:?}) ? {func}($payload) : null)"
            )
        }
        PhpShape::SymfonyRoute => {
            // Symfony controllers are normally reached through
            // `HttpKernel::handle`.  The Phase 16 v1 harness drives
            // the action directly: the entry file publishes a
            // controller instance via `$GLOBALS['__nyx_controller']`
            // and the harness reflectively invokes the action method.
            // Falls back to calling a bare function when no
            // controller class was published.
            format!(
                "(isset($GLOBALS['__nyx_controller']) && is_object($GLOBALS['__nyx_controller'])) ? $GLOBALS['__nyx_controller']->{func}($payload) : (function_exists({func:?}) ? {func}($payload) : null)"
            )
        }
        PhpShape::Generic => build_generic_call(spec, func),
    }
}

/// Per-shape stdout toolchain markers.  Mirrors the Phase 14
/// `JavaShape::SpringController` `NYX_SPRING_TEST` stdout marker so
/// the verifier can confirm a framework knob propagated through to
/// the harness — even though the v1 invocation path is reflective.
fn build_toolchain_marker(shape: PhpShape) -> &'static str {
    match shape {
        PhpShape::LaravelRoute => "echo \"NYX_LARAVEL_TEST=1\\n\";\n",
        PhpShape::SymfonyRoute => "echo \"NYX_SYMFONY_TEST=1\\n\";\n",
        PhpShape::CodeIgniterRoute => "echo \"NYX_CODEIGNITER_TEST=1\\n\";\n",
        _ => "",
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
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
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
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
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
        assert!(
            PhpEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
        assert!(
            PhpEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::HttpRoute)
        );
        assert!(
            PhpEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::CliSubcommand)
        );
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = PhpEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
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
        // Phase 16 reroutes Laravel-marker sources to the dedicated
        // LaravelRoute shape so the harness can emit the
        // `NYX_LARAVEL_TEST=1` toolchain stdout marker (mirroring the
        // Phase 14 Spring `NYX_SPRING_TEST=1` channel).
        let src = "<?php\nRoute::get('/run', function ($payload) { return $payload; });\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::LaravelRoute);
    }

    #[test]
    fn shape_detect_symfony_route_attribute() {
        let src = "<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\nclass C {\n  #[Route('/run')]\n  public function run($p) { return $p; }\n}\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::SymfonyRoute);
    }

    #[test]
    fn shape_detect_codeigniter_route() {
        let src = "<?php\nuse CodeIgniter\\Router\\RouteCollection;\n$routes->get('run', 'UserController::run');\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        assert_eq!(PhpShape::detect(&spec, src), PhpShape::CodeIgniterRoute);
    }

    #[test]
    fn laravel_shape_emits_toolchain_marker() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        let src = generate_source(&spec, PhpShape::LaravelRoute);
        assert!(src.contains("NYX_LARAVEL_TEST=1"));
        assert!(src.contains("$GLOBALS['__nyx_route']"));
    }

    #[test]
    fn symfony_shape_emits_toolchain_marker_and_controller_dispatch() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        let src = generate_source(&spec, PhpShape::SymfonyRoute);
        assert!(src.contains("NYX_SYMFONY_TEST=1"));
        assert!(src.contains("$GLOBALS['__nyx_controller']"));
        assert!(src.contains("->run($payload)"));
    }

    #[test]
    fn codeigniter_shape_emits_toolchain_marker() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.php");
        let src = generate_source(&spec, PhpShape::CodeIgniterRoute);
        assert!(src.contains("NYX_CODEIGNITER_TEST=1"));
        assert!(src.contains("$GLOBALS['__nyx_route']"));
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

    fn make_ldap_spec() -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.expected_cap = Cap::LDAP_INJECTION;
        s.entry_name = "run".into();
        s
    }

    #[test]
    fn emit_ldap_harness_routes_through_stub_when_endpoint_set() {
        let h = emit_ldap_harness(&make_ldap_spec());
        assert!(
            h.source.contains("NYX_LDAP_ENDPOINT"),
            "PHP LDAP harness must read NYX_LDAP_ENDPOINT to route through the stub",
        );
        assert!(
            h.source.contains("fsockopen("),
            "PHP LDAP harness must open a TCP socket against the stub endpoint",
        );
        assert!(
            h.source.contains("'SEARCH '"),
            "PHP LDAP harness must write SEARCH <filter> over the wire",
        );
        assert!(
            h.source.contains("'COUNT '"),
            "PHP LDAP harness must parse the COUNT <n> reply line",
        );
    }

    #[test]
    fn emit_ldap_harness_retains_local_matcher_fallback() {
        let h = emit_ldap_harness(&make_ldap_spec());
        assert!(
            h.source.contains("_nyx_ldap_count_local"),
            "PHP LDAP harness must keep the in-process matcher as a fallback for hosts without the stub",
        );
        assert!(
            h.source.contains("_nyx_ldap_count_via_stub"),
            "PHP LDAP harness must dispatch through the stub-route helper",
        );
    }

    fn make_xpath_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::XPATH_INJECTION;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_xpath_harness_routes_through_fixture_require() {
        let h = emit_xpath_harness(&make_xpath_spec(
            "tests/dynamic_fixtures/xpath_injection/php/vuln.php",
            "run",
        ));
        assert_eq!(h.extra_files.len(), 1);
        assert_eq!(h.extra_files[0].0, "xpath_corpus.xml");
        assert!(
            h.source.contains("function _nyx_xpath_via_fixture("),
            "PHP XPath harness must define the fixture-routing helper",
        );
        assert!(
            h.source.contains("require_once $candidate"),
            "PHP XPath harness must require the entry fixture before invoking it",
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "PHP XPath harness must pass the entry basename to the helper",
        );
        assert!(
            h.source.contains("\"run\""),
            "PHP XPath harness must pass the entry function name to the helper",
        );
        assert!(
            h.source.contains("$result instanceof DOMNodeList"),
            "PHP XPath harness must check the result against DOMNodeList",
        );
        assert!(
            h.source
                .contains("$nodes = _nyx_xpath_select($expr, $NYX_XPATH_USERS);"),
            "PHP XPath harness must keep the inline matcher as a fallback",
        );
    }

    #[test]
    fn emit_xpath_harness_derives_basename_from_entry_file() {
        let h = emit_xpath_harness(&make_xpath_spec("/abs/path/benign.php", "run"));
        assert!(
            h.source.contains("\"benign.php\""),
            "PHP XPath harness must use the entry-file basename, not a hard-coded literal",
        );
    }
}

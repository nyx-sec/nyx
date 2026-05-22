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
    // Cast env to object so json_encode emits `{}` (a JSON map) when
    // `$_ENV` is empty.  PHP's default `variables_order` (`GPCS`)
    // leaves `$_ENV` empty, and an empty PHP array json_encodes to
    // `[]` (a JSON sequence) — which fails to deserialise on the host
    // side as `BTreeMap<String, String>` and would drop every probe
    // record on hosts without `E` in `variables_order`.
    return [
        'env_snapshot'  => (object) $env,
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
    // Phase 11 (Track J.9): CRYPTO weak-RNG short-circuit.  The PHP
    // harness requires the fixture (in a synthetic `Nyx\Captured`
    // namespace so the entry's top-level statements are isolated),
    // invokes `<entry_name>($payload)`, and reduces the produced key
    // into a `ProbeKind::WeakKey { key_int }` record.  Int returns flow
    // through as u64 (masked to PHP_INT_MAX so the sign bit does not
    // flip a 16-bit predicate); string/bytes returns get truncated to
    // the leading 8 bytes via `unpack('J', ...)` with left-zero-pad so
    // a `random_bytes(32)` benign control trivially overshoots any
    // 16-bit budget while `mt_rand(0, 0xFFFF)` stays inside it.
    if spec.expected_cap == crate::labels::Cap::CRYPTO {
        return Ok(emit_crypto_harness(spec));
    }

    // JSON_PARSE depth-bomb short-circuit.  PHP
    // cannot monkey-patch the `json_decode` builtin, so the harness
    // publishes a global `_nyx_json_decode` helper that the fixture
    // calls in place of the builtin.  Inside the captured namespace
    // PHP's unqualified function-call resolution falls back to the
    // global namespace, so a fixture that calls `_nyx_json_decode(...)`
    // routes through the harness helper without further annotation.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 11 (Track J.9): UNAUTHORIZED_ID harness.  Requires the
    // fixture, invokes the named entry with the payload as the
    // requested owner_id, and emits a
    // `ProbeKind::IdorAccess { caller_id, owner_id }` whenever the
    // fixture materialises a non-null record.  The
    // `IdorBoundaryCrossed` predicate fires when `caller_id != owner_id`.
    if spec.expected_cap == crate::labels::Cap::UNAUTHORIZED_ID {
        return Ok(emit_unauthorized_id_harness(spec));
    }

    // Phase 11 (Track J.9): DATA_EXFIL harness.  Registers a stream
    // wrapper against the `http` + `https` schemes so any outbound
    // `file_get_contents` / `fopen` / `stream_*` call from the fixture
    // is intercepted before the wire I/O: the URL's host is parsed via
    // `parse_url(PHP_URL_HOST)`, a
    // [`crate::dynamic::probe::ProbeKind::OutboundNetwork`] probe is
    // emitted, and the wrapper returns an empty stream so the fixture's
    // caller never blocks on the network.
    if spec.expected_cap == crate::labels::Cap::DATA_EXFIL {
        return Ok(emit_data_exfil_harness(spec));
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
/// and — when `NYX_LDAP_ENDPOINT` is set — routes the search through
/// the in-sandbox LDAP stub over the real LDAPv3 BER wire (the stub's
/// accept loop at [`crate::dynamic::stubs::ldap_server::accept_loop`]
/// auto-detects the `0x30 SEQUENCE` lead byte and routes through the
/// reader/writer at [`crate::dynamic::stubs::ldap_ber`]).  Falls back
/// to an in-process RFC 4515 subset matcher against three canonical
/// users (`alice`, `bob`, `carol`) when the env var is unset, the
/// filter does not parse as a supported RFC 4515 shape, or the socket
/// exchange errors, so the harness still produces a verdict on hosts
/// that exercise it outside the stub-backed corpus.  Writes a
/// `ProbeKind::Ldap { entries_returned }` probe whose `n` is the
/// count the directory returned.  The BER client is core-PHP only
/// (`fsockopen` / `fwrite` / `fread`) so no `ext-ldap` extension is
/// required.
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

// --- LDAPv3 BER client (zero-dep, core PHP only) -------------------------
// Tags this client emits / consumes.  Mirrors `src/dynamic/stubs/ldap_ber.rs`.
const _NYX_BER_BOOLEAN = 0x01;
const _NYX_BER_INTEGER = 0x02;
const _NYX_BER_OCTET_STRING = 0x04;
const _NYX_BER_ENUMERATED = 0x0A;
const _NYX_BER_SEQUENCE = 0x30;
const _NYX_BER_BIND_REQUEST = 0x60;
const _NYX_BER_BIND_RESPONSE = 0x61;
const _NYX_BER_SEARCH_REQUEST = 0x63;
const _NYX_BER_SEARCH_RESULT_ENTRY = 0x64;
const _NYX_BER_SEARCH_RESULT_DONE = 0x65;
const _NYX_BER_AUTH_SIMPLE = 0x80;
const _NYX_BER_FILTER_AND = 0xA0;
const _NYX_BER_FILTER_OR = 0xA1;
const _NYX_BER_FILTER_EQUALITY = 0xA3;
const _NYX_BER_FILTER_SUBSTRINGS = 0xA4;
const _NYX_BER_FILTER_PRESENT = 0x87;
const _NYX_BER_SUBSTR_INITIAL = 0x80;
const _NYX_BER_SUBSTR_ANY = 0x81;
const _NYX_BER_SUBSTR_FINAL = 0x82;

function _nyx_ber_length(int $n): string {{
    if ($n < 0x80) return chr($n);
    $tmp = '';
    while ($n > 0) {{
        $tmp = chr($n & 0xFF) . $tmp;
        $n >>= 8;
    }}
    return chr(0x80 | strlen($tmp)) . $tmp;
}}

function _nyx_ber_tlv(int $tag, string $body): string {{
    return chr($tag) . _nyx_ber_length(strlen($body)) . $body;
}}

function _nyx_ber_int(int $n): ?string {{
    if ($n < 0) return null;
    if ($n === 0) {{
        $body = "\x00";
    }} else {{
        $tmp = '';
        while ($n > 0) {{
            $tmp = chr($n & 0xFF) . $tmp;
            $n >>= 8;
        }}
        if (ord($tmp[0]) & 0x80) {{
            $tmp = "\x00" . $tmp;
        }}
        $body = $tmp;
    }}
    return _nyx_ber_tlv(_NYX_BER_INTEGER, $body);
}}

function _nyx_ber_enum(int $n): string {{
    return _nyx_ber_tlv(_NYX_BER_ENUMERATED, chr($n & 0xFF));
}}

function _nyx_ber_octstr(string $s): string {{
    return _nyx_ber_tlv(_NYX_BER_OCTET_STRING, $s);
}}

function _nyx_ber_bool(bool $b): string {{
    return _nyx_ber_tlv(_NYX_BER_BOOLEAN, $b ? "\xFF" : "\x00");
}}

function _nyx_ber_seq(string $body): string {{
    return _nyx_ber_tlv(_NYX_BER_SEQUENCE, $body);
}}

function _nyx_valid_attr(string $a): bool {{
    if ($a === '') return false;
    $n = strlen($a);
    for ($i = 0; $i < $n; $i++) {{
        $c = $a[$i];
        if (!(ctype_alnum($c) || $c === '-' || $c === '_' || $c === '.')) return false;
    }}
    return true;
}}

function _nyx_split_paren_children(string $s): ?array {{
    $out = [];
    $i = 0;
    $n = strlen($s);
    while ($i < $n) {{
        if ($s[$i] !== '(') return null;
        $depth = 0;
        $start = $i;
        while ($i < $n) {{
            $c = $s[$i];
            if ($c === '(') $depth++;
            elseif ($c === ')') {{
                $depth--;
                if ($depth === 0) {{ $i++; break; }}
            }}
            $i++;
        }}
        if ($depth !== 0) return null;
        $out[] = substr($s, $start, $i - $start);
    }}
    return $out;
}}

function _nyx_encode_filter(string $filt): ?string {{
    $s = trim($filt);
    if (!str_starts_with($s, '(') || !str_ends_with($s, ')')) return null;
    $depth = 0;
    $n = strlen($s);
    for ($i = 0; $i < $n; $i++) {{
        $c = $s[$i];
        if ($c === '(') $depth++;
        elseif ($c === ')') {{
            $depth--;
            if ($depth < 0) return null;
            if ($depth === 0 && $i !== $n - 1) return null;
        }}
    }}
    if ($depth !== 0) return null;
    $inner = substr($s, 1, strlen($s) - 2);
    if ($inner === '') return null;
    $head = $inner[0];
    if ($head === '&' || $head === '|') {{
        $children = _nyx_split_paren_children(substr($inner, 1));
        if ($children === null || empty($children)) return null;
        $parts = '';
        foreach ($children as $c) {{
            $sub = _nyx_encode_filter($c);
            if ($sub === null) return null;
            $parts .= $sub;
        }}
        $tag = $head === '&' ? _NYX_BER_FILTER_AND : _NYX_BER_FILTER_OR;
        return _nyx_ber_tlv($tag, $parts);
    }}
    $eq = strpos($inner, '=');
    if ($eq === false) return null;
    $attr = substr($inner, 0, $eq);
    $val = substr($inner, $eq + 1);
    if (!_nyx_valid_attr($attr)) return null;
    if ($val === '*') {{
        return _nyx_ber_tlv(_NYX_BER_FILTER_PRESENT, $attr);
    }}
    if (strpos($val, '*') !== false) {{
        $parts = explode('*', $val);
        $last = count($parts) - 1;
        $seq = '';
        if ($parts[0] !== '') {{
            $seq .= _nyx_ber_tlv(_NYX_BER_SUBSTR_INITIAL, $parts[0]);
        }}
        for ($i = 1; $i < $last; $i++) {{
            if ($parts[$i] !== '') {{
                $seq .= _nyx_ber_tlv(_NYX_BER_SUBSTR_ANY, $parts[$i]);
            }}
        }}
        if ($parts[$last] !== '') {{
            $seq .= _nyx_ber_tlv(_NYX_BER_SUBSTR_FINAL, $parts[$last]);
        }}
        $body = _nyx_ber_octstr($attr) . _nyx_ber_seq($seq);
        return _nyx_ber_tlv(_NYX_BER_FILTER_SUBSTRINGS, $body);
    }}
    $body = _nyx_ber_octstr($attr) . _nyx_ber_octstr($val);
    return _nyx_ber_tlv(_NYX_BER_FILTER_EQUALITY, $body);
}}

function _nyx_read_n($sock, int $n): ?string {{
    $out = '';
    while (strlen($out) < $n) {{
        $chunk = @fread($sock, $n - strlen($out));
        if ($chunk === false || $chunk === '') return null;
        $out .= $chunk;
    }}
    return $out;
}}

function _nyx_read_ber_message($sock): ?string {{
    $head = _nyx_read_n($sock, 2);
    if ($head === null || ord($head[0]) !== _NYX_BER_SEQUENCE) return null;
    $first_len = ord($head[1]);
    if (($first_len & 0x80) === 0) {{
        $body_len = $first_len;
        $length_bytes = '';
    }} else {{
        $nl = $first_len & 0x7F;
        if ($nl === 0 || $nl > 4) return null;
        $length_bytes = _nyx_read_n($sock, $nl);
        if ($length_bytes === null) return null;
        $body_len = 0;
        for ($i = 0; $i < $nl; $i++) {{
            $body_len = ($body_len << 8) | ord($length_bytes[$i]);
        }}
    }}
    if ($body_len > 64 * 1024) return null;
    $body = _nyx_read_n($sock, $body_len);
    if ($body === null) return null;
    return $head . $length_bytes . $body;
}}

function _nyx_decode_tlv(string $buf, int $offset): ?array {{
    if ($offset + 2 > strlen($buf)) return null;
    $tag = ord($buf[$offset]);
    $first_len = ord($buf[$offset + 1]);
    if (($first_len & 0x80) === 0) {{
        $body_len = $first_len;
        $body_start = $offset + 2;
    }} else {{
        $nl = $first_len & 0x7F;
        if ($nl === 0 || $nl > 4 || $offset + 2 + $nl > strlen($buf)) return null;
        $body_len = 0;
        for ($i = 0; $i < $nl; $i++) {{
            $body_len = ($body_len << 8) | ord($buf[$offset + 2 + $i]);
        }}
        $body_start = $offset + 2 + $nl;
    }}
    $body_end = $body_start + $body_len;
    if ($body_end > strlen($buf)) return null;
    return [$tag, substr($buf, $body_start, $body_len), $body_end];
}}

function _nyx_decode_ldap_op(string $msg): ?array {{
    $outer = _nyx_decode_tlv($msg, 0);
    if ($outer === null || $outer[0] !== _NYX_BER_SEQUENCE) return null;
    $inner = $outer[1];
    $msg_id_tlv = _nyx_decode_tlv($inner, 0);
    if ($msg_id_tlv === null || $msg_id_tlv[0] !== _NYX_BER_INTEGER) return null;
    $op_tlv = _nyx_decode_tlv($inner, $msg_id_tlv[2]);
    if ($op_tlv === null) return null;
    return [$op_tlv[0], $op_tlv[1]];
}}

function _nyx_ldap_count_via_ber(string $filt): ?int {{
    $ep = getenv('NYX_LDAP_ENDPOINT');
    if ($ep === false || $ep === '') return null;
    $sep = strrpos($ep, ':');
    if ($sep === false || $sep === 0 || $sep === strlen($ep) - 1) return null;
    $host = substr($ep, 0, $sep);
    $port = (int) substr($ep, $sep + 1);
    if ($port <= 0) return null;
    $filter_bytes = _nyx_encode_filter($filt);
    if ($filter_bytes === null) return null;
    $errno = 0;
    $errstr = '';
    $sock = @fsockopen($host, $port, $errno, $errstr, 2.0);
    if ($sock === false) return null;
    stream_set_timeout($sock, 2);
    $bind_body = _nyx_ber_int(3) . _nyx_ber_octstr('') . _nyx_ber_tlv(_NYX_BER_AUTH_SIMPLE, '');
    $bind_msg = _nyx_ber_seq(_nyx_ber_int(1) . _nyx_ber_tlv(_NYX_BER_BIND_REQUEST, $bind_body));
    if (@fwrite($sock, $bind_msg) === false) {{ @fclose($sock); return null; }}
    $resp = _nyx_read_ber_message($sock);
    if ($resp === null) {{ @fclose($sock); return null; }}
    $decoded = _nyx_decode_ldap_op($resp);
    if ($decoded === null || $decoded[0] !== _NYX_BER_BIND_RESPONSE) {{ @fclose($sock); return null; }}
    $search_body = _nyx_ber_octstr('')
        . _nyx_ber_enum(2)
        . _nyx_ber_enum(0)
        . _nyx_ber_int(0)
        . _nyx_ber_int(2)
        . _nyx_ber_bool(false)
        . $filter_bytes
        . _nyx_ber_seq('');
    $search_msg = _nyx_ber_seq(_nyx_ber_int(2) . _nyx_ber_tlv(_NYX_BER_SEARCH_REQUEST, $search_body));
    if (@fwrite($sock, $search_msg) === false) {{ @fclose($sock); return null; }}
    $count = 0;
    while (true) {{
        $resp = _nyx_read_ber_message($sock);
        if ($resp === null) {{ @fclose($sock); return null; }}
        $decoded = _nyx_decode_ldap_op($resp);
        if ($decoded === null) {{ @fclose($sock); return null; }}
        $op_tag = $decoded[0];
        if ($op_tag === _NYX_BER_SEARCH_RESULT_ENTRY) {{
            $count++;
        }} elseif ($op_tag === _NYX_BER_SEARCH_RESULT_DONE) {{
            @fclose($sock);
            return $count;
        }} else {{
            @fclose($sock);
            return $count;
        }}
    }}
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
    $via_ber = _nyx_ldap_count_via_ber($filt);
    if ($via_ber !== null) return $via_ber;
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

function _nyx_xpath_via_fixture(string $payload, string $entry_basename, string $entry_name): int {{
    // Phase 07 tier-(a): require the fixture file and call its
    // `$entry_name` function so the real `DOMXPath::query` runs
    // against the staged corpus document.  A missing `ext-dom` /
    // `ext-xml` host install or an inaccessible fixture file is the
    // only structural reason this fails; in that case we emit the
    // conventional `NYX_IMPORT_ERROR:` stderr marker plus `exit(77)`
    // so the runner maps the outcome to `RunError::BuildFailed` and
    // the e2e SKIP branch fires.
    if (!class_exists('DOMDocument') || !class_exists('DOMXPath')) {{
        fwrite(STDERR, "NYX_IMPORT_ERROR: ext-dom / ext-xml not loaded\n");
        exit(77);
    }}
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {{
        fwrite(STDERR, "NYX_IMPORT_ERROR: fixture file not found at $candidate\n");
        exit(77);
    }}
    try {{
        require_once $candidate;
    }} catch (\Throwable $_e) {{
        fwrite(STDERR, "NYX_IMPORT_ERROR: " . $_e->getMessage() . "\n");
        exit(77);
    }}
    if (!function_exists($entry_name)) {{
        throw new \RuntimeException(
            "Phase 07 XPath harness: entry function '$entry_name' not found in fixture '$entry_basename'"
        );
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
    return 0;
}}

$payload = (string) (getenv('NYX_PAYLOAD') ?: '');
$expr = "//user[@name='" . $payload . "']";
$nodes = _nyx_xpath_via_fixture($payload, "{entry_basename}", "{entry_name}");
echo "__NYX_XPATH_TIER_A__\n";
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
/// Tier-(a): when the fixture source calls `header(` or `setcookie(`,
/// load the entry source into a synthetic `Nyx\Captured` namespace via
/// `eval()` so unqualified calls to `header()` / `setcookie()` resolve
/// to permissive shims defined in that namespace (rather than PHP's
/// built-in `header()` which rejects raw CRLF since PHP 5.1.2).  The
/// shim records every `(name, value)` pair into a global capture
/// array verbatim; the harness then emits one `ProbeKind::HeaderEmit`
/// per captured pair.  When the gate marker is absent or the eval /
/// invocation fails, fall back to the inline synthetic probe that
/// records the raw payload as a `Set-Cookie` value.  The namespace
/// shadowing pattern mirrors how Python's tier-(a) monkey-patches
/// `werkzeug.datastructures.Headers.__setitem__` before werkzeug's
/// validator runs.
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let entry_source = read_entry_source(&spec.entry_file);
    if entry_source_uses_raw_socket(&entry_source) {
        return emit_header_injection_wire_frame_harness(spec, &entry_source);
    }
    let shim = probe_shim();
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_header_writer =
        entry_source.contains("header(") || entry_source.contains("setcookie(");
    let via_fixture = if uses_header_writer {
        r#"function _nyx_header_via_fixture(string $payload, string $entry_basename, string $entry_name): ?array {
    // Phase 08 tier-(a): load the entry source into a synthetic
    // `Nyx\Captured` namespace via eval() so unqualified `header()`
    // / `setcookie()` calls inside the fixture resolve to permissive
    // shims defined in that namespace (PHP's built-in `header()`
    // rejects raw CRLF since 5.1.2 and would not let us record the
    // attack bytes verbatim).  Returns the captured `(name, value)`
    // pairs on success, `null` when load / eval / invoke fails so
    // the caller can fall back to the inline synthetic probe.
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {
        return null;
    }
    $src = @file_get_contents($candidate);
    if ($src === false) {
        return null;
    }
    $stripped = preg_replace('/^\s*<\?php\s*/', '', $src);
    if ($stripped === null) {
        return null;
    }
    $GLOBALS['__nyx_captured_headers'] = [];
    $eval_src = "namespace Nyx\\Captured;\n"
        . "function header(string \$header, bool \$replace = true, int \$response_code = 0): void { \$GLOBALS['__nyx_captured_headers'][] = \$header; }\n"
        . "function setcookie(string \$name, string \$value = '', \$expires_or_options = 0, string \$path = '', string \$domain = '', bool \$secure = false, bool \$httponly = false): bool { \$GLOBALS['__nyx_captured_headers'][] = 'Set-Cookie: ' . \$name . '=' . \$value; return true; }\n"
        . $stripped;
    try {
        $eval_result = @eval($eval_src);
    } catch (\Throwable $_) {
        return null;
    }
    if ($eval_result === false) {
        return null;
    }
    $fq = 'Nyx\\Captured\\' . $entry_name;
    if (!function_exists($fq)) {
        return null;
    }
    try {
        $fq($payload);
    } catch (\Throwable $_) {
        // shim may have captured bytes before the throw
    }
    $captured = [];
    foreach ($GLOBALS['__nyx_captured_headers'] ?? [] as $h) {
        if (!is_string($h)) continue;
        $colon = strpos($h, ':');
        if ($colon === false) {
            $captured[] = [$h, ''];
        } else {
            $name = trim(substr($h, 0, $colon));
            $value = ltrim(substr($h, $colon + 1));
            $captured[] = [$name, $value];
        }
    }
    if (empty($captured)) {
        return null;
    }
    return $captured;
}

"#
    } else {
        ""
    };
    let invoke_via_fixture = if uses_header_writer {
        format!(
            r#"$captured = _nyx_header_via_fixture($payload, "{entry_basename}", "{entry_name}");
    if ($captured !== null) {{
        foreach ($captured as $pair) {{
            _nyx_header_probe($pair[0], $pair[1]);
        }}
        echo "__NYX_SINK_HIT__\n";
        echo json_encode(['headers' => $captured]) . "\n";
        return;
    }}
    "#
        )
    } else {
        String::new()
    };
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
        'kind'           => ['kind' => 'HeaderEmit', 'name' => $name, 'value' => $value, 'protocol' => 'in-process'],
        'witness'        => __nyx_witness('header()', [$name, $value]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

{via_fixture}function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    {invoke_via_fixture}// Synthetic fallback — records the raw payload as a `Set-Cookie`
    // value via `_nyx_header_probe`.  Used when the fixture does not
    // call `header()` / `setcookie()` (gate marker absent) or when
    // the eval / invocation path fails.
    $name = 'Set-Cookie';
    $value = $payload;
    _nyx_header_probe($name, $value);
    echo "__NYX_SINK_HIT__\n";
    echo json_encode(['name' => $name, 'value' => $value]) . "\n";
}}

_nyx_run();
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

/// Tier-(b) wire-frame gate for HEADER_INJECTION.  Fires when the
/// fixture binds a raw `stream_socket_server` (or `socket_create`) and
/// exposes the `set_cookie_value` / `create_server` / `run_once`
/// triple the harness drives.  Distinct from the `header()` /
/// `setcookie()` gate because the wire-frame branch owns the
/// response-write path itself and bypasses PHP's built-in CRLF
/// validator.
fn entry_source_uses_raw_socket(src: &str) -> bool {
    (src.contains("stream_socket_server") || src.contains("socket_create"))
        && src.contains("set_cookie_value")
}

/// Phase 08 — Track J.6 tier-(b) wire-frame harness for PHP.  Drives
/// the fixture's `create_server` / `run_once` API in a forked / threaded
/// worker while the main process opens a `stream_socket_client` against
/// the bound port, issues one `GET / HTTP/1.0`, and reads the bytes the
/// fixture wrote to the response stream up to the `\r\n\r\n` boundary.
/// The captured header block is emitted as a
/// `ProbeKind::HeaderWireFrame` probe; per-`Set-Cookie` lines are also
/// emitted as `ProbeKind::HeaderEmit` records so the tier-(a)
/// `HeaderInjected` predicate fires on the same pass.  Prints a
/// `wire_frame_len` stdout marker so e2e tests can pin the branch.
///
/// PHP has no portable green-thread primitive — the harness uses
/// `pcntl_fork` when available (Linux + macOS Homebrew PHP both ship
/// `ext-pcntl` by default) and falls back to a non-blocking
/// `stream_select` drive of both the server and the client in a single
/// process when `pcntl_fork` is missing (Windows / minimal CLI builds).
fn emit_header_injection_wire_frame_harness(
    spec: &HarnessSpec,
    _entry_source: &str,
) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let body = format!(
        r#"<?php
// Nyx dynamic harness — HEADER_INJECTION raw-socket wire frame (Phase 08 / Track J.6).
{shim}

function _nyx_header_probe(string $name, string $value): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'fwrite(stream)',
        'args'           => [
            ['kind' => 'String', 'value' => $name],
            ['kind' => 'String', 'value' => $value],
        ],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'HeaderEmit', 'name' => $name, 'value' => $value, 'protocol' => 'wire'],
        'witness'        => __nyx_witness('fwrite(stream)', [$name, $value]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

function _nyx_wire_frame_probe(string $raw_bytes): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $bytes = [];
    $len = strlen($raw_bytes);
    for ($i = 0; $i < $len; $i++) {{
        $bytes[] = ord($raw_bytes[$i]);
    }}
    $rec = [
        'sink_callee'    => 'fwrite(stream)',
        'args'           => [],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'HeaderWireFrame', 'raw_bytes' => $bytes],
        'witness'        => __nyx_witness('fwrite(stream)', []),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

function _nyx_wire_frame_via_fixture(string $payload, string $entry_basename): ?string {{
    // Phase 08 tier-(b): require the fixture, install the cookie
    // value, boot its `stream_socket_server` on 127.0.0.1:0, drive
    // `run_once` either in a forked child (when `pcntl_fork` is
    // available) or in a single-process `stream_select` loop, then
    // issue one raw-socket GET from the harness and read the bytes
    // the fixture wrote to the response stream up to the CRLF-CRLF
    // boundary.  Returns null on require / boot / read failure so the
    // caller can fall back to the synthetic probe.
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {{
        return null;
    }}
    try {{
        require_once $candidate;
    }} catch (\Throwable $_) {{
        return null;
    }}
    if (!function_exists('set_cookie_value')
        || !function_exists('create_server')
        || !function_exists('run_once')) {{
        return null;
    }}
    try {{
        set_cookie_value($payload);
    }} catch (\Throwable $_) {{
        return null;
    }}
    try {{
        $server = create_server();
    }} catch (\Throwable $_) {{
        return null;
    }}
    if ($server === false || $server === null) {{
        return null;
    }}
    $name = @stream_socket_get_name($server, false);
    if ($name === false || $name === '') {{
        @fclose($server);
        return null;
    }}
    $colon = strrpos($name, ':');
    $port = $colon === false ? '0' : substr($name, $colon + 1);
    if ($port === '0' || $port === '') {{
        @fclose($server);
        return null;
    }}
    $forked = false;
    $pid = -1;
    if (function_exists('pcntl_fork')) {{
        $pid = @pcntl_fork();
        if ($pid === 0) {{
            // Child runs the accept loop and exits.
            try {{
                run_once($server);
            }} catch (\Throwable $_) {{
                // ignore fixture errors so the parent can still
                // capture whatever bytes were written before the throw.
            }}
            @fclose($server);
            exit(0);
        }}
        if ($pid > 0) {{
            $forked = true;
        }}
    }}
    $raw = '';
    $errno = 0;
    $errstr = '';
    $client = @stream_socket_client(
        'tcp://127.0.0.1:' . $port,
        $errno,
        $errstr,
        5.0
    );
    if ($client === false) {{
        if ($forked) {{
            @posix_kill($pid, 9);
            @pcntl_waitpid($pid, $status);
        }} else {{
            try {{
                run_once($server);
            }} catch (\Throwable $_) {{
                // ignore
            }}
        }}
        @fclose($server);
        return null;
    }}
    try {{
        @stream_set_timeout($client, 2, 0);
        @fwrite($client, "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
        if (!$forked) {{
            // Single-process path: drive `run_once` after the client
            // has already sent its request so the accept call returns
            // immediately.
            try {{
                run_once($server);
            }} catch (\Throwable $_) {{
                // ignore
            }}
        }}
        $deadline = microtime(true) + 5.0;
        while (strlen($raw) < 65536 && microtime(true) < $deadline) {{
            $chunk = @fread($client, 4096);
            if ($chunk === false || $chunk === '') {{
                break;
            }}
            $raw .= $chunk;
            if (strpos($raw, "\r\n\r\n") !== false) {{
                break;
            }}
        }}
    }} finally {{
        @fclose($client);
        if ($forked) {{
            $status = 0;
            @pcntl_waitpid($pid, $status);
        }}
        @fclose($server);
    }}
    $sep = strpos($raw, "\r\n\r\n");
    if ($sep === false) {{
        return $raw === '' ? null : $raw;
    }}
    return substr($raw, 0, $sep);
}}

function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    $raw_bytes = _nyx_wire_frame_via_fixture($payload, "{entry_basename}");
    if ($raw_bytes !== null) {{
        _nyx_wire_frame_probe($raw_bytes);
        // Derive HeaderEmit records per Set-Cookie line on the wire so
        // the tier-(a) HeaderInjected predicate also fires on the same
        // harness pass.  The wire-frame branch owns the bytes; the
        // HeaderEmit records are derived from them.
        foreach (explode("\n", $raw_bytes) as $line) {{
            $trimmed = (substr($line, -1) === "\r") ? substr($line, 0, -1) : $line;
            $colon = strpos($trimmed, ':');
            if ($colon === false) continue;
            $name = substr($trimmed, 0, $colon);
            if (strcasecmp($name, 'Set-Cookie') !== 0) continue;
            $start = $colon + 1;
            if ($start < strlen($trimmed) && $trimmed[$start] === ' ') {{
                $start++;
            }}
            $value = (string) substr($trimmed, $start);
            _nyx_header_probe($name, $value);
        }}
        echo "__NYX_SINK_HIT__\n";
        echo json_encode(['wire_frame_len' => strlen($raw_bytes)]) . "\n";
        return;
    }}
    // Synthetic fallback when the fixture failed to boot — keeps the
    // differential oracle live on a build/boot failure rather than
    // silently shedding the attempt.
    _nyx_header_probe('Set-Cookie', $payload);
    echo "__NYX_SINK_HIT__\n";
    echo json_encode(['payload_len' => strlen($payload)]) . "\n";
}}

_nyx_run();
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
/// Tier-(a): when the fixture source references a redirect surface
/// (`RedirectResponse` constructor, bare `header(`, or `redirect(`),
/// `require_once` the entry, call its `$entry_name` with the payload,
/// and read the bound `Location:` off the returned response object
/// via `getTargetUrl()` or `->headers->get("Location")` (Symfony-style
/// `Response`).  When the require / invoke fails (Symfony not
/// installed, fixture throws, no recognisable response shape), return
/// null so the caller can fall back to the inline synthetic probe
/// that records the raw payload as the redirect target.
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_redirect_surface = entry_source.contains("RedirectResponse")
        || entry_source.contains("header(")
        || entry_source.contains("Response::")
        || entry_source.contains("redirect(");
    let via_fixture = if uses_redirect_surface {
        r#"function _nyx_redirect_via_fixture(string $payload, string $entry_basename, string $entry_name): ?array {
    // Phase 09 tier-(a): require the entry fixture, call its
    // `$entry_name` so the real redirect surface runs, then read the
    // bound `Location:` off the returned response object.  Recognises
    // both Symfony-style `Response` instances (via `getTargetUrl()`
    // and `->headers->get("Location")`) and arbitrary objects whose
    // `headers` property exposes a `get` method.  Returns
    // `(location, "example.com")` on success or `null` when the
    // require / invoke fails so the caller can fall back to the
    // inline synthetic probe.
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {
        return null;
    }
    try {
        require_once $candidate;
    } catch (\Throwable $_) {
        return null;
    }
    if (!function_exists($entry_name)) {
        return null;
    }
    try {
        $result = $entry_name($payload);
    } catch (\Throwable $_) {
        return null;
    }
    if (is_object($result)) {
        if (method_exists($result, 'getTargetUrl')) {
            try {
                $loc = $result->getTargetUrl();
            } catch (\Throwable $_) {
                $loc = null;
            }
            if (is_string($loc) && $loc !== '') {
                return [$loc, 'example.com'];
            }
        }
        if (isset($result->headers) && is_object($result->headers) && method_exists($result->headers, 'get')) {
            try {
                $loc = $result->headers->get('Location');
            } catch (\Throwable $_) {
                $loc = null;
            }
            if (is_string($loc) && $loc !== '') {
                return [$loc, 'example.com'];
            }
        }
    }
    return null;
}

"#
    } else {
        ""
    };
    let invoke_via_fixture = if uses_redirect_surface {
        format!(
            r#"$captured = _nyx_redirect_via_fixture($payload, "{entry_basename}", "{entry_name}");
    if ($captured !== null) {{
        [$location, $requestHost] = $captured;
        _nyx_redirect_probe($location, $requestHost);
        _nyx_follow_location($location);
        echo "__NYX_SINK_HIT__\n";
        echo json_encode(['location' => $location, 'request_host' => $requestHost]) . "\n";
        return;
    }}
    "#
        )
    } else {
        String::new()
    };
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

// Phase 09 OOB closure: when the captured Location is a fully-qualified
// loopback URL, follow it with a real GET so the OOB listener records
// the per-finding nonce.  Skips non-loopback hosts (no real network egress)
// and any non-HTTP scheme.  Best-effort: failures do not propagate, the
// listener may still have observed the connect before the read errored.
function _nyx_follow_location(string $location): void {{
    if ($location === '') return;
    $lower = strtolower($location);
    if (!(str_starts_with($lower, 'http://127.0.0.1')
            || str_starts_with($lower, 'http://localhost')
            || str_starts_with($lower, 'http://host-gateway'))) {{
        return;
    }}
    $ctx = stream_context_create([
        'http' => ['timeout' => 2, 'follow_location' => 0, 'ignore_errors' => true],
    ]);
    @file_get_contents($location, false, $ctx);
}}

{via_fixture}function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    {invoke_via_fixture}// Synthetic fallback — records the raw payload as the redirect
    // location via `_nyx_redirect_probe`.  Used when the fixture does
    // not reference a recognised redirect surface (gate marker absent)
    // or when the require / invoke path fails (Symfony classes
    // missing, fixture throws).
    $requestHost = 'example.com';
    $location = $payload;
    _nyx_redirect_probe($location, $requestHost);
    _nyx_follow_location($location);
    echo "__NYX_SINK_HIT__\n";
    echo json_encode(['location' => $location, 'request_host' => $requestHost]) . "\n";
}}

_nyx_run();
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

/// Phase 11 (Track J.9) CRYPTO harness for PHP.
///
/// Reads `NYX_PAYLOAD`, loads the fixture source in a synthetic
/// `Nyx\Captured` namespace via `eval()` so the entry's top-level
/// statements are isolated, calls `<entry_name>($payload)`, and
/// reduces the returned key into a
/// [`crate::dynamic::probe::ProbeKind::WeakKey`] probe.  `int` returns
/// flow through masked to `PHP_INT_MAX` (so a high-bit-set value does
/// not flip a 16-bit predicate); `string`/byte returns get truncated
/// to the leading 8 bytes via `unpack('J', ...)` with left-zero-pad,
/// so a 32-byte `random_bytes(32)` benign control trivially overshoots
/// any 16-bit budget while `mt_rand(0, 0xFFFF)` stays inside it.
/// Reflection / load failures fall back to a payload-derived `key_int`
/// so the universal sink-hit path still fires.
pub fn emit_crypto_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"<?php
// Nyx dynamic harness — CRYPTO weak-RNG key entropy (Phase 11 / Track J.9).
{shim}

function _nyx_weak_key_probe(int $keyInt): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => '__nyx_weak_key',
        'args'           => [
            ['kind' => 'Int', 'value' => $keyInt],
        ],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'WeakKey', 'key_int' => $keyInt],
        'witness'        => __nyx_witness('__nyx_weak_key', [(string) $keyInt]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

function _nyx_key_to_int($value): int {{
    if (is_bool($value)) {{
        return $value ? 1 : 0;
    }}
    if (is_int($value)) {{
        return $value & PHP_INT_MAX;
    }}
    if (is_string($value)) {{
        $head = substr($value, 0, 8);
        if ($head === false || $head === '') {{
            return 0;
        }}
        $padded = str_pad($head, 8, "\0", STR_PAD_LEFT);
        $unpacked = @unpack('J', $padded);
        if ($unpacked === false || !isset($unpacked[1])) {{
            return 0;
        }}
        return (int) $unpacked[1] & PHP_INT_MAX;
    }}
    // Fallback — UTF-8 first 8 bytes of string repr
    try {{
        $s = (string) $value;
    }} catch (\Throwable $_) {{
        return 0;
    }}
    if ($s === '') {{
        return 0;
    }}
    $head = substr($s, 0, 8);
    $padded = str_pad($head, 8, "\0", STR_PAD_LEFT);
    $unpacked = @unpack('J', $padded);
    if ($unpacked === false || !isset($unpacked[1])) {{
        return 0;
    }}
    return (int) $unpacked[1] & PHP_INT_MAX;
}}

function _nyx_crypto_via_fixture(string $payload, string $entry_basename, string $entry_name) {{
    // Phase 11 tier-(a): load the entry source in a synthetic
    // `Nyx\Captured` namespace via eval() so the fixture's top-level
    // statements are isolated.  Returns the produced key on success,
    // `null` when load / eval / invoke fails so the caller can fall
    // back to the payload-derived key for the universal sink-hit path.
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {{
        return null;
    }}
    $src = @file_get_contents($candidate);
    if ($src === false) {{
        return null;
    }}
    $stripped = preg_replace('/^\s*<\?php\s*/', '', $src);
    if ($stripped === null) {{
        return null;
    }}
    $eval_src = "namespace Nyx\\Captured;\n" . $stripped;
    try {{
        $eval_result = @eval($eval_src);
    }} catch (\Throwable $_) {{
        return null;
    }}
    if ($eval_result === false) {{
        return null;
    }}
    $fq = 'Nyx\\Captured\\' . $entry_name;
    if (!function_exists($fq)) {{
        return null;
    }}
    try {{
        return $fq($payload);
    }} catch (\Throwable $_) {{
        return null;
    }}
}}

function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    $produced = _nyx_crypto_via_fixture($payload, "{entry_basename}", "{entry_name}");
    $fixtureInvoked = $produced !== null;
    if ($produced === null) {{
        $produced = $payload;
    }}
    $keyInt = _nyx_key_to_int($produced);
    _nyx_weak_key_probe($keyInt);
    echo "__NYX_SINK_HIT__\n";
    if (!$fixtureInvoked) {{
        echo "__NYX_CRYPTO_FALLBACK__\n";
    }}
    echo json_encode(['key_int' => $keyInt]) . "\n";
}}

_nyx_run();
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

/// Phase 11 (Track J.9) — JSON_PARSE depth-bomb harness for PHP.
///
/// The harness publishes a global `_nyx_json_decode($s)` helper that
/// proxies the real `json_decode`, runs an iterative depth walker over
/// the parsed value, and emits a
/// [`crate::dynamic::probe::ProbeKind::JsonParse`] probe record.  PHP
/// cannot monkey-patch `json_decode` itself, so the per-language fixture
/// calls `_nyx_json_decode(...)` instead of the builtin.  PHP's
/// unqualified function-call resolution inside the synthetic
/// `Nyx\Captured` namespace falls back to the global namespace, so the
/// fixture call site resolves to the harness helper at runtime.
///
/// On parser failure with `JSON_ERROR_DEPTH` (which fires when the
/// nesting depth exceeds the helper's `$depth` argument) the harness
/// emits a `JsonParse { depth: 0, excessive_depth: true }` probe before
/// returning `null` — matches the Python `RecursionError` + JS
/// `RangeError` excess paths.
///
/// Mirrors `crate::dynamic::lang::python::emit_json_parse_harness` and
/// `crate::dynamic::lang::js_shared::emit_json_parse_harness`.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"<?php
// Nyx dynamic harness — JSON_PARSE depth checks (Phase 11 / Track J.9).
{shim}

const _NYX_JSON_MAX_WALK = 4096;
const _NYX_JSON_HELPER_DEPTH = 4096;

function _nyx_json_count_depth($parsed): int {{
    $maxDepth = 0;
    $stack = [[$parsed, 1]];
    $visited = 0;
    while (count($stack) > 0) {{
        [$cur, $depth] = array_pop($stack);
        $visited += 1;
        if ($visited > _NYX_JSON_MAX_WALK) {{
            break;
        }}
        if ($depth > $maxDepth) {{
            $maxDepth = $depth;
        }}
        if (is_array($cur)) {{
            foreach ($cur as $child) {{
                $stack[] = [$child, $depth + 1];
            }}
        }} elseif (is_object($cur)) {{
            foreach (get_object_vars($cur) as $child) {{
                $stack[] = [$child, $depth + 1];
            }}
        }}
    }}
    return $maxDepth;
}}

function _nyx_json_parse_probe(int $depth, bool $excessive): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => 'json_decode',
        'args'           => [['kind' => 'Int', 'value' => $depth]],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => [
            'kind' => 'JsonParse',
            'depth' => $depth,
            'excessive_depth' => $excessive,
        ],
        'witness'        => __nyx_witness('json_decode', [(string) $depth]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

// Global helper the fixture calls in place of `json_decode`.  Defined
// in the global namespace so an unqualified `_nyx_json_decode(...)`
// call inside `namespace Nyx\Captured` resolves here.
function _nyx_json_decode(string $text, ?bool $assoc = true, int $depth = _NYX_JSON_HELPER_DEPTH, int $flags = 0) {{
    $parsed = json_decode($text, $assoc, $depth, $flags);
    if ($parsed === null && json_last_error() !== JSON_ERROR_NONE) {{
        if (json_last_error() === JSON_ERROR_DEPTH) {{
            _nyx_json_parse_probe(0, true);
        }}
        return null;
    }}
    $observed = _nyx_json_count_depth($parsed);
    _nyx_json_parse_probe($observed, $observed > 64);
    return $parsed;
}}

function _nyx_json_parse_via_fixture(string $payload, string $entry_basename, string $entry_name): bool {{
    $candidate = __DIR__ . DIRECTORY_SEPARATOR . $entry_basename;
    if (!is_file($candidate)) {{
        return false;
    }}
    $src = @file_get_contents($candidate);
    if ($src === false) {{
        return false;
    }}
    $stripped = preg_replace('/^\s*<\?php\s*/', '', $src);
    if ($stripped === null) {{
        return false;
    }}
    $eval_src = "namespace Nyx\\Captured;\n" . $stripped;
    try {{
        $eval_result = @eval($eval_src);
    }} catch (\Throwable $_) {{
        return false;
    }}
    if ($eval_result === false) {{
        return false;
    }}
    $fq = 'Nyx\\Captured\\' . $entry_name;
    if (!function_exists($fq)) {{
        return false;
    }}
    try {{
        $fq($payload);
    }} catch (\Throwable $_) {{
        // Parser exceptions on the deep payload are expected — the
        // probe is already emitted before the helper re-raises.
    }}
    return true;
}}

function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    _nyx_json_parse_via_fixture($payload, "{entry_basename}", "{entry_name}");
    echo "__NYX_SINK_HIT__\n";
}}

_nyx_run();
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

/// Phase 11 (Track J.9) — UNAUTHORIZED_ID IDOR harness for PHP.
///
/// Requires the fixture, calls `entry_name($payload)`, and emits a
/// [`crate::dynamic::probe::ProbeKind::IdorAccess`] probe iff the
/// fixture materialises a non-null record.  The fixture lives at
/// `__DIR__ . '/' . $entry_basename` (the harness runner copies it
/// next to `harness.php` when `entry_subpath` is `None`).
///
/// `caller_id` is hard-pinned to `"alice"`; the
/// [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
/// predicate fires when the payload (treated as `owner_id`) does not
/// match.
pub fn emit_unauthorized_id_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"<?php
// Nyx dynamic harness — UNAUTHORIZED_ID IDOR boundary (Phase 11 / Track J.9).
{shim}

const _NYX_CALLER_ID = 'alice';

function _nyx_idor_probe(string $caller, string $owner): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => '__nyx_idor_lookup',
        'args'           => [
            ['kind' => 'String', 'value' => $caller],
            ['kind' => 'String', 'value' => $owner],
        ],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => [
            'kind'      => 'IdorAccess',
            'caller_id' => $caller,
            'owner_id'  => $owner,
        ],
        'witness'        => __nyx_witness('__nyx_idor_lookup', [$caller, $owner]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

function _nyx_idor_call_entry(string $payload, string $entry_name) {{
    if (!function_exists($entry_name)) {{
        return null;
    }}
    try {{
        return $entry_name($payload);
    }} catch (\Throwable $_) {{
        return null;
    }}
}}

// Require the fixture at script-top so its top-level state (e.g.
// `$STORE = […]`) lands in the global scope — `require_once` inside a
// function would scope those variables to the calling function, and
// the fixture's `function run() {{ global $STORE; … }}` would then see
// an undefined symbol.
$_NYX_ENTRY_PATH = __DIR__ . DIRECTORY_SEPARATOR . "{entry_basename}";
if (is_file($_NYX_ENTRY_PATH)) {{
    require_once $_NYX_ENTRY_PATH;
}}

function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    $record = _nyx_idor_call_entry($payload, "{entry_name}");
    if ($record !== null) {{
        _nyx_idor_probe(_NYX_CALLER_ID, $payload);
    }}
    echo "__NYX_SINK_HIT__\n";
}}

_nyx_run();
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

/// Phase 11 (Track J.9) — DATA_EXFIL outbound-network harness for PHP.
///
/// PHP has no monkey-patch hook for `file_get_contents` / `fopen`, but
/// the language exposes a per-scheme stream-wrapper registry the
/// harness can override.  Before requiring the fixture the harness
/// unregisters the default `http` + `https` wrappers and installs
/// `NyxHttpStreamWrapper` in their place; the wrapper's `stream_open`
/// parses the URL host via `parse_url(PHP_URL_HOST)`, emits a
/// [`crate::dynamic::probe::ProbeKind::OutboundNetwork`] probe, and
/// returns an immediately-EOF stream so the fixture's caller does not
/// block on a real wire request.  The
/// [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
/// predicate fires when the captured host falls outside the loopback
/// allowlist, so the `attacker.test` vuln payload materialises a probe
/// the predicate matches while the `127.0.0.1` benign control stays
/// clear.
pub fn emit_data_exfil_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_php_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"<?php
// Nyx dynamic harness — DATA_EXFIL outbound-host (Phase 11 / Track J.9).
{shim}

function _nyx_outbound_probe(string $host): void {{
    $p = getenv('NYX_PROBE_PATH');
    if ($p === false || $p === '') return;
    $rec = [
        'sink_callee'    => '__nyx_mock_http',
        'args'           => [['kind' => 'String', 'value' => $host]],
        'captured_at_ns' => (int) hrtime(true),
        'payload_id'     => (string) (getenv('NYX_PAYLOAD_ID') ?: ''),
        'kind'           => ['kind' => 'OutboundNetwork', 'host' => $host],
        'witness'        => __nyx_witness('__nyx_mock_http', [$host]),
    ];
    @file_put_contents($p, json_encode($rec) . "\n", FILE_APPEND);
}}

class NyxHttpStreamWrapper {{
    public $context;
    private int $pos = 0;

    public function stream_open($path, $mode, $options, &$opened_path) {{
        $host = @parse_url($path, PHP_URL_HOST);
        if (is_string($host) && $host !== '') {{
            _nyx_outbound_probe($host);
        }}
        $this->pos = 0;
        return true;
    }}

    public function stream_read($count) {{
        return '';
    }}

    public function stream_write($data) {{
        return strlen((string) $data);
    }}

    public function stream_eof() {{
        return true;
    }}

    public function stream_close() {{}}

    public function stream_stat() {{
        return false;
    }}

    public function url_stat($path, $flags) {{
        // file_get_contents / fopen on http URLs go through stream_open;
        // the probe is captured there.  Returning false here keeps
        // is_file() / file_exists() honest without double-emitting.
        return false;
    }}

    public function stream_set_option($option, $arg1, $arg2) {{
        return false;
    }}

    public function stream_seek($offset, $whence = SEEK_SET) {{
        return false;
    }}

    public function stream_tell() {{
        return $this->pos;
    }}
}}

function _nyx_install_http_wrapper(): void {{
    foreach (['http', 'https'] as $scheme) {{
        if (in_array($scheme, stream_get_wrappers(), true)) {{
            @stream_wrapper_unregister($scheme);
        }}
        @stream_wrapper_register($scheme, 'NyxHttpStreamWrapper');
    }}
}}

function _nyx_data_exfil_call_entry(string $payload, string $entry_name): bool {{
    if (!function_exists($entry_name)) {{
        return false;
    }}
    try {{
        $entry_name($payload);
    }} catch (\Throwable $_) {{
        // Fixture-side throw after a partial outbound call still leaves
        // the probe emitted; nothing else to do here.
    }}
    return true;
}}

// Install the stream-wrapper override at script-top BEFORE requiring
// the fixture so any top-level `file_get_contents(http://…)` inside
// the fixture's body is also captured (the v1 fixtures only call into
// the wrapper from `run()` but a future fixture's top-level state may
// still want the egress trapped).
_nyx_install_http_wrapper();

// Require the fixture at script-top so its top-level state lands in
// the global scope.  `require_once` inside a function scopes any
// top-level variables to that function — the v1 fixture body is pure
// `function run(…) {{ … }}` so the distinction does not bite today,
// but keeping the require at script-top matches the
// UNAUTHORIZED_ID emitter and stays correct under fixture growth.
$_NYX_ENTRY_PATH = __DIR__ . DIRECTORY_SEPARATOR . "{entry_basename}";
if (is_file($_NYX_ENTRY_PATH)) {{
    require_once $_NYX_ENTRY_PATH;
}}

function _nyx_run(): void {{
    $payload = (string) (getenv('NYX_PAYLOAD') ?: '');
    _nyx_data_exfil_call_entry($payload, "{entry_name}");
    echo "__NYX_SINK_HIT__\n";
}}

_nyx_run();
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
            h.source.contains("_NYX_BER_BIND_REQUEST = 0x60"),
            "PHP LDAP harness must compose an LDAPv3 BindRequest (BER tag 0x60)",
        );
        assert!(
            h.source.contains("_NYX_BER_SEARCH_REQUEST = 0x63"),
            "PHP LDAP harness must compose an LDAPv3 SearchRequest (BER tag 0x63)",
        );
        assert!(
            h.source.contains("_nyx_encode_filter"),
            "PHP LDAP harness must encode the RFC 4515 filter string into BER bytes",
        );
        assert!(
            !h.source.contains("'SEARCH '"),
            "PHP LDAP harness must no longer write the plaintext SEARCH <filter> tier-(a) framing",
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
            h.source.contains("_nyx_ldap_count_via_ber"),
            "PHP LDAP harness must dispatch through the BER stub-route helper",
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
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "PHP XPath harness must emit the tier-(a) stdout marker after the real DOMXPath call: {}",
            h.source
        );
    }

    #[test]
    fn emit_xpath_harness_drops_inline_matcher_fallback() {
        let h = emit_xpath_harness(&make_xpath_spec(
            "tests/dynamic_fixtures/xpath_injection/php/vuln.php",
            "run",
        ));
        assert!(
            !h.source.contains("_nyx_xpath_select"),
            "PHP XPath harness must not carry the inline `_nyx_xpath_select` matcher; tier-(a) is the only path",
        );
        assert!(
            !h.source.contains("NYX_XPATH_USERS"),
            "PHP XPath harness must not carry the inline `NYX_XPATH_USERS` table; tier-(a) is the only path",
        );
        assert!(
            h.source.contains("NYX_IMPORT_ERROR:") && h.source.contains("exit(77)"),
            "PHP XPath harness must emit `NYX_IMPORT_ERROR:` stderr marker + `exit(77)` on require / ext failure: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "PHP XPath harness must emit the tier-(a) stdout marker: {}",
            h.source
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

    // ── Phase 08 / 09 tier-(a) PHP emitter tests ─────────────────────────────

    fn make_header_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    fn make_redirect_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_header_injection_harness_routes_through_fixture_when_header_call_present() {
        let dir = std::env::temp_dir().join("nyx_phase08_php_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(
            &entry,
            "<?php\nfunction run($value) {\n    header(\"Set-Cookie: \" . $value);\n}\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("function _nyx_header_via_fixture("),
            "tier-(a) harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("namespace Nyx\\\\Captured"),
            "tier-(a) helper must eval the fixture in the Nyx\\Captured namespace: {}",
            h.source
        );
        assert!(
            h.source.contains("'Nyx\\\\Captured\\\\' . $entry_name"),
            "tier-(a) helper must invoke the fully-qualified namespaced entry: {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "tier-(a) harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert!(
            h.source.contains("$captured = _nyx_header_via_fixture("),
            "harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert!(
            h.source
                .contains("$value = $payload;\n    _nyx_header_probe("),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_falls_back_when_no_header_call() {
        let dir = std::env::temp_dir().join("nyx_phase08_php_test_no_header");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(&entry, "<?php\nfunction run($v) { return $v; }\n").unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("function _nyx_header_via_fixture("),
            "fallback path must not define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("namespace Nyx\\Captured"),
            "fallback path must not eval into the Nyx\\Captured namespace: {}",
            h.source
        );
        assert!(
            h.source
                .contains("$value = $payload;\n    _nyx_header_probe("),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_derives_basename_from_entry_file() {
        let dir = std::env::temp_dir().join("nyx_phase08_php_test_basename_derive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("benign.php");
        std::fs::write(
            &entry,
            "<?php\nfunction run($value) {\n    header(\"Set-Cookie: \" . urlencode($value));\n}\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("\"benign.php\""),
            "tier-(a) harness must use the entry-file basename: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_routes_through_wire_frame_when_raw_socket_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_php_test_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(
            &entry,
            "<?php\n\
             $GLOBALS['nyx_cookie_value'] = '';\n\
             function set_cookie_value($value) { $GLOBALS['nyx_cookie_value'] = (string) $value; }\n\
             function create_server() { $e=0; $s=''; return stream_socket_server('tcp://127.0.0.1:0', $e, $s); }\n\
             function run_once($server) { $c = stream_socket_accept($server, 5.0); if ($c === false) return; fwrite($c, \"HTTP/1.0 200 OK\\r\\nSet-Cookie: \" . $GLOBALS['nyx_cookie_value'] . \"\\r\\n\\r\\nok\"); fclose($c); }\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("function _nyx_wire_frame_via_fixture("),
            "tier-(b) harness must define the wire-frame helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require_once $candidate"),
            "tier-(b) harness must require_once the fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "tier-(b) harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert!(
            h.source.contains("set_cookie_value($payload)"),
            "tier-(b) harness must install the cookie value on the fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("create_server()"),
            "tier-(b) harness must boot the fixture's stream socket via create_server: {}",
            h.source
        );
        assert!(
            h.source.contains("run_once($server)"),
            "tier-(b) harness must drive run_once: {}",
            h.source
        );
        assert!(
            h.source.contains("stream_socket_client("),
            "tier-(b) harness must open a client stream against the bound port: {}",
            h.source
        );
        assert!(
            h.source.contains("GET / HTTP/1.0\\r\\nHost: 127.0.0.1"),
            "tier-(b) harness must issue a raw GET request: {}",
            h.source
        );
        assert!(
            h.source
                .contains("'kind' => 'HeaderWireFrame', 'raw_bytes' => $bytes"),
            "tier-(b) harness must emit a HeaderWireFrame probe carrying the raw header-block bytes: {}",
            h.source
        );
        assert!(
            h.source.contains("'wire_frame_len' => strlen($raw_bytes)"),
            "tier-(b) harness must emit the wire_frame_len stdout marker: {}",
            h.source
        );
        assert!(
            !h.source.contains("namespace Nyx\\\\Captured"),
            "tier-(b) harness must not eval into the Nyx\\Captured namespace (that's the tier-(a) path): {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_wire_frame_branch_drops_when_only_header_call_present() {
        let dir = std::env::temp_dir().join("nyx_phase08_php_test_no_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(
            &entry,
            "<?php\nfunction run($value) {\n    header(\"Set-Cookie: \" . $value);\n}\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("function _nyx_wire_frame_via_fixture("),
            "header()-only harness must not define the wire-frame helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("HeaderWireFrame"),
            "header()-only harness must not emit the HeaderWireFrame probe shape: {}",
            h.source
        );
        assert!(
            !h.source.contains("wire_frame_len"),
            "header()-only harness must not emit the wire_frame_len stdout marker: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_routes_through_fixture_when_redirect_surface_present() {
        let dir = std::env::temp_dir().join("nyx_phase09_php_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(
            &entry,
            "<?php\nuse Symfony\\Component\\HttpFoundation\\RedirectResponse;\nfunction run(string $value): RedirectResponse {\n    return new RedirectResponse($value);\n}\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("function _nyx_redirect_via_fixture("),
            "tier-(a) harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require_once $candidate"),
            "tier-(a) helper must require the entry fixture: {}",
            h.source
        );
        assert!(
            h.source.contains("method_exists($result, 'getTargetUrl')"),
            "tier-(a) helper must check Symfony getTargetUrl(): {}",
            h.source
        );
        assert!(
            h.source.contains("$result->headers->get('Location')"),
            "tier-(a) helper must fall back to ->headers->get('Location'): {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "tier-(a) harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert!(
            h.source.contains("$captured = _nyx_redirect_via_fixture("),
            "harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert!(
            h.source
                .contains("$location = $payload;\n    _nyx_redirect_probe("),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_falls_back_when_no_redirect_surface() {
        let dir = std::env::temp_dir().join("nyx_phase09_php_test_no_redirect");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(&entry, "<?php\nfunction run($v) { return $v; }\n").unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("function _nyx_redirect_via_fixture("),
            "fallback path must not define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("require_once $candidate"),
            "fallback path must not require the entry fixture: {}",
            h.source
        );
        assert!(
            h.source
                .contains("$location = $payload;\n    _nyx_redirect_probe("),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let dir = std::env::temp_dir().join("nyx_phase09_php_test_follow_location");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.php");
        std::fs::write(
            &entry,
            "<?php\nuse Symfony\\Component\\HttpFoundation\\RedirectResponse;\nfunction run($v) { return new RedirectResponse($v); }\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source
                .contains("function _nyx_follow_location(string $location): void"),
            "OPEN_REDIRECT harness must declare the _nyx_follow_location helper: {}",
            h.source
        );
        assert!(
            h.source
                .contains("file_get_contents($location, false, $ctx)"),
            "follow-location helper must call file_get_contents with a stream context: {}",
            h.source
        );
        assert!(
            h.source.contains("'timeout' => 2"),
            "follow-location helper must pin the stream context timeout to 2 seconds: {}",
            h.source
        );
        assert!(
            h.source
                .contains("str_starts_with($lower, 'http://127.0.0.1')")
                && h.source
                    .contains("str_starts_with($lower, 'http://localhost')")
                && h.source
                    .contains("str_starts_with($lower, 'http://host-gateway')"),
            "follow-location helper must gate on loopback host prefixes: {}",
            h.source
        );
        assert!(
            h.source.contains("_nyx_redirect_probe($location, $requestHost);\n        _nyx_follow_location($location);"),
            "tier-(a) must follow the captured Location after emitting the probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Phase 11 (Track J.9) PHP CRYPTO emitter tests ─────────────────────────

    fn make_crypto_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CRYPTO;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_crypto_harness_when_cap_is_crypto() {
        let h = emit(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/php/vuln.php",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_weak_key_probe"),
            "dispatcher must short-circuit Cap::CRYPTO into emit_crypto_harness so the weak-key probe shim is present: {}",
            h.source
        );
        assert!(
            h.source.contains("'kind' => 'WeakKey'"),
            "crypto harness must record probes with kind WeakKey so the WeakKeyEntropy predicate fires",
        );
    }

    #[test]
    fn emit_crypto_harness_routes_through_fixture_eval() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("function _nyx_crypto_via_fixture("),
            "PHP CRYPTO harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("namespace Nyx\\\\Captured"),
            "PHP CRYPTO harness must eval the fixture in the Nyx\\Captured namespace so the entry's top-level statements stay isolated: {}",
            h.source
        );
        assert!(
            h.source.contains("'Nyx\\\\Captured\\\\' . $entry_name"),
            "PHP CRYPTO harness must invoke the fully-qualified namespaced entry: {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "PHP CRYPTO harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert!(
            h.source.contains("$produced = _nyx_crypto_via_fixture("),
            "PHP CRYPTO harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert_eq!(
            h.filename, "harness.php",
            "PHP CRYPTO harness must emit a harness.php file",
        );
        assert!(
            h.extra_files.is_empty(),
            "PHP CRYPTO harness must not require per-spec deps — mt_rand + random_bytes are stdlib",
        );
    }

    #[test]
    fn emit_crypto_harness_emits_weak_key_probe_kind() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/php/vuln.php",
            "run",
        ));
        assert!(
            h.source
                .contains("['kind' => 'WeakKey', 'key_int' => $keyInt]"),
            "PHP CRYPTO harness must emit ProbeKind::WeakKey records carrying a key_int field so the WeakKeyEntropy predicate fires: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_SINK_HIT__"),
            "PHP CRYPTO harness must print the universal sink-hit sentinel",
        );
    }

    #[test]
    fn emit_crypto_harness_reduces_string_via_unpack() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/php/benign.php",
            "run",
        ));
        assert!(
            h.source.contains("unpack('J', $padded)"),
            "PHP CRYPTO harness must reduce string/byte returns via unpack('J', ...) so a 32-byte CSPRNG key produces a key_int whose magnitude exceeds any 16-bit budget: {}",
            h.source
        );
        assert!(
            h.source
                .contains("str_pad($head, 8, \"\\0\", STR_PAD_LEFT)"),
            "PHP CRYPTO harness must left-zero-pad short slices before unpacking",
        );
        assert!(
            h.source.contains("if (is_int($value))"),
            "PHP CRYPTO harness must keep int returns flowing through via masked AND",
        );
    }

    #[test]
    fn emit_crypto_harness_falls_back_when_fixture_eval_fails() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/php/vuln.php",
            "run",
        ));
        assert!(
            h.source
                .contains("if ($produced === null) {\n        $produced = $payload;\n    }"),
            "PHP CRYPTO harness must fall back to the payload bytes when the fixture path returns null: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_CRYPTO_FALLBACK__"),
            "PHP CRYPTO harness must print the crypto-fallback sentinel when tier-(a) returns null so the verifier can spot the fallback path on stdout",
        );
    }

    #[test]
    fn emit_crypto_harness_derives_basename_from_entry_file() {
        let h = emit_crypto_harness(&make_crypto_spec("/abs/path/benign.php", "run"));
        assert!(
            h.source.contains("\"benign.php\""),
            "PHP CRYPTO harness must use the entry-file basename, not a hard-coded literal: {}",
            h.source
        );
    }

    // ── Phase 11 (Track J.9) PHP JSON_PARSE emitter tests ─────────────────────

    fn make_json_parse_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::JSON_PARSE;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_json_parse_harness_when_cap_is_json_parse() {
        let h = emit(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/php/vuln.php",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_json_decode"),
            "dispatcher must short-circuit Cap::JSON_PARSE into the depth harness: {}",
            h.source
        );
        assert!(
            h.source.contains("'kind' => 'JsonParse'"),
            "JSON_PARSE harness must emit JsonParse probe records",
        );
    }

    #[test]
    fn emit_json_parse_harness_defines_global_helper() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("function _nyx_json_decode("),
            "PHP JSON_PARSE harness must publish a global _nyx_json_decode helper the fixture can call",
        );
        assert!(
            h.source.contains("function _nyx_json_count_depth("),
            "PHP JSON_PARSE harness must define the iterative depth walker",
        );
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/php/vuln.php",
            "run",
        ));
        assert!(h.source.contains("'depth' => $depth"));
        assert!(h.source.contains("'excessive_depth' => $excessive"));
        assert!(h.source.contains("$observed > 64"));
        assert!(h.source.contains("__NYX_SINK_HIT__"));
    }

    #[test]
    fn emit_json_parse_harness_handles_parser_depth_error() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/php/vuln.php",
            "run",
        ));
        assert!(h.source.contains("JSON_ERROR_DEPTH"));
        assert!(h.source.contains("_nyx_json_parse_probe(0, true)"));
    }

    #[test]
    fn emit_json_parse_harness_routes_through_fixture_eval() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("function _nyx_json_parse_via_fixture("),
            "PHP JSON_PARSE harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("namespace Nyx\\\\Captured"),
            "PHP JSON_PARSE harness must eval the fixture inside the Nyx\\Captured namespace: {}",
            h.source
        );
        assert!(
            h.source.contains("'Nyx\\\\Captured\\\\' . $entry_name"),
            "PHP JSON_PARSE harness must invoke the fully-qualified namespaced entry: {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "PHP JSON_PARSE harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert_eq!(h.filename, "harness.php");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_json_parse_harness_derives_basename_from_entry_file() {
        let h = emit_json_parse_harness(&make_json_parse_spec("/abs/path/benign.php", "run"));
        assert!(
            h.source.contains("\"benign.php\""),
            "PHP JSON_PARSE harness must use the entry-file basename, not a hard-coded literal: {}",
            h.source
        );
    }

    // ── Phase 11 (Track J.9) PHP UNAUTHORIZED_ID emitter tests ───────────────

    fn make_unauthorized_id_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_unauthorized_id_harness_when_cap_is_unauthorized_id() {
        let h = emit(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/php/vuln.php",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_idor_probe"),
            "dispatcher must short-circuit Cap::UNAUTHORIZED_ID into emit_unauthorized_id_harness: {}",
            h.source
        );
        assert!(
            h.source.contains("'kind'      => 'IdorAccess'"),
            "UNAUTHORIZED_ID harness must record probes with kind IdorAccess so IdorBoundaryCrossed fires: {}",
            h.source
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_pins_caller_id() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("const _NYX_CALLER_ID = 'alice'"),
            "PHP UNAUTHORIZED_ID harness must pin caller_id to 'alice': {}",
            h.source
        );
        assert!(
            h.source
                .contains("_nyx_idor_probe(_NYX_CALLER_ID, $payload)"),
            "PHP UNAUTHORIZED_ID harness must call probe with caller_id + payload-as-owner: {}",
            h.source
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_skips_probe_when_record_is_null() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/php/benign.php",
            "run",
        ));
        assert!(
            h.source.contains("if ($record !== null) {"),
            "PHP UNAUTHORIZED_ID harness must gate probe emission on a non-null record so the benign fixture's null rejection clears the predicate: {}",
            h.source
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_routes_through_fixture_require() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("function _nyx_idor_call_entry("),
            "PHP UNAUTHORIZED_ID harness must define the entry-call helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require_once $_NYX_ENTRY_PATH"),
            "PHP UNAUTHORIZED_ID harness must require_once the fixture at script-top so the fixture's top-level state lands in the global scope: {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "PHP UNAUTHORIZED_ID harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert_eq!(h.filename, "harness.php");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_unauthorized_id_harness_derives_basename_from_entry_file() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "/abs/path/benign.php",
            "run",
        ));
        assert!(
            h.source.contains("\"benign.php\""),
            "PHP UNAUTHORIZED_ID harness must use the entry-file basename, not a hard-coded literal: {}",
            h.source
        );
    }

    // ── Phase 11 (Track J.9) PHP DATA_EXFIL emitter tests ────────────────────

    fn make_data_exfil_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_data_exfil_harness_when_cap_is_data_exfil() {
        let h = emit(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/php/vuln.php",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_outbound_probe"),
            "dispatcher must short-circuit Cap::DATA_EXFIL into emit_data_exfil_harness: {}",
            h.source
        );
        assert!(
            h.source.contains("'kind' => 'OutboundNetwork'"),
            "DATA_EXFIL harness must record probes with kind OutboundNetwork so OutboundHostNotIn fires: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_installs_stream_wrapper() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("class NyxHttpStreamWrapper"),
            "PHP DATA_EXFIL harness must define the http stream-wrapper class: {}",
            h.source
        );
        assert!(
            h.source
                .contains("stream_wrapper_register($scheme, 'NyxHttpStreamWrapper')"),
            "PHP DATA_EXFIL harness must register the wrapper for http/https: {}",
            h.source
        );
        assert!(
            h.source.contains("foreach (['http', 'https'] as $scheme)"),
            "PHP DATA_EXFIL harness must override both http and https schemes: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_parses_host_via_parse_url() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("@parse_url($path, PHP_URL_HOST)"),
            "PHP DATA_EXFIL harness must extract host via parse_url: {}",
            h.source
        );
        assert!(
            h.source.contains("_nyx_outbound_probe($host)"),
            "PHP DATA_EXFIL harness must emit the outbound probe with the parsed host: {}",
            h.source
        );
    }

    #[test]
    fn emit_data_exfil_harness_routes_through_fixture_require() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/php/vuln.php",
            "run",
        ));
        assert!(
            h.source.contains("function _nyx_data_exfil_call_entry("),
            "PHP DATA_EXFIL harness must define the entry-call helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require_once $_NYX_ENTRY_PATH"),
            "PHP DATA_EXFIL harness must require_once the fixture at script-top: {}",
            h.source
        );
        assert!(
            h.source.contains("\"vuln.php\""),
            "PHP DATA_EXFIL harness must pass the entry basename to the helper: {}",
            h.source
        );
        assert_eq!(h.filename, "harness.php");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_data_exfil_harness_installs_wrapper_before_fixture_require() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/php/vuln.php",
            "run",
        ));
        // Both the wrapper install and the fixture require happen at
        // script-top.  The wrapper must come first so any top-level
        // egress from the fixture body is also captured.  Find the
        // last (script-top) occurrence of `_nyx_install_http_wrapper()`
        // to skip the matches inside the helper function definitions.
        let install_idx = h
            .source
            .rfind("_nyx_install_http_wrapper();")
            .expect("script-top install call present");
        let require_idx = h
            .source
            .find("require_once $_NYX_ENTRY_PATH")
            .expect("script-top require_once present");
        assert!(
            install_idx < require_idx,
            "PHP DATA_EXFIL harness must install the stream wrapper before requiring the fixture so top-level egress is also captured",
        );
    }

    #[test]
    fn emit_data_exfil_harness_derives_basename_from_entry_file() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec("/abs/path/benign.php", "run"));
        assert!(
            h.source.contains("\"benign.php\""),
            "PHP DATA_EXFIL harness must use the entry-file basename, not a hard-coded literal: {}",
            h.source
        );
    }
}

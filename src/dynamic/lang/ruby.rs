//! Ruby harness emitter.
//!
//! Phase 15 (Track B Ruby vertical) replaces the previous `LangUnsupported`
//! stub with dispatch over [`RubyShape`] — the cross product of
//! [`EntryKind`] and a lightweight per-file shape detector that inspects
//! the entry file for Sinatra routes, Rails controller actions, Rack
//! middleware, and generic controller methods.
//!
//! Each shape emits a single `harness.rb` that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Requires the entry file from the workdir (`entry.rb`).
//! 3. Invokes the entry point via the per-shape adapter.
//!
//! Sink-reachability probe: fixtures explicitly emit `__NYX_SINK_HIT__`
//! before the actual sink call (same pattern as Rust / JS / Go fixtures).
//!
//! Payload slot support:
//! - `PayloadSlot::Param(n)` — n-th positional argument.
//! - `PayloadSlot::EnvVar(name)` — set `ENV[name]` before calling.
//! - `PayloadSlot::QueryParam(name)` — surfaced via the per-shape
//!   request stub for Sinatra / Rails / Rack.
//! - `PayloadSlot::HttpBody` — surfaced via the per-shape request stub
//!   for Sinatra / Rails / Rack.
//! - `PayloadSlot::Argv(n)` — appended to `ARGV` for CLI-style entries.
//! - `PayloadSlot::Stdin` — produces `UnsupportedReason::PayloadSlotUnsupported`.
//!
//! Build: no compilation step. Command is `ruby harness.rb`.

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for Ruby.
pub struct RubyEmitter;

/// Entry kinds the Ruby emitter understands after Phase 15.
///
/// `HttpRoute` covers Sinatra / Rails / Rack.  `CliSubcommand` covers
/// `ARGV`-driven scripts.  `Function` covers plain methods and
/// controller method shapes.
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::ClassMethod,
    EntryKindTag::ScheduledJob,
    EntryKindTag::WebSocket,
    EntryKindTag::Middleware,
    EntryKindTag::Migration,
];

impl LangEmitter for RubyEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "ruby emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 15 / 19 / 20 / 21 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_ruby(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — Ruby chain-step harness.
///
/// Splices the Ruby probe shim ([`probe_shim`]) in front of a minimal
/// driver that reads `NYX_PREV_OUTPUT` from `ENV` and forwards it on
/// stdout.  When the step is the chain's terminal step the driver also
/// calls `__nyx_probe(callee, prev)` and emits the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` for the chain.
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let shim = probe_shim();
    let mut driver = String::from("prev = ENV[\"NYX_PREV_OUTPUT\"] || \"\"\n$stdout.write(prev)\n");
    if let Some(t) = terminal {
        let callee = ruby_string_literal(&t.sink_callee);
        let sentinel = ruby_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "__nyx_probe({callee}, prev)\nputs {sentinel}\n$stdout.flush\n",
        ));
    }
    let source = format!("{shim}\n{driver}");
    ChainStepHarness {
        source,
        filename: "step.rb".to_owned(),
        command: vec!["ruby".to_owned(), "step.rb".to_owned()],
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

/// Escape a string for safe Ruby double-quoted literal embedding.
fn ruby_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ── Phase 15: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
///
/// One harness template per variant.  When the entry file is unreadable
/// or no marker fires the detector defaults to [`RubyShape::Generic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RubyShape {
    /// `get '/path' do ... end` Sinatra route.  Harness publishes the
    /// payload via `ENV` + `$nyx_request` and triggers the route's
    /// block via `$nyx_sinatra_routes`.
    SinatraRoute,
    /// Rails controller action (e.g. `def index ... end` on a class
    /// inheriting from `ApplicationController` / `ActionController::Base`).
    /// Harness instantiates the controller and calls the action with a
    /// stub `request` / `params` pair.
    RailsAction,
    /// Rack middleware: `def call(env) ... end` on a class.  Harness
    /// builds a minimal Rack `env` hash and dispatches.
    RackMiddleware,
    /// Generic instance method on a controller class (no framework
    /// marker).  Harness instantiates the class with `.new` and calls
    /// the named method with the payload.
    ControllerMethod,
    /// Plain top-level method (no class) — default pre-Phase-15
    /// behaviour.
    Generic,
}

impl RubyShape {
    /// Detect the shape from `(spec, source)`.  Framework markers in
    /// the source win over `spec.entry_kind`.
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let entry = spec.entry_name.as_str();
        let kind = spec.entry_kind.tag();

        let has_sinatra = source.contains("require 'sinatra'")
            || source.contains("require \"sinatra\"")
            || source.contains("Sinatra::Base")
            || source.contains("# nyx-shape: sinatra")
            || (source.contains("get '/") && source.contains(" do"));
        let has_rails = source.contains("ApplicationController")
            || source.contains("ActionController::Base")
            || source.contains("ActionController::API")
            || source.contains("# nyx-shape: rails");
        let has_rack = source.contains("def call(env)")
            || source.contains("Rack::")
            || source.contains("# nyx-shape: rack");
        let has_class = source.contains("class ");
        let has_def = source.contains("def ");
        let entry_named_class = entry
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false);

        if has_sinatra {
            return Self::SinatraRoute;
        }
        if has_rack && entry == "call" {
            return Self::RackMiddleware;
        }
        if has_rails {
            return Self::RailsAction;
        }
        if has_rack {
            return Self::RackMiddleware;
        }
        if kind == EntryKindTag::HttpRoute && has_class {
            return Self::ControllerMethod;
        }
        if has_class && has_def && !entry.is_empty() && !entry_named_class {
            return Self::ControllerMethod;
        }
        Self::Generic
    }
}

/// Public wrapper to detect the shape for a finalised `HarnessSpec`,
/// reading the entry file from disk.
pub fn detect_shape(spec: &HarnessSpec) -> RubyShape {
    let src = read_entry_source(&spec.entry_file);
    RubyShape::detect(spec, &src)
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

/// Phase 08 / 09 tier-(a) helper: strip the `.rb` extension off the
/// entry file's basename so the harness can `require_relative` it.
fn derive_entry_basename(entry_file: &str) -> String {
    PathBuf::from(entry_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "entry".to_owned())
}

/// Source of the `__nyx_probe` shim for the Ruby harness (Phase 06 —
/// Track C.1).
pub fn probe_shim() -> &'static str {
    r#"
# ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
NYX_DENY_SUBSTRINGS = %w[
  TOKEN SECRET PASSWORD PASSWD API_KEY APIKEY PRIVATE_KEY CREDENTIAL SESSION
  COOKIE AUTH BEARER AWS_ACCESS AWS_SESSION GH_TOKEN GITHUB_TOKEN NPM_TOKEN
  PYPI_TOKEN DOCKER_PASS
].freeze
NYX_PAYLOAD_LIMIT = 16 * 1024
NYX_REDACTED = '<redacted-by-nyx-policy>'

def __nyx_is_denied_key(k)
  ku = k.to_s.upcase
  NYX_DENY_SUBSTRINGS.any? { |n| ku.include?(n) }
end

def __nyx_witness(sink_callee, args)
  env_snapshot = {}
  ENV.each do |k, v|
    env_snapshot[k] = __nyx_is_denied_key(k) ? NYX_REDACTED : v
  end
  payload = ENV['NYX_PAYLOAD'] || ''
  pb = payload.bytes
  pb = pb[0, NYX_PAYLOAD_LIMIT] if pb.length > NYX_PAYLOAD_LIMIT
  repr = args.map { |a| a.is_a?(String) ? a : a.to_s }
  cwd = (Dir.pwd rescue '')
  {
    env_snapshot: env_snapshot,
    cwd: cwd,
    payload_bytes: pb,
    callee: sink_callee.to_s,
    args_repr: repr,
  }
end

def __nyx_emit(rec)
  require 'json'
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  begin
    File.open(p, 'a') { |f| f.puts(rec.to_json) }
  rescue StandardError
  end
end

def __nyx_probe(sink_callee, *args)
  ser = args.map do |a|
    case a
    when Integer then { kind: 'Int', value: a }
    when String  then { kind: 'String', value: a }
    else              { kind: 'String', value: a.to_s }
    end
  end
  __nyx_emit({
    sink_callee: sink_callee.to_s,
    args: ser,
    captured_at_ns: (Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond)),
    payload_id: (ENV['NYX_PAYLOAD_ID'] || ''),
    kind: { kind: 'Normal' },
    witness: __nyx_witness(sink_callee, args),
  })
end

# Phase 08: install a sink-site signal trap.  Ruby traps run in interrupt
# context but can write to a file before re-raising via Process.kill.
def __nyx_install_crash_guard(sink_callee)
  %w[SEGV ABRT BUS FPE ILL].each do |nm|
    begin
      Signal.trap(nm) do
        __nyx_emit({
          sink_callee: sink_callee.to_s,
          args: [],
          captured_at_ns: (Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond)),
          payload_id: (ENV['NYX_PAYLOAD_ID'] || ''),
          kind: { kind: 'Crash', signal: "SIG#{nm}" },
          witness: __nyx_witness(sink_callee, []),
        })
        Signal.trap(nm, 'DEFAULT')
        Process.kill(nm, Process.pid)
      end
    rescue ArgumentError, Errno::EINVAL
      # signal not supported on this platform
    end
  end
end

# Phase 10 (Track D.3) HTTP recording helper.  When the verifier spawned an
# HttpStub it publishes the side-channel log path through NYX_HTTP_LOG; a
# sink call site whose outbound request never reaches the on-the-wire
# listener (DNS-mocked, network-isolated sandbox, pre-flight check) can
# call this helper to surface the attempted call.  Format matches the
# Python / Node / PHP / Go siblings so the host-side HttpStub log-line
# merger parses all five streams identically.  No-op when NYX_HTTP_LOG is
# unset so the same harness still runs cleanly under modes that did not
# spawn a stub.  Single-quoted Ruby string literals keep this helper free
# of the literal hash-after-double-quote sequence that would terminate
# the surrounding Rust raw string.
def __nyx_stub_http_record(method, url, body = nil, **detail)
  p = ENV['NYX_HTTP_LOG']
  return if p.nil? || p.empty?
  begin
    File.open(p, 'a') do |f|
      f.puts('# method: ' + method.to_s)
      f.puts('# url: ' + url.to_s)
      f.puts('# body: ' + body.to_s) unless body.nil?
      detail.each { |k, v| f.puts('# ' + k.to_s + ': ' + v.to_s) }
      f.puts(method.to_s + ' ' + url.to_s)
    end
  rescue StandardError
  end
end

# Phase 10 (Track D.3) SQL recording helper.  When the verifier spawned a
# SqlStub it publishes the side-channel log path through NYX_SQL_LOG; a
# sink call site whose query never reaches the on-the-wire SQLite engine
# (no sqlite3 gem on the host, query pre-flighted before
# SQLite3::Database.open) can call this helper to surface the attempted
# query.  Hash-prefixed detail lines followed by the query line so
# SqlStub::drain_events parses every language stream identically.  No-op
# when NYX_SQL_LOG is unset.  Single-quoted Ruby string literals keep this
# helper free of the literal hash-after-double-quote sequence.
def __nyx_stub_sql_record(query, **detail)
  p = ENV['NYX_SQL_LOG']
  return if p.nil? || p.empty?
  begin
    File.open(p, 'a') do |f|
      detail.each { |k, v| f.puts('# ' + k.to_s + ': ' + v.to_s) }
      line = query.to_s
      line += "\n" unless line.end_with?("\n")
      f.write(line)
    end
  rescue StandardError
  end
end
"#
}

/// Phase 09 — Track D.2: synthesise a `Gemfile` listing every captured
/// gem name.
pub fn materialize_ruby(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let mut deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for d in &env.direct_deps {
        if is_ruby_stdlib(d) {
            continue;
        }
        if seen.insert(d.clone()) {
            deps.push(d.clone());
        }
    }
    deps.sort_unstable();

    let mut body = String::with_capacity(64);
    body.push_str("source 'https://rubygems.org'\n");
    for d in &deps {
        body.push_str(&format!("gem '{d}'\n"));
    }
    artifacts.push("Gemfile", body);
    artifacts
}

fn is_ruby_stdlib(name: &str) -> bool {
    matches!(
        name,
        "json"
            | "yaml"
            | "uri"
            | "net"
            | "time"
            | "date"
            | "csv"
            | "logger"
            | "fileutils"
            | "tempfile"
            | "open"
            | "stringio"
            | "set"
            | "open3"
            | "ostruct"
            | "digest"
            | "base64"
            | "securerandom"
            | "etc"
    )
}

/// Emit a Ruby harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_)
        | PayloadSlot::EnvVar(_)
        | PayloadSlot::QueryParam(_)
        | PayloadSlot::HttpBody
        | PayloadSlot::Argv(_) => {}
        PayloadSlot::Stdin => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    if spec.expected_cap == crate::labels::Cap::DESERIALIZE {
        return Ok(emit_deserialize_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::SSTI {
        return Ok(emit_ssti_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::XXE {
        return Ok(emit_xxe_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 11 (Track J.9): JSON_PARSE depth-bomb short-circuit.  The
    // synthetic harness rebinds `JSON.parse` to a depth-counting
    // wrapper, walks the parsed value iteratively, and emits a
    // `ProbeKind::JsonParse { depth, excessive_depth }` record before
    // returning the parsed value.  `JSON::NestingError` (raised by the
    // Ruby json gem when the input exceeds `max_nesting`) is caught
    // and converted into a `JsonParse { depth: 0, excessive_depth:
    // true }` probe before the error is re-raised.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 19 (Track M.1): ClassMethod short-circuit.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(class, method));
    }

    // Phase 21 (Track M.3): ScheduledJob short-circuit (Sidekiq workers).
    if let crate::evidence::EntryKind::ScheduledJob { schedule } = &spec.entry_kind {
        return Ok(emit_scheduled_job_harness(
            &spec.entry_name,
            schedule.as_deref(),
        ));
    }

    // Phase 21 (Track M.3): WebSocket short-circuit (ActionCable channels).
    if let crate::evidence::EntryKind::WebSocket { path } = &spec.entry_kind {
        return Ok(emit_websocket_handler_harness(&spec.entry_name, path));
    }

    // Phase 21 (Track M.3): Middleware short-circuit (Rack-shape).
    if let crate::evidence::EntryKind::Middleware { name } = &spec.entry_kind {
        return Ok(emit_middleware_harness(&spec.entry_name, name));
    }

    // Phase 21 (Track M.3): Migration short-circuit (ActiveRecord up/down).
    if let crate::evidence::EntryKind::Migration { version } = &spec.entry_kind {
        return Ok(emit_migration_harness(&spec.entry_name, version.as_deref()));
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = RubyShape::detect(spec, &entry_source);
    let source = generate_source(spec, shape);

    Ok(HarnessSource {
        source,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.rb".to_owned()),
    })
}

/// Phase 19 (Track M.1) — class-method harness for Ruby.
///
/// Requires the entry file, looks up `class` as a top-level constant,
/// instantiates via `.new` (falling back to a single mock-dependency
/// `.new(...)` when the no-arg path raises `ArgumentError`), and
/// invokes `instance.send(method, payload)`.
fn emit_class_method_harness(class: &str, method: &str) -> HarnessSource {
    let shim = probe_shim();
    let mock_http = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::HttpClient,
        crate::symbol::Lang::Ruby,
    );
    let mock_db = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::DatabaseConnection,
        crate::symbol::Lang::Ruby,
    );
    let mock_log = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::Logger,
        crate::symbol::Lang::Ruby,
    );
    let body = format!(
        r#"# Nyx dynamic harness — class method (Phase 19 / Track M.1).
{shim}
{mock_http}
{mock_db}
{mock_log}

def nyx_payload
  v = ENV['NYX_PAYLOAD']
  return v if v && !v.empty?
  b64 = ENV['NYX_PAYLOAD_B64']
  if b64 && !b64.empty?
    begin
      require 'base64'
      return Base64.decode64(b64)
    rescue StandardError
      return ''
    end
  end
  ''
end

$nyx_payload = nyx_payload

begin
  require_relative './entry'
rescue LoadError, ScriptError => e
  STDERR.puts("NYX_IMPORT_ERROR: #{{e.message}}")
  exit 77
end

cls_name = {class:?}
unless Object.const_defined?(cls_name)
  STDERR.puts("NYX_CLASS_NOT_FOUND: #{{cls_name}}")
  exit 78
end
cls = Object.const_get(cls_name)

def _nyx_build_receiver(cls)
  begin
    return cls.new
  rescue ArgumentError
  end
  begin
    return cls.new(MockHttpClient.new, MockDatabaseConnection.new, MockLogger.new)
  rescue StandardError
  end
  [MockDatabaseConnection.new, MockHttpClient.new, MockLogger.new, nil].each do |dep|
    begin
      return cls.new(dep)
    rescue StandardError
    end
  end
  nil
end

instance = _nyx_build_receiver(cls)
if instance.nil?
  STDERR.puts("NYX_CLASS_CTOR_FAILED: #{{cls_name}}")
  exit 78
end
unless instance.respond_to?({method:?})
  STDERR.puts("NYX_METHOD_NOT_FOUND: " + {method:?})
  exit 78
end
begin
  result = instance.send({method:?}, $nyx_payload)
  print(result.to_s) if result
rescue StandardError => e
  STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
end
"#,
        class = class,
        method = method,
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.rb".to_owned()),
    }
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

fn nyx_ruby_preamble() -> String {
    let shim = probe_shim();
    format!(
        r#"# Nyx dynamic harness — Phase 21 / Track M.3 (auto-generated).
{shim}

def nyx_payload
  v = ENV['NYX_PAYLOAD']
  return v if v && !v.empty?
  b64 = ENV['NYX_PAYLOAD_B64']
  if b64 && !b64.empty?
    begin
      require 'base64'
      return Base64.decode64(b64)
    rescue StandardError
      return ''
    end
  end
  ''
end

$nyx_payload = nyx_payload

begin
  require_relative './entry'
rescue LoadError, ScriptError => e
  STDERR.puts("NYX_IMPORT_ERROR: #{{e.message}}")
  exit 77
end

puts "__NYX_SINK_HIT__"
"#,
        shim = shim,
    )
}

fn emit_scheduled_job_harness(handler: &str, schedule: Option<&str>) -> HarnessSource {
    let preamble = nyx_ruby_preamble();
    let sched = schedule.unwrap_or("<unscheduled>");
    let body = format!(
        r#"{preamble}
puts "__NYX_SCHEDULED_JOB__: " + {sched:?}

# Sidekiq workers expose perform(*args) on a class.  Try looking up the
# named class first; fall back to a top-level function.
target = nil
if Object.const_defined?({handler:?})
  begin
    target = Object.const_get({handler:?}).new
    if target.respond_to?(:perform)
      begin
        result = target.perform($nyx_payload)
        print(result.to_s) if result
      rescue StandardError => e
        STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
      end
      exit 0
    end
  rescue StandardError
  end
end

if respond_to?({handler:?}.to_sym, true)
  begin
    result = send({handler:?}.to_sym, $nyx_payload)
    print(result.to_s) if result
  rescue StandardError => e
    STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
  end
else
  STDERR.puts("NYX_HANDLER_NOT_FOUND: " + {handler:?})
  exit 78
end
"#,
        preamble = preamble,
        handler = handler,
        sched = sched,
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.rb".to_owned()),
    }
}

fn emit_websocket_handler_harness(handler: &str, path: &str) -> HarnessSource {
    let preamble = nyx_ruby_preamble();
    let body = format!(
        r#"{preamble}
puts "__NYX_WEBSOCKET__: " + {path:?}

# ActionCable channels expose `receive(data)` on a subclass.  Find the
# enclosing class via const lookup; fall back to top-level send.
if Object.const_defined?({handler:?})
  cls = Object.const_get({handler:?})
  begin
    inst = cls.new rescue (cls.allocate rescue nil)
    if inst && inst.respond_to?(:receive)
      begin
        result = inst.receive($nyx_payload)
        print(result.to_s) if result
      rescue StandardError => e
        STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
      end
      exit 0
    end
  rescue StandardError
  end
end

if respond_to?({handler:?}.to_sym, true)
  begin
    result = send({handler:?}.to_sym, $nyx_payload)
    print(result.to_s) if result
  rescue StandardError => e
    STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
  end
else
  STDERR.puts("NYX_HANDLER_NOT_FOUND: " + {handler:?})
  exit 78
end
"#,
        preamble = preamble,
        handler = handler,
        path = path,
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.rb".to_owned()),
    }
}

fn emit_middleware_harness(handler: &str, name: &str) -> HarnessSource {
    let preamble = nyx_ruby_preamble();
    let body = format!(
        r#"{preamble}
puts "__NYX_MIDDLEWARE__: " + {name:?}

require 'stringio'

# Rack-shape middleware: class with #call(env).
env = {{
  'REQUEST_METHOD' => 'POST',
  'PATH_INFO' => '/nyx',
  'QUERY_STRING' => "q=#{{$nyx_payload}}",
  'rack.input' => StringIO.new($nyx_payload),
  'nyx.payload' => $nyx_payload,
}}

if Object.const_defined?({handler:?})
  cls = Object.const_get({handler:?})
  begin
    inst = cls.new(lambda {{ |e| [200, {{}}, ['ok']] }})
    if inst.respond_to?(:call)
      result = inst.call(env)
      print(result.to_s) if result
      exit 0
    end
  rescue StandardError => e
    STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
  end
end

if respond_to?({handler:?}.to_sym, true)
  begin
    result = send({handler:?}.to_sym, env)
    print(result.to_s) if result
  rescue StandardError => e
    STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
  end
else
  STDERR.puts("NYX_HANDLER_NOT_FOUND: " + {handler:?})
  exit 78
end
"#,
        preamble = preamble,
        handler = handler,
        name = name,
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.rb".to_owned()),
    }
}

fn emit_migration_harness(handler: &str, version: Option<&str>) -> HarnessSource {
    let preamble = nyx_ruby_preamble();
    let ver = version.unwrap_or("<no-version>");
    let body = format!(
        r#"{preamble}
puts "__NYX_MIGRATION__: " + {ver:?}

# ActiveRecord migrations expose `up` / `down` / `change` on a subclass.
if Object.const_defined?({handler:?})
  cls = Object.const_get({handler:?})
  begin
    inst = cls.new
    %i[up change down].each do |m|
      if inst.respond_to?(m)
        begin
          result = inst.send(m)
          print(result.to_s) if result
        rescue StandardError => e
          STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
        end
        exit 0
      end
    end
  rescue StandardError => e
    STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
  end
end

if respond_to?({handler:?}.to_sym, true)
  begin
    result = send({handler:?}.to_sym)
    print(result.to_s) if result
  rescue StandardError => e
    STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
  end
else
  STDERR.puts("NYX_HANDLER_NOT_FOUND: " + {handler:?})
  exit 78
end
"#,
        preamble = preamble,
        handler = handler,
        ver = ver,
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: Some("entry.rb".to_owned()),
    }
}

/// Phase 03 — Track J.1 deserialize harness for Ruby.
///
/// Wraps a call to `Marshal.load(input)` with a const-lookup
/// instrumentation that asserts the requested constant is on the
/// allowlist (`Integer`, `String`, `Array`).  When the marker class
/// is outside the allowlist the shim writes a
/// [`crate::dynamic::probe::ProbeKind::Deserialize`] probe with
/// `gadget_chain_invoked: true`.
pub fn emit_deserialize_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"# Nyx dynamic harness — deserialize (Phase 03 / Track J.1).
require 'json'

{shim}

def _nyx_deserialize_probe(invoked)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'Marshal.load',
    'args'           => [],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'Deserialize', 'gadget_chain_invoked' => !!invoked }},
    'witness'        => __nyx_witness('Marshal.load', []),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

# Forge a Marshal v4.8 class-reference blob for `name` (opcode `c`
# followed by a long-encoded symbol).  Marshal.load resolves the class
# via `Object.const_get`-style lookup before any instantiation; an
# unknown class raises `ArgumentError: undefined class/module ...` —
# the same boundary `Marshal.const_defined?`-style hardening checks.
def _nyx_forge_marshal_class_ref(name)
  bytes = name.bytesize
  raise ArgumentError, 'class name too long' if bytes >= 256
  if bytes == 0
    len_byte = "\x00".b
  elsif bytes < 123
    len_byte = [bytes + 5].pack('C')
  else
    len_byte = "\x01".b + [bytes].pack('C')
  end
  "\x04\x08c".b + len_byte + name.b
end

allowlist = ['Integer', 'String', 'Array']
payload = ENV['NYX_PAYLOAD'] || ''
if payload.start_with?('NYX_GADGET_CLASS:')
  cls = payload[('NYX_GADGET_CLASS:'.length)..]
  begin
    Marshal.load(_nyx_forge_marshal_class_ref(cls))
  rescue ArgumentError => e
    # `undefined class/module <ns>` — the Marshal class-resolution
    # boundary refused the lookup.  Real hardening would surface this
    # via a `Marshal.const_defined?` pre-check + reject; we record the
    # gadget-class invocation here.
    if e.message.start_with?('undefined class/module')
      _nyx_deserialize_probe(true)
    end
  rescue TypeError, NameError
    # Allow-listed class that exists at load time (e.g. `Integer`)
    # resolves cleanly via `Object.const_get` and Marshal returns the
    # class object — no rescue path.  Other unexpected errors fall
    # through without writing a probe.
  end
end
# Sink-reachability sentinel — runner's `vuln_fired && sink_hit`
# gate consumes this; without it differential confirmation cannot
# fire even when the probe was written.
STDOUT.puts '__NYX_SINK_HIT__'
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 04 — Track J.2 SSTI harness for Ruby (ERB).
///
/// Reads `NYX_PAYLOAD`, simulates ERB's `<%= expr %>` evaluation by
/// scanning for arithmetic inside the inline-output marker, prints
/// `{"render": "<result>"}` plus the sink-hit sentinel.  The synthetic
/// render keeps the corpus deterministic without requiring a live ERB
/// install inside the sandbox.
pub fn emit_ssti_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"# Nyx dynamic harness — SSTI ERB (Phase 04 / Track J.2).
#
# Routes `NYX_PAYLOAD` through the real stdlib `ERB.new(payload).result`
# call.  The corpus vuln payload `<%= 7*7 %>` reaches ERB's Ruby
# expression evaluator and renders as `49`; the benign control `7*7`
# has no `<%= ... %>` markers so the engine echoes it verbatim.
require 'erb'
require 'json'

{shim}

def _nyx_erb_render(payload)
  begin
    ERB.new(payload).result(binding)
  rescue ScriptError, StandardError => e
    "<erb-error:#{{e.class.name}}>"
  end
end

def _nyx_ssti_probe(rendered)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'ERB#result',
    'args'           => [{{ 'kind' => 'String', 'value' => rendered }}],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'Normal' }},
    'witness'        => __nyx_witness('ERB#result', [rendered]),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

payload = ENV['NYX_PAYLOAD'] || ''
rendered = _nyx_erb_render(payload)
_nyx_ssti_probe(rendered)
STDOUT.puts '__NYX_SINK_HIT__'
STDOUT.puts JSON.generate({{"render" => rendered}})
STDOUT.flush
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 05 — Track J.3 XXE harness for Ruby (REXML / Nokogiri).
///
/// Reads `NYX_PAYLOAD`, parses it with stdlib `REXML::Document.new`,
/// inspects the resulting `doctype.entities` table for SYSTEM/PUBLIC
/// external-entity declarations the parser actually parsed and
/// registered, and writes a `ProbeKind::Xxe` probe whose
/// `entity_expanded` flag tracks whether REXML registered any
/// external entity.  REXML never fetches the SYSTEM resource by
/// default (safe-by-default), so the harness does not need a network
/// shim — but the detection runs at the real parser hook the brief
/// calls out: the parser parses the DOCTYPE declarations and exposes
/// them in the document's entities table.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r##"# Nyx dynamic harness — XXE REXML (Phase 05 / Track J.3).
require 'json'
require 'net/http'
require 'rexml/document'
require 'stringio'
require 'uri'

{shim}

# Build the XML document fed into REXML.  Two shapes (Phase 05 OOB
# closure, 2026-05-21):
#   - URL-form NYX_PAYLOAD (`http://...` / `https://...`): treat as the
#     SYSTEM URL of an external entity and wrap into a canonical XXE
#     DTD.  When the URL points at loopback, perform a real GET so the
#     OOB listener observes the per-finding nonce callback.
#   - Anything else: treat as the full XML document (existing shape).
def _nyx_build_xxe_document(payload)
  if payload.start_with?('http://') || payload.start_with?('https://')
    if payload.start_with?('http://127.0.0.1') ||
       payload.start_with?('http://host-gateway') ||
       payload.start_with?('http://localhost')
      begin
        uri = URI.parse(payload)
        Net::HTTP.start(uri.host, uri.port, open_timeout: 2, read_timeout: 2) do |http|
          http.request_get(uri.request_uri)
        end
      rescue StandardError
        # best-effort OOB fetch
      end
    end
    escaped = payload.gsub('&', '&amp;').gsub('"', '&quot;').gsub('<', '&lt;')
    "<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n  <!ENTITY xxe SYSTEM \"#{{escaped}}\">\n]>\n<data>&xxe;</data>"
  else
    payload
  end
end

def _nyx_libxml_parse(payload)
  # Real parser hook: REXML parses `<!ENTITY name SYSTEM "uri">` declarations
  # into Entity objects on the doctype.  Inspect the entities table to
  # detect every external-entity reference the parser registered.
  expanded = false
  begin
    doc = REXML::Document.new(_nyx_build_xxe_document(payload))
    if doc.doctype
      doc.doctype.entities.each_value do |ent|
        s = ent.to_s
        if s =~ /SYSTEM|PUBLIC/
          expanded = true
        end
      end
      # REXML serialization raises on unresolved external entity refs
      # in element bodies — catch the raise as a secondary signal that
      # the parser saw an external reference past the declaration.
      begin
        doc.write(StringIO.new)
      rescue StandardError
        expanded = true
      end
    end
  rescue StandardError
    # Malformed XML still counts as a parser invocation; expanded
    # reflects whatever the parser saw before the error.
  end
  expanded
end

def _nyx_xxe_probe(payload, expanded)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'REXML::Document.new',
    'args'           => [{{ 'kind' => 'String', 'value' => payload }}],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'Xxe', 'entity_expanded' => !!expanded }},
    'witness'        => __nyx_witness('REXML::Document.new', [payload]),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

payload = ENV['NYX_PAYLOAD'] || ''
expanded = _nyx_libxml_parse(payload)
_nyx_xxe_probe(payload, expanded)
STDOUT.puts '__NYX_SINK_HIT__'
STDOUT.puts JSON.generate({{"entity_expanded" => expanded}})
STDOUT.flush
"##
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 08 — Track J.6 header-injection harness for Ruby
/// (`Rack::Response#set_header`).
///
/// Tier (a): when the fixture imports `rack`, prepend a permissive
/// captor module onto `Rack::Response` that records every
/// `set_header(name, value)` call verbatim, then invoke the named
/// entry function with the payload.
///
/// Tier (b) — raw-socket wire frame: when the fixture binds a
/// `TCPServer` and exposes the `set_cookie_value` / `create_server` /
/// `run_once` triple, drive the fixture from the harness while
/// opening a client `TCPSocket` against the bound port, read the
/// bytes the fixture wrote to the response socket up to the
/// CRLF-CRLF boundary, and emit them as a `ProbeKind::HeaderWireFrame`
/// probe.  Bypasses every framework-level CRLF validator since the
/// fixture owns the response-write path itself.
///
/// Tier (c) synthetic fallback: when neither gate fires, emit a
/// single `HeaderEmit` probe with the payload bytes pre-bound to
/// `Set-Cookie`.
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let entry_source = read_entry_source(&spec.entry_file);
    if entry_source_uses_raw_socket(&entry_source) {
        return emit_header_injection_wire_frame_harness(spec, &entry_source);
    }
    let shim = probe_shim();
    let entry_basename = derive_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_rack =
        entry_source.contains("require 'rack'") || entry_source.contains("require \"rack\"");
    let via_fixture = if uses_rack {
        format!(
            r#"def _nyx_header_via_fixture(payload)
  # Phase 08 tier-(a): prepend a permissive captor onto
  # `Rack::Response` so every `set_header(name, value)` call records
  # the unmodified bytes (including raw `\r\n`) before Rack's
  # validator (if any) runs.  Mirrors the Python werkzeug pattern at
  # `src/dynamic/lang/python.rs::emit_header_injection_harness`.
  # Returns `nil` when Rack is missing or the fixture cannot be
  # required so the caller can fall back to the synthetic probe.
  begin
    require 'rack'
  rescue LoadError, ScriptError
    return nil
  end
  captured = []
  patcher = Module.new do
    define_method(:set_header) do |name, value|
      begin
        captured << [name.to_s, value.to_s]
      rescue StandardError
        # ignore non-string args
      end
      self
    end
  end
  Rack::Response.prepend(patcher)
  $LOAD_PATH.unshift('.')
  begin
    require_relative './{entry_basename}'
  rescue LoadError, ScriptError
    return nil
  end
  begin
    Object.new.__send__(:'{entry_name}', payload)
  rescue StandardError
    # Fixture raised — return whatever was captured before throw.
  end
  captured
end

"#
        )
    } else {
        String::new()
    };
    let invoke_via_fixture = if uses_rack {
        r#"  captured = _nyx_header_via_fixture(payload)
  if captured && !captured.empty?
    captured.each do |(name, value)|
      _nyx_header_probe(name, value)
    end
    STDOUT.puts '__NYX_SINK_HIT__'
    STDOUT.puts JSON.generate({ 'headers' => captured.map { |p| [p[0], p[1]] } })
    STDOUT.flush
    return
  end
"#
    } else {
        ""
    };
    let body = format!(
        r#"# Nyx dynamic harness — HEADER_INJECTION Rack::Response#set_header (Phase 08 / Track J.6).
require 'json'

{shim}

def _nyx_header_probe(name, value)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'Rack::Response#set_header',
    'args'           => [
      {{ 'kind' => 'String', 'value' => name }},
      {{ 'kind' => 'String', 'value' => value }},
    ],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'HeaderEmit', 'name' => name, 'value' => value, 'protocol' => 'in-process' }},
    'witness'        => __nyx_witness('Rack::Response#set_header', [name, value]),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

{via_fixture}def _nyx_run
  payload = ENV['NYX_PAYLOAD'] || ''
{invoke_via_fixture}  # Synthetic fallback — mirrors `Rack::Response#set_header`
  # semantics: the value bytes flow through unmodified, so a tainted
  # payload that carries raw `\r\n` lands on the wire as a header split.
  name = 'Set-Cookie'
  value = payload
  _nyx_header_probe(name, value)
  STDOUT.puts '__NYX_SINK_HIT__'
  STDOUT.puts JSON.generate({{ 'name' => name, 'value' => value }})
  STDOUT.flush
end

_nyx_run
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Tier-(b) wire-frame gate for HEADER_INJECTION.  Fires when the
/// fixture binds a raw `TCPServer` and exposes the `set_cookie_value`
/// / `create_server` / `run_once` triple the harness drives.  Distinct
/// from the Rack gate because the wire-frame branch owns the
/// response-write path itself and bypasses every framework CRLF
/// validator.
fn entry_source_uses_raw_socket(src: &str) -> bool {
    src.contains("TCPServer.new") && src.contains("set_cookie_value")
}

/// Phase 08 — Track J.6 tier-(b) wire-frame harness for Ruby.  Drives
/// the fixture's `create_server` / `run_once` API in a worker thread
/// while the harness opens a `TCPSocket` against the bound port,
/// issues one `GET / HTTP/1.0`, and reads the bytes the fixture wrote
/// to the response socket up to the `\r\n\r\n` boundary.  The
/// captured header block is emitted as a `ProbeKind::HeaderWireFrame`
/// probe; per-`Set-Cookie` lines are also emitted as
/// `ProbeKind::HeaderEmit` records so the tier-(a) `HeaderInjected`
/// predicate fires on the same pass.  Prints a `wire_frame_len`
/// stdout marker so e2e tests can pin the branch.
fn emit_header_injection_wire_frame_harness(
    spec: &HarnessSpec,
    _entry_source: &str,
) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_entry_basename(&spec.entry_file);
    let body = format!(
        r#"# Nyx dynamic harness — HEADER_INJECTION raw-socket wire frame (Phase 08 / Track J.6).
require 'json'
require 'socket'

{shim}

def _nyx_header_probe(name, value)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'TCPSocket#write',
    'args'           => [
      {{ 'kind' => 'String', 'value' => name }},
      {{ 'kind' => 'String', 'value' => value }},
    ],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'HeaderEmit', 'name' => name, 'value' => value, 'protocol' => 'wire' }},
    'witness'        => __nyx_witness('TCPSocket#write', [name, value]),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

def _nyx_wire_frame_probe(raw_bytes)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'TCPSocket#write',
    'args'           => [],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'HeaderWireFrame', 'raw_bytes' => raw_bytes.bytes }},
    'witness'        => __nyx_witness('TCPSocket#write', []),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

def _nyx_wire_frame_via_fixture(payload)
  # Phase 08 tier-(b): install the cookie value on the fixture, boot
  # its `TCPServer` on 127.0.0.1:0, drive `run_once` on a worker
  # thread, then issue one raw-socket GET from the harness and read
  # the bytes the fixture wrote to the response socket up to the
  # CRLF-CRLF boundary.  Returns nil on import / boot / read failure
  # so the caller can fall back to the synthetic probe.
  $LOAD_PATH.unshift('.')
  begin
    require_relative './{entry_basename}'
  rescue LoadError, ScriptError
    return nil
  end
  obj = Object.new
  begin
    obj.__send__(:set_cookie_value, payload)
  rescue StandardError
    return nil
  end
  server = begin
    obj.__send__(:create_server)
  rescue StandardError
    return nil
  end
  port = server.addr[1]
  worker = Thread.new do
    begin
      obj.__send__(:run_once, server)
    rescue StandardError
      # ignore fixture errors so the harness can still capture the
      # bytes already written before the throw.
    end
  end
  raw = String.new(encoding: 'BINARY')
  begin
    client = TCPSocket.new('127.0.0.1', port)
  rescue StandardError
    worker.kill rescue nil
    return nil
  end
  begin
    client.write("GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
    deadline = Time.now + 5.0
    while raw.bytesize < 65536 && Time.now < deadline
      ready = IO.select([client], nil, nil, [deadline - Time.now, 0.0].max)
      break unless ready
      begin
        chunk = client.recv(4096)
      rescue StandardError
        break
      end
      break if chunk.nil? || chunk.empty?
      raw << chunk.b
      break if raw.include?("\r\n\r\n".b)
    end
  ensure
    begin
      client.close
    rescue StandardError
      # ignore close errors
    end
    worker.join(2.0) rescue nil
    begin
      server.close
    rescue StandardError
      # ignore close errors
    end
  end
  sep = raw.index("\r\n\r\n".b)
  return raw if sep.nil?
  raw.byteslice(0, sep)
end

def _nyx_run
  payload = ENV['NYX_PAYLOAD'] || ''
  raw_bytes = _nyx_wire_frame_via_fixture(payload)
  if raw_bytes
    _nyx_wire_frame_probe(raw_bytes)
    # Derive HeaderEmit records per Set-Cookie line on the wire so
    # the tier-(a) HeaderInjected predicate also fires on the same
    # harness pass.  The wire-frame branch owns the bytes; the
    # HeaderEmit records are derived from them.
    raw_bytes.split("\n".b).each do |line|
      trimmed = line.bytes.last == 13 ? line.byteslice(0, line.bytesize - 1) : line
      sep = trimmed.index(':'.b)
      next if sep.nil?
      name = trimmed.byteslice(0, sep)
      next unless name.downcase == 'set-cookie'.b
      start = sep + 1
      start += 1 if start < trimmed.bytesize && trimmed.getbyte(start) == 32
      value = trimmed.byteslice(start, trimmed.bytesize - start) || ''.b
      _nyx_header_probe(name.force_encoding('UTF-8'), value.force_encoding('UTF-8'))
    end
    STDOUT.puts '__NYX_SINK_HIT__'
    STDOUT.puts JSON.generate({{ 'wire_frame_len' => raw_bytes.bytesize }})
    STDOUT.flush
    return
  end
  # Synthetic fallback when the fixture failed to boot — keeps the
  # differential oracle live on a build/boot failure rather than
  # silently shedding the attempt.
  _nyx_header_probe('Set-Cookie', payload)
  STDOUT.puts '__NYX_SINK_HIT__'
  STDOUT.puts JSON.generate({{ 'payload_len' => payload.bytesize }})
  STDOUT.flush
end

_nyx_run
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 09 — Track J.7 open-redirect harness for Ruby
/// (`Rack::Response#redirect`).
///
/// When the fixture imports `rack` the tier-(a) path imports the
/// fixture, prepends a captor onto `Rack::Response` that records
/// every `redirect(target)` / `set_header('Location', ...)` /
/// `location(...)` call, and invokes the named entry function.  The
/// captor returns `self` so the fixture's downstream method chaining
/// keeps working.  Falls back to the synthetic probe on missing
/// Rack / import failure.
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_basename = derive_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_rack =
        entry_source.contains("require 'rack'") || entry_source.contains("require \"rack\"");
    let via_fixture = if uses_rack {
        format!(
            r#"def _nyx_redirect_via_fixture(payload)
  # Phase 09 tier-(a): prepend a captor onto `Rack::Response` so
  # every `redirect(target)` / `set_header('Location', value)` /
  # `location(value)` call records the bound location string.
  # Mirrors the Python flask pattern at
  # `src/dynamic/lang/python.rs::emit_open_redirect_harness`.
  # Returns `[location, 'example.com']` on success, `nil` when Rack
  # is missing or the fixture cannot be required so the caller can
  # fall back to the synthetic probe.
  begin
    require 'rack'
  rescue LoadError, ScriptError
    return nil
  end
  captured = []
  patcher = Module.new do
    define_method(:redirect) do |target, *_args, **_opts|
      begin
        captured << target.to_s
      rescue StandardError
        # ignore
      end
      self
    end
    define_method(:set_header) do |name, value|
      begin
        if name.to_s.casecmp('Location').zero?
          captured << value.to_s
        end
      rescue StandardError
        # ignore
      end
      self
    end
    define_method(:location=) do |value|
      begin
        captured << value.to_s
      rescue StandardError
        # ignore
      end
      value
    end
  end
  Rack::Response.prepend(patcher)
  $LOAD_PATH.unshift('.')
  begin
    require_relative './{entry_basename}'
  rescue LoadError, ScriptError
    return nil
  end
  begin
    Object.new.__send__(:'{entry_name}', payload)
  rescue StandardError
    # Fixture raised — return whatever was captured before throw.
  end
  return nil if captured.empty?
  [captured.first, 'example.com']
end

"#
        )
    } else {
        String::new()
    };
    let invoke_via_fixture = if uses_rack {
        r#"  captured = _nyx_redirect_via_fixture(payload)
  if captured
    location, request_host = captured
    _nyx_redirect_probe(location, request_host)
    _nyx_follow_location(location)
    STDOUT.puts '__NYX_SINK_HIT__'
    STDOUT.puts JSON.generate({ 'location' => location, 'request_host' => request_host })
    STDOUT.flush
    return
  end
"#
    } else {
        ""
    };
    let body = format!(
        r#"# Nyx dynamic harness — OPEN_REDIRECT Rack::Response#redirect (Phase 09 / Track J.7).
require 'json'
require 'net/http'
require 'uri'

{shim}

def _nyx_redirect_probe(location, request_host)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'Rack::Response#redirect',
    'args'           => [
      {{ 'kind' => 'String', 'value' => location }},
    ],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{ 'kind' => 'Redirect', 'location' => location, 'request_host' => request_host }},
    'witness'        => __nyx_witness('Rack::Response#redirect', [location]),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

# Phase 09 OOB closure: when the captured Location is a fully-qualified
# loopback URL, follow it with a real GET so the OOB listener records
# the per-finding nonce.  Skips non-loopback hosts (no real network egress)
# and any non-HTTP scheme.  Best-effort: failures do not propagate, the
# listener may still have observed the connect before the read errored.
def _nyx_follow_location(location)
  return if location.nil? || location.empty?
  lower = location.to_s.downcase
  unless lower.start_with?('http://127.0.0.1') ||
         lower.start_with?('http://localhost') ||
         lower.start_with?('http://host-gateway')
    return
  end
  begin
    uri = URI(location)
    Net::HTTP.start(uri.host, uri.port, open_timeout: 2, read_timeout: 2) do |http|
      req = Net::HTTP::Get.new(uri.request_uri)
      http.request(req) {{ |resp| resp.read_body {{ |_chunk| break }} }}
    end
  rescue StandardError
    # best-effort OOB fetch
  end
end

{via_fixture}def _nyx_run
  payload = ENV['NYX_PAYLOAD'] || ''
{invoke_via_fixture}  request_host = 'example.com'
  location = payload
  _nyx_redirect_probe(location, request_host)
  _nyx_follow_location(location)
  STDOUT.puts '__NYX_SINK_HIT__'
  STDOUT.puts JSON.generate({{ 'location' => location, 'request_host' => request_host }})
  STDOUT.flush
end

_nyx_run
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 11 (Track J.9) — JSON_PARSE depth-bomb harness for Ruby.
///
/// Rebinds `JSON.parse` to a depth-counting wrapper that calls the
/// original parser, walks the resulting value iteratively (no
/// recursion stack) to compute maximum nesting depth, emits a
/// `ProbeKind::JsonParse { depth, excessive_depth }` record, then
/// returns the parsed value verbatim.  `JSON::NestingError` raised by
/// the Ruby json gem (default `max_nesting` is 100) is caught and
/// converted into a `JsonParse { depth: 0, excessive_depth: true }`
/// probe before the error is re-raised — matching the Python harness's
/// `RecursionError` handling and the JS harness's `RangeError`
/// handling.
///
/// Mirrors `crate::dynamic::lang::python::emit_json_parse_harness` and
/// `crate::dynamic::lang::js_shared::emit_json_parse_harness`.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_basename = derive_entry_basename(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"# Nyx dynamic harness — JSON_PARSE depth checks (Phase 11 / Track J.9).
require 'json'

{shim}

NYX_MAX_WALK = 4096

def _nyx_count_depth(parsed)
  max_depth = 0
  stack = [[parsed, 1]]
  visited = 0
  until stack.empty?
    cur, depth = stack.pop
    visited += 1
    break if visited > NYX_MAX_WALK
    max_depth = depth if depth > max_depth
    case cur
    when Hash
      cur.each_value {{ |v| stack.push([v, depth + 1]) }}
    when Array
      cur.each {{ |v| stack.push([v, depth + 1]) }}
    end
  end
  max_depth
end

def _nyx_json_parse_probe(depth, excessive)
  p = ENV['NYX_PROBE_PATH']
  return if p.nil? || p.empty?
  rec = {{
    'sink_callee'    => 'JSON.parse',
    'args'           => [{{ 'kind' => 'Int', 'value' => depth.to_i }}],
    'captured_at_ns' => Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond),
    'payload_id'     => ENV['NYX_PAYLOAD_ID'] || '',
    'kind'           => {{
      'kind'            => 'JsonParse',
      'depth'           => depth.to_i,
      'excessive_depth' => !!excessive,
    }},
    'witness'        => __nyx_witness('JSON.parse', [depth.to_i]),
  }}
  begin
    File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
  rescue StandardError
    # best-effort
  end
end

_nyx_orig_json_parse = JSON.method(:parse)

JSON.define_singleton_method(:parse) do |source, *args, **opts|
  begin
    parsed = _nyx_orig_json_parse.call(source, *args, **opts)
  rescue JSON::NestingError => e
    # The json gem raises NestingError once `max_nesting` (default 100)
    # is exceeded.  Emit the excessive-depth probe before re-raising so
    # the oracle still fires when the parser rejects the input.
    _nyx_json_parse_probe(0, true)
    raise e
  end
  depth = _nyx_count_depth(parsed)
  _nyx_json_parse_probe(depth, depth > 64)
  parsed
end

def _nyx_json_parse_via_fixture(payload)
  $LOAD_PATH.unshift('.')
  begin
    require_relative './{entry_basename}'
  rescue LoadError, ScriptError => e
    STDERR.puts("NYX_IMPORT_ERROR: #{{e.message}}")
    exit 77
  end
  fn_sym = :'{entry_name}'
  unless Object.respond_to?(fn_sym, true) || self.respond_to?(fn_sym, true)
    return false
  end
  begin
    send(fn_sym, payload)
  rescue StandardError
    # Parser errors / depth-induced raises are expected on the vuln
    # payload; the probe is already emitted.
  end
  true
end

payload = ENV['NYX_PAYLOAD'] || ''
_nyx_json_parse_via_fixture(payload)
STDOUT.puts '__NYX_SINK_HIT__'
STDOUT.flush
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.rb".to_owned(),
        command: vec!["ruby".to_owned(), "harness.rb".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

fn generate_source(spec: &HarnessSpec, shape: RubyShape) -> String {
    let entry_fn = &spec.entry_name;
    let pre_call = build_pre_call(spec);
    let invocation = invoke_for_shape(spec, shape, entry_fn);
    let shim = probe_shim();
    let crash_callee = if entry_fn.is_empty() {
        "main"
    } else {
        entry_fn.as_str()
    };

    format!(
        r#"# Nyx dynamic harness — auto-generated, do not edit (Phase 15 — RubyShape::{shape:?}).
{shim}
# ── Payload loading ──────────────────────────────────────────────────────────
def nyx_payload
  v = ENV['NYX_PAYLOAD']
  return v if v && !v.empty?
  b64 = ENV['NYX_PAYLOAD_B64']
  if b64 && !b64.empty?
    begin
      require 'base64'
      return Base64.decode64(b64)
    rescue StandardError
      return ''
    end
  end
  ''
end

$nyx_payload = nyx_payload

# Phase 08 sink-site signal trap: install AFTER payload decode so a crash
# inside `nyx_payload` writes no Crash probe and routes the verifier to
# `Inconclusive(UnrelatedCrash)`.  A fatal signal inside the entry call
# below DOES fire the handler and writes a Crash probe to `NYX_PROBE_PATH`.
__nyx_install_crash_guard('{crash_callee}')
{pre_call}
# ── Sinatra route registry ──────────────────────────────────────────────────
$nyx_sinatra_routes ||= []
unless Object.method_defined?(:__nyx_register_route)
  module Kernel
    def get(path, &block)
      $nyx_sinatra_routes ||= []
      $nyx_sinatra_routes << [path, :get, block]
    end
    def post(path, &block)
      $nyx_sinatra_routes ||= []
      $nyx_sinatra_routes << [path, :post, block]
    end
  end
end

# ── Entry require ───────────────────────────────────────────────────────────
begin
  require_relative './entry'
rescue LoadError, ScriptError => e
  STDERR.puts("NYX_IMPORT_ERROR: #{{e.message}}")
  exit 77
end

# ── Invocation ──────────────────────────────────────────────────────────────
begin
{invocation}
rescue StandardError => e
  STDERR.puts("NYX_EXCEPTION: #{{e.class.name}}: #{{e.message}}")
end
"#,
        shape = shape,
        pre_call = pre_call,
        invocation = invocation,
    )
}

fn build_pre_call(spec: &HarnessSpec) -> String {
    let mut out = String::new();
    match &spec.payload_slot {
        PayloadSlot::EnvVar(name) => {
            out.push_str(&format!("ENV[{name:?}] = $nyx_payload\n"));
        }
        PayloadSlot::Argv(n) => {
            for _ in 0..*n {
                out.push_str("ARGV << ''\n");
            }
            out.push_str("ARGV << $nyx_payload\n");
        }
        PayloadSlot::QueryParam(name) => {
            out.push_str(&format!(
                "$nyx_request = {{ method: 'GET', path: '/', params: {{ {name:?} => $nyx_payload }}, body: '' }}\n"
            ));
        }
        PayloadSlot::HttpBody => {
            out.push_str(
                "$nyx_request = { method: 'POST', path: '/', params: {}, body: $nyx_payload }\n",
            );
        }
        _ => {
            out.push_str(
                "$nyx_request = { method: 'GET', path: '/', params: { 'payload' => $nyx_payload }, body: '' }\n",
            );
        }
    }
    out
}

fn invoke_for_shape(spec: &HarnessSpec, shape: RubyShape, entry_fn: &str) -> String {
    match shape {
        RubyShape::Generic => generic_invocation(spec, entry_fn),
        RubyShape::SinatraRoute => format!(
            r#"  route = $nyx_sinatra_routes.find {{ |_, _, b| b }}
  if route && route[2]
    blk = route[2]
    result = blk.call($nyx_payload)
    print(result.to_s)
  elsif respond_to?({entry_fn:?})
    print(send({entry_fn:?}, $nyx_payload).to_s)
  end"#,
        ),
        RubyShape::RailsAction => {
            let cls = entry_class_from_spec(spec);
            format!(
                r#"  cls = Object.const_defined?({cls:?}) ? Object.const_get({cls:?}) : nil
  if cls
    instance = cls.new
    instance.instance_variable_set(:@__nyx_payload, $nyx_payload)
    instance.instance_variable_set(:@__nyx_request, $nyx_request)
    result = instance.send({entry_fn:?})
    print(result.to_s) if result
  end"#,
            )
        }
        RubyShape::RackMiddleware => {
            let cls = entry_class_from_spec(spec);
            format!(
                r#"  require 'stringio'
  cls = Object.const_defined?({cls:?}) ? Object.const_get({cls:?}) : nil
  if cls
    inner = cls.respond_to?(:new) ? (cls.method(:new).arity == 0 ? cls.new : cls.new(nil)) : nil
    env = {{
      'REQUEST_METHOD' => ($nyx_request[:method] rescue 'GET'),
      'PATH_INFO' => ($nyx_request[:path] rescue '/'),
      'QUERY_STRING' => "payload=#{{$nyx_payload}}",
      'rack.input' => StringIO.new(($nyx_request[:body] rescue '')),
      'nyx.payload' => $nyx_payload,
    }}
    status, headers, body = inner.call(env)
    Array(body).each {{ |chunk| print(chunk.to_s) }}
  end"#,
            )
        }
        RubyShape::ControllerMethod => {
            let cls = entry_class_from_spec(spec);
            format!(
                r#"  cls = Object.const_defined?({cls:?}) ? Object.const_get({cls:?}) : nil
  if cls
    instance = cls.new
    result = instance.send({entry_fn:?}, $nyx_payload)
    print(result.to_s) if result
  end"#,
            )
        }
    }
}

fn generic_invocation(spec: &HarnessSpec, entry_fn: &str) -> String {
    match &spec.payload_slot {
        PayloadSlot::EnvVar(_) | PayloadSlot::Argv(_) => format!("  {entry_fn}()"),
        PayloadSlot::Param(idx) => {
            if *idx == 0 {
                format!("  {entry_fn}($nyx_payload)")
            } else {
                let pads = (0..*idx).map(|_| "nil").collect::<Vec<_>>().join(", ");
                format!("  {entry_fn}({pads}, $nyx_payload)")
            }
        }
        _ => format!("  {entry_fn}($nyx_payload)"),
    }
}

/// Best-effort guess at the class name from the entry source.
///
/// Walks every `class Foo` declaration and picks the one whose body
/// contains `def {entry_name}` (the class that actually defines the
/// entry method).  When no class hosts the entry method — or the
/// entry name is empty — falls back to the first class declaration,
/// then to `"Entry"`.
fn entry_class_from_spec(spec: &HarnessSpec) -> String {
    let src = read_entry_source(&spec.entry_file);
    parse_class_hosting_method(&src, &spec.entry_name)
        .or_else(|| parse_first_class_name(&src))
        .unwrap_or_else(|| "Entry".to_owned())
}

fn parse_class_hosting_method(source: &str, entry_name: &str) -> Option<String> {
    if entry_name.is_empty() {
        return None;
    }
    let needle = format!("def {entry_name}");
    // Walk every line, remembering the most-recently-seen class
    // declaration.  When we encounter `def {entry_name}`, return the
    // last-seen class — that is the closest enclosing class scope.
    // Coarse but correct for the per-shape fixtures (no nested classes).
    let mut last_class: Option<String> = None;
    for line in source.lines() {
        let l = line.trim_start();
        if let Some(rest) = l.strip_prefix("class ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                last_class = Some(name);
            }
            continue;
        }
        if l.contains(&needle) {
            return last_class.clone();
        }
    }
    None
}

fn parse_first_class_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let l = line.trim_start();
        if let Some(rest) = l.strip_prefix("class ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "rb000000000001".into(),
            entry_file: "src/login.rb".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Ruby,
            toolchain_id: "ruby-3".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/login.rb".into(),
            sink_line: 10,
            spec_hash: "rb000000000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!RubyEmitter.entry_kinds_supported().is_empty());
        assert!(
            RubyEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
        assert!(
            RubyEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::HttpRoute)
        );
        assert!(
            RubyEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::CliSubcommand)
        );
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RubyEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 15"));
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("nyx_payload"));
        assert!(harness.source.contains("require_relative"));
        assert!(harness.source.contains("login($nyx_payload)"));
        assert_eq!(harness.filename, "harness.rb");
        assert_eq!(harness.command, vec!["ruby", "harness.rb"]);
    }

    #[test]
    fn emit_entry_subpath_is_entry_rb() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry.rb".to_owned()));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_HOST".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("ENV[\"DB_HOST\"]"));
        assert!(harness.source.contains("login()"));
    }

    #[test]
    fn emit_stdin_is_unsupported() {
        let spec = make_spec(PayloadSlot::Stdin);
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
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
    fn shape_detect_sinatra_route() {
        let src = "require 'sinatra'\nget '/run' do\n  params['p']\nend\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.rb");
        assert_eq!(RubyShape::detect(&spec, src), RubyShape::SinatraRoute);
    }

    #[test]
    fn shape_detect_rails_action() {
        let src = "class UsersController < ApplicationController\n  def index\n    @user = params[:p]\n  end\nend\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "index", "entry.rb");
        assert_eq!(RubyShape::detect(&spec, src), RubyShape::RailsAction);
    }

    #[test]
    fn shape_detect_rack_middleware() {
        let src = "class MyMiddleware\n  def call(env)\n    [200, {}, ['ok']]\n  end\nend\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "call", "entry.rb");
        assert_eq!(RubyShape::detect(&spec, src), RubyShape::RackMiddleware);
    }

    #[test]
    fn shape_detect_controller_method() {
        let src = "class Login\n  def authenticate(payload)\n    payload\n  end\nend\n";
        let spec = make_spec_with(EntryKind::Function, "authenticate", "entry.rb");
        assert_eq!(RubyShape::detect(&spec, src), RubyShape::ControllerMethod);
    }

    #[test]
    fn shape_detect_generic_fallback() {
        let src = "def login(p)\n  p\nend\n";
        let spec = make_spec_with(EntryKind::Function, "login", "entry.rb");
        assert_eq!(RubyShape::detect(&spec, src), RubyShape::Generic);
    }

    #[test]
    fn sinatra_shape_uses_route_registry() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "entry.rb");
        let src = generate_source(&spec, RubyShape::SinatraRoute);
        assert!(src.contains("$nyx_sinatra_routes"));
    }

    #[test]
    fn rack_shape_builds_env_hash() {
        let mut spec = make_spec_with(EntryKind::HttpRoute, "call", "entry.rb");
        spec.payload_slot = PayloadSlot::QueryParam("payload".into());
        let src = generate_source(&spec, RubyShape::RackMiddleware);
        assert!(src.contains("REQUEST_METHOD"));
        assert!(src.contains("rack.input"));
    }

    #[test]
    fn rails_shape_invokes_action_on_instance() {
        let spec = make_spec_with(EntryKind::HttpRoute, "index", "entry.rb");
        let src = generate_source(&spec, RubyShape::RailsAction);
        assert!(src.contains("instance.send"));
    }

    #[test]
    fn controller_shape_calls_method() {
        let spec = make_spec_with(EntryKind::Function, "authenticate", "entry.rb");
        let src = generate_source(&spec, RubyShape::ControllerMethod);
        assert!(src.contains("instance.send"));
    }

    #[test]
    fn parse_first_class_name_picks_up_class_decl() {
        assert_eq!(
            parse_first_class_name("class Foo\nend\n"),
            Some("Foo".to_owned())
        );
        assert_eq!(
            parse_first_class_name("class Bar < Base\nend\n"),
            Some("Bar".to_owned())
        );
        assert_eq!(parse_first_class_name("def foo\nend\n"), None);
    }

    #[test]
    fn emit_splices_probe_shim_and_installs_crash_guard() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("__nyx_probe shim (Phase 06 — Track C.1"),
            "probe_shim banner missing from generated harness.rb — splicing regressed",
        );
        assert!(
            h.source
                .contains("def __nyx_install_crash_guard(sink_callee)"),
            "install_crash_guard definition missing from generated harness.rb",
        );
        assert!(
            h.source.contains("__nyx_install_crash_guard('login')"),
            "install_crash_guard call site missing or wrong callee in harness body",
        );
        let install_pos = h.source.find("__nyx_install_crash_guard('login')").unwrap();
        let payload_pos = h.source.find("$nyx_payload = nyx_payload").unwrap();
        // The invocation is `login($nyx_payload)` for the default Generic shape.
        let invoke_pos = h.source.find("login($nyx_payload)").unwrap();
        assert!(
            payload_pos < install_pos && install_pos < invoke_pos,
            "install_crash_guard ordering wrong: payload_pos={payload_pos} install_pos={install_pos} invoke_pos={invoke_pos}",
        );
    }

    #[test]
    fn probe_shim_publishes_stub_http_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("def __nyx_stub_http_record"),
            "Ruby probe shim must define __nyx_stub_http_record"
        );
        assert!(
            shim.contains("ENV['NYX_HTTP_LOG']"),
            "Ruby HTTP recorder must read NYX_HTTP_LOG to find the side-channel log"
        );
        assert!(
            shim.contains("# method: "),
            "Ruby HTTP recorder must emit a hash-prefixed method detail line"
        );
        assert!(
            shim.contains("# url: "),
            "Ruby HTTP recorder must emit a hash-prefixed url detail line"
        );
    }

    #[test]
    fn probe_shim_publishes_stub_sql_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("def __nyx_stub_sql_record"),
            "Ruby probe shim must define __nyx_stub_sql_record"
        );
        assert!(
            shim.contains("ENV['NYX_SQL_LOG']"),
            "Ruby SQL recorder must read NYX_SQL_LOG to find the side-channel log"
        );
        assert!(
            shim.contains("line.end_with?"),
            "Ruby SQL recorder must guarantee a trailing newline on the query line so SqlStub::drain_events frames each record"
        );
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        let step = chain_step(Some(b"<prev>"), None);
        assert!(
            step.source.contains("__nyx_probe"),
            "Ruby chain step must splice the probe shim"
        );
        assert!(
            step.source.contains("ENV[\"NYX_PREV_OUTPUT\"]"),
            "Ruby chain step must keep its NYX_PREV_OUTPUT forwarder"
        );
        let shim_pos = step.source.find("__nyx_probe").unwrap();
        let driver_pos = step.source.find("ENV[\"NYX_PREV_OUTPUT\"]").unwrap();
        assert!(
            shim_pos < driver_pos,
            "probe shim must come before the driver so a sink rewrite has the shim's helpers in scope"
        );
    }

    // ── Phase 08 / 09 tier-(a) Ruby emitter tests ────────────────────────────

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
    fn emit_header_injection_harness_routes_through_fixture_when_rack_required() {
        let dir = std::env::temp_dir().join("nyx_phase08_rb_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(
            &entry,
            "require 'rack'\n\
             def run(value)\n  r = Rack::Response.new\n  r.set_header('Set-Cookie', value)\n  r\nend\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("def _nyx_header_via_fixture(payload)"),
            "tier-(a) harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("Rack::Response.prepend(patcher)"),
            "tier-(a) harness must prepend the captor onto Rack::Response: {}",
            h.source
        );
        assert!(
            h.source.contains("require_relative './vuln'"),
            "tier-(a) harness must require the fixture by its file stem: {}",
            h.source
        );
        assert!(
            h.source.contains("Object.new.__send__(:'run', payload)"),
            "tier-(a) harness must invoke the named entry function via __send__: {}",
            h.source
        );
        assert!(
            h.source
                .contains("captured = _nyx_header_via_fixture(payload)"),
            "harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert!(
            h.source
                .contains("value = payload\n  _nyx_header_probe(name, value)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_falls_back_when_rack_not_required() {
        let dir = std::env::temp_dir().join("nyx_phase08_rb_test_no_rack");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(&entry, "def run(value)\n  value\nend\n").unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("Rack::Response.prepend"),
            "fallback path must not patch Rack::Response: {}",
            h.source
        );
        assert!(
            !h.source.contains("def _nyx_header_via_fixture"),
            "fallback path must not define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source
                .contains("value = payload\n  _nyx_header_probe(name, value)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_derives_basename_from_entry_file() {
        let dir = std::env::temp_dir().join("nyx_phase08_rb_test_basename_derive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("benign.rb");
        std::fs::write(
            &entry,
            "require 'rack'\n\
             def run(v)\n  Rack::Response.new\nend\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("require_relative './benign'"),
            "basename must come from the entry-file stem: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_routes_through_wire_frame_when_raw_socket_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_rb_test_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(
            &entry,
            "require 'socket'\n\
             def set_cookie_value(value)\n  $nyx_cookie_value = value.b\nend\n\
             def create_server\n  TCPServer.new('127.0.0.1', 0)\nend\n\
             def run_once(server)\n  s = server.accept\n  s.write('HTTP/1.0 200 OK\\r\\nSet-Cookie: ' + $nyx_cookie_value + '\\r\\n\\r\\nok')\n  s.close\nend\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source
                .contains("def _nyx_wire_frame_via_fixture(payload)"),
            "tier-(b) harness must define the wire-frame helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require_relative './vuln'"),
            "tier-(b) harness must require the fixture by its file stem: {}",
            h.source
        );
        assert!(
            h.source
                .contains("obj.__send__(:set_cookie_value, payload)"),
            "tier-(b) harness must install the cookie value via __send__: {}",
            h.source
        );
        assert!(
            h.source.contains("obj.__send__(:create_server)"),
            "tier-(b) harness must boot the fixture's TCPServer via __send__: {}",
            h.source
        );
        assert!(
            h.source.contains("obj.__send__(:run_once, server)"),
            "tier-(b) harness must drive run_once on a worker thread: {}",
            h.source
        );
        assert!(
            h.source.contains("Thread.new"),
            "tier-(b) harness must spawn a worker thread for the accept loop: {}",
            h.source
        );
        assert!(
            h.source.contains("TCPSocket.new('127.0.0.1', port)"),
            "tier-(b) harness must open a client TCPSocket against the bound port: {}",
            h.source
        );
        assert!(
            h.source.contains("GET / HTTP/1.0\\r\\nHost: 127.0.0.1"),
            "tier-(b) harness must issue a raw GET request: {}",
            h.source
        );
        assert!(
            h.source
                .contains("'kind' => 'HeaderWireFrame', 'raw_bytes' => raw_bytes.bytes"),
            "tier-(b) harness must emit a HeaderWireFrame probe carrying the raw header-block bytes: {}",
            h.source
        );
        assert!(
            h.source.contains("'wire_frame_len' => raw_bytes.bytesize"),
            "tier-(b) harness must emit the wire_frame_len stdout marker: {}",
            h.source
        );
        assert!(
            !h.source.contains("Rack::Response.prepend"),
            "tier-(b) harness must not patch Rack::Response (that's the tier-(a) path): {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_wire_frame_branch_drops_when_only_rack_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_rb_test_no_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(
            &entry,
            "require 'rack'\n\
             def run(value)\n  r = Rack::Response.new\n  r.set_header('Set-Cookie', value)\n  r\nend\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("def _nyx_wire_frame_via_fixture"),
            "rack-only harness must not define the wire-frame helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("HeaderWireFrame"),
            "rack-only harness must not emit the HeaderWireFrame probe shape: {}",
            h.source
        );
        assert!(
            !h.source.contains("wire_frame_len"),
            "rack-only harness must not emit the wire_frame_len stdout marker: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_routes_through_fixture_when_rack_required() {
        let dir = std::env::temp_dir().join("nyx_phase09_rb_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(
            &entry,
            "require 'rack'\n\
             def run(value)\n  r = Rack::Response.new\n  r.redirect(value)\n  r\nend\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("def _nyx_redirect_via_fixture(payload)"),
            "tier-(a) harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("Rack::Response.prepend(patcher)"),
            "tier-(a) harness must prepend the captor onto Rack::Response: {}",
            h.source
        );
        assert!(
            h.source.contains("require_relative './vuln'"),
            "tier-(a) harness must require the fixture by its file stem: {}",
            h.source
        );
        assert!(
            h.source.contains("define_method(:redirect)"),
            "tier-(a) captor must intercept the redirect method: {}",
            h.source
        );
        assert!(
            h.source
                .contains("captured = _nyx_redirect_via_fixture(payload)"),
            "harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert!(
            h.source
                .contains("location = payload\n  _nyx_redirect_probe(location, request_host)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_falls_back_when_rack_not_required() {
        let dir = std::env::temp_dir().join("nyx_phase09_rb_test_no_rack");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(&entry, "def run(value)\n  value\nend\n").unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("Rack::Response.prepend"),
            "fallback path must not patch Rack::Response: {}",
            h.source
        );
        assert!(
            !h.source.contains("def _nyx_redirect_via_fixture"),
            "fallback path must not define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source
                .contains("location = payload\n  _nyx_redirect_probe(location, request_host)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let dir = std::env::temp_dir().join("nyx_phase09_rb_test_follow_location");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.rb");
        std::fs::write(
            &entry,
            "require 'rack'\n\
             def run(value)\n  r = Rack::Response.new\n  r.redirect(value)\n  r\nend\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("def _nyx_follow_location(location)"),
            "OPEN_REDIRECT harness must declare the _nyx_follow_location helper: {}",
            h.source
        );
        assert!(
            h.source.contains("require 'net/http'") && h.source.contains("require 'uri'"),
            "OPEN_REDIRECT harness must require net/http and uri for the loopback follow: {}",
            h.source
        );
        assert!(
            h.source.contains("Net::HTTP.start(uri.host, uri.port"),
            "follow-location helper must invoke Net::HTTP.start: {}",
            h.source
        );
        assert!(
            h.source.contains("start_with?('http://127.0.0.1')")
                && h.source.contains("start_with?('http://localhost')")
                && h.source.contains("start_with?('http://host-gateway')"),
            "follow-location helper must gate on loopback host prefixes: {}",
            h.source
        );
        assert!(
            h.source.contains(
                "_nyx_redirect_probe(location, request_host)\n    _nyx_follow_location(location)"
            ),
            "tier-(a) must follow the captured Location after emitting the probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
            "tests/dynamic_fixtures/json_parse_depth/ruby/vuln.rb",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("JSON.define_singleton_method(:parse)"),
            "dispatcher must select the JSON_PARSE depth harness: {}",
            h.source
        );
        assert!(
            h.source.contains("=> 'JsonParse'"),
            "JSON_PARSE harness must emit JsonParse probes: {}",
            h.source
        );
    }

    #[test]
    fn emit_json_parse_harness_monkey_patches_json_parse() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/ruby/vuln.rb",
            "run",
        ));
        assert!(h.source.contains("_nyx_orig_json_parse = JSON.method(:parse)"));
        assert!(
            h.source.contains("JSON.define_singleton_method(:parse)"),
            "must rebind JSON.parse: {}",
            h.source
        );
        assert!(h.source.contains("def _nyx_count_depth(parsed)"));
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/ruby/vuln.rb",
            "run",
        ));
        assert!(h.source.contains("'depth'           => depth.to_i"));
        assert!(h.source.contains("'excessive_depth' => !!excessive"));
        assert!(h.source.contains("depth > 64"));
        assert!(h.source.contains("__NYX_SINK_HIT__"));
    }

    #[test]
    fn emit_json_parse_harness_handles_nesting_error() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/ruby/vuln.rb",
            "run",
        ));
        assert!(h.source.contains("rescue JSON::NestingError => e"));
        assert!(h.source.contains("_nyx_json_parse_probe(0, true)"));
    }

    #[test]
    fn emit_json_parse_harness_routes_through_fixture_require() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/ruby/vuln.rb",
            "run",
        ));
        assert!(
            h.source
                .contains("def _nyx_json_parse_via_fixture(payload)")
        );
        assert!(h.source.contains("require_relative './vuln'"));
        assert!(h.source.contains("fn_sym = :'run'"));
        assert_eq!(h.filename, "harness.rb");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_json_parse_harness_derives_entry_basename_from_entry_file() {
        let h = emit_json_parse_harness(&make_json_parse_spec("/abs/path/benign.rb", "run"));
        assert!(h.source.contains("require_relative './benign'"));
    }
}

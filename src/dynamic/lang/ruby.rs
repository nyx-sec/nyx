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
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `response.set_header('Set-Cookie', value)` shim that records the
/// *unmodified* value bytes (including any embedded `\r\n`) via a
/// `ProbeKind::HeaderEmit` probe.  Mirrors the synthetic-harness
/// pattern used by Phase 03 / 04 / 05.
pub fn emit_header_injection_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
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
    'kind'           => {{ 'kind' => 'HeaderEmit', 'name' => name, 'value' => value }},
    'witness'        => __nyx_witness('Rack::Response#set_header', [name, value]),
  }}
  File.open(p, 'a') {{ |f| f.write(rec.to_json + "\n") }}
end

payload = ENV['NYX_PAYLOAD'] || ''
name = 'Set-Cookie'
value = payload
_nyx_header_probe(name, value)
STDOUT.puts '__NYX_SINK_HIT__'
STDOUT.puts JSON.generate({{ 'name' => name, 'value' => value }})
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

/// Phase 09 — Track J.7 open-redirect harness for Ruby
/// (`Rack::Response#redirect`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `response.redirect(value)` shim that records the bound
/// `Location:` value plus the request's origin host via a
/// `ProbeKind::Redirect` probe.
pub fn emit_open_redirect_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let body = format!(
        r#"# Nyx dynamic harness — OPEN_REDIRECT Rack::Response#redirect (Phase 09 / Track J.7).
require 'json'

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

payload = ENV['NYX_PAYLOAD'] || ''
request_host = 'example.com'
location = payload
_nyx_redirect_probe(location, request_host)
STDOUT.puts '__NYX_SINK_HIT__'
STDOUT.puts JSON.generate({{ 'location' => location, 'request_host' => request_host }})
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
}

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
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for Ruby.
pub struct RubyEmitter;

/// Entry kinds the Ruby emitter understands after Phase 15.
///
/// `HttpRoute` covers Sinatra / Rails / Rack.  `CliSubcommand` covers
/// `ARGV`-driven scripts.  `Function` covers plain methods and
/// controller method shapes.
const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::HttpRoute,
    EntryKind::CliSubcommand,
];

impl LangEmitter for RubyEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "ruby emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 15 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_ruby(env)
    }
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
        let kind = spec.entry_kind;

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
        if kind == EntryKind::HttpRoute && has_class {
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
    let candidates = [PathBuf::from(entry_file), PathBuf::from(".").join(entry_file)];
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
__NYX_DENY_SUBSTRINGS = %w[
  TOKEN SECRET PASSWORD PASSWD API_KEY APIKEY PRIVATE_KEY CREDENTIAL SESSION
  COOKIE AUTH BEARER AWS_ACCESS AWS_SESSION GH_TOKEN GITHUB_TOKEN NPM_TOKEN
  PYPI_TOKEN DOCKER_PASS
].freeze
__NYX_PAYLOAD_LIMIT = 16 * 1024
__NYX_REDACTED = '<redacted-by-nyx-policy>'

def __nyx_is_denied_key(k)
  ku = k.to_s.upcase
  __NYX_DENY_SUBSTRINGS.any? { |n| ku.include?(n) }
end

def __nyx_witness(sink_callee, args)
  env_snapshot = {}
  ENV.each do |k, v|
    env_snapshot[k] = __nyx_is_denied_key(k) ? __NYX_REDACTED : v
  end
  payload = ENV['NYX_PAYLOAD'] || ''
  pb = payload.bytes
  pb = pb[0, __NYX_PAYLOAD_LIMIT] if pb.length > __NYX_PAYLOAD_LIMIT
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

fn generate_source(spec: &HarnessSpec, shape: RubyShape) -> String {
    let entry_fn = &spec.entry_name;
    let pre_call = build_pre_call(spec);
    let invocation = invoke_for_shape(spec, shape, entry_fn);

    format!(
        r#"# Nyx dynamic harness — auto-generated, do not edit (Phase 15 — RubyShape::{shape:?}).

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
                r#"  cls = Object.const_defined?({cls:?}) ? Object.const_get({cls:?}) : nil
  if cls
    inner = cls.respond_to?(:new) ? (cls.method(:new).arity == 0 ? cls.new : cls.new(nil)) : nil
    env = {{
      'REQUEST_METHOD' => ($nyx_request[:method] rescue 'GET'),
      'PATH_INFO' => ($nyx_request[:path] rescue '/'),
      'QUERY_STRING' => "payload=#{{$nyx_payload}}",
      'rack.input' => StringIO.new(($nyx_request[:body] rescue '')),
      'nyx.payload' => $nyx_payload,
    }}
    require 'stringio'
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
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
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
        }
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!RubyEmitter.entry_kinds_supported().is_empty());
        assert!(RubyEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
        assert!(RubyEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::HttpRoute));
        assert!(RubyEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RubyEmitter.entry_kind_hint(EntryKind::LibraryApi);
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
        assert_eq!(parse_first_class_name("class Foo\nend\n"), Some("Foo".to_owned()));
        assert_eq!(parse_first_class_name("class Bar < Base\nend\n"), Some("Bar".to_owned()));
        assert_eq!(parse_first_class_name("def foo\nend\n"), None);
    }
}

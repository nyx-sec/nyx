//! Ruby harness emitter (stub).
//!
//! No harness source is generated yet — `emit` returns
//! [`UnsupportedReason::LangUnsupported`].  The module exists so that
//! [`crate::dynamic::lang::entry_kinds_supported`] can advertise the entry
//! kinds Track B will deliver (Phase 15: Sinatra route, Rails action, Rack
//! middleware, generic controller method) and so the verifier can surface
//! a structured `Inconclusive(EntryKindUnsupported { … })` instead of
//! silently dropping Ruby findings.

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for Ruby.
pub struct RubyEmitter;

/// Entry kinds the Ruby emitter intends to support once Phase 15 lands.
/// Advertised pre-implementation so the verifier can route findings into
/// `Inconclusive(EntryKindUnsupported)` rather than `Unsupported`.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

/// Source of the `__nyx_probe` shim for the (future) Ruby harness
/// (Phase 06 — Track C.1).  Defined here for the deliverable contract
/// even though `emit` returns `LangUnsupported` until Phase 15 lands.
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

impl LangEmitter for RubyEmitter {
    fn emit(&self, _spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        Err(UnsupportedReason::LangUnsupported)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "ruby emitter is a stub; once Phase 15 (Track B Ruby vertical) lands it will support {SUPPORTED:?} plus Sinatra / Rails / Rack route shapes — attempted `EntryKind::{attempted}`"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_ruby(env)
    }
}

/// Phase 09 — Track D.2: synthesise a `Gemfile` listing every captured
/// gem name.  Ruby `require` statements give us first-segment package
/// names directly so the manifest can name real gems.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!RubyEmitter.entry_kinds_supported().is_empty());
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RubyEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("Phase 15"));
    }

    #[test]
    fn emit_returns_lang_unsupported() {
        let spec = HarnessSpec {
            finding_id: "0".into(),
            entry_file: "x.rb".into(),
            entry_name: "f".into(),
            entry_kind: EntryKind::Function,
            lang: crate::symbol::Lang::Ruby,
            toolchain_id: "ruby-3".into(),
            payload_slot: crate::dynamic::spec::PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "x.rb".into(),
            sink_line: 1,
            spec_hash: "0".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        };
        assert_eq!(
            RubyEmitter.emit(&spec).unwrap_err(),
            UnsupportedReason::LangUnsupported
        );
    }
}

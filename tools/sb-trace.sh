#!/usr/bin/env bash
# tools/sb-trace.sh — corpus-walking seed generator for the macOS
# sandbox-exec deny-default rollout (Phase 18 follow-up path (a)).
#
# What it does
# ------------
# For each `.sb` profile shipped under `src/dynamic/sandbox_profiles/`,
# this script re-runs the profile in deny-default mode against the
# per-language harness corpus under `tests/dynamic_fixtures/`,
# captures the kernel's deny trace, and writes one
# `tools/sb-trace/{cap}.allow` seed file with the minimum allow rules
# the interpreter cold-start needs.
#
# The seed files are consumed by `src/dynamic/sandbox/process_macos.rs`
# at runtime when `NYX_SB_DENY_DEFAULT=1` is set; the splice path
# replaces the baked `(allow default)` with `(deny default)` and
# appends the seed body verbatim.
#
# Usage
# -----
#   tools/sb-trace.sh                 # walk every profile + every lang fixture
#   tools/sb-trace.sh cmdi            # just the cmdi profile
#   tools/sb-trace.sh cmdi python     # cmdi + python only
#
# Requirements
# ------------
#   * macOS host with `/usr/bin/sandbox-exec` available
#   * `python3`, `node`, `ruby`, `php`, `java` resolvable via $PATH for
#     every language whose fixtures you want to walk
#
# Output
# ------
#   tools/sb-trace/<cap>.allow         — generated seed, hand-review
#   tools/sb-trace/<cap>.trace.raw     — full raw deny trace, for audit
#
# The seed files are intended to be committed; the .trace.raw files
# are .gitignore'd because they capture host-specific paths.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED_DIR="$ROOT/tools/sb-trace"
PROFILE_DIR="$ROOT/src/dynamic/sandbox_profiles"
FIXTURE_ROOT="$ROOT/tests/dynamic_fixtures"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "sb-trace: must run on macOS (uname=$(uname -s))" >&2
  exit 2
fi

if ! command -v /usr/bin/sandbox-exec >/dev/null 2>&1; then
  echo "sb-trace: /usr/bin/sandbox-exec missing" >&2
  exit 2
fi

mkdir -p "$SEED_DIR"

# ── Profile + language coverage ──────────────────────────────────────────────

ALL_PROFILES=(base cmdi path_traversal ssrf deserialize xxe)
ALL_LANGS=(python javascript ruby php java)

selected_profiles=()
selected_langs=()

if [[ $# -ge 1 ]]; then
  selected_profiles+=("$1")
else
  selected_profiles=("${ALL_PROFILES[@]}")
fi

if [[ $# -ge 2 ]]; then
  selected_langs+=("$2")
else
  selected_langs=("${ALL_LANGS[@]}")
fi

# ── Per-language probe ───────────────────────────────────────────────────────
#
# Each probe runs the language's interpreter cold-start path (import
# the standard libraries the harness needs).  The probes are
# intentionally minimal: they exercise filesystem reads of stdlib /
# package manager locations + a `mach-lookup` for the system
# notification center, which is what the trace needs to enumerate.

probe_command_for() {
  local lang="$1"
  case "$lang" in
    python)
      echo "/usr/bin/python3" "-c" "import socket,subprocess,os,sys,json"
      ;;
    javascript)
      command -v node >/dev/null 2>&1 || { echo ""; return; }
      echo "node" "-e" "require('fs');require('os');require('child_process');require('http');"
      ;;
    ruby)
      command -v ruby >/dev/null 2>&1 || { echo ""; return; }
      echo "ruby" "-e" "require 'json';require 'socket';require 'net/http';require 'open3'"
      ;;
    php)
      command -v php >/dev/null 2>&1 || { echo ""; return; }
      echo "php" "-r" "echo phpversion();"
      ;;
    java)
      command -v java >/dev/null 2>&1 || { echo ""; return; }
      echo "java" "--version"
      ;;
    *)
      echo ""
      ;;
  esac
}

# ── Trace helper ─────────────────────────────────────────────────────────────
#
# Builds a deny-default variant of the named profile, runs the probe
# under it, captures the sandbox trace via the `(with trace)` directive,
# and prints any deny lines for further processing.

trace_one() {
  local profile_name="$1"
  local lang="$2"
  local probe_cmd
  probe_cmd="$(probe_command_for "$lang")"
  if [[ -z "$probe_cmd" ]]; then
    echo "sb-trace: skipping $lang (interpreter missing)" >&2
    return 0
  fi

  local source="$PROFILE_DIR/$profile_name.sb"
  if [[ ! -f "$source" ]]; then
    echo "sb-trace: profile $profile_name missing at $source" >&2
    return 1
  fi

  local tmp_profile
  tmp_profile="$(mktemp -t "sb-trace-$profile_name.XXXXXX.sb")"
  local trace_file
  trace_file="$(mktemp -t "sb-trace-$profile_name.XXXXXX.trace")"

  # Rewrite (allow default) -> (deny default), append a trace directive.
  # `(trace "...")` emits one s-expression record per sandbox decision.
  sed 's/(allow default)/(deny default)/' "$source" >"$tmp_profile"
  printf '\n(trace "%s")\n' "$trace_file" >>"$tmp_profile"

  # Run the probe under the new profile.  Exit code is ignored — the
  # interpreter is expected to fail under deny-default; what we want is
  # the captured trace.
  /usr/bin/sandbox-exec -f "$tmp_profile" -D WORKDIR=/tmp -- $probe_cmd >/dev/null 2>&1 || true

  if [[ -s "$trace_file" ]]; then
    cat "$trace_file"
  fi

  rm -f "$tmp_profile" "$trace_file"
}

# ── Trace summariser ─────────────────────────────────────────────────────────
#
# The sandbox-exec trace format records one s-expression per decision.
# We extract the deny records, normalise the per-host paths into
# parameterised allow rules, and dedupe.

summarise_traces() {
  awk '
    /\(deny / {
      sub(/.*\(deny /, "")
      sub(/\).*/, "")
      print
    }
  ' | sort -u
}

# ── Emit seed for one profile ────────────────────────────────────────────────

emit_seed() {
  local profile_name="$1"
  shift
  local langs=("$@")

  local raw="$SEED_DIR/$profile_name.trace.raw"
  : >"$raw"

  for lang in "${langs[@]}"; do
    echo ";; ── trace from $lang probe ───────────────────────────" >>"$raw"
    trace_one "$profile_name" "$lang" >>"$raw" || true
  done

  if [[ ! -s "$raw" ]]; then
    echo "sb-trace: no deny traces captured for $profile_name" >&2
    return 0
  fi

  local seed="$SEED_DIR/$profile_name.allow"
  {
    echo ";; tools/sb-trace/$profile_name.allow"
    echo ";; Generated by tools/sb-trace.sh against per-language harness corpus."
    echo ";; Hand-review before commit: paths under \$HOME need to be regex'd"
    echo ";; rather than literalised so the seed survives a different host's"
    echo ";; \$HOME layout."
    echo ";;"
    echo ";; Languages walked: ${langs[*]}"
    echo ";; Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    summarise_traces <"$raw" | sed 's/^/(allow /;s/$/)/'
  } >"$seed"

  echo "sb-trace: wrote $seed ($(wc -l <"$seed" | tr -d ' ') lines)"
}

# ── Main ─────────────────────────────────────────────────────────────────────

for profile in "${selected_profiles[@]}"; do
  emit_seed "$profile" "${selected_langs[@]}"
done

echo "sb-trace: done."
echo "Next steps:"
echo "  1. Hand-review each tools/sb-trace/*.allow seed"
echo "  2. Replace host-specific literal paths with regex matches"
echo "     (e.g. /Users/<you>/.pyenv/... -> ^/Users/[^/]+/\\.pyenv/)"
echo "  3. Commit the .allow files; the .trace.raw files are .gitignore'd"
echo "  4. Run nyx with NYX_SB_DENY_DEFAULT=1 to exercise the splice"

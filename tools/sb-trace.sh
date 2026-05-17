#!/usr/bin/env bash
# tools/sb-trace.sh — iterative-permit seed generator for the macOS
# sandbox-exec deny-default rollout (Phase 18 follow-up path (a)).
#
# How it works
# ------------
# Apple removed the `(trace "<file>")` directive's file-emission in a
# recent macOS release while keeping the directive syntactically valid,
# so the older "set a trace path, run probe, parse trace file" workflow
# captures nothing on macOS 26+.  This script substitutes an iterative
# loop driven by `log show`:
#
#   1. Materialise the named `.sb` profile with `(allow default)`
#      rewritten to `(deny default)` plus all `(allow ...)` rules the
#      loop has accumulated so far.
#   2. Run the per-language probe under `sandbox-exec -f` against that
#      profile.  Capture the resulting PID.
#   3. Query `log show --predicate 'eventMessage CONTAINS "(<pid>) deny"'`
#      for the deny records the kernel logged against our process.
#   4. Convert each deny record into a corresponding `(allow ...)` rule
#      and append it to the accumulated rule set.
#   5. Repeat until no new deny records appear (either the probe ran
#      cleanly under the accumulated allows or the kernel deduplicated
#      everything new).  Emit the rule set as the seed.
#
# The PID-targeted log query sidesteps the kernel's per-tuple dedup
# window: every iteration's probe runs as a new process with a fresh
# PID, so the kernel emits fresh records each time even if the
# operation tuples repeat.
#
# Usage
# -----
#   tools/sb-trace.sh                 # walk every profile + every lang fixture
#   tools/sb-trace.sh cmdi            # just the cmdi profile, every lang
#   tools/sb-trace.sh cmdi python     # cmdi + python only
#   tools/sb-trace.sh --selftest      # rule-parser unit tests
#
# Requirements
# ------------
#   * macOS host with `/usr/bin/sandbox-exec` + `/usr/bin/log` available.
#   * `python3`, `node`, `ruby`, `php`, `java` resolvable via $PATH for
#     every language whose fixtures you want to walk.  Missing
#     interpreters are skipped with a warning.
#
# Output
# ------
#   tools/sb-trace/<cap>.allow         — generated seed, hand-review.
#
# The seeds are intended to be committed.  Hand-review each one to:
#   * regex-anonymise host-specific user paths (`/Users/<you>/...` →
#     `^/Users/[^/]+/...`)
#   * collapse related rules onto one `(allow op a b c ...)` directive
#     when several rules share an operation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED_DIR="$ROOT/tools/sb-trace"
PROFILE_DIR="$ROOT/src/dynamic/sandbox_profiles"

MAX_ITERATIONS="${SB_TRACE_MAX_ITERATIONS:-200}"
LOG_WAIT="${SB_TRACE_LOG_WAIT_SECONDS:-1.5}"

# Self-test mode short-circuits the macOS-host plumbing so the parser
# can be exercised in CI on any platform.
if [[ "${1:-}" == "--selftest" ]]; then
  selftest_mode=1
else
  selftest_mode=0
fi

# ── deny → allow rule parser ─────────────────────────────────────────────────
#
# Format of a kernel sandbox deny record (as it appears in `log show`'s
# `eventMessage` field):
#
#   Sandbox: <name>(<pid>) deny(<level>) <op> <target...>
#
# `<target>` is positional — everything after the operation token, up to
# the end of the message.  It may contain spaces (file paths with
# embedded whitespace).  Operation classes map to different
# sandbox-exec rule filters:
#
#   file-read*, file-write*, file-ioctl, file-* (most)  → (literal "<path>")
#   mach-lookup                                          → (global-name "<name>")
#   sysctl-read, sysctl-write                            → (sysctl-name "<name>")
#   ipc-posix-shm-read*, ipc-posix-shm-write*            → (ipc-posix-name "<name>")
#   iokit-open                                           → (iokit-user-client-class "<class>")
#   network-outbound, network-inbound, network-bind      → (literal "<path>") if path-like
#   process-fork, process-exec*, signal, pseudo-tty,
#   sysctl-*, system-*                                   → bare (allow <op>)
#
# Unknown operations fall through to bare allow with a `;; TODO review`
# comment so the operator notices on hand-review.

deny_to_allow_rule() {
  local line="$1"
  # Strip everything up to and including "deny(N) ".
  local rest="${line#*Sandbox: }"
  rest="${rest#*deny(}"
  rest="${rest#*) }"

  # First whitespace-delimited token is the operation, the rest is the target.
  local op="${rest%% *}"
  local target=""
  if [[ "$rest" == *" "* ]]; then
    target="${rest#* }"
  fi

  # Strip a trailing CR that some log timestamps emit.
  target="${target%$'\r'}"

  case "$op" in
    file-read*|file-write*|file-ioctl|file-issue-extension|file-map-executable|file-mount*|file-revoke|file-test-existence|file-chroot|file-clone)
      printf '(allow %s (literal "%s"))\n' "$op" "$(escape_quotes "$target")"
      ;;
    mach-lookup|mach-register|mach-priv-task-port|mach-task-name)
      printf '(allow %s (global-name "%s"))\n' "$op" "$(escape_quotes "$target")"
      ;;
    sysctl-read|sysctl-write)
      printf '(allow %s (sysctl-name "%s"))\n' "$op" "$(escape_quotes "$target")"
      ;;
    ipc-posix-shm-read*|ipc-posix-shm-write*|ipc-posix-shm)
      printf '(allow %s (ipc-posix-name "%s"))\n' "$op" "$(escape_quotes "$target")"
      ;;
    iokit-open|iokit-set-properties|iokit-get-properties)
      printf '(allow %s (iokit-user-client-class "%s"))\n' "$op" "$(escape_quotes "$target")"
      ;;
    network-outbound|network-inbound|network-bind)
      if [[ "$target" == /* ]]; then
        printf '(allow %s (literal "%s"))\n' "$op" "$(escape_quotes "$target")"
      else
        printf '(allow %s)\n' "$op"
      fi
      ;;
    process-fork|process-exec*|process-info*|signal|pseudo-tty|system-*|sysctl-*)
      printf '(allow %s)\n' "$op"
      ;;
    "")
      # Unrecognised structure — emit nothing.
      ;;
    *)
      printf ';; TODO review unfamiliar op: %s %s\n(allow %s)\n' \
        "$op" "$target" "$op"
      ;;
  esac
}

# Escape `"` and `\` for safe embedding inside a sandbox-exec string literal.
escape_quotes() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# ── Self-test ────────────────────────────────────────────────────────────────

assert_rule() {
  local label="$1"
  local input="$2"
  local expected="$3"
  local got
  got="$(deny_to_allow_rule "$input")"
  # Trim trailing newline from `got` for comparison.
  got="${got%$'\n'}"
  if [[ "$got" != "$expected" ]]; then
    printf '[FAIL] %s\n  input:    %s\n  expected: %s\n  got:      %s\n' \
      "$label" "$input" "$expected" "$got" >&2
    return 1
  fi
  printf '[PASS] %s\n' "$label"
}

run_selftest() {
  local fails=0
  assert_rule "file-read-data" \
    "kernel: (Sandbox) Sandbox: python3(54920) deny(1) file-read-data /etc/hosts" \
    '(allow file-read-data (literal "/etc/hosts"))' || ((fails++))

  assert_rule "file-read-data-root" \
    "Sandbox: python3(54920) deny(1) file-read-data /" \
    '(allow file-read-data (literal "/"))' || ((fails++))

  assert_rule "sysctl-read" \
    "Sandbox: python3(54920) deny(1) sysctl-read security.mac.lockdown_mode_state" \
    '(allow sysctl-read (sysctl-name "security.mac.lockdown_mode_state"))' || ((fails++))

  assert_rule "mach-lookup" \
    "Sandbox: contactsd(54920) deny(1) mach-lookup com.apple.tccd.system" \
    '(allow mach-lookup (global-name "com.apple.tccd.system"))' || ((fails++))

  assert_rule "ipc-posix-shm-read" \
    "Sandbox: python3(54920) deny(1) ipc-posix-shm-read-data apple.shm.notification_center" \
    '(allow ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))' || ((fails++))

  assert_rule "network-outbound-path" \
    "Sandbox: python3(54920) deny(1) network-outbound /private/var/run/syslog" \
    '(allow network-outbound (literal "/private/var/run/syslog"))' || ((fails++))

  assert_rule "network-outbound-host" \
    "Sandbox: python3(54920) deny(1) network-outbound 1.2.3.4:80" \
    '(allow network-outbound)' || ((fails++))

  assert_rule "process-fork" \
    "Sandbox: python3(54920) deny(1) process-fork" \
    '(allow process-fork)' || ((fails++))

  assert_rule "process-exec-star" \
    "Sandbox: python3(54920) deny(1) process-exec* /bin/ls" \
    '(allow process-exec*)' || ((fails++))

  assert_rule "iokit-open" \
    "Sandbox: python3(54920) deny(1) iokit-open IOUserClientCrossEndpoint" \
    '(allow iokit-open (iokit-user-client-class "IOUserClientCrossEndpoint"))' || ((fails++))

  assert_rule "path-with-space" \
    'Sandbox: python3(54920) deny(1) file-read-data /Users/me/has spaces/file' \
    '(allow file-read-data (literal "/Users/me/has spaces/file"))' || ((fails++))

  assert_rule "path-with-quote" \
    'Sandbox: python3(54920) deny(1) file-read-data /a"b' \
    '(allow file-read-data (literal "/a\"b"))' || ((fails++))

  if (( fails > 0 )); then
    printf '\nsb-trace selftest: %d failure(s)\n' "$fails" >&2
    return 1
  fi
  printf '\nsb-trace selftest: all OK\n'
}

if (( selftest_mode )); then
  run_selftest
  exit $?
fi

# ── macOS-host guards ────────────────────────────────────────────────────────

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "sb-trace: must run on macOS (uname=$(uname -s))" >&2
  exit 2
fi

if [[ ! -x /usr/bin/sandbox-exec ]]; then
  echo "sb-trace: /usr/bin/sandbox-exec missing" >&2
  exit 2
fi

if [[ ! -x /usr/bin/log ]]; then
  echo "sb-trace: /usr/bin/log missing" >&2
  exit 2
fi

mkdir -p "$SEED_DIR"

# ── Probe selection ──────────────────────────────────────────────────────────

ALL_PROFILES=(base cmdi path_traversal ssrf deserialize xxe)
ALL_LANGS=(python javascript ruby php java)

declare -a selected_profiles selected_langs
if [[ $# -ge 1 ]]; then
  selected_profiles=("$1")
else
  selected_profiles=("${ALL_PROFILES[@]}")
fi
if [[ $# -ge 2 ]]; then
  selected_langs=("$2")
else
  selected_langs=("${ALL_LANGS[@]}")
fi

# Per-language probe command.  Each probe exercises the interpreter's
# cold-start path with the minimum import set the dynamic harness
# needs.  Probe argv is written into the global `PROBE_ARGV` array (one
# token per element) on success; on missing interpreter the function
# returns 1 and leaves `PROBE_ARGV` cleared.
PROBE_ARGV=()
probe_command_for() {
  PROBE_ARGV=()
  case "$1" in
    python)
      command -v python3 >/dev/null 2>&1 || return 1
      PROBE_ARGV=(python3 -c 'import os, sys, json, socket, subprocess')
      ;;
    javascript)
      command -v node >/dev/null 2>&1 || return 1
      PROBE_ARGV=(node -e "require('fs');require('os');require('http');require('child_process')")
      ;;
    ruby)
      command -v ruby >/dev/null 2>&1 || return 1
      PROBE_ARGV=(ruby -e "require 'json'; require 'socket'; require 'net/http'; require 'open3'")
      ;;
    php)
      command -v php >/dev/null 2>&1 || return 1
      PROBE_ARGV=(php -r 'echo phpversion();')
      ;;
    java)
      command -v java >/dev/null 2>&1 || return 1
      PROBE_ARGV=(java --version)
      ;;
    *)
      return 1
      ;;
  esac
}

# ── Iterative loop ───────────────────────────────────────────────────────────

# Run one probe under the given (already materialised) profile and return
# the kernel deny lines logged against the probe's PID, one per line.
run_probe_capture_denies() {
  local profile_path="$1"
  shift
  local -a probe_argv=("$@")

  # Spawn the probe in the background so we can capture its PID.
  /usr/bin/sandbox-exec -f "$profile_path" -D WORKDIR=/tmp "${probe_argv[@]}" \
    >/dev/null 2>/dev/null &
  local probe_pid=$!

  # Wait for the probe to finish.  Don't propagate its exit code — many
  # operations under deny-default are silently degraded by the
  # interpreter (a denied sysctl-read just returns ENOENT, the
  # interpreter handles it gracefully).
  wait "$probe_pid" 2>/dev/null || true

  # Wait for the kernel's log queue to drain.  Empirically a few hundred
  # milliseconds suffice on macOS 26.
  sleep "$LOG_WAIT"

  # Query log for deny lines targeting our PID.  Use both the procname
  # token "(<pid>) deny" (more selective than just the pid) and the
  # `--style ndjson` flag for parseable output.  We re-extract
  # `eventMessage` via a simple field grep because jq isn't required on
  # every macOS host.
  /usr/bin/log show \
      --predicate "eventMessage CONTAINS \"(${probe_pid}) deny\"" \
      --info --debug --last 30s 2>/dev/null \
    | awk '
        /Sandbox: .*\([0-9]+\) deny\(/ {
          sub(/^.*Sandbox:/, "Sandbox:")
          print
        }
      '
}

iterate_one_profile() {
  local profile_name="$1"
  shift
  local -a langs=("$@")

  local source_path="$PROFILE_DIR/$profile_name.sb"
  if [[ ! -f "$source_path" ]]; then
    echo "sb-trace: profile $profile_name missing at $source_path" >&2
    return 1
  fi

  local base
  base="$(sed 's/(allow default)/(deny default)/' "$source_path")"

  # Per-cap accumulators.
  local -a accumulated_rules=()
  local -a accumulated_keys=()
  local total_iters=0

  for lang in "${langs[@]}"; do
    if ! probe_command_for "$lang"; then
      echo "sb-trace: skipping $lang (interpreter missing or unsupported)" >&2
      continue
    fi
    local -a argv=("${PROBE_ARGV[@]}")
    if (( ${#argv[@]} == 0 )); then
      echo "sb-trace: skipping $lang (empty argv)" >&2
      continue
    fi

    local iteration=0
    while (( iteration < MAX_ITERATIONS )); do
      iteration=$((iteration + 1))
      total_iters=$((total_iters + 1))

      # Materialise tmp profile = base + accumulated rules.
      local tmp_profile
      tmp_profile="$(mktemp -t "sb-trace-$profile_name.XXXXXX.sb")"
      {
        printf '%s\n' "$base"
        printf ';; sb-trace iterative seeds (lang=%s iter=%d)\n' \
          "$lang" "$iteration"
        local r
        for r in "${accumulated_rules[@]+"${accumulated_rules[@]}"}"; do
          printf '%s\n' "$r"
        done
      } >"$tmp_profile"

      # Run probe, collect deny lines.
      local denies
      denies="$(run_probe_capture_denies "$tmp_profile" "${argv[@]}" || true)"
      rm -f "$tmp_profile"

      if [[ -z "$denies" ]]; then
        # No new denies for this lang — done.
        break
      fi

      # Convert denies to allow rules, dedup against accumulated.
      local new_in_iter=0
      local line
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local rule
        rule="$(deny_to_allow_rule "$line")"
        rule="${rule%$'\n'}"
        [[ -z "$rule" ]] && continue
        # Dedup by exact-rule-text match.
        local seen=0
        local k
        for k in "${accumulated_keys[@]+"${accumulated_keys[@]}"}"; do
          if [[ "$k" == "$rule" ]]; then
            seen=1; break
          fi
        done
        if (( ! seen )); then
          accumulated_rules+=("$rule")
          accumulated_keys+=("$rule")
          new_in_iter=$((new_in_iter + 1))
        fi
      done <<<"$denies"

      if (( new_in_iter == 0 )); then
        # Denies present but all already-known — kernel dedup, or
        # repeats of rules we've already issued.  Bail to avoid
        # infinite loops.
        break
      fi
    done
  done

  local seed_path="$SEED_DIR/$profile_name.allow"
  {
    printf ';; tools/sb-trace/%s.allow\n' "$profile_name"
    printf ';; Generated %s by tools/sb-trace.sh (iterative-permit loop)\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf ';; Languages walked: %s\n' "${langs[*]}"
    printf ';; Total probe iterations: %d\n' "$total_iters"
    printf ';;\n'
    printf ';; Hand-review before commit:\n'
    printf ';;   * regex-anonymise host-specific paths under /Users/<you>/...\n'
    printf ';;     into ^/Users/[^/]+/... so the seed survives a different\n'
    printf ';;     operator host\n'
    printf ';;   * collapse same-op rules onto one (allow op a b c ...)\n'
    printf ';;     directive when the targets share semantics\n'
    printf '\n'
    if (( ${#accumulated_rules[@]} == 0 )); then
      printf ';; (no deny records captured; profile already runs cleanly\n'
      printf ';;  for the probed languages under (deny default))\n'
    else
      local r
      for r in "${accumulated_rules[@]}"; do
        printf '%s\n' "$r"
      done
    fi
  } >"$seed_path"

  printf 'sb-trace: wrote %s (%d rule(s) across %d iteration(s))\n' \
    "$seed_path" "${#accumulated_rules[@]}" "$total_iters"
}

# ── Main loop ────────────────────────────────────────────────────────────────

for profile in "${selected_profiles[@]}"; do
  iterate_one_profile "$profile" "${selected_langs[@]}"
done

printf '\nsb-trace: done.\n'
printf 'Next steps:\n'
printf '  1. Hand-review each tools/sb-trace/*.allow seed.\n'
printf '  2. Replace host-specific literal paths with regex matches.\n'
printf '  3. Commit the .allow files.\n'
printf '  4. Run nyx with NYX_SB_DENY_DEFAULT=1 + NYX_SB_SEED_DIR pointing at\n'
printf '     tools/sb-trace/ to exercise the splice.\n'

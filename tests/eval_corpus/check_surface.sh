#!/usr/bin/env bash
# Phase 31 acceptance walker: assert `nyx surface` produces a usable
# map on every downloaded eval-corpus fixture root.
#
# Walks the project trees under $NYX_EVAL_CORPUS_DIR plus the in-house
# `tests/benchmark/corpus` and `tests/dynamic_fixtures` trees, runs
# `nyx surface --build --format json <root>` against each, and asserts
# the resulting JSON contains at least one EntryPoint plus at least
# one DataStore / ExternalService / DangerousLocal node.
#
# `--build` forces the inline pass-1 + call-graph path so the walker
# does not depend on a prior `nyx index build` or `nyx scan`.
#
# Usage:
#   tests/eval_corpus/check_surface.sh [--nyx BIN] [--corpus-dir DIR]
#                                      [--also-inhouse]
#                                      [--report FILE]
#
# Environment:
#   NYX_EVAL_CORPUS_DIR  — path to pre-downloaded corpus roots
#                          (default: ~/.cache/nyx/eval_corpus).  When
#                          missing or empty the walker still scans the
#                          in-house corpus and exits 0 so CI without a
#                          corpus mirror does not block on Phase 31.
#
# Exit codes:
#   0  every walked project produced a usable SurfaceMap (or no
#      projects were available — see corpus-missing note above).
#   1  setup / I/O / missing-binary error.
#   2  one or more projects produced an empty or unusable SurfaceMap.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NYX_BIN="${NYX_BIN:-${REPO_ROOT}/target/release/nyx}"
CORPUS_CACHE="${NYX_EVAL_CORPUS_DIR:-${HOME}/.cache/nyx/eval_corpus}"
ALSO_INHOUSE="false"
REPORT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nyx)          NYX_BIN="$2"; shift 2 ;;
    --corpus-dir)   CORPUS_CACHE="$2"; shift 2 ;;
    --also-inhouse) ALSO_INHOUSE="true"; shift ;;
    --report)       REPORT_FILE="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 1
      ;;
  esac
done

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "[surface-check] $*"; }
warn() { echo "[surface-check] WARN: $*" >&2; }

[[ -x "$NYX_BIN" ]] || die "nyx binary not found or not executable: $NYX_BIN"
command -v jq >/dev/null 2>&1 || die "required command not found: jq"

# Collect project roots.  Each corpus directory is treated as a single
# project; the in-house corpus trees are handled the same way (each
# language vertical is a project root).
PROJECTS=()
if [[ -d "$CORPUS_CACHE" ]]; then
  for entry in "$CORPUS_CACHE"/*; do
    [[ -d "$entry" ]] && PROJECTS+=("$entry")
  done
else
  warn "corpus directory missing: $CORPUS_CACHE (run tests/eval_corpus/run.sh to bootstrap)"
fi
if [[ "$ALSO_INHOUSE" == "true" ]]; then
  for dir in \
    "${REPO_ROOT}/tests/benchmark/corpus" \
    "${REPO_ROOT}/tests/dynamic_fixtures"
  do
    [[ -d "$dir" ]] && PROJECTS+=("$dir")
  done
fi

if [[ ${#PROJECTS[@]} -eq 0 ]]; then
  info "no project roots to walk (eval corpus not downloaded, in-house trees absent)"
  exit 0
fi

PASS_COUNT=0
FAIL_COUNT=0
FAIL_PROJECTS=()
declare -a REPORT_ROWS=()

for project in "${PROJECTS[@]}"; do
  info "walking: $project"
  set +e
  out="$("$NYX_BIN" surface --build --format json "$project" 2>/dev/null)"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    warn "nyx surface --build exited $rc on $project"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_PROJECTS+=("$project (nyx exit=$rc)")
    REPORT_ROWS+=("$(printf '{"project":%s,"status":"nyx-error","exit":%d}' \
      "$(jq -Rn --arg p "$project" '$p')" "$rc")")
    continue
  fi
  if [[ -z "$out" ]]; then
    warn "empty output on $project"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_PROJECTS+=("$project (empty output)")
    REPORT_ROWS+=("$(printf '{"project":%s,"status":"empty-output"}' \
      "$(jq -Rn --arg p "$project" '$p')")")
    continue
  fi
  # Count nodes by kind.  SurfaceMap serialises each node as a flat
  # object with a `node` discriminator: `entry_point`, `data_store`,
  # `external_service`, `dangerous_local`.
  entry_count="$(echo "$out" | jq '[.nodes[] | select(.node == "entry_point")] | length')"
  ds_count="$(echo "$out" | jq '[.nodes[] | select(.node == "data_store")] | length')"
  es_count="$(echo "$out" | jq '[.nodes[] | select(.node == "external_service")] | length')"
  dl_count="$(echo "$out" | jq '[.nodes[] | select(.node == "dangerous_local")] | length')"
  sink_count=$((ds_count + es_count + dl_count))
  if [[ "$entry_count" -lt 1 ]]; then
    warn "no EntryPoint nodes on $project"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_PROJECTS+=("$project (no entry-points)")
    REPORT_ROWS+=("$(printf '{"project":%s,"status":"no-entry-points","entry_count":%d}' \
      "$(jq -Rn --arg p "$project" '$p')" "$entry_count")")
    continue
  fi
  if [[ "$sink_count" -lt 1 ]]; then
    warn "no DataStore / ExternalService / DangerousLocal nodes on $project"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_PROJECTS+=("$project (no sinks: ds=$ds_count es=$es_count dl=$dl_count)")
    REPORT_ROWS+=("$(printf '{"project":%s,"status":"no-sinks","entry_count":%d,"ds":%d,"es":%d,"dl":%d}' \
      "$(jq -Rn --arg p "$project" '$p')" "$entry_count" "$ds_count" "$es_count" "$dl_count")")
    continue
  fi
  info "  ok: ${entry_count} entry-points, ${ds_count} data stores, ${es_count} external, ${dl_count} dangerous"
  PASS_COUNT=$((PASS_COUNT + 1))
  REPORT_ROWS+=("$(printf '{"project":%s,"status":"ok","entry_count":%d,"ds":%d,"es":%d,"dl":%d}' \
    "$(jq -Rn --arg p "$project" '$p')" "$entry_count" "$ds_count" "$es_count" "$dl_count")")
done

if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "{"
    echo "  \"pass\": $PASS_COUNT,"
    echo "  \"fail\": $FAIL_COUNT,"
    echo "  \"projects\": ["
    for i in "${!REPORT_ROWS[@]}"; do
      sep=","
      [[ $i -eq $((${#REPORT_ROWS[@]} - 1)) ]] && sep=""
      echo "    ${REPORT_ROWS[$i]}$sep"
    done
    echo "  ]"
    echo "}"
  } > "$REPORT_FILE"
  info "report written: $REPORT_FILE"
fi

info ""
info "summary: ${PASS_COUNT} pass, ${FAIL_COUNT} fail (of $((PASS_COUNT + FAIL_COUNT)) projects)"
if [[ $FAIL_COUNT -gt 0 ]]; then
  for p in "${FAIL_PROJECTS[@]}"; do
    info "  fail: $p"
  done
  exit 2
fi
exit 0

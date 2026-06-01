#!/usr/bin/env bash
# Full eval-corpus orchestrator.
#
# Drives a complete pass against every corpus set the project knows about
# (OWASP Benchmark v1.2, the NIST SARD subset, OWASP NodeGoat + Juice Shop,
# the Track R.2 polyglot corpora — RailsGoat / DVWA / DVPWA / gosec / RustSec —
# and the Nyx benchmark fixtures), then emits `tests/eval_corpus/results.json`
# for reports, diffs, and docs.
#
# Usage:
#   tests/eval_corpus/run_full.sh [--nyx BIN] [--budget FILE] [--diff FILE]
#                                 [--output DIR] [--corpus-dir DIR]
#
# Differences vs `run.sh`:
#   * Always runs every set (no `--sets` selector).
#   * Always passes `--budget tests/eval_corpus/budget.toml` so the
#     configured per-cell limits are checked on every pass.
#   * Copies the timestamped results file to
#     `tests/eval_corpus/results.json`.
#
# Exit codes:
#   0  every set ran and the merged result met the per-cell budget.
#   1  setup or I/O error.
#   2  budget exceeded OR monotonic-improvement regression.
#   3  budget/diff input malformed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NYX_BIN="${NYX_BIN:-${REPO_ROOT}/target/release/nyx}"
BUDGET_FILE="${BUDGET_FILE:-${SCRIPT_DIR}/budget.toml}"
DIFF_FILE="${DIFF_FILE:-}"
OUTPUT_DIR=""
CORPUS_CACHE="${NYX_EVAL_CORPUS_DIR:-${HOME}/.cache/nyx/eval_corpus}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nyx)         NYX_BIN="$2"; shift 2 ;;
    --budget)      BUDGET_FILE="$2"; shift 2 ;;
    --diff)        DIFF_FILE="$2"; shift 2 ;;
    --output)      OUTPUT_DIR="$2"; shift 2 ;;
    --corpus-dir)  CORPUS_CACHE="$2"; shift 2 ;;
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
info() { echo "[full] $*"; }

[[ -x "$NYX_BIN" ]] || die "nyx binary not found or not executable: $NYX_BIN"
[[ -f "$BUDGET_FILE" ]] || die "budget file not found: $BUDGET_FILE"

OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/.run-out}"
mkdir -p "$OUTPUT_DIR"

info "nyx:    $NYX_BIN"
info "budget: $BUDGET_FILE"
info "diff:   ${DIFF_FILE:-<none>}"
info "output: $OUTPUT_DIR"

set +e
NYX_EVAL_CORPUS_DIR="$CORPUS_CACHE" \
  bash "${SCRIPT_DIR}/run.sh" \
    --nyx     "$NYX_BIN" \
    --sets    owasp,sard,nodegoat,juiceshop,railsgoat,dvwa,dvpwa,gosec,rustsec,inhouse \
    --output  "$OUTPUT_DIR" \
    --budget  "$BUDGET_FILE" \
    ${DIFF_FILE:+--diff "$DIFF_FILE"}
RC=$?
set -e

RESULTS_SRC="${OUTPUT_DIR}/eval_results.json"
RESULTS_DST="${SCRIPT_DIR}/results.json"
if [[ -f "$RESULTS_SRC" ]]; then
  cp "$RESULTS_SRC" "$RESULTS_DST"
  info "results: $RESULTS_DST"
else
  info "no eval_results.json produced; corpus may not be downloaded"
fi

exit "$RC"

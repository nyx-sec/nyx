#!/usr/bin/env bash
# Eval corpus runner.
#
# Usage:
#   tests/eval_corpus/run.sh [--output DIR] [--nyx BIN] [--sets owasp,sard,inhouse]
#
# Bootstraps OWASP Benchmark v1.2, the NIST SARD subset, and Nyx benchmark
# fixtures. Runs `nyx scan --verify` on each. Emits
# per-cell (cap x language) precision/recall table and per-cap Unsupported
# rate to stdout (and --output DIR if given).
#
# Environment:
#   NYX_EVAL_CORPUS_DIR  - path to pre-downloaded corpus roots
#                          (default: ~/.cache/nyx/eval_corpus)
#   NYX_BIN              - path to nyx binary (default: ./target/release/nyx)
#
# Exit codes:
#   0 - all budget thresholds met
#   1 - setup or I/O error
#   2 - one or more budget thresholds exceeded (see output for details)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Defaults
OUTPUT_DIR=""
NYX_BIN="${NYX_BIN:-${REPO_ROOT}/target/release/nyx}"
CORPUS_CACHE="${NYX_EVAL_CORPUS_DIR:-${HOME}/.cache/nyx/eval_corpus}"
SETS="owasp,sard,inhouse"
# Optional per-cell budgets and monotonic-improvement diff.
BUDGET_FILE=""
DIFF_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --nyx)    NYX_BIN="$2"; shift 2 ;;
    --sets)   SETS="$2"; shift 2 ;;
    --budget) BUDGET_FILE="$2"; shift 2 ;;
    --diff)   DIFF_FILE="$2"; shift 2 ;;
    *)        shift ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
die()  { echo "error: $*" >&2; exit 1; }
info() { echo "[eval] $*"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
require_cmd jq
require_cmd python3

[[ -x "$NYX_BIN" ]] || die "nyx binary not found or not executable: $NYX_BIN"

mkdir -p "$CORPUS_CACHE"
[[ -n "$OUTPUT_DIR" ]] && mkdir -p "$OUTPUT_DIR"

RESULTS_JSON="${OUTPUT_DIR:-/tmp}/eval_results_$(date +%Y%m%d_%H%M%S).json"
echo "[]" > "$RESULTS_JSON"

# ── OWASP Benchmark v1.2 bootstrap ───────────────────────────────────────────
OWASP_DIR="${CORPUS_CACHE}/owasp_benchmark_v1.2"
if [[ "$SETS" == *owasp* ]]; then
  if [[ ! -d "$OWASP_DIR" ]]; then
    info "Bootstrapping OWASP Benchmark v1.2..."
    info "  Clone from https://github.com/OWASP-Benchmark/BenchmarkJava"
    info "  into ${OWASP_DIR}"
    info "  then re-run this script."
    info "  git clone --depth 1 --branch v1.2 \\"
    info "    https://github.com/OWASP-Benchmark/BenchmarkJava \\"
    info "    ${OWASP_DIR}"
    info "Skipping OWASP set (not yet downloaded)."
  else
    info "Running nyx scan on OWASP Benchmark v1.2..."
    set +e
    "$NYX_BIN" scan --format json --verify --no-index "$OWASP_DIR" \
      > /tmp/nyx_owasp.json 2>/tmp/nyx_owasp.stderr
    NYX_EXIT=$?
    set -e
    if [[ $NYX_EXIT -ne 0 && $NYX_EXIT -ne 1 ]]; then
      info "  nyx exited $NYX_EXIT on OWASP set (stderr follows):"
      cat /tmp/nyx_owasp.stderr >&2
    else
      python3 "${SCRIPT_DIR}/tabulate.py" \
        --label owasp \
        --scan /tmp/nyx_owasp.json \
        --ground-truth "${SCRIPT_DIR}/ground_truth/owasp_benchmark_v1.2.json" \
        --append "$RESULTS_JSON" \
        ${BUDGET_FILE:+--budget "$BUDGET_FILE"} \
        ${DIFF_FILE:+--diff "$DIFF_FILE"} \
        || info "  tabulate.py failed; ground truth file may be absent"
    fi
  fi
fi

# ── NIST SARD subset bootstrap ────────────────────────────────────────────────
SARD_DIR="${CORPUS_CACHE}/nist_sard"
if [[ "$SETS" == *sard* ]]; then
  if [[ ! -d "$SARD_DIR" ]]; then
    info "Bootstrapping NIST SARD subset..."
    info "  Download from https://samate.nist.gov/SARD/"
    info "  into ${SARD_DIR} then re-run this script."
    info "Skipping SARD set (not yet downloaded)."
  else
    info "Running nyx scan on NIST SARD subset..."
    set +e
    "$NYX_BIN" scan --format json --verify --no-index "$SARD_DIR" \
      > /tmp/nyx_sard.json 2>/tmp/nyx_sard.stderr
    NYX_EXIT=$?
    set -e
    if [[ $NYX_EXIT -ne 0 && $NYX_EXIT -ne 1 ]]; then
      info "  nyx exited $NYX_EXIT on SARD set"
    else
      python3 "${SCRIPT_DIR}/tabulate.py" \
        --label sard \
        --scan /tmp/nyx_sard.json \
        --ground-truth "${SCRIPT_DIR}/ground_truth/nist_sard.json" \
        --append "$RESULTS_JSON" \
        ${BUDGET_FILE:+--budget "$BUDGET_FILE"} \
        ${DIFF_FILE:+--diff "$DIFF_FILE"} \
        || info "  tabulate.py failed; ground truth file may be absent"
    fi
  fi
fi

# ── In-house bughunt-curated set ──────────────────────────────────────────────
if [[ "$SETS" == *inhouse* ]]; then
  INHOUSE_DIRS=(
    "${REPO_ROOT}/tests/benchmark/corpus"
    "${REPO_ROOT}/tests/dynamic_fixtures"
  )
  for dir in "${INHOUSE_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    label="inhouse_$(basename "$dir")"
    info "Running nyx scan on in-house set: $dir"
    set +e
    "$NYX_BIN" scan --format json --verify --no-index "$dir" \
      > "/tmp/nyx_${label}.json" 2>"/tmp/nyx_${label}.stderr"
    NYX_EXIT=$?
    set -e
    if [[ $NYX_EXIT -ne 0 && $NYX_EXIT -ne 1 ]]; then
      info "  nyx exited $NYX_EXIT on $label"
      continue
    fi
    python3 "${SCRIPT_DIR}/tabulate.py" \
      --label "$label" \
      --scan "/tmp/nyx_${label}.json" \
      --inhouse \
      --append "$RESULTS_JSON" \
      ${BUDGET_FILE:+--budget "$BUDGET_FILE"} \
      ${DIFF_FILE:+--diff "$DIFF_FILE"} \
      || info "  tabulate.py failed on $label"
  done
fi

# ── Emit summary table ────────────────────────────────────────────────────────
info ""
info "Results written to: $RESULTS_JSON"

[[ -n "$OUTPUT_DIR" ]] && cp "$RESULTS_JSON" "${OUTPUT_DIR}/eval_results.json"

if [[ ! -f "${SCRIPT_DIR}/report.py" ]]; then
  info "report.py not available; raw results at $RESULTS_JSON"
  exit 0
fi

set +e
python3 "${SCRIPT_DIR}/report.py" \
  --results "$RESULTS_JSON" \
  ${BUDGET_FILE:+--budget "$BUDGET_FILE"} \
  ${DIFF_FILE:+--diff "$DIFF_FILE"}
REPORT_RC=$?
set -e
# Propagate budget failures (exit 2) and malformed config (exit 3). Treat other
# non-zero exits as setup errors.
if [[ $REPORT_RC -eq 2 ]]; then
  exit 2
elif [[ $REPORT_RC -eq 3 ]]; then
  info "report.py: budget/diff configuration malformed; see $RESULTS_JSON"
  exit 3
elif [[ $REPORT_RC -ne 0 ]]; then
  info "report.py crashed (exit $REPORT_RC); raw results at $RESULTS_JSON"
  exit 1
fi
exit 0

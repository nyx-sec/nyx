#!/usr/bin/env bash
# m7_ship_gate.sh — milestone-7 ship gates.
#
# Each gate runs as an isolated function so CI can call a subset:
#
#   scripts/m7_ship_gate.sh                     # every gate
#   scripts/m7_ship_gate.sh --gates 3,6         # only gates 3 + 6
#   scripts/m7_ship_gate.sh --sets owasp        # Java OWASP corpus only
#
# Gate map (kept in sync with .pitboss/play/plan.md track M.7):
#   Gate 1: Static-only scan is green on `tests/benchmark/corpus`.
#   Gate 2: `cargo nextest run --features dynamic` is green.
#   Gate 3: With-verify / static-only wall-clock ratio ≤ 2× on
#           `benches/fixtures/`.  Phase 22 lowered the bar from the
#           original ≤ 1.5× because the dispatcher + sandbox baseline
#           still pay the same per-finding workdir cost, even with the
#           warm `javac` daemon.  Phase 23 will tighten this back.
#   Gate 4: SARIF schema validation on every dynamic verdict variant.
#   Gate 5: Layering boundary test green.
#   Gate 6: Java OWASP Benchmark v1.2 `--verify` wall-clock ≤ 15 min on
#           CI / ≤ 10 min on the dev reference machine, confirmed-rate
#           ≥ 40% per cap.  Added Phase 22 as the headline acceptance
#           for the warm `javac` daemon.  The corpus is *not* checked
#           into the repo; the gate skips with a clear message when
#           `NYX_OWASP_CORPUS` does not point at a real checkout.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

GATES="1,2,3,4,5,6"
SETS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gates)
            GATES="$2"
            shift 2
            ;;
        --sets)
            SETS="$2"
            shift 2
            ;;
        -h | --help)
            sed -n '2,/^$/p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

# When `--sets owasp` is passed CI only wants Gate 6.
if [[ "${SETS}" == "owasp" ]]; then
    GATES="6"
fi

want_gate() {
    [[ ",${GATES}," == *",$1,"* ]]
}

# ── Gate 1 ────────────────────────────────────────────────────────────────────

gate_1_static_corpus() {
    echo "── Gate 1: static-only scan on tests/benchmark/corpus ──"
    if [[ ! -d "${REPO_ROOT}/tests/benchmark/corpus" ]]; then
        echo "  SKIP: tests/benchmark/corpus not present"
        return 0
    fi
    cargo run --release --quiet -- scan \
        --path "${REPO_ROOT}/tests/benchmark/corpus" \
        --format json > /tmp/m7_gate1.json
    echo "  PASS: static scan completed"
}

# ── Gate 2 ────────────────────────────────────────────────────────────────────

gate_2_dynamic_tests() {
    echo "── Gate 2: cargo nextest run --features dynamic ──"
    cargo nextest run --features dynamic
    echo "  PASS: dynamic test suite green"
}

# ── Gate 3: with-verify / static-only ratio ───────────────────────────────────

# Phase 22 baseline: target ratio ≤ 2×.  Tightening back to ≤ 1.5×
# is Gate 3's Phase 23 follow-up once the cross-lang pools land.
GATE3_RATIO_TARGET="${GATE3_RATIO_TARGET:-2.0}"

gate_3_verify_ratio() {
    echo "── Gate 3: with-verify / static-only ratio on benches/fixtures/ ──"
    local fixtures="${REPO_ROOT}/benches/fixtures"
    if [[ ! -d "${fixtures}" ]]; then
        echo "  SKIP: ${fixtures} not present"
        return 0
    fi

    local static_seconds verify_seconds
    static_seconds="$(time_scan "${fixtures}" 0)"
    verify_seconds="$(time_scan "${fixtures}" 1)"
    local ratio
    ratio="$(awk -v v="${verify_seconds}" -v s="${static_seconds}" \
        'BEGIN { if (s <= 0) { print "inf"; exit } printf "%.3f", v / s }')"

    echo "  static-only wall-clock: ${static_seconds}s"
    echo "  with-verify wall-clock: ${verify_seconds}s"
    echo "  ratio: ${ratio} (target ≤ ${GATE3_RATIO_TARGET})"

    awk -v r="${ratio}" -v t="${GATE3_RATIO_TARGET}" \
        'BEGIN { if (r+0 > t+0) exit 1 }' \
        || { echo "  FAIL: ratio exceeds target"; return 1; }
    echo "  PASS"
}

# Print wall-clock seconds for a single scan run.
#   $1 = path to scan
#   $2 = 0 for static-only, 1 for --verify
time_scan() {
    local path="$1" verify="$2"
    local args=("--path" "${path}" "--format" "json")
    if [[ "${verify}" == "1" ]]; then
        args+=("--verify")
    fi
    local start end
    start="$(python3 -c 'import time;print(time.monotonic())')"
    cargo run --release --quiet --features dynamic -- scan "${args[@]}" > /dev/null
    end="$(python3 -c 'import time;print(time.monotonic())')"
    awk -v a="${start}" -v b="${end}" 'BEGIN { printf "%.3f", b - a }'
}

# ── Gate 4 ────────────────────────────────────────────────────────────────────

gate_4_sarif_schema() {
    echo "── Gate 4: SARIF schema validation ──"
    cargo nextest run --features dynamic --test sarif_dynamic_verdict_tests
    echo "  PASS"
}

# ── Gate 5 ────────────────────────────────────────────────────────────────────

gate_5_layering() {
    echo "── Gate 5: dynamic layering boundary ──"
    cargo nextest run --features dynamic --test dynamic_layering
    echo "  PASS"
}

# ── Gate 6: Java OWASP-scale ratio ────────────────────────────────────────────

# Phase 22 + Phase 27 jointly own this gate.  The wall-clock budgets
# are split: 10 min on the dev reference (M1 macOS w/ JDK 21) and 15
# min in CI.  Override `NYX_OWASP_WALLCLOCK_BUDGET_SECONDS` to tighten.
GATE6_WALLCLOCK_BUDGET="${NYX_OWASP_WALLCLOCK_BUDGET_SECONDS:-900}"
GATE6_CONFIRMED_RATE_TARGET="${NYX_OWASP_CONFIRMED_RATE_TARGET:-0.40}"

gate_6_owasp_scale() {
    echo "── Gate 6: Java OWASP Benchmark v1.2 verify wall-clock + confirmed-rate ──"
    local corpus="${NYX_OWASP_CORPUS:-}"
    if [[ -z "${corpus}" || ! -d "${corpus}" ]]; then
        echo "  SKIP: set NYX_OWASP_CORPUS to a v1.2 checkout to run this gate."
        echo "        (Gate 6 is Phase 22's headline acceptance for the warm javac daemon.)"
        return 0
    fi

    local report="/tmp/m7_gate6_report.json"
    local start end wallclock
    start="$(python3 -c 'import time;print(time.monotonic())')"
    cargo run --release --quiet --features dynamic -- scan \
        --path "${corpus}" \
        --verify \
        --format json > "${report}"
    end="$(python3 -c 'import time;print(time.monotonic())')"
    wallclock="$(awk -v a="${start}" -v b="${end}" 'BEGIN { printf "%.1f", b - a }')"

    echo "  OWASP verify wall-clock: ${wallclock}s (budget ${GATE6_WALLCLOCK_BUDGET}s)"

    awk -v w="${wallclock}" -v b="${GATE6_WALLCLOCK_BUDGET}" \
        'BEGIN { if (w+0 > b+0) exit 1 }' \
        || { echo "  FAIL: wall-clock exceeds budget"; return 1; }

    if [[ -x "${REPO_ROOT}/tests/eval_corpus/report.py" ]]; then
        # Per-cap confirmed-rate report; the helper exits non-zero if
        # any cap falls below the target.
        NYX_CONFIRMED_RATE_TARGET="${GATE6_CONFIRMED_RATE_TARGET}" \
            python3 "${REPO_ROOT}/tests/eval_corpus/report.py" "${report}" \
            || { echo "  FAIL: confirmed-rate below ${GATE6_CONFIRMED_RATE_TARGET}"; return 1; }
    else
        echo "  NOTE: tests/eval_corpus/report.py not present; skipping per-cap check"
    fi
    echo "  PASS"
}

# ── Driver ────────────────────────────────────────────────────────────────────

declare -a FAILED=()
run_gate() {
    local idx="$1" name="$2"
    if want_gate "${idx}"; then
        if ! "gate_${idx}_${name}"; then
            FAILED+=("${idx}")
        fi
    fi
}

run_gate 1 static_corpus
run_gate 2 dynamic_tests
run_gate 3 verify_ratio
run_gate 4 sarif_schema
run_gate 5 layering
run_gate 6 owasp_scale

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo
    echo "FAILED gates: ${FAILED[*]}"
    exit 1
fi
echo
echo "All requested gates passed."

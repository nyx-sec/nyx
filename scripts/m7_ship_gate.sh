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
#   Gate 3: With-verify / static-only wall-clock ratio ≤ 1.5× on
#           `benches/fixtures/`.  Phase 22 had relaxed this to ≤ 2×
#           while only `javac` had a warm daemon; Phase 23 lands the
#           cross-lang build pools (shared caches for Node/Python/PHP/
#           Ruby/Go/Rust/C/C++), so the bar is tightened back to ≤ 1.5×.
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
        --format json \
        "${REPO_ROOT}/tests/benchmark/corpus" > /tmp/m7_gate1.json
    echo "  PASS: static scan completed"
}

# ── Gate 2 ────────────────────────────────────────────────────────────────────

gate_2_dynamic_tests() {
    echo "── Gate 2: cargo nextest run --features dynamic ──"
    cargo nextest run --features dynamic
    # The real-toolchain build-pool perf benches (dynamic_*_build_pool +
    # dynamic_java_compile_pool) are #[ignore]d so the default inner-loop
    # suite stays hermetic + fast: no cargo/go/cc/c++/npm/pip/composer/
    # bundle/javac spawns.  Run them explicitly here so CI still exercises
    # the warm-pool compile path end to end.  They self-skip when a
    # toolchain is missing, so a toolchain-less CI row stays green.
    cargo nextest run --features dynamic --run-ignored ignored-only \
        -E 'binary(~build_pool) | binary(~compile_pool)'
    echo "  PASS: dynamic test suite green"
}

# ── Gate 3: with-verify / static-only ratio ───────────────────────────────────

# Phase 23 target: ratio ≤ 1.5×, now that the cross-lang build pools
# give every shipped language a warm cache (was ≤ 2× under Phase 22).
GATE3_RATIO_TARGET="${GATE3_RATIO_TARGET:-1.5}"

gate_3_verify_ratio() {
    echo "── Gate 3: with-verify / static-only ratio on benches/fixtures/ ──"
    local fixtures="${REPO_ROOT}/benches/fixtures"
    if [[ ! -d "${fixtures}" ]]; then
        echo "  SKIP: ${fixtures} not present"
        return 0
    fi

    # Phase 23: the warm build pools are what buy the ≤ 1.5× ratio, so
    # make sure they are on for both scans even if the caller's env
    # disabled them.  Default is already ON for every shipped language.
    export NYX_DYNAMIC_BUILD_POOL="java=1,node=1,python=1,php=1,ruby=1,go=1,rust=1,c=1,cpp=1"

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
    local args=("--format" "json")
    if [[ "${verify}" == "1" ]]; then
        args+=("--verify")
    fi
    args+=("${path}")
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

    local scan_report="/tmp/m7_gate6_scan.json"
    local results_report="/tmp/m7_gate6_results.json"
    local wallclock_report="/tmp/m7_gate6_wallclock.txt"
    local gate_home="${TMPDIR:-/tmp}/nyx_m7_gate6_home"
    local gate_build_pool="${TMPDIR:-/tmp}/nyx_m7_gate6_build_pool"
    local wallclock

    cargo build --release --quiet --features dynamic
    mkdir -p "${gate_home}" "${gate_build_pool}"
    rm -f "${scan_report}" "${results_report}" "${wallclock_report}"

    set +e
    HOME="${gate_home}" \
    NYX_BUILD_POOL_DIR="${gate_build_pool}" \
    python3 - "${GATE6_WALLCLOCK_BUDGET}" "${scan_report}" "${wallclock_report}" \
        "${REPO_ROOT}/target/release/nyx" scan \
        --verify \
        --index off \
        --format json \
        --quiet \
        "${corpus}" <<'PY'
import subprocess
import sys
import time

budget = float(sys.argv[1])
scan_report = sys.argv[2]
wallclock_report = sys.argv[3]
cmd = sys.argv[4:]
start = time.monotonic()
rc = 0
try:
    with open(scan_report, "wb") as out:
        completed = subprocess.run(cmd, stdout=out, timeout=budget)
        rc = completed.returncode
except subprocess.TimeoutExpired:
    rc = 124
finally:
    elapsed = time.monotonic() - start
    with open(wallclock_report, "w") as f:
        f.write(f"{elapsed:.1f}\n")
sys.exit(rc)
PY
    local nyx_exit=$?
    set -e
    wallclock="$(cat "${wallclock_report}" 2>/dev/null || printf "%s" "${GATE6_WALLCLOCK_BUDGET}")"

    echo "  OWASP verify wall-clock: ${wallclock}s (budget ${GATE6_WALLCLOCK_BUDGET}s)"

    if [[ ${nyx_exit} -eq 124 ]]; then
        echo "  FAIL: nyx scan exceeded wall-clock budget"
        return 1
    fi
    if [[ ${nyx_exit} -ne 0 && ${nyx_exit} -ne 1 ]]; then
        echo "  FAIL: nyx scan exited ${nyx_exit}"
        return 1
    fi
    if [[ ! -s "${scan_report}" ]]; then
        echo "  FAIL: nyx scan produced no JSON report"
        return 1
    fi

    awk -v w="${wallclock}" -v b="${GATE6_WALLCLOCK_BUDGET}" \
        'BEGIN { if (w+0 > b+0) exit 1 }' \
        || { echo "  FAIL: wall-clock exceeds budget"; return 1; }

    echo "[]" > "${results_report}"
    python3 "${REPO_ROOT}/tests/eval_corpus/tabulate.py" \
        --label owasp \
        --scan "${scan_report}" \
        --ground-truth "${REPO_ROOT}/tests/eval_corpus/ground_truth/owasp_benchmark_v1.2.json" \
        --append "${results_report}" \
        || { echo "  FAIL: OWASP result tabulation failed"; return 1; }

    python3 "${REPO_ROOT}/tests/eval_corpus/report.py" \
        --results "${results_report}" \
        --min-confirmed-rate "${GATE6_CONFIRMED_RATE_TARGET}" \
        || { echo "  FAIL: confirmed-rate below ${GATE6_CONFIRMED_RATE_TARGET}"; return 1; }
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

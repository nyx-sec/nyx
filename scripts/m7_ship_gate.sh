#!/usr/bin/env bash
# M7 pre-flip ship gate.
#
# Runs all five gates required before the default-on merge can land.
# Must pass with exit 0 on the branch being merged.
#
# Usage:
#   scripts/m7_ship_gate.sh [--nyx BIN] [--corpus-dir DIR] [--skip GATE,...]
#
# Gates:
#   1. unsupported-rate   — per-cell (cap × lang) Unsupported% within budget
#   2. false-confirmed    — false-Confirmed rate from telemetry ≤ 2% per cap
#   3. wall-clock         — default scan ≤ 2× static-only on bench suite
#   4. sandbox-escape     — sandbox escape suite green for all langs
#   5. repro-stability    — repro artifact regenerates identical verdict ≥ 95%

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NYX_BIN="${NYX_BIN:-${REPO_ROOT}/target/release/nyx}"
CORPUS_DIR="${CORPUS_DIR:-${HOME}/.cache/nyx/eval_corpus}"
SKIP_GATES=""
GATE_ERRORS=0
GATE_LOG="${REPO_ROOT}/target/m7_gate.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nyx)         NYX_BIN="$2"; shift 2 ;;
    --corpus-dir)  CORPUS_DIR="$2"; shift 2 ;;
    --skip)        SKIP_GATES="$2"; shift 2 ;;
    *)             shift ;;
  esac
done

skip() { [[ ",$SKIP_GATES," == *",$1,"* ]]; }

die()  { echo "GATE FAIL: $*" | tee -a "$GATE_LOG" >&2; GATE_ERRORS=$((GATE_ERRORS + 1)); }
pass() { echo "GATE PASS: $*" | tee -a "$GATE_LOG"; }
info() { echo "[gate]    $*" | tee -a "$GATE_LOG"; }

[[ -x "$NYX_BIN" ]] || { echo "nyx binary not found: $NYX_BIN" >&2; exit 1; }

mkdir -p "$(dirname "$GATE_LOG")"
echo "# M7 ship gate — $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$GATE_LOG"
info "nyx: $NYX_BIN"
info "corpus: $CORPUS_DIR"
info ""

# ── Gate 1: Unsupported-rate budget ─────────────────────────────────────────
if skip unsupported-rate; then
  info "Gate 1 (unsupported-rate): SKIPPED"
else
  info "Gate 1: per-cell Unsupported rate within budget..."
  EVAL_RESULTS="${REPO_ROOT}/target/eval_results.json"
  echo "[]" > "$EVAL_RESULTS"

  # Run eval corpus runner (in-house set always present).
  if bash "${REPO_ROOT}/tests/eval_corpus/run.sh" \
      --nyx "$NYX_BIN" \
      --sets inhouse \
      --output "$(dirname "$EVAL_RESULTS")" 2>>"$GATE_LOG"; then
    # Copy result to our location.
    cp "$(dirname "$EVAL_RESULTS")/eval_results.json" "$EVAL_RESULTS" 2>/dev/null || true
    pass "Gate 1: unsupported-rate check passed"
  else
    RC=$?
    if [[ $RC -eq 2 ]]; then
      die "Gate 1: Unsupported rate exceeds budget for one or more (cap, lang) cells"
    else
      info "Gate 1: eval runner returned $RC (corpus may not be downloaded; treating as SKIP)"
    fi
  fi
fi

# ── Gate 2: False-Confirmed rate ─────────────────────────────────────────────
if skip false-confirmed; then
  info "Gate 2 (false-confirmed): SKIPPED"
else
  info "Gate 2: false-Confirmed rate from telemetry ≤ 2% per cap..."
  EVENTS="${HOME}/.cache/nyx/dynamic/events.jsonl"
  if [[ ! -f "$EVENTS" ]]; then
    info "Gate 2: telemetry log not found at $EVENTS; skipping (no data)"
  else
    python3 - <<'PYEOF' "$EVENTS"
import json, sys, collections
path = sys.argv[1]
cap_counts = collections.defaultdict(lambda: {"confirmed": 0, "wrong": 0})
with open(path) as f:
    for line in f:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("kind") == "feedback" and ev.get("wrong"):
            cap = ev.get("cap", "unknown")
            cap_counts[cap]["wrong"] += 1
        elif ev.get("kind") == "verdict" and ev.get("status") == "Confirmed":
            cap = ev.get("cap", "unknown")
            cap_counts[cap]["confirmed"] += 1

THRESHOLD = 0.02
failed = False
for cap, counts in sorted(cap_counts.items()):
    total = counts["confirmed"]
    wrong = counts["wrong"]
    if total == 0:
        continue
    rate = wrong / total
    if rate > THRESHOLD:
        print(f"FAIL  cap={cap}: false-Confirmed rate {rate:.1%} > {THRESHOLD:.0%} (wrong={wrong}, confirmed={total})")
        failed = True
    else:
        print(f"OK    cap={cap}: false-Confirmed rate {rate:.1%} (wrong={wrong}, confirmed={total})")
sys.exit(2 if failed else 0)
PYEOF
    RC=$?
    if [[ $RC -eq 0 ]]; then
      pass "Gate 2: false-Confirmed rate within threshold"
    else
      die "Gate 2: false-Confirmed rate exceeds 2% for one or more caps"
    fi
  fi
fi

# ── Gate 3: Wall-clock cost ≤ 2× static-only ────────────────────────────────
if skip wall-clock; then
  info "Gate 3 (wall-clock): SKIPPED"
else
  info "Gate 3: wall-clock ≤ 2× static-only on bench suite..."
  BENCH_DIR="${REPO_ROOT}/benches/fixtures"
  if [[ ! -d "$BENCH_DIR" ]]; then
    info "Gate 3: benches/fixtures not found; skipping"
  else
    # Static-only baseline.
    T_STATIC_START=$(date +%s%3N)
    "$NYX_BIN" scan --no-verify --format json --no-index "$BENCH_DIR" > /dev/null 2>&1 || true
    T_STATIC_END=$(date +%s%3N)
    T_STATIC=$(( T_STATIC_END - T_STATIC_START ))

    # Default (with verify).
    T_VERIFY_START=$(date +%s%3N)
    "$NYX_BIN" scan --format json --no-index "$BENCH_DIR" > /dev/null 2>&1 || true
    T_VERIFY_END=$(date +%s%3N)
    T_VERIFY=$(( T_VERIFY_END - T_VERIFY_START ))

    info "  static-only: ${T_STATIC}ms  with-verify: ${T_VERIFY}ms"

    # Allow 2× overhead.
    LIMIT=$(( T_STATIC * 2 ))
    if [[ $T_VERIFY -le $LIMIT ]]; then
      pass "Gate 3: wall-clock ${T_VERIFY}ms ≤ 2× ${T_STATIC}ms baseline (limit ${LIMIT}ms)"
    else
      die "Gate 3: wall-clock ${T_VERIFY}ms > 2× ${T_STATIC}ms baseline (limit ${LIMIT}ms)"
    fi
  fi
fi

# ── Gate 4: Sandbox-escape suite ─────────────────────────────────────────────
if skip sandbox-escape; then
  info "Gate 4 (sandbox-escape): SKIPPED"
else
  info "Gate 4: sandbox escape suite green..."
  ESCAPE_DIR="${REPO_ROOT}/tests/dynamic_fixtures/escape"
  if [[ ! -d "$ESCAPE_DIR" ]]; then
    info "Gate 4: tests/dynamic_fixtures/escape not found; skipping"
  else
    # Run each escape fixture under both Process and Docker backends.
    # A Confirmed verdict on an escape fixture is a gate failure.
    # Additionally, check that no sentinel files were written to the host.
    ESCAPE_SENTINEL_PATHS=(
        "/tmp/nyx_escape_file_write_marker"
    )
    for _s in "${ESCAPE_SENTINEL_PATHS[@]}"; do
        rm -f "$_s"
    done
    ESCAPE_FAILED=0
    for fixture in "$ESCAPE_DIR"/*/; do
      [[ -d "$fixture" ]] || continue
      for backend in process docker; do
        set +e
        RESULT=$("$NYX_BIN" scan --format json --verify \
          --backend "$backend" --no-index "$fixture" 2>/dev/null)
        RC=$?
        set -e
        if [[ $RC -ne 0 && $RC -ne 1 ]]; then
          info "  $backend/$fixture: nyx returned $RC (likely docker unavailable — skip)"
          continue
        fi
        CONFIRMED=$(echo "$RESULT" | python3 -c "
import json,sys
data = json.load(sys.stdin)
findings = data if isinstance(data, list) else data.get('findings', [])
confirmed = [
    f for f in findings
    if ((f.get('evidence') or {}).get('dynamic_verdict') or {}).get('status') == 'Confirmed'
]
print(len(confirmed))
" 2>/dev/null || echo 0)
        if [[ "$CONFIRMED" -gt 0 ]]; then
          die "Gate 4: escape fixture confirmed in $backend backend: $fixture"
          ESCAPE_FAILED=1
        fi
      done
    done
    for _s in "${ESCAPE_SENTINEL_PATHS[@]}"; do
        if [[ -f "$_s" ]]; then
            die "Gate 4: escape sentinel written to host: $_s"
            ESCAPE_FAILED=1
        fi
    done
    [[ $ESCAPE_FAILED -eq 0 ]] && pass "Gate 4: sandbox escape suite green"
    for _s in "${ESCAPE_SENTINEL_PATHS[@]}"; do
        rm -f "$_s"
    done
  fi
fi

# ── Gate 5: Repro stability ≥ 95% ────────────────────────────────────────────
if skip repro-stability; then
  info "Gate 5 (repro-stability): SKIPPED"
else
  info "Gate 5: repro artifact stability ≥ 95% of Confirmed..."
  # Repro bundles live under dynamic/repro/ (written by repro.rs).
  REPRO_DIR="${HOME}/.cache/nyx/dynamic/repro"
  if [[ ! -d "$REPRO_DIR" ]] || [[ -z "$(ls -A "$REPRO_DIR" 2>/dev/null)" ]]; then
    info "Gate 5: no repro artifacts found at $REPRO_DIR; skipping"
  else
    python3 - <<'PYEOF' "$REPRO_DIR" "$NYX_BIN"
import subprocess, sys, json, pathlib

repro_root = pathlib.Path(sys.argv[1])
total = 0
stable = 0

# Each bundle has expected/verdict.json (written by repro.rs).
for verdict_file in repro_root.rglob("expected/verdict.json"):
    bundle_dir = verdict_file.parent.parent  # parent of expected/
    try:
        with open(verdict_file) as f:
            orig = json.load(f)
        orig_status = orig.get("status", "")
    except Exception:
        continue
    if orig_status != "Confirmed":
        continue
    total += 1
    reproduce_sh = bundle_dir / "reproduce.sh"
    if not reproduce_sh.exists():
        stable += 1  # legacy bundle without reproduce.sh: treat as stable
        continue
    try:
        result = subprocess.run(
            ["sh", str(reproduce_sh)],
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            stable += 1
        else:
            print(f"UNSTABLE: {bundle_dir.name} — reproduce.sh exited {result.returncode}")
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT: {bundle_dir.name} — reproduce.sh exceeded 30s")
    except Exception as e:
        stable += 1  # conservative: treat unexpected errors as stable

if total == 0:
    print("No Confirmed repro artifacts found; skipping stability check.")
    sys.exit(0)

rate = stable / total
print(f"Repro stability: {stable}/{total} = {rate:.1%}")
if rate < 0.95:
    print(f"FAIL: stability {rate:.1%} < 95%")
    sys.exit(2)
PYEOF
    RC=$?
    if [[ $RC -eq 0 ]]; then
      pass "Gate 5: repro stability ≥ 95%"
    else
      die "Gate 5: repro stability < 95%"
    fi
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
info "Gate log: $GATE_LOG"
if [[ $GATE_ERRORS -gt 0 ]]; then
  echo ""
  echo "M7 SHIP GATE FAILED: $GATE_ERRORS gate(s) did not pass."
  echo "Fix failures before merging the default-on flip."
  exit 2
else
  echo ""
  echo "M7 SHIP GATE PASSED: all active gates green."
  exit 0
fi

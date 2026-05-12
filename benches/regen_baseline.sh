#!/usr/bin/env bash
# Regenerate benches/dynamic_bench_baseline.json from a real cargo bench run.
#
# Usage:
#   bash benches/regen_baseline.sh
#
# Requirements:
#   - python3 on PATH
#   - cargo (nightly or stable with edition 2024)
#   - Criterion's JSON output (criterion feature already in dev-deps)
#
# The script runs the dynamic bench group, parses Criterion's estimates JSON,
# and overwrites dynamic_bench_baseline.json with real numbers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BASELINE_FILE="${SCRIPT_DIR}/dynamic_bench_baseline.json"

echo "Running cargo bench --features dynamic -- dynamic ..."
cargo bench --manifest-path "${REPO_ROOT}/Cargo.toml" \
    --features dynamic \
    -- dynamic \
    2>&1 | tee /tmp/nyx_bench_raw.txt

# Criterion writes estimates to target/criterion/<bench>/<group>/estimates.json.
# Extract mean_ns for each tracked benchmark.
extract_ns() {
    local path="$1"
    if [[ -f "${path}" ]]; then
        python3 -c "
import json, sys
d = json.load(open('${path}'))
mean = d['mean']['point_estimate']
stddev = (d['std_dev']['point_estimate']) if 'std_dev' in d else 0
print(int(mean), int(stddev))
"
    else
        echo "0 0"
    fi
}

TARGET="${REPO_ROOT}/target/criterion"

read COLD_MEAN COLD_STDDEV < <(extract_ns "${TARGET}/harness_build_cold/default/estimates.json")
read WARM_MEAN WARM_STDDEV < <(extract_ns "${TARGET}/harness_build_warm/default/estimates.json")
read RUN_MEAN  RUN_STDDEV  < <(extract_ns "${TARGET}/sandbox_run_payload/default/estimates.json")

MACHINE="$(uname -m) / $(uname -s)"
NYX_VER="$(cargo metadata --manifest-path "${REPO_ROOT}/Cargo.toml" --no-deps --format-version 1 \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(p['version'] for p in d['packages'] if p['name']=='nyx-scanner'))")"
DATE="$(date +%Y-%m-%d)"

cat > "${BASELINE_FILE}" <<EOF
{
  "schema": 1,
  "note": "Baseline captured on ${MACHINE}, nyx v${NYX_VER}, ${DATE}. Regenerate with: benches/regen_baseline.sh",
  "benchmarks": {
    "harness_build_cold": {
      "mean_ns": ${COLD_MEAN},
      "stddev_ns": ${COLD_STDDEV},
      "description": "Fresh workdir; spec → BuiltHarness including source gen + disk write."
    },
    "harness_build_warm": {
      "mean_ns": ${WARM_MEAN},
      "stddev_ns": ${WARM_STDDEV},
      "description": "Workdir already staged; file write skipped by dst.exists() guard."
    },
    "sandbox_run_payload": {
      "mean_ns": ${RUN_MEAN},
      "stddev_ns": ${RUN_STDDEV},
      "description": "Single process-backend run with sqli payload; includes python3 startup + settrace."
    }
  },
  "regression_thresholds": {
    "harness_build_cold": 2.0,
    "harness_build_warm": 2.0,
    "sandbox_run_payload": 1.5
  }
}
EOF

echo "Updated ${BASELINE_FILE}"

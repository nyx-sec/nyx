#!/usr/bin/env bash
# Usage: performance-measure.sh <base-sha> <head-sha> <out-dir>
#
# Both revisions run head's benches/ so the workload matches. If that doesn't
# compile against base, base falls back to its own benches/.
set -euo pipefail

base=$(git rev-parse --verify "$1^{commit}")
head=$(git rev-parse --verify "$2^{commit}")
out=$(mkdir -p "$3" && cd "$3" && pwd)
repo=$(git rev-parse --show-toplevel)
scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bench=${PERF_BENCH:-scan_bench}
rounds=${PERF_ROUNDS:-2}
criterion=(--bench --noplot
  --warm-up-time "${PERF_WARMUP:-1}"
  --measurement-time "${PERF_MEASURE:-3}"
  --sample-size "${PERF_SAMPLES:-20}")
if [[ -n ${PERF_FILTER:-} ]]; then criterion+=("$PERF_FILTER"); fi

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/nyx-performance.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target}
rm -rf "$out/raw" "$out/logs"
mkdir -p "$out/raw" "$out/logs"

extract() {
  git -C "$repo" archive "$1" "$2" | tar -x -C "$3"
}

build() {
  local role=$1
  # Both trees share a target dir and cargo tracks workspace crates by relative
  # path + mtime. Without fresh mtimes base can silently reuse head's build.
  find "$work/$role" -type f -exec touch {} +
  (cd "$work/$role" && cargo bench --locked --bench "$bench" --no-run \
    --message-format=json-render-diagnostics) \
    > "$work/$role-build.jsonl" 2> "$out/logs/$role-build.log" || return 1
  python3 - "$work/$role-build.jsonl" "$bench" "$work/$role.bin" <<'PY'
import json, shutil, sys
path, bench, dest = sys.argv[1:]
for line in open(path, encoding='utf-8'):
    try:
        message = json.loads(line)
    except ValueError:
        continue
    target = message.get('target') or {}
    if (message.get('reason') == 'compiler-artifact' and message.get('executable')
            and 'bench' in target.get('kind', []) and target.get('name') == bench):
        shutil.copy2(message['executable'], dest)
        sys.exit(0)
sys.exit('no bench executable in cargo output')
PY
}

for role in base head; do
  if [[ $role == base ]]; then revision=$base; else revision=$head; fi
  mkdir -p "$work/$role"
  extract "$revision" . "$work/$role"
  # build.rs stubs the web UI when frontend/ is missing instead of running npm.
  rm -rf "$work/$role/frontend"
done
rm -rf "$work/base/benches"
extract "$head" benches "$work/base"

harness=shared
base_status=ok
head_status=ok
echo "::group::Build head"
build head || head_status=build-failed
echo "::endgroup::"
echo "::group::Build base"
if ! build base; then
  echo "head benches/ doesn't build against base, using base's own"
  mv "$out/logs/base-build.log" "$out/logs/base-shared-harness-build.log"
  harness=own
  rm -rf "$work/base/benches"
  extract "$base" benches "$work/base"
  build base || base_status=build-failed
fi
echo "::endgroup::"

if [[ $base_status != ok || $head_status != ok ]]; then rounds=0; fi
# Alternate base/head so runner drift hits both sides.
for ((round = 1; round <= rounds; round++)); do
  for role in base head; do
    echo "::group::Run $role, round $round"
    status=0
    (cd "$work/$role" && CRITERION_HOME="$out/raw/$role-$round" "$work/$role.bin" "${criterion[@]}") \
      2>&1 | tee "$out/logs/$role-$round.log" || status=$?
    if (( status != 0 )); then
      echo "::warning::$role round $round exited with $status"
    fi
    echo "::endgroup::"
  done
done

python3 "$scripts/performance-report.py" collect --raw "$out/raw" --output "$out/report.json" \
  --base "$base" --head "$head" --bench "$bench" --harness "$harness" --rounds "$rounds" \
  --base-status "$base_status" --head-status "$head_status"
[[ $base_status == ok && $head_status == ok ]]

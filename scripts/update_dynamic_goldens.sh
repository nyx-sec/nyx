#!/usr/bin/env bash
# Regenerate dynamic-fixture golden verdicts.
#
# Usage:
#   ./scripts/update_dynamic_goldens.sh [--test <name>]
#
# Re-runs the dynamic fixture suites under `NYX_UPDATE_GOLDENS=1` so each
# fixture's harness overwrites its `.golden.json` file with the current
# verdict. After this script completes, rerun without the env var to
# confirm the goldens match.
#
# Default: refreshes both python_fixtures and rust_fixtures. Pass --test
# to refresh only one suite (e.g. `--test python_fixtures`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SUITES=(python_fixtures rust_fixtures)
if [[ $# -gt 0 ]]; then
  case "$1" in
    --test) SUITES=("$2"); shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 1
      ;;
  esac
fi

cd "$REPO_ROOT"

for suite in "${SUITES[@]}"; do
  echo "[update-goldens] refreshing $suite ..."
  NYX_UPDATE_GOLDENS=1 \
    cargo nextest run --features dynamic --test "$suite" --no-fail-fast
done

echo "[update-goldens] re-running suites without NYX_UPDATE_GOLDENS=1 to verify ..."
for suite in "${SUITES[@]}"; do
  cargo nextest run --features dynamic --test "$suite"
done

echo "[update-goldens] done. Inspect git diff under tests/dynamic_fixtures/ before committing."

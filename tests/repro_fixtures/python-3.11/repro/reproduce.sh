#!/bin/sh
# Nyx dynamic repro — finding flask_eval_python_311 / payload eval-rce-arith
#
# Usage:
#   ./reproduce.sh          — run via process backend (direct)
#   ./reproduce.sh --docker — run via Docker backend (isolated)
#
# Exit codes:
#   0  sink_hit matches expected/outcome.json (replay green)
#   1  sink_hit mismatch (replay diverged from recorded outcome)
#   2  docker requested but unavailable
#   3  host toolchain mismatch in process mode (Phase 28 hermeticity)
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
PAYLOAD="$(cat payload/payload.bin)"
EXPECTED_TOOLCHAIN="python-3.11"
EXPECTED_SINK=$(grep -o '"sink_hit"[[:space:]]*:[[:space:]]*[a-z]*' \
expected/outcome.json | grep -o '[a-z]*$')

if [ "${1:-}" = "--docker" ]; then
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
echo 'error: docker not available' >&2; exit 2
fi
IMAGE="nyx-repro-repro"
docker build -t "$IMAGE" -f harness/Dockerfile.harness harness/ >/dev/null
ACTUAL=$(docker run --rm --cap-drop=ALL --security-opt no-new-privileges:true --network none -e NYX_PAYLOAD="$PAYLOAD" "$IMAGE" 2>&1) || ACTUAL=''
docker rmi "$IMAGE" >/dev/null 2>&1 || true
else
# Phase 28 hermeticity check: refuse process-backend replay when
# the host is missing the expected toolchain id.  Operators must
# either install the toolchain or pass --docker.
if ! sh -c 'command -v python3' >/dev/null 2>&1; then
echo "error: host toolchain does not match expected $EXPECTED_TOOLCHAIN; re-run with --docker" >&2
exit 3
fi
ACTUAL=$(NYX_PAYLOAD="$PAYLOAD" python3 ./harness/harness.py 2>&1) || ACTUAL=''
fi

if echo "$ACTUAL" | grep -q '__NYX_SINK_HIT__'; then
ACTUAL_SINK=true
else
ACTUAL_SINK=false
fi

if [ "$ACTUAL_SINK" = "$EXPECTED_SINK" ]; then
echo "PASS: sink_hit=$ACTUAL_SINK (matches expected)"
exit 0
else
echo "FAIL: sink_hit=$ACTUAL_SINK expected=$EXPECTED_SINK"
exit 1
fi

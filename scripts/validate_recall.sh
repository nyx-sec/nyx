#!/usr/bin/env bash
# validate_recall.sh — run `nyx scan --format json` against a real OSS
# checkout and diff the result against a frozen baseline.
#
# Phase 11 of the JS/TS recall-gap engine plan owns the JS targets.
# Phase 17 adds cross-language targets (php/java/python/rust/go/ruby)
# under `tests/recall_targets/xlang/<lang>/<target>.json`. JS-era
# baselines stay at `tests/recall_targets/<target>.json` for backwards
# compatibility.
#
# Baseline files were relocated out of `.pitboss/` per the Phase 01
# precedent — pitboss implementer agents must not write under
# `.pitboss/`.
#
# Usage:
#   scripts/validate_recall.sh <target> <clone_path> [--capture]
#   scripts/validate_recall.sh --lang <lang> <target> <clone_path> [--capture]
#
#   <lang>        php | java | python | rust | go | ruby
#                 Selects the per-language target set under
#                 `tests/recall_targets/xlang/<lang>/`.
#   <target>      Without --lang: cal_com | vercel_commerce |
#                 shadcn_examples | blitz_apps (Phase 11 JS targets).
#                 With --lang: any baseline shipped under
#                 `tests/recall_targets/xlang/<lang>/<target>.json`.
#   <clone_path>  path to a local clone of the OSS repo
#   --capture     overwrite the baseline with the current scan output
#                 (every finding marked `needs_review`); use this when
#                 the baseline file is a placeholder or when intentional
#                 recall lift is being frozen.
#
# Default mode (no --capture) loads the baseline, re-scans the clone,
# and prints `{ added, removed, unchanged }` finding counts per
# rule_id. Findings are matched on the tuple
# `(rule_id, path_suffix, line)`; `path_suffix` is the clone-relative
# path so the diff is robust against absolute-path differences.
#
# Dependencies: bash, jq. Nothing else.

set -euo pipefail

usage() {
    cat >&2 <<EOF
usage: $(basename "$0") <target> <clone_path> [--capture]
       $(basename "$0") --lang <lang> <target> <clone_path> [--capture]

  lang        php | java | python | rust | go | ruby
  target      JS targets: cal_com | vercel_commerce | shadcn_examples |
              blitz_apps. With --lang: any name shipped under
              tests/recall_targets/xlang/<lang>/.
  clone_path  path to local checkout of the target repo
  --capture   overwrite the baseline JSON with the current scan output
EOF
    exit 2
}

LANG_FLAG=""
POSITIONAL=()
CAPTURE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --lang)
            if [ $# -lt 2 ]; then
                echo "--lang requires an argument" >&2
                usage
            fi
            LANG_FLAG="$2"
            shift 2
            ;;
        --lang=*)
            LANG_FLAG="${1#--lang=}"
            shift
            ;;
        --capture)
            CAPTURE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        --*)
            echo "unknown flag: $1" >&2
            usage
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -lt 2 ]; then
    usage
fi

TARGET="${POSITIONAL[0]}"
CLONE_PATH="${POSITIONAL[1]}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -n "$LANG_FLAG" ]; then
    case "$LANG_FLAG" in
        php|java|python|rust|go|ruby) ;;
        *) echo "unknown lang: $LANG_FLAG" >&2; usage ;;
    esac
    BASELINE="$REPO_ROOT/tests/recall_targets/xlang/${LANG_FLAG}/${TARGET}.json"
else
    case "$TARGET" in
        cal_com|vercel_commerce|shadcn_examples|blitz_apps) ;;
        *) echo "unknown target: $TARGET (use --lang for cross-lang targets)" >&2; usage ;;
    esac
    BASELINE="$REPO_ROOT/tests/recall_targets/${TARGET}.json"
fi

if [ ! -d "$CLONE_PATH" ]; then
    echo "clone path is not a directory: $CLONE_PATH" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required but not installed" >&2
    exit 1
fi

if [ ! -f "$BASELINE" ]; then
    echo "baseline not found: $BASELINE" >&2
    exit 1
fi

# Locate the nyx binary — prefer a release build, fall back to debug.
if [ -n "${NYX_BIN:-}" ] && [ -x "$NYX_BIN" ]; then
    NYX="$NYX_BIN"
elif [ -x "$REPO_ROOT/target/release/nyx" ]; then
    NYX="$REPO_ROOT/target/release/nyx"
elif [ -x "$REPO_ROOT/target/debug/nyx" ]; then
    NYX="$REPO_ROOT/target/debug/nyx"
elif command -v nyx >/dev/null 2>&1; then
    NYX="$(command -v nyx)"
else
    echo "nyx binary not found; build with 'cargo build --release' first" >&2
    exit 1
fi

CLONE_ABS="$(cd "$CLONE_PATH" && pwd)"
TMP_OUT="$(mktemp -t nyx_recall_${TARGET}.XXXXXX.json)"
trap 'rm -f "$TMP_OUT"' EXIT

if [ -n "$LANG_FLAG" ]; then
    echo "[validate_recall] lang=$LANG_FLAG target=$TARGET clone=$CLONE_ABS" >&2
else
    echo "[validate_recall] target=$TARGET clone=$CLONE_ABS" >&2
fi
echo "[validate_recall] nyx=$NYX baseline=$BASELINE" >&2
echo "[validate_recall] scanning..." >&2

"$NYX" scan "$CLONE_ABS" --format json --index off >"$TMP_OUT"

# Strip the clone-absolute prefix off each finding's path so the diff
# tuple `(rule_id, path_suffix, line)` is portable across machines.
# Also drop the trailing ` (source N:M)` suffix on `id` so taint
# findings group under their canonical rule_id.
CURRENT="$(jq --arg root "$CLONE_ABS/" '
    [ .[] | {
        rule_id: ((.id // "") | sub(" \\(source [^)]*\\)$"; "")),
        path_suffix: ((.path // "") | ltrimstr($root)),
        line: (.line // 0),
        severity: (.severity // "Unknown")
    } ]
' "$TMP_OUT")"

if [ "$CAPTURE" -eq 1 ]; then
    PIN="$(cd "$CLONE_ABS" && git log -1 --format=%H 2>/dev/null || echo "unknown")"
    UPDATED="$(jq --argjson findings "$CURRENT" \
                  --arg pin "$PIN" \
                  --arg captured_on "$(date -u +%Y-%m-%d)" \
                  '. + {
                       captured_against: ("real-scan @ " + $pin),
                       captured_on: $captured_on,
                       pinned_commit: $pin,
                       findings: ($findings | map(. + {verdict: "needs_review", note: "captured by validate_recall.sh --capture"}))
                   }' "$BASELINE")"
    printf '%s\n' "$UPDATED" >"$BASELINE"
    echo "[validate_recall] wrote $(echo "$CURRENT" | jq 'length') findings to $BASELINE" >&2
    exit 0
fi

# Diff mode: compare current scan to baseline.
BASELINE_FINDINGS="$(jq '.findings // []' "$BASELINE")"

DIFF_REPORT="$(jq -n \
    --argjson cur "$CURRENT" \
    --argjson base "$BASELINE_FINDINGS" '
    def key(f): [f.rule_id, f.path_suffix, f.line];

    def index_set(arr):
        reduce arr[] as $f ({}; .[(key($f) | tojson)] = $f);

    (index_set($cur))   as $cidx
    | (index_set($base)) as $bidx
    | ($cidx | keys_unsorted) as $ckeys
    | ($bidx | keys_unsorted) as $bkeys
    | ($ckeys - $bkeys) as $added_keys
    | ($bkeys - $ckeys) as $removed_keys
    | ($ckeys - $added_keys) as $unchanged_keys
    | def by_rule(keys; idx):
        keys
        | map(idx[.])
        | group_by(.rule_id)
        | map({(.[0].rule_id): length}) | add // {};

    {
        added:     by_rule($added_keys; $cidx),
        removed:   by_rule($removed_keys; $bidx),
        unchanged: by_rule($unchanged_keys; $cidx),
        added_total:     ($added_keys | length),
        removed_total:   ($removed_keys | length),
        unchanged_total: ($unchanged_keys | length)
    }
')"

printf '%s\n' "$DIFF_REPORT"

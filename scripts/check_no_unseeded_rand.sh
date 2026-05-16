#!/usr/bin/env bash
# Phase 30 — Track C: determinism audit gate.
#
# Greps `src/dynamic/` for non-deterministic RNG APIs.  Anything inside
# the dynamic verifier must route through `crate::dynamic::rand::SpecRng`
# so identical inputs produce identical sandbox runs; the Phase 27
# `events.jsonl` replay invariant and the Phase 28 repro bundle
# hermeticity contract both depend on it.
#
# Exits 0 on a clean tree, 1 when any banned API surfaces.  CI wires
# this into the dynamic workflow so a regression fails the build before
# it ships.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DYN_DIR="$ROOT/src/dynamic"

if [[ ! -d "$DYN_DIR" ]]; then
  echo "audit: src/dynamic/ missing at $DYN_DIR" >&2
  exit 2
fi

# Banned patterns: any real call site of a non-deterministic RNG API.
#
# Each pattern is a Rust-token shape we expect to never appear inside
# src/dynamic/ once Phase 30 lands.  The seccomp policy file (which
# names the "getrandom" syscall as a string literal) is excluded
# because its mention is a syscall name, not a Rust API call — the
# string-literal regex below matches the bare token, and the seccomp
# files spell it inside quotes that look identical, so we exclude the
# seccomp subtree explicitly.
PATTERNS=(
  'rand::thread_rng'
  'thread_rng\s*\('
  'rand::random'
  'OsRng'
  'from_entropy'
  'getrandom::getrandom'
  'Uuid::new_v4'
  'uuid::Uuid::new_v4'
  'fastrand'
  'nanoid'
)

EXCLUDE_PATHS=(
  "$DYN_DIR/sandbox/seccomp"
  "$DYN_DIR/rand.rs"
)

# Use `git grep` when inside a git repo (respects .gitignore), fall
# back to `grep -r` otherwise.  Either way the exclusion list is
# applied via a post-filter so the audit catches new files even
# before they are tracked.
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  HITS="$(git -C "$ROOT" grep -nE "$(IFS='|'; echo "${PATTERNS[*]}")" -- 'src/dynamic/**/*.rs' 'src/dynamic/*.rs' || true)"
else
  HITS="$(grep -rnE "$(IFS='|'; echo "${PATTERNS[*]}")" --include='*.rs' "$DYN_DIR" || true)"
fi

if [[ -z "$HITS" ]]; then
  echo "audit: src/dynamic/ is free of unseeded RNG APIs"
  exit 0
fi

FILTERED=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  path="${line%%:*}"
  skip=0
  for ex in "${EXCLUDE_PATHS[@]}"; do
    case "$path" in
      "$ex"*|"${ex#$ROOT/}"*) skip=1; break ;;
    esac
  done
  if [[ $skip -eq 0 ]]; then
    FILTERED+="$line"$'\n'
  fi
done <<< "$HITS"

if [[ -z "${FILTERED//[$' \t\n\r']/}" ]]; then
  echo "audit: src/dynamic/ is free of unseeded RNG APIs"
  exit 0
fi

echo "audit: banned RNG APIs surfaced inside src/dynamic/" >&2
echo "$FILTERED" >&2
echo >&2
echo "Replace with crate::dynamic::rand::SpecRng::seeded(&spec.spec_hash)." >&2
exit 1

# Dynamic verification

Nyx verifies every `Confidence >= Medium` finding by default: it builds
a minimal harness, runs your code's entry point against a curated payload corpus
inside a sandbox, and records the verdict in each finding's evidence block.

## Default-on semantics

```
nyx scan                 # verifies Medium+ findings (default)
nyx scan --no-verify     # static analysis only, no harness execution
nyx scan --verify        # same as default; explicit for clarity in scripts
```

`--no-verify` is the escape hatch. It overrides the config default for a single
run without changing `nyx.toml`.

### What "verified" means

A finding with `dynamic_verdict.status: Confirmed` was successfully triggered
by at least one payload in nyx's corpus. The corpus covers common patterns for
each vulnerability class (SQL injection, XSS, command injection, SSRF, etc.) per
language.

A finding with `dynamic_verdict.status: NotConfirmed` was attempted but no
payload fired. This is not a false-positive signal — it means the corpus did not
have a payload that matched the specific sink variant or the execution path was
not reachable in the test harness.

A finding with `dynamic_verdict.status: Unsupported` could not be attempted.
Common reasons: confidence below threshold, no flow steps, language or sink type
not yet supported by the harness layer.

### Confidence gate

Only `Confidence >= Medium` findings are verified by default (§5.1). To also
verify low-confidence findings — for corpus building or backfill — pass
`--verify-all-confidence`:

```
nyx scan --verify-all-confidence
```

This is not recommended for production scans because low-confidence findings have
a higher false-positive rate and the harness may produce unreliable verdicts.

## nyx.toml opt-out

If you want static-only scans permanently, set `verify = false` in `nyx.toml`:

```toml
[scanner]
verify = false
```

This survives upgrades — the M7 default flip only changes the inherited default
for projects that have not explicitly set the field.

## Sandbox backends

nyx uses docker when available, then falls back to an in-process runner:

```
nyx scan --backend docker    # require docker; fail if unavailable
nyx scan --backend process   # in-process runner (no container; less isolation)
nyx scan --unsafe-sandbox    # alias for --backend process
```

The docker backend mounts only the entry file's directory and blocks all
outbound network by default. When out-of-band detection is enabled (`oob_listener`
in config), the container gets `--network bridge` with a host-gateway route.

## Repro artifacts

When a finding is `Confirmed`, nyx writes a repro artifact to
`~/.cache/nyx/repro/<stable_hash>/`. The artifact contains the harness spec and
the triggering payload. You can regenerate the verdict with:

```
nyx scan --verify <path>    # re-scans and re-verifies
```

See `docs/output.md` for the `dynamic_verdict` field schema.

## Wall-clock cost

Verification adds harness build + sandbox startup time per finding. On typical
codebases with 10–50 Medium+ findings, end-to-end overhead is 2–5× static-only.

If scan time is unacceptable for a given workflow (e.g. IDE integration, quick
pre-commit check), use `--no-verify` for that workflow and rely on the full scan
in CI.

## Event schema

The dynamic layer writes one JSON record per verdict to
`~/.cache/nyx/dynamic/events.jsonl`. Every record begins with a fixed envelope
so older readers fail loudly instead of silently mixing incompatible shapes:

```json
{
  "schema_version": 1,
  "nyx_version": "0.7.0",
  "corpus_version": "4",
  "kind": "verdict",
  "ts": "2026-05-15T18:42:09Z",
  "finding_id": "a3b1...",
  "spec_hash": "9f4e...",
  "lang": "python",
  "cap": "SQL_QUERY",
  "status": "Confirmed",
  "toolchain_id": "python-3.11",
  "toolchain_match": "exact",
  "duration_ms": 312,
  "build_attempts": 1
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Bumped on any breaking change. Readers reject mismatches. |
| `nyx_version` | string | `CARGO_PKG_VERSION` of the writing binary. |
| `corpus_version` | string | Payload-corpus version the verdict was scored against. |
| `kind` | string | `"verdict"` (per-finding) or `"rank_delta"` (rank-score shift). |
| `ts` | RFC-3339 string | Wall-clock at write time. |
| `finding_id` | string | Stable finding identifier. |
| `spec_hash` | string | Hash of the `HarnessSpec` that drove the run. |
| `lang` | string | Language slug; `"unknown"` when spec derivation failed. |
| `cap` | string | Sink capability (e.g. `SQL_QUERY`, `CODE_EXEC`). |
| `status` | string | `Confirmed`, `NotConfirmed`, `Inconclusive`, or `Unsupported`. |
| `inconclusive_reason` | string | Present iff `status == Inconclusive`. |

A `rank_delta` record carries the envelope plus `finding_id`, `status`, and a
signed `delta` applied to the rank score.

### Schema-version mismatch

`scripts/m7_ship_gate.sh` Gate 2 walks every line of the log, requires
`schema_version == EXPECTED_SCHEMA_VERSION`, and exits 3 if any record fails
the check. Programmatic readers use
`crate::dynamic::telemetry::read_events(path)`, which surfaces the same
condition as `TelemetryReadError::SchemaMismatch { expected, found, .. }`.

When schema bumps land, the canonical migration is to roll the log over (move
or delete `events.jsonl`) so new and old records never coexist in a file. The
gate refuses to skip silently on mismatch.

### Sampling

`[telemetry]` in `nyx.toml` controls the on-disk sampling policy:

```toml
[telemetry]
keep_all_confirmed = true     # default: retain every Confirmed verdict
keep_all_inconclusive = true  # default: retain every Inconclusive verdict
sample_rate_other = 1.0       # 0.0–1.0 for NotConfirmed / Unsupported
```

`sample_rate_other < 1.0` downsamples NotConfirmed and Unsupported verdicts
deterministically — the decision is seeded by the finding's `spec_hash`, so a
given finding makes the same keep-or-drop call across reruns. Confirmed and
Inconclusive verdicts ignore the rate and are always retained (they gate the
false-Confirmed budget and drive the spec-derivation roadmap).

`NYX_NO_TELEMETRY=1` disables every write regardless of the policy.

## Opting in to feedback

False positives (nyx says `Confirmed` but you disagree) can be recorded:

```
nyx verify-feedback <finding_id> --wrong "reason"
```

This writes to the local telemetry log (`~/.cache/nyx/dynamic/events.jsonl`)
and contributes to precision monitoring. Feedback is never uploaded automatically.

## nyx serve integration

The browser UI shows `dynamic_verdict` in each finding's detail panel and
uses the verdict in ranking (Confirmed findings surface first). The scan compare
page has a **Verdict Diff** tab that shows which findings changed verification
status between two scans.

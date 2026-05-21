# Dynamic verification

Nyx re-runs findings in generated harnesses when verification is enabled. By
default, `nyx scan` verifies each `Confidence >= Medium` finding, tries
payloads in a sandbox, and writes the result to `evidence.dynamic_verdict`.
Default Nyx builds include the `dynamic` feature; custom
`--no-default-features` builds run static-only unless rebuilt with
`--features dynamic`.

Dynamic verification is a second signal, not a replacement for review. A
confirmed verdict means Nyx triggered the sink in its harness. `NotConfirmed`
means the harness ran but no payload fired.

## Running it

```bash
nyx scan                 # verifies Medium and High confidence findings
nyx scan --no-verify     # static analysis only
nyx scan --verify        # explicit form of the default behavior
```

Use `--no-verify` for fast local checks or editor workflows. Keep verification
on for CI when scan time allows it.

To verify low-confidence findings too:

```bash
nyx scan --verify-all-confidence
```

Use it when tuning payloads or investigating coverage. It is slower and noisier
than the default.

## Verdicts

| Status | Meaning |
| --- | --- |
| `Confirmed` | At least one payload reached the expected sink in the harness. |
| `NotConfirmed` | The harness ran, but no payload reached the sink. Treat the original finding as still open until reviewed. |
| `Inconclusive` | Nyx could not finish the check with enough isolation or runtime support. |
| `Unsupported` | Nyx did not try the finding. Common causes are unsupported language, unsupported sink shape, missing flow steps, or confidence below the verification threshold. |

## Configuration

To disable verification for a project, set:

```toml
[scanner]
verify = false
```

This makes scans static-only unless the command line overrides it.

The related scanner settings are:

| Setting | Default | Meaning |
| --- | --- | --- |
| `verify` | `true` | Run dynamic verification after static analysis. |
| `verify_all_confidence` | `false` | Include findings below `Confidence::Medium`. |
| `verify_backend` | `"auto"` | Use Docker when available, otherwise use the process backend. |
| `harden_profile` | `"standard"` | Hardening profile for the process backend. |

See [Configuration](configuration.md) for the full config table.

## Sandbox backends

```bash
nyx scan --backend docker    # require Docker
nyx scan --backend process   # run directly on the host with weaker isolation
nyx scan --unsafe-sandbox    # alias for --backend process
```

Docker is the preferred backend. It mounts only the entry file's directory and
blocks outbound network by default. If out-of-band detection is enabled with
`oob_listener`, Docker uses bridge networking with a host-gateway route so the
harness can reach the listener.

The process backend is useful for development and machines without Docker. It
does not provide the same isolation.

## Repro artifacts

Confirmed findings write a repro bundle under:

```text
~/.cache/nyx/dynamic/repro/<spec_hash>/
```

The bundle contains the harness spec, payload, expected output, trace, and
`reproduce.sh`.

```bash
cd ~/.cache/nyx/dynamic/repro/<spec_hash>
./reproduce.sh
./reproduce.sh --docker
```

Use the Docker form when the bundle records a pinned container image or when
host toolchains differ from the original run.

## Runtime cost

Verification adds harness build time and sandbox startup time for each verified
finding. For quick local checks, `--no-verify` is usually the right choice. For
CI or scheduled scans, keep verification enabled so confirmed findings rank
higher and not-confirmed findings carry the extra context.

## Event log

Nyx writes verdict events to:

```text
~/.cache/nyx/dynamic/events.jsonl
```

Each line is a JSON object with a versioned envelope:

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

| Field | Meaning |
| --- | --- |
| `schema_version` | Event schema version. Readers reject mismatches. |
| `nyx_version` | Version of the Nyx binary that wrote the event. |
| `corpus_version` | Payload corpus version used for the verdict. |
| `kind` | `verdict`, `rank_delta`, or `feedback`. |
| `ts` | Write time in RFC 3339 format. |
| `finding_id` | Stable finding identifier. |
| `spec_hash` | Hash of the harness spec. |
| `lang` | Language slug, or `unknown` when spec derivation failed. |
| `cap` | Sink capability, such as `SQL_QUERY` or `CODE_EXEC`. |
| `status` | `Confirmed`, `NotConfirmed`, `Inconclusive`, or `Unsupported`. |
| `inconclusive_reason` | Present when `status` is `Inconclusive`. |

If the schema changes, move or delete the old `events.jsonl` before reading it
with the new binary. Programmatic readers should use
`crate::dynamic::telemetry::read_events(path)`.

## Sampling

`[telemetry]` in `nyx.toml` controls event retention:

```toml
[telemetry]
keep_all_confirmed = true
keep_all_inconclusive = true
sample_rate_other = 1.0
```

`sample_rate_other` accepts `0.0` to `1.0` and applies to `NotConfirmed` and
`Unsupported` verdicts. The decision is deterministic for a given `spec_hash`.
Confirmed, Inconclusive, and rank-delta events are always kept by default.

Set `NYX_NO_TELEMETRY=1` to disable event writes.

## Feedback

To record a bad verdict:

```bash
nyx verify-feedback <finding_id> --wrong "reason"
```

Feedback is written to the local event log. Nyx does not upload it.

## Browser UI

`nyx serve` shows dynamic verdicts on finding detail pages, uses them in
ranking, and can compare verdict changes between saved scans.

See [Output formats](output.md) for the `dynamic_verdict` schema.

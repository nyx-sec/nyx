# Recall validation runbook

Phase 11 of the JS/TS recall-gap engine plan freezes a finding-shape
baseline against four real-world OSS targets so future recall work
can prove "actually lifts recall on real code", not just "tests pass".
This runbook covers re-running the validation against a fresh OSS
release.

## Targets

| Target            | Clone URL                                  | Recall items exercised |
|-------------------|--------------------------------------------|------------------------|
| `cal_com`         | https://github.com/calcom/cal.com          | 1, 5, 6, 7             |
| `vercel_commerce` | https://github.com/vercel/commerce         | 1, 4, 7                |
| `shadcn_examples` | https://github.com/shadcn-ui/ui            | 4, 7                   |
| `blitz_apps`      | https://github.com/blitz-js/blitz          | 1, 3, 6                |

Item numbering is from `.pitboss/RECALL_GAPS.md`.

## Files

| File                                          | Role                                    |
|-----------------------------------------------|-----------------------------------------|
| `scripts/validate_recall.sh`                  | runner (capture + diff modes)           |
| `tests/recall_targets/<target>.json`          | per-target baseline                     |
| `tests/recall_gaps.rs::validate_real_world_targets` | schema-validity test (`#[ignore]`)|
| `tests/recall_gaps_baseline.json`             | corpus regression baseline (Phase 01)   |

Baselines were relocated out of `.pitboss/` per the Phase 01
precedent: pitboss implementer agents are forbidden to write under
`.pitboss/`, so the baseline files live next to the harness instead.

## Baseline schema

```json
{
  "_doc": "...",
  "target": "cal_com",
  "clone_url": "https://github.com/calcom/cal.com",
  "exercises_recall_items": [1, 5, 6, 7],
  "captured_against": "real-scan @ <sha>",
  "captured_on": "YYYY-MM-DD",
  "pinned_commit": "<sha>",
  "findings": [
    {
      "rule_id": "taint-unsanitised-flow",
      "path_suffix": "packages/...",
      "line": 130,
      "severity": "High",
      "verdict": "TP" | "FP" | "needs_review",
      "note": "..."
    }
  ]
}
```

The diff key is `(rule_id, path_suffix, line)`. The `verdict` field
must be one of `TP`, `FP`, or `needs_review`; unknown verdicts are
rejected by the schema test.

## Usage

### Diff a fresh scan against the frozen baseline

```bash
scripts/validate_recall.sh cal_com /path/to/cal.com
```

Output is a JSON object `{ added, removed, unchanged, *_total }`
keyed by `rule_id`. Use this to spot intentional recall lift
(`added`) and regressions (`removed`).

### Refresh the baseline after an intentional recall lift

```bash
scripts/validate_recall.sh cal_com /path/to/cal.com --capture
```

This overwrites `tests/recall_targets/cal_com.json` with the current
scan output. Every finding is re-marked `verdict: "needs_review"`;
hand-label `TP`/`FP` afterwards as you triage.

### Schema-validity check

```bash
cargo test --release --test recall_gaps -- --ignored validate_real_world_targets
```

Loads each per-target JSON, asserts the required keys exist, and
asserts every finding carries a valid verdict label.

## Refresh procedure

1. Clone or pull the target repo into `~/oss/<target>` (or wherever).
2. Build nyx: `cargo build --release`.
3. Run the diff in plain mode to see what changed:
   `scripts/validate_recall.sh <target> ~/oss/<target>`.
4. If the lift is intentional, recapture:
   `scripts/validate_recall.sh <target> ~/oss/<target> --capture`.
5. Spot-check a handful of new findings — open the file at
   `path_suffix:line` and confirm the source-to-sink flow is real.
   Hand-label them `TP`/`FP`.
6. Commit the updated `tests/recall_targets/<target>.json`.

## Known captured baselines (2026-05-08)

| Target            | Pinned commit | Findings | TP | FP | needs_review |
|-------------------|---------------|----------|----|----|--------------|
| `cal_com`         | `d278d6c9`    | 662      | 0  | 4  | 658          |
| `vercel_commerce` | unknown       | 0 (placeholder) | — | — | — |
| `shadcn_examples` | unknown       | 0 (placeholder) | — | — | — |
| `blitz_apps`      | unknown       | 0 (placeholder) | — | — | — |

The `cal_com` capture used commit `d278d6c9bc535bf3f2c6ba0607654f78dd74d6ee`
(`refactor: remove dead insights references (#29029)`). The 4 `FP`
labels are `ts.crypto.math_random` hits inside `apps/web/playwright/`
test fixtures, which are not a security context.

The other three targets ship as placeholders (empty `findings`) —
nobody has cloned them locally yet. Run `validate_recall.sh
<target> <clone> --capture` to populate. The schema test still passes
because `[]` is a valid `findings` array with zero entries to check.

## Perf baseline

Phase 11 records the post-phase-11 scanner perf in
`tests/recall_targets/perf_after.txt`. Compare against the
`captured_against` snapshot in `tests/recall_gaps_baseline.json`
(`corpus_finding_lines.findings_total` = 1121, captured at master
`ea82ea98`). Phase 11's acceptance bar: scanner throughput on the
existing `tests/fixtures/` corpus must regress by ≤ 15%. Future
recall work uses the same corpus + the same record file to measure
its own perf delta.

## What lives where (quick reference)

- Targets list and recall-item mapping → this file.
- Per-target findings → `tests/recall_targets/<target>.json`.
- Diff/capture runner → `scripts/validate_recall.sh`.
- Schema-validity test → `tests/recall_gaps.rs`.
- Corpus regression baseline → `tests/recall_gaps_baseline.json`.
- Perf record → `tests/recall_targets/perf_after.txt`.

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
5. Spot-check a handful of new findings. Open the file at
   `path_suffix:line` and confirm the source-to-sink flow is real.
   Hand-label them `TP`/`FP`.
6. Commit the updated `tests/recall_targets/<target>.json`.

## Known captured baselines (2026-05-08)

| Target            | Pinned commit | Findings | TP | FP | needs_review |
|-------------------|---------------|----------|----|----|--------------|
| `cal_com`         | `d278d6c9`    | 662      | 0  | 4  | 658          |
| `vercel_commerce` | unknown       | 0 (placeholder) |    |    |              |
| `shadcn_examples` | unknown       | 0 (placeholder) |    |    |              |
| `blitz_apps`      | unknown       | 0 (placeholder) |    |    |              |

The `cal_com` capture used commit `d278d6c9bc535bf3f2c6ba0607654f78dd74d6ee`
(`refactor: remove dead insights references (#29029)`). The 4 `FP`
labels are `ts.crypto.math_random` hits inside `apps/web/playwright/`
test fixtures, which are not a security context.

The other three targets ship as placeholders (empty `findings`).
Nobody has cloned them locally yet. Run `validate_recall.sh
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

## Cross-language runbook (Phase 17)

Phase 11 covered JS-only targets. Phase 17 mirrors that work against
real-world non-JS targets so the cross-language phases (12–16) prove
"actually lifts recall on real code", not just "tests pass". Per-lang
baselines live under `tests/recall_targets/xlang/<lang>/<target>.json`
and the runner accepts a `--lang` flag to select the target set.

### Cross-language targets

| Lang   | Target       | Clone URL                                    | Pinned commit (capture) | Findings | Notes |
|--------|--------------|----------------------------------------------|-------------------------|----------|-------|
| php    | phpmyadmin   | https://github.com/phpmyadmin/phpmyadmin     | `ddf4e993`              | 119      | DBA UI; XSS / `php.deser` / `cfg-unguarded-sink` heavy. |
| php    | joomla       | https://github.com/joomla/joomla-cms         | `7e8527d0`              | 83       | CMS; `php.deser.unserialize` and `php.path.include_variable` clusters. |
| php    | drupal       | https://github.com/drupal/drupal             | `92aa759e`              | 635      | CMS / DI container; `cfg-unguarded-sink` (198) and `taint-prototype-pollution` (121) dominant. |
| php    | nextcloud    | https://github.com/nextcloud/server          | `5c0fe4c3`              | 262      | File-sync platform; `cfg-resource-leak` / `state-resource-leak` heavy. |
| java   | openmrs      | https://github.com/openmrs/openmrs-core      | `f9c76db2`              | 273      | Hibernate-heavy; JPA Criteria fix from `project_realrepo_openmrs.md` already applied. |
| python | airflow      | https://github.com/apache/airflow            | `3d42610a`              | 892      | Scheduler / DAG runner; `cfg-unguarded-sink` (252) and `taint-unsanitised-flow` (179) lead. |
| python | flask        | https://github.com/pallets/flask             | placeholder             | 0        | Smaller-surface Python framework; capture deferred. |
| go     | gin          | https://github.com/gin-gonic/gin             | `d3ffc998`              | 20       | HTTP framework test corpus; `taint-header-injection` and TLS skip-verify in tests. |
| rust   | axum         | https://github.com/tokio-rs/axum             | placeholder             | 0        | Not cloned in pitboss sandbox at capture time; populate locally. |
| ruby   | rails        | https://github.com/rails/rails               | placeholder             | 0        | Capture against the `actionpack/` subtree once cloned. |

Captures dated `2026-05-09` (UTC). Counts are deduplicated tuples
`(rule_id, path_suffix, line)`. Duplicate raw findings collapse on
the diff key, so the schema-test count and diff-mode `unchanged_total`
may differ from the `findings | length` total by a handful of
duplicate sites. The diff key is what matters for regression
detection.

### Per-lang TP/FP splits

Every captured finding ships with `verdict: "needs_review"` from
`--capture`. Hand-triage is bounded but pending; none of the Phase 17
captures are sweep-labelled yet. Use the per-lang dominant rule_id
clusters above as the priority queue:

- **PHP**: `cfg-unguarded-sink` and `taint-prototype-pollution` are
  the FP-dominant clusters across drupal / nextcloud / phpmyadmin
  (CMS routing + JS object construction). `php.deser.unserialize` is
  the highest-value TP cluster on joomla (17) and drupal (83). See
  `project_realrepo_joomla.md` 2026-05-03 for the magic-method
  passthrough fix that already filters one shape.
- **Java**: `taint-unsanitised-flow` (61) and `state-resource-leak`
  (60) are openmrs's leading clusters. The JPA Criteria-API fix
  already absorbed the `cfg-unguarded-sink` cluster (216 to 24);
  remaining Hibernate / Spring resource-management FPs are the next
  triage target.
- **Python**: `cfg-unguarded-sink` (252) on airflow is dominated by
  Airflow's scheduler / DB plumbing; `py.auth.token_override_*`
  (83) and `py.auth.missing_ownership_check` (61) are the auth-rule
  noise typical of an admin/operator codebase.
- **Go**: gin's 20 findings are mostly test-corpus artifacts
  (`gin_test.go`, `routes_test.go`); 4 of 4 `go.transport.insecure_skip_verify`
  hits are inside `gin*_test.go` and are legitimate test setup.
- **Rust / Ruby**: placeholder. Capture once a local clone exists.

### `--lang` runner usage

```bash
# diff mode (default)
scripts/validate_recall.sh --lang php drupal /Users/me/oss/drupal
scripts/validate_recall.sh --lang java openmrs /Users/me/oss/openmrs

# capture / refresh
scripts/validate_recall.sh --lang go gin /Users/me/oss/gin --capture
```

Output is the same `{ added, removed, unchanged, *_total }` JSON shape
as the JS-target diff. The diff key is `(rule_id, path_suffix, line)`.

### Cross-language refresh procedure

1. Clone or update the target into `~/oss/<target>` (or wherever).
2. Build nyx: `cargo build --release`.
3. Diff vs the frozen baseline:
   `scripts/validate_recall.sh --lang <lang> <target> ~/oss/<target>`.
4. If the lift is intentional, recapture with `--capture`.
5. Spot-check new findings; hand-label `TP`/`FP`.
6. Commit the updated `tests/recall_targets/xlang/<lang>/<target>.json`.

### Sandbox-capture caveat

Pitboss implementer agents run sandboxed without network egress, so
target repos that are not already present under `~/oss/` ship as
placeholders (`pinned_commit: "unknown"`, `findings: []`). Phase 17
shipped captures for php/java/python/go (every target whose repo was
already cloned locally) and placeholders for `rust/axum`, `ruby/rails`,
and `python/flask`. The schema test in `validate_real_world_targets`
passes against placeholders because `[]` is a valid `findings` array.

## What lives where (quick reference)

- Targets list and recall-item mapping → this file.
- Per-target JS findings → `tests/recall_targets/<target>.json`.
- Per-target cross-lang findings → `tests/recall_targets/xlang/<lang>/<target>.json`.
- Diff/capture runner → `scripts/validate_recall.sh` (accepts `--lang`).
- Schema-validity test → `tests/recall_gaps.rs::validate_real_world_targets`.
- Corpus regression baseline → `tests/recall_gaps_baseline.json`.
- Perf records → `tests/recall_targets/perf_after.txt` (Phase 11) and
  `tests/recall_targets/perf_after_xlang.txt` (Phase 17 delta).

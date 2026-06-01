# Ground truth files

Place corpus ground truth JSON files here before running `tests/eval_corpus/run.sh`.

## OWASP Benchmark v1.2

File: `owasp_benchmark_v1.2.json` (checked in; complete — one record per
BenchmarkTest file, 2740 total).

Format:
```json
[
  {"path": "src/main/java/org/owasp/.../BenchmarkTest00001.java", "line": 0, "cap": "sqli", "vuln": true},
  ...
]
```

`path` is **relative to the corpus root** (the BenchmarkJava clone), with POSIX
separators. `tabulate.py` suffix-matches it against the absolute paths nyx
emits, so the committed JSON is portable: it matches whether the corpus lives at
`~/.cache/nyx/eval_corpus/owasp_benchmark_v1.2` on a laptop or at a CI checkout
path. `line` is `0` (the expected-results CSV does not pin a line; matching
falls back to file+cap).

Regenerate from `expectedresults-1.2beta.csv` shipped with the benchmark repo:
```sh
python3 tests/eval_corpus/owasp_gt_convert.py \
    --corpus-dir ~/.cache/nyx/eval_corpus/owasp_benchmark_v1.2 \
    --output     tests/eval_corpus/ground_truth/owasp_benchmark_v1.2.json
```

## NIST SARD subset

File: `nist_sard.json`

Same format. Source: SARD manifest XML converted with `python3 tests/eval_corpus/sard_gt_convert.py`.

## OWASP NodeGoat / OWASP Juice Shop (JS/TS — Track R.1)

Files: `nodegoat.json` (Express, `.js`), `juiceshop.json` (TypeScript, `.ts`).
Same four-field format as above; all records are `vuln: true`.

These two apps are intentionally vulnerable end to end, so — unlike OWASP
Benchmark — they ship no machine-readable per-file vuln labels and have no
benign-control files to pair against. The authoritative source is a curated
TOML manifest committed here, one `[[entry]]` per known-vulnerable handler
with a `note` citing why:

- `nodegoat.manifest.toml`
- `juiceshop.manifest.toml`

`manifest_gt_convert.py` turns a manifest into the committed `.json`:

```sh
python3 tests/eval_corpus/manifest_gt_convert.py \
    --manifest tests/eval_corpus/ground_truth/nodegoat.manifest.toml \
    --output   tests/eval_corpus/ground_truth/nodegoat.json
```

Pass `--corpus-dir <clone>` to validate every labelled path against a real
checkout. The converter exits non-zero if any path is missing, so a corpus
bump that moves a handler fails loudly instead of silently dropping recall.
CI (`.github/workflows/eval.yml`, `jsts` job) regenerates each `.json`
against a fresh clone of the pinned ref and asserts it matches the committed
file.

Because the manifests label canonical vulns only, recall (did nyx catch the
known vulns) is the meaningful metric; precision vs this partial ground
truth is informational. Gate 7 publishes per-cap precision/recall/confirmed
report-only by default (`NYX_JSTS_FLOOR_CAPS` empty), matching the OWASP
gate.

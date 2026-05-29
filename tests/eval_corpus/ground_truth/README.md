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

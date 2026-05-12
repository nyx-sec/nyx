# Ground truth files

Place corpus ground truth JSON files here before running `tests/eval_corpus/run.sh`.

## OWASP Benchmark v1.2

File: `owasp_benchmark_v1.2.json`

Format:
```json
[
  {"path": "src/main/java/org/owasp/.../BenchmarkTest00001.java", "line": 42, "cap": "sqli", "vuln": true},
  ...
]
```

Source: generate from `expectedresults-1.2.csv` shipped with the benchmark repo using
`python3 tests/eval_corpus/owasp_gt_convert.py`.

## NIST SARD subset

File: `nist_sard.json`

Same format. Source: SARD manifest XML converted with `python3 tests/eval_corpus/sard_gt_convert.py`.

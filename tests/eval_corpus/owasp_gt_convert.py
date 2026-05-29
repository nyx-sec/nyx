#!/usr/bin/env python3
"""Convert OWASP Benchmark v1.2 expectedresults-*.csv into nyx ground-truth JSON.

Source: `expectedresults-1.2beta.csv` shipped in the BenchmarkJava repo.
Output: list of `{path, line, cap, vuln}` records, where:
  - `path` is the BenchmarkTest*.java path **relative to --corpus-dir**, with
    POSIX separators (e.g. `src/main/java/org/owasp/benchmark/testcode/
    BenchmarkTest00001.java`).  Relative paths keep the committed ground truth
    portable: `tabulate.py` suffix-matches them against the absolute paths nyx
    emits, so the same JSON works on the dev laptop and on CI regardless of
    where the corpus was cloned.
  - `line` is 0 (CSV does not pin a line; tabulate uses LINE_TOLERANCE on findings).
  - `cap` is a nyx cap label mapped from the OWASP category column.
  - `vuln` is True for `real vulnerability == true`, else False.

Usage:
  tests/eval_corpus/owasp_gt_convert.py \\
      --corpus-dir ~/.cache/nyx/eval_corpus/owasp_benchmark_v1.2 \\
      --output     tests/eval_corpus/ground_truth/owasp_benchmark_v1.2.json
"""

import argparse
import csv
import json
import sys
from pathlib import Path

OWASP_TO_NYX_CAP = {
    "cmdi":        "cmdi",
    "crypto":      "crypto",
    "hash":        "crypto",
    "ldapi":       "ldap_injection",
    "pathtraver":  "path_traversal",
    "securecookie": "auth",
    "sqli":        "sqli",
    "trustbound":  "xss",
    "weakrand":    "crypto",
    "xpathi":      "xpath_injection",
    "xss":         "xss",
}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--corpus-dir", required=True,
                   help="Path to BenchmarkJava clone root.")
    p.add_argument("--output", required=True,
                   help="Output ground-truth JSON path.")
    p.add_argument("--csv", default="",
                   help="Override CSV path (default: <corpus-dir>/expectedresults-1.2beta.csv).")
    args = p.parse_args()

    corpus = Path(args.corpus_dir).expanduser().resolve()
    csv_path = Path(args.csv) if args.csv else corpus / "expectedresults-1.2beta.csv"
    if not csv_path.exists():
        print(f"error: csv not found: {csv_path}", file=sys.stderr)
        return 1

    java_root = corpus / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    if not java_root.is_dir():
        print(f"error: java testcode dir not found: {java_root}", file=sys.stderr)
        return 1

    records: list[dict] = []
    skipped = 0
    with open(csv_path) as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) < 3:
                continue
            name, category, real_vuln = row[0].strip(), row[1].strip(), row[2].strip().lower()
            cap = OWASP_TO_NYX_CAP.get(category)
            if cap is None:
                skipped += 1
                continue
            java_file = java_root / f"{name}.java"
            if not java_file.exists():
                skipped += 1
                continue
            records.append({
                "path": java_file.relative_to(corpus).as_posix(),
                "line": 0,
                "cap":  cap,
                "vuln": real_vuln == "true",
            })

    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(records, f, indent=2)

    vuln_count = sum(1 for r in records if r["vuln"])
    print(f"wrote {len(records)} records to {out}")
    print(f"  vulns:    {vuln_count}")
    print(f"  non-vuln: {len(records) - vuln_count}")
    print(f"  skipped:  {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

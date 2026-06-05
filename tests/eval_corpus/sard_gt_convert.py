#!/usr/bin/env python3
"""Convert NIST SARD manifest XML into nyx ground-truth JSON.

SARD ships per-test-case `manifest.xml` files alongside source. Each
`<testcase>` lists one or more `<file path="…">` entries with optional
`<flaw line="…" name="CWE-XXX_…"/>` children.

Output schema (consumed by tabulate.py):
  list of {"path", "line", "cap", "vuln"} records.

Usage:
  tests/eval_corpus/sard_gt_convert.py \\
      --corpus-dir ~/.cache/nyx/eval_corpus/nist_sard \\
      --output     tests/eval_corpus/ground_truth/nist_sard.json
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CWE_TO_NYX_CAP = {
    "20":  "validation",
    "22":  "path_traversal",
    "78":  "cmdi",
    "79":  "xss",
    "89":  "sqli",
    "90":  "ldap_injection",
    "91":  "xpath_injection",
    "94":  "cmdi",
    "113": "header_injection",
    "117": "header_injection",
    "190": "memory",
    "200": "data_exfil",
    "287": "auth",
    "295": "crypto",
    "311": "crypto",
    "327": "crypto",
    "328": "crypto",
    "330": "crypto",
    "352": "auth",
    "434": "path_traversal",
    "476": "memory",
    "502": "deserialize",
    "601": "redirect",
    "611": "xxe",
    "643": "xpath_injection",
    "798": "crypto",
    "918": "ssrf",
}

CWE_RE = re.compile(r"CWE[-_](\d+)", re.IGNORECASE)


def cap_for_flaw(name: str) -> str | None:
    m = CWE_RE.search(name or "")
    if not m:
        return None
    return CWE_TO_NYX_CAP.get(m.group(1))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--corpus-dir", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    root = Path(args.corpus_dir).expanduser().resolve()
    if not root.is_dir():
        print(f"error: corpus dir not found: {root}", file=sys.stderr)
        return 1

    records: list[dict] = []
    skipped_files = 0
    skipped_caps = 0

    for manifest in root.rglob("manifest.xml"):
        try:
            tree = ET.parse(manifest)
        except ET.ParseError as e:
            print(f"warn: parse failed {manifest}: {e}", file=sys.stderr)
            continue
        for tc in tree.iter("testcase"):
            for fnode in tc.iter("file"):
                rel = fnode.get("path") or ""
                if not rel:
                    continue
                abs_path = (manifest.parent / rel).resolve()
                if not abs_path.exists():
                    skipped_files += 1
                    continue
                flaws = list(fnode.iter("flaw")) + list(fnode.iter("mixed"))
                if not flaws:
                    records.append({
                        "path": str(abs_path),
                        "line": 0,
                        "cap":  "other",
                        "vuln": False,
                    })
                    continue
                for flaw in flaws:
                    cap = cap_for_flaw(flaw.get("name", ""))
                    if cap is None:
                        skipped_caps += 1
                        continue
                    try:
                        line = int(flaw.get("line", "0") or 0)
                    except ValueError:
                        line = 0
                    records.append({
                        "path": str(abs_path),
                        "line": line,
                        "cap":  cap,
                        "vuln": True,
                    })

    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(records, f, indent=2)

    vuln_count = sum(1 for r in records if r["vuln"])
    print(f"wrote {len(records)} records to {out}")
    print(f"  vulns:           {vuln_count}")
    print(f"  non-vuln:        {len(records) - vuln_count}")
    print(f"  skipped (file):  {skipped_files}")
    print(f"  skipped (cap):   {skipped_caps}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Convert a curated TOML vuln manifest into nyx ground-truth JSON.

Used for real-world apps that ship **no** machine-readable per-file vuln
labels of their own (OWASP NodeGoat, OWASP Juice Shop).  OWASP Benchmark
ships `expectedresults-1.2beta.csv` (see owasp_gt_convert.py); NIST SARD
ships `manifest.xml` (see sard_gt_convert.py).  NodeGoat / Juice Shop are
intentionally-vulnerable apps without an equivalent, so the authoritative
source here is a curated manifest committed *in this repo* — one
`[[entry]]` table per known-vulnerable location, each carrying a
provenance `note` so a reviewer can trace why the label is what it is.

Manifest schema (TOML)::

    # provenance comments at the top
    corpus = "nodegoat"          # informational label
    upstream = "https://github.com/OWASP/NodeGoat"
    pinned_ref = "master@<sha>"  # the ref the paths were curated against

    [[entry]]
    path = "app/routes/contributions.js"   # relative to the corpus root, POSIX
    cap  = "cmdi"                           # a nyx cap label (tabulate.py)
    vuln = true                             # true = real vuln, false = benign control
    note = "eval() of user-supplied pre/after-tax fields (NodeGoat A1)"

Negative-control corpora.  A few real corpora carry **no** scannable
source-level vulnerabilities of their own — most notably the RustSec
`advisory-db`, which ships advisory *metadata* (TOML/Markdown), not
vulnerable `.rs` source.  Such a corpus has zero ground-truth positives by
construction, yet it is still worth scanning: it exercises the language's
scan + verify path end to end on a large real-world tree and acts as an
over-confirmation guard (nyx must Confirm nothing on a corpus with no real
source vulns).  Declare it with a top-level ``negative_control = true`` and
**zero** ``[[entry]]`` tables; the converter then emits an empty ``[]``
ground truth.  ``negative_control`` and ``[[entry]]`` are mutually
exclusive — a manifest that sets the flag *and* lists entries is rejected,
so a real vuln can never be silently dropped behind the flag.

Output (consumed by tabulate.py): a list of `{path, line, cap, vuln}`
records, sorted by `(path, cap)` for deterministic, diff-stable JSON.
`note` is intentionally dropped — the ground-truth JSON keeps the exact
same four-field schema OWASP/SARD produce, so tabulate.py needs no special
casing.  `line` is always 0 (the manifest pins a file, not a line;
tabulate.py matches file+cap and treats line 0 as "any line").

Path validation (the no-compromise guard).  When `--corpus-dir` is given,
**every** manifest path must resolve to a real file under that root or the
converter exits non-zero.  CI runs the converter against a fresh clone of
the pinned corpus and then asserts the committed JSON byte-matches the
regenerated JSON, so a corpus bump that moves/renames/deletes a labelled
file (or a typo'd path) fails the build loudly instead of silently
degrading recall.  Authoring the committed JSON offline (no corpus on
hand) is done by omitting `--corpus-dir`: the transform is identical, only
the existence check is skipped.

Usage::

    # author / regenerate the committed JSON offline (no validation):
    tests/eval_corpus/manifest_gt_convert.py \\
        --manifest tests/eval_corpus/ground_truth/nodegoat.manifest.toml \\
        --output   tests/eval_corpus/ground_truth/nodegoat.json

    # CI: validate every path against a real checkout, then diff vs committed:
    tests/eval_corpus/manifest_gt_convert.py \\
        --manifest tests/eval_corpus/ground_truth/nodegoat.manifest.toml \\
        --corpus-dir ~/.cache/nyx/eval_corpus/nodegoat \\
        --output   /tmp/nodegoat_regen.json
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover — older interpreters only
    import tomli as tomllib  # type: ignore[no-redef]

# nyx cap labels (see tabulate.py _CAP_BIT_TABLE / _CAP_RULE_TABLE).  A
# manifest cap outside this set is almost always a typo, so reject it at
# conversion time rather than letting a never-matching cap silently sink
# recall.
VALID_CAPS = {
    "path_traversal",
    "fmt_string",
    "sqli",
    "deserialize",
    "ssrf",
    "cmdi",
    "crypto",
    "unauthorized_id",
    "data_exfil",
    "ldap_injection",
    "xpath_injection",
    "header_injection",
    "redirect",
    "xss",
    "xxe",
    "prototype_pollution",
    "auth",
    "memory",
    "validation",
}


def load_manifest(path: Path) -> dict:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        print(f"error: manifest not found: {path}", file=sys.stderr)
        raise SystemExit(1)
    except tomllib.TOMLDecodeError as e:
        print(f"error: manifest malformed: {path}: {e}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True, help="curated TOML manifest path")
    p.add_argument("--output", required=True, help="output ground-truth JSON path")
    p.add_argument(
        "--corpus-dir",
        default="",
        help=(
            "when set, every manifest path must resolve to a real file under "
            "this root or the converter exits 2 (the CI corpus-drift guard)"
        ),
    )
    args = p.parse_args()

    manifest = load_manifest(Path(args.manifest).expanduser())
    entries = manifest.get("entry", []) or []
    negative_control = bool(manifest.get("negative_control", False))
    if negative_control and entries:
        print(
            f"error: negative_control manifest must declare zero [[entry]] "
            f"tables (found {len(entries)}): {args.manifest}",
            file=sys.stderr,
        )
        return 1
    if not entries and not negative_control:
        print(f"error: manifest has no [[entry]] tables: {args.manifest}", file=sys.stderr)
        return 1

    corpus = Path(args.corpus_dir).expanduser().resolve() if args.corpus_dir else None
    if args.corpus_dir and (corpus is None or not corpus.is_dir()):
        print(f"error: corpus dir not found: {args.corpus_dir}", file=sys.stderr)
        return 1

    records: list[dict] = []
    missing: list[str] = []
    seen: set[tuple[str, str]] = set()
    for i, e in enumerate(entries):
        path = e.get("path")
        cap = e.get("cap")
        vuln = e.get("vuln")
        if not path or not cap or not isinstance(vuln, bool):
            print(
                f"error: entry #{i} needs string path, string cap, bool vuln: {e!r}",
                file=sys.stderr,
            )
            return 1
        if cap not in VALID_CAPS:
            print(
                f"error: entry #{i} cap {cap!r} is not a known nyx cap "
                f"(path {path!r}); fix the manifest",
                file=sys.stderr,
            )
            return 1
        norm = path.replace("\\", "/")
        key = (norm, cap)
        if key in seen:
            print(
                f"error: duplicate (path, cap) entry: {norm!r} / {cap!r}",
                file=sys.stderr,
            )
            return 1
        seen.add(key)
        if corpus is not None and not (corpus / norm).is_file():
            missing.append(norm)
        records.append({"path": norm, "line": 0, "cap": cap, "vuln": vuln})

    if missing:
        print(
            f"error: {len(missing)} manifest path(s) absent from {corpus} "
            f"(corpus drift or typo) — regenerate the manifest against the "
            f"pinned ref:",
            file=sys.stderr,
        )
        for m in missing:
            print(f"  missing: {m}", file=sys.stderr)
        return 2

    # Deterministic order so the committed JSON is diff-stable and the CI
    # byte-equality guard is meaningful regardless of manifest ordering.
    records.sort(key=lambda r: (r["path"], r["cap"]))

    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")

    vuln_count = sum(1 for r in records if r["vuln"])
    print(f"wrote {len(records)} records to {out}")
    if negative_control:
        print("  negative-control corpus: zero ground-truth positives by construction")
    print(f"  vulns:    {vuln_count}")
    print(f"  non-vuln: {len(records) - vuln_count}")
    if corpus is not None:
        print(f"  validated against: {corpus}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

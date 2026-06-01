#!/usr/bin/env python3
"""
Phase 28 (Track R.1) regression test for tests/eval_corpus/manifest_gt_convert.py.

Proves the manifest -> ground-truth converter is non-vacuous:
  * a well-formed manifest converts to the expected sorted JSON,
  * --corpus-dir validation passes when every labelled path exists and
    produces byte-identical output to the no-corpus transform (so the CI
    in-sync guard, which diffs committed vs a validated regen, is sound),
  * --corpus-dir validation HARD-ERRORS (exit 2) on a missing path,
  * an unknown cap / duplicate (path,cap) / malformed TOML are rejected,
  * the committed nodegoat.json / juiceshop.json are exactly what a fresh
    conversion of their manifests produces (offline half of the CI guard).

Run with::

    python3 tests/eval_corpus/test_manifest_gt_convert.py

Exits 0 when every assertion holds, non-zero otherwise.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONVERT = REPO / "tests/eval_corpus/manifest_gt_convert.py"
GT_DIR = REPO / "tests/eval_corpus/ground_truth"

GOOD_MANIFEST = """\
corpus = "demo"
upstream = "https://example.test/demo"
pinned_ref = "v1"

[[entry]]
path = "routes/login.ts"
cap = "sqli"
vuln = true
note = "raw SQL string-concat in login"

[[entry]]
path = "app/routes/contributions.js"
cap = "cmdi"
vuln = true
note = "eval of user input"

[[entry]]
path = "lib/insecurity.ts"
cap = "crypto"
vuln = false
note = "benign control example"
"""


def run_convert(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CONVERT), *args], capture_output=True, text=True
    )


def test_transform_is_sorted_and_schema_clean(tmp: Path) -> None:
    man = tmp / "demo.manifest.toml"
    man.write_text(GOOD_MANIFEST)
    out = tmp / "demo.json"
    proc = run_convert("--manifest", str(man), "--output", str(out))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    records = json.loads(out.read_text())
    # Sorted by (path, cap); only the 4 GT fields; `note` dropped.
    assert [r["path"] for r in records] == [
        "app/routes/contributions.js",
        "lib/insecurity.ts",
        "routes/login.ts",
    ], records
    for r in records:
        assert set(r) == {"path", "line", "cap", "vuln"}, r
        assert r["line"] == 0, r
    assert records[0]["cap"] == "cmdi" and records[0]["vuln"] is True
    assert records[1]["cap"] == "crypto" and records[1]["vuln"] is False


def test_corpus_validation_passes_and_matches_no_corpus(tmp: Path) -> None:
    man = tmp / "demo.manifest.toml"
    man.write_text(GOOD_MANIFEST)
    # Build a corpus tree containing every labelled path.
    corpus = tmp / "corpus"
    for rel in ("routes/login.ts", "app/routes/contributions.js", "lib/insecurity.ts"):
        f = corpus / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("// stub\n")
    no_corpus = tmp / "no_corpus.json"
    with_corpus = tmp / "with_corpus.json"
    assert run_convert("--manifest", str(man), "--output", str(no_corpus)).returncode == 0
    proc = run_convert(
        "--manifest", str(man),
        "--corpus-dir", str(corpus),
        "--output", str(with_corpus),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Validation must not change the output — that is what makes the CI guard
    # (diff committed vs validated regen) meaningful.
    assert no_corpus.read_text() == with_corpus.read_text()
    assert "validated against" in proc.stdout, proc.stdout


def test_missing_path_exits_2(tmp: Path) -> None:
    man = tmp / "demo.manifest.toml"
    man.write_text(GOOD_MANIFEST)
    corpus = tmp / "corpus"
    # Only two of the three labelled files exist → the third must trip.
    for rel in ("routes/login.ts", "app/routes/contributions.js"):
        f = corpus / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("// stub\n")
    out = tmp / "demo.json"
    proc = run_convert(
        "--manifest", str(man), "--corpus-dir", str(corpus), "--output", str(out)
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "lib/insecurity.ts" in proc.stderr and "missing" in proc.stderr, proc.stderr


def test_unknown_cap_rejected(tmp: Path) -> None:
    man = tmp / "bad_cap.manifest.toml"
    man.write_text(
        '[[entry]]\npath = "a.js"\ncap = "not_a_cap"\nvuln = true\n'
    )
    out = tmp / "out.json"
    proc = run_convert("--manifest", str(man), "--output", str(out))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not a known nyx cap" in proc.stderr, proc.stderr


def test_duplicate_path_cap_rejected(tmp: Path) -> None:
    man = tmp / "dup.manifest.toml"
    man.write_text(
        '[[entry]]\npath = "a.js"\ncap = "xss"\nvuln = true\n'
        '[[entry]]\npath = "a.js"\ncap = "xss"\nvuln = true\n'
    )
    out = tmp / "out.json"
    proc = run_convert("--manifest", str(man), "--output", str(out))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "duplicate" in proc.stderr, proc.stderr


def test_malformed_manifest_exits_1(tmp: Path) -> None:
    man = tmp / "broken.toml"
    man.write_text("[[entry]\npath = \n")  # invalid TOML
    out = tmp / "out.json"
    proc = run_convert("--manifest", str(man), "--output", str(out))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "malformed" in proc.stderr, proc.stderr


def test_empty_manifest_exits_1(tmp: Path) -> None:
    man = tmp / "empty.toml"
    man.write_text('corpus = "x"\n')  # no [[entry]] tables
    out = tmp / "out.json"
    proc = run_convert("--manifest", str(man), "--output", str(out))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "no [[entry]]" in proc.stderr, proc.stderr


def test_committed_gt_matches_manifest(tmp: Path) -> None:
    # Offline half of the CI in-sync guard: the committed ground-truth JSON
    # must be exactly what a fresh conversion of its manifest produces.  This
    # catches a manifest edit that was not followed by a regenerate.
    for name in ("nodegoat", "juiceshop"):
        man = GT_DIR / f"{name}.manifest.toml"
        committed = GT_DIR / f"{name}.json"
        assert man.exists(), f"missing manifest: {man}"
        assert committed.exists(), f"missing committed GT: {committed}"
        regen = tmp / f"{name}.json"
        proc = run_convert("--manifest", str(man), "--output", str(regen))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert json.loads(regen.read_text()) == json.loads(committed.read_text()), (
            f"{committed} is stale — regenerate with manifest_gt_convert.py"
        )


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for fn in (
            test_transform_is_sorted_and_schema_clean,
            test_corpus_validation_passes_and_matches_no_corpus,
            test_missing_path_exits_2,
            test_unknown_cap_rejected,
            test_duplicate_path_cap_rejected,
            test_malformed_manifest_exits_1,
            test_empty_manifest_exits_1,
            test_committed_gt_matches_manifest,
        ):
            sub = tmp / fn.__name__
            sub.mkdir()
            print(f"... {fn.__name__}")
            fn(sub)
            print("    OK")
    print("\nAll manifest_gt_convert.py regression checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

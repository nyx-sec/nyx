#!/usr/bin/env python3
# Usage: python3 scripts/check_corpus_sync.py
# Run from repo root or any subdirectory; the script relocates to repo root.
# Exits 0 if src/dynamic/corpus.rs and scripts/corpus_dashboard.py agree on
# CORPUS_VERSION and all payload labels.  Exits 1 on any divergence.

import os
import re
import sys
from pathlib import Path

# ── locate repo root (parent of the scripts/ dir this file lives in) ─────────

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
os.chdir(REPO_ROOT)

CORPUS_RS = REPO_ROOT / "src" / "dynamic" / "corpus.rs"
DASHBOARD_PY = REPO_ROOT / "scripts" / "corpus_dashboard.py"

# ── parse helpers ─────────────────────────────────────────────────────────────

def parse_corpus_rs(path: Path):
    text = path.read_text(encoding="utf-8")
    version_match = re.search(r'pub const CORPUS_VERSION:\s*u32\s*=\s*(\d+);', text)
    version = int(version_match.group(1)) if version_match else None
    labels = set(re.findall(r'label:\s*"([^"]+)"', text))
    return version, labels

def parse_dashboard_py(path: Path):
    text = path.read_text(encoding="utf-8")
    version_match = re.search(r'CORPUS_VERSION\s*=\s*(\d+)', text)
    version = int(version_match.group(1)) if version_match else None
    labels = set(re.findall(r'label="([^"]+)"', text))
    return version, labels

# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    rs_version, rs_labels = parse_corpus_rs(CORPUS_RS)
    py_version, py_labels = parse_dashboard_py(DASHBOARD_PY)

    ok = True

    # version check
    if rs_version is None:
        print("ERROR: CORPUS_VERSION not found in corpus.rs")
        ok = False
    if py_version is None:
        print("ERROR: CORPUS_VERSION not found in corpus_dashboard.py")
        ok = False
    if rs_version is not None and py_version is not None:
        if rs_version == py_version:
            print(f"CORPUS_VERSION: {rs_version}  [match]")
        else:
            print(f"CORPUS_VERSION mismatch: corpus.rs={rs_version}  corpus_dashboard.py={py_version}")
            ok = False

    # label check
    only_in_rs = rs_labels - py_labels
    only_in_py = py_labels - rs_labels
    shared = rs_labels & py_labels

    print(f"Labels in both:              {len(shared)}")
    if only_in_rs:
        print(f"Labels only in corpus.rs:    {len(only_in_rs)}")
        for lbl in sorted(only_in_rs):
            print(f"  + {lbl}")
        ok = False
    if only_in_py:
        print(f"Labels only in corpus_dashboard.py: {len(only_in_py)}")
        for lbl in sorted(only_in_py):
            print(f"  - {lbl}")
        ok = False

    if ok:
        print("Corpus sync: OK")
        return 0
    else:
        print("Corpus sync: FAIL — update corpus_dashboard.py to match corpus.rs")
        return 1

if __name__ == "__main__":
    sys.exit(main())

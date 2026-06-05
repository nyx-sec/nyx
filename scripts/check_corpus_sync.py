#!/usr/bin/env python3
# Usage: python3 scripts/check_corpus_sync.py
# Run from repo root or any subdirectory; the script relocates to repo root.
# Exits 0 if scripts/corpus_dashboard.py reads the same CORPUS_VERSION and
# payload identities as the canonical Rust registry.

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
os.chdir(REPO_ROOT)

sys.path.insert(0, str(SCRIPT_DIR))
import corpus_dashboard  # noqa: E402

CORPUS_RS = REPO_ROOT / "src" / "dynamic" / "corpus.rs"
CORPUS_DIR = REPO_ROOT / "src" / "dynamic" / "corpus"


def parse_corpus_rs_version(path: Path) -> int | None:
    text = path.read_text(encoding="utf-8")
    version_match = re.search(r"pub const CORPUS_VERSION:\s*u32\s*=\s*(\d+);", text)
    return int(version_match.group(1)) if version_match else None


def payload_identities(payloads: list[corpus_dashboard.PayloadEntry]) -> set[tuple[str, str, str]]:
    return {(p.cap, p.lang, p.label) for p in payloads}


def count_raw_payload_blocks(path: Path = CORPUS_DIR) -> int:
    count = 0
    for source in path.rglob("*.rs"):
        if source.name in {"audit.rs", "mod.rs", "registry.rs"}:
            continue
        text = source.read_text(encoding="utf-8")
        count += len(re.findall(r"\bCuratedPayload\s*\{", text))
    return count


def fmt_identity(identity: tuple[str, str, str]) -> str:
    cap, lang, label = identity
    return f"{cap}/{lang}/{label}"


def main() -> int:
    rs_version = parse_corpus_rs_version(CORPUS_RS)
    dashboard_version = corpus_dashboard.CORPUS_VERSION
    registry_payloads = corpus_dashboard.load_payloads()
    raw_payload_count = count_raw_payload_blocks()

    ok = True

    if rs_version is None:
        print("ERROR: CORPUS_VERSION not found in corpus.rs")
        ok = False
    elif rs_version == dashboard_version:
        print(f"CORPUS_VERSION: {rs_version}  [match]")
    else:
        print(
            "CORPUS_VERSION mismatch: "
            f"corpus.rs={rs_version}  corpus_dashboard.py={dashboard_version}"
        )
        ok = False

    registry_ids = payload_identities(registry_payloads)
    dashboard_ids = payload_identities(corpus_dashboard.PAYLOADS)
    only_in_registry = registry_ids - dashboard_ids
    only_in_dashboard = dashboard_ids - registry_ids
    shared = registry_ids & dashboard_ids

    print(f"Payload identities in both:              {len(shared)}")
    if only_in_registry:
        print(f"Payload identities only in Rust registry: {len(only_in_registry)}")
        for identity in sorted(only_in_registry):
            print(f"  + {fmt_identity(identity)}")
        ok = False
    if only_in_dashboard:
        print(f"Payload identities only in dashboard:    {len(only_in_dashboard)}")
        for identity in sorted(only_in_dashboard):
            print(f"  - {fmt_identity(identity)}")
        ok = False

    if len(corpus_dashboard.PAYLOADS) == raw_payload_count:
        print(f"CuratedPayload blocks covered:           {raw_payload_count}  [match]")
    else:
        print(
            "CuratedPayload block count mismatch: "
            f"source_tree={raw_payload_count}  dashboard={len(corpus_dashboard.PAYLOADS)}"
        )
        ok = False

    if ok:
        print("Corpus sync: OK")
        return 0

    print("Corpus sync: FAIL - update corpus_dashboard.py to match the Rust registry")
    return 1


if __name__ == "__main__":
    sys.exit(main())

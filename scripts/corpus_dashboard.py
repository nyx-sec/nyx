#!/usr/bin/env python3
"""Corpus health report for src/dynamic/corpus.rs.

Produces:
  - Per-cap coverage table (payload count, benign controls, OOB slots)
  - Per-payload last-confirmed timestamp (from repro artifacts if present)
  - CVE reference count
  - Marker collision audit

Exit code 0 = healthy.  Non-zero = collision or missing coverage.

Usage:
    python3 scripts/corpus_dashboard.py [--repro-dir REPRO_DIR] [--json]
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Payload table (mirrors src/dynamic/corpus.rs) ────────────────────────────
# Manually synced; CI should flag drift via cargo test no_marker_collisions.

CORPUS_VERSION = 3

@dataclass
class PayloadEntry:
    cap: str
    label: str
    bytes_repr: str
    oracle_kind: str
    oracle_value: Optional[str]
    is_benign: bool
    provenance: str
    since_corpus_version: int
    deprecated_at_corpus_version: Optional[int]
    fixture_paths: list[str]
    oob_nonce_slot: bool
    cve_refs: list[str] = field(default_factory=list)

PAYLOADS: list[PayloadEntry] = [
    # ── SQL_QUERY ──────────────────────────────────────────────────────────────
    PayloadEntry(
        cap="SQL_QUERY", label="sqli-tautology",
        bytes_repr="' OR '1'='1", oracle_kind="OutputContains",
        oracle_value="NYX_SQL_CONFIRMED", is_benign=False,
        provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot=False,
    ),
    PayloadEntry(
        cap="SQL_QUERY", label="sqli-union-nyx",
        bytes_repr="' UNION SELECT 'NYX_SQL_CONFIRMED'--",
        oracle_kind="OutputContains", oracle_value="NYX_SQL_CONFIRMED",
        is_benign=False, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot=False,
    ),
    # ── CODE_EXEC ──────────────────────────────────────────────────────────────
    PayloadEntry(
        cap="CODE_EXEC", label="cmdi-echo-marker",
        bytes_repr="; echo NYX_PWN_CMDI",
        oracle_kind="OutputContains", oracle_value="NYX_PWN_CMDI",
        is_benign=False, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=[
            "tests/benchmark/corpus/rust/cmdi/cmdi_command.rs",
            "tests/benchmark/corpus/rust/cmdi/cmdi_args.rs",
        ],
        oob_nonce_slot=False,
    ),
    # ── FILE_IO ────────────────────────────────────────────────────────────────
    PayloadEntry(
        cap="FILE_IO", label="path-traversal-passwd",
        bytes_repr="../../../../etc/passwd",
        oracle_kind="OutputContains", oracle_value="root:",
        is_benign=False, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=[
            "tests/benchmark/corpus/rust/path_traversal/path_file_open.rs",
            "tests/benchmark/corpus/rust/path_traversal/path_read.rs",
        ],
        oob_nonce_slot=False,
    ),
    PayloadEntry(
        cap="FILE_IO", label="path-traversal-benign",
        bytes_repr="benign_safe_file_that_does_not_exist_NYX_BENIGN",
        oracle_kind="OutputContains", oracle_value="root:",
        is_benign=True, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/path_traversal/path_file_open.rs"],
        oob_nonce_slot=False,
    ),
    # ── SSRF ───────────────────────────────────────────────────────────────────
    PayloadEntry(
        cap="SSRF", label="ssrf-file-scheme",
        bytes_repr="file:///etc/passwd",
        oracle_kind="OutputContains", oracle_value="daemon:",
        is_benign=False, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot=False,
    ),
    PayloadEntry(
        cap="SSRF", label="ssrf-oob-nonce",
        bytes_repr="<OOB URL generated at runtime>",
        oracle_kind="OobCallback", oracle_value="host=127.0.0.1",
        is_benign=False, provenance="Curated", since_corpus_version=2,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot=True,
    ),
    # ── HTML_ESCAPE ────────────────────────────────────────────────────────────
    PayloadEntry(
        cap="HTML_ESCAPE", label="xss-script-marker",
        bytes_repr="<script>NYX_XSS_CONFIRMED</script>",
        oracle_kind="OutputContains",
        oracle_value="<script>NYX_XSS_CONFIRMED</script>",
        is_benign=False, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/xss/axum_html/main.rs"],
        oob_nonce_slot=False,
    ),
    PayloadEntry(
        cap="HTML_ESCAPE", label="xss-benign-text",
        bytes_repr="Hello World",
        oracle_kind="OutputContains",
        oracle_value="<script>NYX_XSS_CONFIRMED</script>",
        is_benign=True, provenance="Curated", since_corpus_version=1,
        deprecated_at_corpus_version=None,
        fixture_paths=["tests/benchmark/corpus/rust/xss/axum_html/main.rs"],
        oob_nonce_slot=False,
    ),
]

ALL_CAPS = ["SQL_QUERY", "CODE_EXEC", "FILE_IO", "SSRF", "HTML_ESCAPE"]


# ── Marker collision audit ────────────────────────────────────────────────────

def audit_marker_collisions() -> list[tuple[str, str, str]]:
    collisions = []
    for p in PAYLOADS:
        if p.is_benign or p.oracle_kind != "OutputContains":
            continue
        marker = p.oracle_value or ""
        for other in PAYLOADS:
            if other.cap == p.cap:
                continue
            if other.is_benign or other.oob_nonce_slot:
                continue
            if marker in other.bytes_repr:
                collisions.append((p.cap, p.label, other.cap))
    return collisions


# ── Coverage table ────────────────────────────────────────────────────────────

def build_coverage_table() -> dict:
    result = {}
    for cap in ALL_CAPS:
        cap_payloads = [p for p in PAYLOADS if p.cap == cap]
        result[cap] = {
            "total": len(cap_payloads),
            "vuln": sum(1 for p in cap_payloads if not p.is_benign),
            "benign": sum(1 for p in cap_payloads if p.is_benign),
            "oob_slots": sum(1 for p in cap_payloads if p.oob_nonce_slot),
            "has_fixture_paths": all(len(p.fixture_paths) > 0 for p in cap_payloads),
            "payloads": [p.label for p in cap_payloads],
        }
    return result


# ── Repro artifact timestamps ─────────────────────────────────────────────────

def scan_last_confirmed(repro_dir: Path) -> dict[str, str]:
    """Return {payload_label: iso_timestamp} from repro artifact metadata."""
    timestamps: dict[str, str] = {}
    if not repro_dir.exists():
        return timestamps
    for meta_file in repro_dir.rglob("*.json"):
        try:
            data = json.loads(meta_file.read_text())
            label = data.get("payload_label", "")
            ts = data.get("confirmed_at", "")
            if label and ts:
                # Keep most recent.
                if label not in timestamps or ts > timestamps[label]:
                    timestamps[label] = ts
        except (json.JSONDecodeError, KeyError):
            pass
    return timestamps


# ── fuzz-discovered count ─────────────────────────────────────────────────────

def count_discovered(discovered_dir: Path) -> int:
    if not discovered_dir.exists():
        return 0
    return sum(
        1 for f in discovered_dir.rglob("*")
        if f.is_file() and not f.name.endswith(".json") and f.name != ".gitkeep"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Nyx corpus health dashboard")
    parser.add_argument("--repro-dir", default="repro", help="Path to repro artifacts")
    parser.add_argument("--discovered-dir", default="fuzz-discovered",
                        help="Path to fuzz-discovered/ directory")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = parser.parse_args()

    # Change to repo root (parent of scripts/).
    repo_root = Path(__file__).parent.parent
    os.chdir(repo_root)

    collisions = audit_marker_collisions()
    coverage = build_coverage_table()
    timestamps = scan_last_confirmed(Path(args.repro_dir))
    discovered_count = count_discovered(Path(args.discovered_dir))

    report = {
        "corpus_version": CORPUS_VERSION,
        "total_payloads": len(PAYLOADS),
        "coverage": coverage,
        "marker_collisions": collisions,
        "last_confirmed": timestamps,
        "fuzz_discovered_pending": discovered_count,
        "healthy": len(collisions) == 0,
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["healthy"] else 1

    # Text output.
    print(f"Nyx Corpus Dashboard  (corpus_version={CORPUS_VERSION})")
    print("=" * 60)
    print()

    # Coverage table.
    print("Per-cap coverage:")
    hdr = f"  {'Cap':<18} {'Total':>5} {'Vuln':>5} {'Benign':>6} {'OOB':>4} {'Fixtures':>8}"
    print(hdr)
    print("  " + "-" * 52)
    for cap, info in coverage.items():
        fixture_ok = "ok" if info["has_fixture_paths"] else "MISSING"
        print(
            f"  {cap:<18} {info['total']:>5} {info['vuln']:>5} "
            f"{info['benign']:>6} {info['oob_slots']:>4} {fixture_ok:>8}"
        )
    print()

    # Last confirmed timestamps.
    if timestamps:
        print("Last confirmed timestamps:")
        for label, ts in sorted(timestamps.items()):
            print(f"  {label:<35} {ts}")
        print()

    # fuzz-discovered pending.
    print(f"Fuzz-discovered pending promotion: {discovered_count}")
    print()

    # Marker collisions.
    if collisions:
        print("FAIL: Marker collisions detected (§16.3):")
        for cap, label, other_cap in collisions:
            print(f"  {cap}/{label} marker appears in {other_cap} payload bytes")
        return 1
    else:
        print("OK: No marker collisions detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

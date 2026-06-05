#!/usr/bin/env python3
"""Corpus health report for the Rust dynamic payload registry.

Produces:
  - Per-cap coverage table (payload count, benign controls, OOB slots)
  - Per-payload last-confirmed timestamp (from repro artifacts if present)
  - CVE reference count
  - Marker collision audit

Exit code 0 = healthy. Non-zero = collision or missing coverage.

Usage:
    python3 scripts/corpus_dashboard.py [--repro-dir REPRO_DIR] [--json]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CORPUS_RS = REPO_ROOT / "src" / "dynamic" / "corpus.rs"
CORPUS_DIR = REPO_ROOT / "src" / "dynamic" / "corpus"
REGISTRY_RS = CORPUS_DIR / "registry.rs"


@dataclass(frozen=True)
class RegistryEntry:
    cap: str
    lang: str
    module_path: str
    source_path: Path


@dataclass
class PayloadEntry:
    cap: str
    lang: str
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
    source_path: str
    cve_refs: list[str] = field(default_factory=list)


# Rust source helpers ---------------------------------------------------------


def load_corpus_version(path: Path = CORPUS_RS) -> int:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"pub const CORPUS_VERSION:\s*u32\s*=\s*(\d+);", text)
    if not match:
        raise ValueError(f"CORPUS_VERSION not found in {path}")
    return int(match.group(1))


def parse_registry_entries(path: Path = REGISTRY_RS) -> list[RegistryEntry]:
    text = path.read_text(encoding="utf-8")
    entries: list[RegistryEntry] = []
    pattern = re.compile(
        r"\(\s*Cap::([A-Z0-9_]+)\s*,\s*Lang::([A-Za-z0-9_]+)\s*,"
        r"\s*([A-Za-z0-9_:]+)::PAYLOADS\s*,?\s*\)",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        cap, lang, module_path = match.groups()
        source_path = CORPUS_DIR / f"{module_path.replace('::', '/')}.rs"
        entries.append(RegistryEntry(cap, lang, module_path, source_path))
    if not entries:
        raise ValueError(f"No registry entries found in {path}")
    return entries


def _raw_string_bounds(text: str, index: int) -> Optional[tuple[int, int, int]]:
    if text.startswith("br", index):
        marker_index = index + 2
    elif text.startswith("r", index):
        marker_index = index + 1
    else:
        return None

    cursor = marker_index
    while cursor < len(text) and text[cursor] == "#":
        cursor += 1
    if cursor >= len(text) or text[cursor] != '"':
        return None

    hashes = text[marker_index:cursor]
    body_start = cursor + 1
    terminator = '"' + hashes
    body_end = text.find(terminator, body_start)
    if body_end < 0:
        raise ValueError("unterminated Rust raw string literal")
    return body_start, body_end, body_end + len(terminator)


def _quoted_literal_end(text: str, index: int) -> Optional[int]:
    raw = _raw_string_bounds(text, index)
    if raw:
        return raw[2]

    if text.startswith('b"', index):
        quote = '"'
        cursor = index + 2
    elif text[index:index + 1] == '"':
        quote = '"'
        cursor = index + 1
    elif (
        text[index:index + 1] == "'"
        and index + 1 < len(text)
        and not (text[index + 1].isalpha() or text[index + 1] == "_")
    ):
        quote = "'"
        cursor = index + 1
    else:
        return None

    while cursor < len(text):
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == quote:
            return cursor + 1
        cursor += 1
    raise ValueError("unterminated Rust quoted literal")


def _skip_ignored(text: str, index: int) -> int:
    if text.startswith("//", index):
        newline = text.find("\n", index + 2)
        return len(text) if newline < 0 else newline + 1

    if text.startswith("/*", index):
        depth = 1
        cursor = index + 2
        while cursor < len(text) and depth:
            if text.startswith("/*", cursor):
                depth += 1
                cursor += 2
            elif text.startswith("*/", cursor):
                depth -= 1
                cursor += 2
            else:
                cursor += 1
        if depth:
            raise ValueError("unterminated Rust block comment")
        return cursor

    literal_end = _quoted_literal_end(text, index)
    return literal_end if literal_end is not None else index


def _find_matching(text: str, open_index: int, open_char: str, close_char: str) -> int:
    depth = 1
    cursor = open_index + 1
    while cursor < len(text):
        skipped = _skip_ignored(text, cursor)
        if skipped != cursor:
            cursor = skipped
            continue

        char = text[cursor]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return cursor
        cursor += 1
    raise ValueError(f"unterminated {open_char}{close_char} block")


def _payload_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"\bCuratedPayload\s*\{", text):
        open_index = match.end() - 1
        close_index = _find_matching(text, open_index, "{", "}")
        blocks.append(text[open_index + 1:close_index])
    return blocks


def _add_field(segment: str, fields: dict[str, str]) -> None:
    match = re.search(r"(^|\n)\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", segment)
    if not match:
        return
    fields[match.group(2)] = segment[match.end():].strip()


def _split_top_level_fields(block: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    start = 0
    cursor = 0
    brace_depth = 0
    bracket_depth = 0
    paren_depth = 0

    while cursor < len(block):
        skipped = _skip_ignored(block, cursor)
        if skipped != cursor:
            cursor = skipped
            continue

        char = block[cursor]
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
        elif (
            char == ","
            and brace_depth == 0
            and bracket_depth == 0
            and paren_depth == 0
        ):
            _add_field(block[start:cursor], fields)
            start = cursor + 1
        cursor += 1

    _add_field(block[start:], fields)
    return fields


def _parse_rust_string_literal(text: str, index: int) -> Optional[tuple[str, int]]:
    raw = _raw_string_bounds(text, index)
    if raw:
        body_start, body_end, literal_end = raw
        return text[body_start:body_end], literal_end

    if text.startswith('b"', index):
        cursor = index + 2
    elif text[index:index + 1] == '"':
        cursor = index + 1
    else:
        return None

    while cursor < len(text):
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == '"':
            literal = text[index:cursor + 1]
            value = ast.literal_eval(literal)
            if isinstance(value, bytes):
                return value.decode("latin-1"), cursor + 1
            return str(value), cursor + 1
        cursor += 1
    raise ValueError("unterminated Rust string literal")


def _rust_string_literals(expr: str) -> list[str]:
    strings: list[str] = []
    cursor = 0
    while cursor < len(expr):
        if expr.startswith("//", cursor) or expr.startswith("/*", cursor):
            cursor = _skip_ignored(expr, cursor)
            continue

        parsed = _parse_rust_string_literal(expr, cursor)
        if parsed:
            value, cursor = parsed
            strings.append(value)
            continue

        cursor += 1
    return strings


def _parse_string_constants(text: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    pattern = re.compile(r"(?:pub\s+)?const\s+([A-Z][A-Z0-9_]*):\s*&str\s*=\s*([^;]+);")
    for match in pattern.finditer(text):
        strings = _rust_string_literals(match.group(2))
        if strings:
            constants[match.group(1)] = strings[0]
    return constants


def _required(fields: dict[str, str], name: str, source_path: Path) -> str:
    if name not in fields:
        rel = source_path.relative_to(REPO_ROOT)
        raise ValueError(f"missing field {name!r} in payload from {rel}")
    return fields[name]


def _string_expr(expr: str, constants: dict[str, str]) -> str:
    expr = expr.strip()
    if expr in constants:
        return constants[expr]
    strings = _rust_string_literals(expr)
    if strings:
        return strings[0]
    return expr


def _bool_expr(expr: str) -> bool:
    value = expr.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"expected Rust bool literal, got {value!r}")


def _int_expr(expr: str) -> int:
    match = re.search(r"\d+", expr)
    if not match:
        raise ValueError(f"expected integer literal, got {expr!r}")
    return int(match.group(0))


def _optional_int_expr(expr: str) -> Optional[int]:
    expr = expr.strip()
    if expr == "None":
        return None
    match = re.fullmatch(r"Some\(\s*(\d+)\s*\)", expr)
    if match:
        return int(match.group(1))
    raise ValueError(f"expected Rust Option<u32> literal, got {expr!r}")


def _oracle_expr(expr: str, constants: dict[str, str]) -> tuple[str, Optional[str]]:
    expr = expr.strip()
    if expr.startswith("Oracle::OutputContains"):
        open_index = expr.find("(")
        close_index = _find_matching(expr, open_index, "(", ")")
        marker = _string_expr(expr[open_index + 1:close_index], constants)
        return "OutputContains", marker

    if expr.startswith("Oracle::OobCallback"):
        strings = _rust_string_literals(expr)
        return "OobCallback", f"host={strings[0]}" if strings else None

    if expr.startswith("Oracle::SinkCrash"):
        return "SinkCrash", "signals=all"

    if expr.startswith("Oracle::SinkProbe"):
        predicates = list(dict.fromkeys(re.findall(r"ProbePredicate::([A-Za-z0-9_]+)", expr)))
        return "SinkProbe", ",".join(predicates) if predicates else None

    return expr.split("{", 1)[0].split("(", 1)[0].strip(), None


def _payload_from_block(
    entry: RegistryEntry,
    block: str,
    constants: dict[str, str],
) -> PayloadEntry:
    fields = _split_top_level_fields(block)
    source_path = entry.source_path
    oracle_kind, oracle_value = _oracle_expr(_required(fields, "oracle", source_path), constants)
    rel_source = str(source_path.relative_to(REPO_ROOT))

    return PayloadEntry(
        cap=entry.cap,
        lang=entry.lang,
        label=_string_expr(_required(fields, "label", source_path), constants),
        bytes_repr=_string_expr(_required(fields, "bytes", source_path), constants),
        oracle_kind=oracle_kind,
        oracle_value=oracle_value,
        is_benign=_bool_expr(_required(fields, "is_benign", source_path)),
        provenance=_required(fields, "provenance", source_path)
        .strip()
        .removeprefix("PayloadProvenance::"),
        since_corpus_version=_int_expr(_required(fields, "since_corpus_version", source_path)),
        deprecated_at_corpus_version=_optional_int_expr(
            _required(fields, "deprecated_at_corpus_version", source_path)
        ),
        fixture_paths=_rust_string_literals(_required(fields, "fixture_paths", source_path)),
        oob_nonce_slot=_bool_expr(_required(fields, "oob_nonce_slot", source_path)),
        source_path=rel_source,
        cve_refs=sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", block))),
    )


def load_payloads() -> list[PayloadEntry]:
    payloads: list[PayloadEntry] = []
    for entry in parse_registry_entries():
        if not entry.source_path.exists():
            rel = entry.source_path.relative_to(REPO_ROOT)
            raise FileNotFoundError(f"registry entry points at missing payload file: {rel}")

        text = entry.source_path.read_text(encoding="utf-8")
        constants = _parse_string_constants(text)
        blocks = _payload_blocks(text)
        if not blocks:
            rel = entry.source_path.relative_to(REPO_ROOT)
            raise ValueError(f"no CuratedPayload entries found in {rel}")

        for block in blocks:
            payloads.append(_payload_from_block(entry, block, constants))

    return payloads


CORPUS_VERSION = load_corpus_version()
PAYLOADS: list[PayloadEntry] = load_payloads()
ALL_CAPS = list(dict.fromkeys(p.cap for p in PAYLOADS))


# Marker collision audit ------------------------------------------------------


def audit_marker_collisions(payloads: list[PayloadEntry] = PAYLOADS) -> list[tuple[str, str, str]]:
    collisions = []
    for payload in payloads:
        if payload.is_benign or payload.oracle_kind != "OutputContains":
            continue
        marker = payload.oracle_value or ""
        if not marker:
            continue

        for other in payloads:
            if other.cap == payload.cap:
                continue
            if other.is_benign or other.oob_nonce_slot:
                continue
            if marker in other.bytes_repr:
                collisions.append((payload.cap, payload.label, other.cap))
    return collisions


# Coverage table --------------------------------------------------------------


def build_coverage_table(payloads: list[PayloadEntry] = PAYLOADS) -> dict:
    result = {}
    for cap in ALL_CAPS:
        cap_payloads = [payload for payload in payloads if payload.cap == cap]
        result[cap] = {
            "total": len(cap_payloads),
            "vuln": sum(1 for p in cap_payloads if not p.is_benign),
            "benign": sum(1 for p in cap_payloads if p.is_benign),
            "oob_slots": sum(1 for p in cap_payloads if p.oob_nonce_slot),
            "has_fixture_paths": all(len(p.fixture_paths) > 0 for p in cap_payloads),
            "payloads": [p.label for p in cap_payloads],
        }
    return result


# Repro artifact timestamps ---------------------------------------------------


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
                if label not in timestamps or ts > timestamps[label]:
                    timestamps[label] = ts
        except (json.JSONDecodeError, KeyError):
            pass
    return timestamps


# fuzz-discovered count -------------------------------------------------------


def count_discovered(discovered_dir: Path) -> int:
    if not discovered_dir.exists():
        return 0
    return sum(
        1 for path in discovered_dir.rglob("*")
        if path.is_file() and not path.name.endswith(".json") and path.name != ".gitkeep"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Nyx corpus health dashboard")
    parser.add_argument("--repro-dir", default="repro", help="Path to repro artifacts")
    parser.add_argument(
        "--discovered-dir",
        default="fuzz-discovered",
        help="Path to fuzz-discovered/ directory",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = parser.parse_args()

    os.chdir(REPO_ROOT)

    collisions = audit_marker_collisions()
    coverage = build_coverage_table()
    timestamps = scan_last_confirmed(Path(args.repro_dir))
    discovered_count = count_discovered(Path(args.discovered_dir))

    report = {
        "corpus_version": CORPUS_VERSION,
        "registry_entries": len(parse_registry_entries()),
        "total_payloads": len(PAYLOADS),
        "coverage": coverage,
        "marker_collisions": collisions,
        "last_confirmed": timestamps,
        "cve_reference_count": sum(len(p.cve_refs) for p in PAYLOADS),
        "fuzz_discovered_pending": discovered_count,
        "healthy": len(collisions) == 0,
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["healthy"] else 1

    print(f"Nyx Corpus Dashboard  (corpus_version={CORPUS_VERSION})")
    print("=" * 60)
    print()

    print("Per-cap coverage:")
    hdr = f"  {'Cap':<22} {'Total':>5} {'Vuln':>5} {'Benign':>6} {'OOB':>4} {'Fixtures':>8}"
    print(hdr)
    print("  " + "-" * 56)
    for cap, info in coverage.items():
        fixture_ok = "ok" if info["has_fixture_paths"] else "MISSING"
        print(
            f"  {cap:<22} {info['total']:>5} {info['vuln']:>5} "
            f"{info['benign']:>6} {info['oob_slots']:>4} {fixture_ok:>8}"
        )
    print()

    if timestamps:
        print("Last confirmed timestamps:")
        for label, ts in sorted(timestamps.items()):
            print(f"  {label:<35} {ts}")
        print()

    print(f"Registry entries: {report['registry_entries']}")
    print(f"CVE references: {report['cve_reference_count']}")
    print(f"Fuzz-discovered pending promotion: {discovered_count}")
    print()

    if collisions:
        print("FAIL: Marker collisions detected (section 16.3):")
        for cap, label, other_cap in collisions:
            print(f"  {cap}/{label} marker appears in {other_cap} payload bytes")
        return 1

    print("OK: No marker collisions detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

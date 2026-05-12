#!/usr/bin/env python3
"""
Tabulate nyx scan results against a ground-truth file.

For OWASP / SARD sets: compares nyx findings against known-true/known-false
labels from the ground truth JSON.

For in-house sets (--inhouse): counts findings by cap x language; reports
Unsupported rate only (no ground truth required).

Output: appends a result record to --append FILE.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

LINE_TOLERANCE = 5

_CAP_PREFIX_TABLE = [
    ("taint.path_traversal", "path_traversal"),
    ("taint.sql", "sqli"),
    ("taint.xss", "xss"),
    ("taint.ssrf", "ssrf"),
    ("taint.cmdi", "cmdi"),
    ("taint.deserialize", "deserialize"),
    ("taint.redirect", "redirect"),
    ("taint.xxe", "xxe"),
    ("path_traversal", "path_traversal"),
    ("sqli", "sqli"),
    ("xss", "xss"),
    ("ssrf", "ssrf"),
    ("cmdi", "cmdi"),
    ("deserialize", "deserialize"),
    ("redirect", "redirect"),
    ("xxe", "xxe"),
    ("auth", "auth"),
    ("taint", "taint"),
]


def load_json(path: str) -> object:
    with open(path) as f:
        return json.load(f)


def cap_of(finding: dict) -> str:
    rule = finding.get("rule_id", "").lower()
    for prefix, cap in _CAP_PREFIX_TABLE:
        if rule.startswith(prefix):
            return cap
    return "other"


def lang_of(finding: dict) -> str:
    path = finding.get("path", "")
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
        ".rs": "rust", ".c": "c", ".cpp": "cpp",
    }
    for ext, lang in ext_map.items():
        if path.endswith(ext):
            return lang
    return "unknown"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True)
    p.add_argument("--scan", required=True, help="nyx scan --format json output")
    p.add_argument("--ground-truth", default="", help="ground truth JSON")
    p.add_argument("--inhouse", action="store_true")
    p.add_argument("--append", required=True, help="results accumulator JSON")
    args = p.parse_args()

    scan_data = load_json(args.scan)
    findings = scan_data if isinstance(scan_data, list) else scan_data.get("findings", [])

    # Per-cell tallies: {(cap, lang): {tp, fp, fn, unsupported}}
    cells: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "unsupported": 0, "total": 0}
    )

    for f in findings:
        cap = cap_of(f)
        lang = lang_of(f)
        key = (cap, lang)
        ev = f.get("evidence", {}) or {}
        dv = ev.get("dynamic_verdict") if ev else None
        cells[key]["total"] += 1
        if dv and dv.get("status") == "Unsupported":
            cells[key]["unsupported"] += 1

    if not args.inhouse and args.ground_truth and Path(args.ground_truth).exists():
        gt = load_json(args.ground_truth)
        # Ground truth format: list of {"path": ..., "line": ..., "cap": ..., "vuln": bool}
        gt_true: list[dict] = []
        for entry in gt if isinstance(gt, list) else []:
            if entry.get("vuln"):
                gt_true.append({
                    "path": entry.get("path", ""),
                    "line": entry.get("line", 0),
                    "cap": entry.get("cap", ""),
                })

        # Track which GT entries were matched (by index) to avoid double-counting.
        matched_gt: set[int] = set()
        # Track (path, cap) pairs that had at least one finding match.
        found_path_caps: set[tuple[str, str]] = set()

        for f in findings:
            f_path = f.get("path", "")
            f_line = f.get("line", 0)
            f_cap = cap_of(f)
            cap = f_cap
            lang = lang_of(f)
            cell_key = (cap, lang)
            matched_idx = None
            for idx, gt_entry in enumerate(gt_true):
                if (gt_entry["path"] == f_path
                        and gt_entry["cap"] == f_cap
                        and abs(gt_entry["line"] - f_line) <= LINE_TOLERANCE
                        and idx not in matched_gt):
                    matched_idx = idx
                    break
            if matched_idx is not None:
                matched_gt.add(matched_idx)
                found_path_caps.add((f_path, f_cap))
                cells[cell_key]["tp"] += 1
            else:
                cells[cell_key]["fp"] += 1

        for idx, gt_entry in enumerate(gt_true):
            if idx not in matched_gt:
                cap = gt_entry["cap"]
                cells[(cap, "unknown")]["fn"] += 1

    result = {
        "label": args.label,
        "total_findings": len(findings),
        "cells": [
            {
                "cap": k[0],
                "lang": k[1],
                **v,
                "precision": v["tp"] / max(v["tp"] + v["fp"], 1),
                "recall": v["tp"] / max(v["tp"] + v["fn"], 1),
                "unsupported_rate": v["unsupported"] / max(v["total"], 1),
            }
            for k, v in sorted(cells.items())
        ],
    }

    existing = load_json(args.append) if Path(args.append).exists() else []
    existing.append(result)
    with open(args.append, "w") as f:
        json.dump(existing, f, indent=2)

    # Print summary
    print(f"\n=== {args.label} ===")
    print(f"{'Cap':<20} {'Lang':<12} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>6} {'Rec':>6} {'Unsup%':>7}")
    print("-" * 72)
    for c in result["cells"]:
        print(
            f"{c['cap']:<20} {c['lang']:<12} "
            f"{c['tp']:>5} {c['fp']:>5} {c['fn']:>5} "
            f"{c['precision']:>6.2f} {c['recall']:>6.2f} "
            f"{c['unsupported_rate']*100:>6.1f}%"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

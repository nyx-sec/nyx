#!/usr/bin/env python3
"""
Tabulate nyx scan results against a ground-truth file.

For OWASP / SARD sets: compares nyx findings against known-true/known-false
labels from the ground truth JSON.

For in-house sets (--inhouse): counts findings by cap x language; reports
Unsupported rate only (no ground truth required).

Output: appends a result record to --append FILE.

Phase 29 (Track I) extensions:
  --budget tests/eval_corpus/budget.toml   enforce per-cell budget thresholds
  --diff   previous.json                   compare against prior result file,
                                           fail on monotonic-improvement
                                           regression

Exit codes:
  0  all rows pass.
  2  one or more per-cell budgets exceeded OR a diff regression was found.
  3  malformed budget / diff input (callers must fix configuration).
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover — older interpreters only
    import tomli as tomllib  # type: ignore[no-redef]

LINE_TOLERANCE = 5

# Bitflag positions for Cap (src/labels/mod.rs). Sink bits map to a cap label.
_CAP_BIT_TABLE = [
    (1 << 5,  "path_traversal"),  # FILE_IO
    (1 << 6,  "fmt_string"),
    (1 << 7,  "sqli"),             # SQL_QUERY
    (1 << 8,  "deserialize"),
    (1 << 9,  "ssrf"),
    (1 << 10, "cmdi"),             # CODE_EXEC
    (1 << 11, "crypto"),
    (1 << 12, "unauthorized_id"),
    (1 << 13, "data_exfil"),
    (1 << 14, "ldap_injection"),
    (1 << 15, "xpath_injection"),
    (1 << 16, "header_injection"),
    (1 << 17, "redirect"),         # OPEN_REDIRECT
    (1 << 18, "xss"),              # SSTI (template_injection); also covers XSS sinks
    (1 << 19, "xxe"),
    (1 << 20, "prototype_pollution"),
]

# Substring → cap lookup for rule IDs. Order matters: most specific first.
_CAP_RULE_TABLE = [
    ("path_traversal", "path_traversal"),
    ("sql",           "sqli"),
    ("xss",           "xss"),
    ("ssrf",          "ssrf"),
    ("cmdi",          "cmdi"),
    ("cmd_exec",      "cmdi"),
    ("code_exec",     "cmdi"),
    ("deser",         "deserialize"),
    ("unserialize",   "deserialize"),
    ("redirect",      "redirect"),
    ("xxe",           "xxe"),
    ("template",      "xss"),
    ("auth",          "auth"),
    ("memory",        "memory"),
    ("crypto",        "crypto"),
    ("data-exfil",    "data_exfil"),
    ("data_exfil",    "data_exfil"),
    ("header",        "header_injection"),
]


def load_json(path: str) -> object:
    with open(path) as f:
        return json.load(f)


def cap_of(finding: dict) -> str:
    # 1. Prefer evidence.sink_caps bitmask — the engine's own classification.
    ev = finding.get("evidence", {}) or {}
    sink_caps = ev.get("sink_caps")
    if isinstance(sink_caps, int) and sink_caps:
        for bit, name in _CAP_BIT_TABLE:
            if sink_caps & bit:
                return name
    # 2. Fall back to rule id substring (e.g. py.cmdi.os_system, java.deser.readobject).
    rid = (finding.get("id") or "").lower()
    head = rid.split(" ", 1)[0]
    for needle, cap in _CAP_RULE_TABLE:
        if needle in head:
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


# ── Budget loading ──────────────────────────────────────────────────────────


def load_budget(path: str) -> dict:
    """Parse a budget.toml file.

    Returns a dict::

        {
            "default": {"unsupported_rate": 0.8, "false_confirmed_rate": 0.02,
                        "repro_stability": 0.95, "ratchet_deadline": "..."},
            "cells": {(cap, lang): {...overrides...}, ...},
        }

    Raises SystemExit(3) on a malformed file.
    """

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        print(f"ERROR  budget file not found: {path}", file=sys.stderr)
        sys.exit(3)
    except tomllib.TOMLDecodeError as e:
        print(f"ERROR  budget file malformed: {path}: {e}", file=sys.stderr)
        sys.exit(3)

    default = raw.get("default", {}) or {}
    cells = {}
    for row in raw.get("cell", []) or []:
        cap = row.get("cap")
        lang = row.get("lang")
        if not cap or not lang:
            print(
                f"ERROR  budget cell missing cap/lang: {row!r}", file=sys.stderr
            )
            sys.exit(3)
        cells[(cap, lang)] = row

    return {"default": default, "cells": cells}


def budget_for_cell(budget: dict, cap: str, lang: str) -> dict:
    """Merge cell-specific overrides on top of [default]."""
    merged = dict(budget.get("default", {}) or {})
    cell = budget.get("cells", {}).get((cap, lang))
    if cell:
        merged.update({k: v for k, v in cell.items() if k not in ("cap", "lang")})
    # Fall back to a wildcard override if present.
    if not cell:
        wildcard = budget.get("cells", {}).get((cap, "*")) or \
                   budget.get("cells", {}).get(("*", lang)) or \
                   budget.get("cells", {}).get(("*", "*"))
        if wildcard:
            merged.update({k: v for k, v in wildcard.items() if k not in ("cap", "lang")})
    return merged


def enforce_budget(cells: list, budget: dict) -> list:
    """Return a list of human-readable failure strings.

    Each cell's measured Unsupported / false-Confirmed / repro-stability
    rate is compared against its merged budget row. A missing measurement
    (e.g. no Confirmed findings → false-Confirmed denominator = 0) is
    treated as "no data" and skipped, never as a failure.
    """

    failures = []
    for c in cells:
        b = budget_for_cell(budget, c["cap"], c["lang"])
        if not b:
            continue
        cap, lang = c["cap"], c["lang"]
        max_unsup = b.get("unsupported_rate")
        max_false = b.get("false_confirmed_rate")
        min_stable = b.get("repro_stability")

        if isinstance(max_unsup, (int, float)) and c.get("total", 0) > 0:
            if c["unsupported_rate"] > max_unsup:
                failures.append(
                    f"  FAIL  {cap}/{lang}: Unsupported {c['unsupported_rate']*100:.1f}%"
                    f" > budget {max_unsup*100:.1f}%"
                )
        if isinstance(max_false, (int, float)) and c.get("confirmed", 0) > 0:
            rate = c.get("wrong_confirmed", 0) / c["confirmed"]
            if rate > max_false:
                failures.append(
                    f"  FAIL  {cap}/{lang}: false-Confirmed {rate*100:.1f}%"
                    f" > budget {max_false*100:.1f}%"
                )
        # Repro stability is only enforced when callers stamped at least
        # one `replay_stable: true` flag — otherwise stable_replays == 0
        # is indistinguishable from "we did not measure stability for
        # this row" and the gate would fire vacuously on every clean run.
        if (
            isinstance(min_stable, (int, float))
            and c.get("confirmed", 0) > 0
            and c.get("stable_replays", 0) > 0
        ):
            rate = c["stable_replays"] / c["confirmed"]
            if rate < min_stable:
                failures.append(
                    f"  FAIL  {cap}/{lang}: repro stability {rate*100:.1f}%"
                    f" < budget {min_stable*100:.1f}%"
                )
    return failures


# ── Diff loading ────────────────────────────────────────────────────────────


def load_previous_cells(path: str, label: str) -> dict:
    """Index a previous results file by (cap, lang) → cell.

    The previous file is the same shape as `--append`'s output. We pick the
    record whose `label` matches the current run; if no exact match, fall
    back to the first record. Missing/unreadable files exit 3.
    """

    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR  diff file not found: {path}", file=sys.stderr)
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"ERROR  diff file malformed: {path}: {e}", file=sys.stderr)
        sys.exit(3)

    records = data if isinstance(data, list) else [data]
    chosen = None
    for r in records:
        if r.get("label") == label:
            chosen = r
            break
    if chosen is None and records:
        chosen = records[0]
    if not chosen:
        return {}
    return {(c["cap"], c["lang"]): c for c in chosen.get("cells", [])}


def diff_regressions(cells: list, prev: dict) -> list:
    """Compare current cells against previous. Returns failure strings.

    Three monotonicity rules:
      * Unsupported% must not increase.
      * False-Confirmed% must not increase.
      * Repro-stability% must not decrease.

    Cells absent from `prev` are treated as new (skipped).
    A small epsilon (0.5 percentage points) absorbs flake noise.
    """
    EPS = 0.005
    failures = []
    for c in cells:
        key = (c["cap"], c["lang"])
        old = prev.get(key)
        if not old:
            continue
        # Unsupported.
        old_unsup = old.get("unsupported_rate", 0.0)
        new_unsup = c.get("unsupported_rate", 0.0)
        if new_unsup > old_unsup + EPS:
            failures.append(
                f"  REGRESSION  {key[0]}/{key[1]}: Unsupported"
                f" {old_unsup*100:.1f}% → {new_unsup*100:.1f}%"
            )
        # False-Confirmed.
        old_conf = old.get("confirmed", 0)
        old_false = (old.get("wrong_confirmed", 0) / old_conf) if old_conf else None
        new_conf = c.get("confirmed", 0)
        new_false = (c.get("wrong_confirmed", 0) / new_conf) if new_conf else None
        if old_false is not None and new_false is not None and new_false > old_false + EPS:
            failures.append(
                f"  REGRESSION  {key[0]}/{key[1]}: false-Confirmed"
                f" {old_false*100:.1f}% → {new_false*100:.1f}%"
            )
        # Repro stability (higher is better).
        old_stable = (
            (old.get("stable_replays", 0) / old_conf) if old_conf else None
        )
        new_stable = (
            (c.get("stable_replays", 0) / new_conf) if new_conf else None
        )
        if (
            old_stable is not None
            and new_stable is not None
            and new_stable < old_stable - EPS
        ):
            failures.append(
                f"  REGRESSION  {key[0]}/{key[1]}: repro stability"
                f" {old_stable*100:.1f}% → {new_stable*100:.1f}%"
            )
    return failures


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True)
    p.add_argument("--scan", required=True, help="nyx scan --format json output")
    p.add_argument("--ground-truth", default="", help="ground truth JSON")
    p.add_argument("--inhouse", action="store_true")
    p.add_argument("--append", required=True, help="results accumulator JSON")
    p.add_argument(
        "--manual-triage",
        default="",
        help=(
            "path to a manual-triage JSON file (list of "
            "{path, line, cap, vuln: bool}).  Confirmed findings matching a "
            "`vuln: false` entry are stamped with `wrong: true` before "
            "tabulation so the per-cell False-Confirmed budget becomes "
            "non-vacuous without depending on the host's `nyx verify-feedback` "
            "log.  Matching uses LINE_TOLERANCE (=5) — line == 0 in the triage "
            "entry matches any line."
        ),
    )
    p.add_argument(
        "--budget",
        default="",
        help="path to budget.toml (per-(cap,lang) thresholds)",
    )
    p.add_argument(
        "--diff",
        default="",
        help="path to a previous results JSON; fail on monotonic-improvement regression",
    )
    args = p.parse_args()

    scan_data = load_json(args.scan)
    findings = scan_data if isinstance(scan_data, list) else scan_data.get("findings", [])

    # ── Manual-triage stamping (Phase 31 follow-up) ───────────────────────
    # Cross-reference Confirmed rows against a manual-triage file before
    # tabulation.  Each `vuln: false` entry whose `(path, cap)` matches a
    # Confirmed finding (with LINE_TOLERANCE, or any line when triage
    # entry's `line == 0`) stamps `wrong: true` on the finding's
    # `dynamic_verdict`, which the existing wrong_confirmed counter picks
    # up below.  Decouples the False-Confirmed budget from the host-local
    # `nyx verify-feedback` log so CI on a fresh eval corpus can still
    # gate the headline target.
    if args.manual_triage and Path(args.manual_triage).exists():
        triage = load_json(args.manual_triage)
        not_vuln: list[dict] = []
        for entry in triage if isinstance(triage, list) else []:
            if entry.get("vuln") is False:
                not_vuln.append({
                    "path": entry.get("path", ""),
                    "line": entry.get("line", 0),
                    "cap": entry.get("cap", ""),
                })
        used: set[int] = set()
        for f in findings:
            ev = f.get("evidence") or {}
            dv = ev.get("dynamic_verdict") or {}
            if dv.get("status") != "Confirmed":
                continue
            f_path = f.get("path", "")
            f_line = f.get("line", 0)
            f_cap = cap_of(f)
            for idx, entry in enumerate(not_vuln):
                if idx in used:
                    continue
                if (entry["path"] == f_path
                        and entry["cap"] == f_cap
                        and (entry["line"] == 0
                             or abs(entry["line"] - f_line) <= LINE_TOLERANCE)):
                    used.add(idx)
                    dv["wrong"] = True
                    ev["dynamic_verdict"] = dv
                    f["evidence"] = ev
                    break

    # Per-cell tallies: {(cap, lang): {tp, fp, fn, unsupported, confirmed,
    # partially_confirmed, wrong_confirmed, stable_replays, total}}
    cells: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "unsupported": 0,
            "confirmed": 0,
            "partially_confirmed": 0,
            "wrong_confirmed": 0,
            "stable_replays": 0,
            "total": 0,
        }
    )

    for f in findings:
        cap = cap_of(f)
        lang = lang_of(f)
        key = (cap, lang)
        ev = f.get("evidence", {}) or {}
        dv = ev.get("dynamic_verdict") if ev else None
        cells[key]["total"] += 1
        if dv:
            status = dv.get("status")
            if status == "Unsupported":
                cells[key]["unsupported"] += 1
            elif status == "PartiallyConfirmed":
                cells[key]["partially_confirmed"] += 1
            elif status == "Confirmed":
                cells[key]["confirmed"] += 1
                # Repro-stability and false-Confirmed counts are optional
                # fields tabulate.py reads off the verdict when callers have
                # stamped them.
                if dv.get("wrong") is True:
                    cells[key]["wrong_confirmed"] += 1
                if dv.get("replay_stable") is True:
                    cells[key]["stable_replays"] += 1

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
                        and idx not in matched_gt
                        and (gt_entry["line"] == 0
                             or abs(gt_entry["line"] - f_line) <= LINE_TOLERANCE)):
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

    exit_rc = 0

    # ── Phase 29: per-cell budget enforcement ─────────────────────────────
    if args.budget:
        budget = load_budget(args.budget)
        failures = enforce_budget(result["cells"], budget)
        if failures:
            print(f"\n=== Per-cell budget regressions ({args.budget}) ===")
            for line in failures:
                print(line)
            exit_rc = 2
        else:
            print(f"\nPer-cell budget ({args.budget}): OK")

    # ── Phase 29: diff against previous run ───────────────────────────────
    if args.diff:
        prev = load_previous_cells(args.diff, args.label)
        failures = diff_regressions(result["cells"], prev)
        if failures:
            print(f"\n=== Monotonic-improvement regressions vs {args.diff} ===")
            for line in failures:
                print(line)
            exit_rc = 2
        else:
            print(f"\nDiff vs {args.diff}: no regressions")

    return exit_rc


if __name__ == "__main__":
    sys.exit(main())

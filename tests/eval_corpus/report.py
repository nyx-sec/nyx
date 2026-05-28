#!/usr/bin/env python3
"""
Aggregate eval results across all corpus sets and emit a summary table.
Used by run.sh after all corpus sets have been tabulated.

Phase 29 (Track I) extensions:
  --budget tests/eval_corpus/budget.toml   per-cell budget enforcement
  --diff   previous.json                   monotonic-improvement diff;
                                           CI fails on any regression.
"""

import argparse
import json
import sys
from collections import defaultdict

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover — older interpreters only
    import tomli as tomllib  # type: ignore[no-redef]


def load_budget(path: str) -> dict:
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
            print(f"ERROR  budget cell missing cap/lang: {row!r}", file=sys.stderr)
            sys.exit(3)
        cells[(cap, lang)] = row
    return {"default": default, "cells": cells}


def budget_for_cell(budget: dict, cap: str, lang: str) -> dict:
    merged = dict(budget.get("default", {}) or {})
    cell = budget.get("cells", {}).get((cap, lang))
    if cell:
        merged.update({k: v for k, v in cell.items() if k not in ("cap", "lang")})
    if not cell:
        wildcard = (
            budget.get("cells", {}).get((cap, "*"))
            or budget.get("cells", {}).get(("*", lang))
            or budget.get("cells", {}).get(("*", "*"))
        )
        if wildcard:
            merged.update(
                {k: v for k, v in wildcard.items() if k not in ("cap", "lang")}
            )
    return merged


def load_previous_agg(path: str) -> dict:
    """Aggregate a previous results file the same way main() does."""
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR  diff file not found: {path}", file=sys.stderr)
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"ERROR  diff file malformed: {path}: {e}", file=sys.stderr)
        sys.exit(3)
    agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "unsupported": 0,
            "confirmed": 0,
            "wrong_confirmed": 0,
            "stable_replays": 0,
            "total": 0,
        }
    )
    for r in data:
        for c in r.get("cells", []):
            k = (c["cap"], c["lang"])
            for field in (
                "tp",
                "fp",
                "fn",
                "unsupported",
                "confirmed",
                "wrong_confirmed",
                "stable_replays",
                "total",
            ):
                agg[k][field] += c.get(field, 0)
    return agg


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--results", required=True)
    p.add_argument(
        "--budget",
        default="",
        help="path to budget.toml (per-(cap,lang) thresholds)",
    )
    p.add_argument(
        "--diff",
        default="",
        help="path to a previous results.json; fail on monotonic-improvement regression",
    )
    p.add_argument(
        "--min-confirmed-rate",
        type=float,
        default=None,
        help=(
            "minimum Confirmed / total rate per cap; exits 2 when any cap "
            "with findings falls below the threshold"
        ),
    )
    args = p.parse_args()

    with open(args.results) as f:
        results = json.load(f)

    if not results:
        print("No results to report.")
        return 0

    # Aggregate across sets.
    agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "unsupported": 0,
            "confirmed": 0,
            "wrong_confirmed": 0,
            "stable_replays": 0,
            "total": 0,
        }
    )
    for r in results:
        for c in r.get("cells", []):
            k = (c["cap"], c["lang"])
            for field in (
                "tp",
                "fp",
                "fn",
                "unsupported",
                "confirmed",
                "wrong_confirmed",
                "stable_replays",
                "total",
            ):
                agg[k][field] += c.get(field, 0)

    print("\n=== Aggregated eval corpus report ===")
    print(f"{'Cap':<20} {'Lang':<12} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>6} {'Rec':>6} {'Unsup%':>7}")
    print("-" * 72)
    for k, v in sorted(agg.items()):
        prec = v["tp"] / max(v["tp"] + v["fp"], 1)
        rec = v["tp"] / max(v["tp"] + v["fn"], 1)
        unsup = v["unsupported"] / max(v["total"], 1)
        print(
            f"{k[0]:<20} {k[1]:<12} "
            f"{v['tp']:>5} {v['fp']:>5} {v['fn']:>5} "
            f"{prec:>6.2f} {rec:>6.2f} "
            f"{unsup*100:>6.1f}%"
        )

    gate_failed = False

    # ── Phase 29: per-cell budget enforcement ────────────────────────────
    if args.budget:
        budget = load_budget(args.budget)
        print(f"\n=== Per-cell budget ({args.budget}) ===")
        cell_fails: list[str] = []
        for k, v in sorted(agg.items()):
            b = budget_for_cell(budget, k[0], k[1])
            if not b:
                continue
            max_unsup = b.get("unsupported_rate")
            max_false = b.get("false_confirmed_rate")
            min_stable = b.get("repro_stability")

            if isinstance(max_unsup, (int, float)) and v["total"] > 0:
                rate = v["unsupported"] / v["total"]
                if rate > max_unsup:
                    cell_fails.append(
                        f"  FAIL  {k[0]}/{k[1]}: Unsupported {rate*100:.1f}%"
                        f" > budget {max_unsup*100:.1f}%"
                    )
            if isinstance(max_false, (int, float)) and v["confirmed"] > 0:
                rate = v["wrong_confirmed"] / v["confirmed"]
                if rate > max_false:
                    cell_fails.append(
                        f"  FAIL  {k[0]}/{k[1]}: false-Confirmed {rate*100:.1f}%"
                        f" > budget {max_false*100:.1f}%"
                    )
            if (
                isinstance(min_stable, (int, float))
                and v["confirmed"] > 0
                and v.get("stable_replays", 0) > 0
            ):
                rate = v["stable_replays"] / v["confirmed"]
                if rate < min_stable:
                    cell_fails.append(
                        f"  FAIL  {k[0]}/{k[1]}: repro stability {rate*100:.1f}%"
                        f" < budget {min_stable*100:.1f}%"
                    )
        if cell_fails:
            for line in cell_fails:
                print(line)
            gate_failed = True
        else:
            print("  All per-cell budgets met.")
    else:
        # Legacy fallback: per-cap Unsupported rate <= 80%.
        print("\n=== Gate checks ===")
        UNSUPPORTED_BUDGET = 0.80
        cell_fails: list[str] = []
        for k, v in sorted(agg.items()):
            unsup = v["unsupported"] / max(v["total"], 1)
            if unsup > UNSUPPORTED_BUDGET:
                cell_fails.append(
                    f"  FAIL  {k[0]}/{k[1]}: Unsupported {unsup*100:.1f}%"
                    f" > {UNSUPPORTED_BUDGET*100:.0f}% budget"
                )
        if cell_fails:
            for line in cell_fails:
                print(line)
            gate_failed = True
        else:
            print("  All gate thresholds met.")

    # ── Optional confirmed-rate floor ────────────────────────────────────
    if args.min_confirmed_rate is not None:
        print(
            f"\n=== Confirmed-rate floor ({args.min_confirmed_rate*100:.1f}%) ==="
        )
        cap_totals: dict[str, dict] = defaultdict(lambda: {"confirmed": 0, "total": 0})
        for (cap, _lang), v in agg.items():
            cap_totals[cap]["confirmed"] += v.get("confirmed", 0)
            cap_totals[cap]["total"] += v.get("total", 0)
        confirmed_fails: list[str] = []
        for cap, v in sorted(cap_totals.items()):
            if v["total"] <= 0:
                continue
            rate = v["confirmed"] / v["total"]
            line = (
                f"  {cap:<20} {v['confirmed']:>5}/{v['total']:<5} "
                f"{rate*100:>6.1f}%"
            )
            if rate < args.min_confirmed_rate:
                confirmed_fails.append(f"{line}  FAIL")
            else:
                print(f"{line}  OK")
        if confirmed_fails:
            for line in confirmed_fails:
                print(line)
            gate_failed = True
        else:
            print("  All confirmed-rate floors met.")

    # ── Phase 29: monotonic-improvement diff ─────────────────────────────
    if args.diff:
        prev = load_previous_agg(args.diff)
        print(f"\n=== Monotonic-improvement diff vs {args.diff} ===")
        diff_fails: list[str] = []
        EPS = 0.005
        for k, v in sorted(agg.items()):
            old = prev.get(k)
            if not old:
                continue
            old_unsup = old["unsupported"] / max(old["total"], 1)
            new_unsup = v["unsupported"] / max(v["total"], 1)
            if new_unsup > old_unsup + EPS:
                diff_fails.append(
                    f"  REGRESSION  {k[0]}/{k[1]}: Unsupported"
                    f" {old_unsup*100:.1f}% → {new_unsup*100:.1f}%"
                )
            old_conf = old.get("confirmed", 0)
            new_conf = v.get("confirmed", 0)
            old_false = (old.get("wrong_confirmed", 0) / old_conf) if old_conf else None
            new_false = (v.get("wrong_confirmed", 0) / new_conf) if new_conf else None
            if old_false is not None and new_false is not None and new_false > old_false + EPS:
                diff_fails.append(
                    f"  REGRESSION  {k[0]}/{k[1]}: false-Confirmed"
                    f" {old_false*100:.1f}% → {new_false*100:.1f}%"
                )
            old_stable = (old.get("stable_replays", 0) / old_conf) if old_conf else None
            new_stable = (v.get("stable_replays", 0) / new_conf) if new_conf else None
            if (
                old_stable is not None
                and new_stable is not None
                and new_stable < old_stable - EPS
            ):
                diff_fails.append(
                    f"  REGRESSION  {k[0]}/{k[1]}: repro stability"
                    f" {old_stable*100:.1f}% → {new_stable*100:.1f}%"
                )
        if diff_fails:
            for line in diff_fails:
                print(line)
            gate_failed = True
        else:
            print("  No regressions vs previous run.")

    return 2 if gate_failed else 0


if __name__ == "__main__":
    sys.exit(main())

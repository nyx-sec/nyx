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
            "partially_confirmed": 0,
            "wrong_confirmed": 0,
            "stable_replays": 0,
            "confirmed_tp": 0,
            "confirmed_fp": 0,
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
                "partially_confirmed",
                "wrong_confirmed",
                "stable_replays",
                "confirmed_tp",
                "confirmed_fp",
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
    p.add_argument(
        "--min-precision",
        type=float,
        default=None,
        help=(
            "minimum precision (tp / (tp+fp)) per cap; exits 2 when any cap "
            "with at least one finding falls below the threshold. Phase 27 "
            "OWASP acceptance floor (>= 0.85)."
        ),
    )
    p.add_argument(
        "--min-recall",
        type=float,
        default=None,
        help=(
            "minimum recall (tp / (tp+fn)) per cap; exits 2 when any cap "
            "with at least one ground-truth positive falls below the "
            "threshold. Phase 27 OWASP acceptance floor (>= 0.40)."
        ),
    )
    p.add_argument(
        "--floor-caps",
        default="",
        help=(
            "comma-separated cap allowlist. When set, the --min-confirmed-rate, "
            "--min-precision and --min-recall floors are ENFORCED only for these "
            "caps; other caps are still measured and printed but not gated. Used "
            "to exempt caps with no sound runtime oracle (e.g. crypto weak "
            "randomness, secure-cookie config smells) from dynamic-confirmation "
            "floors that they fundamentally cannot meet. Empty = gate every cap."
        ),
    )
    args = p.parse_args()
    floor_caps = {c.strip() for c in args.floor_caps.split(",") if c.strip()}

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
            "partially_confirmed": 0,
            "wrong_confirmed": 0,
            "stable_replays": 0,
            "confirmed_tp": 0,
            "confirmed_fp": 0,
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
                "partially_confirmed",
                "wrong_confirmed",
                "stable_replays",
                "confirmed_tp",
                "confirmed_fp",
                "total",
            ):
                agg[k][field] += c.get(field, 0)

    print("\n=== Aggregated eval corpus report ===")
    print(
        f"{'Cap':<20} {'Lang':<12} {'TP':>5} {'FP':>5} {'FN':>5} "
        f"{'Prec':>6} {'Rec':>6} {'Unsup%':>7} {'Conf%':>7} {'Part%':>7}"
    )
    print("-" * 88)
    for k, v in sorted(agg.items()):
        prec = v["tp"] / max(v["tp"] + v["fp"], 1)
        rec = v["tp"] / max(v["tp"] + v["fn"], 1)
        unsup = v["unsupported"] / max(v["total"], 1)
        conf = v["confirmed"] / max(v["total"], 1)
        part = v["partially_confirmed"] / max(v["total"], 1)
        print(
            f"{k[0]:<20} {k[1]:<12} "
            f"{v['tp']:>5} {v['fp']:>5} {v['fn']:>5} "
            f"{prec:>6.2f} {rec:>6.2f} "
            f"{unsup*100:>6.1f}% {conf*100:>6.1f}% {part*100:>6.1f}%"
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
            min_confirmed = b.get("confirmed_rate")

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
            if isinstance(min_confirmed, (int, float)) and v["total"] > 0:
                rate = v["confirmed"] / v["total"]
                if rate < min_confirmed:
                    cell_fails.append(
                        f"  FAIL  {k[0]}/{k[1]}: Confirmed {rate*100:.1f}%"
                        f" < budget {min_confirmed*100:.1f}%"
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

    # ── Per-cap Confirmed-rate (published always; gated when a floor given) ──
    # Aggregated per cap across languages.  The table is always printed so the
    # corpus's confirmation profile is visible ("publish per-cap …"); the floor
    # only FAILS the run when --min-confirmed-rate is supplied and the cap is in
    # scope (floor_caps empty = every cap in scope).
    cap_totals: dict[str, dict] = defaultdict(lambda: {"confirmed": 0, "total": 0})
    for (cap, _lang), v in agg.items():
        cap_totals[cap]["confirmed"] += v.get("confirmed", 0)
        cap_totals[cap]["total"] += v.get("total", 0)
    if cap_totals:
        floor_txt = (
            f" (floor {args.min_confirmed_rate*100:.1f}%)"
            if args.min_confirmed_rate is not None
            else " (report-only)"
        )
        print(f"\n=== Per-cap Confirmed-rate{floor_txt} ===")
        confirmed_fails: list[str] = []
        for cap, v in sorted(cap_totals.items()):
            if v["total"] <= 0:
                continue
            rate = v["confirmed"] / v["total"]
            gated = args.min_confirmed_rate is not None and (
                (not floor_caps) or (cap in floor_caps)
            )
            line = (
                f"  {cap:<20} {v['confirmed']:>5}/{v['total']:<5} "
                f"{rate*100:>6.1f}%"
            )
            if gated and rate < args.min_confirmed_rate:
                confirmed_fails.append(f"{line}  FAIL")
            elif args.min_confirmed_rate is None:
                print(line)
            else:
                print(f"{line}  {'OK' if gated else 'skip (no floor)'}")
        if confirmed_fails:
            for line in confirmed_fails:
                print(line)
            gate_failed = True
        elif args.min_confirmed_rate is not None:
            print("  All confirmed-rate floors met.")

    # ── Per-cap precision / recall (published always; gated when a floor given) ──
    # OWASP acceptance: per-cap precision ≥ 0.85, recall ≥ 0.40.  Aggregated per
    # cap across languages (tp/fp/fn summed over every lang cell).  The table is
    # always printed ("publish per-cap precision/recall"); a cap FAILS only when
    # the matching --min-* floor is supplied and the cap is in scope (floor_caps
    # empty = every cap in scope).
    cap_pr: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for (cap, _lang), v in agg.items():
        cap_pr[cap]["tp"] += v.get("tp", 0)
        cap_pr[cap]["fp"] += v.get("fp", 0)
        cap_pr[cap]["fn"] += v.get("fn", 0)
    if cap_pr:
        floors = []
        if args.min_precision is not None:
            floors.append(f"precision ≥ {args.min_precision*100:.1f}%")
        if args.min_recall is not None:
            floors.append(f"recall ≥ {args.min_recall*100:.1f}%")
        floor_txt = f" (floors: {', '.join(floors)})" if floors else " (report-only)"
        print(f"\n=== Per-cap precision/recall{floor_txt} ===")
        print(f"  {'Cap':<20} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>7} {'Rec':>7}  Status")
        pr_failed = False
        any_gated = False
        for cap, v in sorted(cap_pr.items()):
            tp, fp, fn = v["tp"], v["fp"], v["fn"]
            # No findings and no GT positives → cap not present in this corpus.
            if tp + fp + fn == 0:
                continue
            prec = tp / max(tp + fp, 1)
            rec = tp / max(tp + fn, 1)
            gated = (not floor_caps) or (cap in floor_caps)
            tags = []
            if gated and args.min_precision is not None and (tp + fp) > 0 and prec < args.min_precision:
                tags.append("PRECISION")
            if gated and args.min_recall is not None and (tp + fn) > 0 and rec < args.min_recall:
                tags.append("RECALL")
            if tags:
                status = "FAIL " + "+".join(tags)
            elif not floors:
                status = "—"
            elif gated:
                status = "OK"
                any_gated = True
            else:
                status = "skip (no floor)"
            print(
                f"  {cap:<20} {tp:>5} {fp:>5} {fn:>5} "
                f"{prec:>7.2f} {rec:>7.2f}  {status}"
            )
            if tags:
                pr_failed = True
        if pr_failed:
            gate_failed = True
        elif floors and any_gated:
            print("  All per-cap precision/recall floors met.")

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

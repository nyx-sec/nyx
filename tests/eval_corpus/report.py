#!/usr/bin/env python3
"""
Aggregate eval results across all corpus sets and emit a summary table.
Used by run.sh after all corpus sets have been tabulated.
"""

import argparse
import json
import sys
from collections import defaultdict


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--results", required=True)
    args = p.parse_args()

    with open(args.results) as f:
        results = json.load(f)

    if not results:
        print("No results to report.")
        return 0

    # Aggregate across sets.
    agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "unsupported": 0, "total": 0}
    )
    for r in results:
        for c in r.get("cells", []):
            k = (c["cap"], c["lang"])
            for field in ("tp", "fp", "fn", "unsupported", "total"):
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

    # Gate check: per-cap Unsupported rate <= 80%
    gate_failed = False
    print("\n=== Gate checks ===")
    UNSUPPORTED_BUDGET = 0.80
    for k, v in sorted(agg.items()):
        unsup = v["unsupported"] / max(v["total"], 1)
        if unsup > UNSUPPORTED_BUDGET:
            print(f"  FAIL  {k[0]}/{k[1]}: Unsupported {unsup*100:.1f}% > {UNSUPPORTED_BUDGET*100:.0f}% budget")
            gate_failed = True

    if not gate_failed:
        print("  All gate thresholds met.")

    return 2 if gate_failed else 0


if __name__ == "__main__":
    sys.exit(main())

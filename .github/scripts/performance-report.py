#!/usr/bin/env python3
"""Collect criterion results into report.json, or render report.json as markdown."""

import argparse
import html
import json
import math
import pathlib
import re
import sys

MARKER = '<!-- nyx-performance -->'
NOISE_FLOOR = 5.0
STATUSES = {'ok', 'build-failed'}


def collect(args):
    def runs(role):
        result = []
        for round_ in range(1, args.rounds + 1):
            medians = {}
            for path in sorted((args.raw / f'{role}-{round_}').rglob('new/benchmark.json')):
                try:
                    name = json.loads(path.read_text())['full_id']
                    estimates = json.loads((path.parent / 'estimates.json').read_text())
                    medians[name] = estimates['median']['point_estimate']
                except (OSError, ValueError, KeyError):
                    continue
            result.append(medians)
        return result

    report = dict(base=args.base, head=args.head, bench=args.bench, harness=args.harness,
                  arms=dict(base=dict(status=args.base_status, runs=runs('base')),
                            head=dict(status=args.head_status, runs=runs('head'))))
    args.output.write_text(json.dumps(report, indent=1, allow_nan=False))


def load(path, base, head):
    """Return a validated report, or None. The file comes from PR code, so trust nothing."""
    try:
        if path.is_symlink() or path.stat().st_size > 1_000_000:
            return None
        report = json.loads(path.read_text())
        if not all(re.fullmatch(r'[0-9a-f]{40}', str(report[role])) for role in ('base', 'head')):
            return None
        if (base and report['base'] != base) or (head and report['head'] != head):
            return None
        if report['harness'] not in ('shared', 'own'):
            return None
        for arm in report['arms']['base'], report['arms']['head']:
            if arm['status'] not in STATUSES or not isinstance(arm['runs'], list):
                return None
            for run in arm['runs']:
                if not all(isinstance(name, str) and len(name) <= 200 and isinstance(value, (int, float))
                           and math.isfinite(value) and value > 0 for name, value in run.items()):
                    return None
        return report
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def escape(value):
    text = html.escape(str(value), quote=False).replace('\r', ' ').replace('\n', ' ')
    text = text.replace('|', '&#124;').replace('`', '&#96;')
    return re.sub(r'([\\\[\]()*_!~])', r'\\\1', text)


def duration(ns):
    for unit, scale in (('s', 1e9), ('ms', 1e6), ('µs', 1e3)):
        if ns >= scale:
            return f'{ns / scale:#.4g} {unit}'
    return f'{ns:#.4g} ns'


def spread(values):
    return (max(values) / min(values) - 1) * 100 if len(values) > 1 else 0.0


def rows(report):
    base_runs, head_runs = report['arms']['base']['runs'], report['arms']['head']['runs']
    names = sorted({name for run in base_runs + head_runs for name in run})
    own = report['harness'] == 'own'
    for name in names:
        before = [run[name] for run in base_runs if name in run]
        after = [run[name] for run in head_runs if name in run]
        if not before or not after:
            change = ('New' if own else 'Failed in base') if after else ('Removed' if own else 'Failed in PR')
            yield name, before, after, change, None
            continue
        percent = (min(after) / min(before) - 1) * 100
        band = max(NOISE_FLOOR, spread(before), spread(after))
        words = f'{abs(percent):.1f}% {"more" if percent > 0 else "less"} time'
        if percent == 0:
            yield name, before, after, 'No measured change', 'same'
        elif abs(percent) < band:
            yield name, before, after, f'⚪ {words} (noise)', 'same'
        elif percent > 0:
            yield name, before, after, f'🔴 {words}', 'slower'
        else:
            yield name, before, after, f'🟢 {words}', 'faster'


def render(args):
    report = load(args.report, args.base, args.head)
    lines = [MARKER, f'<!-- base: {args.base}; head: {args.head} -->', ''] if args.comment else []
    lines += ['### Performance check ⚡', '']
    run = f' See the [run]({args.run_url}).' if args.run_url else ''
    if report is None:
        lines.append(f'No usable benchmark results.{run}')
        return lines
    base, head = report['base'][:7], report['head'][:7]
    failed = [label for label, arm in (('base', report['arms']['base']), ('PR', report['arms']['head']))
              if arm['status'] != 'ok']
    if failed:
        lines.append(f'Benchmarks did not build for {" and ".join(failed)}.{run}')
        return lines

    lines += [f'| Benchmark | Base {base} | PR {head} | Measured change |', '|---|---:|---:|---|']
    counts = dict(slower=0, faster=0, same=0)
    for name, before, after, change, verdict in rows(report):
        cells = [duration(min(values)) if values else 'Failed' for values in (before, after)]
        lines.append(f'| {escape(name)} | {cells[0]} | {cells[1]} | {change} |')
        if verdict:
            counts[verdict] += 1
    rounds = len(report['arms']['head']['runs'])
    note = (f'{counts["slower"]} slower, {counts["faster"]} faster, {counts["same"]} unchanged. '
            f'Median time per iteration, best of {rounds} alternating runs on one GitHub-hosted runner. '
            f'⚪ means the change is under {NOISE_FLOOR:g}% or under the gap between runs of the same revision.')
    if report['harness'] == 'own':
        note += " The PR's benches/ didn't build against base, so each side ran its own."
    lines += ['', f'<sub>{note}{run}</sub>']
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)

    c = commands.add_parser('collect')
    c.add_argument('--raw', type=pathlib.Path, required=True)
    c.add_argument('--output', type=pathlib.Path, required=True)
    c.add_argument('--base', required=True)
    c.add_argument('--head', required=True)
    c.add_argument('--bench', required=True)
    c.add_argument('--harness', choices=('shared', 'own'), required=True)
    c.add_argument('--rounds', type=int, required=True)
    c.add_argument('--base-status', choices=sorted(STATUSES), required=True)
    c.add_argument('--head-status', choices=sorted(STATUSES), required=True)

    r = commands.add_parser('render')
    r.add_argument('report', type=pathlib.Path)
    r.add_argument('--base', default='')
    r.add_argument('--head', default='')
    r.add_argument('--comment', action='store_true')
    r.add_argument('--run-url', default='')

    args = parser.parse_args()
    if args.command == 'collect':
        collect(args)
    else:
        print('\n'.join(render(args)))


if __name__ == '__main__':
    main()

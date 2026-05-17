#!/usr/bin/env python3
"""
Phase 29 (Track I) regression test for tests/eval_corpus/tabulate.py.

Exercises --budget and --diff against hand-crafted scan + ground-truth
fixtures so the per-cell budget gate and monotonic-improvement diff are
demonstrably non-vacuous.

Run with::

    python3 tests/eval_corpus/test_tabulate_regression.py

Exits 0 when every assertion holds, non-zero otherwise.  The asserts are
plain `assert` statements so the file works both as a stand-alone script
and under unittest discovery.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TABULATE = REPO / "tests/eval_corpus/tabulate.py"
BUDGET = REPO / "tests/eval_corpus/budget.toml"


def run_tabulate(*args: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(TABULATE), *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2))


# Cap bit positions cribbed from tabulate.py / src/labels/mod.rs.
SINK_BIT_SQL = 1 << 7   # SQL_QUERY
SINK_BIT_CMDI = 1 << 10  # CODE_EXEC


def python_finding(cap_bit: int, path: str, line: int, status: str | None) -> dict:
    finding = {
        "path": path,
        "line": line,
        "col": 0,
        "id": "py.sqli.cursor_execute",
        "evidence": {"sink_caps": cap_bit},
    }
    if status:
        finding["evidence"]["dynamic_verdict"] = {"status": status}
    return finding


def test_budget_passes_on_clean_scan(tmp: Path) -> None:
    scan = tmp / "scan_clean.json"
    write_json(
        scan,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "app.py", 10, "Confirmed"),
                python_finding(SINK_BIT_SQL, "app.py", 20, "Confirmed"),
                python_finding(SINK_BIT_SQL, "app.py", 30, "NotConfirmed"),
            ]
        },
    )
    append = tmp / "results_clean.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "test",
        "--scan", str(scan),
        "--inhouse",
        "--append", str(append),
        "--budget", str(BUDGET),
    )
    assert proc.returncode == 0, f"clean scan must pass budget, got rc={proc.returncode}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    assert "Per-cell budget" in proc.stdout and "OK" in proc.stdout, proc.stdout


def test_budget_fails_when_unsupported_exceeds(tmp: Path) -> None:
    # SQL_QUERY/python budget is 40% Unsupported. Hand-craft a scan with
    # 100% Unsupported in that cell so the gate must trip.
    scan = tmp / "scan_unsup.json"
    write_json(
        scan,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "app.py", i, "Unsupported")
                for i in (10, 20, 30, 40, 50)
            ]
        },
    )
    append = tmp / "results_unsup.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "test",
        "--scan", str(scan),
        "--inhouse",
        "--append", str(append),
        "--budget", str(BUDGET),
    )
    assert proc.returncode == 2, (
        f"budget breach must exit 2, got {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "FAIL" in proc.stdout and "sqli/python" in proc.stdout, proc.stdout


def test_diff_fails_on_regression(tmp: Path) -> None:
    # Previous run: 1/4 Unsupported = 25%.  Current run: 3/4 = 75%.  The
    # default cell budget tolerates 80%, but the monotonic-improvement
    # diff must still flag the +50pp regression.
    prev_findings = [
        python_finding(SINK_BIT_CMDI, "x.unknown", 1, "Confirmed"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 2, "Confirmed"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 3, "Confirmed"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 4, "Unsupported"),
    ]
    prev_scan = tmp / "prev_scan.json"
    write_json(prev_scan, {"findings": prev_findings})
    prev_results = tmp / "prev_results.json"
    write_json(prev_results, [])
    rc_prev = run_tabulate(
        "--label", "diff-test",
        "--scan", str(prev_scan),
        "--inhouse",
        "--append", str(prev_results),
    ).returncode
    assert rc_prev == 0, f"prev seed run must succeed, got {rc_prev}"

    cur_findings = [
        python_finding(SINK_BIT_CMDI, "x.unknown", 1, "Unsupported"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 2, "Unsupported"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 3, "Unsupported"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 4, "Confirmed"),
    ]
    cur_scan = tmp / "cur_scan.json"
    write_json(cur_scan, {"findings": cur_findings})
    cur_results = tmp / "cur_results.json"
    write_json(cur_results, [])
    proc = run_tabulate(
        "--label", "diff-test",
        "--scan", str(cur_scan),
        "--inhouse",
        "--append", str(cur_results),
        "--diff", str(prev_results),
    )
    assert proc.returncode == 2, (
        f"regression diff must exit 2, got {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "REGRESSION" in proc.stdout and "Unsupported" in proc.stdout, proc.stdout


def test_diff_passes_on_improvement(tmp: Path) -> None:
    # Previous: 3/4 Unsupported.  Current: 1/4.  Monotonic improvement
    # must not flag any regression.
    prev_findings = [
        python_finding(SINK_BIT_CMDI, "x.unknown", 1, "Unsupported"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 2, "Unsupported"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 3, "Unsupported"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 4, "Confirmed"),
    ]
    prev_scan = tmp / "prev_scan.json"
    write_json(prev_scan, {"findings": prev_findings})
    prev_results = tmp / "prev_results.json"
    write_json(prev_results, [])
    run_tabulate(
        "--label", "improve-test",
        "--scan", str(prev_scan),
        "--inhouse",
        "--append", str(prev_results),
    )

    cur_findings = [
        python_finding(SINK_BIT_CMDI, "x.unknown", 1, "Confirmed"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 2, "Confirmed"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 3, "Confirmed"),
        python_finding(SINK_BIT_CMDI, "x.unknown", 4, "Unsupported"),
    ]
    cur_scan = tmp / "cur_scan.json"
    write_json(cur_scan, {"findings": cur_findings})
    cur_results = tmp / "cur_results.json"
    write_json(cur_results, [])
    proc = run_tabulate(
        "--label", "improve-test",
        "--scan", str(cur_scan),
        "--inhouse",
        "--append", str(cur_results),
        "--diff", str(prev_results),
    )
    assert proc.returncode == 0, (
        f"improvement diff must exit 0, got {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "no regressions" in proc.stdout, proc.stdout


def test_manual_triage_stamps_wrong_confirmed(tmp: Path) -> None:
    # Phase 31 follow-up: --manual-triage should cross-reference Confirmed
    # findings against a list of {path, line, cap, vuln: false} entries
    # and stamp `wrong: true` so the per-cell wrong_confirmed counter
    # becomes non-vacuous without the host's verify-feedback log.
    #
    # Confirmed at line 10 matches the triage's vuln:false at line 12
    # (within LINE_TOLERANCE=5).  Confirmed at line 100 does not match
    # any triage entry, so wrong_confirmed stays at 1 / 2 Confirmed.
    scan = tmp / "scan.json"
    write_json(
        scan,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "app.py", 10, "Confirmed"),
                python_finding(SINK_BIT_SQL, "app.py", 100, "Confirmed"),
            ]
        },
    )
    triage = tmp / "triage.json"
    write_json(
        triage,
        [
            {"path": "app.py", "line": 12, "cap": "sqli", "vuln": False},
        ],
    )
    append = tmp / "results.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "triage-test",
        "--scan", str(scan),
        "--inhouse",
        "--append", str(append),
        "--manual-triage", str(triage),
    )
    assert proc.returncode == 0, (
        f"manual-triage run must succeed without budget, got {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    results = json.loads(append.read_text())
    cells = {(c["cap"], c["lang"]): c for c in results[-1]["cells"]}
    sqli_py = cells.get(("sqli", "python"))
    assert sqli_py is not None, f"expected sqli/python cell, got {list(cells)}"
    assert sqli_py["confirmed"] == 2, sqli_py
    assert sqli_py["wrong_confirmed"] == 1, (
        "exactly one Confirmed finding must be stamped wrong via the triage match; "
        f"got {sqli_py}"
    )


def test_manual_triage_ignores_vuln_true_entries(tmp: Path) -> None:
    # Triage entries with `vuln: true` are ground-truth-positive markers,
    # not False-Confirmed evidence.  --manual-triage must leave them alone
    # so a real Confirmed-on-vuln-true row does not get downgraded.
    scan = tmp / "scan.json"
    write_json(
        scan,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "app.py", 10, "Confirmed"),
            ]
        },
    )
    triage = tmp / "triage.json"
    write_json(
        triage,
        [
            {"path": "app.py", "line": 10, "cap": "sqli", "vuln": True},
        ],
    )
    append = tmp / "results.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "triage-true-test",
        "--scan", str(scan),
        "--inhouse",
        "--append", str(append),
        "--manual-triage", str(triage),
    )
    assert proc.returncode == 0
    results = json.loads(append.read_text())
    cells = {(c["cap"], c["lang"]): c for c in results[-1]["cells"]}
    sqli_py = cells[("sqli", "python")]
    assert sqli_py["confirmed"] == 1
    assert sqli_py["wrong_confirmed"] == 0, (
        f"vuln:true triage rows must not stamp wrong; got {sqli_py}"
    )


def test_budget_malformed_exits_3(tmp: Path) -> None:
    bad = tmp / "bad.toml"
    bad.write_text("[default]\nunsupported_rate = not_a_number\n")
    scan = tmp / "scan.json"
    write_json(scan, {"findings": []})
    append = tmp / "results.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "test",
        "--scan", str(scan),
        "--inhouse",
        "--append", str(append),
        "--budget", str(bad),
    )
    assert proc.returncode == 3, (
        f"malformed budget must exit 3, got {proc.returncode}\nstderr: {proc.stderr}"
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for fn in (
            test_budget_passes_on_clean_scan,
            test_budget_fails_when_unsupported_exceeds,
            test_diff_fails_on_regression,
            test_diff_passes_on_improvement,
            test_manual_triage_stamps_wrong_confirmed,
            test_manual_triage_ignores_vuln_true_entries,
            test_budget_malformed_exits_3,
        ):
            sub = tmp / fn.__name__
            sub.mkdir()
            print(f"... {fn.__name__}")
            fn(sub)
            print(f"    OK")
    print("\nAll tabulate.py regression checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

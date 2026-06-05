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
REPORT = REPO / "tests/eval_corpus/report.py"
BUDGET = REPO / "tests/eval_corpus/budget.toml"


def run_tabulate(*args: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(TABULATE), *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def run_report(*args: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(REPORT), *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2))


# Cap bit positions cribbed from tabulate.py / src/labels/mod.rs.
SINK_BIT_SQL = 1 << 7   # SQL_QUERY
SINK_BIT_CMDI = 1 << 10  # CODE_EXEC
SINK_BIT_SHELL = 1 << 2  # SHELL_ESCAPE (Java/other command-exec sink)
SINK_BIT_FILE = 1 << 5   # FILE_IO (path_traversal)


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


def test_lang_filter_scopes_findings_and_gt(tmp: Path) -> None:
    # Phase 29 (Track R.2): --lang scopes a single-language corpus to its
    # target language so incidental other-language assets (e.g. the vendored
    # JavaScript a Rails app bundles, which nyx flags as prototype_pollution)
    # do not pollute the corpus's per-cap metrics.  The filter must drop both
    # findings AND ground-truth entries outside the scope.
    gt = tmp / "gt.json"
    write_json(
        gt,
        [
            {"path": "app/models/user.rb", "line": 0, "cap": "sqli", "vuln": True},
            {"path": "app/assets/lib.js", "line": 0, "cap": "sqli", "vuln": True},
        ],
    )
    scan = tmp / "scan.json"
    write_json(
        scan,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "/x/app/models/user.rb", 10, "NotConfirmed"),
                # A vendored-JS finding nyx would otherwise Confirm — must be
                # excluded entirely under `--lang ruby`.
                python_finding(SINK_BIT_SQL, "/x/app/assets/lib.js", 10, "Confirmed"),
            ]
        },
    )

    # Unscoped: both language cells appear.
    unscoped = tmp / "unscoped.json"
    write_json(unscoped, [])
    proc = run_tabulate(
        "--label", "railsgoat",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--append", str(unscoped),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]) for c in json.loads(unscoped.read_text())[-1]["cells"]}
    assert ("sqli", "ruby") in cells and ("sqli", "javascript") in cells, cells

    # Scoped to ruby: the JS finding AND the JS ground-truth positive vanish.
    scoped = tmp / "scoped.json"
    write_json(scoped, [])
    proc = run_tabulate(
        "--label", "railsgoat",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--lang", "ruby",
        "--append", str(scoped),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]): c for c in json.loads(scoped.read_text())[-1]["cells"]}
    assert ("sqli", "javascript") not in cells, f"JS must be filtered out: {list(cells)}"
    ruby = cells[("sqli", "ruby")]
    assert ruby["tp"] == 1 and ruby["fn"] == 0, ruby
    # The dropped JS positive must NOT resurface as a phantom FN in any cell.
    assert all(lang != "javascript" for _cap, lang in cells), cells


def test_static_lens_buckets_shell_escape_as_cmdi(tmp: Path) -> None:
    # Caveat-1 fix: in an env with 0 dynamic confirmations a Java command-exec
    # finding carries only SHELL_ESCAPE (1<<2), which the default bit table
    # leaves in "other" — so the cmdi cell reads 0 TP / N FN regardless of
    # static quality.  --static appends SHELL_ESCAPE→cmdi so static recall is
    # measurable without dynamic confirmation.
    gt = tmp / "gt.json"
    write_json(
        gt,
        [{"path": "testcode/Cmd.java", "line": 0, "cap": "cmdi", "vuln": True}],
    )
    # Real Java taint findings carry id "taint-unsanitised-flow" (no cap
    # substring), so the rule-id fallback yields "other" — not the sqli/cmdi
    # the hand-crafted python_finding id would imply.
    java_cmdi = {
        "path": "/x/testcode/Cmd.java",
        "line": 10,
        "col": 0,
        "id": "taint-unsanitised-flow",
        "evidence": {"sink_caps": SINK_BIT_SHELL, "dynamic_verdict": {"status": "NotConfirmed"}},
    }
    scan = tmp / "scan.json"
    write_json(scan, {"findings": [java_cmdi]})

    # Default lens: the finding buckets as "other", so cmdi shows the GT
    # positive as a pure FN (recall 0) — the measurement gap.
    default = tmp / "default.json"
    write_json(default, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--append", str(default),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]): c for c in json.loads(default.read_text())[-1]["cells"]}
    assert ("cmdi", "java") in cells and cells[("cmdi", "java")]["tp"] == 0, cells
    assert cells[("cmdi", "java")]["fn"] == 1, cells[("cmdi", "java")]
    assert ("other", "java") in cells, f"SHELL_ESCAPE must bucket as other by default: {list(cells)}"

    # Static lens: the finding buckets as cmdi → recall measurable (TP=1, FN=0).
    static = tmp / "static.json"
    write_json(static, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--static",
        "--append", str(static),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]): c for c in json.loads(static.read_text())[-1]["cells"]}
    cmdi = cells[("cmdi", "java")]
    assert cmdi["tp"] == 1 and cmdi["fn"] == 0, cmdi
    assert ("other", "java") not in cells, f"static lens must reclaim the other-bucketed finding: {list(cells)}"


def test_static_lens_preserves_higher_priority_bits(tmp: Path) -> None:
    # A finding carrying BOTH FILE_IO and SHELL_ESCAPE must keep bucketing as
    # path_traversal under the static lens (SHELL_ESCAPE is appended at lowest
    # priority), so the static lens never steals a finding from a non-cmdi cell.
    scan = tmp / "scan.json"
    write_json(
        scan,
        {
            "findings": [
                python_finding(SINK_BIT_FILE | SINK_BIT_SHELL, "B.java", 10, "NotConfirmed"),
            ]
        },
    )
    for flag in ([], ["--static"]):
        append = tmp / f"out{len(flag)}.json"
        write_json(append, [])
        proc = run_tabulate(
            "--label", "x",
            "--scan", str(scan),
            "--inhouse",
            "--append", str(append),
            *flag,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        caps = {c["cap"] for c in json.loads(append.read_text())[-1]["cells"]}
        assert caps == {"path_traversal"}, f"flag={flag}: {caps}"


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


def test_relative_gt_path_suffix_matches_absolute_finding(tmp: Path) -> None:
    # Phase 27: ground truth stores corpus-relative paths; nyx emits absolute
    # paths.  A relative GT path must suffix-match the absolute finding path so
    # the committed JSON stays portable across machines / CI checkouts.
    gt = tmp / "gt.json"
    write_json(
        gt,
        [
            {
                "path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest1.java",
                "line": 0,
                "cap": "sqli",
                "vuln": True,
            }
        ],
    )
    scan = tmp / "scan.json"
    write_json(
        scan,
        {
            "findings": [
                # Absolute path with the GT relative path as a suffix → TP.
                python_finding(
                    SINK_BIT_SQL,
                    "/home/ci/work/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest1.java",
                    10,
                    "Confirmed",
                ),
                # Different file under the same corpus → no GT positive → FP.
                python_finding(
                    SINK_BIT_SQL,
                    "/home/ci/work/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest2.java",
                    10,
                    "NotConfirmed",
                ),
            ]
        },
    )
    append = tmp / "results.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--append", str(append),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]): c for c in json.loads(append.read_text())[-1]["cells"]}
    sqli_java = cells[("sqli", "java")]
    assert sqli_java["tp"] == 1, f"relative GT path must suffix-match absolute finding: {sqli_java}"
    assert sqli_java["fp"] == 1, f"benign-file finding must count as FP: {sqli_java}"
    assert sqli_java["fn"] == 0, sqli_java


def test_unmatched_gt_positive_lands_in_lang_cell(tmp: Path) -> None:
    # Phase 27: a ground-truth positive with no matching finding is a FN, and
    # it must land in the cell its file extension implies (java), not a stray
    # "unknown" lang cell, so per-cap recall aggregation is meaningful.
    gt = tmp / "gt.json"
    write_json(
        gt,
        [
            {
                "path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest9.java",
                "line": 0,
                "cap": "sqli",
                "vuln": True,
            }
        ],
    )
    scan = tmp / "scan.json"
    write_json(scan, {"findings": []})
    append = tmp / "results.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--append", str(append),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]): c for c in json.loads(append.read_text())[-1]["cells"]}
    assert ("sqli", "java") in cells, f"FN must land in the java cell: {list(cells)}"
    assert cells[("sqli", "java")]["fn"] == 1, cells[("sqli", "java")]
    assert ("sqli", "unknown") not in cells, f"no stray unknown-lang cell: {list(cells)}"


def test_gt_grounded_false_confirm(tmp: Path) -> None:
    # Phase 27: with full ground truth, a Confirmed finding that matches no GT
    # positive is a false confirm — derived from GT, no manual-triage file
    # needed.  vuln file → confirmed_tp; benign/other file → confirmed_fp →
    # wrong_confirmed.  Makes false_confirmed_rate non-vacuous on a fresh corpus.
    gt = tmp / "gt.json"
    write_json(
        gt,
        [
            {"path": "testcode/Vuln.java", "line": 0, "cap": "sqli", "vuln": True},
            {"path": "testcode/Benign.java", "line": 0, "cap": "sqli", "vuln": False},
        ],
    )
    scan = tmp / "scan.json"
    write_json(
        scan,
        {
            "findings": [
                # Correct confirm on the vuln file.
                python_finding(SINK_BIT_SQL, "/x/testcode/Vuln.java", 10, "Confirmed"),
                # False confirm on the benign file (no GT positive there).
                python_finding(SINK_BIT_SQL, "/x/testcode/Benign.java", 10, "Confirmed"),
            ]
        },
    )
    append = tmp / "results.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan),
        "--ground-truth", str(gt),
        "--append", str(append),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cells = {(c["cap"], c["lang"]): c for c in json.loads(append.read_text())[-1]["cells"]}
    sqli_java = cells[("sqli", "java")]
    assert sqli_java["confirmed_tp"] == 1, sqli_java
    assert sqli_java["confirmed_fp"] == 1, sqli_java
    assert sqli_java["wrong_confirmed"] == 1, (
        f"benign-file Confirmed must be a GT-derived false confirm: {sqli_java}"
    )


def test_budget_confirmed_rate_floor(tmp: Path) -> None:
    # Phase 27: budget.toml may carry a per-cell `confirmed_rate` minimum.
    # 1 Confirmed of 5 (20%) must trip a 40% floor.
    budget = tmp / "budget.toml"
    budget.write_text(
        "[default]\n"
        "[[cell]]\n"
        'cap = "sqli"\n'
        'lang = "java"\n'
        "confirmed_rate = 0.40\n"
    )
    scan_fail = tmp / "scan_fail.json"
    write_json(
        scan_fail,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "B.java", 10, "Confirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 20, "NotConfirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 30, "NotConfirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 40, "NotConfirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 50, "NotConfirmed"),
            ]
        },
    )
    append = tmp / "results_fail.json"
    write_json(append, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan_fail),
        "--inhouse",
        "--append", str(append),
        "--budget", str(budget),
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "Confirmed" in proc.stdout and "sqli/java" in proc.stdout, proc.stdout

    # 3 Confirmed of 5 (60%) clears the floor.
    scan_ok = tmp / "scan_ok.json"
    write_json(
        scan_ok,
        {
            "findings": [
                python_finding(SINK_BIT_SQL, "B.java", 10, "Confirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 20, "Confirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 30, "Confirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 40, "NotConfirmed"),
                python_finding(SINK_BIT_SQL, "B.java", 50, "NotConfirmed"),
            ]
        },
    )
    append_ok = tmp / "results_ok.json"
    write_json(append_ok, [])
    proc = run_tabulate(
        "--label", "owasp",
        "--scan", str(scan_ok),
        "--inhouse",
        "--append", str(append_ok),
        "--budget", str(budget),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_report_precision_recall_floors(tmp: Path) -> None:
    # Phase 27: report.py --min-precision / --min-recall enforce per-cap floors
    # aggregated across langs.  cmdi precision 0.20 trips 0.85; ldap recall 0.10
    # trips 0.40; sqli (prec 1.0, rec 0.90) clears both.
    results = tmp / "results.json"

    def cell(cap, lang, tp, fp, fn):
        return {
            "cap": cap, "lang": lang, "tp": tp, "fp": fp, "fn": fn,
            "unsupported": 0, "confirmed": 0, "partially_confirmed": 0,
            "wrong_confirmed": 0, "stable_replays": 0,
            "total": tp + fp + fn,
        }

    write_json(
        results,
        [
            {
                "label": "owasp",
                "total_findings": 0,
                "cells": [
                    cell("sqli", "java", 9, 0, 1),   # prec 1.00, rec 0.90 → OK
                    cell("cmdi", "java", 1, 4, 0),   # prec 0.20 → FAIL precision
                    cell("ldap_injection", "java", 1, 0, 9),  # rec 0.10 → FAIL recall
                ],
            }
        ],
    )
    proc = run_report(
        "--results", str(results),
        "--min-precision", "0.85",
        "--min-recall", "0.40",
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "PRECISION" in proc.stdout and "cmdi" in proc.stdout, proc.stdout
    assert "RECALL" in proc.stdout and "ldap_injection" in proc.stdout, proc.stdout

    # Clean: only the passing sqli cap.
    clean = tmp / "clean.json"
    write_json(
        clean,
        [{"label": "owasp", "total_findings": 0, "cells": [cell("sqli", "java", 9, 0, 1)]}],
    )
    proc = run_report(
        "--results", str(clean),
        "--min-precision", "0.85",
        "--min-recall", "0.40",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "All per-cap precision/recall floors met" in proc.stdout, proc.stdout


def test_report_confirmed_rate_floor(tmp: Path) -> None:
    results = tmp / "results.json"
    write_json(
        results,
        [
            {
                "label": "owasp",
                "total_findings": 5,
                "cells": [
                    {
                        "cap": "sqli",
                        "lang": "java",
                        "tp": 0,
                        "fp": 0,
                        "fn": 0,
                        "unsupported": 0,
                        "confirmed": 2,
                        "wrong_confirmed": 0,
                        "stable_replays": 0,
                        "total": 5,
                    }
                ],
            }
        ],
    )
    proc = run_report("--results", str(results), "--min-confirmed-rate", "0.40")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "All confirmed-rate floors met" in proc.stdout, proc.stdout

    proc = run_report("--results", str(results), "--min-confirmed-rate", "0.50")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout and "sqli" in proc.stdout, proc.stdout


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
            test_lang_filter_scopes_findings_and_gt,
            test_static_lens_buckets_shell_escape_as_cmdi,
            test_static_lens_preserves_higher_priority_bits,
            test_budget_malformed_exits_3,
            test_relative_gt_path_suffix_matches_absolute_finding,
            test_unmatched_gt_positive_lands_in_lang_cell,
            test_gt_grounded_false_confirm,
            test_budget_confirmed_rate_floor,
            test_report_precision_recall_floors,
            test_report_confirmed_rate_floor,
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

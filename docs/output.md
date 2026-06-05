# Output Formats

Nyx supports three output formats, selected with `--format` or `output.default_format` in config.

## Console (default)

Human-readable, color-coded output to stdout. Status messages go to stderr.

```
[HIGH]   taint-unsanitised-flow (source 5:11)  src/handler.rs:12:5 (Score: 76, Confidence: High)
         Source: env::var("CMD") → Command::new("sh").arg("-c")

[MEDIUM] cfg-unguarded-sink                    src/handler.rs:12:5 (Score: 35, Confidence: Medium)

[LOW]    rs.quality.unwrap                     src/lib.rs:88:5 (Score: 10, Confidence: High)
```

### Severity indicators

| Tag | Color | Meaning |
|-----|-------|---------|
| `[HIGH]` | Red, bold | Critical, likely exploitable |
| `[MEDIUM]` | Orange, bold | Important, may be exploitable |
| `[LOW]` | Muted blue-gray | Informational: code quality or weak signal |

### Evidence fields

Taint and state findings include structured evidence:

| Label | Meaning |
|-------|---------|
| **Source** | Where tainted data originated (function name + location) |
| **Sink** | Where the dangerous operation happens |
| **Path guard** | Type of validation predicate protecting the path |

### Score

When attack-surface ranking is enabled (default), each finding shows a `Score` value. Higher scores indicate greater exploitability. See [Detector Overview](detectors.md) for the scoring formula.

### Rollup findings

High-frequency LOW Quality findings (e.g. `rs.quality.unwrap`) are grouped into rollup findings by `(file, rule)`:

```
  21:10  ● [LOW]   rs.quality.unwrap
      rs.quality.unwrap (38 occurrences)
      Examples: 21:10, 50:10, 79:10, 105:10, 134:10
      Run: nyx scan --show-instances rs.quality.unwrap
```

Rollups count as **one finding** for LOW budget enforcement. Use `--show-instances <RULE>` to expand a specific rule or `--all` to disable rollups entirely.

### Suppression footer

When findings are suppressed by the prioritization pipeline, a footer is shown:

```
Suppressed 195 LOW/Quality findings.
Active filters:
  include_quality = false
  max_low = 20
  max_low_per_file = 1
  max_low_per_rule = 10

Use --include-quality, --max-low, or --all to adjust.
```

---

## JSON

Machine-readable JSON object. The main keys are:

| Key | Type | Description |
|-----|------|-------------|
| `findings` | array | Finding objects |
| `chains` | array | Composed exploit chains, when emitted |
| `dynamic_verification` | object | Count of attached dynamic verdicts |
| `verdict_diff` | object | Baseline comparison, only when `--baseline` is used |

```json
{
  "findings": [
    {
      "path": "src/handler.rs",
      "line": 12,
      "col": 5,
      "severity": "High",
      "id": "taint-unsanitised-flow (source 5:11)",
      "path_validated": false,
      "labels": [
        ["Source", "env::var(\"CMD\") at 5:11"],
        ["Sink", "Command::new(\"sh\").arg(\"-c\")"]
      ],
      "confidence": "High",
      "evidence": {
        "source": {
          "path": "src/handler.rs",
          "line": 5,
          "col": 11,
          "kind": "source",
          "snippet": "env::var(\"CMD\")"
        },
        "sink": {
          "path": "src/handler.rs",
          "line": 12,
          "col": 5,
          "kind": "sink",
          "snippet": "Command::new(\"sh\")"
        },
        "notes": ["source_kind:EnvironmentConfig"],
        "dynamic_verdict": {
          "finding_id": "a3b12f0c91e04420",
          "status": "Confirmed",
          "triggered_payload": "cmdi-echo-marker"
        }
      },
      "rank_score": 76.0,
      "rank_reason": [
        ["severity_base", "60"],
        ["analysis_kind", "10"],
        ["source_kind", "5"],
        ["evidence_count", "1"]
      ]
    }
  ],
  "chains": [],
  "dynamic_verification": {
    "total": 1,
    "confirmed": 1,
    "partially_confirmed": 0,
    "not_confirmed": 0,
    "inconclusive": 0,
    "unsupported": 0
  }
}
```

### Field descriptions

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `path` | string | yes | File path relative to scan root |
| `line` | int | yes | 1-indexed line number |
| `col` | int | yes | 1-indexed column number |
| `severity` | string | yes | `"High"`, `"Medium"`, or `"Low"` |
| `id` | string | yes | Rule ID |
| `category` | string | yes | Finding category: `"Security"`, `"Reliability"`, or `"Quality"` |
| `path_validated` | bool | no | True if guarded by validation predicate |
| `guard_kind` | string | no | Predicate type (e.g. `"NullCheck"`, `"ValidationCall"`) |
| `message` | string | no | Human-readable context (state analysis findings) |
| `labels` | array | no | Array of `[label, value]` pairs for console display |
| `confidence` | string | no | Confidence level: `"Low"`, `"Medium"`, or `"High"` |
| `evidence` | object | no | Structured evidence (source/sink spans, state, notes) |
| `rank_score` | float | no | Attack-surface score (omitted when ranking disabled) |
| `rank_reason` | array | no | Score breakdown (omitted when ranking disabled) |
| `rollup` | object | no | Rollup data when findings are grouped (see below) |
| `chain_member_of` | int | no | Stable hash of the emitted chain this finding belongs to |

Fields marked "no" are omitted when empty/null/false to keep output compact.

### Confidence levels

| Level | Meaning |
|-------|---------|
| `High` | Strong signal: taint-confirmed flow, definite state violation |
| `Medium` | Moderate signal: resource leak, path-validated taint, CFG structural |
| `Low` | Weak signal: AST pattern match, possible resource leak, degraded analysis |

### Evidence object

The `evidence` field provides structured provenance data:

| Field | Type | Description |
|-------|------|-------------|
| `source` | object | Source span (path, line, col, kind, snippet) |
| `sink` | object | Sink span (path, line, col, kind, snippet) |
| `guards` | array | Validation guard spans |
| `sanitizers` | array | Sanitizer spans |
| `state` | object | State-machine evidence (machine, subject, from_state, to_state) |
| `notes` | array | Free-form notes (e.g. `"source_kind:UserInput"`, `"path_validated"`) |
| `dynamic_verdict` | object | Dynamic verification result, when verification ran or was skipped for a typed reason |

All fields are omitted when empty/null.

### Dynamic verdict object

`evidence.dynamic_verdict` uses this shape:

| Field | Type | Description |
|-------|------|-------------|
| `finding_id` | string | Stable 16-character hex finding id |
| `status` | string | `Confirmed`, `PartiallyConfirmed`, `NotConfirmed`, `Inconclusive`, or `Unsupported` |
| `triggered_payload` | string | Payload label for `Confirmed` verdicts |
| `reason` | object/string | Typed reason for `Unsupported` |
| `inconclusive_reason` | object/string | Typed reason for `Inconclusive` |
| `detail` | string | Extra build, sandbox, or policy detail |
| `attempts` | array | Per-payload attempt summaries |
| `toolchain_match` | string | `exact` or `drift` |
| `differential` | object | Vulnerable versus benign control result, when both ran |
| `hardening_outcome` | object | Process-backend hardening result, when recorded |

The top-level `dynamic_verification` object counts verdict statuses across the emitted findings:

```json
{
  "total": 4,
  "confirmed": 2,
  "partially_confirmed": 0,
  "not_confirmed": 1,
  "inconclusive": 0,
  "unsupported": 1
}
```

### Rollup object

When a finding is a rollup (grouped from multiple occurrences), the `rollup` field is present:

```json
{
  "rollup": {
    "count": 38,
    "occurrences": [
      { "line": 21, "col": 10 },
      { "line": 50, "col": 10 },
      { "line": 79, "col": 10 }
    ]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `count` | int | Total number of occurrences |
| `occurrences` | array | First N example locations (controlled by `rollup_examples`) |

---

## SARIF (Static Analysis Results Interchange Format)

SARIF 2.1.0 JSON, suitable for GitHub Code Scanning and other SARIF-compatible tools.

```bash
nyx scan . --format sarif > results.sarif
```

The SARIF output includes:

- **Tool metadata**: Nyx name and version
- **Rules**: Rule ID, description, severity mapping
- **Results**: One result per finding with location, message, and properties
- **Properties**: Each result includes `category` and optionally `confidence`, `rollup.count`, and `nyx_dynamic_verdict`
- **Fingerprints**: Dynamic verdict status is added as `partialFingerprints.dynamic_verdict_status` when present
- **Related locations**: Rollup findings include example locations in `relatedLocations`
- **Artifacts**: File paths referenced by findings

### GitHub Code Scanning integration

```yaml
- name: Run Nyx
  run: nyx scan . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully; no findings matched `--fail-on` threshold |
| `1` | `--fail-on` threshold breached (at least one finding meets or exceeds the specified severity) |
| `2` | `--gate` policy tripped (e.g. `no-new-confirmed` saw a new Confirmed finding, or `resolve-all-confirmed` saw a previously Confirmed finding still open) |
| Other non-zero | Error (I/O, config, database, parse error) |

Without `--fail-on` or `--gate`, Nyx always exits `0` on a successful scan regardless of findings count.

---

## Repository Triage

`nyx scan` and `nyx serve` share `.nyx/triage.json` in the scan root. The file
uses portable fingerprints so committed triage decisions survive different
checkout paths in local runs and CI.

When the file exists, CLI scans apply it automatically:

- `open` and `investigating` findings remain active.
- `false_positive`, `accepted_risk`, `suppressed`, and `fixed` findings are
  excluded from output and `--fail-on` checks by default.
- `--show-suppressed` includes terminal triage findings and emits
  `triage_state` plus `triage_note` when present.

`nyx serve` continues to read and write the same file when triage sync is
enabled, so browser triage and CI gating use the same decisions.

---

## Severity Levels

| Level | Description | Typical rules |
|-------|-------------|---------------|
| **High** | Critical vulnerabilities, likely exploitable | Command injection, unsafe deserialization, banned C functions, taint-confirmed flows with user input sources |
| **Medium** | Important issues, may be exploitable with additional context | SQL concatenation, XSS sinks, reflection, unguarded sinks, resource leaks |
| **Low** | Informational: code quality or weak signals | Weak crypto algorithms, insecure randomness, `unwrap()`/`panic!()`, type-safety escapes |

### Non-production severity downgrade

By default, findings in paths matching common non-production patterns (`tests/`, `test/`, `vendor/`, `build/`, `examples/`, `benchmarks/`) are downgraded by one tier:

- High → Medium
- Medium → Low
- Low → Low (unchanged)

Use `--keep-nonprod-severity` to disable this behavior.

---

## Inline Suppressions

Suppress specific findings directly in source code using `nyx:ignore` comments. Suppressed findings are excluded from output, severity counts, and `--fail-on` checks by default.

### Comment syntax

| Language | Comment styles |
|----------|---------------|
| Rust, C, C++, Java, Go, JS, TS | `// nyx:ignore ...` or `/* nyx:ignore ... */` |
| Python, Ruby | `# nyx:ignore ...` |
| PHP | `// nyx:ignore ...`, `# nyx:ignore ...`, or `/* nyx:ignore ... */` |

### Directive forms

```python
x = dangerous()  # nyx:ignore taint-unsanitised-flow     (suppresses this line)
# nyx:ignore-next-line taint-unsanitised-flow
x = dangerous()                                           (suppressed by the comment above)
```

- `nyx:ignore <RULE_ID>`: suppresses findings on the **same line** as the comment.
- `nyx:ignore-next-line <RULE_ID>`: suppresses findings on the **next line**.
- For taint findings, the primary line is the **sink line** (the `line` field in output).

### Rule ID matching

- **Case-sensitive**, exact match after canonicalization.
- Comma-separated: `nyx:ignore rule-a, rule-b`
- Wildcard suffix: `nyx:ignore rs.quality.*` matches any ID starting with `rs.quality.`
- Taint IDs are canonicalized: `nyx:ignore taint-unsanitised-flow` matches `taint-unsanitised-flow (source 5:1)` (parenthetical suffix stripped).

### Console behavior

- **Default**: suppressed findings are hidden entirely.
- **`--show-suppressed`**: suppressed findings appear dimmed with `[SUPPRESSED]` tag. Summary shows `"N issues (M suppressed)"`.

### JSON / SARIF behavior

- **Default**: suppressed findings are excluded from JSON/SARIF output.
- **`--show-suppressed`**: suppressed findings are included with additional fields:

```json
{
  "suppressed": true,
  "suppression": {
    "kind": "SameLine",
    "matched_pattern": "taint-unsanitised-flow",
    "directive_line": 42
  }
}
```

### Exit code

Suppressed findings do **not** trigger `--fail-on`. A scan with only suppressed findings exits `0`.

---

## Rule ID Format

| Prefix | Detector | Example |
|--------|----------|---------|
| `taint-*` | Taint analysis | `taint-unsanitised-flow (source 5:11)` |
| `cfg-*` | CFG structural | `cfg-unguarded-sink`, `cfg-auth-gap` |
| `state-*` | State model | `state-use-after-close`, `state-resource-leak` |
| `<lang>.*.*` | AST patterns | `rs.memory.transmute`, `js.code_exec.eval` |

See the [Rule Reference](rules.md) for a complete listing.

# Quick start

After `cargo install nyx-scanner` (or dropping a release binary on your PATH), point Nyx at a directory:

```bash
nyx scan ./my-project
```

First run builds a SQLite index under `.nyx/`; later runs skip files whose content hash hasn't changed. Default builds also verify Medium and High confidence findings in a sandbox. Use `--no-verify` when you want a static-only local loop.

## What a finding looks like

<p align="center"><img src="assets/screenshots/cli-scan.png" alt="nyx scan output: HIGH taint flows from req.params.user, req.query.url, and req.query.path into exec/fetch/fs.readFileSync, framed by the brand mint-cyan gradient" width="900"/></p>

The same scan in console form:

```
/tmp/demo/cmdi_direct.py
  6:5  ✖ [HIGH] taint-unsanitised-flow (source 5:11)  (Score: 81, Confidence: High)
      Unsanitised user input flows from request.args.get → os.system

      Source: request.args.get (5:11)
      Sink:   os.system
      [DYN: confirmed via cmdi-echo-marker-python]

  6:5  ✖ [HIGH] py.cmdi.os_system  (Score: 64, Confidence: High)
      os.system() runs a shell command

/tmp/demo/xss_document_write.js
  5:5  ✖ [HIGH] taint-unsanitised-flow (source 3:18)  (Score: 81, Confidence: High)
      Unsanitised user input flows from req.query.content → document.write

      Source: req.query.content (3:18)
      Sink:   document.write
      [DYN: confirmed via xss-script-marker]

  5:5  ⚠ [MEDIUM] js.xss.document_write  (Score: 34, Confidence: High)
      document.write() is an XSS sink

Dynamic verification: 4 verdicts (2 confirmed, 0 partially confirmed, 1 not confirmed, 0 inconclusive, 1 unsupported)

warning 'demo' generated 10 issues.
Finished in 1.842s.
```

Each finding is one line of header plus evidence. Fields that matter:

| Field | Meaning |
|---|---|
| `[HIGH]` / `[MEDIUM]` / `[LOW]` | Severity after the non-prod downgrade |
| Rule ID | Either a taint rule (`taint-unsanitised-flow`), a structural rule (`cfg-*`, `state-*`), or an AST pattern (`<lang>.<category>.<name>`) |
| Score | Attack-surface ranking (severity + analysis kind + source kind + evidence). Higher is more exploitable |
| Confidence | `High`, `Medium`, `Low`. Drops for AST-only matches, capped widened flows, and lowered-to-Low backwards-infeasible findings |
| Source / Sink | Where tainted data entered and where the dangerous call happened |
| `[DYN: ...]` | Dynamic verifier result, when Nyx built and ran a harness for the finding |

Two rules firing on the same line (the taint finding plus the AST pattern) is normal. The pattern matches the structural presence of `document.write`; the taint rule adds the evidence that `req.query.content` actually reached it. Both carry distinct rule IDs so suppressions can target one without the other.

## Fail a CI job on High findings

```bash
nyx scan . --fail-on HIGH --quiet
```

Exit 1 if any HIGH finding remains. `--quiet` drops the "Using default configuration" banner so CI logs stay tidy.

## Emit SARIF for GitHub Code Scanning

```bash
nyx scan . --format sarif > results.sarif
```

Full SARIF schema and GitHub Actions wiring: [cli.md](cli.md) and [output.md](output.md).

## Tighten the gate

```bash
# Only HIGH findings
nyx scan . --severity HIGH

# HIGH + MEDIUM
nyx scan . --severity ">=MEDIUM"

# Drop anything below Medium confidence (useful for CI)
nyx scan . --min-confidence medium

# Also drop findings the engine could not fully resolve (widened / bailed)
nyx scan . --require-converged
```

`--require-converged` keeps `under-report` findings (the emitted flow is still real) but drops over-reports and widenings. Intended for strict gates where a noisy finding is worse than nothing.

## Skip work for a fast first pass

```bash
nyx scan . --mode ast
nyx scan . --no-verify
```

AST-only mode runs tree-sitter patterns without building a CFG or running taint. It's fast and still catches banned-API uses, weak crypto, and obvious XSS sinks, but it can't tell `eval("1+1")` apart from `eval(userInput)`. Use it as a pre-commit filter, not as a CI gate replacement.

`--no-verify` keeps the static engine on but skips sandboxed execution. Use it when you are iterating locally and only need the analyzer result.

## Next

- [CLI reference](cli.md) for every flag and subcommand.
- [Configuration](configuration.md) for the `nyx.conf` / `nyx.local` schema, profiles, and custom rules.
- [`nyx serve`](serve.md) for the browser UI, triage workflow, and scan history.
- [Language maturity](language-maturity.md) for per-language tier and known FP/FN patterns.

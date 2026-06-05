# Contributing to Nyx

Thank you for your interest in improving Nyx. This guide covers everything you need to contribute effectively.

User-facing documentation lives at **[elicpeter.github.io/nyx](https://elicpeter.github.io/nyx/)**; the source for those pages is in [`docs/`](docs/).

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Layout](#project-layout)
3. [How to Add a New AST Pattern](#how-to-add-a-new-ast-pattern)
4. [How to Add a New Taint Rule](#how-to-add-a-new-taint-rule)
5. [How to Add a New Language](#how-to-add-a-new-language)
6. [Testing](#testing)
7. [Pull Request Guidelines](#pull-request-guidelines)
8. [Bug Reports](#bug-reports)
9. [Feature Requests](#feature-requests)
10. [Release Process](#release-process)

---

## Development Setup

### Prerequisites

- **Rust 1.88+** (edition 2024)
- Git
- **Node 20+** — only if you touch the browser UI under `frontend/` (the
  `nyx serve` web app). Pure-Rust changes do not need it.

### Building

```bash
git clone https://github.com/elicpeter/nyx.git
cd nyx

cargo build            # Debug build
cargo build --release  # Release build
cargo install --path . # Install as `nyx` binary
```

### Running Quality Checks

The fastest way to reproduce CI locally is the bundled script — it runs the same
commands CI runs (fmt, Clippy, tests, and the frontend checks):

```bash
./scripts/check.sh              # Mirror CI: fmt + clippy + tests (+ frontend)
./scripts/check.sh --rust-only  # Skip the frontend checks
./scripts/fix.sh                # Auto-fix: cargo fmt + clippy --fix + prettier/eslint
```

Or run the steps individually:

```bash
cargo test --all-features                                  # Tests, incl. tests/ integration suite
cargo clippy --all-targets --all-features -- -D warnings   # Lint, warnings = errors
cargo fmt                                                  # Format code
cargo fmt -- --check                                       # Check formatting without modifying
```

> **Match CI exactly.** CI lints and tests with `--all-targets --all-features`.
> The older `cargo test --bin nyx` / `cargo clippy --all` commands skip the
> `tests/` integration suite and feature-gated code, so they can pass locally
> while CI fails. Prefer `./scripts/check.sh`.

> **Note**: The first build downloads and compiles tree-sitter grammars for all 10 languages. Subsequent builds are faster.

### Benchmarks

```bash
cargo bench --bench scan_bench
```

Benchmark fixtures live in `benches/fixtures/`. Criterion produces HTML reports in `target/criterion/`.

---

## Project Layout

> **New here?** [`docs/how-it-works.md`](docs/how-it-works.md) walks the analysis
> pipeline end to end (with a diagram), and [`docs/detectors/taint.md`](docs/detectors/taint.md)
> covers the taint engine. The easiest first contribution is usually a new AST
> pattern (see [below](#how-to-add-a-new-ast-pattern)) — small, self-contained,
> and well templated.

```
src/
  main.rs                CLI entry point
  lib.rs                 Library re-exports (benchmarks, integration tests)
  cli.rs                 Clap command definitions
  commands/              Subcommand handlers (scan, index, list, clean, config, serve)
  ast.rs                 Entry points for both passes; tree-sitter parsing
  cfg/                   CFG construction from AST, type hierarchy
  cfg_analysis/          CFG structural detectors
    guards.rs            Unguarded sink detection (dominator analysis)
    auth.rs              Auth gap detection
    resources.rs         Resource leak detection
    error_handling.rs    Error fallthrough detection
    unreachable.rs       Unreachable security code detection
    rules.rs             Guard rules, auth rules, resource pairs
  ssa/                   SSA IR (lowering, optimization passes, const prop)
  taint/                 SSA-based taint engine (sole engine since 0.5.0)
    mod.rs               Facade + JS two-level solve
    domain.rs            Shared lattice types (VarTaint, Cap, TaintOrigin)
    ssa_transfer/        Block-level worklist, k=1 inline cache, gated sinks
    backwards.rs         Demand-driven backwards taint walk (opt-in)
    path_state.rs        Predicate tracking and contradiction pruning
  state/
    engine.rs            Generic monotone dataflow engine (Transfer<S: Lattice>)
    transfer.rs          DefaultTransfer: resource lifecycle + auth state
  summary/               FuncSummary, SsaFuncSummary, GlobalSummaries, hierarchy index
  abstract_interp/       Interval + string prefix/suffix domains
  pointer/               Field-sensitive points-to (Steensgaard-style)
  symex/                 Symbolic execution + witness generation
  constraint/            Path-constraint solving (optional Z3 via `smt` feature)
  auth_analysis/         Rust auth rule (`rs.auth.missing_ownership_check`) + sink classes
  suppress/              Inline `nyx:ignore` directive parsing
  labels/                Per-language label rules (one file per language)
  patterns/              Per-language AST pattern queries (one file per language)
  callgraph.rs           Call graph construction (petgraph), SCC, topo sort
  database.rs            SQLite indexing via r2d2 pool
  rank.rs                Attack-surface ranking
  fmt.rs                 Console output formatting
  output.rs              SARIF 2.1 builder
  walk.rs                Parallel file walker (ignore crate, respects .gitignore)
  symbol/                Symbol interning (SymbolId)
  server/                `nyx serve` HTTP layer, routes, triage sync
  interop.rs             Cross-language interop edges
  engine_notes.rs        Direction-aware engine notes (UnderReport / OverReport / Bail)
  evidence.rs            Structured evidence emitted with each finding
  errors.rs              NyxError, NyxResult types
  utils/
    config.rs            TOML config loading, merging, Config struct
```

---

## How to Add a New AST Pattern

AST patterns are the simplest detector to add. Each pattern is a tree-sitter query that matches a structural code construct.

### Step-by-step

1. **Pick the language file** under `src/patterns/<lang>.rs`.

2. **Choose the metadata**:

   | Field | Options | Guidelines |
   |-------|---------|------------|
   | **ID** | `<lang>.<category>.<specific>` | e.g. `py.cmdi.os_popen` |
   | **Tier** | `A` or `B` | `A` = presence alone is high-signal; `B` = query includes a heuristic guard |
   | **Severity** | `High`, `Medium`, `Low` | High: command exec, deser, banned functions. Medium: SQL concat, reflection, XSS. Low: weak crypto, code quality. |
   | **Category** | See `PatternCategory` enum | `CommandExec`, `CodeExec`, `Deserialization`, `SqlInjection`, `PathTraversal`, `Xss`, `Crypto`, `Secrets`, `InsecureTransport`, `Reflection`, `MemorySafety`, `Prototype`, `CodeQuality` |

3. **Write the tree-sitter query**:

   ```rust
   Pattern {
       id: "py.cmdi.os_popen",
       description: "os.popen() shell command execution",
       query: r#"(call
                    function: (attribute
                      object: (identifier) @pkg (#eq? @pkg "os")
                      attribute: (identifier) @fn (#eq? @fn "popen")))
                  @vuln"#,
       severity: Severity::High,
       tier: PatternTier::A,
       category: PatternCategory::CommandExec,
   },
   ```

   The query **must** capture a `@vuln` node. That node's span determines the reported location.

4. **Test it**:

   ```bash
   cargo test --bin nyx
   ```

5. **Update docs**: Add the new rule to `docs/rules/<lang>.md`.

### Tips

- Use the [tree-sitter playground](https://tree-sitter.github.io/tree-sitter/playground) to develop and test queries.
- Avoid duplicating taint coverage. If the same function is already a labeled sink in `src/labels/<lang>.rs`, the AST pattern is still useful for `--mode ast`, but use a distinct ID namespace. The dedup pass prevents exact-duplicate findings at the same location.
- Test with real-world code to check false positive rates before choosing a tier.

---

## How to Add a New Taint Rule

Taint rules define sources (where untrusted data enters), sinks (where dangerous operations happen), and sanitizers (where data is made safe).

### Step-by-step

1. **Open the language file** in `src/labels/<lang>.rs`.

2. **Add an entry** to the `RULES` slice:

   ```rust
   LabelRule {
       matchers: &["dangerouslySetInnerHTML"],
       label: DataLabel::Sink(Cap::HTML_ESCAPE),
   },
   ```

3. **Choose the right label type**:

   | Type | Purpose | Example |
   |------|---------|---------|
   | `DataLabel::Source(cap)` | Introduces tainted data | `env::var`, `req.body` |
   | `DataLabel::Sanitizer(cap)` | Strips matching capability bits | `html_escape`, `encodeURIComponent` |
   | `DataLabel::Sink(cap)` | Dangerous operation requiring sanitization | `eval`, `innerHTML`, `Command::new` |

4. **Choose capabilities**:

   | Capability | When to use |
   |-----------|-------------|
   | `Cap::all()` | Sources that produce universally dangerous data |
   | `Cap::SHELL_ESCAPE` | Shell command injection sinks/sanitizers |
   | `Cap::HTML_ESCAPE` | XSS sinks/sanitizers |
   | `Cap::URL_ENCODE` | URL injection sinks/sanitizers |
   | `Cap::JSON_PARSE` | JSON parsing sanitizers |
   | `Cap::FILE_IO` | File I/O sinks |
   | `Cap::FMT_STRING` | Format string sinks |
   | `Cap::ENV_VAR` | Environment/config data sources |

5. **Matcher semantics**:
   - Case-insensitive suffix matching by default.
   - If a matcher ends with `_`, it acts as a prefix match.
   - Multiple matchers in one rule are alternatives (any match triggers the rule).

### User-defined rules (no code change needed)

Users can add taint rules via config:

```toml
[[analysis.languages.javascript.rules]]
matchers = ["dangerouslySetInnerHTML"]
kind = "sink"
cap = "html_escape"
```

Or via CLI:

```bash
nyx config add-rule --lang javascript --matcher dangerouslySetInnerHTML --kind sink --cap html_escape
```

---

## How to Add a New Language

Adding a new language requires changes across several modules. Use an existing language (e.g. Go or Python) as a template.

### Checklist

1. **Tree-sitter parser**: Add `tree-sitter-<lang>` to `Cargo.toml`.

2. **Language registration**: Register the parser in `ast.rs` (language detection from file extension, parser initialization).

3. **CFG node kinds**: Create `src/labels/<lang>.rs` with a `KINDS` map that maps tree-sitter node types to the internal `Kind` enum (`Block`, `If`, `While`, `For`, `Return`, `CallFn`, `CallMethod`, `Assignment`, etc.).

4. **Parameter extraction**: Add a `PARAM_CONFIG` constant specifying how to extract function parameters from the AST (field name for parameter list, node type for individual parameters, extraction field for parameter names).

5. **Label rules**: Add `RULES` (sources, sinks, sanitizers) and `TERMINATORS` to the labels file.

6. **AST patterns**: Create `src/patterns/<lang>.rs` with a `PATTERNS` constant.

7. **Registry updates**:
   - `src/patterns/mod.rs`: add to the `REGISTRY` HashMap
   - `src/labels/mod.rs`: add to the `classify()` dispatch

8. **File extension mapping**: Add the extension in `ast.rs`.

9. **Tests**: Write unit tests and add test fixtures.

---

## Testing

### Tests

Unit tests are inline `#[test]` blocks inside source modules; integration tests
live under `tests/`. Run everything the way CI does:

```bash
cargo test --all-features
```

### What to Test

- **New AST patterns**: Ensure the tree-sitter query matches the intended construct and does not match safe alternatives.
- **New taint rules**: Verify that source-to-sink flows are detected and that sanitizers properly neutralize findings.
- **New CFG rules**: Test that guard dominance logic correctly suppresses findings when guards are present.
- **Edge cases**: Empty files, files with syntax errors (tree-sitter is error-tolerant), deeply nested structures.

### Linting

CI runs Clippy with strict settings. Before submitting:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

---

## Pull Request Guidelines

First-time contributors are welcome. If you are unsure where to start, open an issue and we can help identify a focused starter task.

1. **Branch from `master`**. Use descriptive branch names: `feat/add-kotlin-support`, `fix/false-positive-sql-concat`, `docs/update-rule-reference`.

2. **Keep PRs focused**. One logical change per PR.

3. **Ensure CI passes** — run `./scripts/check.sh` (mirrors CI), or the steps individually:
   ```bash
   cargo test --all-features
   cargo clippy --all-targets --all-features -- -D warnings
   cargo fmt -- --check
   ```

4. **Commit style**: Use [Conventional Commits](https://www.conventionalcommits.org/).
   ```
   feat(patterns): add Python subprocess.Popen pattern
   fix(taint): prevent false positive on sanitized innerHTML
   docs(rules): update JavaScript rule reference
   ```

5. **Document new rules**. If you add patterns or taint rules, update the corresponding `docs/rules/<lang>.md` page.

6. **Include test cases** for any new detection rules.

7. **Disclose material AI assistance** in the PR description if the change was drafted, generated, or substantially refactored by an AI tool. One line is enough. See [AI-POLICY.md](AI-POLICY.md) for the full policy and the bar we hold AI-assisted contributions to.

---

## Bug Reports

Please [open an issue](https://github.com/elicpeter/nyx/issues) for:

- **Crashes or panics**: include the backtrace (`RUST_BACKTRACE=1 nyx scan .`)
- **False positives**: include the minimal code snippet, rule ID, and Nyx version
- **False negatives**: describe what you expected Nyx to find and why
- **Documentation errors**: point to the specific page and what's wrong

---

## Feature Requests

We welcome well-motivated feature proposals. Please describe:

1. **Problem statement**: what pain point does this solve?
2. **Proposed solution**: high-level description, optionally with pseudo-code.
3. **Alternatives considered**: why existing functionality is not enough.

---

## Release Process

1. Update version in `Cargo.toml`.
2. Update `CHANGELOG.md` with the new version section.
3. Run full checks: `./scripts/check.sh` (or `cargo test --all-features && cargo clippy --all-targets --all-features -- -D warnings`).
4. Create a git tag: `git tag v0.x.y`.
5. Push tag: `git push origin v0.x.y`.
6. CI builds release binaries and publishes to crates.io.

---

## Security Issues

Please do **not** open public issues for security-sensitive bugs. See [SECURITY.md](SECURITY.md) for our responsible disclosure process.

---

## License

### Contributions are released under GPL-3.0-or-later

By submitting a pull request, patch, or other contribution to Nyx, you agree that your contribution will be released under the [GPL-3.0-or-later](./LICENSE), the same license as the project.

### Developer Certificate of Origin

We use the Developer Certificate of Origin (DCO) as a lightweight baseline for contributions. All commits must include a `Signed-off-by:` trailer, which certifies that you wrote the code yourself or otherwise have the right to submit it under the project license.

Use `git commit -s` to add this automatically.

### Contributor License Agreement

Before your first contribution can be merged, you must sign the Nyx [Contributor License Agreement](./CLA.md).

The CLA does not transfer ownership of your work. You retain copyright to your contributions. It grants Nyx the rights needed to maintain, distribute, and evolve the project over time, including the flexibility to support long-term sustainability through future licensing or commercial offerings.

If you do not agree to these terms, please do not submit contributions to Nyx.

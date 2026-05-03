# Benchmark Results

Current baseline (2026-05-02):

| Metric    | File-level | Rule-level | CI floor |
|-----------|------------|------------|----------|
| Precision | 1.000      | 1.000      | 0.861    |
| Recall    | 1.000      | 1.000      | 0.944    |
| F1        | 1.000      | 1.000      | 0.901    |

Corpus: 507 cases across 10 languages, 504 evaluated (3 disabled). Per-run JSON lands in `tests/benchmark/results/` (`latest.json` plus dated snapshots). See `README.md` for what the scoring modes mean and how to run a subset.

The corpus is mostly synthetic 8-20 line fixtures, one vulnerability or one safe pattern per file. A smaller real-CVE replay set under `cve_corpus/` covers 30 published advisories across all 10 languages. Both contribute to the headline numbers.

## Real CVE coverage

Real disclosed CVEs reduced to minimal reproducers, vulnerable + patched pair per CVE. Vulnerable fixtures must produce a finding for the disclosed sink class. Patched fixtures must produce zero findings.

| CVE            | Language   | Project                    | License              | Class           | Status   |
|----------------|------------|----------------------------|----------------------|-----------------|----------|
| CVE-2023-48022 | Python     | Ray                        | Apache-2.0           | CMDI            | detected |
| CVE-2017-18342 | Python     | PyYAML                     | MIT                  | Deserialization | detected |
| CVE-2025-69662 | Python     | geopandas                  | BSD-3-Clause         | SQL Injection   | detected |
| CVE-2026-33626 | Python     | LMDeploy                   | Apache-2.0           | SSRF            | detected |
| CVE-2019-14939 | JavaScript | mongo-express              | MIT                  | code_exec       | detected |
| CVE-2025-64430 | JavaScript | Parse Server               | Apache-2.0           | SSRF            | detected |
| CVE-2023-22621 | JavaScript | Strapi                     | MIT                  | code_exec (SSTI)| detected |
| CVE-2023-26159 | TypeScript | follow-redirects           | MIT                  | SSRF            | detected |
| GHSA-4x48-cgf9-q33f | TypeScript | Novu                       | MIT                  | SSRF            | detected |
| CVE-2022-30323 | Go         | hashicorp/go-getter        | MPL-2.0              | CMDI            | detected |
| CVE-2023-3188  | Go         | owncast                    | MIT                  | SSRF            | detected |
| CVE-2024-31450 | Go         | owncast                    | MIT                  | path_traversal  | detected |
| CVE-2026-41422 | Go         | daptin                     | LGPL-3.0             | sql_injection   | detected |
| CVE-2015-7501  | Java       | Apache Commons Collections | Apache-2.0           | Deserialization | detected |
| CVE-2017-12629 | Java       | Apache Solr                | Apache-2.0           | CMDI            | detected |
| CVE-2022-1471  | Java       | SnakeYAML                  | Apache-2.0           | Deserialization | detected |
| CVE-2022-42889 | Java       | Apache Commons Text        | Apache-2.0           | code_exec       | detected |
| GHSA-h8cj-hpmg-636v | Java  | Appsmith                   | Apache-2.0           | sql_injection   | detected |
| CVE-2013-0156  | Ruby       | Ruby on Rails              | MIT                  | Deserialization | detected |
| CVE-2020-8130  | Ruby       | Rake                       | MIT                  | CMDI            | detected |
| CVE-2021-21288 | Ruby       | CarrierWave                | MIT                  | SSRF            | detected |
| CVE-2023-38337 | Ruby       | rswag                      | MIT                  | path_traversal  | detected |
| CVE-2017-9841  | PHP        | PHPUnit                    | BSD-3-Clause         | code_exec       | detected |
| CVE-2018-15133 | PHP        | Laravel                    | MIT                  | Deserialization | detected |
| CVE-2018-20997 | Rust       | tar-rs                     | MIT OR Apache-2.0    | path_traversal  | detected |
| CVE-2022-36113 | Rust       | cargo                      | MIT OR Apache-2.0    | path_traversal  | detected |
| CVE-2024-24576 | Rust       | Rust stdlib                | MIT OR Apache-2.0    | CMDI            | detected |
| CVE-2016-3714  | C          | ImageMagick (ImageTragick) | ImageMagick License  | CMDI            | detected |
| CVE-2019-18634 | C          | sudo (pwfeedback)          | ISC                  | memory_safety   | detected |
| CVE-2019-13132 | C++        | ZeroMQ libzmq              | MPL-2.0              | memory_safety   | detected |
| CVE-2022-1941  | C++        | Protocol Buffers           | BSD-3-Clause         | memory_safety   | detected |
| CVE-2026-25544 | TypeScript | Payload (Drizzle adapter)  | MIT                  | sql_injection   | deferred |

Deferred entries are real bugs Nyx can't yet detect. The fixture stays committed with `disabled: true` in ground truth so the gap remains visible.

### How CVEs get picked

- Publicly disclosed with a stable advisory link.
- Class Nyx already has a rule for, so the vulnerable fixture asserts on a concrete rule ID, not just a generic taint flow.
- Reducible to roughly 30 lines without hiding the disclosed sink shape.
- Permissive upstream license (MIT, Apache, BSD, MPL, ISC, ImageMagick).

Fixtures are minimal reproducers of the unsafe pattern, not verbatim upstream code.

## CI floor

CI fails the build if rule-level precision drops below 0.861, recall below 0.944, or F1 below 0.901. Floors sit roughly 8 percentage points below the live baseline. A single-case flip is about 0.6 pp on this corpus, so the headroom absorbs honest FP/TN trades while still tripping on a class-level regression. Floors only move up, when a durable improvement lands. Never relax them to paper over a regression.

The gate runs in the `benchmark-gate` job in `.github/workflows/ci.yml`. Thresholds are encoded at the bottom of `tests/benchmark_test.rs`.

## Recent changes

Most recent first. Metrics are rule-level on the corpus size at that point.

| Date       | Change                                                                       | Corpus | P     | R     | F1    |
|------------|------------------------------------------------------------------------------|--------|-------|-------|-------|
| 2026-05-03 | Go for-range loop binding now defined from `range_clause` child of `for_statement` (was: tree-sitter wraps the binding/iterable on a child node; only direct `left`/`right` fields were consulted, so taint never reached the loop binding). gin sources extended to `c.QueryArray` / `c.GetQueryArray` / `c.PostFormArray` / `c.GetPostFormArray`. goqu raw SQL literal builders `goqu.L` / `goqu.Lit` recognised as SQL_QUERY sinks. CVE-2026-41422 (daptin aggregate API) detected | 521 | 1.000 | 1.000 | 1.000 |
| 2026-05-02 | TS regex-allowlist `<*regex*>.test(value)` / `<*pattern*>.test(value)` recognised as ValidationCall whose target is the first arg (overrides default receiver-as-target); conservative on receiver names so non-regex `*.test()` callees stay Unknown.  CVE-2026-25544 (Payload drizzle SQL injection) lands in corpus disabled — needs validated-flow propagation through SSA derivation / helper-summary returns | 499 | 1.000 | 1.000 | 1.000 |
| 2026-05-02 | JS arrow `assignment_pattern` default-param extraction + JS object-literal kwarg fallback for gated sinks + double-call (`f()(x)`) chained-inner rebinding; lodash `_.template` modeled as gated CODE_EXEC sink suppressed by `{ evaluate: false }`; CVE-2023-22621 (Strapi SSTI) detected | 494 | — | — | — |
| 2026-05-02 | `strings.ReplaceAll` recognised as CMDi sanitiser in chain-wrapper / call-site-replace shapes; clears `go-safe-009` (last open corpus FP); aggregate rule-level reaches P=R=F1=1.000 | 492 | 1.000 | 1.000 | 1.000 |
| 2026-05-01 | PathFact opaque-prefix-lock (`canonicalise + start_with?(<expr>)` recognised across Ruby/Python/JS) + `is_path_traversal_safe` predicate + negated-form polarity flip on assertion narrowing; rswag CVE-2023-38337 detected | 490 | 0.972 | 0.992 | 0.982 |
| 2026-05-01 | Ruby `OpenURI.open_uri` SSRF sink + inner-call fallback for statement-level Ruby calls (`YAML.safe_load(File.read(x))` shape now classifies); CVE-2021-21288 (CarrierWave) detected | 482 | 0.972 | 0.992 | 0.982 |
| 2026-04-29 | Java SnakeYAML + Text4Shell patterns; CVE-2022-1471 and CVE-2022-42889 detected | 449 | 0.996 | 1.000 | 0.998 |
| 2026-04-29 | Indirect-validator branch narrowing (`const err = validate(x); if (err) throw …;`) + helper-summary all_validated propagation; Novu GHSA-4x48-cgf9-q33f detected | 445 | 0.991 | 1.000 | 0.995 |
| 2026-04-29 | Python f-string SQLi pattern + bindparams sanitizer + HttpClient SSRF rules; CVE-2025-69662 (geopandas) and CVE-2026-33626 (LMDeploy) detected | 439 | 0.991 | 1.000 | 0.995 |
| 2026-04-29 | Phantom-Param-aware field suppression: CVE-2023-3188 detected, FP guards hold | 432    | 0.995 | 1.000 | 0.998 |
| 2026-04-28 | Ruby bare `Kernel#open` CMDI sink, exact-match sigil on label matchers        | 428    | 0.995 | 1.000 | 0.998 |
| 2026-04-28 | Go SSRF/FILE_IO sink expansion (`http.DefaultClient.*`, `os.Remove`/`WriteFile`) plus Decode-writeback container op | 426 | 0.995 | 1.000 | 0.998 |
| 2026-04-27 | JS chained-method inner-gate classification (`http.get(u, cb).on(...)`)      | 422    | 0.994 | 1.000 | 0.997 |
| 2026-04-23 | Auth FP remediation: 10 Rust ownership-check fixtures wired to corpus         | 305    | 0.946 | 0.994 | 0.970 |
| 2026-04-23 | C and C++ added as first-class CVE-corpus languages (5 new CVE pairs)         | 295    | 0.945 | 0.994 | 0.969 |
| 2026-04-23 | Go, Java, Ruby, PHP, plus second Python CVE pair                              | 285    | 0.944 | 0.994 | 0.968 |
| 2026-04-23 | Real-CVE replay corpus seeded (Python, JS, TS, one CVE per language)          | 273    | 0.942 | 0.994 | 0.967 |
| 2026-04-22 | Cross-file points-to summaries, SCC joint fixed-point, backwards taint        | 273    | 0.940 | 0.994 | 0.966 |
| 2026-04-22 | Cross-file context-sensitive inline taint (k=1)                               | 270    | 0.940 | 0.994 | 0.966 |
| 2026-04-20 | Rust weak-spot fixes across FILE_IO, SSRF, SQL, DESERIALIZE sink families     | 262    | 0.906 | 0.994 | 0.948 |
| 2026-04-20 | TypeScript weak-spot fixes, Fastify framework detection, TSX/JSX grammar      | 262    | 0.899 | 0.981 | 0.938 |
| 2026-04-20 | Rust corpus expansion: honest FNs in classes lacking Rust rules               | 262    | 0.891 | 0.961 | 0.925 |
| 2026-04-20 | TypeScript corpus 0 to 32 cases across 12 vuln classes                        | 246    | 0.904 | 0.986 | 0.944 |
| 2026-03-24 | Benchmark expansion: C, C++, Rust as first-class; +73 cases                   | 214    | 0.827 | 0.950 | 0.885 |
| 2026-03-22 | Cross-file SSA validation, multi-file directory cases                         | 141    | 0.840 | 0.975 | 0.903 |
| 2026-03-22 | Ruby corpus 1 to 21 cases across 8 vuln classes                               | 123    | 0.821 | 0.986 | 0.896 |
| 2026-03-22 | SSA lowering hardening (PHP closures, Python try/except, exception edges)     | 103    | 0.841 | 0.983 | 0.906 |
| 2026-03-21 | SSRF semantic completion (axios, got, undici, httpx, Net::HTTP, HTTParty)     | 103    | 0.671 | 0.966 | 0.792 |
| 2026-03-21 | Constant-arg suppression at AST and CFG level                                 | 95     | 0.654 | 0.964 | 0.779 |
| 2026-03-21 | Bare `exec`/`execSync` as JS CMDI sinks; Python `Template` as XSS sink        | 95     | 0.624 | 0.964 | 0.757 |
| 2026-03-21 | First baseline after symbolic-strings work                                    | 95     | 0.620 | 0.891 | 0.731 |

## Known limitations

These show up across multiple corpora and aren't fully fixed yet.

- **Variable-receiver method calls** (`client.send(...)` vs `HttpClient.send(...)`) miss without an inferred receiver type. Type-aware callee resolution closes most cases; some residuals remain.
- **Arbitrary import aliases** (`from flask import request as r`) aren't traced. Only explicitly listed aliases resolve.
- **URL-parsing isn't credited as SSRF sanitization.** Allowlist checks in conditions are recognised; call-site sanitizers aren't.
- **Rust unguarded-sink** still fires for shell-escape sinks when a source is in scope but not flowing to the sink arg. Intentional for high-risk classes.
- **Rust negative-validation** patterns (`contains` dominators, match-arm guards) aren't recognised yet.
- **DNS rebinding and async-callback flows** are out of scope for static analysis without runtime context.

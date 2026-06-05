# Language Maturity Matrix

Nyx supports ten languages, but support depth is not uniform. This page gives an
honest per-language picture so you can calibrate expectations before depending
on Nyx for a given stack.

The classifications here are grounded in three concrete signals:

1. **Rule depth**: how many distinct source / sanitizer / sink matchers exist
   for the language in `src/labels/<lang>.rs`, and how many vulnerability
   classes (Cap bits) those matchers cover.
2. **Benchmark results**: rule-level precision / recall / F1 on the synthetic
   corpus in
   [`tests/benchmark/RESULTS.md`](https://github.com/elicpeter/nyx/blob/master/tests/benchmark/RESULTS.md).
   `RESULTS.md` is the authoritative case counts and per-language scores.
3. **Known weak spots**: FPs and FNs the maintainers have deliberately left
   in the benchmark rather than suppressed, plus structural engine
   limitations the corpus does not stress, documented in
   [`RESULTS.md`](https://github.com/elicpeter/nyx/blob/master/tests/benchmark/RESULTS.md).

The synthetic corpus has effectively saturated: every
real-CVE fixture fires and rule-level precision and recall are both 100%.
All ten languages report rule-level F1 = 100.0%. Aggregate rule-level
P=1.000, R=1.000, F1=1.000. That means F1 alone no longer differentiates
tiers, so the differentiators are **rule depth**, **gated-sink coverage**,
and **structural idioms the corpus does not fully stress** (deep pointer
aliasing in C/C++, framework-specific context). All parser integrations
use tree-sitter and are stable; parsing is not a differentiator.

---

## Tier Summary

| Tier | Languages | F1 | What to expect |
|------|-----------|----|----------------|
| **Stable** | Python, JavaScript, TypeScript | 100% | Deep rule sets, gated sinks (argument-role-aware), framework detection, extensive fixtures, and the bulk of advanced-analysis (SSA two-level solve, context-sensitivity, symbolic execution, abstract interpretation) coverage. Safe to depend on in CI gates. |
| **Beta** | Go, Java, PHP, Ruby, Rust | 100% | Solid mid-depth rule sets with narrower cap coverage and **no gated sinks**. Cross-file flows work; some idioms (variable-typed method receivers, framework context, string interpolation, match-arm guards) are partially modeled. Usable in CI; review FP/FN lists before tightening gates. |
| **Preview** | C, C++ | 100% on synthetic corpus | Recent work taught the engine to follow taint through `std::vector` / `std::string` / map containers (including `c_str()`), through fluent builder chains like `Socket::builder().host(h).connect()`, and through inline class member functions. Function pointers and deeper pointer aliasing through `*p` / `p->field` are still not tracked. Rule-level scores against a corpus of obvious unsafe-API uses look perfect, but that is not the same as a clean audit on a real codebase. Pair with clang-tidy, Clang Static Analyzer, or Infer. |

---

## Per-Language Detail

### Stable tier

#### Python

- **Rule depth**: deep source / sanitizer / sink coverage in
  [`src/labels/python.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/python.rs)
  spanning HTML, URL, Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Framework context**: Flask, Django, argparse source matchers; `flask_request`
  import-alias support.
- **Advanced analysis**: gated sinks (`Popen`, `subprocess.run/call` with
  activation-arg awareness), most SSA-equivalence and symbolic-execution
  fixtures target Python.
- **Fixtures**: extensive `.py` coverage under `tests/fixtures/` plus the benchmark cases.
- **Blind spots**: f-string interpolation is not explicitly modeled as a
  distinct taint-producing construct; string-formatting flows are caught by
  the general concatenation path.

#### JavaScript

- **Rule depth**: deep source / sanitizer / sink coverage in
  [`src/labels/javascript.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/javascript.rs)
  spanning HTML, URL, JSON, Shell, SQL, Code, SSRF, and File I/O.
- **Advanced analysis**: gated sinks (`setAttribute`, `parseFromString`),
  two-level SSA solve for top-level + per-function scopes
  (`analyse_ssa_js_two_level`), prefix-locked SSRF suppression via
  StringFact, abstract-interpretation interval tracking.
- **Framework context**: Express, Koa, Fastify (via in-file import scan when
  `package.json` is absent).
- **Fixtures**: the largest `.js` set under `tests/fixtures/` of any
  language.
- **Blind spots**: template literals are lowered through concatenation rather
  than modeled as a first-class taint operator; dynamic property access
  (`obj[user]`) is conservatively treated.

#### TypeScript

- **Rule depth**: shares the JS ruleset (see
  [`src/labels/typescript.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/typescript.rs))
  plus TS-specific grammar handling.
- **Advanced analysis**: TSX and JSX grammars wired;
  discriminated-union narrowing, generic erasure, decorator flow, and
  interface dispatch are all validated against adversarial type-system
  stressors.
- **Framework context**: Fastify detection via `detect_in_file_frameworks`
  (import-driven, no `package.json` required).
- **Fixtures**: dedicated `.ts` / `.tsx` set under `tests/fixtures/` plus the benchmark cases.
- **Blind spots**: `as any` casts and `any`-typed flows are handled
  conservatively (treated as tainted).

### Beta tier

#### Go

- **Rule depth**: mid-depth source / sanitizer / sink coverage in
  [`src/labels/go.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/go.rs)
  covering HTML, URL, Shell, SQL, SSRF, Crypto, and File I/O.
- **Framework context**: Gin, Echo source matchers.
- **Recent fix**: `strings.ReplaceAll` is now recognised as a CMDi sanitiser
  in chain-wrapper / call-site-replace shapes, clearing the last open
  Go safe-fixture FP (`go-safe-009`, `validate(s string)` wrapping a
  `strings.ReplaceAll` over `;`).
- **Known gaps**: no gated sinks, no deserialization class. `fmt.Sprintf`
  is deliberately not a sink. Cap coverage is narrower than the Stable
  tier and argument-role-aware sink modeling is not yet implemented for Go,
  so production CI gates may surface additional FPs the corpus does not
  exercise.

#### Java

- **Rule depth**: mid-depth source / sanitizer / sink coverage in
  [`src/labels/java.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/java.rs)
  covering HTML, URL, Shell, SQL, Code, SSRF, and Deserialization.
- **Framework context**: Spring, JPA, Hibernate ORM rules; JNDI injection
  sinks.
- **Known gaps**: no gated sinks. Variable-receiver method calls
  (`client.send(...)` vs `HttpClient.send(...)`) rely on type-qualified
  resolution from receiver-type inference; flows where the receiver type
  cannot be inferred are conservatively over-tainted on unusual builder
  chains.

#### PHP

- **Rule depth**: sources include `$_GET`, `$_POST`, `$_REQUEST`
  superglobals plus sanitizer / sink matchers in
  [`src/labels/php.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/php.rs)
  covering HTML, URL, Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Known gaps**: no gated sinks. Limited framework context (Laravel raw
  methods only). `echo` language-construct detection is wired but its
  inner-argument propagation is narrower than function-call sinks.

#### Ruby

- **Rule depth**: source / sanitizer / sink coverage in
  [`src/labels/ruby.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/ruby.rs)
  covering HTML, Shell, SQL, Code, SSRF, File I/O, and Deserialization. SSRF
  coverage includes `URI.open` and the low-level `OpenURI.open_uri` it
  delegates to (the canonical CarrierWave CVE-2021-21288 sink).
  Statement-level chained-call wrappers
  (`YAML.safe_load(File.read(filename))`, `Marshal.load(File.read(p))`,
  `String.new(File.read(x))`) classify the inner sink for cross-function
  summary extraction so the outer call does not strip the sink classification
  on the helper.
- **Framework context**: Rails helpers (`sanitize_sql`, `permit`, `require`).
- **Known gaps**: string interpolation inside shell and SQL strings is
  recognized structurally but not modeled as a distinct operator.
  `begin/rescue/ensure` exception-edge wiring is not implemented.

#### Rust

Rust holds the largest per-language adversarial corpus. PathFact-driven
path-domain narrowing covers the `rs-safe-*` regression set.

- **Rule depth**: source / sanitizer / sink coverage in
  [`src/labels/rust.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/rust.rs)
  covering HTML, Shell, SQL, SSRF, Deserialization, and File I/O.
  Extensive framework source coverage (Axum, Actix, Rocket); the most of
  any language on the source side. The narrow sanitizer rule set (prefix
  and type-coercion only) is the primary reason Rust is not in the Stable
  tier. Engine-side path/typed sanitizer recognition (PathFact)
  compensates, but the ruleset itself is shallow.
- **Coverage**: SQL class (`rusqlite`, `sqlx`, `diesel`, `postgres`),
  Deserialization class (`serde_yaml`, `bincode`, `rmp_serde`, `ciborium`,
  `ron`, `toml`), file I/O (`fs::remove_file/dir/rename/copy`), and the
  `reqwest` SSRF builder chain.
- **PathFact-narrowed shapes** (`src/abstract_interp/path_domain.rs` plus
  per-return-path PathFact entries on `SsaFuncSummary`) cover
  `.replace("..","")` sanitisers, negative-validation returns, match-arm
  guards via condition lifting, static-map lookups,
  `.contains("..")` + `.starts_with('/')` rejection, Option-returning
  user sanitisers, `Path::new(p).is_absolute()` typed rejection,
  cross-function `.contains("..")` rejection, and the
  `CVE-2018-20997` / `CVE-2022-36113` / `CVE-2024-24576` patch shapes.
- **Not yet covered**: unsafe FFI / `std::mem::transmute` (no rules), Tokio
  `process::Command` async variants (not distinguished from sync),
  `hyper` / `surf` / `ureq` SSRF clients (reqwest family only).

### Preview tier

C and C++ remain **Preview** despite reporting 100% rule-level F1 on the
synthetic corpus. The engine follows taint through STL containers, builder
chains, inline member functions, and the wider `std::sto*` family, so the
gap between "passes the synthetic corpus" and "would catch the same flow
on a real codebase" is narrower than the synthetic numbers suggest. It is
not zero. The biggest remaining gaps are deep pointer aliasing and function
pointers, both of which are pervasive in real C/C++ code. Treat a clean
report as a starting point, not an audit. Pair Nyx with clang-tidy, the
Clang Static Analyzer, or Infer for production use.

**What works:**

- STL container flow. `vec.push_back(tainted)` followed by
  `vec.front().c_str()` carries taint into a downstream `system()` sink.
  `std::map::insert_or_assign`, `find`, `count`, `at`, and `data` all
  participate in the container store/load model.
- Inline class member functions. `class C { void run(...) { ... } };`
  bodies are now extracted as their own functions, so an intra-file call
  like `inner.run(input)` resolves to the body summary. Same fix covers
  `struct_specifier`, `union_specifier`, `enum_specifier`,
  `template_declaration`, and `extern "C"` blocks.
- Lambda passthrough. `auto echo = [](const char* s) { return s; };` carries
  argument taint into the result via the engine's default call-argument
  propagation.
- Builder chains. `Socket::builder().host(user).port(8080).connect()`
  resolves the chained returns and fires on `.connect()` when `user` is
  tainted; the safe variant with a hardcoded host stays quiet.
- Wider numeric sanitizer family. The full `std::sto*` set (including
  `stoll`, `stoull`, `stold`) and the C-stdlib forms (`atoi`, `atof`,
  `strtol`, etc.) clear all caps when they're called.
- More header / source extensions. `.cc`, `.cxx`, `.hpp`, `.hxx`, `.hh`,
  and `.h++` are recognized as C++ on top of `.cpp` and `.c++`. `.h` is
  intentionally still routed to C since it's ambiguous without a build
  system.

**Still not modeled** (common to both C and C++):

- Deep pointer aliasing. Taint through `*p`, `p->field`, and arbitrary
  pointer arithmetic is not tracked through arbitrary aliased writes.
  Field-sensitive points-to (see [Advanced analysis](advanced-analysis.md))
  handles the "lock on a sub-field" case but is not a general escape
  analysis.
- Function pointers and callback dispatch. An indirect call through
  `void (*fn)(char *)` resolves to no callee, so cross-pointer flows are
  invisible.
- Array-element taint by index. Writes to `buf[i]` do not always propagate
  taint to `buf` as a whole; subscript-handling helps the general case but
  doesn't make `buf` an alias for every element.
- Nested classes beyond one level (C++ only).

#### C

- **Rule depth**: source / sanitizer / sink coverage in
  [`src/labels/c.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/c.rs).
  Sanitizers are limited to the `sanitize_*` prefix and numeric-parse
  functions; sinks span Shell, File, SSRF, and Format-String.
- **Known gaps**: no framework rules, no gated sinks. The structural
  limitations listed above are the dominant concern; rule additions alone
  will not lift this language out of the Preview tier.

#### C++

- **Rule depth**: builds on the C ruleset (see
  [`src/labels/cpp.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/cpp.rs))
  with `std::cin` / `std::getline` sources and a wider numeric-sanitizer
  set covering the full `std::sto*` family.
- **Known gaps**: still no framework rules and no gated sinks. The
  structural blind spots are now narrower than they were a release ago
  (see "What now works" above), but function pointers and the harder
  pointer-aliasing patterns still produce false negatives.

---

## How the tiers were assigned

Because rule-level F1 has saturated for nine of ten languages, the tier
boundaries are drawn primarily on **rule depth** and **engine coverage of
real-world idioms** rather than on benchmark scores alone.

A language lands in **Stable** when all three hold:

- Rule set covers ≥ 8 vulnerability classes with both source and sink
  matchers, and at least one class has argument-role-aware **gated-sink**
  modeling (e.g. `setAttribute("href", url)` only flags href-like attrs).
- Benchmark F1 ≥ 95% on a corpus of ≥ 25 cases.
- Advanced analysis (SSA lowering, context-sensitivity, symbolic execution,
  abstract interpretation) is exercised by fixtures for the language.

A language lands in **Beta** when benchmark F1 is in the mid-90s or higher
on a meaningful corpus but at least one Stable criterion fails. Typical
gaps: absence of gated sinks, or sanitizer rule depth narrow enough that
the engine compensates structurally rather than via the ruleset.

A language lands in **Preview** when the engine has documented structural
blind spots for constructs that are pervasive in typical codebases for that
language. For C and C++ that means deep pointer aliasing, function
pointers, and array-element taint; STL container flow and builder chains
have moved out of the blind-spot list. Synthetic-corpus F1 is not a
reliable signal for Preview-tier languages: a clean report can coexist
with structural gaps.

(No language currently sits in the **Experimental** tier; it is reserved
for future additions whose corpus has not yet stabilised.)

---

## What this means for you

- **CI gates**: safe to set strict `--fail-on HIGH` gates on Stable-tier
  languages. On Beta-tier, expect occasional FP triage on production code
  (the synthetic corpus does not cover every framework idiom); the
  weak-spot lists above tell you what to skim for. On Preview-tier, treat
  Nyx findings as a starting point for manual review rather than
  authoritative. STL container flow and builder chains are tracked now,
  but deep pointer aliasing and function pointers are not, so a clean
  report does not tell you what the engine could not see.
- **Rule contributions**: the shortest path to raising a language's tier is
  contributing sink matchers and gated-sink registrations. Label files live
  at `src/labels/<lang>.rs`; benchmark cases live at
  `tests/benchmark/corpus/<lang>/`.
- **Scope planning**: if your primary stack is C or C++, Nyx will surface
  real findings on obvious unsafe-API uses, but budget for review time and
  combine Nyx with `clang-tidy` or the Clang Static Analyzer. Rust is now
  Beta-tier and suitable as a CI gate; pair with `cargo-audit` for
  dependency CVEs.

The benchmark thresholds in `tests/benchmark_test.rs` are deliberately set
~5 pp below current baselines so any drop in a language's F1 fails CI. Tier
promotions require sustained benchmark performance, not just rule additions.

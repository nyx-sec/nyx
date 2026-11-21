# Language Maturity Matrix

Nyx supports ten languages at uneven depth. Calibrate expectations here before
depending on Nyx for a given stack.

Three signals drive the classifications:

1. Rule depth: how many source / sanitizer / sink matchers the language has in
   `src/labels/<lang>.rs`, and how many vulnerability classes (Cap bits) they
   cover.
2. Benchmark results: rule-level precision / recall / F1 on the synthetic
   corpus, scored in
   [`tests/benchmark/RESULTS.md`](https://github.com/nyx-sec/nyx/blob/master/tests/benchmark/RESULTS.md),
   authoritative for case counts and per-language scores.
3. Known weak spots, also in `RESULTS.md`: FPs and FNs the maintainers
   deliberately left in the benchmark rather than suppressing, plus structural
   engine limitations the corpus does not stress.

The corpus has saturated: every real-CVE fixture fires, rule-level precision
and recall are both 100%, all ten languages report rule-level F1 = 100.0%, and
the aggregate is P=1.000, R=1.000, F1=1.000. F1 no longer separates tiers;
rule depth, gated-sink coverage, and structural idioms the corpus does not
fully stress (deep pointer aliasing in C/C++, framework-specific context) do.
All parser integrations use tree-sitter and are stable, so parsing is not a
differentiator.

---

## Tier Summary

| Tier | Languages | F1 | What to expect |
|------|-----------|----|----------------|
| **Stable** | Python, JavaScript, TypeScript | 100% | Deep rule sets, gated sinks (argument-role-aware), framework detection, extensive fixtures, and most advanced-analysis coverage (SSA two-level solve, context-sensitivity, symbolic execution, abstract interpretation). Safe to depend on in CI gates, with strict `--fail-on HIGH`. |
| **Beta** | Go, Java, PHP, Ruby, Rust | 100% | Mid-depth rule sets with narrower cap coverage and **no gated sinks**. Cross-file flows work; some idioms (variable-typed method receivers, framework context, string interpolation, match-arm guards) are partially modeled. Usable in CI; review FP/FN lists before tightening gates. |
| **Preview** | C, C++ | 100% on synthetic corpus | Taint follows STL containers (including `c_str()`), fluent builder chains, and inline class member functions; function pointers and deeper aliasing through `*p` / `p->field` are not tracked. Perfect scores on obvious unsafe-API uses are not a clean audit of a real codebase. Pair with clang-tidy, Clang Static Analyzer, or Infer. See [Preview tier](#preview-tier). |

---

## Rule Coverage

Classes are the vulnerability classes with source / sanitizer / sink matchers in
each label file.

| Language | Label file | Classes | Framework context |
|----------|------------|---------|-------------------|
| Python | [`python.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/python.rs) | Deep: HTML, URL, Shell, SQL, Code, SSRF, File I/O, Deserialization | Flask, Django, argparse source matchers; `flask_request` import-alias support |
| JavaScript | [`javascript.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/javascript.rs) | Deep: HTML, URL, JSON, Shell, SQL, Code, SSRF, File I/O | Express, Koa, Fastify (in-file import scan when `package.json` is absent) |
| TypeScript | [`typescript.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/typescript.rs) | Shares the JS ruleset, plus TS-specific grammar handling | Fastify via `detect_in_file_frameworks` (import-driven, no `package.json` required) |
| Go | [`go.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/go.rs) | Mid-depth: HTML, URL, Shell, SQL, SSRF, Crypto, File I/O | Gin, Echo source matchers |
| Java | [`java.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/java.rs) | Mid-depth: HTML, URL, Shell, SQL, Code, SSRF, Deserialization | Spring, JPA, Hibernate ORM rules; JNDI injection sinks |
| PHP | [`php.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/php.rs) | HTML, URL, Shell, SQL, Code, SSRF, File I/O, Deserialization; `$_GET` / `$_POST` / `$_REQUEST` superglobal sources | Limited: Laravel raw methods only |
| Ruby | [`ruby.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/ruby.rs) | HTML, Shell, SQL, Code, SSRF, File I/O, Deserialization | Rails helpers (`sanitize_sql`, `permit`, `require`) |
| Rust | [`rust.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/rust.rs) | HTML, Shell, SQL, SSRF, Deserialization, File I/O | Axum, Actix, Rocket; widest source-side framework coverage of any language |
| C | [`c.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/c.rs) | Sinks: Shell, File, SSRF, Format-String. Sanitizers: `sanitize_*` prefix and numeric-parse functions only | None |
| C++ | [`cpp.rs`](https://github.com/nyx-sec/nyx/blob/master/src/labels/cpp.rs) | C ruleset plus `std::cin` / `std::getline` sources and a wider numeric-sanitizer set covering the full `std::sto*` family | None |

---

## Per-Language Detail

### Stable tier

#### Python

Gated sinks cover `Popen` and `subprocess.run/call` with activation-arg
awareness. Most SSA-equivalence and symbolic-execution fixtures target Python,
on top of extensive `.py` coverage under `tests/fixtures/` and the benchmark
cases.

Blind spot: f-string interpolation is not explicitly modeled as a distinct
taint-producing construct, so string-formatting flows are caught by the general
concatenation path.

#### JavaScript

Gated sinks (`setAttribute`, `parseFromString`), two-level SSA solve over
top-level plus per-function scopes (`analyse_ssa_js_two_level`), prefix-locked
SSRF suppression via StringFact, abstract-interpretation interval tracking.
`tests/fixtures/` holds the largest `.js` set of any language.

Blind spots: template literals lower through concatenation rather than a
first-class taint operator, and dynamic property access (`obj[user]`) is
conservatively treated.

#### TypeScript

TSX and JSX grammars are wired, and discriminated-union narrowing, generic
erasure, decorator flow, and interface dispatch are validated against
adversarial type-system stressors. Fixtures: a dedicated `.ts` / `.tsx` set
under `tests/fixtures/` plus the benchmark cases.

Blind spot: `as any` casts and `any`-typed flows are handled conservatively,
treated as tainted.

### Beta tier

#### Go

`strings.Replace` and `strings.ReplaceAll` count as a sanitiser only when the
literal pair is a complete escape for the cap (see the symex limitations in
[advanced-analysis](advanced-analysis.md)). A strip of a single shell
metacharacter such as `;` is not one, so the `go-safe-009` fixture validates
through a `strconv.Atoi` round trip instead.

Gaps: no gated sinks, no deserialization class, and `fmt.Sprintf` is
deliberately not a sink. Cap coverage is narrower than the Stable tier and
argument-role-aware sink modeling is not yet implemented for Go, so production
CI gates may surface additional FPs the corpus does not exercise.

#### Java

Gaps: no gated sinks. Variable-receiver method calls (`client.send(...)` vs
`HttpClient.send(...)`) rely on type-qualified resolution from receiver-type
inference; flows where the receiver type cannot be inferred are conservatively
over-tainted on unusual builder chains.

#### PHP

Gaps: no gated sinks. `echo` language-construct detection is wired, but its
inner-argument propagation is narrower than function-call sinks.

#### Ruby

SSRF coverage includes `URI.open` and the low-level `OpenURI.open_uri` it
delegates to (the canonical CarrierWave CVE-2021-21288 sink). Statement-level
chained-call wrappers (`YAML.safe_load(File.read(filename))`,
`Marshal.load(File.read(p))`, `String.new(File.read(x))`) classify the inner
sink for cross-function summary extraction, so the outer call does not strip
the sink classification on the helper.

Gaps: string interpolation inside shell and SQL strings is recognized
structurally but not modeled as a distinct operator, and `begin/rescue/ensure`
exception-edge wiring is not implemented.

#### Rust

Rust holds the largest per-language adversarial corpus, and PathFact-driven
path-domain narrowing covers the `rs-safe-*` regression set. The narrow
sanitizer rule set (prefix and type-coercion only) is the primary reason Rust
is not Stable: engine-side path/typed sanitizer recognition (PathFact)
compensates, but the ruleset itself is shallow.

Class coverage: SQL (`rusqlite`, `sqlx`, `diesel`, `postgres`),
Deserialization (`serde_yaml`, `bincode`, `rmp_serde`, `ciborium`, `ron`,
`toml`), file I/O (`fs::remove_file/dir/rename/copy`), and the `reqwest` SSRF
builder chain.

PathFact-narrowed shapes (`src/abstract_interp/path_domain.rs` plus
per-return-path PathFact entries on `SsaFuncSummary`) cover
`.replace("..","")` sanitisers, negative-validation returns, match-arm guards
via condition lifting, static-map lookups, `.contains("..")` +
`.starts_with('/')` rejection, Option-returning user sanitisers,
`Path::new(p).is_absolute()` typed rejection, cross-function `.contains("..")`
rejection, and the `CVE-2018-20997` / `CVE-2022-36113` / `CVE-2024-24576`
patch shapes.

Not yet covered: unsafe FFI / `std::mem::transmute` (no rules), Tokio
`process::Command` async variants (not distinguished from sync), and
`hyper` / `surf` / `ureq` SSRF clients (reqwest family only).

### Preview tier

C and C++ remain **Preview** despite 100% rule-level F1 on the synthetic
corpus. The engine now follows taint through the constructs listed below, so
the gap between "passes the synthetic corpus" and "would catch the same flow on
a real codebase" is narrower than the numbers suggest. It is not zero: deep
pointer aliasing and function pointers are the biggest remaining gaps, and both
are pervasive in real C/C++ code.

**What works:**

- STL container flow through `std::vector`, `std::string`, and map containers:
  `vec.push_back(tainted)` then `vec.front().c_str()` carries taint into a
  downstream `system()` sink. `std::map::insert_or_assign`, `find`, `count`,
  `at`, and `data` participate in the container store/load model.
- Inline class member functions: bodies of `class C { void run(...) { ... } };`
  become their own functions, so an intra-file `inner.run(input)` resolves to
  the body summary. Same for `struct_specifier`, `union_specifier`,
  `enum_specifier`, `template_declaration`, and `extern "C"` blocks.
- Lambda passthrough: `auto echo = [](const char* s) { return s; };` carries
  argument taint into the result via default call-argument propagation.
- Builder chains: `Socket::builder().host(user).port(8080).connect()` resolves
  the chained returns and fires on `.connect()` when `user` is tainted; the
  safe variant with a hardcoded host stays quiet.
- Numeric sanitizers: the full `std::sto*` set (`stoll`, `stoull`, `stold`
  included) and the C-stdlib forms (`atoi`, `atof`, `strtol`, etc.) clear all
  caps when called.
- Extensions: `.cc`, `.cxx`, `.hpp`, `.hxx`, `.hh`, and `.h++` are recognized
  as C++ alongside `.cpp` and `.c++`. `.h` still routes to C, intentionally,
  since it's ambiguous without a build system.

**Still not modeled** (common to both C and C++):

- Deep pointer aliasing: taint through `*p`, `p->field`, and arbitrary pointer
  arithmetic is not tracked through arbitrary aliased writes. Field-sensitive
  points-to (see [Advanced analysis](advanced-analysis.md)) handles the "lock
  on a sub-field" case but is not a general escape analysis.
- Function pointers and callback dispatch: an indirect call through
  `void (*fn)(char *)` resolves to no callee, so cross-pointer flows are
  invisible.
- Array-element taint by index: writes to `buf[i]` do not always propagate
  taint to `buf` as a whole; subscript-handling helps the general case but
  doesn't make `buf` an alias for every element.
- Nested classes beyond one level (C++ only).

#### C

Gaps: no framework rules, no gated sinks. The structural limitations above are
the dominant concern, and rule additions alone will not lift C out of Preview.

#### C++

Gaps: still no framework rules and no gated sinks. The structural blind spots
are narrower than they were a release ago (see the list above), but function
pointers and the harder pointer-aliasing patterns still produce false
negatives.

---

## How the tiers were assigned

Because rule-level F1 has saturated for nine of ten languages, tier boundaries
are drawn on rule depth and engine coverage of real-world idioms, not benchmark
scores alone.

**Stable** requires all three:

- ≥ 8 vulnerability classes with both source and sink matchers, and at least
  one class with argument-role-aware **gated-sink** modeling (e.g.
  `setAttribute("href", url)` only flags href-like attrs).
- Benchmark F1 ≥ 95% on a corpus of ≥ 25 cases.
- Fixtures for the language that exercise advanced analysis (SSA lowering,
  context-sensitivity, symbolic execution, abstract interpretation).

**Beta** is benchmark F1 in the mid-90s or higher on a meaningful corpus with
at least one Stable criterion failing, usually no gated sinks or a sanitizer
rule set narrow enough that the engine compensates structurally rather than via
the ruleset.

**Preview** means documented structural blind spots for constructs pervasive in
typical codebases for that language: for C and C++, deep pointer aliasing,
function pointers, and array-element taint (STL container flow and builder
chains have moved off that list). Synthetic-corpus F1 is not a reliable signal
at this tier, since a clean report can coexist with structural gaps.

No language currently sits in the **Experimental** tier; it is reserved for
future additions whose corpus has not yet stabilised.

---

## What this means for you

On Beta-tier languages, expect occasional FP triage on production code, since
the synthetic corpus does not cover every framework idiom; the weak-spot lists
above say what to skim for. On Preview-tier, treat findings as a starting point
for manual review rather than authoritative: STL container flow and builder
chains are tracked, deep pointer aliasing and function pointers are not, so a
clean report does not tell you what the engine could not see.

The shortest path to raising a language's tier is contributing sink matchers
and gated-sink registrations. Label files live at `src/labels/<lang>.rs`,
benchmark cases at `tests/benchmark/corpus/<lang>/`.

With C or C++ as a primary stack, Nyx will surface real findings on obvious
unsafe-API uses, but budget review time and combine it with `clang-tidy` or the
Clang Static Analyzer. Rust is now Beta-tier and suitable as a CI gate; pair
with `cargo-audit` for dependency CVEs.

Benchmark thresholds in `tests/benchmark_test.rs` sit ~5 pp below current
baselines, so any drop in a language's F1 fails CI. Tier promotions require
sustained benchmark performance, not just rule additions.

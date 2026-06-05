# Dynamic verification

Static analysis tells you a sink is reachable from a source. Dynamic
verification tries to prove it. When verification is on, Nyx builds a small
harness around each finding, runs it in a sandbox against a curated payload
set, and stamps the result onto `evidence.dynamic_verdict`.

It is a second signal, not a replacement for review. A `Confirmed` verdict
means Nyx triggered the sink in its harness with an attacker-controlled
payload and proved the benign control stayed clean. `NotConfirmed` means the
harness ran but nothing fired. Neither verdict closes a finding on its own.

Default Nyx builds include the `dynamic` feature. Custom
`--no-default-features` builds run static-only unless rebuilt with
`--features dynamic`.

## How confirmation works

Every cap that can be verified ships a curated corpus of payload pairs: at
least one vulnerable payload and one benign control. The verifier runs both
through the same harness and compares.

- The vulnerable payload must fire the sink. A payload "fires" when an
  oracle predicate matches the observed behavior, not when a string appears
  in the output.
- The benign control must stay clean. It exercises the same code path with a
  value that a correct implementation handles safely.

A finding is `Confirmed` only when at least one vulnerable payload fires and
every paired benign control stays clean. This differential rule is what keeps
the verifier from confirming a finding just because the harness echoed an
input.

Oracles are behavioral, scoped to the cap:

| Cap | Oracle | What it observes |
| --- | --- | --- |
| Command/code injection | stub event | the harness's exec boundary saw the injected command |
| SQL injection | stub event | the SQL boundary saw the injected clause |
| SSRF, data exfil | outbound host | the request left for a host outside the allowlist |
| Path traversal | stub event | the filesystem boundary opened a path outside the root |
| Template injection | template eval | `{{7*7}}` rendered as `49`, not echoed as text |
| Deserialization | gadget marker | a non-allowlisted class was resolved during decode |
| XXE | entity expansion | an external entity was expanded by the parser |
| LDAP / XPath injection | result count | the malicious filter returned more rows than the benign one |
| Header / CRLF | header split | an injected `\r\n` split or added a response header |
| Open redirect | redirect host | the `Location` header pointed off-origin |
| Prototype pollution | canary touch | a property write reached `Object.prototype` |
| Weak crypto | key entropy | the produced key fit inside a 16-bit search space |
| JSON parse abuse | parse depth | the parser accepted a depth past its limit |
| IDOR | ownership cross | the read crossed from the caller's id to another owner's |

Every canary is derived per-run from `BLAKE3(spec_hash || run_nonce)`, so it is
unique per finding, collision-resistant against ambient harness output, and
never appears on the host.

## Running it

```bash
nyx scan                      # verifies Medium and High confidence findings
nyx scan --no-verify          # static analysis only
nyx scan --verify             # explicit form of the default behavior
nyx scan --verify-all-confidence   # also verify Low-confidence findings
```

Use `--no-verify` for fast local checks or editor workflows. Keep
verification on for CI when scan time allows it. `--verify-all-confidence` is
slower and noisier; reach for it when tuning payloads or chasing coverage.

## Verdicts

| Status | Meaning |
| --- | --- |
| `Confirmed` | A vulnerable payload fired the sink and every benign control stayed clean. |
| `PartiallyConfirmed` | The sink was reached but no oracle marker was observed. The exploit chain did not complete. Treat as a strong lead, not a proof. |
| `NotConfirmed` | The harness ran but no payload fired. The path is likely infeasible or the corpus does not cover this shape. The original finding stays open until reviewed. |
| `Inconclusive` | Nyx could not finish the check. Carries a typed reason (build failed, spec derivation failed, sandbox error, policy denied, and others). |
| `Unsupported` | Nyx did not attempt the finding. Carries a typed reason (language unsupported, entry kind unsupported, no payloads for cap, confidence below threshold, no sound oracle). |

When a `Confirmed` sink sits behind a recognized input-validation or
output-sanitization guard (Spring `@PreAuthorize`, Express `helmet`, Nest
`@UseGuards`, Django `@permission_classes`), the verdict demotes to
`ConfirmedWithKnownGuard` and the guard names land on
`differential.known_guards`. Authentication-only filters do not trigger the
demotion, since they do not mitigate injection.

`PartiallyConfirmed` is deliberate. It marks the cases where engine work can
ratchet without the tool overstating what it proved.

## Capability coverage

Caps split into two groups. Data-style injection (SQL, command, path,
SSRF, XSS) uses language-neutral payload bytes (`' OR 1=1--`, `../../etc/passwd`,
a callback URL), so the harness emitter for any language can carry them. The
caps below have language-specific payloads (a Java gadget chain is not a
Python pickle), so each language is curated on its own.

A checkmark means a tuned per-language payload set ships for that cell. Cells
without a checkmark in the data-style rows still run, falling back to the
language-neutral payload union.

| Cap | Py | JS | TS | Java | PHP | Ruby | Go | Rust | C | C++ |
| --- | -- | -- | -- | ---- | --- | ---- | -- | ---- | - | --- |
| Command / code injection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SQL injection | union | union | union | union | union | union | union | ✓ | union | union |
| Path traversal | union | union | union | union | union | union | union | ✓ | union | union |
| SSRF | union | union | union | union | union | union | union | ✓ | union | union |
| XSS | union | union | union | union | union | union | union | ✓ | union | union |
| Format string | | | | | | | | | ✓ | |
| Deserialization | ✓ | | | ✓ | ✓ | ✓ | | | | |
| Template injection | ✓ | ✓ | | ✓ | ✓ | ✓ | | | | |
| XXE | ✓ | | | ✓ | ✓ | ✓ | ✓ | | | |
| LDAP injection | ✓ | | | ✓ | ✓ | | | | | |
| XPath injection | ✓ | ✓ | | ✓ | ✓ | | | | | |
| Header / CRLF | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| Open redirect | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| Prototype pollution | | ✓ | ✓ | | | | | | | |
| Weak crypto | ✓ | | | ✓ | ✓ | | ✓ | ✓ | | |
| JSON parse abuse | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| IDOR | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| Data exfiltration | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ | | |

`ENV_VAR`, `SHELL_ESCAPE`, and `URL_ENCODE` are source and sanitizer caps with
no externally observable sink behavior. They route to
`Unsupported(SoundOracleUnavailable)` rather than counting as a missing-payload
gap.

## Framework adapters

Adapters bind a function to its external entry surface so the harness can
drive the real entry point (an HTTP request through the framework, a published
message, a scheduled fire) instead of calling the function in isolation.
Middleware and request validation participate in the verdict that way.

| Language | HTTP routers | Other surfaces |
| --- | --- | --- |
| Python | Flask, Django, FastAPI, Starlette | Jinja2, pickle, LDAP, Celery, Kafka, SQS, Pub/Sub, RabbitMQ, Django Channels, Socket.IO, Django middleware, Django + Flask migrations |
| JavaScript | Express, Koa, NestJS, Fastify | Handlebars, Apollo + Relay GraphQL, lodash.merge + JSON deep-assign, Socket.IO, SQS, Express middleware, Knex + Prisma + Sequelize migrations |
| TypeScript | NestJS | Object.assign + lodash.merge + JSON deep-assign |
| Java | Spring, Quarkus, Micronaut, Jakarta Servlet | Thymeleaf, ObjectInputStream, Spring LDAP, Kafka, SQS, RabbitMQ, Quartz, Spring middleware, Flyway + Liquibase migrations |
| PHP | Laravel, Symfony, CodeIgniter | Twig, unserialize, LDAP, Laravel middleware, Laravel migrations |
| Ruby | Rails, Sinatra, Hanami | ERB, Marshal, Sidekiq, ActionCable, Rails middleware, Rails migrations |
| Go | Gin, Echo, Fiber, Chi | gqlgen GraphQL, NATS, Pub/Sub, go-migrate migrations |
| Rust | Axum, Actix, Rocket, Warp | Juniper GraphQL, Refinery + SQLx migrations |
| C / C++ | none | argv / stdin entry only |

Adapters are sanitizer-aware. An XXE, header-injection, open-redirect, SSTI,
LDAP, XPath, deserialization, crypto, or data-exfil adapter declines the
binding when the surrounding source visibly hardens the call: a parser set to
`disallow-doctype-decl` or `resolve_entities=False`, a value routed through
`LdapEncoder.filterEncode` or `escape_filter_chars`, a weak primitive swapped
for `secrets.token_bytes` or `crypto.randomBytes` or `SecureRandom`, or a
redirect host checked against an allowlist. That cuts adapter false positives
without losing the genuinely dangerous calls.

## Entry points

The verifier knows how to stand up these entry shapes:

`Function`, `HttpRoute`, `CliSubcommand`, `LibraryApi`, `ClassMethod`,
`MessageHandler`, `ScheduledJob`, `GraphQLResolver`, `WebSocket`,
`Middleware`, `Migration`.

`ClassMethod` walks constructor parameters and builds the receiver, preferring
a default constructor and otherwise stubbing dependencies (`MockHttpClient`,
`MockDatabaseConnection`, `MockLogger`) up to a bounded depth. `MessageHandler`
boots an in-sandbox broker stub on loopback and publishes the payload.
`Migration` runs under a database-in-test-mode profile with no real
connection. An entry kind a language emitter does not yet support produces
`Inconclusive(EntryKindUnsupported)` with a hint, never a silent skip.

## Sandbox backends

```bash
nyx scan --backend auto      # docker when available, else process (default)
nyx scan --backend docker    # require docker
nyx scan --backend process   # run on the host with weaker isolation
nyx scan --unsafe-sandbox    # alias for --backend process
nyx scan --harden strict     # full process-backend lockdown
```

Docker is the preferred backend. It mounts only the entry file's directory and
blocks outbound network by default. Nyx binds a loopback OOB listener at scan
start for callback-style payloads (SSRF, blind SSTI). When the bind succeeds,
Docker switches to bridge networking with a host-gateway route so the harness
can reach the listener; OOB payloads are skipped if the bind fails.

The process backend runs on the host. It is useful for development and
machines without Docker, and it does not provide the same isolation. Hardening
profiles apply to it:

- `standard` (default): no-new-privs plus a memory rlimit on Linux. No
  `sandbox-exec` wrap on macOS.
- `strict`: namespace unshare, chroot to the workdir, and a default-deny
  seccomp filter on Linux; `sandbox-exec -f <cap>.sb` on macOS. Opt-in,
  because interpreted Linux harnesses can SIGSYS until the per-language seccomp
  allowlists are widened.

Every sink under test passes through the policy deny rules in
`src/dynamic/policy.rs` before the harness builds. Network egress, writes
outside the sandbox root, and process spawns can be denied per rule, and the
deny decision lands in the trace.

## Performance

Verification adds a harness build and a sandbox run per finding. Two pieces of
infrastructure keep that affordable at corpus scale.

Per-language build pools reuse a warm toolchain across findings instead of
cold-starting one each time. Java runs a long-lived `javac` daemon; Node, PHP,
Ruby, Go, Rust, C, and C++ reuse shared module, package, and object caches;
Python layers a read-only venv with a warmed bytecode cache. The target is a
P50 harness build at or under 200ms hot and 1.5s cold, with an OWASP-scale run
finishing in 10 minutes on the dev reference machine.

Copy-on-write workdirs (`clonefile` on macOS, `reflink` or `copy_file_range`
on Linux) replace per-finding file copies, and the worker pool routes findings
into per-cap concurrency lanes so a slow `DESERIALIZE` harness does not block
fast `SSRF` ones.

The CI ship gate holds the with-verify to static-only wall-clock ratio at or
under 1.5x on `benches/fixtures/`. If a change pushes it past that, the gate
fails.

## Repro artifacts

Confirmed findings write a hermetic bundle:

```text
~/.cache/nyx/dynamic/repro/<spec_hash>/
```

The bundle carries the harness spec, payload, expected output, trace, and a
`reproduce.sh`. When the toolchain is pinned in `tools/image-builder/images.toml`
it also writes a `docker_pull.sh`.

```bash
cd ~/.cache/nyx/dynamic/repro/<spec_hash>
./reproduce.sh
./reproduce.sh --docker
```

Use the Docker form when the bundle records a pinned image or when host
toolchains differ from the original run.

## Configuration

```toml
[scanner]
verify                = true        # run dynamic verification after static analysis
verify_all_confidence = false       # include findings below Confidence::Medium
verify_backend        = "auto"      # auto | docker | process | firecracker
harden_profile        = "standard"  # standard | strict
```

Set `verify = false` to make scans static-only unless the command line
overrides it. See [Configuration](configuration.md) for the full table.

## Event log

Nyx writes verdict events to:

```text
~/.cache/nyx/dynamic/events.jsonl
```

Each line is a JSON object with a versioned envelope:

```json
{
  "schema_version": 1,
  "nyx_version": "0.8.0",
  "corpus_version": "15",
  "kind": "verdict",
  "ts": "2026-06-01T18:42:09Z",
  "finding_id": "a3b1...",
  "spec_hash": "9f4e...",
  "lang": "python",
  "cap": "SQL_QUERY",
  "status": "Confirmed",
  "toolchain_id": "python-3.11",
  "toolchain_match": "exact",
  "duration_ms": 312,
  "build_attempts": 1
}
```

The literal `nyx_version` and `corpus_version` values shift between releases;
see `crate::dynamic::telemetry::CORPUS_VERSION` for the active payload-corpus
version your binary writes.

| Field | Meaning |
| --- | --- |
| `schema_version` | Event schema version. Readers reject mismatches. |
| `nyx_version` | Version of the Nyx binary that wrote the event. |
| `corpus_version` | Payload corpus version used for the verdict. |
| `kind` | `verdict` or `rank_delta`. Feedback rows use an `event: "verify_feedback"` field instead. |
| `ts` | Write time in RFC 3339 format. |
| `finding_id` | Stable finding identifier. |
| `spec_hash` | Hash of the harness spec. |
| `lang` | Language slug, or `unknown` when spec derivation failed. |
| `cap` | Sink capability, such as `SQL_QUERY` or `CODE_EXEC`. |
| `status` | `Confirmed`, `PartiallyConfirmed`, `NotConfirmed`, `Inconclusive`, or `Unsupported`. |
| `inconclusive_reason` | Present when `status` is `Inconclusive`. |

If the schema changes, move or delete the old `events.jsonl` before reading it
with the new binary. Programmatic readers should use
`crate::dynamic::telemetry::read_events(path)`.

### Sampling

`[telemetry]` in `nyx.toml` controls event retention:

```toml
[telemetry]
keep_all_confirmed    = true
keep_all_inconclusive = true
sample_rate_other     = 1.0
```

`sample_rate_other` accepts `0.0` to `1.0` and applies to `NotConfirmed` and
`Unsupported` verdicts. The decision is deterministic for a given `spec_hash`.
Confirmed, Inconclusive, and rank-delta events are always kept by default.

Set `NYX_NO_TELEMETRY=1` to disable event writes.

## Feedback

To record a bad verdict:

```bash
nyx verify-feedback <finding_id> --wrong "reason"
```

Feedback is written to the local event log. Nyx does not upload it.

## Determinism

Every random source is seeded from the spec hash, so two runs of the same spec
produce identical payloads and identical verdicts. `scripts/check_no_unseeded_rand.sh`
audits the tree for unseeded `rand` usage on every CI run.

## Limitations

- The harness drives the finding's enclosing entry function when one is
  derivable, routing the payload to the tainted parameter, so a guard in the
  code around the sink (a merge target built with `Object.create(null)`, an
  `ObjectInputStream` subclass whose `resolveClass` enforces an allowlist, a
  const-name check before `Marshal.load`) runs first and participates in the
  verdict. The build-time choice is recorded on the verify trace as
  `entry_invocation` (`mode=entry_function` or `mode=direct_sink`). When no
  enclosing entry can be derived the harness falls back to driving the sink
  directly, and that fallback can over-confirm a guard it never executes. Read
  a `direct_sink` `Confirmed` as "this sink is reachable and fires on attacker
  input," not "this exact code path has no in-line mitigation." Framework-level
  guards (auth middleware, helmet) are also recognized and demote to
  `ConfirmedWithKnownGuard`.
- Per-language payload curation is uneven. Command and code injection ship for
  all ten languages; the classic data-style injection caps (SQL, path
  traversal, SSRF, XSS) ship a tuned set for Rust and fall back to a
  language-neutral payload union elsewhere; the framework-specific caps are
  curated for the languages where they occur. The matrix above is the precise
  state.
- A `NotConfirmed` verdict is not a clean bill. It means the harness did not
  fire, which can be an infeasible path or a corpus that does not cover the
  shape. Keep reviewing `NotConfirmed` findings.
- The process backend is weaker isolation than Docker. Use `--backend docker`
  or `--harden strict` for untrusted code, and never `--unsafe-sandbox` in CI.
- Real-corpus acceptance rows (OWASP Benchmark, NodeGoat, Juice Shop, and the
  polyglot set) self-skip in CI unless the corresponding `NYX_*_CORPUS`
  environment variable points at a checkout. They are not vendored into the
  repo.
- C and C++ have no framework adapters. Findings in those languages verify
  through `argv` and `stdin` entry points only.

## Browser UI

`nyx serve` shows dynamic verdicts on finding detail pages, uses them in
ranking, and can compare verdict changes between saved scans. See
[Output formats](output.md) for the `dynamic_verdict` schema.

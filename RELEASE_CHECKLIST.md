# Release checklist: 0.8.0 (dynamic verification)

Maintainer-facing gate for cutting `0.8.0`. The release ships the dynamic
verifier (Tracks J through S of `.pitboss/play/plan.md`). Sign-off requires
every row below green, and every CI matrix row green for at least three
consecutive runs on `master`.

Legend: `[x]` verified locally on the dev reference machine, `[ ]` confirmed
by CI (must hold for three consecutive runs before tagging).

## Cross-cutting invariants

- [x] `cargo check --no-default-features --features serve` green.
- [x] `cargo check --features dynamic` green.
- [x] `cargo nextest run --features dynamic` green: 6545 passed, 0 failed, 16 skipped.
- [x] Determinism: every payload RNG seeds from `spec.spec_hash`; oracle canaries derive from `BLAKE3(spec_hash || run_nonce)`. `scripts/check_no_unseeded_rand.sh` audits the tree.
- [x] Observability: each new code path emits a `VerifyTrace` event and a typed `Inconclusive` / `Unsupported` reason.
- [x] Security: every sink-under-test routes through `src/dynamic/policy.rs` deny rules; no phase weakened the seccomp / `.sb` profile sets.
- [ ] Performance: default `nyx scan` (no `--verify`) latency does not regress.

## Ship gates (`scripts/m7_ship_gate.sh`)

- [x] Gate 1: static-only scan green on `tests/benchmark/corpus`.
- [x] Gate 2: `cargo nextest run --features dynamic` green (covers Gate 4 + Gate 5 binaries).
- [x] Gate 3: with-verify / static-only wall-clock ratio <= 1.5x on `benches/fixtures/`.
- [x] Gate 4: SARIF schema validation on every dynamic verdict variant.
- [x] Gate 5: layering boundary test green.
- [ ] Gate 6: Java OWASP Benchmark v1.2 `--verify` acceptance (wall-clock <= 15 min CI, per-cap precision >= 0.85 / recall >= 0.40, per-`(cap, lang)` budget). Self-skips without `NYX_OWASP_CORPUS`.
- [ ] Gate 7: NodeGoat + Juice Shop acceptance. Self-skips without `NYX_NODEGOAT_CORPUS` / `NYX_JUICESHOP_CORPUS`.
- [ ] Gate 8: RailsGoat / DVWA / DVPWA / gosec / RustSec acceptance. Self-skips without the matching `NYX_*_CORPUS`.

Gates 6 through 8 run against real corpora that are not vendored into the repo.
They are enforced in the `eval` workflow with the corpora cached on the CI
runner. Locally they self-skip with a clear message.

## CI matrix rows (must be green three runs running)

`ci.yml`:
- [ ] frontend, rustfmt, clippy-stable, cargo-deny, unused-deps, third-party-licenses
- [ ] docs-fresh (`nyx-docgen` output committed), rustdoc
- [ ] rust-beta-build, msrv
- [ ] rust-stable-test-linux-without-docker, rust-stable-test-linux-with-docker (`cargo nextest run --all-features`)

`dynamic.yml` (each runs `cargo nextest run --features dynamic`):
- [ ] linux-process-only
- [ ] linux-with-docker
- [ ] macos

`eval.yml`:
- [ ] owasp (Gate 6)
- [ ] jsts matrix: nodegoat, juiceshop (Gate 7)
- [ ] polyglot matrix: railsgoat, dvwa, dvpwa, gosec, rustsec (Gate 8)

## Docs and metadata

- [x] `Cargo.toml` version bumped to `0.8.0`; `Cargo.lock` regenerated.
- [x] `docs/dynamic.md` rewritten: cap x lang matrix, framework adapter table, oracle table, performance budgets, limitations.
- [x] `README.md` dynamic verification section + docs link.
- [x] `CHANGELOG.md` `[0.8.0]` entry covers Tracks J through S.
- [x] Stray version strings updated (README GitHub Action pin, telemetry doc example).

## Known limitations carried into 0.8.0

These are documented in `docs/dynamic.md` and accepted for the MVP. They are
not release blockers, but the release notes should not overstate the verifier.

- **Guarded-sink over-confirmation (resolved on `dynamic`).** The synthesized
  harness now drives the finding's enclosing entry function when one is
  derivable, routing the payload to the tainted parameter, so a guard that
  lives in the caller (a `Object.create(null)` merge target, an allowlisting
  `resolveClass`, a const-name check before `Marshal.load`) runs first and
  participates in the verdict. The build-time entry-vs-sink choice is recorded
  on the verify trace as `entry_invocation`. When no enclosing entry can be
  derived the harness falls back to driving the sink directly, which can still
  over-confirm a guard it never executes. On the in-house fixture set the
  verify scan now confirms the 8 genuine vulnerabilities and reads
  `NotConfirmed` on all 4 negative-control files.
- **In-house confirmed rate is modest.** A `--verify` scan of
  `tests/dynamic_fixtures` (process backend) lands 8 Confirmed / 15
  NotConfirmed / 115 Inconclusive / 137 Unsupported of 275. The Unsupported
  bulk is `SoundOracleUnavailable` (ENV_VAR / SHELL_ESCAPE / URL_ENCODE source
  and sanitizer caps, correct by design); the Inconclusive bulk is
  `SpecDerivationFailed` on benign and scaffolding fixtures with no derivable
  flow. The authoritative confirmed / precision / recall numbers come from the
  real-corpus gates (6 through 8), which require the corpora.
- **Real-corpus gates unverified locally.** Gates 6 through 8 self-skip without
  `NYX_*_CORPUS`. The >= 40% confirmed and >= 0.85 precision targets are
  enforced only in the `eval` workflow.

## Tag

- [ ] Three consecutive green CI runs on `master` confirmed.
- [ ] Real-corpus gates (6 through 8) green in the `eval` workflow with corpora wired.
- [ ] `git tag v0.8.0` and push; `release-build.yml` publishes the binaries and `SHA256SUMS`.

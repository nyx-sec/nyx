# sb-trace seeds

This directory holds per-capability allowlist seeds for the macOS
sandbox-exec deny-default rollout.

## What the seeds are

Each `.allow` file is a fragment of sandbox-exec profile syntax (one
or more `(allow ...)` directives, plus comments).  At runtime,
`src/dynamic/sandbox/process_macos.rs::profile_path` consults the
`NYX_SB_DENY_DEFAULT` environment variable; when set, it locates the
seed for the active capability, rewrites the baked profile's
`(allow default)` directive to `(deny default)`, and appends the seed
body verbatim.  Sandbox-exec resolves later directives over earlier
ones, so the appended allow rules stack on top of the deny baseline.

The splice path lives in `process_macos.rs::splice_deny_default`; it
is pure, unit-tested, and a no-op when the seed for a capability is
missing.  Misconfiguration cannot brick the sandbox-exec backend.

## How the seeds get generated

Run `tools/sb-trace.sh` from a macOS host that has the interpreters
on `$PATH`.  The script materialises each `.sb` profile with
`(allow default)` rewritten to `(deny default)`, runs each
per-language probe under `sandbox-exec`, queries
`log show --predicate 'eventMessage CONTAINS "(<pid>) deny"'` for the
kernel deny records the probe triggered, converts each deny line
into the matching `(allow ...)` rule, appends it to the profile, and
re-runs the probe.  The loop stops when an iteration produces no new
denies (the probe ran cleanly under the accumulated allows) or when
the kernel's per-tuple dedup window swallows every remaining record.

The PID-targeted log query sidesteps the dedup window: each iteration's
probe runs as a new process with a fresh PID, so the kernel emits a
fresh deny record even when the operation tuple repeats.  The older
`(trace "<file>")` mechanism is silently ignored on macOS 26+ and is
no longer used.

Output:

    tools/sb-trace/<cap>.allow         (committed after hand-review)

After a run, hand-review each `.allow` seed before committing.  The
emitted seeds usually need two passes:

1.  Replace host-specific literal paths with regex matches.  For
    instance `/Users/eli/.pyenv/versions/3.11/lib/python3.11/...`
    should become a regex anchored on `^/Users/[^/]+/\\.pyenv/`.
2.  Group related rules onto one `(allow <op> a b c ...)` directive
    when the targets share semantics.

The parser logic that turns one deny line into one allow rule is
exercised in CI via `tests/sb_trace_script.rs`, which invokes
`tools/sb-trace.sh --selftest` — a mode that runs the parser against
canned input and exits non-zero on any mismatch.

## Activating a seed at runtime

Set both env vars before invoking `nyx`:

    export NYX_SB_DENY_DEFAULT=1
    export NYX_SB_SEED_DIR="$(pwd)/tools/sb-trace"

The seed dir defaults to `tools/sb-trace/` relative to the workspace
root, so the second env var is only needed when running outside the
workspace.

The runtime splice is opt-in.  Production builds leave the baked
`(allow default)` body intact unless the operator flips the env var.

## Verifying a seed end-to-end

The smoke test `deny_default_seed_loads_under_strict` in
`tests/sandbox_hardening_macos.rs` exercises the splice through the
production call site.  It writes a synthetic seed to a tempdir,
points `NYX_SB_SEED_DIR` at it, calls `profile_path`, and asserts the
materialised file contains both `(deny default)` and the synthetic
seed body.

For a real-host smoke test against a generated seed, run:

    NYX_SB_DENY_DEFAULT=1 \
    NYX_SB_SEED_DIR="$(pwd)/tools/sb-trace" \
    cargo nextest run --features dynamic --test sandbox_hardening_macos

When every cap profile has a seed that lets the python3 / node
cold-start clear, the macOS strict-mode acceptance row in
`.github/workflows/dynamic.yml` flips from "ships (allow default)" to
"ships deny-default by default" — that's the closing condition for
the Phase 18 follow-up.

# scripts

Local helpers for repo-wide checks and a couple of one-off tools.

| Script                   | What it does                                                                                  |
| ------------------------ | --------------------------------------------------------------------------------------------- |
| `fix.sh`                 | Apply all auto-fixes (clippy, fmt, eslint, prettier), then run tests.                         |
| `check.sh`               | Verify only (no fixes). Mirrors the GitHub Actions CI workflow.                               |
| `cached-cargo-test.sh`   | Wrap `cargo test` with a source-hash cache; concurrent invocations of the same args share one run. |
| `capture-screenshots.mjs`| Capture the README stills and demo GIF from a running `nyx serve`. Needs Playwright and ffmpeg. |
| `frame-screenshots.py`   | Wrap a PNG in the brand mint-cyan gradient. Called by `capture-screenshots.mjs` as its final phase, but can be run standalone. |

Fixers stream their output (so you can see what changed); tests run quietly and
only show output if they fail. Both scripts print a green/red summary at the end
and exit non-zero if any step failed.

## Usage

```bash
./scripts/fix.sh                # fix everything + run tests
./scripts/fix.sh --no-tests     # just apply fixes
./scripts/fix.sh --rust-only    # skip frontend
./scripts/fix.sh --frontend-only

./scripts/check.sh              # verify everything (CI-equivalent)
./scripts/check.sh --rust-only
```

Scripts can be run from any directory; they resolve the repo root from their
own location.

## Cached cargo test

Wraps `cargo test`. The first run executes normally and records its output
keyed by a hash of the source tree. Later runs with the same args and an
unchanged tree return the cached output. Concurrent callers share a single
cargo run via a mkdir lock.

```bash
./scripts/cached-cargo-test.sh --lib
./scripts/cached-cargo-test.sh --tests
FORCE_CARGO=1 ./scripts/cached-cargo-test.sh --lib   # bypass cache
```

Use it for full-suite invocations. Narrow per-test runs (`cargo test
some_function`) are fast on their own and just clutter the cache.

## Capture screenshots

Regenerates `assets/screenshots/*.png` and `assets/screenshots/demo.gif` for
the README and `docs/`. Requires Playwright, ffmpeg, and Python 3 with
Pillow on PATH, plus a running `nyx serve` on `$NYX_URL` (default
`http://127.0.0.1:9876`). The served scan root must have no prior scans.

```bash
node scripts/capture-screenshots.mjs --stills   # only PNGs
node scripts/capture-screenshots.mjs --gif      # only the GIF
node scripts/capture-screenshots.mjs --all      # both
```

The script writes a synthetic demo to `$SCAN_ROOT` (default
`/tmp/nyx-demo-app`). V1 has four endpoints and produces a 5-hop CMDi
taint flow that the GIF drills into. After scan #1 the script overwrites
the demo with V2 (just that one flow) and runs scan #2 via the API, so
the overview trend chart shows findings going down.

Stills are captured in two phases:

- After scan #1 (more findings): `serve-findings-list.png`,
  `serve-finding-detail.png`.
- After scan #2 (trend established): `serve-overview.png`,
  `serve-triage.png`, `serve-explorer.png`, `serve-scans.png`,
  `serve-scan-detail.png`, `serve-rules.png`, `serve-config.png`.

Then `frame-screenshots.py` runs over every captured PNG and wraps it in
the brand mint-led four-corner gradient (1800x1113 outer, 1600x992 inner,
12px rounded corners: TL `#72f3d7`, TR `#ff6aa2`, BL `#f8c56b`, BR
`#4cc9ff`). Finally,
`docs/serve-overview.png` is copied to the top-level `overview.png`
because that is the path the README references.

GIF storyboard:

1. Empty dashboard with the "Run your first scan" prompt.
2. Click `Start Scan` in the header bar to open the modal.
3. Confirm in the modal and wait for the scan to finish.
4. Back to the overview, scroll down through the cards, scroll back.
5. Click `Findings` in the sidebar.
6. Click the 5-hop taint row.
7. On the finding detail, expand Evidence, Analysis Notes, and
   Confidence Reasoning.
8. Open the triage status dropdown and dismiss it.
9. Navigate to `/debug/call-graph` for the closing visual.

To frame an existing PNG without re-capturing:

```bash
python3 scripts/frame-screenshots.py path/to/foo.png [...]
```

Run with no args to re-frame every PNG under `assets/screenshots/`.

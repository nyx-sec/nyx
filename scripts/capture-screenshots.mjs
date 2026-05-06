#!/usr/bin/env node
/**
 * Capture stills + a demo GIF of the Nyx dashboard for the README/docs.
 *
 * The demo source is embedded below (V1_SERVER + V2_SERVER) so the
 * storyboard is reproducible from this file alone.  V1 has 4 endpoints
 * and yields ~6 findings (one of them a 5-hop CMDi taint flow that
 * the GIF drills into); V2 keeps only that flow so scan #2 has fewer
 * findings than scan #1 and the overview trend chart shows a
 * downward slope.
 *
 * Phases:
 *   1. setup        — write V1 to SCAN_ROOT, ensure server reachable
 *   2. gif (opt)    — record the storyboard against a fresh DB; this
 *                     also drives scan #1 via the UI
 *   3. scan #1      — if --gif didn't run, kick off scan #1 via API
 *   4. stills/p1    — capture pages whose content benefits from many
 *                     findings (findings list, finding detail)
 *   5. patch+scan2  — overwrite SCAN_ROOT with V2 + run scan #2 via API
 *   6. stills/p2    — capture pages whose content benefits from a
 *                     two-scan history (overview trend, scans list,
 *                     scan detail) plus the static-ish ones
 *                     (triage, explorer, rules, config)
 *   7. frame        — composite the brand mint-cyan gradient around every
 *                     captured PNG via scripts/frame-screenshots.py
 *
 * Prerequisites (script asserts each before starting):
 *   - playwright installed (npx playwright)
 *   - ffmpeg on PATH (palette-based GIF conversion)
 *   - python3 + Pillow on PATH (frame compositing)
 *   - nyx serve running on $NYX_URL (default http://127.0.0.1:9876)
 *   - the served scan root is empty of prior scans (system DB wiped)
 *
 * Usage:
 *   node scripts/capture-screenshots.mjs --stills   # PNGs only
 *   node scripts/capture-screenshots.mjs --gif      # GIF only
 *   node scripts/capture-screenshots.mjs --all      # both, in one orchestrated run
 *
 * Output (under assets/screenshots/):
 *   demo.gif                       (~25–30s serve walkthrough)
 *   demo_raw.gif                   (unframed source — saved before compositing)
 *   cli-scan.gif                   (~15s CLI scan walkthrough — requires vhs on PATH)
 *   cli-scan_raw.gif               (unframed source)
 *   overview.png                   (mirror of docs/serve-overview.png; used by README)
 *   *_raw.png / *_raw.gif          (unframed originals for every captured asset)
 *   docs/serve-overview.png        (overview after scan #2 — trend going down)
 *   docs/serve-findings-list.png   (post-scan-#1 list with multiple highs)
 *   docs/serve-finding-detail.png  (5-hop taint flow visualizer)
 *   docs/serve-triage.png
 *   docs/serve-explorer.png
 *   docs/serve-scans.png
 *   docs/serve-scan-detail.png
 *   docs/serve-rules.png
 *   docs/serve-config.png
 */
import { execFileSync, spawn } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { extname, join } from 'node:path';
import process from 'node:process';

const URL_BASE  = process.env.NYX_URL  || 'http://127.0.0.1:9876';
const SCAN_ROOT = process.env.SCAN_ROOT || '/tmp/nyx-demo-app';
const OUT_DIR   = process.env.OUT_DIR  || '/Users/elipeter/nyx/assets/screenshots';
const FRAMER    = process.env.FRAMER   || '/Users/elipeter/nyx/scripts/frame-screenshots.py';
const NYX_BIN   = process.env.NYX_BIN  || '/Users/elipeter/nyx/target/release/nyx';
// Sibling marketing site that mirrors a small subset of these assets.
// Set NYXSCAN_DIR=skip to disable the mirror step.
const NYXSCAN_DIR = process.env.NYXSCAN_DIR || '/Users/elipeter/nyxscan.dev/assets/screenshots';
const VIEW = { width: 1600, height: 992 };
const COLOR_SCHEME = 'light';

const args = new Set(process.argv.slice(2));
const wantStills = args.has('--stills') || args.has('--all');
const wantGif    = args.has('--gif')    || args.has('--all');
const wantCli    = args.has('--cli')    || args.has('--all');
const wantCombo  = args.has('--combo')  || args.has('--all');
if (!wantStills && !wantGif && !wantCli && !wantCombo) {
  console.error('usage: capture-screenshots.mjs [--stills|--gif|--cli|--combo|--all]');
  process.exit(2);
}

mkdirSync(join(OUT_DIR, 'docs'), { recursive: true });

// Demo source ----------------------------------------------------------------

const V1_SERVER = `import express from 'express';
import { exec } from 'child_process';
import fs from 'fs';

const app = express();
app.use(express.json());

// Lookup endpoint. Multi-hop CMDi: req.params.user → trim → flag → cmd → exec.
app.get('/lookup/:user', (req, res) => {
  const raw = req.params.user;
  const cleaned = raw.trim();
  const flag = \`--user=\${cleaned}\`;
  const cmd = \`whois \${flag} --verbose\`;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

// SSRF: req.query.url → fetch.
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const response = await fetch(target);
  const body = await response.text();
  res.send(body);
});

// Path traversal / unsafe file read.
app.get('/file', (req, res) => {
  const requested = req.query.path;
  const body = fs.readFileSync(requested, 'utf8');
  res.send(body);
});

// Login endpoint with weak (Math.random) session id.
app.post('/login', (req, res) => {
  const sid = Math.random().toString(36).slice(2);
  res.cookie('sid', sid).json({ ok: true });
});

app.listen(3000);
`;

const V2_SERVER = `import express from 'express';
import { exec } from 'child_process';

const app = express();
app.use(express.json());

// Lookup endpoint. Multi-hop CMDi: req.params.user → trim → flag → cmd → exec.
app.get('/lookup/:user', (req, res) => {
  const raw = req.params.user;
  const cleaned = raw.trim();
  const flag = \`--user=\${cleaned}\`;
  const cmd = \`whois \${flag} --verbose\`;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000);
`;

const PACKAGE_JSON = `{ "name": "nyx-demo-app", "version": "1.0.0", "type": "module", "main": "src/server.js" }
`;

const AUTH_JS = `import jwt from 'jsonwebtoken';
const SECRET = 'super-secret-key';
export function sign(p) { return jwt.sign(p, SECRET); }
export function verify(t) { return jwt.verify(t, SECRET); }
`;

function writeDemo(variant) {
  mkdirSync(join(SCAN_ROOT, 'src'), { recursive: true });
  writeFileSync(join(SCAN_ROOT, 'package.json'), PACKAGE_JSON);
  writeFileSync(
    join(SCAN_ROOT, 'src/server.js'),
    variant === 'v2' ? V2_SERVER : V1_SERVER,
  );
  const authPath = join(SCAN_ROOT, 'src/auth.js');
  if (variant === 'v1') writeFileSync(authPath, AUTH_JS);
  if (variant === 'v2' && existsSync(authPath)) unlinkSync(authPath);
}

// Server helpers -------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(path) {
  const res = await fetch(URL_BASE + path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

async function csrfToken() {
  const r = await fetch(URL_BASE + '/api/session');
  return (await r.json()).csrf_token;
}

async function waitForServer() {
  for (let i = 0; i < 30; i++) {
    try { await fetchJson('/api/health'); return; } catch { await sleep(250); }
  }
  throw new Error(`nyx serve not reachable at ${URL_BASE}, start it first`);
}

async function startScanViaApi(token) {
  const res = await fetch(URL_BASE + '/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-nyx-csrf': token },
    body: '{}',
  });
  if (!res.ok && res.status !== 409) {
    throw new Error(`POST /api/scans: ${res.status} ${await res.text()}`);
  }
}

async function waitForScanComplete(prevScanId, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const overview = await fetchJson('/api/overview').catch(() => null);
    if (
      overview?.latest_scan_id &&
      overview.state !== 'empty' &&
      overview.latest_scan_id !== prevScanId
    ) {
      await sleep(400);
      return overview;
    }
    await sleep(400);
  }
  throw new Error('scan did not complete within deadline');
}

async function currentScanId() {
  const overview = await fetchJson('/api/overview').catch(() => null);
  return overview?.latest_scan_id ?? null;
}

// Storyboard helpers ---------------------------------------------------------

async function findFirstTaintRow(page) {
  return page.locator('tbody tr').filter({ hasText: 'taint-' }).first();
}

// Stills ---------------------------------------------------------------------

async function captureStillsAfterScan1(page) {
  console.error('[stills/p1] findings list');
  await page.goto(URL_BASE + '/findings');
  await page.waitForSelector('tbody tr', { timeout: 15_000 });
  await sleep(1500);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-findings-list.png') });

  console.error('[stills/p1] finding detail (5-hop CMDi)');
  const row = await findFirstTaintRow(page);
  await row.click();
  await page.waitForURL(/\/findings\/\d+/, { timeout: 10_000 });
  await sleep(2200); // flow visualizer animation
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-finding-detail.png') });
}

async function captureStillsAfterScan2(page) {
  console.error('[stills/p2] overview (with 2-scan trend)');
  await page.goto(URL_BASE + '/');
  await page
    .waitForSelector('.health-score-card, [class*="health"]', { timeout: 10_000 })
    .catch(() => {});
  await sleep(1800);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-overview.png') });

  console.error('[stills/p2] triage');
  await page.goto(URL_BASE + '/triage');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1500);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-triage.png') });

  console.error('[stills/p2] explorer');
  await page.goto(URL_BASE + '/explorer');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await page.waitForSelector('.tree-node', { timeout: 10_000 }).catch(() => {});
  await sleep(1000);
  // Expand the src/ folder, then click server.js so the screenshot
  // includes the highlighted source view rather than a "Select a
  // file" prompt.  Best-effort: skip silently if selectors miss.
  const srcDir = page.locator('.tree-node:has-text("src")').first();
  if (await srcDir.count()) {
    await srcDir.click().catch(() => {});
    await sleep(700);
  }
  const serverFile = page.locator('.tree-node:has-text("server.js")').first();
  if (await serverFile.count()) {
    await serverFile.click().catch(() => {});
    await sleep(1500);
  }
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-explorer.png') });

  console.error('[stills/p2] scans list');
  await page.goto(URL_BASE + '/scans');
  await page.waitForSelector('tbody tr', { timeout: 10_000 }).catch(() => {});
  await sleep(1500);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-scans.png') });

  console.error('[stills/p2] scan detail');
  const firstScan = page.locator('tbody tr').first();
  if (await firstScan.count()) {
    await firstScan.click();
    await page.waitForURL(/\/scans\/\d+/, { timeout: 10_000 }).catch(() => {});
    await sleep(1800);
    await page.screenshot({ path: join(OUT_DIR, 'docs/serve-scan-detail.png') });
  }

  console.error('[stills/p2] rules');
  await page.goto(URL_BASE + '/rules');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1800);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-rules.png') });

  console.error('[stills/p2] config');
  await page.goto(URL_BASE + '/config');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1800);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-config.png') });
}

// GIF storyboard -------------------------------------------------------------

async function captureGifFrames(page) {
  console.error('[gif] scene 1: empty dashboard');
  await page.goto(URL_BASE + '/');
  await page.waitForSelector('text=Run your first scan');
  await sleep(2200);

  console.error('[gif] scene 2: open Start Scan modal');
  await page.click('header button:has-text("Start Scan"), .header button:has-text("Start Scan"), button:has-text("Start Scan")');
  await page.waitForSelector('.scan-modal');
  await sleep(1200);

  console.error('[gif] scene 3: confirm scan');
  await page.click('.scan-modal button.btn-primary');
  await page.waitForURL('**/scans', { timeout: 10_000 }).catch(() => {});
  await waitForScanComplete(null);

  console.error('[gif] scene 4: back to overview, scroll');
  await page.goto(URL_BASE + '/');
  await page
    .waitForSelector('.health-score-card, [class*="health"]', { timeout: 10_000 })
    .catch(() => {});
  await sleep(1800);
  await page.evaluate(() => window.scrollBy({ top: 480, behavior: 'smooth' }));
  await sleep(1500);
  await page.evaluate(() => window.scrollBy({ top: 480, behavior: 'smooth' }));
  await sleep(1500);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(800);

  console.error('[gif] scene 5: navigate to Findings');
  await page.click('a.nav-link:has-text("Findings"), .sidebar a:has-text("Findings")');
  await page.waitForURL('**/findings', { timeout: 10_000 });
  await page.waitForSelector('tbody tr', { timeout: 10_000 });
  await sleep(1500);

  console.error('[gif] scene 6: click the 5-hop taint finding');
  const taintRow = await findFirstTaintRow(page);
  await taintRow.click();
  await page.waitForURL(/\/findings\/\d+/, { timeout: 10_000 });
  await sleep(2500);
  // Scroll well into the page so the viewer can see the taint flow
  // animate before the section toggles fire.
  await page.evaluate(() => window.scrollBy({ top: 480, behavior: 'smooth' }));
  await sleep(1600);
  await page.evaluate(() => window.scrollBy({ top: 360, behavior: 'smooth' }));
  await sleep(1600);

  console.error('[gif] scene 7: open the collapsed sections');
  for (const title of ['Evidence', 'Analysis Notes', 'Confidence Reasoning']) {
    const toggle = page.locator(`.section-toggle:has-text("${title}")`).first();
    if (await toggle.count()) {
      await toggle.scrollIntoViewIfNeeded();
      await sleep(500);
      await toggle.click();
      await sleep(1100);
    }
  }
  await sleep(800);

  console.error('[gif] scene 8: mark Investigating');
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(900);
  const statusBtn = page.locator('.status-trigger').first();
  if (await statusBtn.count()) {
    await statusBtn.click().catch(() => {});
    await sleep(1100);
    const investigating = page.locator('text=Investigating').first();
    if (await investigating.count()) {
      await investigating.click().catch(() => {});
      await sleep(1200);
    }
  }

  console.error('[gif] scene 9: triage page (closing visual)');
  await page.goto(URL_BASE + '/triage');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1500);
}

// Combo GIF browser storyboard — data already present from VHS scan phase -----

async function captureGifFramesCombo(page) {
  console.error('[combo/gif] scene 1: overview with scan data');
  await page.goto(URL_BASE + '/');
  await page
    .waitForSelector('.health-score-card, [class*="health"]', { timeout: 15_000 })
    .catch(() => {});
  await sleep(2200);
  await page.evaluate(() => window.scrollBy({ top: 480, behavior: 'smooth' }));
  await sleep(1500);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(900);

  console.error('[combo/gif] scene 2: findings list');
  await page.click('a.nav-link:has-text("Findings"), .sidebar a:has-text("Findings")');
  await page.waitForURL('**/findings', { timeout: 10_000 });
  await page.waitForSelector('tbody tr', { timeout: 10_000 });
  await sleep(1500);

  console.error('[combo/gif] scene 3: 5-hop taint finding detail');
  const taintRow = await findFirstTaintRow(page);
  await taintRow.click();
  await page.waitForURL(/\/findings\/\d+/, { timeout: 10_000 });
  await sleep(2500);
  await page.evaluate(() => window.scrollBy({ top: 480, behavior: 'smooth' }));
  await sleep(1600);
  await page.evaluate(() => window.scrollBy({ top: 360, behavior: 'smooth' }));
  await sleep(1600);

  console.error('[combo/gif] scene 4: open Evidence + Analysis Notes');
  for (const title of ['Evidence', 'Analysis Notes']) {
    const toggle = page.locator(`.section-toggle:has-text("${title}")`).first();
    if (await toggle.count()) {
      await toggle.scrollIntoViewIfNeeded();
      await sleep(500);
      await toggle.click();
      await sleep(1000);
    }
  }
  await sleep(1200);
}

async function convertWebmToGif(webm, gifOut) {
  const palette = '/tmp/nyx-demo-palette.png';
  console.error('[gif] generating palette');
  execFileSync('ffmpeg', [
    '-y', '-ss', '1.0', '-i', webm,
    '-vf', 'fps=15,scale=1280:-1:flags=lanczos,palettegen',
    palette,
  ], { stdio: 'inherit' });
  console.error('[gif] palette → gif');
  execFileSync('ffmpeg', [
    '-y', '-ss', '1.0', '-i', webm, '-i', palette,
    '-lavfi', 'fps=15,scale=1280:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle',
    gifOut,
  ], { stdio: 'inherit' });
}

// CLI capture phase ----------------------------------------------------------
//
// `render-cli.py` orchestrates: force ANSI via `CLICOLOR_FORCE=1`,
// merge consecutive SGR escapes (freeze otherwise honors only the
// last one and drops fg/bg/dim), invoke freeze with the brand-
// consistent window chrome, then crop or pad to exactly 1600x992 so
// the framer never resamples the captured text.

const CLI_RENDERER = '/Users/elipeter/nyx/scripts/render-cli.py';
const VHS_BIN      = process.env.VHS_BIN || 'vhs';
const CLI_GIF      = join(OUT_DIR, 'cli-scan.gif');

function renderCli(shellCommand, outFile) {
  execFileSync(
    'python3',
    [CLI_RENDERER, outFile, shellCommand],
    { stdio: ['ignore', 'inherit', 'inherit'] },
  );
}

// Stage a temporary HOME with a sample nyx.local so that
// `nyx config show` (which now defaults to a diff view) has
// something to display.  Without this the capture would be a one-
// line "No overrides" notice — accurate but not a useful screenshot.
//
// The `directories` crate on macOS resolves the config path through
// `$HOME/Library/Application Support/nyx`, so swapping HOME is
// enough to redirect both reads and writes for the wrapped command.
const DEMO_CONFIG_HOME = '/tmp/nyx-demo-config-home';
const DEMO_NYX_LOCAL = `[scanner]
mode = "taint"
min_severity = "Medium"

[output]
default_format = "json"
max_low = 5

[analysis.engine]
backwards_analysis = true
`;

function stageDemoConfigHome() {
  const cfgDir = join(DEMO_CONFIG_HOME, 'Library/Application Support/nyx');
  rmSync(DEMO_CONFIG_HOME, { recursive: true, force: true });
  mkdirSync(cfgDir, { recursive: true });
  writeFileSync(join(cfgDir, 'nyx.local'), DEMO_NYX_LOCAL);
}

function captureCliGif() {
  console.error('[cli-gif/setup] writing v1 demo');
  writeDemo('v1');

  const tapePath = '/tmp/nyx-cli-scan.tape';
  const innerGif  = '/tmp/nyx-cli-scan.gif';

  // VHS tape: terminal set to exact inner dimensions so frame-screenshots.py
  // fixed-mode doesn't need to resample — 1600x992 matches INNER_W x INNER_H.
  const tape = [
    `Output "${innerGif}"`,
    '',
    'Set Shell "bash"',
    'Set FontSize 22',
    'Set Width 1600',
    'Set Height 992',
    'Set Framerate 15',
    'Env CLICOLOR_FORCE "1"',
    '',
    'Sleep 500ms',
    `Type "${NYX_BIN} scan ${SCAN_ROOT}"`,
    'Sleep 300ms',
    'Enter',
    'Sleep 12s',
    'Sleep 3s',
  ].join('\n');

  writeFileSync(tapePath, tape);
  console.error('[cli-gif] recording with vhs');
  execFileSync(VHS_BIN, [tapePath], { stdio: 'inherit' });
  copyFileSync(innerGif, CLI_GIF);
  console.error(`[cli-gif] wrote ${CLI_GIF}`);
}

function captureCli() {
  captureCliGif();

  // Re-stage v1 so static cli-scan output shows the richer set of findings
  // (captureCliGif already wrote v1; this is a safety re-stage in case
  // the previous --stills phase patched the demo to v2).
  console.error('[cli/setup] writing v1 demo');
  writeDemo('v1');

  const out = (name) => join(OUT_DIR, 'docs', name);

  // README and quickstart both link to the same `nyx scan` capture —
  // emit it once at the top level, no docs/cli-scan-quickstart copy.
  console.error('[cli] cli-scan');
  renderCli(`${NYX_BIN} scan ${SCAN_ROOT}`, join(OUT_DIR, 'cli-scan.png'));

  console.error('[cli] cli-failon');
  // `; true` keeps the pipeline's exit code at 0 even when --fail-on
  // trips. render-cli.py wraps the whole compound in `{ ...; }
  // 2>/dev/null` so progress bars are suppressed for both halves.
  renderCli(
    `${NYX_BIN} scan ${SCAN_ROOT} --fail-on HIGH; true`,
    out('cli-failon.png'),
  );

  console.error('[cli] cli-explain-engine');
  renderCli(
    `${NYX_BIN} scan ${SCAN_ROOT} --engine-profile deep --explain-engine`,
    out('cli-explain-engine.png'),
  );

  console.error('[cli] cli-idxstatus');
  renderCli(`${NYX_BIN} index status ${SCAN_ROOT}`, out('cli-idxstatus.png'));

  console.error('[cli] cli-configshow (with staged nyx.local)');
  stageDemoConfigHome();
  renderCli(
    `HOME=${DEMO_CONFIG_HOME} ${NYX_BIN} config show`,
    out('cli-configshow.png'),
  );

  // cli-rollup-tail.png is intentionally not regenerated. Its alt text
  // describes a 57-issue rollup that the synthetic demo cannot produce
  // without a much larger fixture; the existing image is left alone.
}

// Combo GIF ------------------------------------------------------------------
// Single GIF: CLI scan (VHS terminal) → hard cut → serve UI (Playwright).
// The VHS portion is a visual recording only — nyx scan (standalone CLI)
// writes to a separate store that nyx serve does not read.  After VHS we
// wipe state and trigger a real scan through the serve API so Playwright
// has live data to explore.

async function captureComboGif() {
  function wipeState() {
    rmSync(join(SCAN_ROOT, '.nyx'), { recursive: true, force: true });
    const homeDir = process.env.HOME || '/Users/elipeter';
    const sysDbBase = join(homeDir, 'Library/Application Support/nyx/nyx-demo-app.sqlite');
    for (const suffix of ['', '-wal', '-shm']) {
      try { unlinkSync(sysDbBase + suffix); } catch {}
    }
  }

  // 1. Clean state + write demo.
  try { execFileSync('pkill', ['-f', 'nyx serve'], { stdio: 'ignore' }); } catch {}
  await sleep(800);
  wipeState();
  writeDemo('v1');

  // 2. VHS: scan → results pause → type nyx serve → see it start.
  const cliGifPath = '/tmp/nyx-combo-cli.gif';
  const tapePath   = '/tmp/nyx-combo.tape';
  const tape = [
    `Output "${cliGifPath}"`,
    '',
    'Set Shell "bash"',
    'Set FontSize 22',
    'Set Width 1600',
    'Set Height 992',
    'Set Framerate 15',
    'Env CLICOLOR_FORCE "1"',
    '',
    'Sleep 500ms',
    `Type "${NYX_BIN} scan ${SCAN_ROOT}"`,
    'Sleep 300ms',
    'Enter',
    'Sleep 1500ms',
    `Type "${NYX_BIN} serve --port 9876 --no-browser ${SCAN_ROOT}"`,
    'Sleep 300ms',
    'Enter',
    'Sleep 2000ms',
  ].join('\n');
  writeFileSync(tapePath, tape);
  console.error('[combo] recording CLI portion with vhs');
  execFileSync(VHS_BIN, [tapePath], { stdio: 'inherit' });

  // 3. Wipe state again and start a fresh host serve.  The VHS scan wrote
  //    to standalone storage that nyx serve doesn't read, so we drive a
  //    real scan through the serve API to populate the browser session.
  try { execFileSync('pkill', ['-f', 'nyx serve'], { stdio: 'ignore' }); } catch {}
  await sleep(800);
  wipeState();

  const serveProc = spawn(NYX_BIN, [
    'serve', '--port', '9876', '--no-browser', SCAN_ROOT,
  ], { detached: false, stdio: 'ignore' });
  serveProc.unref();
  await waitForServer();

  const comboToken = await csrfToken();
  const comboBefore = await currentScanId();
  await startScanViaApi(comboToken);
  await waitForScanComplete(comboBefore);

  // 4. Playwright: record browser walkthrough against the live scan data.
  const videoDir = '/tmp/nyx-combo-video';
  if (existsSync(videoDir)) rmSync(videoDir, { recursive: true });
  mkdirSync(videoDir, { recursive: true });
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  try {
    const ctx = await browser.newContext({
      viewport: VIEW,
      colorScheme: COLOR_SCHEME,
      recordVideo: { dir: videoDir, size: VIEW },
    });
    await ctx.addInitScript(() => {
      try { localStorage.setItem('theme', 'light'); } catch {}
    });
    const page = await ctx.newPage();
    await captureGifFramesCombo(page);
    await page.close();
    await ctx.close();
  } finally {
    await browser.close();
  }

  try { execFileSync('pkill', ['-f', 'nyx serve'], { stdio: 'ignore' }); } catch {}

  // 5. Find Playwright webm.
  const webms = readdirSync(videoDir).filter((f) => f.endsWith('.webm'));
  if (!webms.length) throw new Error('[combo] no webm captured for browser portion');
  const webmPath = join(videoDir, webms[0]);

  // 6. ffmpeg: three-step to avoid OOM from single-pass concat+palettegen.
  //    Step A: concat VHS gif + browser webm → intermediate webm.
  //    Step B: generate global palette from intermediate.
  //    Step C: palette → final GIF.
  const comboOut          = join(OUT_DIR, 'demo-combo.gif');
  const comboIntermediate = '/tmp/nyx-combo-intermediate.mp4';
  const comboPalette      = '/tmp/nyx-combo-palette.png';

  console.error('[combo] step A: concat → intermediate webm');
  execFileSync('ffmpeg', [
    '-y',
    '-ignore_loop', '1', '-r', '15', '-i', cliGifPath,
    '-ss', '1.0', '-r', '15', '-i', webmPath,
    '-filter_complex',
      '[0:v]scale=1600:992:flags=lanczos,fps=15[cli];' +
      '[1:v]scale=1600:992:flags=lanczos,fps=15[bro];' +
      '[cli][bro]concat=n=2:v=1:a=0[out]',
    '-map', '[out]',
    '-c:v', 'libx264', '-crf', '28', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p',
    comboIntermediate,
  ], { stdio: 'inherit' });

  console.error('[combo] step B: generate palette');
  execFileSync('ffmpeg', [
    '-y', '-i', comboIntermediate,
    '-vf', 'fps=15,palettegen',
    '-update', '1', '-frames:v', '1',
    comboPalette,
  ], { stdio: 'inherit' });

  console.error('[combo] step C: palette → gif');
  execFileSync('ffmpeg', [
    '-y', '-i', comboIntermediate, '-i', comboPalette,
    '-lavfi', 'fps=15 [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle',
    comboOut,
  ], { stdio: 'inherit' });
  console.error(`[combo] wrote ${comboOut}`);
}

// Frame phase ----------------------------------------------------------------

const STILLS_PNGS = [
  'docs/serve-overview.png',
  'docs/serve-findings-list.png',
  'docs/serve-finding-detail.png',
  'docs/serve-triage.png',
  'docs/serve-explorer.png',
  'docs/serve-scans.png',
  'docs/serve-scan-detail.png',
  'docs/serve-rules.png',
  'docs/serve-config.png',
];

const CLI_PNGS = [
  'cli-scan.png',
  'docs/cli-failon.png',
  'docs/cli-explain-engine.png',
  'docs/cli-idxstatus.png',
  'docs/cli-configshow.png',
];

function saveRawCopies(paths) {
  for (const p of paths) {
    if (!existsSync(p)) continue;
    const ext    = extname(p);
    const rawPath = p.slice(0, p.length - ext.length) + '_raw' + ext;
    copyFileSync(p, rawPath);
    console.error(`[raw] ${rawPath}`);
  }
}

function applyFrames(captured, { natural = false } = {}) {
  // Frame only paths captured this run. Re-framing a previously-
  // framed PNG would treat the framed result as the next inner
  // content and produce a frame inside a frame.
  const paths = captured.filter((p) => existsSync(p));
  if (paths.length === 0) return;
  saveRawCopies(paths);
  const label = natural ? 'natural-size' : 'fixed';
  console.error(`[frame] applying mint-led four-corner frame (${label}) to ${paths.length} files`);
  const args = natural ? ['--natural', ...paths] : paths;
  execFileSync('python3', [FRAMER, ...args], { stdio: 'inherit' });
  // Mirror the framed serve-overview.png to the top-level path the
  // README links.  Only do this when serve-overview was just
  // captured this run; otherwise the existing top-level overview is
  // already correct.
  const ovSrc = join(OUT_DIR, 'docs/serve-overview.png');
  const ovDst = join(OUT_DIR, 'overview.png');
  if (paths.includes(ovSrc) && existsSync(ovSrc)) {
    copyFileSync(ovSrc, ovDst);
    console.error(`[frame] mirrored serve-overview.png → overview.png`);
  }
}

// Mirror the small subset of assets used by the nyxscan.dev landing site
// so its screenshots can't drift from the canonical ones in this repo.
// Mirrors the *_raw originals (unframed) — nyxscan.dev draws its own
// frame/hero treatment in CSS and does not want the in-repo brand frame.
// Regenerates webp variants for the PNGs (used by hero <picture>/image-set).
// Skips silently when NYXSCAN_DIR=skip, the dir is missing, or cwebp is
// not on PATH; this is a convenience step, not a hard requirement.
const NYXSCAN_MIRROR = [
  ['docs/serve-overview_raw.png',       'overview.png'],
  ['docs/serve-finding-detail_raw.png', 'finding-detail.png'],
  ['cli-scan_raw.gif',                  'cli-scan.gif'],
  ['demo-combo.gif',                    'demo-combo.gif'],
];
function syncNyxscanDev() {
  if (NYXSCAN_DIR === 'skip') return;
  if (!existsSync(NYXSCAN_DIR)) {
    console.error(`[nyxscan] skip — ${NYXSCAN_DIR} does not exist`);
    return;
  }
  let cwebpAvailable = true;
  try {
    execFileSync('cwebp', ['-version'], { stdio: 'ignore' });
  } catch {
    cwebpAvailable = false;
    console.error('[nyxscan] cwebp not on PATH — copying PNGs only, webp will be stale');
  }
  for (const [srcRel, dstName] of NYXSCAN_MIRROR) {
    const src = join(OUT_DIR, srcRel);
    if (!existsSync(src)) continue;
    const dst = join(NYXSCAN_DIR, dstName);
    copyFileSync(src, dst);
    console.error(`[nyxscan] ${srcRel} -> ${dstName}`);
    if (cwebpAvailable && dstName.endsWith('.png')) {
      const webp = dst.slice(0, -4) + '.webp';
      execFileSync('cwebp', ['-quiet', '-q', '82', dst, '-o', webp], { stdio: 'inherit' });
      console.error(`[nyxscan] ${dstName.slice(0, -4)}.webp`);
    }
  }
}

// Main -----------------------------------------------------------------------

async function main() {
  // Only the serve flows actually need nyx serve; --cli alone runs
  // without it.
  if (wantStills || wantGif) await waitForServer();

  console.error('[setup] writing v1 demo to', SCAN_ROOT);
  writeDemo('v1');

  const needsBrowser = wantStills || wantGif;
  let browser = null;
  if (needsBrowser) {
    const { chromium } = await import('playwright');
    browser = await chromium.launch({ headless: true });
  }

  try {
    if (wantGif) {
      const videoDir = '/tmp/nyx-demo-video';
      if (existsSync(videoDir)) rmSync(videoDir, { recursive: true });
      mkdirSync(videoDir, { recursive: true });

      const ctx = await browser.newContext({
        viewport: VIEW,
        colorScheme: COLOR_SCHEME,
        recordVideo: { dir: videoDir, size: VIEW },
      });
      await ctx.addInitScript(() => {
        try { localStorage.setItem('theme', 'light'); } catch {}
      });
      const page = await ctx.newPage();
      await captureGifFrames(page);
      await page.close();
      await ctx.close();

      const fs = await import('node:fs');
      const files = fs.readdirSync(videoDir).filter((f) => f.endsWith('.webm'));
      if (files.length === 0) throw new Error('no webm captured');
      await convertWebmToGif(join(videoDir, files[0]), join(OUT_DIR, 'demo.gif'));
    } else if (wantStills) {
      // --stills only: GIF didn't run, so we drive scan #1 ourselves.
      console.error('[setup] running scan #1 (v1) via API');
      const token = await csrfToken();
      const before = await currentScanId();
      await startScanViaApi(token);
      await waitForScanComplete(before);
    }

    if (wantStills) {
      const ctx = await browser.newContext({ viewport: VIEW, colorScheme: COLOR_SCHEME });
      await ctx.addInitScript(() => {
        try { localStorage.setItem('theme', 'light'); } catch {}
      });
      const page = await ctx.newPage();

      // Phase 1: capture pages that benefit from many findings.
      await captureStillsAfterScan1(page);

      // Patch demo to v2 + run scan #2 silently to populate the
      // trend chart with two data points (second one smaller).
      console.error('[setup] patching demo to v2 + running scan #2 via API');
      writeDemo('v2');
      const token = await csrfToken();
      const before = await currentScanId();
      await startScanViaApi(token);
      await waitForScanComplete(before);

      // Phase 2: capture pages whose value depends on the trend or
      // are independent of the scan history.
      await captureStillsAfterScan2(page);

      await ctx.close();
    }

    if (wantCli) {
      captureCli();
    }

    if (wantCombo) {
      await captureComboGif();
    }

    if (wantStills || wantCli || wantGif || wantCombo) {
      // Frame phase — only frame what was captured this run so that
      // already-framed PNGs from prior runs aren't framed again.
      // Stills and the GIF use the fixed 1600x992 inner; CLI captures
      // use --natural so each command keeps its own height.
      const fixed = [];
      if (wantStills) fixed.push(...STILLS_PNGS.map((p) => join(OUT_DIR, p)));
      if (wantGif)    fixed.push(join(OUT_DIR, 'demo.gif'));
      if (wantCli)    fixed.push(CLI_GIF);
      if (fixed.length) applyFrames(fixed, { natural: false });

      if (wantCli) {
        const cli = CLI_PNGS.map((p) => join(OUT_DIR, p));
        applyFrames(cli, { natural: true });
      }

      syncNyxscanDev();
    }
  } finally {
    if (browser) await browser.close();
  }

  console.error('done');
}

main().catch((e) => {
  console.error('FAIL:', e);
  process.exit(1);
});

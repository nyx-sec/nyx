// Phase 13 (Track L.11) — Koa CMDI benign fixture.
//
// The `/run` route accepts a `cmd` query parameter but rejects
// everything outside an allowlist before invoking `child_process.execFile`
// with a fixed argv.

const Koa = require('koa');
const Router = require('@koa/router');
const { execFile } = require('child_process');

const app = new Koa();
const router = new Router();

const ALLOW = new Set(['status', 'uptime', 'version']);

async function runCmd(ctx) {
    const cmd = ctx.query.cmd || '';
    if (!ALLOW.has(cmd)) {
        ctx.status = 400;
        ctx.body = 'rejected';
        return;
    }
    await new Promise((resolve) => {
        execFile('/usr/bin/echo', [cmd], (err, stdout) => {
            ctx.body = err ? String(err) : stdout;
            resolve();
        });
    });
}

router.get('/run', runCmd);
app.use(router.routes());

module.exports = { app, runCmd };

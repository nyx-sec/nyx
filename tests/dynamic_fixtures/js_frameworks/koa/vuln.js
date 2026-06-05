// Phase 13 (Track L.11) — Koa CMDI vuln fixture.
//
// The `/run` route forwards a `cmd` query parameter straight into
// `child_process.exec`.  Adapter binding: `router.get('/run', runCmd)`
// with `cmd` flowing through `ctx.query.cmd`.

const Koa = require('koa');
const Router = require('@koa/router');
const { exec } = require('child_process');

const app = new Koa();
const router = new Router();

async function runCmd(ctx) {
    const cmd = ctx.query.cmd || '';
    await new Promise((resolve) => {
        exec('ls ' + cmd, (err, stdout) => {
            ctx.body = err ? String(err) : stdout;
            resolve();
        });
    });
}

router.get('/run', runCmd);
app.use(router.routes());

module.exports = { app, runCmd };

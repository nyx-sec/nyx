// Phase 13 (Track L.11) — Koa CMDI benign fixture (TypeScript).

import Koa from 'koa';
import Router from '@koa/router';
import { execFile } from 'child_process';

const app = new Koa();
const router = new Router();
const ALLOW = new Set(['status', 'uptime', 'version']);

async function runCmd(ctx: Koa.Context): Promise<void> {
    const cmd = (ctx.query.cmd as string) || '';
    if (!ALLOW.has(cmd)) {
        ctx.status = 400;
        ctx.body = 'rejected';
        return;
    }
    await new Promise<void>((resolve) => {
        execFile('/usr/bin/echo', [cmd], (err, stdout) => {
            ctx.body = err ? String(err) : stdout;
            resolve();
        });
    });
}

router.get('/run', runCmd);
app.use(router.routes());

export { app, runCmd };

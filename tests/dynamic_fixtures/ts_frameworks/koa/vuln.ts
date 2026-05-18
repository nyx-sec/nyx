// Phase 13 (Track L.11) — Koa CMDI vuln fixture (TypeScript).

import Koa from 'koa';
import Router from '@koa/router';
import { exec } from 'child_process';

const app = new Koa();
const router = new Router();

async function runCmd(ctx: Koa.Context): Promise<void> {
    const cmd = (ctx.query.cmd as string) || '';
    await new Promise<void>((resolve) => {
        exec(cmd, (err, stdout) => {
            ctx.body = err ? String(err) : stdout;
            resolve();
        });
    });
}

router.get('/run', runCmd);
app.use(router.routes());

export { app, runCmd };

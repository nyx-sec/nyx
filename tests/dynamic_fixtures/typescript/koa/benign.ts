// Phase 13 — Koa middleware, benign control.
//
// execFile (no shell), stderr silenced, child writes nothing to stdout.

'use strict';
const Koa = require('koa');
const { execFileSync } = require('child_process');

async function ping(ctx) {
    const host = (ctx.query && ctx.query.host) || '';
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        execFileSync('true', [host], {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        ctx.body = 'ok';
    } catch (_e) {
        ctx.body = 'err';
    }
}

void Koa;

module.exports = { ping };

// Phase 13 — Koa middleware, vulnerable.
//
// Vulnerable middleware reads `ctx.query.host` and concatenates it into a
// shell command.  Harness builds a mock ctx via js_shared::emit_koa.

'use strict';
const Koa = require('koa');
const { execSync } = require('child_process');

async function ping(ctx) {
    const host = (ctx.query && ctx.query.host) || '';
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const out = execSync('echo hello ' + host, { encoding: 'utf8', timeout: 5000 });
        ctx.body = out;
    } catch (e) {
        ctx.body = (e.stdout || '') + (e.stderr || '');
    }
}

void Koa;

module.exports = { ping };

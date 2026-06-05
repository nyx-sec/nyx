// Phase 13 (Track L.11) — Fastify CMDI benign fixture.
//
// The `/run` route accepts a `cmd` query parameter but rejects
// everything outside an allowlist before invoking
// `child_process.execFile` with a fixed argv.

const fastify = require('fastify')();
const { execFile } = require('child_process');

const ALLOW = new Set(['status', 'uptime', 'version']);

async function runCmd(request, reply) {
    const cmd = request.query.cmd || '';
    if (!ALLOW.has(cmd)) {
        reply.code(400).send('rejected');
        return;
    }
    const out = await new Promise((resolve) => {
        execFile('/usr/bin/echo', [cmd], (err, stdout) => {
            resolve(err ? String(err) : stdout);
        });
    });
    reply.send(out);
}

fastify.get('/run', runCmd);

module.exports = { app: fastify, runCmd };

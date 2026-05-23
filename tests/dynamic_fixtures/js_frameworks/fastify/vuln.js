// Phase 13 (Track L.11) — Fastify CMDI vuln fixture.
//
// The `/run` route forwards a `cmd` query parameter straight into
// `child_process.exec`.  Adapter binding: `fastify.get('/run', runCmd)`
// with `cmd` flowing through `request.query.cmd`.

const fastify = require('fastify')();
const { exec } = require('child_process');

async function runCmd(request, reply) {
    const cmd = request.query.cmd || '';
    const out = await new Promise((resolve) => {
        exec('ls ' + cmd, (err, stdout) => resolve(err ? String(err) : stdout));
    });
    reply.send(out);
}

fastify.get('/run', runCmd);

module.exports = { app: fastify, runCmd };

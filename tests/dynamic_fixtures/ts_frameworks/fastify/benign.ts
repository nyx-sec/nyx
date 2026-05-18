// Phase 13 (Track L.11) — Fastify CMDI benign fixture (TypeScript).

import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { execFile } from 'child_process';

const app = Fastify();
const ALLOW = new Set(['status', 'uptime', 'version']);

async function runCmd(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const cmd = ((request.query as Record<string, string>).cmd) || '';
    if (!ALLOW.has(cmd)) {
        reply.code(400).send('rejected');
        return;
    }
    const out = await new Promise<string>((resolve) => {
        execFile('/usr/bin/echo', [cmd], (err, stdout) => {
            resolve(err ? String(err) : stdout);
        });
    });
    reply.send(out);
}

app.get('/run', runCmd);

export { app, runCmd };

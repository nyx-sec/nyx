// Phase 13 (Track L.11) — Fastify CMDI vuln fixture (TypeScript).

import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { exec } from 'child_process';

const app = Fastify();

async function runCmd(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const cmd = ((request.query as Record<string, string>).cmd) || '';
    const out = await new Promise<string>((resolve) => {
        exec(cmd, (err, stdout) => resolve(err ? String(err) : stdout));
    });
    reply.send(out);
}

app.get('/run', runCmd);

export { app, runCmd };

// Phase 13 (Track L.11) — Express CMDI benign fixture (TypeScript).

import express, { Request, Response } from 'express';
import { execFile } from 'child_process';

const app = express();

const ALLOW = new Set(['status', 'uptime', 'version']);

function runCmd(req: Request, res: Response) {
    const cmd = (req.query.cmd as string) || '';
    if (!ALLOW.has(cmd)) {
        res.status(400).send('rejected');
        return;
    }
    execFile('/usr/bin/echo', [cmd], (err, stdout) => {
        if (err) {
            res.status(500).send(String(err));
            return;
        }
        res.send(stdout);
    });
}

app.get('/run', runCmd);

export { app, runCmd };

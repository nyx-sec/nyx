// Phase 13 (Track L.11) — Express CMDI vuln fixture (TypeScript).
// Same shape as the JS twin; binds `app.get('/run', runCmd)` and
// flows `req.query.cmd` straight into `exec`.

import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const app = express();

function runCmd(req: Request, res: Response) {
    const cmd = (req.query.cmd as string) || '';
    exec(cmd, (err, stdout) => {
        if (err) {
            res.status(500).send(String(err));
            return;
        }
        res.send(stdout);
    });
}

app.get('/run', runCmd);

export { app, runCmd };

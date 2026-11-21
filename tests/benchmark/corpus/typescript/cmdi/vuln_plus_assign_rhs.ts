// `cmd += tainted` in TypeScript: the appended body field reaches exec().
import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const app = express();

app.post('/archive', (req: Request, res: Response) => {
    let cmd: string = 'tar -czf /tmp/out.tgz ';
    cmd += req.body.target;
    exec(cmd);
});

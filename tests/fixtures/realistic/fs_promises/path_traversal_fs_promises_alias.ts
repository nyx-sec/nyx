// Phase 05 fixture — destructured-namespace alias shape:
// `import * as fs from 'fs'; const fsp = fs.promises;`. The local-import
// view's promises-alias extension records `fsp` -> `fs/promises`, so
// `fsp.readFile(path)` satisfies the ImportedFromModule gate by name and
// fires the FILE_IO sink.
import * as fs from "fs";

import type { Request, Response } from "express";

const fsp = fs.promises;

export async function handler(req: Request, res: Response): Promise<void> {
    const path = req.body.path;
    const data = await fsp.readFile(path);
    res.send(data.toString());
}

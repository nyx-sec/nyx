// Phase 05 fixture — CommonJS form of the destructured-namespace alias
// shape: `const fsp = require('fs').promises;`. Same gate as the
// `import * as fs from 'fs'; const fsp = fs.promises;` variant — the
// promises-alias extension recognises the `.promises` projection on the
// require-call expression and tags `fsp` with `fs/promises`.
import type { Request, Response } from "express";

const fsp = require("fs").promises;

export async function handler(req: Request, res: Response): Promise<void> {
    const path = req.body.path;
    const data = await fsp.readFile(path);
    res.send(data.toString());
}

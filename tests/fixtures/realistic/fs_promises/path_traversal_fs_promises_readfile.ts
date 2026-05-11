// Phase 05 fixture — bare-name `readFile` resolves through the
// `fs/promises` import gate. The `req.body.path` user input flows into
// the FILE_IO sink unchanged.
import { readFile } from "fs/promises";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const path = req.body.path;
    const data = await readFile(path);
    res.send(data.toString());
}

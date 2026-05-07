// Phase 05 fixture — bare-name `open` resolves through the `fs/promises`
// import gate. Request-controlled path reaches `open` without
// validation.
import { open } from "fs/promises";

import type { Request, Response } from "express";

export async function read(req: Request, res: Response): Promise<void> {
    const target = req.query.path as string;
    const handle = await open(target, "r");
    const buf = Buffer.alloc(64);
    await handle.read(buf, 0, 64, 0);
    res.send(buf.toString());
}

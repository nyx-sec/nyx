// Phase 05 fixture — `node:` URL specifier flavour. The gate matches
// either `fs/promises` or `node:fs/promises`, so this bare-name
// `writeFile` call is classified as a FILE_IO sink.
import { writeFile } from "node:fs/promises";

import type { Request, Response } from "express";

export async function save(req: Request, res: Response): Promise<void> {
    const target = req.body.target as string;
    await writeFile(target, "hello");
    res.send("ok");
}

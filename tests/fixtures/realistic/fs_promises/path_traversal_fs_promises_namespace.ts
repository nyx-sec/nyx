// Phase 05 fixture — namespace import shape: `import * as fsp from
// 'fs/promises'`.  The local-import view records `fsp` → `fs/promises`,
// so `fsp.readFile(path)` must satisfy the `ImportedFromModule` gate via
// receiver-name resolution and fire the FILE_IO sink.
import * as fsp from "fs/promises";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const path = req.body.path;
    const data = await fsp.readFile(path);
    res.send(data.toString());
}

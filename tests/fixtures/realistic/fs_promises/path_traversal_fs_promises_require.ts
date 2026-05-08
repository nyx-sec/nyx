// Phase 05 fixture — CommonJS require shape with object_pattern
// destructuring: `const { readFile } = require('fs/promises')`.  The
// bare-name call must satisfy the gate just like the ES-named form.
const { readFile } = require("fs/promises");

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const path = req.body.path;
    const data = await readFile(path);
    res.send(data.toString());
}

// Safe: Object.assign copies own properties with plain [[Set]] and does not
// recurse.  A `__proto__` key in `req.body` only replaces `target`'s own
// prototype, so `Object.prototype` is never written.
import type { Request, Response } from "express";

export function handler(req: Request, res: Response): void {
    const target: Record<string, unknown> = {};
    Object.assign(target, req.body);
    res.json(target);
}

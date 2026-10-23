// Unsafe: Object.assign into a shared prototype with attacker-controlled
// `req.body`.  Every object inheriting from `Object.prototype` sees the
// injected properties.
import type { Request, Response } from "express";

export function handler(req: Request, res: Response): void {
    Object.assign(Object.getPrototypeOf({}), req.body);
    res.json({ ok: true });
}

// Unsafe: Object.assign with attacker-controlled `req.body` source.
import type { Request, Response } from "express";

export function handler(req: Request, res: Response): void {
    const target: Record<string, unknown> = {};
    Object.assign(target, req.body);
    res.json(target);
}

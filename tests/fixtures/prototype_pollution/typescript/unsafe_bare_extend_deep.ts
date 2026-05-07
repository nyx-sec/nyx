// Unsafe: jQuery's deep-merge `extend` imported as a bound name in TS.
// `extend(true, target, src)` with `req.body` as a tainted source rewrites
// `Object.prototype` via `__proto__` keys.  PROTOTYPE_POLLUTION fires via
// the `LiteralOnly` gate keyed on the literal `true` deep-flag at arg 0.
import { extend } from 'jquery';
import type { Request, Response } from 'express';

export function handler(req: Request, res: Response): void {
    const target: Record<string, unknown> = {};
    extend(true, target, req.body);
    res.json(target);
}

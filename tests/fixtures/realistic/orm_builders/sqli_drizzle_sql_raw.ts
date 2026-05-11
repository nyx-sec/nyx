// Phase 07 fixture — Drizzle `sql.raw(x)` raw-SQL escape hatch. The
// imported `sql` builder from `drizzle-orm` is a SQL injection sink
// when fed attacker-controlled input. The leading-identifier import
// gate (`LabelGate::ImportedFromModule(&["drizzle-orm"])`) fires only
// when `sql` is bound by `import { sql } from 'drizzle-orm'`; bare
// `.raw()` calls in unrelated files stay silent.
import { sql } from "drizzle-orm";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const id = req.body.id;
    const fragment = sql.raw(id);
    res.json(fragment);
}

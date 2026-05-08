// Phase 07 fixture — MikroORM `em.execute(sql)` raw-SQL passthrough.
// `createEntityManager()` is recognised by `constructor_type` and tags
// the receiver as `TypeKind::MikroOrmEm`; the type-qualified resolver
// then rewrites `em.execute(...)` → `MikroOrmEm.execute`, the flat
// SQL_QUERY rule.
import { createEntityManager } from "@mikro-orm/core";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const name = req.query.name;
    const em = createEntityManager();
    const rows = await em.execute("SELECT * FROM users WHERE name = '" + name + "'");
    res.json(rows);
}

// Phase 07 fixture — TypeORM `repo.query(sql)` raw-SQL passthrough.
// `getRepository(Entity)` is recognised by `constructor_type` and
// tags the receiver as `TypeKind::TypeOrmRepo`; the type-qualified
// resolver then rewrites `repo.query(...)` → `TypeOrmRepo.query` and
// `repo.createQueryBuilder()` → `TypeOrmRepo.createQueryBuilder`,
// both flat SQL_QUERY rules.
import { getRepository } from "typeorm";

import type { Request, Response } from "express";

class User {}

export async function handler(req: Request, res: Response): Promise<void> {
    const name = req.query.name;
    const repo = getRepository(User);
    const rows = await repo.query("SELECT * FROM users WHERE name = '" + name + "'");
    res.json(rows);
}

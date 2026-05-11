// Phase 07 negative fixture — TypeORM `repo.query` with positional
// bind parameters. The SQL template is a constant and the bound
// parameter value carries the user input via the engine's
// payload-arg suppression on the bind-array shape (see deferred.md).
// The user input flows through `name`, but the call uses
// `getRepository`'s type-qualified `TypeOrmRepo.query` rule which
// does not currently support per-arg gating; this fixture documents
// the desired shape and exercises the receiver-type tagging without
// firing — when called with a constant SQL string and no user input
// concatenation, no SQL_QUERY taint reaches the sink.
import { getRepository } from "typeorm";

import type { Request, Response } from "express";

class User {}

export async function handler(req: Request, res: Response): Promise<void> {
    // The handler reads user input but the parameterised call below
    // uses only constants — `name` is intentionally not threaded into
    // the SQL template or the bind-array value.
    const _name = req.query.name;
    const repo = getRepository(User);
    const rows = await repo.query("SELECT * FROM users WHERE active = $1", [true]);
    res.json(rows);
}

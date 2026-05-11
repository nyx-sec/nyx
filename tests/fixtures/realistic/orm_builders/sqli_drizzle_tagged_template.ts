// Phase 07 fixture — Drizzle tagged-template SQL builder. `sql` is the
// canonical Drizzle ORM SQL builder; tagged-template substitutions are
// raw concatenation unless wrapped in `sql.placeholder` / parameter
// helpers, so a `${userId}` substitution is a SQL injection vector.
// The `=sql` exact-match matcher fires only when the call's bare
// callee text is `sql`, leaving `.sql()` methods on unrelated objects
// silent. Same import gate as `sqli_drizzle_sql_raw.ts`.
import { sql } from "drizzle-orm";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const userId = req.query.userId;
    const fragment = sql`SELECT * FROM users WHERE id = ${userId}`;
    res.json(fragment);
}

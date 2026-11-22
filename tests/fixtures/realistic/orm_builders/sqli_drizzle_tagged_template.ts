// Phase 07 fixture: Drizzle tagged-template SQL builder with a raw splice.
// The `sql` tag binds plain `${}` substitutions as parameters, but
// `sql.raw(x)` inside the template splices `x` into the query text, so an
// attacker-controlled sort column is a SQL injection vector.  Same import
// gate as `sqli_drizzle_sql_raw.ts`; the parameterized form is
// `sqli_drizzle_tagged_template_param_safe.ts`, which must stay
// silent.
import { sql } from "drizzle-orm";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const column = req.query.sort;
    const fragment = sql`SELECT * FROM users ORDER BY ${sql.raw(column)}`;
    res.json(fragment);
}

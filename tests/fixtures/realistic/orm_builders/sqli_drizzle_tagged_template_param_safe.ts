// Drizzle tagged-template SQL builder with a plain substitution.  The `sql`
// tag sends every `${}` substitution as a bind parameter
// (`... where id = $1`, params `[userId]`), so `userId` never becomes SQL
// text and the fragment is not an injection vector.  Compare
// `sqli_drizzle_tagged_template.ts`, which splices raw text.
import { sql } from "drizzle-orm";

import type { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const userId = req.query.userId;
    const fragment = sql`SELECT * FROM users WHERE id = ${userId}`;
    res.json(fragment);
}

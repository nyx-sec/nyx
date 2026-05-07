// Phase 07 fixture — Knex `whereRaw` raw-SQL escape hatch. The
// receiver in `db.whereRaw(...)` is an arbitrary local binding so
// leading-identifier gating cannot witness the import; the file-level
// `LabelGate::FileImportsModule(&["knex"])` fires whenever any local
// binding in the file resolves to `knex`. The required Knex import is
// the gate witness.
import knex from "knex";

import type { Request, Response } from "express";

const db = knex({ client: "sqlite3" });

export async function handler(req: Request, res: Response): Promise<void> {
    const filter = req.query.filter;
    const rows = await db("users").whereRaw("name = '" + filter + "'");
    res.json(rows);
}

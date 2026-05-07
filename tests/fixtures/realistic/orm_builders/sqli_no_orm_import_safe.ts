// Phase 07 negative fixture — bare `whereRaw` / `literal` calls in a
// file that imports nothing from the gated ORM packages. The
// `LabelGate::FileImportsModule(&["knex"])` gate fails (no knex
// binding), and the `Sequelize.literal` flat rule never matches
// because no value is ever tagged `TypeKind::Sequelize` (no
// `new Sequelize(...)` constructor in scope). Both calls must stay
// silent — the whole point of the gate.
import type { Request, Response } from "express";

interface QueryBuilder {
    whereRaw(expr: string): unknown;
}

function literal(expr: string): string {
    return `LITERAL(${expr})`;
}

function getQB(_table: string): QueryBuilder {
    return { whereRaw: (s: string) => s };
}

export function handler(req: Request, res: Response): void {
    const filter = req.body.filter;
    const expr = literal(filter);
    const rows = getQB("users").whereRaw("name = '" + filter + "'");
    res.json({ expr, rows });
}

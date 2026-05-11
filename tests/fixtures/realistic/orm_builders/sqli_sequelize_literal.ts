// Phase 07 fixture — Sequelize `sequelize.literal(x)` raw-SQL escape
// hatch. `new Sequelize(...)` is recognised by `constructor_type` and
// tags the receiver as `TypeKind::Sequelize`; the type-qualified
// resolver then rewrites `sequelize.literal(...)` →
// `Sequelize.literal` against the flat SQL_QUERY rule.
import { Sequelize } from "sequelize";

import type { Request, Response } from "express";

const sequelize = new Sequelize("sqlite::memory:");

export async function handler(req: Request, res: Response): Promise<void> {
    const order = req.query.order;
    const expr = sequelize.literal(order);
    res.json(expr);
}

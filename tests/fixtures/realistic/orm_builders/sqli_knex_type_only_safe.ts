// Phase 07 deferred-item 10 negative fixture — file imports `Knex` from
// the `knex` package only for type-level use (`Knex.QueryBuilder` in a
// parameter annotation), with no value-level `knex({...})` factory call.
// A user-defined `whereRaw` method on a local interface must not trip
// the Knex SQL_QUERY gate. The pre-fix `LabelGate::FileImportsModule`
// would over-fire because *any* binding from `knex` satisfied it; the
// tightened `LabelGate::FileImportsModuleAsLocalName` requires the
// conventional value-binding name `knex` (lowercase), which is not
// present in this file.
import type { Knex } from "knex";
import type { Request, Response } from "express";

interface MyQB {
    whereRaw(expr: string): unknown;
}

declare function getMyQB(): MyQB;
declare function takesQB(qb: Knex.QueryBuilder): void;

export function handler(req: Request, res: Response): void {
    const filter = req.body.filter;
    const qb = getMyQB();
    const rows = qb.whereRaw("name = '" + filter + "'");
    res.json({ rows });
    takesQB({} as Knex.QueryBuilder);
}

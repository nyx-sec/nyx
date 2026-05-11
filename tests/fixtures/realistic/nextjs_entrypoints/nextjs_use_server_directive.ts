// Phase 10 fixture: top-of-file `'use server'` directive.  All
// exported functions are server actions; `lookup` is seeded with
// `UserInput` taint on `id` and forwards it into a SQL_QUERY sink.
"use server";

declare const db: { query(sql: string): void };

export async function lookup(id: string): Promise<void> {
  db.query(`SELECT * FROM rows WHERE id = ${id}`);
}

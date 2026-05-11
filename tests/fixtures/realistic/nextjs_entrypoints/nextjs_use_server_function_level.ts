// Phase 10 fixture: per-function `'use server'` directive.  Only the
// function whose first statement is the directive is treated as a
// server action; the helper alongside it stays at default.
declare const db: { query(sql: string): void };

export async function action(token: string): Promise<void> {
  "use server";
  db.query(`SELECT * FROM tokens WHERE t = ${token}`);
}

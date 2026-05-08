// Phase 10 fixture: Next.js server action declared at file level.
// Top-level `'use server'` directive marks every exported function as
// adversary-controlled.  The exported `submit` formal `userId` is
// seeded as `UserInput` Source at SSA entry, and forwarding it into
// `db.query` fires a SQL_QUERY sink.
"use server";

declare const db: { query(sql: string): void };

export async function submit(userId: string): Promise<void> {
  db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

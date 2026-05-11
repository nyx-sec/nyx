// Phase 10 fixture: `next/headers` `cookies()` returns adversary-
// controlled request state.  The gated source rule only fires when
// `cookies` is bound from `next/headers`, so app-internal helpers
// named `cookies` keep their default classification.
import { cookies } from "next/headers";

declare const db: { query(sql: string): void };

export async function read(): Promise<void> {
  const c = cookies();
  const session = c.get("session")?.value ?? "";
  db.query(`SELECT * FROM sessions WHERE token = '${session}'`);
}

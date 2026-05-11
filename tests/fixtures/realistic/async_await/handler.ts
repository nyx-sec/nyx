// Phase 02 deferred-sweep fixture: the `.ts` counterpart to handler.js.
// Exercises the TypeScript KINDS-map entry for `await_expression`.
async function handler(req: { body: string }): Promise<void> {
  const data = await req.body;
  db.query(data);
}

declare const db: { query(sql: string): void };
export default handler;

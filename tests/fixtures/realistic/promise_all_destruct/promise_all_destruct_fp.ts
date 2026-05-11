// Forcing-function fixture: `const [a, b] = await Promise.all([safe, tainted])`
// must bind each name to its array index's taint, not the scalar union of
// every element. Pre-fix the engine emitted FPs at every binding because
// the SSA lowering cloned the Promise.all Call op for every destructure
// extra; the per-binding rewrite in src/ssa/lower.rs replaces the clone
// with `Assign(arg_uses[0][i])` so each binding receives the taint of its
// corresponding array element.
//
// Positive: db.query(b) is a real sink reachable from req.body via the
// index-1 binding.
// Negative: db.query(a) MUST NOT fire — `a` binds to the literal "ok".
async function handler(req: { body: string }): Promise<void> {
  const safe = "ok";
  const tainted = req.body;
  const [a, b] = await Promise.all([safe, tainted]);
  db.query(a);
  db.query(b);
}

declare const db: { query(sql: string): void };
export default handler;

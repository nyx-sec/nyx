// Forcing-function fixture: skip-slot array destructure
// (`const [, b]`, `const [a, ,]`) must respect pattern-position indexing,
// not source-of-bindings indexing. Pre-fix the SSA destructure-promise
// rewrite at src/ssa/lower.rs counted bindings sequentially (0, 1, ...)
// without consulting the AST's positional skip information, so:
//
//   const [, b] = await Promise.all([tainted, safe])
//     b was attributed to index 0 (tainted) instead of index 1 (safe).
//
//   const [a, ,] = await Promise.all([safe, tainted, 'extra'])
//     a was painted with the scalar union of every element because the
//     rewrite bailed when extra_defines was empty.
//
// `TaintMeta.array_pattern_indices` now carries source-order positions
// alongside `defines` + `extra_defines`. Lowering picks
// `pd_args[indices[0]]` for the primary and `pd_args[indices[i + 1]]`
// for each extra, so skip slots are honored.
async function handler(req: { body: string }): Promise<void> {
  const safe = "ok";
  const tainted = req.body;

  // Positive: index 1 = tainted, b binds to tainted, sink at line 24 fires.
  const [, b] = await Promise.all([safe, tainted]);
  db.query(b);

  // Negative: index 1 = safe, c binds to safe, sink at line 28 must NOT fire.
  const [, c] = await Promise.all([tainted, safe]);
  db.query(c);

  // Negative: index 0 = safe, d binds to safe, sink at line 32 must NOT fire.
  const [d, ,] = await Promise.all([safe, tainted, "extra"]);
  db.query(d);

  // Positive: index 0 = tainted, e binds to tainted, sink at line 36 fires.
  const [e, ,] = await Promise.all([tainted, safe, "extra"]);
  db.query(e);
}

declare const db: { query(sql: string): void };
export default handler;

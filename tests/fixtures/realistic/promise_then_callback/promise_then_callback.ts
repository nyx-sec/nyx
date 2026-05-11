// Phase 03 recall-gap fixture: source flows through `p.then(cb)` into the
// callback's first parameter, which feeds a SQL sink.  The named-promise
// shape isolates the receiver-binding flow that Phase 03 ships; the
// chained-receiver form (`Promise.resolve(req.body).then(cb)`) is parked
// in `deferred.md` because it depends on a CFG-level chain-call rewrite
// that is out of scope for this phase.
async function handler(req: { body: string }): Promise<void> {
  function cb(data: string): void {
    db.query(data);
  }
  const p: Promise<string> = Promise.resolve(req.body);
  p.then(cb);
}

declare const db: { query(sql: string): void };
export default handler;

// Phase 03 recall-gap fixture: `Promise.all([req.body, req.query])`
// returns a value carrying the union of element taints.  The named-promise
// shape isolates the flow so receiver binding works through a plain
// identifier (the chained-receiver form `Promise.all(...).then(cb)`
// collapses in CFG and is parked in `deferred.md`).
async function handler(req: { body: string; query: string }): Promise<void> {
  function cb(items: string): void {
    db.query(items);
  }
  const p: Promise<string[]> = Promise.all([req.body, req.query]);
  p.then(cb);
}

declare const db: { query(sql: string): void };
export default handler;

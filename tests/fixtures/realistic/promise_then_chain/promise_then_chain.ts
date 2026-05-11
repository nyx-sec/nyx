// Phase 03 re-entrancy guard: a 2-deep `.then` chain whose inner callback
// itself awaits another promise.  Confirms that the inline cache does not
// deadlock, k=1 depth is still enforced, and the outer flow's first level
// reaches the sink.
async function handler(req: { body: string }): Promise<void> {
  function inner(data: string): void {
    db.query(data);
  }
  function outer(data: string): Promise<void> {
    return Promise.resolve(data).then(inner);
  }
  Promise.resolve(req.body).then(outer);
}

declare const db: { query(sql: string): void };
export default handler;

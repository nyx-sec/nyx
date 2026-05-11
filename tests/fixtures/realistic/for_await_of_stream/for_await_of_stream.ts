// Phase 03 recall-gap fixture: `for await (const chunk of req.body)` should
// taint `chunk` from the iterator (Web Streams / async-iterable request body).
async function handler(req: { body: AsyncIterable<string> }): Promise<void> {
  for await (const chunk of req.body) {
    db.query(chunk);
  }
}

declare const db: { query(sql: string): void };
export default handler;

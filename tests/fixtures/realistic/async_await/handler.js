// Phase 02 recall-gap fixture: source flows through `await` into a SQL sink.
// Modern handler shape — `await` is the front door of every framework that
// exposes the request as a Promise (Next.js, Web Streams, fetch handlers).
async function handler(req, res) {
  const data = await req.body;
  db.query(data);
}

module.exports = handler;

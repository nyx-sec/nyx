// Phase 10 fixture: Next.js App Router POST handler.  The
// `app/.../route.ts` path with an exported `POST` function is detected
// as an `AppRouteHandler { method: POST }` entry point.  The first
// formal `req` is auto-typed as `TypeKind::Request` so `req.json()`
// becomes a Source; awaiting and forwarding into `db.query` is a
// SQL_QUERY sink.
declare const db: { query(sql: string): void };

export async function POST(req: Request): Promise<void> {
  const body = await req.json();
  db.query(body);
}

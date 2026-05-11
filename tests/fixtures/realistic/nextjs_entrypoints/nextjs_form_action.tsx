// Phase 10 recall: a function bound as `<form action={fn}>` is a
// server-action callee.  The framework invokes `fn(formData)` with
// the submitted FormData, so the engine seeds the first formal as
// `Source(UserInput)` and traces it into the SQL_QUERY sink at
// `db.query`.

declare const db: { query(sql: string): void };

async function submit(name: string): Promise<void> {
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

export default function Page() {
  return <form action={submit}>OK</form>;
}

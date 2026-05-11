// Negative control: an unbound base must still surface SSRF.
// Without const-bound origin lock the abstract domain has no prefix
// info, the SSRF arm fires.

export async function fetchByBase(req: {
  body: { path: string; base: string };
}) {
  const u = new URL(req.body.path, req.body.base);
  return fetch(u);
}

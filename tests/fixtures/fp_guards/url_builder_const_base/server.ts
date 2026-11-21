// Phase 08 const-bound base: the URL constructor's second arg is a
// `const` identifier whose value is a literal, and the path starts with a
// fixed segment, which makes it a reference that keeps the base host. Must
// surface no SSRF finding because the abstract-string singleton domain proves
// the origin is locked even though the base arg is not a syntactic literal at
// the call site.  (A bare attacker path would not lock: it can be `//evil/`.)

export async function fetchUserPath(req: { body: { path: string } }) {
  const apiBase = "https://api.example.com";
  const u = new URL(`/v1/${req.body.path}`, apiBase);
  return fetch(u);
}

export async function fetchAltPath(req: { body: { path: string } }) {
  const altBase = "https://alt.example.com/";
  const u = new URL("items/" + req.body.path, altBase);
  return fetch(u);
}

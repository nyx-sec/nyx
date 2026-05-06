// Unsafe: tainted req.query value flows into the bare-subscript header set
// `res.headers["X-Forwarded-By"] = lang`.  The LHS-subscript classification
// path matches `res.headers` as a HEADER_INJECTION sink so this form fires
// alongside the explicit `setHeader` / `res.set` method-call shapes.
export function handler(req: any, res: any): void {
    const lang: string = req.query.lang;
    res.headers["X-Forwarded-By"] = lang;
    res.end();
}

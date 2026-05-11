// Safe: req.query.lang routed through the project-local `stripCRLF` helper
// (a registered HEADER_INJECTION sanitizer) before the subscript-set, so
// taint-header-injection stays clean.
function stripCRLF(raw: string): string {
    return raw.replace(/[\r\n]/g, '');
}

export function handler(req: any, res: any): void {
    const lang: string = req.query.lang;
    res.headers["X-Forwarded-By"] = stripCRLF(lang);
    res.end();
}

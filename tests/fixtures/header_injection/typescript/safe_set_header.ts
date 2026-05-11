// Safe: req.query.lang routed through `stripCRLF` before being written to
// the response header.
function stripCRLF(raw: string): string {
    return raw.replace(/[\r\n]/g, '');
}

export function handler(req: any, res: any): void {
    const lang: string = req.query.lang;
    const safe: string = stripCRLF(lang);
    res.setHeader('X-Lang', safe);
    res.end();
}

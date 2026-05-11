// Safe: req.query.next routed through `ensureRelativeUrl` which enforces
// a leading `/` and rejects scheme-prefixed values (relative-only path).
function ensureRelativeUrl(raw: string): string {
    if (!raw.startsWith('/') || raw.startsWith('//')) {
        return '/';
    }
    return raw;
}

export function handler(req: any, res: any): void {
    const target: string = req.query.next;
    const safe: string = ensureRelativeUrl(target);
    res.redirect(safe);
}

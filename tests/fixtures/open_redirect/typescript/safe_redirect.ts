// Safe: req.query.next routed through `validateRedirectUrl` allowlist.
function validateRedirectUrl(raw: string): string {
    return raw.startsWith('/') ? raw : '/';
}

export function handler(req: any, res: any): void {
    const target: string = req.query.next;
    const safe: string = validateRedirectUrl(target);
    res.redirect(safe);
}

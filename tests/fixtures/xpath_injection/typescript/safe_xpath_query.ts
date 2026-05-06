// Safe: user-supplied substring routed through `escapeXpath` before
// concatenation.  The sanitizer clears XPATH_INJECTION so the sink does not
// fire.
import * as xpath from 'xpath';
import { DOMParser } from 'xmldom';

function escapeXpath(raw: string): string {
    return raw.replace(/'/g, '&apos;').replace(/"/g, '&quot;');
}

export function lookup(req: any, res: any): void {
    const doc = new DOMParser().parseFromString('<root/>');
    const user: string = req.query.user;
    const safe: string = escapeXpath(user);
    const expr: string = "//user[name='" + safe + "']";
    const nodes = xpath.select(expr, doc);
    res.json(nodes);
}

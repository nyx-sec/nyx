// Unsafe: npm `xpath` package's `select` receives an expression assembled
// from req.query.  XPATH_INJECTION fires on the expression argument.
import * as xpath from 'xpath';
import { DOMParser } from 'xmldom';

export function lookup(req: any, res: any): void {
    const doc = new DOMParser().parseFromString('<root/>');
    const user: string = req.query.user;
    const expr: string = "//user[name='" + user + "']";
    const nodes = xpath.select(expr, doc);
    res.json(nodes);
}

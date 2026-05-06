// Baseline: expression is a compile-time constant.  No taint reaches
// xpath.select so no XPATH_INJECTION finding fires.
import * as xpath from 'xpath';
import { DOMParser } from 'xmldom';

export function lookup(req: any, res: any): void {
    const doc = new DOMParser().parseFromString('<root/>');
    const nodes = xpath.select("//user[@role='admin']", doc);
    res.json(nodes);
}

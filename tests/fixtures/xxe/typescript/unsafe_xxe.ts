// Unsafe: tainted XML reaches xml2js.parseString with `processEntities: true`,
// activating the XXE gate (mirrors javascript/unsafe_xxe.js).
import * as xml2js from "xml2js";

export function handle(req: any, res: any): void {
    const body: string = req.query.xml;
    xml2js.parseString(body, { processEntities: true }, (err: any, result: any) => {
        res.json(result);
    });
}

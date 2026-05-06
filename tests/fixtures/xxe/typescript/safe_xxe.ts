// Safe: tainted XML reaches xml2js.parseString with default options.
// xml2js does not expand external entities by default; the gate's
// dangerous_kwargs do not match this options literal.
import * as xml2js from "xml2js";

export function handle(req: any, res: any): void {
    const body: string = req.query.xml;
    xml2js.parseString(body, { explicitArray: false }, (err: any, result: any) => {
        res.json(result);
    });
}

// Unsafe: tainted XML reaches a fast-xml-parser instance whose
// constructor was explicitly opted into entity resolution
// (`processEntities: true`).  fast-xml-parser is XXE-safe by default,
// but this opt-in form is the documented unsafe escape hatch.  The
// constructor-driven fact is captured in `XmlParserConfigResult`
// (`external_entities = true`) and the `parser.parse(xml)` call adds
// Cap::XXE on top of the otherwise empty sink_caps.
import { XMLParser } from "fast-xml-parser";

export function handle(req: any, res: any): void {
    const body: string = req.query.xml;
    const parser = new XMLParser({ processEntities: true });
    const result = parser.parse(body);
    res.json(result);
}

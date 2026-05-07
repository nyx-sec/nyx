// Unsafe: Handlebars.compile receives a tainted template source.
import * as Handlebars from 'handlebars';

export function handler(req: any, res: any): void {
    const tmpl: string = req.body.template;
    const compiled = Handlebars.compile(tmpl);
    res.send(compiled({}));
}

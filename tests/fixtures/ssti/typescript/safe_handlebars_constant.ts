// Safe: Handlebars.compile receives a constant template source.
import * as Handlebars from 'handlebars';

export function handler(req: any, res: any): void {
    const compiled = Handlebars.compile('Hello, {{name}}');
    res.send(compiled({ name: req.query.name }));
}

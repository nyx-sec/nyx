// Unsafe: nunjucks.renderString receives a tainted template source
// from req.body; SSTI fires on the source argument.
import nunjucks from 'nunjucks';
import type { Request, Response } from 'express';

export function handler(req: Request, res: Response): void {
    const src: string = req.body.template;
    const html: string = nunjucks.renderString(src, { user: 'anon' });
    res.send(html);
}

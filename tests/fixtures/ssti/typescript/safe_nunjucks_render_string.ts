// Safe-template-var: nunjucks.renderString with constant template
// source; user-controlled context only.  Gated SSTI classifier must NOT
// fire (payload_args=[0]).
import nunjucks from 'nunjucks';
import type { Request, Response } from 'express';

export function handler(req: Request, res: Response): void {
    const html = nunjucks.renderString('Hello, {{ name }}', {
        name: req.query.name,
    });
    res.send(html);
}

// Unsafe: Express `res.setHeader` receives a value built from req.query.
// HEADER_INJECTION fires on the value argument.
export function handler(req: any, res: any): void {
    const lang: string = req.query.lang;
    res.setHeader('X-Lang', lang);
    res.end();
}

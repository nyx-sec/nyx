// Unsafe: req.query.next flows directly into res.redirect.
export function handler(req: any, res: any): void {
    const target: string = req.query.next;
    res.redirect(target);
}

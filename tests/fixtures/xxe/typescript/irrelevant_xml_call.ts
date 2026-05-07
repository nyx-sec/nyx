// Baseline: tainted body flows through a non-parser string operation.
// No XML parser entry point, no XXE label classification.
export function handle(req: any, res: any): void {
    const body: string = req.query.xml;
    res.send("<wrap>" + body + "</wrap>");
}

// Safe: req.query.next routed through `new URL(...).hostname === ALLOWED`
// host-allowlist gate before reaching res.redirect.  Recognised by
// PredicateKind::HostAllowlistValidated which clears Cap::OPEN_REDIRECT
// on the validated branch.
const ALLOWED_HOST: string = "trusted.example.com";

export function handler(req: any, res: any): void {
    const target: string = req.query.next;
    if (new URL(target).hostname === ALLOWED_HOST) {
        res.redirect(target);
        return;
    }
    res.redirect("/");
}

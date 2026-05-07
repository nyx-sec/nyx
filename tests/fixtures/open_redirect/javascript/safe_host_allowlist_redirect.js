// Safe: req.query.next routed through `new URL(...).host === ALLOWED`
// host-allowlist gate before reaching res.redirect.  Recognised by
// PredicateKind::HostAllowlistValidated which clears Cap::OPEN_REDIRECT
// on the validated branch.
const ALLOWED_HOST = "trusted.example.com";

function handler(req, res) {
    const target = req.query.next;
    if (new URL(target).host === ALLOWED_HOST) {
        res.redirect(target);
        return;
    }
    res.redirect("/");
}

module.exports = handler;

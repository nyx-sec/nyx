<?php
// Phase 09 (Track J.7) — PHP OPEN_REDIRECT vuln fixture.
//
// The function splices `$value` into a Symfony `RedirectResponse`
// without host validation; an attacker URL routes the
// `Location:` header off-origin.
use Symfony\Component\HttpFoundation\RedirectResponse;

function run(string $value): RedirectResponse {
    return new RedirectResponse($value);
}

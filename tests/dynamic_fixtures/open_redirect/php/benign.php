<?php
// Phase 09 (Track J.7) — PHP OPEN_REDIRECT benign control fixture.
//
// The function ignores the attacker-supplied value and redirects to
// a same-origin path; the captured `Location:` header carries no
// off-origin authority.
use Symfony\Component\HttpFoundation\RedirectResponse;

function run(string $value): RedirectResponse {
    return new RedirectResponse('/dashboard');
}

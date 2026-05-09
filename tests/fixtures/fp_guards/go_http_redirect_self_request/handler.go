package main

import (
	"net/http"
)

// Canonical OPEN_REDIRECT vulnerability: redirect destination is fully
// attacker-controlled via `r.FormValue`.  This MUST still fire
// `taint-open-redirect` after the same-request self-redirect suppression,
// otherwise the gate over-clears.
func openRedirectVuln(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("redirect")
	http.Redirect(w, r, target, http.StatusFound)
}

// Cross-request shape: a `*http.Request` from `http.NewRequest` (proxy
// request) is NOT the inbound request; redirecting to its URL would land
// off-origin if the URL was attacker-influenced.  The same-request gate
// only fires when arg 1 (the redirect's *Request) and the URL chain root
// match by name, so this stays in scope of the OPEN_REDIRECT detector.
func proxyRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("upstream")
	other, _ := http.NewRequest("GET", target, nil)
	http.Redirect(w, r, other.URL.String(), http.StatusFound)
}

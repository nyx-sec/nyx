package handler

import (
	"net/http"
	"net/url"
)

const allowedHost = "trusted.example.com"

// Safe: tainted query value parsed via `url.Parse` then host pinned against
// `allowedHost`.  Multi-statement form — `parsed, err := url.Parse(target)`
// happens on a separate line from the `parsed.Host == allowedHost` check.
// Recognised by PredicateKind::HostAllowlistValidated which clears
// Cap::OPEN_REDIRECT on the validated branch.
func SafeHostAllowlist(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	parsed, err := url.Parse(target)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if parsed.Host == allowedHost {
		http.Redirect(w, r, parsed.String(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

package handler

import (
	"net/http"
	"strings"
)

// validateRedirectUrl is a project-local allowlist helper: it requires a
// leading `/` to limit redirects to same-origin paths.  Registered as a
// Sanitizer(OPEN_REDIRECT) by `labels/go.rs`.
func validateRedirectUrl(raw string) string {
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	return "/"
}

// Safe: query arg routed through validateRedirectUrl allowlist.
func Safe(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	safe := validateRedirectUrl(target)
	http.Redirect(w, r, safe, http.StatusFound)
}

package handler

import (
	"net/http"
	"strings"
)

// ensureRelativeUrl enforces a leading `/` and rejects scheme-prefixed or
// protocol-relative values (`//evil.example`).  Registered as a
// Sanitizer(OPEN_REDIRECT) by `labels/go.rs`.
func ensureRelativeUrl(raw string) string {
	if !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") {
		return "/"
	}
	return raw
}

// Safe: query arg routed through ensureRelativeUrl (relative-only).
func SafeRelative(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	safe := ensureRelativeUrl(target)
	http.Redirect(w, r, safe, http.StatusFound)
}

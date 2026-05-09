package main

import (
	"net/http"
)

// Same-request self-redirect via the canonical `*url.URL.String()` shape.
// gin's `redirectTrailingSlash` / `redirectFixedPath` / `redirectRequest`
// helpers all bottom out here: scheme/host echo the inbound request, only
// the path can be edited.  MUST suppress `taint-open-redirect`.
func redirectTrailingSlash(r *http.Request, w http.ResponseWriter) {
	r.URL.Path = r.URL.Path + "/"
	rURL := r.URL.String()
	http.Redirect(w, r, rURL, http.StatusMovedPermanently)
}

// Same-request self-redirect via the `*url.URL.Path` field accessor.  No
// method-call parens; SSA encodes this as a flat callee text.  MUST
// suppress.
func redirectPath(r *http.Request, w http.ResponseWriter) {
	target := r.URL.Path
	http.Redirect(w, r, target, http.StatusFound)
}

// Same-request self-redirect via the `*url.URL.RequestURI()` accessor.
// MUST suppress.
func redirectRequestURI(w http.ResponseWriter, r *http.Request) {
	target := r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusFound)
}

// Same-request self-redirect via the `*url.URL.EscapedPath()` accessor.
// MUST suppress.
func redirectEscapedPath(w http.ResponseWriter, r *http.Request) {
	target := r.URL.EscapedPath()
	http.Redirect(w, r, target, http.StatusFound)
}

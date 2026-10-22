// Unsafe: response-side header writes through the `Header()` method.  The
// request's Origin header is reflected into the CORS allow-origin header, and
// a query value is appended as a cookie.  net/http strips CR/LF from header
// values, so the risk is the attacker-chosen value itself.
package main

import (
	"net/http"
)

func corsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	theme := r.URL.Query().Get("theme")
	w.Header().Add("Set-Cookie", "theme="+theme)
}

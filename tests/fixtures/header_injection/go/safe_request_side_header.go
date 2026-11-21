// Safe for HEADER_INJECTION: `Header` here is the struct FIELD of
// *http.Request (an inbound rewrite and an outbound client request), not the
// ResponseWriter's `Header()` method, so nothing reaches the response.  The
// last handler only taints the header NAME; the value is constant.
package main

import (
	"net/http"
	"strings"
)

func rewriteInbound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag := r.Header.Get("If-None-Match"); etag != "" {
			if before, ok := strings.CutSuffix(etag, "-gzip"); ok {
				r.Header.Set("If-None-Match", before)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func forwardUser(w http.ResponseWriter, r *http.Request) {
	out, _ := http.NewRequest("GET", "https://api.internal/x", nil)
	out.Header.Set("X-Forwarded-User", r.Header.Get("X-User"))
	http.DefaultClient.Do(out)
}

func taggedName(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Tag-"+r.URL.Query().Get("tag"), "1")
}
